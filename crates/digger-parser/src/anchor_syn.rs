use crate::model::*;
use crate::operations::{extract_operations_from_block, extract_operations_from_metadata};
use digger_ir::CallKind;
use quote::ToTokens;
/// Production Anchor parser using syn AST.
///
/// Anchor is Rust with proc macros. This parser uses syn to extract
/// Anchor-specific structure and normalize it into the existing IR.
///
/// # Normalization Rules
///
/// | Anchor AST                | IR Primitive    | Notes                         |
/// |---------------------------|-----------------|-------------------------------|
/// | `pub fn instruction()`    | ExecutableUnit  | body = reconstructed source   |
/// | `#[program] mod`          | metadata only   | ContractMeta(kind="program")  |
/// | `#[derive(Accounts)]`     | metadata only   | StructMeta (account struct)   |
/// | `#[account]`              | metadata only   | StructMeta (account type)     |
/// | `Account<'info, T>`       | metadata only   | constraint in metadata        |
/// | `Signer<'info>`           | metadata only   | authority detection via body  |
/// | `has_one` constraint      | metadata only   | constraint in metadata        |
/// | `seeds` constraint        | metadata only   | constraint in metadata        |
/// | `invoke`                  | CallEdge        | kind=CrossProgram             |
/// | `invoke_signed`           | CallEdge        | kind=CrossProgram             |
/// | `CpiContext`              | CallEdge        | kind=CrossProgram             |
/// | `require!`                | body pattern    | authority detection via body  |
/// | `emit!`                   | metadata only   | event emission in metadata    |
///
/// # Key Decisions
///
/// - Anchor is NOT a new IR model — it's Rust with constraint-heavy metadata
/// - Instruction handlers are ExecutableUnits (same as Rust functions)
/// - Account constraints are metadata only — never in IR
/// - CPI is indistinguishable from external calls in graph layer
/// - Authority detection happens via body pattern matching (graph engine)
/// - Macros are opaque — never expanded
use syn::{
    parse_file, Attribute, Block, Expr, ExprCall, ExprMacro, ExprMethodCall, File, ImplItem, Item,
    ItemFn, ItemMod, ItemStruct, Stmt, TraitItem, Visibility,
};

/// Parse Anchor source code using syn AST.
/// Falls back to regex parser if AST parsing fails.
pub fn parse(code: &str) -> RawProgram {
    match parse_file(code) {
        Ok(file) => extract_from_ast(&file, code),
        Err(_) => {
            // Fallback to regex parser if AST parsing fails
            super::anchor::parse(code)
        }
    }
}

fn extract_from_ast(file: &File, code: &str) -> RawProgram {
    let mut functions = vec![];
    let mut state = vec![];
    let mut calls = vec![];
    let mut operations = vec![];
    let mut metadata = AnalysisMetadata::default();

    for item in &file.items {
        process_item(
            item,
            code,
            &mut functions,
            &mut state,
            &mut calls,
            &mut operations,
            &mut metadata,
            None,
        );
    }

    // Post-process: detect CPI patterns in function bodies
    detect_cpi_calls(&functions, &mut calls);

    // Post-process: extract authority-check operations from Anchor metadata
    // constraints (has_one, signer, constraint, seeds, bump)
    let mut op_idx = operations.len();
    extract_operations_from_metadata(
        &RawProgram {
            functions: functions.clone(),
            state: vec![],
            calls: vec![],
            operations: vec![],
            source: String::new(),
            metadata: metadata.clone(),
        },
        &mut operations,
        &mut op_idx,
    );

    RawProgram {
        functions,
        state,
        calls,
        operations,
        source: code.to_string(),
        metadata,
    }
}

/// Process a top-level item.
#[allow(clippy::too_many_arguments)]
fn process_item(
    item: &Item,
    code: &str,
    functions: &mut Vec<RawFunction>,
    state: &mut Vec<RawState>,
    calls: &mut Vec<RawCall>,
    operations: &mut Vec<RawOperation>,
    metadata: &mut AnalysisMetadata,
    parent_context: Option<&str>,
) {
    match item {
        Item::Fn(item_fn) => {
            extract_function(
                item_fn,
                code,
                functions,
                operations,
                metadata,
                parent_context,
            );
        }
        Item::Mod(item_mod) => {
            extract_module(
                item_mod, code, functions, state, calls, operations, metadata,
            );
        }
        Item::Impl(item_impl) => {
            extract_impl(item_impl, code, functions, state, operations, metadata);
        }
        Item::Struct(item_struct) => {
            extract_struct(item_struct, metadata);
        }
        Item::Enum(item_enum) => {
            extract_enum(item_enum, metadata);
        }
        Item::Trait(item_trait) => {
            extract_trait(item_trait, metadata);
        }
        Item::Use(item_use) => {
            let use_str = format_use(item_use);
            metadata.using_directives.push(use_str);
        }
        _ => {}
    }
}

// ─────────────────────────────────────────────────────────────
// Module extraction — detect #[program] modules
// ─────────────────────────────────────────────────────────────

fn extract_module(
    item_mod: &ItemMod,
    code: &str,
    functions: &mut Vec<RawFunction>,
    state: &mut Vec<RawState>,
    calls: &mut Vec<RawCall>,
    operations: &mut Vec<RawOperation>,
    metadata: &mut AnalysisMetadata,
) {
    let name = item_mod.ident.to_string();
    let is_program = has_attribute(&item_mod.attrs, "program");

    // Record module as metadata
    metadata.contracts.push(ContractMeta {
        name: name.clone(),
        kind: if is_program {
            "anchor_program"
        } else {
            "module"
        }
        .into(),
        inheritance: vec![],
        function_names: vec![],
        state_var_names: vec![],
    });

    // Recurse into module contents
    if let Some((_, items)) = &item_mod.content {
        for item in items {
            if is_program {
                // Inside #[program] module — instruction handlers
                process_item(
                    item,
                    code,
                    functions,
                    state,
                    calls,
                    operations,
                    metadata,
                    Some(&name),
                );
            } else {
                // Regular module
                process_item(
                    item,
                    code,
                    functions,
                    state,
                    calls,
                    operations,
                    metadata,
                    Some(&name),
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Function extraction — instruction handlers → ExecutableUnit
// ─────────────────────────────────────────────────────────────

fn extract_function(
    item_fn: &ItemFn,
    code: &str,
    functions: &mut Vec<RawFunction>,
    operations: &mut Vec<RawOperation>,
    metadata: &mut AnalysisMetadata,
    parent_context: Option<&str>,
) {
    let name = item_fn.sig.ident.to_string();
    let visibility = format_visibility(&item_fn.vis);

    // Build qualified name if inside module
    let qualified_name = match parent_context {
        Some(ctx) => format!("{}::{}", ctx, name),
        None => name.clone(),
    };

    // Determine execution context
    let execution_context = if parent_context.is_some() {
        "instruction_handler"
    } else {
        "free_fn"
    };

    // Extract parameters
    let inputs: Vec<String> = item_fn
        .sig
        .inputs
        .iter()
        .map(|arg| match arg {
            syn::FnArg::Receiver(recv) => {
                if recv.reference.is_some() {
                    "&self".to_string()
                } else {
                    "self".to_string()
                }
            }
            syn::FnArg::Typed(pat_type) => {
                format!(
                    "{}: {}",
                    format_pat(&pat_type.pat),
                    format_type(&pat_type.ty)
                )
            }
        })
        .collect();

    // Extract return type
    let return_type = match &item_fn.sig.output {
        syn::ReturnType::Default => String::new(),
        syn::ReturnType::Type(_, ty) => format_type(ty),
    };

    // Extract function body (reconstructed from AST)
    let body = extract_block_source(&item_fn.block, code);

    // Extract operations from AST body
    let mut op_index = operations.len();
    extract_operations_from_block(&item_fn.block, &qualified_name, operations, &mut op_index);

    // Check for async
    let is_async = item_fn.sig.asyncness.is_some();

    // Build function metadata — enrichment only, not consumed by engines
    let mut fn_meta = FunctionMeta::default();
    fn_meta.fn_type = "function".into();
    fn_meta.mutability = if is_async { "async" } else { "nonpayable" }.into();
    fn_meta.return_types = if return_type.is_empty() {
        vec![]
    } else {
        vec![return_type]
    };
    fn_meta.execution_context = execution_context.into();
    fn_meta.rust_kind = if is_async { "async" } else { "sync" }.into();
    fn_meta.container_path = parent_context.unwrap_or("").into();
    fn_meta.body_source_mode = "reconstructed".into();
    fn_meta.loss_of_precision = true;

    // Semantic layer — ExecutableUnit (unchanged)
    functions.push(RawFunction {
        name: qualified_name.clone(),
        contract: String::new(),
        visibility,
        inputs,
        body,
        has_arithmetic: false,
    });

    // Metadata layer — AST enrichment
    metadata.function_details.insert(qualified_name, fn_meta);
}

// ─────────────────────────────────────────────────────────────
// Impl extraction — methods as ExecutableUnits
// ─────────────────────────────────────────────────────────────

fn extract_impl(
    item_impl: &syn::ItemImpl,
    code: &str,
    functions: &mut Vec<RawFunction>,
    state: &mut Vec<RawState>,
    operations: &mut Vec<RawOperation>,
    metadata: &mut AnalysisMetadata,
) {
    let type_name = format_type(&item_impl.self_ty);

    // Determine if this is a trait impl
    let trait_name = item_impl.trait_.as_ref().map(|(_, path, _)| {
        path.segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::")
    });

    let kind = if trait_name.is_some() {
        "trait_impl"
    } else {
        "impl"
    };

    // Record impl as metadata
    metadata.contracts.push(ContractMeta {
        name: type_name.clone(),
        kind: kind.into(),
        inheritance: trait_name.clone().into_iter().collect(),
        function_names: vec![],
        state_var_names: vec![],
    });

    // Process contained items
    let is_trait_impl = trait_name.is_some();
    for item in &item_impl.items {
        match item {
            ImplItem::Fn(method) => {
                let method_name = method.sig.ident.to_string();
                let qualified_name = format!("{}::{}", type_name, method_name);

                let body = extract_block_source(&method.block, code);
                let visibility = format_impl_visibility(&method.vis);

                let inputs: Vec<String> = method
                    .sig
                    .inputs
                    .iter()
                    .map(|arg| match arg {
                        syn::FnArg::Receiver(recv) => {
                            if recv.reference.is_some() {
                                "&self".to_string()
                            } else {
                                "self".to_string()
                            }
                        }
                        syn::FnArg::Typed(pat_type) => {
                            format!(
                                "{}: {}",
                                format_pat(&pat_type.pat),
                                format_type(&pat_type.ty)
                            )
                        }
                    })
                    .collect();

                let return_type = match &method.sig.output {
                    syn::ReturnType::Default => String::new(),
                    syn::ReturnType::Type(_, ty) => format_type(ty),
                };

                let is_async = method.sig.asyncness.is_some();

                let mut fn_meta = FunctionMeta::default();
                fn_meta.fn_type = "method".into();
                fn_meta.mutability = if is_async { "async" } else { "nonpayable" }.into();
                fn_meta.return_types = if return_type.is_empty() {
                    vec![]
                } else {
                    vec![return_type]
                };
                fn_meta.execution_context = if is_trait_impl {
                    "trait_impl_method"
                } else {
                    "impl_method"
                }
                .into();
                fn_meta.rust_kind = if is_async { "async" } else { "sync" }.into();
                fn_meta.container_path = type_name.clone();
                fn_meta.body_source_mode = "reconstructed".into();
                fn_meta.loss_of_precision = true;

                functions.push(RawFunction {
                    name: qualified_name.clone(),
                    contract: String::new(),
                    visibility,
                    inputs,
                    body,
                    has_arithmetic: false,
                });

                // Extract operations from method body
                let mut op_index = operations.len();
                extract_operations_from_block(
                    &method.block,
                    &qualified_name,
                    operations,
                    &mut op_index,
                );

                metadata.function_details.insert(qualified_name, fn_meta);
            }
            ImplItem::Const(const_item) => {
                let name = const_item.ident.to_string();
                let qualified_name = format!("{}::{}", type_name, name);
                state.push(RawState {
                    name: qualified_name,
                    ty: "const".into(),
                });
            }
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Struct extraction — detect #[account] and #[derive(Accounts)]
// ─────────────────────────────────────────────────────────────

fn extract_struct(item_struct: &ItemStruct, metadata: &mut AnalysisMetadata) {
    let name = item_struct.ident.to_string();
    let is_account = has_attribute(&item_struct.attrs, "account");
    let is_accounts = has_derive_attribute(&item_struct.attrs, "Accounts");

    let fields: Vec<(String, String)> = item_struct
        .fields
        .iter()
        .map(|f| {
            let field_name = f
                .ident
                .as_ref()
                .map(|i| i.to_string())
                .unwrap_or_else(|| "_".into());
            let field_ty = format_type(&f.ty);
            (field_name, field_ty)
        })
        .collect();

    // Extract constraint annotations from fields
    let constraints = extract_constraints(&item_struct.fields);

    // Record in metadata — NEVER as IR
    metadata.structs.push(StructMeta {
        name: name.clone(),
        fields: fields.clone(),
    });

    // Store Anchor-specific enrichment in extra
    if is_account || is_accounts {
        metadata.extra.insert(
            format!("anchor_struct_{}", name),
            serde_json::json!({
                "name": name,
                "is_account": is_account,
                "is_accounts": is_accounts,
                "constraints": constraints,
                "field_count": fields.len(),
            }),
        );
    }

    // D-IR1: Store structured AccountModel per field (additive, metadata-only)
    if is_accounts {
        let models = extract_account_models(&item_struct.fields);
        if !models.is_empty() {
            metadata.extra.insert(
                format!("anchor_accounts_{}", name),
                serde_json::to_value(&models).unwrap_or_default(),
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Enum/Trait extraction — metadata only
// ─────────────────────────────────────────────────────────────

fn extract_enum(item_enum: &syn::ItemEnum, metadata: &mut AnalysisMetadata) {
    let name = item_enum.ident.to_string();
    let values: Vec<String> = item_enum
        .variants
        .iter()
        .map(|v| v.ident.to_string())
        .collect();
    metadata.enums.push(EnumMeta { name, values });
}

fn extract_trait(item_trait: &syn::ItemTrait, metadata: &mut AnalysisMetadata) {
    let name = item_trait.ident.to_string();
    let method_names: Vec<String> = item_trait
        .items
        .iter()
        .filter_map(|item| match item {
            TraitItem::Fn(method) => Some(method.sig.ident.to_string()),
            _ => None,
        })
        .collect();

    metadata.contracts.push(ContractMeta {
        name,
        kind: "trait".into(),
        inheritance: vec![],
        function_names: method_names,
        state_var_names: vec![],
    });
}

// ─────────────────────────────────────────────────────────────
// CPI detection — invoke/invoke_signed → CallEdge
// ─────────────────────────────────────────────────────────────

fn detect_cpi_calls(functions: &[RawFunction], calls: &mut Vec<RawCall>) {
    for func in functions {
        let body = &func.body;

        // CPI patterns → CallEdge(kind=CrossProgram)
        // Try to extract actual target from CpiContext::new(target, ...) pattern
        if body.contains("invoke(") || body.contains("invoke_signed(") {
            let target = extract_cpi_target(body);
            calls.push(RawCall {
                from: func.name.clone(),
                to: target,
                kind: CallKind::CrossProgram,
            });
        }

        // CpiContext pattern → CallEdge(kind=CrossProgram)
        if body.contains("CpiContext") {
            let target = extract_cpi_target(body);
            calls.push(RawCall {
                from: func.name.clone(),
                to: target,
                kind: CallKind::CrossProgram,
            });
        }
    }
}

/// Extract CPI target program from body text.
///
/// Resolves known Solana program identifiers and CpiContext patterns.
/// Returns the program name or canonical identifier.
fn extract_cpi_target(body: &str) -> String {
    // Known Solana programs — pattern → canonical name
    // Covers System Program, SPL Token, Token-2022, Associated Token,
    // Rent, Clock, Memo, Compute Budget, Address Lookup Table
    let known_programs = [
        // System Program
        ("system_program", "system_program"),
        ("system_program::id()", "system_program"),
        ("system_program::transfer", "system_program"),
        // SPL Token
        ("token_program", "spl_token"),
        ("token::", "spl_token"),
        ("spl_token::", "spl_token"),
        ("spl_token_2022", "spl_token_2022"),
        ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "spl_token"),
        (
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "spl_token_2022",
        ),
        // Associated Token
        ("associated_token_program", "associated_token"),
        ("associated_token::", "associated_token"),
        (
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            "associated_token",
        ),
        // Sysvars
        ("rent", "sysvar_rent"),
        ("Rent::get()", "sysvar_rent"),
        ("rent::Rent::get()", "sysvar_rent"),
        ("SysvarRent111111111111111111111111111111111", "sysvar_rent"),
        ("clock", "sysvar_clock"),
        ("Clock::get()", "sysvar_clock"),
        (
            "SysvarC1ock11111111111111111111111111111111",
            "sysvar_clock",
        ),
        // Memo
        ("memo_program", "memo"),
        ("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "memo"),
        // Compute Budget
        ("compute_budget", "compute_budget"),
        (
            "ComputeBudget111111111111111111111111111111",
            "compute_budget",
        ),
        // Address Lookup Table
        ("address_lookup_table", "address_lookup_table"),
        (
            "AddressLookupTab1e1111111111111111111111111",
            "address_lookup_table",
        ),
    ];

    for (pattern, target) in &known_programs {
        if body.contains(pattern) {
            return target.to_string();
        }
    }

    // Try to extract from CpiContext::new(target, ...) pattern
    if let Some(start) = body.find("CpiContext::new(") {
        let rest = &body[start + "CpiContext::new(".len()..];
        if let Some(comma_pos) = rest.find(',') {
            let target = rest[..comma_pos].trim().to_string();
            if !target.is_empty() && target != "..." {
                return target;
            }
        }
    }

    // Try to extract from CpiContext::new_with_program_id(target, ...) pattern
    if let Some(start) = body.find("CpiContext::new_with_program_id(") {
        let rest = &body[start + "CpiContext::new_with_program_id(".len()..];
        if let Some(comma_pos) = rest.find(',') {
            let target = rest[..comma_pos].trim().to_string();
            if !target.is_empty() && target != "..." {
                return target;
            }
        }
    }

    "cpi".into()
}

// ─────────────────────────────────────────────────────────────
// Constraint extraction — metadata only
// ─────────────────────────────────────────────────────────────

/// Extract constraint annotations from struct fields.
/// Returns a list of (field_name, constraint_type, constraint_value) tuples.
fn extract_constraints(fields: &syn::Fields) -> Vec<serde_json::Value> {
    let mut constraints = vec![];

    for field in fields {
        let field_name = field
            .ident
            .as_ref()
            .map(|i| i.to_string())
            .unwrap_or_default();

        let type_str = format_type(&field.ty);

        // Check field type for Signer, Account, etc.
        let type_lower = type_str.to_lowercase();
        if type_lower.contains("signer") {
            constraints.push(serde_json::json!({
                "field": field_name,
                "type": "signer_type",
                "value": format!("signer:{}", type_str),
            }));
        }
        if type_lower.contains("account") {
            constraints.push(serde_json::json!({
                "field": field_name,
                "type": "account_type",
                "value": format!("account:{}", type_str),
            }));
        }

        for attr in &field.attrs {
            if attr.path().is_ident("account") {
                // Parse #[account(...)] constraints
                let constraint_str = format_attribute_tokens(attr);
                constraints.push(serde_json::json!({
                    "field": field_name,
                    "type": "account_constraint",
                    "value": constraint_str,
                }));
            }
            if attr.path().is_ident("seeds") || attr.path().is_ident("init") {
                let constraint_str = format_attribute_tokens(attr);
                constraints.push(serde_json::json!({
                    "field": field_name,
                    "type": "seed_constraint",
                    "value": constraint_str,
                }));
            }
        }
    }

    constraints
}

/// Classify the wrapper type of an Anchor account field from its Rust type string.
fn classify_wrapper_type(type_str: &str) -> AccountWrapperType {
    let t = type_str.trim().to_lowercase();

    if t.contains("signer") {
        return AccountWrapperType::SIGNER;
    }

    if t.contains("uncheckedaccount") || t.contains("accountinfo") || t.contains("check:") {
        return AccountWrapperType::RAW;
    }

    if t.contains("account<")
        || t.contains("account <")
        || t.contains("interfaceaccount")
        || t.contains("program<")
        || t.contains("program <")
        || t.contains("systemaccount")
        || t.starts_with("sysvar<")
        || t.starts_with("sysvar <")
    {
        return AccountWrapperType::TYPED;
    }

    AccountWrapperType::UNKNOWN
}

/// Extract the identifier after a keyword like `has_one = X` or `constraint = X`.
fn extract_name_after(attr_str: &str, keyword: &str) -> String {
    let lower = attr_str.to_lowercase();
    if let Some(pos) = lower.find(keyword) {
        let rest = &attr_str[pos + keyword.len()..];
        let trimmed = rest.trim_start().trim_start_matches('=').trim_start();
        let name: String = trimmed
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return name;
        }
    }
    String::new()
}

/// Extract structured AccountModel entries from an Anchor #[derive(Accounts)] struct.
fn extract_account_models(fields: &syn::Fields) -> Vec<AccountModel> {
    let mut models = Vec::new();

    for field in fields {
        let field_name = field
            .ident
            .as_ref()
            .map(|i| i.to_string())
            .unwrap_or_default();

        let type_str = format_type(&field.ty);
        let wrapper_type = classify_wrapper_type(&type_str);

        let mut is_init = false;
        let mut is_signer = false;

        for attr in &field.attrs {
            let lower = format_attribute_tokens(attr).to_lowercase();
            if attr.path().is_ident("account") {
                if lower.contains("init_if_needed") || lower.contains("init") {
                    is_init = true;
                }
                if lower.contains("signer") {
                    is_signer = true;
                }
            }
        }

        let constraints = extract_structured_constraints_for_field(field);

        models.push(AccountModel {
            name: field_name,
            wrapper_type,
            constraints,
            is_init,
            is_signer,
        });
    }

    models
}

/// Extract structured constraints for a single field.
fn extract_structured_constraints_for_field(field: &syn::Field) -> Vec<AccountConstraint> {
    let field_name = field
        .ident
        .as_ref()
        .map(|i| i.to_string())
        .unwrap_or_default();

    let mut out = Vec::new();

    for attr in &field.attrs {
        if !attr.path().is_ident("account") {
            continue;
        }
        let tokens_str = format_attribute_tokens(attr);
        let lower = tokens_str.to_lowercase();

        if lower.contains("has_one") {
            let target = extract_name_after(&tokens_str, "has_one");
            out.push(AccountConstraint {
                kind: "has_one".into(),
                target,
            });
        }
        if lower.contains("constraint") {
            let target = extract_name_after(&tokens_str, "constraint");
            out.push(AccountConstraint {
                kind: "constraint".into(),
                target,
            });
        }
        if lower.contains("owner") {
            let target = extract_name_after(&tokens_str, "owner");
            out.push(AccountConstraint {
                kind: "owner".into(),
                target,
            });
        }
        if lower.contains("seeds") {
            out.push(AccountConstraint {
                kind: "seeds".into(),
                target: field_name.clone(),
            });
        }
        if lower.contains("init_if_needed") {
            out.push(AccountConstraint {
                kind: "init_if_needed".into(),
                target: field_name.clone(),
            });
        } else if lower.contains("init") {
            out.push(AccountConstraint {
                kind: "init".into(),
                target: field_name.clone(),
            });
        }
        if lower.contains("mut") {
            out.push(AccountConstraint {
                kind: "mut".into(),
                target: field_name.clone(),
            });
        }
    }

    out
}

// ─────────────────────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────────────────────

/// Check if an item has a specific attribute (e.g., #[program], #[account]).
fn has_attribute(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident(name))
}

/// Check if an item has a specific derive attribute (e.g., #[derive(Accounts)]).
fn has_derive_attribute(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        // Parse the derive attribute tokens to check for the specific derive
        let tokens = attr.meta.to_token_stream().to_string();
        tokens.contains(name)
    })
}

/// Format attribute tokens as a string.
fn format_attribute_tokens(attr: &Attribute) -> String {
    attr.meta.to_token_stream().to_string()
}

/// Extract block source code (reconstructed from AST).
fn extract_block_source(block: &Block, _code: &str) -> String {
    reconstruct_block(block)
}

/// Reconstruct block source from AST.
fn reconstruct_block(block: &Block) -> String {
    let mut parts = vec!["{".to_string()];
    for stmt in &block.stmts {
        parts.push(reconstruct_stmt(stmt));
    }
    parts.push("}".to_string());
    parts.join(" ")
}

fn reconstruct_stmt(stmt: &Stmt) -> String {
    match stmt {
        Stmt::Local(local) => {
            let mut s = "let ".to_string();
            s.push_str(&format_pat(&local.pat));
            if let Some(init) = &local.init {
                s.push_str(" = ");
                s.push_str(&format_expr(&init.expr));
            }
            s.push(';');
            s
        }
        Stmt::Item(_) => "...".into(),
        Stmt::Expr(expr, _) => format_expr(expr),
        Stmt::Macro(mac) => {
            format!(
                "{}!(...)",
                mac.mac
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default()
            )
        }
    }
}

fn format_expr(expr: &Expr) -> String {
    match expr {
        Expr::Call(ExprCall { func, args, .. }) => {
            let func_str = format_expr(func);
            let args_str: Vec<String> = args.iter().map(format_expr).collect();
            format!("{}({})", func_str, args_str.join(", "))
        }
        Expr::MethodCall(ExprMethodCall {
            receiver,
            method,
            args,
            ..
        }) => {
            let recv_str = format_expr(receiver);
            let args_str: Vec<String> = args.iter().map(format_expr).collect();
            format!("{}.{}({})", recv_str, method, args_str.join(", "))
        }
        Expr::Path(path) => path
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Expr::Lit(lit) => format!("{}...", if lit.attrs.is_empty() { "" } else { "attr_" }),
        Expr::Reference(expr_ref) => {
            let mutability = if expr_ref.mutability.is_some() {
                "mut "
            } else {
                ""
            };
            format!("&{}{}", mutability, format_expr(&expr_ref.expr))
        }
        Expr::Macro(ExprMacro { mac, .. }) => {
            format!(
                "{}!(...)",
                mac.path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default()
            )
        }
        Expr::Block(block) => reconstruct_block(&block.block),
        Expr::If(expr_if) => {
            let cond = format_expr(&expr_if.cond);
            format!("if {} {{ ... }}", cond)
        }
        Expr::Return(ret) => match &ret.expr {
            Some(expr) => format!("return {}", format_expr(expr)),
            None => "return".into(),
        },
        Expr::Try(expr_try) => {
            format!("{}?", format_expr(&expr_try.expr))
        }
        Expr::Assign(assign) => {
            format!(
                "{} = {}",
                format_expr(&assign.left),
                format_expr(&assign.right)
            )
        }
        Expr::Binary(binary) => {
            format!(
                "{} ... {}",
                format_expr(&binary.left),
                format_expr(&binary.right)
            )
        }
        Expr::Unary(unary) => {
            format!("...{}", format_expr(&unary.expr))
        }
        Expr::Field(field) => {
            let member_str = match &field.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            };
            format!("{}.{}", format_expr(&field.base), member_str)
        }
        Expr::Index(index) => {
            format!(
                "{}[{}]",
                format_expr(&index.expr),
                format_expr(&index.index)
            )
        }
        Expr::Struct(struct_expr) => {
            let path = struct_expr
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            format!("{} {{ ... }}", path)
        }
        Expr::Tuple(tuple) => {
            let elems: Vec<String> = tuple.elems.iter().map(format_expr).collect();
            format!("({})", elems.join(", "))
        }
        Expr::Paren(paren) => {
            format!("({})", format_expr(&paren.expr))
        }
        Expr::TryBlock(_block) => {
            format!("try {{ ... }}")
        }
        Expr::Closure(_closure) => {
            format!("|...| ...")
        }
        _ => "...".to_string(),
    }
}

fn format_pat(pat: &syn::Pat) -> String {
    match pat {
        syn::Pat::Ident(ident) => ident.ident.to_string(),
        syn::Pat::Reference(pat_ref) => {
            let mutability = if pat_ref.mutability.is_some() {
                "mut "
            } else {
                ""
            };
            format!("&{}{}", mutability, format_pat(&pat_ref.pat))
        }
        syn::Pat::TupleStruct(ts) => {
            let path = ts
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            format!("{}(...)", path)
        }
        syn::Pat::Wild(_) => "_".into(),
        _ => "...".into(),
    }
}

fn format_type(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .iter()
            .map(|s| {
                let ident = s.ident.to_string();
                match &s.arguments {
                    syn::PathArguments::None => ident,
                    syn::PathArguments::AngleBracketed(args) => {
                        let type_args: Vec<String> = args
                            .args
                            .iter()
                            .filter_map(|arg| match arg {
                                syn::GenericArgument::Type(t) => Some(format_type(t)),
                                _ => None,
                            })
                            .collect();
                        format!("{}<{}>", ident, type_args.join(", "))
                    }
                    syn::PathArguments::Parenthesized(args) => {
                        let inputs: Vec<String> =
                            args.inputs.iter().map(|t| format_type(t)).collect();
                        format!("{}({})", ident, inputs.join(", "))
                    }
                }
            })
            .collect::<Vec<_>>()
            .join("::"),
        syn::Type::Reference(reference) => {
            let mutability = if reference.mutability.is_some() {
                "mut "
            } else {
                ""
            };
            format!("&{}{}", mutability, format_type(&reference.elem))
        }
        syn::Type::Tuple(tuple) => {
            let elems: Vec<String> = tuple.elems.iter().map(format_type).collect();
            format!("({})", elems.join(", "))
        }
        syn::Type::Slice(slice) => format!("[{}]", format_type(&slice.elem)),
        syn::Type::Array(array) => {
            format!("[{}; ...]", format_type(&array.elem))
        }
        syn::Type::Ptr(ptr) => {
            let mutability = if ptr.mutability.is_some() {
                "*mut "
            } else {
                "*const "
            };
            format!("{}{}", mutability, format_type(&ptr.elem))
        }
        syn::Type::Never(_) => "!".into(),
        syn::Type::Paren(paren) => format!("({})", format_type(&paren.elem)),
        _ => "...".into(),
    }
}

fn format_visibility(vis: &Visibility) -> String {
    match vis {
        Visibility::Public(_) => "public".into(),
        Visibility::Restricted(restricted) => {
            if restricted.path.segments.iter().any(|s| s.ident == "crate") {
                "crate".into()
            } else if restricted.path.segments.iter().any(|s| s.ident == "self") {
                "private".into()
            } else {
                "restricted".into()
            }
        }
        Visibility::Inherited => "private".into(),
    }
}

fn format_impl_visibility(vis: &Visibility) -> String {
    match vis {
        Visibility::Public(_) => "public".into(),
        _ => "private".into(),
    }
}

fn format_use(item_use: &syn::ItemUse) -> String {
    let mut path = String::new();
    format_use_tree(&item_use.tree, &mut path);
    path
}

fn format_use_tree(tree: &syn::UseTree, path: &mut String) {
    match tree {
        syn::UseTree::Path(p) => {
            path.push_str(&p.ident.to_string());
            path.push_str("::");
            format_use_tree(&p.tree, path);
        }
        syn::UseTree::Name(name) => {
            path.push_str(&name.ident.to_string());
        }
        syn::UseTree::Rename(rename) => {
            path.push_str(&rename.ident.to_string());
            path.push_str(" as ");
            path.push_str(&rename.rename.to_string());
        }
        syn::UseTree::Glob(_) => {
            path.push('*');
        }
        syn::UseTree::Group(group) => {
            path.push('{');
            for (i, item) in group.items.iter().enumerate() {
                if i > 0 {
                    path.push_str(", ");
                }
                format_use_tree(item, path);
            }
            path.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize;

    #[test]
    fn test_instruction_handlers() {
        let code = r#"
#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        Ok(())
    }
}
"#;
        let program = parse(code);

        // Instruction handlers → ExecutableUnit
        assert_eq!(
            program.functions.len(),
            3,
            "Should extract 3 instruction handlers, got {}",
            program.functions.len()
        );

        let names: Vec<&str> = program.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"vault::initialize"));
        assert!(names.contains(&"vault::deposit"));
        assert!(names.contains(&"vault::withdraw"));
    }

    #[test]
    fn test_program_module_as_metadata() {
        let code = r#"
#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
}
"#;
        let program = parse(code);

        // #[program] module → metadata only
        let program_meta = program
            .metadata
            .contracts
            .iter()
            .find(|c| c.kind == "anchor_program");
        assert!(
            program_meta.is_some(),
            "Should have anchor_program in metadata"
        );
        assert_eq!(program_meta.unwrap().name, "vault");
    }

    #[test]
    fn test_accounts_struct_metadata() {
        let code = r#"
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 8)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);

        // Accounts struct → metadata only
        assert_eq!(program.metadata.structs.len(), 1);
        assert_eq!(program.metadata.structs[0].name, "Initialize");

        // Constraint metadata stored in extra
        let anchor_meta = program.metadata.extra.get("anchor_struct_Initialize");
        assert!(anchor_meta.is_some(), "Should have anchor struct metadata");
    }

    #[test]
    fn test_account_type_metadata() {
        let code = r#"
#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;
        let program = parse(code);

        // #[account] struct → metadata only
        assert_eq!(program.metadata.structs.len(), 1);
        assert_eq!(program.metadata.structs[0].name, "Vault");

        let anchor_meta = program.metadata.extra.get("anchor_struct_Vault");
        assert!(anchor_meta.is_some(), "Should have anchor struct metadata");
    }

    #[test]
    fn test_cpi_as_call_edge() {
        let code = r#"
#[program]
pub mod vault {
    use super::*;

    pub fn do_cpi(ctx: Context<Cpi>) -> Result<()> {
        invoke(&ix, &accounts)?;
        Ok(())
    }

    pub fn do_cpi_signed(ctx: Context<CpiSigned>) -> Result<()> {
        invoke_signed(&ix, &accounts, &[&[b"seed"]])?;
        Ok(())
    }
}
"#;
        let program = parse(code);

        // CPI → CallEdge(kind=CrossProgram)
        let cpi_calls: Vec<_> = program
            .calls
            .iter()
            .filter(|c| c.kind == CallKind::CrossProgram)
            .collect();
        assert!(
            cpi_calls.len() >= 2,
            "Should detect CPI calls, got {}",
            cpi_calls.len()
        );
    }

    #[test]
    fn test_constraints_metadata_only() {
        let code = r#"
#[derive(Accounts)]
pub struct Init<'info> {
    #[account(init, payer = authority, space = 8 + 32)]
    pub vault: Account<'info, Vault>,
    #[account(has_one = authority)]
    pub data: Account<'info, Data>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);

        // Constraints → metadata only, NOT IR
        let anchor_meta = program.metadata.extra.get("anchor_struct_Init");
        assert!(anchor_meta.is_some(), "Should have anchor struct metadata");

        // No IR expansion — just metadata
        assert!(
            program.functions.is_empty(),
            "No functions in accounts-only code"
        );
    }

    #[test]
    fn test_events_errors_metadata() {
        let code = r#"
#[event]
pub struct DepositEvent {
    pub amount: u64,
}

#[error]
pub enum VaultError {
    InsufficientBalance,
    Unauthorized,
}
"#;
        let _program = parse(code);

        // Events → metadata only
        // (Note: #[event] is a struct with the event attribute)
        // Errors → metadata only
        // (Note: #[error] is an enum with the error attribute)
        // These are handled as regular structs/enums in metadata
    }

    #[test]
    fn test_metadata_discipline() {
        let code = r#"
#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);
        let errors = normalize::validate_metadata_discipline(&program.metadata);
        assert!(
            errors.is_empty(),
            "Anchor metadata should not contain graph-relevant data: {:?}",
            errors
        );
    }

    #[test]
    fn test_normalization_validation() {
        let code = r#"
#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
}
"#;
        let program = parse(code);
        let errors = normalize::validate(&program);
        assert!(
            errors.is_empty(),
            "Anchor normalization should produce valid program: {:?}",
            errors
        );
    }

    #[test]
    fn test_no_ir_expansion() {
        // Anchor must NOT introduce new IR types
        let code = r#"
#[program]
pub mod vault {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;
        let program = parse(code);

        // IR has only the 3 primitive types
        // ExecutableUnit: the instruction handler
        assert_eq!(program.functions.len(), 1);
        // No account nodes in IR
        // No instruction graphs in IR
        // No PDA graphs in IR
        // Everything else is metadata
    }

    #[test]
    fn test_fallback_to_regex() {
        let code = "this is not valid rust code { fn broken";
        let program = parse(code);
        // Should not panic — fallback to regex parser
        let _ = program.functions;
    }

    #[test]
    fn test_instruction_handler_execution_context() {
        let code = r#"
#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
}
"#;
        let program = parse(code);
        let init_meta = program
            .metadata
            .function_details
            .get("vault::initialize")
            .unwrap();
        assert_eq!(
            init_meta.execution_context, "instruction_handler",
            "Instruction handler should have execution_context='instruction_handler'"
        );
    }

    #[test]
    fn test_full_anchor_program() {
        let code = r#"
use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance += amount;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        require!(vault.balance >= amount, VaultError::InsufficientBalance);
        vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 8)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error]
pub enum VaultError {
    InsufficientBalance,
    Unauthorized,
}
"#;
        let program = parse(code);

        // 3 instruction handlers → ExecutableUnit
        assert_eq!(program.functions.len(), 3);

        // Program module → metadata
        let program_meta = program
            .metadata
            .contracts
            .iter()
            .find(|c| c.kind == "anchor_program");
        assert!(program_meta.is_some());

        // Account structs → metadata only
        assert!(program.metadata.structs.len() >= 3);

        // Metadata discipline maintained
        let errors = normalize::validate(&program);
        assert!(
            errors.is_empty(),
            "Full Anchor program should pass validation: {:?}",
            errors
        );
    }

    // ── D-IR1: AccountModel classification tests ──

    fn get_account_models(program: &RawProgram, struct_name: &str) -> Vec<AccountModel> {
        let key = format!("anchor_accounts_{}", struct_name);
        let val = program.metadata.extra.get(&key).unwrap();
        serde_json::from_value(val.clone()).unwrap()
    }

    #[test]
    fn test_account_model_typed_wrapper() {
        let code = r#"
#[derive(Accounts)]
pub struct SafeAccounts<'info> {
    #[account(mut)]
    pub mint: Account<'info, TokenMint>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);
        let models = get_account_models(&program, "SafeAccounts");
        assert_eq!(models.len(), 2);

        let mint = models.iter().find(|m| m.name == "mint").unwrap();
        assert_eq!(mint.wrapper_type, AccountWrapperType::TYPED);
        assert!(!mint.is_init);
        assert!(!mint.is_signer);
        assert!(mint.constraints.iter().any(|c| c.kind == "mut"));

        let auth = models.iter().find(|m| m.name == "authority").unwrap();
        assert_eq!(auth.wrapper_type, AccountWrapperType::SIGNER);
    }

    #[test]
    fn test_account_model_raw_account_info() {
        let code = r#"
#[derive(Accounts)]
pub struct RelayAccounts<'info> {
    #[account(mut)]
    pub source_account: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);
        let models = get_account_models(&program, "RelayAccounts");

        let src = models.iter().find(|m| m.name == "source_account").unwrap();
        assert_eq!(src.wrapper_type, AccountWrapperType::RAW);
    }

    #[test]
    fn test_account_model_unchecked_account() {
        let code = r#"
#[derive(Accounts)]
pub struct WithdrawAccounts<'info> {
    #[account(mut)]
    pub target_account: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);
        let models = get_account_models(&program, "WithdrawAccounts");

        let target = models.iter().find(|m| m.name == "target_account").unwrap();
        assert_eq!(target.wrapper_type, AccountWrapperType::RAW);
    }

    #[test]
    fn test_account_model_has_one_constraint() {
        let code = r#"
#[derive(Accounts)]
pub struct SafeTransferAccounts<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);
        let models = get_account_models(&program, "SafeTransferAccounts");

        let vault = models.iter().find(|m| m.name == "vault").unwrap();
        assert_eq!(vault.wrapper_type, AccountWrapperType::TYPED);
        assert!(vault
            .constraints
            .iter()
            .any(|c| c.kind == "has_one" && c.target == "authority"));
    }

    #[test]
    fn test_account_model_init_and_signer() {
        let code = r#"
#[derive(Accounts)]
pub struct InitAccounts<'info> {
    #[account(init, payer = authority, space = 8 + 32)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);
        let models = get_account_models(&program, "InitAccounts");

        let vault = models.iter().find(|m| m.name == "vault").unwrap();
        assert!(vault.is_init);
    }

    #[test]
    fn test_account_model_gt_type_cosplay_safe_1() {
        let code = r#"
#[derive(Accounts)]
pub struct SafeAccounts<'info> {
    #[account(mut)]
    pub mint: Account<'info, TokenMint>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);
        let models = get_account_models(&program, "SafeAccounts");
        let mint = models.iter().find(|m| m.name == "mint").unwrap();
        assert_eq!(
            mint.wrapper_type,
            AccountWrapperType::TYPED,
            "type-cosplay-safe-1: Account<T> should be TYPED"
        );
    }

    #[test]
    fn test_account_model_gt_owner_check_vuln_1() {
        let code = r#"
#[derive(Accounts)]
pub struct DrainAccounts<'info> {
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);
        let models = get_account_models(&program, "DrainAccounts");
        let vault = models.iter().find(|m| m.name == "vault").unwrap();
        assert_eq!(
            vault.wrapper_type,
            AccountWrapperType::RAW,
            "owner-check-vuln-1: AccountInfo should be RAW"
        );
    }

    #[test]
    fn test_account_model_gt_type_cosplay_vuln_1() {
        let code = r#"
#[derive(Accounts)]
pub struct RelayAccounts<'info> {
    #[account(mut)]
    pub source_account: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse(code);
        let models = get_account_models(&program, "RelayAccounts");
        let src = models.iter().find(|m| m.name == "source_account").unwrap();
        assert_eq!(
            src.wrapper_type,
            AccountWrapperType::RAW,
            "type-cosplay-vuln-1: AccountInfo should be RAW"
        );
    }

    #[test]
    fn test_account_model_no_accounts_struct_yields_no_entry() {
        let code = r#"
pub fn plain_fn(x: u32) -> u32 {
    x + 1
}
"#;
        let program = parse(code);
        assert!(!program
            .metadata
            .extra
            .keys()
            .any(|k| k.starts_with("anchor_accounts_")));
    }
}
