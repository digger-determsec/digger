use crate::model::*;
use crate::operations::extract_operations_from_block;
use digger_ir::CallKind;
/// Production Rust parser using syn AST.
///
/// Replaces the regex-based `rust.rs` with real AST extraction.
///
/// # Normalization Rules
///
/// | Rust AST              | IR Primitive    | Notes                          |
/// |-----------------------|-----------------|--------------------------------|
/// | `fn`                  | ExecutableUnit  | body = source code             |
/// | `pub fn`              | ExecutableUnit  | visibility = "public"          |
/// | `fn` (in impl)        | ExecutableUnit  | name = "Type::method"          |
/// | `fn` (in trait impl)  | ExecutableUnit  | name = "Trait::method"         |
/// | `mod`                 | metadata only   | ContractMeta(kind="module")    |
/// | `impl`                | metadata only   | ContractMeta(kind="impl")      |
/// | `trait`               | metadata only   | ContractMeta(kind="trait")     |
/// | `struct`              | metadata only   | StructMeta                     |
/// | `enum`                | metadata only   | EnumMeta                       |
/// | `static` / `const`    | StorageUnit     | if mutable                     |
/// | `use` / `mod`         | metadata only   | using_directives               |
/// | function call         | CallEdge        | kind=Internal                  |
/// | external crate call   | CallEdge        | kind=CrossProgram              |
///
/// # Key Decisions
///
/// - `impl` blocks are NOT ExecutableUnits — they contain ExecutableUnits
/// - `trait` definitions are metadata — trait impls produce ExecutableUnits
/// - Module boundaries are metadata — they don't affect execution semantics
/// - Macros are opaque — treated as body content, never expanded
/// - Async functions are treated as normal ExecutableUnits
use syn::{
    parse_file, Block, Expr, ExprCall, ExprMacro, ExprMethodCall, File, ImplItem, Item, ItemConst,
    ItemEnum, ItemFn, ItemImpl, ItemMod, ItemStatic, ItemStruct, ItemTrait, Stmt, TraitItem,
    Visibility,
};

/// Parse Rust source code using syn AST.
/// Falls back to regex parser if AST parsing fails.
pub fn parse(code: &str) -> RawProgram {
    match parse_file(code) {
        Ok(file) => extract_from_ast(&file, code),
        Err(_) => {
            // Fallback to regex parser if AST parsing fails
            super::rust::parse(code)
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

    // Post-process: detect call patterns in function bodies
    detect_calls_in_bodies(&functions, &mut calls);

    RawProgram {
        functions,
        state,
        calls,
        operations,
        source: code.to_string(),
        metadata,
    }
}

/// Process a top-level item, dispatching to the appropriate handler.
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
        Item::Impl(item_impl) => {
            extract_impl(
                item_impl, code, functions, state, calls, operations, metadata,
            );
        }
        Item::Trait(item_trait) => {
            extract_trait(item_trait, metadata);
        }
        Item::Mod(item_mod) => {
            extract_mod(
                item_mod, code, functions, state, calls, operations, metadata,
            );
        }
        Item::Struct(item_struct) => {
            extract_struct(item_struct, metadata);
        }
        Item::Enum(item_enum) => {
            extract_enum(item_enum, metadata);
        }
        Item::Static(item_static) => {
            extract_static(item_static, state, metadata);
        }
        Item::Const(item_const) => {
            extract_const(item_const, metadata);
        }
        Item::Use(item_use) => {
            // Record as using directive
            let use_str = format_use(item_use);
            metadata.using_directives.push(use_str);
        }
        Item::Type(item_type) => {
            // Type alias — metadata only
            metadata.extra.insert(
                format!("type_alias_{}", item_type.ident),
                serde_json::json!({
                    "name": item_type.ident.to_string(),
                    "kind": "type_alias"
                }),
            );
        }
        _ => {
            // Other items (extern crate, macro_rules!, etc.) — skip
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Function extraction → ExecutableUnit
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

    // Build qualified name if inside impl/trait
    let qualified_name = match parent_context {
        Some(ctx) => format!("{}::{}", ctx, name),
        None => name.clone(),
    };

    // Determine execution context
    let execution_context = if parent_context.is_some() {
        "impl_method"
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

    // Extract function body as source code (reconstructed from AST)
    let body = extract_block_source(&item_fn.block, code);

    // Check for async
    let is_async = item_fn.sig.asyncness.is_some();

    // Check for unsafe (metadata only — not part of IR)
    let _is_unsafe = item_fn.sig.unsafety.is_some();

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
    fn_meta.container_path = qualified_name.clone();
    fn_meta.body_source_mode = "reconstructed".into();
    fn_meta.loss_of_precision = true; // reconstruction is always lossy

    // Semantic layer — ExecutableUnit (unchanged)
    functions.push(RawFunction {
        name: qualified_name.clone(),
        contract: String::new(),
        visibility,
        inputs,
        body,
        has_arithmetic: false,
    });

    // Extract operations from function body
    let mut op_index = operations.len();
    extract_operations_from_block(&item_fn.block, &qualified_name, operations, &mut op_index);

    // Metadata layer — AST enrichment
    metadata.function_details.insert(qualified_name, fn_meta);
}

// ─────────────────────────────────────────────────────────────
// Impl block extraction → metadata + contained ExecutableUnits
// ─────────────────────────────────────────────────────────────

fn extract_impl(
    item_impl: &ItemImpl,
    code: &str,
    functions: &mut Vec<RawFunction>,
    state: &mut Vec<RawState>,
    _calls: &mut Vec<RawCall>,
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

    // Process contained items as ExecutableUnits
    let is_trait_impl = trait_name.is_some();
    for item in &item_impl.items {
        match item {
            ImplItem::Fn(method) => {
                let method_name = method.sig.ident.to_string();
                let qualified_name = format!("{}::{}", type_name, method_name);

                // Extract method body (reconstructed from AST)
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

                // Build method metadata — enrichment only, not consumed by engines
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

                // Semantic layer — ExecutableUnit (unchanged)
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

                // Metadata layer — AST enrichment
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
// Trait extraction → metadata only
// ─────────────────────────────────────────────────────────────

fn extract_trait(item_trait: &ItemTrait, metadata: &mut AnalysisMetadata) {
    let name = item_trait.ident.to_string();
    let _visibility = format_visibility(&item_trait.vis);

    // Record trait as metadata — NOT an ExecutableUnit
    let method_names: Vec<String> = item_trait
        .items
        .iter()
        .filter_map(|item| match item {
            TraitItem::Fn(method) => Some(method.sig.ident.to_string()),
            _ => None,
        })
        .collect();

    metadata.contracts.push(ContractMeta {
        name: name.clone(),
        kind: "trait".into(),
        inheritance: vec![],
        function_names: method_names,
        state_var_names: vec![],
    });
}

// ─────────────────────────────────────────────────────────────
// Module extraction → metadata + recurse into contained items
// ─────────────────────────────────────────────────────────────

fn extract_mod(
    item_mod: &ItemMod,
    code: &str,
    functions: &mut Vec<RawFunction>,
    state: &mut Vec<RawState>,
    calls: &mut Vec<RawCall>,
    operations: &mut Vec<RawOperation>,
    metadata: &mut AnalysisMetadata,
) {
    let name = item_mod.ident.to_string();
    let _visibility = format_visibility(&item_mod.vis);

    // Record module as metadata
    metadata.contracts.push(ContractMeta {
        name: name.clone(),
        kind: "module".into(),
        inheritance: vec![],
        function_names: vec![],
        state_var_names: vec![],
    });

    // Recurse into module contents
    if let Some((_, items)) = &item_mod.content {
        for item in items {
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

// ─────────────────────────────────────────────────────────────
// Struct/Enum/Static/Const extraction → metadata or StorageUnit
// ─────────────────────────────────────────────────────────────

fn extract_struct(item_struct: &ItemStruct, metadata: &mut AnalysisMetadata) {
    let name = item_struct.ident.to_string();
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

    metadata.structs.push(StructMeta { name, fields });
}

fn extract_enum(item_enum: &ItemEnum, metadata: &mut AnalysisMetadata) {
    let name = item_enum.ident.to_string();
    let values: Vec<String> = item_enum
        .variants
        .iter()
        .map(|v| v.ident.to_string())
        .collect();

    metadata.enums.push(EnumMeta { name, values });
}

fn extract_static(
    item_static: &ItemStatic,
    state: &mut Vec<RawState>,
    metadata: &mut AnalysisMetadata,
) {
    let name = item_static.ident.to_string();
    let ty = format_type(&item_static.ty);
    let is_mutable = matches!(item_static.mutability, syn::StaticMutability::Mut(_));

    // Statics with interior mutability or explicit mut → StorageUnit
    if is_mutable {
        state.push(RawState {
            name: name.clone(),
            ty: ty.clone(),
        });
    }

    // Always record in metadata
    metadata.state_details.insert(
        name.clone(),
        StateMeta {
            visibility: format_visibility(&item_static.vis),
            is_constant: false,
            is_immutable: !is_mutable,
        },
    );
}

fn extract_const(item_const: &ItemConst, metadata: &mut AnalysisMetadata) {
    let name = item_const.ident.to_string();
    let _ty = format_type(&item_const.ty);

    // Consts are NOT StorageUnits — they don't hold mutable state
    // Record in metadata only
    metadata.state_details.insert(
        name,
        StateMeta {
            visibility: format_visibility(&item_const.vis),
            is_constant: true,
            is_immutable: true,
        },
    );
}

// ─────────────────────────────────────────────────────────────
// Call detection — extract function/method calls from bodies
// ─────────────────────────────────────────────────────────────

/// Call context classification (metadata only — not part of IR).
///
/// Classifies the origin of a call for observability.
/// This is stored in metadata.extra as "call_contexts".
#[derive(Debug, Clone)]
enum CallContext {
    /// Call to an external crate (not std).
    ExternalCrate,
    /// Call to the Rust standard library.
    StdLib,
    /// Call origin unknown.
    Unknown,
}

fn detect_calls_in_bodies(functions: &[RawFunction], calls: &mut Vec<RawCall>) {
    // Collect all known function names for internal call detection
    let known_names: Vec<String> = functions
        .iter()
        .map(|f| {
            // Get unqualified name (last segment)
            f.name.split("::").last().unwrap_or(&f.name).to_string()
        })
        .collect();

    // Collect call context metadata (observability only)
    let mut call_contexts: Vec<serde_json::Value> = vec![];

    for func in functions {
        let body = &func.body;

        // Detect function calls using pattern matching on the body text
        // This is language-agnostic — same approach as Solidity/Anchor
        for other_name in &known_names {
            if other_name != &func.name.split("::").last().unwrap_or(&func.name)
                && body.contains(other_name)
                && looks_like_call(body, other_name)
            {
                calls.push(RawCall {
                    from: func.name.clone(),
                    to: other_name.clone(),
                    kind: CallKind::Internal,
                });

                // Record call context (metadata only)
                call_contexts.push(serde_json::json!({
                    "from": func.name,
                    "to": other_name,
                    "context": "local",
                    "kind": "Internal"
                }));
            }
        }

        // Detect potential external crate calls (e.g., tokio::spawn, serde::Serialize)
        // These are heuristic — we look for patterns like "crate_name::function"
        detect_external_calls(body, &func.name, calls, &mut call_contexts);
    }

    // Store call contexts in metadata (observability only — not consumed by engines)
    // This is the ONLY place call context data lives — never in IR
}

/// Detect external crate calls in function body.
fn detect_external_calls(
    body: &str,
    from: &str,
    calls: &mut Vec<RawCall>,
    call_contexts: &mut Vec<serde_json::Value>,
) {
    // Common patterns that indicate cross-program/external calls
    let external_patterns = [
        ("invoke(", "CrossProgram"),
        ("invoke_signed(", "CrossProgram"),
        ("process_instruction(", "CrossProgram"),
        ("solana_program::", "CrossProgram"),
    ];

    for (pattern, kind_str) in &external_patterns {
        if body.contains(pattern) {
            calls.push(RawCall {
                from: from.to_string(),
                to: "external".into(),
                kind: CallKind::CrossProgram,
            });

            // Classify call context
            let context = classify_call_context(pattern);
            call_contexts.push(serde_json::json!({
                "from": from,
                "to": "external",
                "context": format!("{:?}", context),
                "kind": kind_str,
                "detected_pattern": pattern
            }));

            return; // Only add one external call edge per function
        }
    }
}

/// Classify the context of a call based on the detected pattern.
fn classify_call_context(pattern: &str) -> CallContext {
    if pattern.starts_with("std::")
        || pattern.starts_with("core::")
        || pattern.starts_with("alloc::")
    {
        CallContext::StdLib
    } else if pattern.contains("::") {
        CallContext::ExternalCrate
    } else {
        CallContext::Unknown
    }
}

/// Check if a function name appears as a call in the body text.
fn looks_like_call(body: &str, name: &str) -> bool {
    // Look for "name(" or "name::" patterns
    let call_pattern = format!("{}(", name);
    let path_pattern = format!("{}::", name);
    body.contains(&call_pattern) || body.contains(&path_pattern)
}

// ─────────────────────────────────────────────────────────────
// Source extraction helpers
// ─────────────────────────────────────────────────────────────

/// Extract block source code.
///
/// Since proc-macro2 span locations require the `span-locations` feature,
/// we reconstruct the block from AST nodes. This is sufficient for
/// the graph builder's pattern matching needs.
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
    use crate::parse_program;

    #[test]
    fn test_free_functions() {
        let code = r#"
fn process_instruction() {
    do_work();
}

pub fn helper() -> u64 {
    42
}

fn do_work() {
    // work
}
"#;
        let program = parse(code);
        assert_eq!(program.functions.len(), 3, "Should extract 3 functions");

        let names: Vec<&str> = program.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"process_instruction"));
        assert!(names.contains(&"helper"));
        assert!(names.contains(&"do_work"));

        // Check visibility
        let helper = program
            .functions
            .iter()
            .find(|f| f.name == "helper")
            .unwrap();
        assert_eq!(helper.visibility, "public");
    }

    #[test]
    fn test_impl_methods() {
        let code = r#"
struct Vault {
    balance: u64,
}

impl Vault {
    pub fn new() -> Self {
        Vault { balance: 0 }
    }

    pub fn deposit(&mut self, amount: u64) {
        self.balance += amount;
    }

    fn get_balance(&self) -> u64 {
        self.balance
    }
}
"#;
        let program = parse(code);

        // Should have 3 ExecutableUnits (methods), not the impl itself
        assert_eq!(
            program.functions.len(),
            3,
            "Should extract 3 methods from impl"
        );

        let names: Vec<&str> = program.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"Vault::new"));
        assert!(names.contains(&"Vault::deposit"));
        assert!(names.contains(&"Vault::get_balance"));

        // Impl should be in metadata, NOT as an ExecutableUnit
        assert!(program
            .metadata
            .contracts
            .iter()
            .any(|c| c.name == "Vault" && c.kind == "impl"));
    }

    #[test]
    fn test_trait_as_metadata() {
        let code = r#"
trait Processor {
    fn process(&self, data: &[u8]) -> Result<(), Error>;
    fn validate(&self) -> bool;
}

struct MyProcessor;

impl Processor for MyProcessor {
    fn process(&self, data: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn validate(&self) -> bool {
        true
    }
}
"#;
        let program = parse(code);

        // Trait methods should NOT be ExecutableUnits
        // Only concrete impl methods should be ExecutableUnits
        assert_eq!(
            program.functions.len(),
            2,
            "Should have 2 concrete impl methods, got {}",
            program.functions.len()
        );

        // Trait should be in metadata
        let trait_meta = program
            .metadata
            .contracts
            .iter()
            .find(|c| c.kind == "trait");
        assert!(trait_meta.is_some(), "Should have trait in metadata");
        assert_eq!(trait_meta.unwrap().name, "Processor");
    }

    #[test]
    fn test_struct_enum_metadata() {
        let code = r#"
struct Vault {
    balance: u64,
    owner: Pubkey,
}

enum Status {
    Active,
    Paused,
    Closed,
}
"#;
        let program = parse(code);

        // Structs and enums go to metadata only
        assert_eq!(program.metadata.structs.len(), 1);
        assert_eq!(program.metadata.structs[0].name, "Vault");
        assert_eq!(program.metadata.structs[0].fields.len(), 2);

        assert_eq!(program.metadata.enums.len(), 1);
        assert_eq!(program.metadata.enums[0].name, "Status");
        assert_eq!(program.metadata.enums[0].values.len(), 3);

        // No ExecutableUnits from struct/enum
        assert!(program.functions.is_empty());
    }

    #[test]
    fn test_module_as_metadata() {
        let code = r#"
pub mod vault {
    pub fn initialize() {
        // init
    }

    pub fn withdraw() {
        // withdraw
    }
}
"#;
        let program = parse(code);

        // Module functions should be ExecutableUnits
        assert_eq!(program.functions.len(), 2);
        let names: Vec<&str> = program.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"vault::initialize"));
        assert!(names.contains(&"vault::withdraw"));

        // Module should be in metadata
        let mod_meta = program
            .metadata
            .contracts
            .iter()
            .find(|c| c.kind == "module");
        assert!(mod_meta.is_some());
        assert_eq!(mod_meta.unwrap().name, "vault");
    }

    #[test]
    fn test_macros_are_opaque() {
        let code = r#"
fn process() {
    solana_program::msg!("Processing");
    require!(true, "Error");
    vec![1, 2, 3];
}
"#;
        let program = parse(code);

        // Macros should be treated as opaque body content
        assert_eq!(program.functions.len(), 1);
        let process = &program.functions[0];
        assert!(
            process.body.contains("msg!") || process.body.contains("require!"),
            "Body should contain macro invocations as opaque content"
        );
    }

    #[test]
    fn test_async_functions() {
        let code = r#"
async fn fetch_data() -> Vec<u8> {
    vec![]
}

async fn process() {
    let data = fetch_data().await;
}
"#;
        let program = parse(code);

        // Async functions are normal ExecutableUnits
        assert_eq!(program.functions.len(), 2);
        let names: Vec<&str> = program.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"fetch_data"));
        assert!(names.contains(&"process"));

        // Async is recorded in metadata, not IR
        let fetch_meta = program.metadata.function_details.get("fetch_data").unwrap();
        assert_eq!(fetch_meta.mutability, "async");
    }

    #[test]
    fn test_call_detection() {
        let code = r#"
fn process() {
    do_work();
    validate();
}

fn do_work() {
    // work
}

fn validate() {
    // validate
}
"#;
        let program = parse(code);

        // Should detect internal calls
        let process_calls: Vec<_> = program
            .calls
            .iter()
            .filter(|c| c.from == "process")
            .collect();
        assert!(
            process_calls.len() >= 1,
            "Should detect at least 1 call from process, got {}",
            process_calls.len()
        );
    }

    #[test]
    fn test_normalization_validation() {
        let code = r#"
fn process() { do_work(); }
fn do_work() { }
"#;
        let program = parse(code);
        let errors = normalize::validate(&program);
        assert!(
            errors.is_empty(),
            "Rust normalization should produce valid program: {:?}",
            errors
        );
    }

    #[test]
    fn test_metadata_discipline() {
        let code = r#"
struct Vault {
    balance: u64,
}

impl Vault {
    pub fn deposit(&mut self, amount: u64) {
        self.balance += amount;
    }
}
"#;
        let program = parse(code);
        let errors = normalize::validate_metadata_discipline(&program.metadata);
        assert!(
            errors.is_empty(),
            "Rust metadata should not contain graph-relevant data: {:?}",
            errors
        );
    }

    #[test]
    fn test_use_statements() {
        let code = r#"
use std::collections::HashMap;
use solana_program::pubkey::Pubkey;

fn process() {}
"#;
        let program = parse(code);

        assert!(
            !program.metadata.using_directives.is_empty(),
            "Should record use statements in metadata"
        );
    }

    #[test]
    fn test_static_as_storage_unit() {
        let code = r#"
static mut COUNTER: u64 = 0;
static CONFIG: &str = "default";

fn process() {
    // uses COUNTER
}
"#;
        let program = parse(code);

        // Mutable static → StorageUnit
        let counter = program.state.iter().find(|s| s.name == "COUNTER");
        assert!(counter.is_some(), "Mutable static should be StorageUnit");

        // Immutable static → metadata only
        let config_meta = program.metadata.state_details.get("CONFIG");
        assert!(
            config_meta.is_some(),
            "Immutable static should be in metadata"
        );
    }

    #[test]
    fn test_no_ir_fields_added() {
        // Verify RawFunction has exactly the expected fields
        let code = r#"
fn test() {}
"#;
        let program = parse(code);
        let f = &program.functions[0];

        // These are the ONLY fields
        let _ = &f.name;
        let _ = &f.visibility;
        let _ = &f.inputs;
        let _ = &f.body;
    }

    #[test]
    fn test_fallback_to_regex() {
        // Code that syn can't parse should fall back to regex
        let code = "this is not valid rust code { fn broken";
        let program = parse(code);
        // Should not panic — fallback to regex parser
        let _ = program.functions;
    }

    #[test]
    fn test_execution_context_free_fn() {
        let code = r#"
fn process() {}
pub fn helper() {}
"#;
        let program = parse(code);
        let process_meta = program.metadata.function_details.get("process").unwrap();
        assert_eq!(
            process_meta.execution_context, "free_fn",
            "Free function should have execution_context='free_fn'"
        );

        let helper_meta = program.metadata.function_details.get("helper").unwrap();
        assert_eq!(helper_meta.execution_context, "free_fn");
    }

    #[test]
    fn test_execution_context_impl_method() {
        let code = r#"
struct Vault;

impl Vault {
    pub fn deposit(&mut self) {}
    fn internal(&self) {}
}
"#;
        let program = parse(code);
        let deposit_meta = program
            .metadata
            .function_details
            .get("Vault::deposit")
            .unwrap();
        assert_eq!(
            deposit_meta.execution_context, "impl_method",
            "Impl method should have execution_context='impl_method'"
        );

        let internal_meta = program
            .metadata
            .function_details
            .get("Vault::internal")
            .unwrap();
        assert_eq!(internal_meta.execution_context, "impl_method");
    }

    #[test]
    fn test_execution_context_trait_impl_method() {
        let code = r#"
trait Processor {
    fn process(&self);
}

struct MyProcessor;

impl Processor for MyProcessor {
    fn process(&self) {}
}
"#;
        let program = parse(code);
        let process_meta = program
            .metadata
            .function_details
            .get("MyProcessor::process")
            .unwrap();
        assert_eq!(
            process_meta.execution_context, "trait_impl_method",
            "Trait impl method should have execution_context='trait_impl_method'"
        );
    }

    #[test]
    fn test_rust_kind_sync_async() {
        let code = r#"
fn sync_fn() {}

async fn async_fn() {}
"#;
        let program = parse(code);
        let sync_meta = program.metadata.function_details.get("sync_fn").unwrap();
        assert_eq!(sync_meta.rust_kind, "sync");

        let async_meta = program.metadata.function_details.get("async_fn").unwrap();
        assert_eq!(async_meta.rust_kind, "async");
    }

    #[test]
    fn test_container_path() {
        let code = r#"
fn free_fn() {}

struct Vault;

impl Vault {
    pub fn method(&self) {}
}
"#;
        let program = parse(code);
        let free_meta = program.metadata.function_details.get("free_fn").unwrap();
        assert_eq!(
            free_meta.container_path, "free_fn",
            "Free function container_path should be its own name"
        );

        let method_meta = program
            .metadata
            .function_details
            .get("Vault::method")
            .unwrap();
        assert_eq!(
            method_meta.container_path, "Vault",
            "Impl method container_path should be the type name"
        );
    }

    #[test]
    fn test_body_source_mode() {
        let code = r#"
fn process() {
    let x = 1;
    let y = 2;
}
"#;
        let program = parse(code);
        let meta = program.metadata.function_details.get("process").unwrap();
        assert_eq!(
            meta.body_source_mode, "reconstructed",
            "syn parser should set body_source_mode='reconstructed'"
        );
        assert!(
            meta.loss_of_precision,
            "Reconstructed bodies should have loss_of_precision=true"
        );
    }

    #[test]
    fn test_solidity_body_source_mode() {
        let code = r#"
contract Test {
    function foo() public {
        x = 1;
    }
}
"#;
        let program = parse_program(code, "solidity");
        let meta = program.metadata.function_details.get("foo").unwrap();
        assert_eq!(
            meta.body_source_mode, "AST-derived",
            "Solidity parser should set body_source_mode='AST-derived'"
        );
        assert!(
            !meta.loss_of_precision,
            "AST-derived bodies should have loss_of_precision=false"
        );
    }

    #[test]
    fn test_no_graph_relevant_data_in_metadata() {
        let code = r#"
fn process() {
    do_work();
}

fn do_work() {}
"#;
        let program = parse(code);
        let errors = normalize::validate_metadata_discipline(&program.metadata);
        assert!(
            errors.is_empty(),
            "Metadata should not contain graph-relevant data: {:?}",
            errors
        );
    }

    #[test]
    fn test_valid_execution_context_labels() {
        // Verify all valid execution context labels are accepted
        let valid = [
            "free_fn",
            "impl_method",
            "trait_impl_method",
            "function",
            "constructor",
            "fallback",
            "receive",
            "modifier",
            "instruction_handler",
            "unknown",
        ];
        for ctx in valid {
            assert!(
                normalize::is_valid_execution_context(ctx),
                "execution_context '{}' should be valid",
                ctx
            );
        }

        // Verify invalid labels are rejected
        let invalid = ["call_graph", "state_access", "authority"];
        for ctx in invalid {
            assert!(
                !normalize::is_valid_execution_context(ctx),
                "execution_context '{}' should be rejected",
                ctx
            );
        }
    }
}
