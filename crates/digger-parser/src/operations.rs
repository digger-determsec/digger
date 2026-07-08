/// Shared operation extraction from syn AST blocks.
///
/// Used by both Anchor and Rust parsers to extract ordered operations
/// from function bodies. This is critical for execution ordering,
/// state transitions, and resource lifecycle analysis.
use crate::model::*;
use syn::{Block, Expr, Stmt};

/// Extract operations from a function body block.
///
/// Walks the AST and classifies each statement into operation types:
/// - StateRead: accessing ctx.accounts.X, reading state variables
/// - StateWrite: mutating ctx.accounts.X, writing state variables
/// - ExternalCall: invoke(), invoke_signed(), CPI, .call(), .transfer()
/// - AuthorityCheck: require!, assert!, has_one, constraint checks
/// - InternalCall: calling other functions
/// - ValueTransfer: system_program::transfer, lamport transfers
pub fn extract_operations_from_block(
    block: &Block,
    func_name: &str,
    operations: &mut Vec<RawOperation>,
    op_index: &mut usize,
) {
    for stmt in &block.stmts {
        extract_operations_from_stmt(stmt, func_name, operations, op_index);
    }
}

fn extract_operations_from_stmt(
    stmt: &Stmt,
    func_name: &str,
    operations: &mut Vec<RawOperation>,
    op_index: &mut usize,
) {
    match stmt {
        Stmt::Expr(expr, _) => {
            extract_operations_from_expr(expr, func_name, operations, op_index);
        }
        Stmt::Local(local) => {
            if let Some(init) = &local.init {
                extract_operations_from_expr(&init.expr, func_name, operations, op_index);
            }
        }
        Stmt::Macro(mac) => {
            let macro_name = mac
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();

            match macro_name.as_str() {
                "require" | "assert" | "assert_eq" | "assert_ne" | "require_eq" | "require_gt"
                | "require_gte" | "require_lt" | "require_lte" | "require_keys_eq"
                | "require_keys_ne" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::AuthorityCheck,
                        target: macro_name,
                    });
                    *op_index += 1;
                }
                "emit" => {}
                _ => {
                    let tokens = mac.mac.tokens.to_string();
                    if tokens.contains("invoke") || tokens.contains("CpiContext") {
                        operations.push(RawOperation {
                            function: func_name.into(),
                            index: *op_index,
                            kind: OperationKind::ExternalCall,
                            target: "cpi".into(),
                        });
                        *op_index += 1;
                    }
                }
            }
        }
        Stmt::Item(_) => {}
    }
}

fn extract_operations_from_expr(
    expr: &Expr,
    func_name: &str,
    operations: &mut Vec<RawOperation>,
    op_index: &mut usize,
) {
    match expr {
        Expr::Call(call) => {
            let func_str = format_expr_short(&call.func);

            if func_str.contains("invoke(")
                || func_str.contains("invoke_signed(")
                || func_str == "invoke"
                || func_str == "invoke_signed"
                || func_str.contains("::cpi::")
            {
                operations.push(RawOperation {
                    function: func_name.into(),
                    index: *op_index,
                    kind: OperationKind::ExternalCall,
                    target: "cpi".into(),
                });
                *op_index += 1;
            } else if func_str.contains("system_program::transfer")
                || func_str.contains("system_program::transfer_many_raw")
            {
                operations.push(RawOperation {
                    function: func_name.into(),
                    index: *op_index,
                    kind: OperationKind::ValueTransfer,
                    target: "system_program::transfer".into(),
                });
                *op_index += 1;
            } else if func_str.contains("token::transfer")
                || func_str.contains("token::burn")
                || func_str.contains("token::mint_to")
                || func_str.contains("spl_token")
            {
                operations.push(RawOperation {
                    function: func_name.into(),
                    index: *op_index,
                    kind: OperationKind::ValueTransfer,
                    target: "token::transfer".into(),
                });
                *op_index += 1;
            } else if !func_str.is_empty()
                && !func_str.starts_with('.')
                && !func_str.contains("...")
                && !func_str.contains("|")
            {
                operations.push(RawOperation {
                    function: func_name.into(),
                    index: *op_index,
                    kind: OperationKind::InternalCall,
                    target: func_str,
                });
                *op_index += 1;
            }

            for arg in &call.args {
                extract_operations_from_expr(arg, func_name, operations, op_index);
            }
        }

        Expr::MethodCall(method_call) => {
            let method = method_call.method.to_string();
            let recv_str = format_expr_short(&method_call.receiver);

            match method.as_str() {
                "call" | "call_raw" | "call_with_user_data" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::ExternalCall,
                        target: method,
                    });
                    *op_index += 1;
                }
                "transfer" | "transfer_checked" | "burn" | "burn_checked" | "mint_to"
                | "mint_to_checked" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::ValueTransfer,
                        target: format!("token::{}", method),
                    });
                    *op_index += 1;
                }
                "try_transfer_lamports" | "transfer_lamports" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::ValueTransfer,
                        target: "lamport_transfer".into(),
                    });
                    *op_index += 1;
                }
                "exit" | "close" | "realloc" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::StateWrite,
                        target: recv_str,
                    });
                    *op_index += 1;
                }
                "borrow_mut" | "try_borrow_mut" => {
                    if recv_str.contains("ctx.accounts") || recv_str.contains("account") {
                        operations.push(RawOperation {
                            function: func_name.into(),
                            index: *op_index,
                            kind: OperationKind::StateWrite,
                            target: recv_str,
                        });
                        *op_index += 1;
                    }
                }
                "borrow" | "try_borrow" | "key" | "to_account_info" | "as_ref" => {
                    if recv_str.contains("ctx.accounts") || recv_str.contains("account") {
                        operations.push(RawOperation {
                            function: func_name.into(),
                            index: *op_index,
                            kind: OperationKind::StateRead,
                            target: recv_str,
                        });
                        *op_index += 1;
                    }
                }
                _ => {}
            }

            extract_operations_from_expr(&method_call.receiver, func_name, operations, op_index);
            for arg in &method_call.args {
                extract_operations_from_expr(arg, func_name, operations, op_index);
            }
        }

        Expr::Assign(assign) => {
            let left_str = format_expr_short(&assign.left);
            if left_str.contains("ctx.accounts")
                || left_str.contains("account")
                || (!left_str.starts_with('.') && !left_str.contains("..."))
            {
                operations.push(RawOperation {
                    function: func_name.into(),
                    index: *op_index,
                    kind: OperationKind::StateWrite,
                    target: left_str,
                });
                *op_index += 1;
            }
            extract_operations_from_expr(&assign.right, func_name, operations, op_index);
        }

        Expr::Field(field) => {
            let field_str = format_expr_short(expr);
            if field_str.contains("ctx.accounts") {
                operations.push(RawOperation {
                    function: func_name.into(),
                    index: *op_index,
                    kind: OperationKind::StateRead,
                    target: field_str,
                });
                *op_index += 1;
            }
            extract_operations_from_expr(&field.base, func_name, operations, op_index);
        }

        Expr::Index(index) => {
            let index_str = format_expr_short(expr);
            if index_str.contains("ctx.accounts") {
                operations.push(RawOperation {
                    function: func_name.into(),
                    index: *op_index,
                    kind: OperationKind::StateRead,
                    target: index_str,
                });
                *op_index += 1;
            }
            extract_operations_from_expr(&index.index, func_name, operations, op_index);
        }

        Expr::If(expr_if) => {
            extract_operations_from_expr(&expr_if.cond, func_name, operations, op_index);
            extract_operations_from_block(&expr_if.then_branch, func_name, operations, op_index);
            if let Some((_, else_expr)) = &expr_if.else_branch {
                extract_operations_from_expr(else_expr, func_name, operations, op_index);
            }
        }

        Expr::Block(block) => {
            extract_operations_from_block(&block.block, func_name, operations, op_index);
        }

        Expr::Match(match_expr) => {
            extract_operations_from_expr(&match_expr.expr, func_name, operations, op_index);
            for arm in &match_expr.arms {
                extract_operations_from_expr(&arm.body, func_name, operations, op_index);
            }
        }

        Expr::Try(try_expr) => {
            extract_operations_from_expr(&try_expr.expr, func_name, operations, op_index);
        }

        Expr::Return(ret) => {
            if let Some(expr) = &ret.expr {
                extract_operations_from_expr(expr, func_name, operations, op_index);
            }
        }

        Expr::Binary(binary) => {
            extract_operations_from_expr(&binary.left, func_name, operations, op_index);
            extract_operations_from_expr(&binary.right, func_name, operations, op_index);
        }

        Expr::Unary(unary) => {
            extract_operations_from_expr(&unary.expr, func_name, operations, op_index);
        }

        Expr::Reference(expr_ref) => {
            // Detect &mut ctx.accounts.X as StateWrite (mutable borrow = write intent)
            if expr_ref.mutability.is_some() {
                let inner_str = format_expr_short(&expr_ref.expr);
                if inner_str.contains("ctx.accounts") || inner_str.contains("account") {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::StateWrite,
                        target: inner_str,
                    });
                    *op_index += 1;
                }
            }
            extract_operations_from_expr(&expr_ref.expr, func_name, operations, op_index);
        }

        Expr::Tuple(tuple) => {
            for elem in &tuple.elems {
                extract_operations_from_expr(elem, func_name, operations, op_index);
            }
        }

        Expr::Paren(paren) => {
            extract_operations_from_expr(&paren.expr, func_name, operations, op_index);
        }

        Expr::Struct(struct_expr) => {
            for field in &struct_expr.fields {
                extract_operations_from_expr(&field.expr, func_name, operations, op_index);
            }
        }

        _ => {}
    }
}

/// Short expression formatter for operation targets.
fn format_expr_short(expr: &Expr) -> String {
    match expr {
        Expr::Path(path) => path
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Expr::Field(field) => {
            let member = match &field.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            };
            format!("{}.{}", format_expr_short(&field.base), member)
        }
        Expr::Index(index) => {
            format!(
                "{}[{}]",
                format_expr_short(&index.expr),
                format_expr_short(&index.index)
            )
        }
        Expr::MethodCall(method_call) => {
            format!(
                "{}.{}",
                format_expr_short(&method_call.receiver),
                method_call.method
            )
        }
        Expr::Call(call) => {
            let func = format_expr_short(&call.func);
            let args: Vec<String> = call.args.iter().map(format_expr_short).collect();
            format!("{}({})", func, args.join(", "))
        }
        Expr::Reference(expr_ref) => {
            format!("&{}", format_expr_short(&expr_ref.expr))
        }
        Expr::Lit(_) => "...".into(),
        Expr::Tuple(tuple) => {
            let elems: Vec<String> = tuple.elems.iter().map(format_expr_short).collect();
            format!("({})", elems.join(", "))
        }
        _ => "...".into(),
    }
}

/// Extract authority-check operations from Anchor metadata constraints.
///
/// Processes `anchor_struct_*` entries in metadata.extra to find:
/// - Signer account types (Signer<'info>)
/// - has_one= constraints
/// - constraint= with authority/owner/signer patterns
/// - seeds= + bump (PDA derivation evidence)
///
/// Emits AuthorityCheck operations so ABSENCE of authority is detectable
/// by downstream analyzers. Only emits from concrete metadata evidence.
pub fn extract_operations_from_metadata(
    program: &RawProgram,
    operations: &mut Vec<RawOperation>,
    op_index: &mut usize,
) {
    for (key, value) in &program.metadata.extra {
        if !key.starts_with("anchor_struct_") {
            continue;
        }

        let constraints = match value.get("constraints") {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => continue,
        };

        // Find functions that use this struct
        let struct_name = match value.get("name") {
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => continue,
        };

        let using_functions: Vec<String> = program
            .functions
            .iter()
            .filter(|f| {
                f.body.contains(&struct_name) || f.inputs.iter().any(|i| i.contains(&struct_name))
            })
            .map(|f| f.name.clone())
            .collect();

        for constraint_json in constraints {
            let field = constraint_json
                .get("field")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let value_str = constraint_json
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let constraint_lower = value_str.to_lowercase();

            for func_name in &using_functions {
                // has_one= → AuthorityCheck
                if constraint_lower.contains("has_one") {
                    operations.push(RawOperation {
                        function: func_name.clone(),
                        index: *op_index,
                        kind: OperationKind::AuthorityCheck,
                        target: format!("has_one:{}", field),
                    });
                    *op_index += 1;
                }

                // Signer type → AuthorityCheck
                if constraint_lower.contains("signer") {
                    operations.push(RawOperation {
                        function: func_name.clone(),
                        index: *op_index,
                        kind: OperationKind::AuthorityCheck,
                        target: format!("signer:{}", field),
                    });
                    *op_index += 1;
                }

                // constraint with authority/owner/signer → AuthorityCheck
                if constraint_lower.contains("constraint")
                    && (constraint_lower.contains("authority")
                        || constraint_lower.contains("owner")
                        || constraint_lower.contains("signer"))
                {
                    operations.push(RawOperation {
                        function: func_name.clone(),
                        index: *op_index,
                        kind: OperationKind::AuthorityCheck,
                        target: format!("constraint:{}", field),
                    });
                    *op_index += 1;
                }

                // seeds= + bump → PDA evidence
                if constraint_lower.contains("seeds") {
                    operations.push(RawOperation {
                        function: func_name.clone(),
                        index: *op_index,
                        kind: OperationKind::AuthorityCheck,
                        target: format!("pda_seed:{}", field),
                    });
                    *op_index += 1;
                }

                // bump → PDA bump validation
                if constraint_lower.contains("bump") {
                    operations.push(RawOperation {
                        function: func_name.clone(),
                        index: *op_index,
                        kind: OperationKind::AuthorityCheck,
                        target: format!("pda_bump:{}", field),
                    });
                    *op_index += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_test_program(
        functions: Vec<RawFunction>,
        extra: BTreeMap<String, serde_json::Value>,
    ) -> RawProgram {
        RawProgram {
            functions,
            state: vec![],
            calls: vec![],
            operations: vec![],
            source: String::new(),
            metadata: AnalysisMetadata {
                extra,
                ..Default::default()
            },
        }
    }

    fn make_fn(name: &str, body: &str) -> RawFunction {
        make_fn_with_input(name, body, "ctx: Context<Init>")
    }

    fn make_fn_with_input(name: &str, body: &str, input: &str) -> RawFunction {
        RawFunction {
            name: name.into(),
            contract: String::new(),
            visibility: "pub".into(),
            inputs: vec![input.into()],
            body: body.into(),
            has_arithmetic: false,
        }
    }

    #[test]
    fn metadata_has_one_emits_authority_check() {
        let mut extra = BTreeMap::new();
        extra.insert(
            "anchor_struct_Init".into(),
            serde_json::json!({
                "name": "Init",
                "is_account": false,
                "is_accounts": true,
                "constraints": [
                    { "field": "vault", "type": "account_constraint", "value": "account(has_one = authority)" },
                    { "field": "authority", "type": "signer_type", "value": "signer:Signer" },
                ],
                "field_count": 2,
            }),
        );
        let program = make_test_program(
            vec![make_fn("initialize", "{ let v = ctx.accounts; }")],
            extra,
        );

        let mut ops = vec![];
        let mut idx = 0;
        extract_operations_from_metadata(&program, &mut ops, &mut idx);

        assert!(!ops.is_empty(), "Should emit operations from metadata");
        assert!(
            ops.iter().any(
                |o| o.kind == OperationKind::AuthorityCheck && o.target.starts_with("has_one:")
            ),
            "Should have has_one AuthorityCheck"
        );
        assert!(ops.iter().any(|o| o.kind == OperationKind::AuthorityCheck && o.target.starts_with("signer:")),
            "Should have signer AuthorityCheck");
    }

    #[test]
    fn metadata_constraint_with_owner_emits_authority_check() {
        let mut extra = BTreeMap::new();
        extra.insert(
            "anchor_struct_Transfer".into(),
            serde_json::json!({
                "name": "Transfer",
                "is_account": false,
                "is_accounts": true,
                "constraints": [
                    { "field": "from", "type": "account_constraint", "value": "account(constraint = from.owner == authority.key())" },
                ],
                "field_count": 1,
            }),
        );
        let program = make_test_program(
            vec![make_fn_with_input(
                "transfer",
                "{ ctx.accounts.from.amount -= 1; }",
                "ctx: Context<Transfer>",
            )],
            extra,
        );

        let mut ops = vec![];
        let mut idx = 0;
        extract_operations_from_metadata(&program, &mut ops, &mut idx);

        assert!(
            ops.iter()
                .any(|o| o.kind == OperationKind::AuthorityCheck
                    && o.target.starts_with("constraint:")),
            "Should have constraint AuthorityCheck for owner check"
        );
    }

    #[test]
    fn metadata_no_authority_emits_nothing() {
        let mut extra = BTreeMap::new();
        extra.insert(
            "anchor_struct_Simple".into(),
            serde_json::json!({
                "name": "Simple",
                "is_account": false,
                "is_accounts": true,
                "constraints": [
                    { "field": "data", "type": "account_type", "value": "account:Account" },
                ],
                "field_count": 1,
            }),
        );
        let program = make_test_program(vec![make_fn("simple_fn", "{}")], extra);

        let mut ops = vec![];
        let mut idx = 0;
        extract_operations_from_metadata(&program, &mut ops, &mut idx);

        let authority_ops: Vec<_> = ops
            .iter()
            .filter(|o| o.kind == OperationKind::AuthorityCheck)
            .collect();
        assert!(
            authority_ops.is_empty(),
            "Should not emit AuthorityCheck for plain account types"
        );
    }

    #[test]
    fn metadata_pda_seeds_emits_authority_check() {
        let mut extra = BTreeMap::new();
        extra.insert(
            "anchor_struct_PdaInit".into(),
            serde_json::json!({
                "name": "PdaInit",
                "is_account": false,
                "is_accounts": true,
                "constraints": [
                    { "field": "vault", "type": "seed_constraint", "value": "seeds = [b\"vault\", authority.key().as_ref()], bump" },
                ],
                "field_count": 1,
            }),
        );
        let program = make_test_program(
            vec![make_fn_with_input(
                "pda_init",
                "{}",
                "ctx: Context<PdaInit>",
            )],
            extra,
        );

        let mut ops = vec![];
        let mut idx = 0;
        extract_operations_from_metadata(&program, &mut ops, &mut idx);

        assert!(
            ops.iter()
                .any(|o| o.kind == OperationKind::AuthorityCheck
                    && o.target.starts_with("pda_seed:")),
            "Should have pda_seed AuthorityCheck"
        );
        assert!(
            ops.iter()
                .any(|o| o.kind == OperationKind::AuthorityCheck
                    && o.target.starts_with("pda_bump:")),
            "Should have pda_bump AuthorityCheck"
        );
    }

    #[test]
    fn body_invoke_emits_external_call() {
        let mut ops = vec![];
        let mut idx = 0;
        let code = r#"{ invoke(&ix, &accounts)?; }"#;
        let block: Block = syn::parse_str(code).unwrap();
        extract_operations_from_block(&block, "handler", &mut ops, &mut idx);
        assert!(
            ops.iter()
                .any(|o| o.kind == OperationKind::ExternalCall && o.target == "cpi"),
            "invoke should emit ExternalCall"
        );
    }

    #[test]
    fn body_borrow_mut_emits_state_write() {
        let mut ops = vec![];
        let mut idx = 0;
        let code = r#"{ ctx.accounts.vault.amount = 42; }"#;
        let block: Block = syn::parse_str(code).unwrap();
        extract_operations_from_block(&block, "handler", &mut ops, &mut idx);
        assert!(
            ops.iter().any(|o| o.kind == OperationKind::StateWrite),
            "assignment to ctx.accounts should emit StateWrite"
        );
    }

    #[test]
    fn body_require_emits_authority_check() {
        let mut ops = vec![];
        let mut idx = 0;
        let code = r#"{ require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized); }"#;
        let block: Block = syn::parse_str(code).unwrap();
        extract_operations_from_block(&block, "handler", &mut ops, &mut idx);
        assert!(
            ops.iter()
                .any(|o| o.kind == OperationKind::AuthorityCheck && o.target == "require"),
            "require! should emit AuthorityCheck"
        );
    }
}
