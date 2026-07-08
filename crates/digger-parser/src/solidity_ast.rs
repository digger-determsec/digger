use crate::model::*;
use digger_ir::CallKind;
/// Production Solidity AST parser using solang-parser.
///
/// Phase 6.1: AST-based call detection replaces substring matching.
/// Walks the expression tree to detect all call patterns including
/// typed interface calls like IOracle(oracle).getSpotPrice().
///
/// Semantic data (functions, state, calls) flows to graph builder via RawProgram.
/// AST enrichment (contracts, events, modifiers, etc.) flows to metadata bag.
/// Graph/hypothesis engines never touch metadata.
use solang_parser::parse as solang_parse;
use solang_parser::pt::{
    Base, ContractDefinition, ContractPart, ContractTy, EnumDefinition, ErrorDefinition,
    EventDefinition, Expression, FunctionAttribute, FunctionDefinition, FunctionTy,
    Mutability as PtMutability, SourceUnit, SourceUnitPart, Statement, StructDefinition,
    VariableAttribute, VariableDefinition, Visibility as PtVisibility,
};

/// Parse Solidity source code using the AST parser.
/// Falls back to regex parser if AST parsing fails.
pub fn parse(code: &str) -> RawProgram {
    match solang_parse(code, 0) {
        Ok((source_unit, _diagnostics)) => extract_from_ast(&source_unit, code),
        Err(_) => {
            // Fallback to regex parser if AST parsing fails
            super::solidity::parse(code)
        }
    }
}

fn extract_from_ast(source: &SourceUnit, code: &str) -> RawProgram {
    let mut functions = vec![];
    let mut state = vec![];
    let mut calls = vec![];
    let mut operations = vec![];
    let mut metadata = AnalysisMetadata::default();

    // Collect interface names for interface call detection
    let mut interface_names = std::collections::HashSet::new();

    for part in &source.0 {
        match part {
            SourceUnitPart::ContractDefinition(contract) => {
                // Track interface names
                if matches!(contract.ty, ContractTy::Interface(_)) {
                    if let Some(ref name) = contract.name {
                        interface_names.insert(name.name.clone());
                    }
                }
                extract_from_contract(
                    contract,
                    code,
                    &mut functions,
                    &mut state,
                    &mut calls,
                    &mut metadata,
                );
            }
            SourceUnitPart::FunctionDefinition(func) => {
                let empty_state = std::collections::HashSet::new();
                extract_function(func, code, &mut functions, &mut metadata, "", &empty_state);
            }
            SourceUnitPart::VariableDefinition(var) => {
                extract_state_variable(var, &mut state, &mut metadata);
            }
            SourceUnitPart::EventDefinition(event) => {
                extract_event(event, &mut metadata);
            }
            SourceUnitPart::ErrorDefinition(error) => {
                extract_error(error, &mut metadata);
            }
            SourceUnitPart::StructDefinition(s) => {
                extract_struct(s, &mut metadata);
            }
            SourceUnitPart::EnumDefinition(e) => {
                extract_enum(e, &mut metadata);
            }
            SourceUnitPart::Using(u) => {
                metadata.using_directives.push(format!("{:?}", u));
            }
            _ => {}
        }
    }

    // Phase 6.1: AST-based call detection.
    // Phase 6.3: Operation ordering extraction.
    // Walk the expression tree for each function body to find all call patterns
    // AND extract the ordered sequence of operations.
    let state_var_names: std::collections::HashSet<String> =
        state.iter().map(|s| s.name.clone()).collect();
    for part in &source.0 {
        match part {
            SourceUnitPart::ContractDefinition(contract) => {
                for contract_part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = contract_part {
                        let fn_name = func.name.as_ref().map(|n| n.name.clone()).unwrap_or_else(
                            || match func.ty {
                                FunctionTy::Constructor => "constructor".into(),
                                FunctionTy::Fallback => "fallback".into(),
                                FunctionTy::Receive => "receive".into(),
                                FunctionTy::Modifier => "modifier".into(),
                                FunctionTy::Function => "anonymous".into(),
                            },
                        );
                        if let Some(ref body) = func.body {
                            let body_calls = extract_calls_from_statement(body, &interface_names);
                            for (target, kind) in body_calls {
                                calls.push(RawCall {
                                    from: fn_name.clone(),
                                    to: target,
                                    kind,
                                });
                            }
                            // Phase 6.3: Extract ordered operations
                            let mut op_index = 0;
                            extract_operations_from_statement(
                                body,
                                &fn_name,
                                &state_var_names,
                                &interface_names,
                                &mut operations,
                                &mut op_index,
                            );
                        }
                    }
                }
            }
            SourceUnitPart::FunctionDefinition(func) => {
                let fn_name = func
                    .name
                    .as_ref()
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| "anonymous".into());
                if let Some(ref body) = func.body {
                    let body_calls = extract_calls_from_statement(body, &interface_names);
                    for (target, kind) in body_calls {
                        calls.push(RawCall {
                            from: fn_name.clone(),
                            to: target,
                            kind,
                        });
                    }
                    // Phase 6.3: Extract ordered operations
                    let mut op_index = 0;
                    extract_operations_from_statement(
                        body,
                        &fn_name,
                        &state_var_names,
                        &interface_names,
                        &mut operations,
                        &mut op_index,
                    );
                }
            }
            _ => {}
        }
    }

    // Deduplicate calls (same from/to/kind)
    calls.sort_by(|a, b| {
        a.from
            .cmp(&b.from)
            .then(a.to.cmp(&b.to))
            .then(format!("{:?}", a.kind).cmp(&format!("{:?}", b.kind)))
    });
    calls.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);

    RawProgram {
        functions,
        state,
        calls,
        operations,
        source: code.to_string(),
        metadata,
    }
}

// ─────────────────────────────────────────────────────────────
// AST-based call extraction — walks expression trees
// ─────────────────────────────────────────────────────────────

/// Extract all call relationships from a statement by walking the AST.
///
/// Returns (target, CallKind) pairs.
/// Handles:
/// - msg.sender.call{value:}() → External to "external"
/// - addr.delegatecall() → External to "delegate"
/// - addr.staticcall() → External to "static"
/// - payable(addr).transfer() → External to "transfer"
/// - IType(addr).method() → External to "interface:IType.method"
/// - function() → Internal (direct function calls)
fn extract_calls_from_statement(
    stmt: &Statement,
    interface_names: &std::collections::HashSet<String>,
) -> Vec<(String, CallKind)> {
    let mut calls = vec![];
    match stmt {
        Statement::Block { statements, .. } => {
            for s in statements {
                calls.extend(extract_calls_from_statement(s, interface_names));
            }
        }
        Statement::Expression(_loc, expr) => {
            calls.extend(extract_calls_from_expression(expr, interface_names));
        }
        Statement::If(_loc, cond, then_branch, else_branch) => {
            calls.extend(extract_calls_from_expression(cond, interface_names));
            calls.extend(extract_calls_from_statement(then_branch, interface_names));
            if let Some(else_b) = else_branch {
                calls.extend(extract_calls_from_statement(else_b, interface_names));
            }
        }
        Statement::While(_loc, cond, body) => {
            calls.extend(extract_calls_from_expression(cond, interface_names));
            calls.extend(extract_calls_from_statement(body, interface_names));
        }
        Statement::For(_loc, init, cond, update, body) => {
            if let Some(init_s) = init {
                calls.extend(extract_calls_from_statement(init_s, interface_names));
            }
            if let Some(cond_e) = cond {
                calls.extend(extract_calls_from_expression(cond_e, interface_names));
            }
            if let Some(update_e) = update {
                calls.extend(extract_calls_from_expression(update_e, interface_names));
            }
            if let Some(body_s) = body {
                calls.extend(extract_calls_from_statement(body_s, interface_names));
            }
        }
        Statement::DoWhile(_loc, body, cond) => {
            calls.extend(extract_calls_from_statement(body, interface_names));
            calls.extend(extract_calls_from_expression(cond, interface_names));
        }
        Statement::Try(_loc, expr, _, catch_clauses) => {
            calls.extend(extract_calls_from_expression(expr, interface_names));
            for clause in catch_clauses {
                let body = match clause {
                    solang_parser::pt::CatchClause::Simple(_, _, stmt) => stmt,
                    solang_parser::pt::CatchClause::Named(_, _, _, stmt) => stmt,
                };
                calls.extend(extract_calls_from_statement(body, interface_names));
            }
        }
        Statement::Return(_loc, expr) => {
            if let Some(e) = expr {
                calls.extend(extract_calls_from_expression(e, interface_names));
            }
        }
        Statement::Revert(_loc, _expr, args) => {
            // expr is IdentifierPath, not Expression — skip it
            for arg in args {
                calls.extend(extract_calls_from_expression(arg, interface_names));
            }
        }
        Statement::RevertNamedArgs(_loc, _expr, _) => {
            // expr is IdentifierPath, not Expression — skip it
        }
        Statement::Emit(_loc, expr) => {
            calls.extend(extract_calls_from_expression(expr, interface_names));
        }
        Statement::Assembly { block, .. } => {
            // Phase 7.3: Extract security-relevant operations from Yul assembly
            // Return (target, kind) pairs — caller fills in the function name
            let asm_calls = extract_calls_from_yul_block(block);
            calls.extend(asm_calls);
        }
        Statement::VariableDefinition(_loc, _, expr) => {
            if let Some(e) = expr {
                calls.extend(extract_calls_from_expression(e, interface_names));
            }
        }
        _ => {}
    }
    calls
}

/// Known SafeMath / fixed-point library method names that perform arithmetic.
const ARITH_LIB_METHODS: &[&str] = &[
    "mul",
    "div",
    "mod",
    "mulDiv",
    "mulDivDown",
    "mulDivUp",
    "wmul",
    "wdiv",
];

/// Lightweight AST walk that detects arithmetic expressions and collects
/// state-variable reads that appear inside arithmetic subtrees. This runs
/// as a SEPARATE pass alongside the existing operations walker — it does
/// not modify any existing function signatures or call sites.
///
/// The walker recurses through statements and expressions. When it enters
/// an arithmetic expression node (binary * / % + - or a known library call),
/// it increments a depth counter. Any `Expression::Variable` matching a
/// state variable name at depth > 0 is recorded as a state-read-in-arithmetic.
fn walk_arithmetic(
    stmt: &Statement,
    state_vars: &std::collections::HashSet<String>,
    ctx: &mut ArithContext,
) {
    match stmt {
        Statement::Block {
            statements,
            unchecked,
            ..
        } => {
            if *unchecked {
                ctx.unchecked_depth += 1;
            }
            for s in statements {
                walk_arithmetic(s, state_vars, ctx);
            }
            if *unchecked {
                ctx.unchecked_depth = ctx.unchecked_depth.saturating_sub(1);
            }
        }
        Statement::Expression(_, expr) => {
            walk_arith_expr(expr, state_vars, ctx);
        }
        // Variable definitions with initializers: uint256 x = expr;
        Statement::VariableDefinition(_, _, Some(expr)) => {
            walk_arith_expr(expr, state_vars, ctx);
        }
        Statement::If(_, cond, then_b, else_b) => {
            walk_arith_expr(cond, state_vars, ctx);
            walk_arithmetic(then_b, state_vars, ctx);
            if let Some(eb) = else_b {
                walk_arithmetic(eb, state_vars, ctx);
            }
        }
        Statement::While(_, cond, body) => {
            walk_arith_expr(cond, state_vars, ctx);
            walk_arithmetic(body, state_vars, ctx);
        }
        Statement::For(_, init, cond, post, body) => {
            if let Some(ref i) = init {
                walk_arithmetic(i.as_ref(), state_vars, ctx);
            }
            if let Some(ref c) = cond {
                walk_arith_expr(c.as_ref(), state_vars, ctx);
            }
            if let Some(ref p) = post {
                walk_arith_expr(p.as_ref(), state_vars, ctx);
            }
            if let Some(ref b) = body {
                walk_arithmetic(b.as_ref(), state_vars, ctx);
            }
        }
        Statement::DoWhile(_, body, cond) => {
            walk_arithmetic(body, state_vars, ctx);
            walk_arith_expr(cond, state_vars, ctx);
        }
        Statement::Return(_, Some(expr)) => {
            walk_arith_expr(expr, state_vars, ctx);
        }
        Statement::Emit(_, expr) => {
            // Emit: walk the event call expression for args
            walk_arith_expr(expr, state_vars, ctx);
        }
        Statement::Revert(_, _, args) => {
            for a in args {
                walk_arith_expr(a, state_vars, ctx);
            }
        }
        Statement::Try(_, expr, _, catch_clauses) => {
            walk_arith_expr(expr, state_vars, ctx);
            for clause in catch_clauses {
                let body = match clause {
                    solang_parser::pt::CatchClause::Simple(_, _, ref stmt) => stmt,
                    solang_parser::pt::CatchClause::Named(_, _, _, ref stmt) => stmt,
                };
                walk_arithmetic(body, state_vars, ctx);
            }
        }
        _ => {}
    }
}

/// Strip transparent parentheses from an expression.
/// (a / b) * c → Multiply(Parenthesis(Divide(a,b)), c); this peels the
/// Parenthesis wrapper so the divide-child check works on the raw operator.
fn strip_parens(mut e: &Expression) -> &Expression {
    while let Expression::Parenthesis(_, inner) = e {
        e = inner.as_ref();
    }
    e
}

/// Walk an expression for arithmetic nodes. When inside an arithmetic
/// subtree (arith_depth > 0), state-variable reads are recorded.
fn walk_arith_expr(
    expr: &Expression,
    state_vars: &std::collections::HashSet<String>,
    ctx: &mut ArithContext,
) {
    match expr {
        // ── Multiply: set flag + check for div-before-mul precision loss ──
        Expression::Multiply(_, left, right) => {
            ctx.enter_arith();
            // Check if Divide is a (possibly parenthesized) child.
            // (a / b) * c → Multiply(Parenthesis(Divide(a,b)), NumberLiteral(100))
            if matches!(strip_parens(left), Expression::Divide(..))
                || matches!(strip_parens(right), Expression::Divide(..))
            {
                ctx.has_precision_loss_ordering = true;
            }
            walk_arith_expr(left, state_vars, ctx);
            walk_arith_expr(right, state_vars, ctx);
            ctx.exit_arith();
        }
        // ── Div/mod/power: set flag ──
        Expression::Divide(_, left, right)
        | Expression::Modulo(_, left, right)
        | Expression::Power(_, left, right) => {
            ctx.enter_arith();
            walk_arith_expr(left, state_vars, ctx);
            walk_arith_expr(right, state_vars, ctx);
            ctx.exit_arith();
        }
        // ── Add/sub: recurse (may contain nested mul/div) but DON'T set flag ──
        Expression::Add(_, left, right) | Expression::Subtract(_, left, right) => {
            walk_arith_expr(left, state_vars, ctx);
            walk_arith_expr(right, state_vars, ctx);
        }
        // ── Function calls: detect SafeMath / library arithmetic ──
        Expression::FunctionCall(_, callee, args) => {
            // Check if this is a library arithmetic call (e.g., SafeMath.mul, mulDiv)
            let is_arith_call = match callee.as_ref() {
                Expression::MemberAccess(_, _, method) => {
                    ARITH_LIB_METHODS.contains(&method.name.as_str())
                }
                Expression::Variable(id) => ARITH_LIB_METHODS.contains(&id.name.as_str()),
                _ => false,
            };
            if is_arith_call {
                ctx.enter_arith();
                for a in args {
                    walk_arith_expr(a, state_vars, ctx);
                }
                ctx.exit_arith();
            } else {
                // Regular call — still recurse into arguments
                for a in args {
                    walk_arith_expr(a, state_vars, ctx);
                }
                walk_arith_expr(callee, state_vars, ctx);
            }
        }
        // ── Ternary-like: solang uses different naming — skip unknown variants ──
        // ── Unary operators: recurse into operand ──
        Expression::Not(_, e)
        | Expression::Negate(_, e)
        | Expression::PreIncrement(_, e)
        | Expression::PreDecrement(_, e)
        | Expression::PostIncrement(_, e)
        | Expression::PostDecrement(_, e) => {
            walk_arith_expr(e, state_vars, ctx);
        }
        // ── Compound assignments: mirror the plain +/- vs */÷/% rule ──
        // AssignAdd/Subtract mirror plain Add/Subtract: recurse but don't set flag.
        Expression::AssignAdd(_, left, right) | Expression::AssignSubtract(_, left, right) => {
            walk_arith_expr(left, state_vars, ctx);
            walk_arith_expr(right, state_vars, ctx);
        }
        // AssignMultiply/Divide/Modulo ARE arithmetic: set flag.
        // Also check for div-before-mul: x *= (a / b) is div-before-mul.
        Expression::AssignMultiply(_, left, right)
        | Expression::AssignDivide(_, left, right)
        | Expression::AssignModulo(_, left, right) => {
            ctx.enter_arith();
            // Check if RHS has Divide feeding into this multiply
            if matches!(strip_parens(right), Expression::Divide(..)) {
                ctx.has_precision_loss_ordering = true;
            }
            walk_arith_expr(left, state_vars, ctx);
            walk_arith_expr(right, state_vars, ctx);
            ctx.exit_arith();
        }
        // ── Plain assignment: recurse into value ──
        Expression::Assign(_, _, expr) => {
            walk_arith_expr(expr, state_vars, ctx);
        }
        // ── Comparison / logical / bitwise: recurse both sides ──
        Expression::Equal(_, l, r)
        | Expression::NotEqual(_, l, r)
        | Expression::Less(_, l, r)
        | Expression::More(_, l, r)
        | Expression::LessEqual(_, l, r)
        | Expression::MoreEqual(_, l, r)
        | Expression::And(_, l, r)
        | Expression::Or(_, l, r) => {
            walk_arith_expr(l, state_vars, ctx);
            walk_arith_expr(r, state_vars, ctx);
        }
        // ── Variable reference: record if inside arithmetic subtree ──
        Expression::Variable(id) => {
            ctx.record_if_arith(&id.name, state_vars);
        }
        // ── Array subscript access (e.g., balances[msg.sender]): check base ──
        Expression::ArraySubscript(_, inner, _index) => {
            if let Expression::Variable(id) = inner.as_ref() {
                ctx.record_if_arith(&id.name, state_vars);
            }
            walk_arith_expr(inner, state_vars, ctx);
        }
        // ── Member access (e.g., balances[msg.sender]): check base ──
        Expression::MemberAccess(_, obj, _) => {
            if let Expression::Variable(id) = obj.as_ref() {
                ctx.record_if_arith(&id.name, state_vars);
            }
            walk_arith_expr(obj, state_vars, ctx);
        }
        _ => {}
    }
}

/// Detect whether a function body contains state-mutating writes to
/// mappings indexed by msg.sender. Structural check — inspects
/// ArraySubscript index expressions for the `msg.sender` keyword.
fn detect_caller_scoped_writes(
    body: &Statement,
    state_vars: &std::collections::HashSet<String>,
) -> bool {
    fn has_sender(expr: &Expression) -> bool {
        match expr {
            Expression::Variable(id) => id.name == "msg",
            Expression::MemberAccess(_, inner, member) => {
                member.name == "sender"
                    && matches!(inner.as_ref(), Expression::Variable(id) if id.name == "msg")
            }
            Expression::ArraySubscript(_, inner, idx) => {
                has_sender(inner) || idx.as_ref().is_some_and(|i| has_sender(i))
            }
            Expression::Add(_, l, r)
            | Expression::Subtract(_, l, r)
            | Expression::Multiply(_, l, r)
            | Expression::Divide(_, l, r) => has_sender(l) || has_sender(r),
            _ => false,
        }
    }

    fn check_expr(expr: &Expression, sv: &std::collections::HashSet<String>) -> bool {
        match expr {
            Expression::AssignAdd(_, left, right)
            | Expression::AssignSubtract(_, left, right)
            | Expression::AssignMultiply(_, left, right)
            | Expression::AssignDivide(_, left, right) => {
                if let Expression::ArraySubscript(_, base, index) = left.as_ref() {
                    let is_st = matches!(base.as_ref(), Expression::Variable(id) if sv.contains(id.name.as_str()));
                    if is_st && index.as_ref().is_some_and(|i| has_sender(i)) {
                        return true;
                    }
                }
                check_expr(left, sv) || check_expr(right, sv)
            }
            Expression::Assign(_, left, right) => {
                if let Expression::ArraySubscript(_, base, index) = left.as_ref() {
                    let is_st = matches!(base.as_ref(), Expression::Variable(id) if sv.contains(id.name.as_str()));
                    if is_st && index.as_ref().is_some_and(|i| has_sender(i)) {
                        return true;
                    }
                }
                check_expr(left, sv) || check_expr(right, sv)
            }
            Expression::Add(_, l, r)
            | Expression::Subtract(_, l, r)
            | Expression::Multiply(_, l, r)
            | Expression::Divide(_, l, r)
            | Expression::Modulo(_, l, r)
            | Expression::Equal(_, l, r)
            | Expression::NotEqual(_, l, r)
            | Expression::Less(_, l, r)
            | Expression::More(_, l, r)
            | Expression::LessEqual(_, l, r)
            | Expression::MoreEqual(_, l, r)
            | Expression::And(_, l, r)
            | Expression::Or(_, l, r) => check_expr(l, sv) || check_expr(r, sv),
            Expression::FunctionCall(_, callee, args) => {
                check_expr(callee, sv) || args.iter().any(|a| check_expr(a, sv))
            }
            Expression::Not(_, e) | Expression::Negate(_, e) => check_expr(e, sv),
            Expression::MemberAccess(_, obj, _) => check_expr(obj, sv),
            Expression::ArraySubscript(_, inner, index) => {
                check_expr(inner, sv) || index.as_ref().is_some_and(|i| check_expr(i, sv))
            }
            _ => false,
        }
    }

    fn check_stmt(stmt: &Statement, sv: &std::collections::HashSet<String>) -> bool {
        match stmt {
            Statement::Block { statements, .. } => statements.iter().any(|s| check_stmt(s, sv)),
            Statement::Expression(_, expr) => check_expr(expr, sv),
            Statement::VariableDefinition(_, _, Some(expr)) => check_expr(expr, sv),
            Statement::If(_, cond, then_b, else_b) => {
                check_expr(cond, sv)
                    || check_stmt(then_b, sv)
                    || else_b.as_ref().is_some_and(|eb| check_stmt(eb, sv))
            }
            Statement::While(_, cond, body) => check_expr(cond, sv) || check_stmt(body, sv),
            Statement::For(_, init, cond, post, body) => {
                init.as_ref().is_some_and(|i| check_stmt(i, sv))
                    || cond.as_ref().is_some_and(|c| check_expr(c, sv))
                    || post.as_ref().is_some_and(|p| check_expr(p, sv))
                    || body.as_ref().is_some_and(|b| check_stmt(b, sv))
            }
            Statement::DoWhile(_, body, cond) => check_stmt(body, sv) || check_expr(cond, sv),
            Statement::Return(_, Some(expr)) => check_expr(expr, sv),
            _ => false,
        }
    }

    check_stmt(body, state_vars)
}

/// Extract call relationships from an expression by walking the AST.
///
/// This is the core of Phase 6.1 — replaces substring matching with
/// structural AST analysis.
fn extract_calls_from_expression(
    expr: &Expression,
    interface_names: &std::collections::HashSet<String>,
) -> Vec<(String, CallKind)> {
    let mut calls = vec![];

    match expr {
        // ── FunctionCall: the primary call pattern ──
        Expression::FunctionCall(_, callee, args) => {
            // Check if this is a type cast to an interface (IType(addr))
            if let Expression::Variable(ident) = callee.as_ref() {
                if interface_names.contains(&ident.name) {
                    // This is a type cast: IOracle(oracle)
                    // The actual method call will be in a MemberAccess wrapping this
                    // Don't emit a call here — wait for the MemberAccess
                }
            }

            // Check if this is a member access call: obj.method()
            if let Expression::MemberAccess(_, inner, member) = callee.as_ref() {
                let method = member.name.as_str();
                let _target_str = expr_to_type_string(inner);

                match method {
                    "call" => {
                        calls.push(("external".into(), CallKind::External));
                    }
                    "delegatecall" => {
                        calls.push(("delegate".into(), CallKind::External));
                    }
                    "staticcall" => {
                        calls.push(("static".into(), CallKind::External));
                    }
                    "transfer" => {
                        calls.push(("transfer".into(), CallKind::External));
                    }
                    _ => {
                        // Check if the inner expression is a type cast to an interface
                        // Pattern: IType(addr).method()
                        if let Expression::FunctionCall(_, type_name, _) = inner.as_ref() {
                            if let Expression::Variable(ident) = type_name.as_ref() {
                                if interface_names.contains(&ident.name) {
                                    // Interface call: IOracle(oracle).getSpotPrice()
                                    let target = format!("interface:{}.{}", ident.name, method);
                                    calls.push((target, CallKind::External));
                                }
                            }
                        }
                    }
                }
            }

            // Recurse into arguments
            for arg in args {
                calls.extend(extract_calls_from_expression(arg, interface_names));
            }

            // Recurse into callee (for nested calls)
            calls.extend(extract_calls_from_expression(callee, interface_names));
        }

        // ── FunctionCallBlock: Solidity .call{{value:}} syntax ──
        // Pattern: msg.sender.call{{value: 100}}("")
        // AST: FunctionCall(_, FunctionCallBlock(_, MemberAccess(..., "call"), block), args)
        Expression::FunctionCallBlock(_, callee, _block) => {
            // Check if callee is a MemberAccess with method "call", "delegatecall", etc.
            if let Expression::MemberAccess(_, inner, member) = callee.as_ref() {
                match member.name.as_str() {
                    "call" => {
                        calls.push(("external".into(), CallKind::External));
                    }
                    "delegatecall" => {
                        calls.push(("delegate".into(), CallKind::External));
                    }
                    "staticcall" => {
                        calls.push(("static".into(), CallKind::External));
                    }
                    _ => {}
                }
                calls.extend(extract_calls_from_expression(inner, interface_names));
            } else {
                calls.extend(extract_calls_from_expression(callee, interface_names));
            }
        }

        // ── NamedFunctionCall: f{arg: value}() ──
        Expression::NamedFunctionCall(_, callee, _args) => {
            calls.extend(extract_calls_from_expression(callee, interface_names));
        }

        // ── MemberAccess: might be part of a call pattern ──
        Expression::MemberAccess(_, inner, _member) => {
            calls.extend(extract_calls_from_expression(inner, interface_names));
        }

        // ── Binary operators: recurse both sides ──
        Expression::Power(_, left, right)
        | Expression::Multiply(_, left, right)
        | Expression::Divide(_, left, right)
        | Expression::Modulo(_, left, right)
        | Expression::Add(_, left, right)
        | Expression::Subtract(_, left, right)
        | Expression::ShiftLeft(_, left, right)
        | Expression::ShiftRight(_, left, right)
        | Expression::BitwiseAnd(_, left, right)
        | Expression::BitwiseXor(_, left, right)
        | Expression::BitwiseOr(_, left, right)
        | Expression::Less(_, left, right)
        | Expression::More(_, left, right)
        | Expression::LessEqual(_, left, right)
        | Expression::MoreEqual(_, left, right)
        | Expression::Equal(_, left, right)
        | Expression::NotEqual(_, left, right)
        | Expression::And(_, left, right)
        | Expression::Or(_, left, right) => {
            calls.extend(extract_calls_from_expression(left, interface_names));
            calls.extend(extract_calls_from_expression(right, interface_names));
        }

        // ── Unary operators: recurse operand ──
        Expression::Not(_, expr)
        | Expression::BitwiseNot(_, expr)
        | Expression::PreIncrement(_, expr)
        | Expression::PreDecrement(_, expr)
        | Expression::UnaryPlus(_, expr)
        | Expression::Negate(_, expr)
        | Expression::PostIncrement(_, expr)
        | Expression::PostDecrement(_, expr) => {
            calls.extend(extract_calls_from_expression(expr, interface_names));
        }

        // ── Delete: recurse inner ──
        Expression::Delete(_, expr) => {
            calls.extend(extract_calls_from_expression(expr, interface_names));
        }

        // ── Ternary: recurse all three ──
        Expression::ConditionalOperator(_, cond, then_expr, else_expr) => {
            calls.extend(extract_calls_from_expression(cond, interface_names));
            calls.extend(extract_calls_from_expression(then_expr, interface_names));
            calls.extend(extract_calls_from_expression(else_expr, interface_names));
        }

        // ── Assignment: recurse both sides ──
        Expression::Assign(_, left, right)
        | Expression::AssignOr(_, left, right)
        | Expression::AssignAnd(_, left, right)
        | Expression::AssignXor(_, left, right)
        | Expression::AssignShiftLeft(_, left, right)
        | Expression::AssignShiftRight(_, left, right)
        | Expression::AssignAdd(_, left, right)
        | Expression::AssignSubtract(_, left, right)
        | Expression::AssignMultiply(_, left, right)
        | Expression::AssignDivide(_, left, right)
        | Expression::AssignModulo(_, left, right) => {
            calls.extend(extract_calls_from_expression(left, interface_names));
            calls.extend(extract_calls_from_expression(right, interface_names));
        }

        // ── Array/Map access: recurse index ──
        Expression::ArraySubscript(_, inner, index) => {
            calls.extend(extract_calls_from_expression(inner, interface_names));
            if let Some(idx) = index {
                calls.extend(extract_calls_from_expression(idx, interface_names));
            }
        }

        // ── Array slice ──
        Expression::ArraySlice(_, inner, start, end) => {
            calls.extend(extract_calls_from_expression(inner, interface_names));
            if let Some(s) = start {
                calls.extend(extract_calls_from_expression(s, interface_names));
            }
            if let Some(e) = end {
                calls.extend(extract_calls_from_expression(e, interface_names));
            }
        }

        // ── Parenthesis: recurse inner ──
        Expression::Parenthesis(_, inner) => {
            calls.extend(extract_calls_from_expression(inner, interface_names));
        }

        // ── New: recurse inner ──
        Expression::New(_, inner) => {
            calls.extend(extract_calls_from_expression(inner, interface_names));
        }

        // ── Type cast: IType(addr) — check if it's an interface cast ──
        Expression::Type(_, _) => {
            // Type expressions don't contain calls
        }

        // ── Literals: no calls ──
        Expression::NumberLiteral(..)
        | Expression::RationalNumberLiteral(..)
        | Expression::StringLiteral(..)
        | Expression::BoolLiteral(..)
        | Expression::HexNumberLiteral(..)
        | Expression::HexLiteral(..)
        | Expression::AddressLiteral(..)
        | Expression::Variable(..) => {
            // No calls in literals or variables
        }

        _ => {
            // Unknown expression type — recurse generically
            // This handles any future expression types
        }
    }

    calls
}

// ─────────────────────────────────────────────────────────────
// Operation ordering extraction — Phase 6.3
// ─────────────────────────────────────────────────────────────

/// Mutable context threaded through the AST walk to accumulate arithmetic
/// signals. Eliminates the text-based `body_has_arithmetic` check and the
/// fragile `body_lower.contains(state_var_name)` name-match.
struct ArithContext {
    has_arithmetic: bool,
    has_unchecked_arithmetic: bool,
    has_precision_loss_ordering: bool,
    state_reads_in_arithmetic: std::collections::BTreeSet<String>,
    arith_depth: u32,
    unchecked_depth: u32,
}

impl ArithContext {
    fn new() -> Self {
        Self {
            has_arithmetic: false,
            has_unchecked_arithmetic: false,
            has_precision_loss_ordering: false,
            state_reads_in_arithmetic: std::collections::BTreeSet::new(),
            arith_depth: 0,
            unchecked_depth: 0,
        }
    }

    fn enter_arith(&mut self) {
        self.has_arithmetic = true;
        if self.unchecked_depth > 0 {
            self.has_unchecked_arithmetic = true;
        }
        self.arith_depth += 1;
    }

    fn exit_arith(&mut self) {
        self.arith_depth = self.arith_depth.saturating_sub(1);
    }

    fn record_if_arith(&mut self, var: &str, state_vars: &std::collections::HashSet<String>) {
        if self.arith_depth > 0 && state_vars.contains(var) {
            self.state_reads_in_arithmetic.insert(var.to_string());
        }
    }
}

/// Extract ordered operations from a statement by walking the AST.
///
/// Operations are emitted in sequential order as they appear in the source.
/// This enables checks-effects-interactions analysis.
fn extract_operations_from_statement(
    stmt: &Statement,
    func_name: &str,
    state_vars: &std::collections::HashSet<String>,
    interface_names: &std::collections::HashSet<String>,
    operations: &mut Vec<RawOperation>,
    op_index: &mut usize,
) {
    match stmt {
        Statement::Block { statements, .. } => {
            for s in statements {
                extract_operations_from_statement(
                    s,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
        }
        Statement::Expression(_loc, expr) => {
            extract_operations_from_expression(
                expr,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }
        Statement::If(_loc, cond, then_branch, else_branch) => {
            extract_operations_from_expression(
                cond,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            extract_operations_from_statement(
                then_branch,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            if let Some(else_b) = else_branch {
                extract_operations_from_statement(
                    else_b,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
        }
        Statement::While(_loc, cond, body) => {
            extract_operations_from_expression(
                cond,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            extract_operations_from_statement(
                body,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }
        Statement::For(_loc, init, cond, update, body) => {
            if let Some(init_s) = init {
                extract_operations_from_statement(
                    init_s,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
            if let Some(cond_e) = cond {
                extract_operations_from_expression(
                    cond_e,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
            if let Some(update_e) = update {
                extract_operations_from_expression(
                    update_e,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
            if let Some(body_s) = body {
                extract_operations_from_statement(
                    body_s,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
        }
        Statement::DoWhile(_loc, body, cond) => {
            extract_operations_from_statement(
                body,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            extract_operations_from_expression(
                cond,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }
        Statement::Try(_loc, expr, _, catch_clauses) => {
            extract_operations_from_expression(
                expr,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            for clause in catch_clauses {
                let body = match clause {
                    solang_parser::pt::CatchClause::Simple(_, _, stmt) => stmt,
                    solang_parser::pt::CatchClause::Named(_, _, _, stmt) => stmt,
                };
                extract_operations_from_statement(
                    body,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
        }
        Statement::Return(_loc, expr) => {
            if let Some(e) = expr {
                extract_operations_from_expression(
                    e,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
        }
        Statement::Revert(_loc, _, args) => {
            for arg in args {
                extract_operations_from_expression(
                    arg,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
        }
        Statement::Emit(_loc, expr) => {
            extract_operations_from_expression(
                expr,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }
        Statement::Assembly { block, .. } => {
            // Phase 7.3: Extract security-relevant operations from Yul assembly
            extract_operations_from_yul_block(block, func_name, state_vars, operations, op_index);
        }
        Statement::VariableDefinition(_loc, _, expr) => {
            if let Some(e) = expr {
                extract_operations_from_expression(
                    e,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
        }
        // Named arguments block: {value: X, ...} in .call{value: X}()
        Statement::Args(_loc, args) => {
            for arg in args {
                extract_operations_from_expression(
                    &arg.expr,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
        }
        _ => {}
    }
}

/// Extract ordered operations from an expression.
///
/// Emits operations in the order they would execute at runtime.
fn extract_operations_from_expression(
    expr: &Expression,
    func_name: &str,
    state_vars: &std::collections::HashSet<String>,
    interface_names: &std::collections::HashSet<String>,
    operations: &mut Vec<RawOperation>,
    op_index: &mut usize,
) {
    match expr {
        // ── FunctionCall: check for external calls and authority checks ──
        Expression::FunctionCall(_, callee, args) => {
            // Check if callee is a MemberAccess (method call)
            if let Expression::MemberAccess(_, inner, member) = callee.as_ref() {
                let method = member.name.as_str();
                match method {
                    "call" | "delegatecall" | "staticcall" | "transfer" => {
                        operations.push(RawOperation {
                            function: func_name.into(),
                            index: *op_index,
                            kind: OperationKind::ExternalCall,
                            target: method.into(),
                        });
                        *op_index += 1;
                    }
                    _ => {
                        // Check if inner is an interface type cast
                        if let Expression::FunctionCall(_, type_name, _) = inner.as_ref() {
                            if let Expression::Variable(ident) = type_name.as_ref() {
                                if interface_names.contains(&ident.name) {
                                    operations.push(RawOperation {
                                        function: func_name.into(),
                                        index: *op_index,
                                        kind: OperationKind::ExternalCall,
                                        target: format!("{}.{}", ident.name, method),
                                    });
                                    *op_index += 1;
                                }
                            }
                        }
                    }
                }
            }

            // Check for require/assert (authority checks) and internal calls
            if let Expression::Variable(ident) = callee.as_ref() {
                if ident.name == "require" || ident.name == "assert" {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::AuthorityCheck,
                        target: ident.name.clone(),
                    });
                    *op_index += 1;
                } else if ident.name != "emit" {
                    // Direct function call — likely an internal call
                    // (emit is not a function call, it's an event emission)
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::InternalCall,
                        target: ident.name.clone(),
                    });
                    *op_index += 1;
                }
            }

            // Recurse into arguments (left-to-right evaluation)
            for arg in args {
                extract_operations_from_expression(
                    arg,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
            // Recurse into callee
            extract_operations_from_expression(
                callee,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }

        // ── FunctionCallBlock: .call{value:}() ──
        // Runtime order: evaluate callee, evaluate value block, then execute call.
        // We recurse into subexpressions first, then emit the ExternalCall.
        Expression::FunctionCallBlock(_, callee, block) => {
            if let Expression::MemberAccess(_, inner, _member) = callee.as_ref() {
                // Recurse into callee (e.g., msg.sender)
                extract_operations_from_expression(
                    inner,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
            // Recurse into value block to capture state reads
            // (e.g., balances[msg.sender] in .call{value: balances[msg.sender]}())
            extract_operations_from_statement(
                block,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            // Emit ExternalCall AFTER subexpressions (matches runtime order:
            // value evaluates before the call executes)
            if let Expression::MemberAccess(_, _, member) = callee.as_ref() {
                match member.name.as_str() {
                    "call" | "delegatecall" | "staticcall" => {
                        operations.push(RawOperation {
                            function: func_name.into(),
                            index: *op_index,
                            kind: OperationKind::ExternalCall,
                            target: member.name.clone(),
                        });
                        *op_index += 1;
                    }
                    _ => {}
                }
            }
        }

        // ── Assignment: state write if LHS is a state variable ──
        Expression::Assign(_, left, right)
        | Expression::AssignAdd(_, left, right)
        | Expression::AssignSubtract(_, left, right)
        | Expression::AssignMultiply(_, left, right)
        | Expression::AssignDivide(_, left, right)
        | Expression::AssignModulo(_, left, right) => {
            // Check if LHS is a state variable
            let lhs_name = expr_to_simple_string(left);
            if state_vars.contains(&lhs_name) || lhs_name.contains('[') {
                // Indexed write to state (e.g., balances[msg.sender] += amount)
                let base_var = lhs_name.split('[').next().unwrap_or(&lhs_name).to_string();
                if state_vars.contains(&base_var) {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::StateWrite,
                        target: base_var,
                    });
                    *op_index += 1;
                }
            }
            // Recurse into RHS (value is computed before assignment)
            extract_operations_from_expression(
                right,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            extract_operations_from_expression(
                left,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }

        // ── Binary operators: recurse both sides (left first) ──
        Expression::Add(_, left, right)
        | Expression::Subtract(_, left, right)
        | Expression::Multiply(_, left, right)
        | Expression::Divide(_, left, right)
        | Expression::Modulo(_, left, right)
        | Expression::Equal(_, left, right)
        | Expression::NotEqual(_, left, right)
        | Expression::Less(_, left, right)
        | Expression::More(_, left, right)
        | Expression::LessEqual(_, left, right)
        | Expression::MoreEqual(_, left, right)
        | Expression::And(_, left, right)
        | Expression::Or(_, left, right) => {
            extract_operations_from_expression(
                left,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            extract_operations_from_expression(
                right,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }

        // ── Unary operators ──
        Expression::Not(_, expr)
        | Expression::Negate(_, expr)
        | Expression::PreIncrement(_, expr)
        | Expression::PreDecrement(_, expr) => {
            extract_operations_from_expression(
                expr,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }

        // ── MemberAccess: potential state read ──
        Expression::MemberAccess(_, inner, _member) => {
            // Check if this is a state variable access (e.g., msg.sender doesn't count)
            let inner_str = expr_to_simple_string(inner);
            if state_vars.contains(&inner_str) {
                operations.push(RawOperation {
                    function: func_name.into(),
                    index: *op_index,
                    kind: OperationKind::StateRead,
                    target: inner_str,
                });
                *op_index += 1;
            }
            extract_operations_from_expression(
                inner,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }

        // ── ArraySubscript: indexed state read ──
        Expression::ArraySubscript(_, inner, index) => {
            let base = expr_to_simple_string(inner);
            if state_vars.contains(&base) {
                operations.push(RawOperation {
                    function: func_name.into(),
                    index: *op_index,
                    kind: OperationKind::StateRead,
                    target: base,
                });
                *op_index += 1;
            }
            extract_operations_from_expression(
                inner,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            if let Some(idx) = index {
                extract_operations_from_expression(
                    idx,
                    func_name,
                    state_vars,
                    interface_names,
                    operations,
                    op_index,
                );
            }
        }

        // ── Variable: check if it's a state variable read ──
        Expression::Variable(ident) => {
            if state_vars.contains(&ident.name) {
                operations.push(RawOperation {
                    function: func_name.into(),
                    index: *op_index,
                    kind: OperationKind::StateRead,
                    target: ident.name.clone(),
                });
                *op_index += 1;
            }
        }

        // ── ConditionalOperator ──
        Expression::ConditionalOperator(_, cond, then_expr, else_expr) => {
            extract_operations_from_expression(
                cond,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            extract_operations_from_expression(
                then_expr,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
            extract_operations_from_expression(
                else_expr,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }

        // ── Parenthesis ──
        Expression::Parenthesis(_, inner) => {
            extract_operations_from_expression(
                inner,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }

        // ── New ──
        Expression::New(_, inner) => {
            extract_operations_from_expression(
                inner,
                func_name,
                state_vars,
                interface_names,
                operations,
                op_index,
            );
        }

        _ => {
            // Literals, types, etc. — no operations
        }
    }
}

/// Extract a simple string representation from an expression (for state var matching).
fn expr_to_simple_string(expr: &Expression) -> String {
    match expr {
        Expression::Variable(ident) => ident.name.clone(),
        Expression::MemberAccess(_, inner, member) => {
            format!("{}.{}", expr_to_simple_string(inner), member.name)
        }
        Expression::ArraySubscript(_, inner, Some(index)) => {
            format!(
                "{}[{}]",
                expr_to_simple_string(inner),
                expr_to_simple_string(index)
            )
        }
        Expression::ArraySubscript(_, inner, None) => {
            format!("{}[]", expr_to_simple_string(inner))
        }
        _ => format!("{:?}", expr),
    }
}

// ─────────────────────────────────────────────────────────────
// Contract extraction → metadata
// ─────────────────────────────────────────────────────────────

fn extract_from_contract(
    contract: &ContractDefinition,
    code: &str,
    functions: &mut Vec<RawFunction>,
    state: &mut Vec<RawState>,
    _calls: &mut Vec<RawCall>,
    metadata: &mut AnalysisMetadata,
) {
    let contract_name = contract
        .name
        .as_ref()
        .map(|n| n.name.clone())
        .unwrap_or_else(|| "anonymous".into());

    let contract_kind = match &contract.ty {
        ContractTy::Contract(_) => "contract",
        ContractTy::Interface(_) => "interface",
        ContractTy::Abstract(_) => "abstract",
        ContractTy::Library(_) => "library",
    };

    let inheritance: Vec<String> = contract.base.iter().map(|b| base_to_string(b)).collect();

    let contract_state_set: std::collections::HashSet<String> = {
        let mut set: std::collections::HashSet<String> =
            state.iter().map(|s| s.name.clone()).collect();
        for part in &contract.parts {
            if let ContractPart::VariableDefinition(var) = part {
                if let Some(name) = var.name.as_ref().map(|n| n.name.clone()) {
                    set.insert(name);
                }
            }
        }
        set
    };

    let mut contract_functions = vec![];
    let mut contract_state_vars = vec![];

    for part in &contract.parts {
        match part {
            ContractPart::FunctionDefinition(func) => {
                let fn_name = func
                    .name
                    .as_ref()
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| match func.ty {
                        FunctionTy::Constructor => "constructor".into(),
                        FunctionTy::Fallback => "fallback".into(),
                        FunctionTy::Receive => "receive".into(),
                        FunctionTy::Modifier => "modifier".into(),
                        FunctionTy::Function => "anonymous".into(),
                    });
                contract_functions.push(fn_name);
                extract_function(
                    func,
                    code,
                    functions,
                    metadata,
                    &contract_name,
                    &contract_state_set,
                );
            }
            ContractPart::VariableDefinition(var) => {
                let var_name = var
                    .name
                    .as_ref()
                    .map(|n| n.name.clone())
                    .unwrap_or_default();
                contract_state_vars.push(var_name);
                extract_state_variable(var, state, metadata);
            }
            ContractPart::EventDefinition(event) => {
                extract_event(event, metadata);
            }
            ContractPart::ErrorDefinition(error) => {
                extract_error(error, metadata);
            }
            ContractPart::StructDefinition(s) => {
                extract_struct(s, metadata);
            }
            ContractPart::EnumDefinition(e) => {
                extract_enum(e, metadata);
            }
            ContractPart::Using(u) => {
                metadata.using_directives.push(format!("{:?}", u));
            }
            _ => {}
        }
    }

    metadata.contracts.push(ContractMeta {
        name: contract_name,
        kind: contract_kind.into(),
        inheritance,
        function_names: contract_functions,
        state_var_names: contract_state_vars,
    });
}

// ─────────────────────────────────────────────────────────────
// Function extraction → semantic + metadata
// ─────────────────────────────────────────────────────────────

fn extract_function(
    func: &FunctionDefinition,
    code: &str,
    functions: &mut Vec<RawFunction>,
    metadata: &mut AnalysisMetadata,
    contract_name: &str,
    state_vars: &std::collections::HashSet<String>,
) {
    let name = func
        .name
        .as_ref()
        .map(|n| n.name.clone())
        .unwrap_or_else(|| match func.ty {
            FunctionTy::Constructor => "constructor".into(),
            FunctionTy::Fallback => "fallback".into(),
            FunctionTy::Receive => "receive".into(),
            FunctionTy::Modifier => "modifier".into(),
            FunctionTy::Function => "anonymous".into(),
        });

    let fn_type = match func.ty {
        FunctionTy::Constructor => "constructor",
        FunctionTy::Fallback => "fallback",
        FunctionTy::Receive => "receive",
        FunctionTy::Modifier => "modifier",
        FunctionTy::Function => "function",
    };

    let mut visibility = "unknown".to_string();
    let mut mutability = "nonpayable".to_string();
    let mut fn_modifiers = vec![];
    let mut is_virtual = false;
    let mut overrides = vec![];

    for attr in &func.attributes {
        match attr {
            FunctionAttribute::Visibility(v) => {
                visibility = match v {
                    PtVisibility::Public(_) => "public",
                    PtVisibility::Private(_) => "private",
                    PtVisibility::Internal(_) => "internal",
                    PtVisibility::External(_) => "external",
                }
                .into();
            }
            FunctionAttribute::Mutability(m) => {
                mutability = match m {
                    PtMutability::Pure(_) => "pure",
                    PtMutability::View(_) => "view",
                    PtMutability::Constant(_) => "constant",
                    PtMutability::Payable(_) => "payable",
                }
                .into();
            }
            FunctionAttribute::BaseOrModifier(_, base) => {
                fn_modifiers.push(base_to_string(base));
            }
            FunctionAttribute::Virtual(_) => {
                is_virtual = true;
            }
            FunctionAttribute::Override(_, paths) => {
                for path in paths {
                    overrides.push(
                        path.identifiers
                            .iter()
                            .map(|i| i.name.clone())
                            .collect::<Vec<_>>()
                            .join("."),
                    );
                }
            }
            _ => {}
        }
    }

    let inputs: Vec<String> = func
        .params
        .iter()
        .filter_map(|p| {
            p.1.as_ref().map(|param| {
                let pname = param
                    .name
                    .as_ref()
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| "_".into());
                let ty = expr_to_type_string(&param.ty);
                format!("{}: {}", pname, ty)
            })
        })
        .collect();

    let return_types: Vec<String> = func
        .returns
        .iter()
        .filter_map(|p| {
            p.1.as_ref().map(|param| {
                let ty = expr_to_type_string(&param.ty);
                let pname = param
                    .name
                    .as_ref()
                    .map(|n| n.name.clone())
                    .unwrap_or_default();
                if pname.is_empty() {
                    ty
                } else {
                    format!("{}: {}", pname, ty)
                }
            })
        })
        .collect();

    let body = extract_body_source(func, code);

    // Virtual/override enrichment
    if is_virtual {
        fn_modifiers.push("virtual".into());
    }
    if !overrides.is_empty() {
        fn_modifiers.push(format!("override({})", overrides.join(", ")));
    }

    // Semantic layer — consumed by graph builder
    // Run the targeted arithmetic walker on the function body AST.
    // Filter out function parameter names so local variable shadowing
    // doesn't pollute state_reads_in_arithmetic.
    let param_names: std::collections::HashSet<String> = func
        .params
        .iter()
        .filter_map(|p| {
            p.1.as_ref()
                .and_then(|param| param.name.as_ref().map(|n| n.name.clone()))
        })
        .filter(|s| !s.is_empty())
        .collect();
    let effective_state_vars: std::collections::HashSet<String> = state_vars
        .iter()
        .filter(|v| !param_names.contains(v.as_str()))
        .cloned()
        .collect();

    let mut arith_ctx = ArithContext::new();
    if let Some(ref body_stmt) = func.body {
        walk_arithmetic(body_stmt, &effective_state_vars, &mut arith_ctx);
        // Detect caller-scoped state writes (balances[msg.sender] += x)
        let caller_scoped = detect_caller_scoped_writes(body_stmt, &effective_state_vars);
        if caller_scoped {
            metadata.extra.insert(
                format!("ast_caller_scoped:{}", name),
                serde_json::Value::Bool(true),
            );
        }
    }
    // Store precision-loss-ordering flag from the AST walk
    if arith_ctx.has_precision_loss_ordering {
        metadata.extra.insert(
            format!("ast_prec_loss:{}", name),
            serde_json::Value::Bool(true),
        );
    }
    // SOLIDITY PATH ONLY: AST walk is authoritative. No text fallback for
    // has_arithmetic or state_reads_in_arithmetic. The walker already detects
    // SafeMath library calls via ARITH_LIB_METHODS on FunctionCall callees.
    let ast_sria = arith_ctx.state_reads_in_arithmetic;
    // Store AST-derived data in metadata.extra (only when non-empty)
    if !ast_sria.is_empty() {
        if let Ok(val) = serde_json::to_value(&ast_sria) {
            metadata
                .extra
                .insert(format!("ast_arith_sria:{}", name), val);
        }
    }

    // Store unchecked arithmetic flag
    if arith_ctx.has_unchecked_arithmetic {
        metadata.extra.insert(
            format!("ast_unchecked_arith:{}", name),
            serde_json::Value::Bool(true),
        );
    }

    functions.push(RawFunction {
        name: name.clone(),
        contract: contract_name.to_string(),
        visibility,
        inputs,
        body,
        has_arithmetic: arith_ctx.has_arithmetic,
    });

    // Metadata layer — AST enrichment
    metadata.function_details.insert(
        name.clone(),
        FunctionMeta {
            fn_type: fn_type.into(),
            mutability,
            modifiers: fn_modifiers,
            return_types,
            execution_context: fn_type.into(), // Solidity: fn_type IS the execution context
            rust_kind: String::new(),          // Not Rust — leave empty
            container_path: name,
            body_source_mode: "AST-derived".into(), // solang-parser uses AST
            loss_of_precision: false,               // AST-derived is lossless
        },
    );
}

/// Extract function body source code from the original source using AST location offsets.
fn extract_body_source(func: &FunctionDefinition, code: &str) -> String {
    if let Some(ref body_stmt) = func.body {
        let loc = stmt_loc(body_stmt);
        match loc {
            solang_parser::pt::Loc::File(_, start, end) => {
                if start < code.len() && end <= code.len() && start <= end {
                    return code[start..end].to_string();
                }
            }
            _ => {}
        }
    }
    // Fallback: extract from function location
    match func.loc {
        solang_parser::pt::Loc::File(_, start, end) => {
            if start < code.len() && end <= code.len() && start <= end {
                return code[start..end].to_string();
            }
        }
        _ => {}
    }
    String::new()
}

/// Get the location of a statement.
fn stmt_loc(stmt: &Statement) -> solang_parser::pt::Loc {
    match stmt {
        Statement::Block { loc, .. } => *loc,
        Statement::Assembly { loc, .. } => *loc,
        Statement::Args(loc, _) => *loc,
        Statement::If(loc, _, _, _) => *loc,
        Statement::While(loc, _, _) => *loc,
        Statement::Expression(loc, _) => *loc,
        Statement::VariableDefinition(loc, _, _) => *loc,
        Statement::For(loc, _, _, _, _) => *loc,
        Statement::DoWhile(loc, _, _) => *loc,
        Statement::Continue(loc) => *loc,
        Statement::Break(loc) => *loc,
        Statement::Return(loc, _) => *loc,
        Statement::Revert(loc, _, _) => *loc,
        Statement::RevertNamedArgs(loc, _, _) => *loc,
        Statement::Emit(loc, _) => *loc,
        Statement::Try(loc, _, _, _) => *loc,
        Statement::Error(loc) => *loc,
    }
}

// ─────────────────────────────────────────────────────────────
// State variable extraction → semantic + metadata
// ─────────────────────────────────────────────────────────────

fn extract_state_variable(
    var: &VariableDefinition,
    state: &mut Vec<RawState>,
    metadata: &mut AnalysisMetadata,
) {
    let name = var
        .name
        .as_ref()
        .map(|n| n.name.clone())
        .unwrap_or_default();
    let ty = expr_to_type_string(&var.ty);

    let mut visibility = "internal".to_string();
    let mut is_constant = false;
    let mut is_immutable = false;

    for attr in &var.attrs {
        match attr {
            VariableAttribute::Visibility(v) => {
                visibility = match v {
                    PtVisibility::Public(_) => "public",
                    PtVisibility::Private(_) => "private",
                    PtVisibility::Internal(_) => "internal",
                    PtVisibility::External(_) => "external",
                }
                .into();
            }
            VariableAttribute::Constant(_) => {
                is_constant = true;
            }
            VariableAttribute::Immutable(_) => {
                is_immutable = true;
            }
            _ => {}
        }
    }

    // Semantic layer
    state.push(RawState {
        name: name.clone(),
        ty,
    });

    // Metadata layer
    metadata.state_details.insert(
        name,
        StateMeta {
            visibility,
            is_constant,
            is_immutable,
        },
    );
}

// ─────────────────────────────────────────────────────────────
// Event extraction → metadata only
// ─────────────────────────────────────────────────────────────

fn extract_event(event: &EventDefinition, metadata: &mut AnalysisMetadata) {
    let name = event
        .name
        .as_ref()
        .map(|n| n.name.clone())
        .unwrap_or_default();

    let params: Vec<String> = event
        .fields
        .iter()
        .map(|p| {
            let ty = expr_to_type_string(&p.ty);
            let pname = p.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();
            let indexed = if p.indexed { " indexed" } else { "" };
            if pname.is_empty() {
                format!("{}{}", ty, indexed)
            } else {
                format!("{}{} {}", ty, indexed, pname)
            }
        })
        .collect();

    metadata.events.push(EventMeta {
        name,
        params,
        anonymous: event.anonymous,
    });
}

// ─────────────────────────────────────────────────────────────
// Error extraction → metadata only
// ─────────────────────────────────────────────────────────────

fn extract_error(error: &ErrorDefinition, metadata: &mut AnalysisMetadata) {
    let name = error
        .name
        .as_ref()
        .map(|n| n.name.clone())
        .unwrap_or_default();

    let params: Vec<String> = error
        .fields
        .iter()
        .map(|p| {
            let ty = expr_to_type_string(&p.ty);
            let pname = p.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();
            if pname.is_empty() {
                ty
            } else {
                format!("{} {}", ty, pname)
            }
        })
        .collect();

    metadata.errors.push(ErrorMeta { name, params });
}

// ─────────────────────────────────────────────────────────────
// Struct extraction → metadata only
// ─────────────────────────────────────────────────────────────

fn extract_struct(s: &StructDefinition, metadata: &mut AnalysisMetadata) {
    let name = s.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();

    let fields: Vec<(String, String)> = s
        .fields
        .iter()
        .map(|f| {
            let fname = f.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();
            let fty = expr_to_type_string(&f.ty);
            (fname, fty)
        })
        .collect();

    metadata.structs.push(StructMeta { name, fields });
}

// ─────────────────────────────────────────────────────────────
// Enum extraction → metadata only
// ─────────────────────────────────────────────────────────────

fn extract_enum(e: &EnumDefinition, metadata: &mut AnalysisMetadata) {
    let name = e.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();

    let values: Vec<String> = e
        .values
        .iter()
        .filter_map(|v| v.as_ref().map(|i| i.name.clone()))
        .collect();

    metadata.enums.push(EnumMeta { name, values });
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

/// Convert a base contract reference to a string.
fn base_to_string(base: &Base) -> String {
    let name = base
        .name
        .identifiers
        .iter()
        .map(|i| i.name.clone())
        .collect::<Vec<_>>()
        .join(".");

    if let Some(ref args) = base.args {
        let arg_strs: Vec<String> = args.iter().map(|a| expr_to_type_string(a)).collect();
        format!("{}({})", name, arg_strs.join(", "))
    } else {
        name
    }
}

/// Convert an expression to a type string representation.
fn expr_to_type_string(expr: &Expression) -> String {
    match expr {
        Expression::Type(_, ty) => match ty {
            solang_parser::pt::Type::Address => "address".into(),
            solang_parser::pt::Type::AddressPayable => "address payable".into(),
            solang_parser::pt::Type::Bool => "bool".into(),
            solang_parser::pt::Type::String => "string".into(),
            solang_parser::pt::Type::Int(n) => format!("int{}", n),
            solang_parser::pt::Type::Uint(n) => format!("uint{}", n),
            solang_parser::pt::Type::Bytes(n) => format!("bytes{}", n),
            solang_parser::pt::Type::DynamicBytes => "bytes".into(),
            solang_parser::pt::Type::Rational => "rational".into(),
            solang_parser::pt::Type::Payable => "payable".into(),
            solang_parser::pt::Type::Mapping { key, value, .. } => {
                let key_str = expr_to_type_string(key);
                let val_str = expr_to_type_string(value);
                format!("mapping({} => {})", key_str, val_str)
            }
            solang_parser::pt::Type::Function {
                params, returns, ..
            } => {
                let param_strs: Vec<String> = params
                    .iter()
                    .filter_map(|p| p.1.as_ref().map(|pp| expr_to_type_string(&pp.ty)))
                    .collect();
                let ret_str = if let Some((ret_params, _)) = returns {
                    let ret_strs: Vec<String> = ret_params
                        .iter()
                        .filter_map(|p| p.1.as_ref().map(|pp| expr_to_type_string(&pp.ty)))
                        .collect();
                    format!(" returns ({})", ret_strs.join(", "))
                } else {
                    String::new()
                };
                format!("function({}){}", param_strs.join(", "), ret_str)
            }
        },
        Expression::Variable(ident) => ident.name.clone(),
        Expression::MemberAccess(_, inner, member) => {
            format!("{}.{}", expr_to_type_string(inner), member.name)
        }
        Expression::ArraySubscript(_, inner, index) => {
            if let Some(idx) = index {
                format!(
                    "{}[{}]",
                    expr_to_type_string(inner),
                    expr_to_type_string(idx)
                )
            } else {
                format!("{}[]", expr_to_type_string(inner))
            }
        }
        Expression::FunctionCall(_, inner, args) => {
            let arg_strs: Vec<String> = args.iter().map(|a| expr_to_type_string(a)).collect();
            format!("{}({})", expr_to_type_string(inner), arg_strs.join(", "))
        }
        Expression::New(_, inner) => {
            format!("new {}", expr_to_type_string(inner))
        }
        Expression::Parenthesis(_, inner) => {
            format!("({})", expr_to_type_string(inner))
        }
        Expression::NumberLiteral(_, val, _, _) => val.clone(),
        Expression::StringLiteral(lits) => lits
            .iter()
            .map(|l| l.string.clone())
            .collect::<Vec<_>>()
            .join(""),
        Expression::BoolLiteral(_, val) => val.to_string(),
        Expression::HexNumberLiteral(_, val, _) => val.clone(),
        Expression::AddressLiteral(_, val) => val.clone(),
        _ => format!("{:?}", expr),
    }
}

// ─────────────────────────────────────────────────────────────
// Phase 7.3: Yul Assembly Extraction
// ─────────────────────────────────────────────────────────────

/// Extract calls from a Yul block by walking the AST.
///
/// Returns (target, CallKind) pairs for security-relevant operations.
fn extract_calls_from_yul_block(block: &solang_parser::pt::YulBlock) -> Vec<(String, CallKind)> {
    let mut calls = vec![];
    extract_calls_from_yul_statements(&block.statements, &mut calls);
    calls
}

/// Recursively extract calls from Yul statements.
fn extract_calls_from_yul_statements(
    statements: &[solang_parser::pt::YulStatement],
    calls: &mut Vec<(String, CallKind)>,
) {
    for stmt in statements {
        extract_calls_from_yul_statement(stmt, calls);
    }
}

/// Extract calls from a single Yul statement.
fn extract_calls_from_yul_statement(
    stmt: &solang_parser::pt::YulStatement,
    calls: &mut Vec<(String, CallKind)>,
) {
    use solang_parser::pt::YulStatement;

    match stmt {
        YulStatement::FunctionCall(fc) => {
            let name = &fc.id.name;
            if let Some(kind) = classify_yul_call(name) {
                calls.push((name.clone(), kind));
            }
            for arg in &fc.arguments {
                extract_calls_from_yul_expression(arg, calls);
            }
        }
        YulStatement::Block(block) => {
            extract_calls_from_yul_statements(&block.statements, calls);
        }
        YulStatement::If(_, cond, body) => {
            extract_calls_from_yul_expression(cond, calls);
            extract_calls_from_yul_statements(&body.statements, calls);
        }
        YulStatement::For(yul_for) => {
            extract_calls_from_yul_statements(&yul_for.init_block.statements, calls);
            extract_calls_from_yul_expression(&yul_for.condition, calls);
            extract_calls_from_yul_statements(&yul_for.post_block.statements, calls);
            extract_calls_from_yul_statements(&yul_for.execution_block.statements, calls);
        }
        YulStatement::Switch(switch) => {
            extract_calls_from_yul_expression(&switch.condition, calls);
            for case in &switch.cases {
                match case {
                    solang_parser::pt::YulSwitchOptions::Case(_, expr, block) => {
                        extract_calls_from_yul_expression(expr, calls);
                        extract_calls_from_yul_statements(&block.statements, calls);
                    }
                    solang_parser::pt::YulSwitchOptions::Default(_, block) => {
                        extract_calls_from_yul_statements(&block.statements, calls);
                    }
                }
            }
        }
        YulStatement::Assign(_, exprs, value) => {
            for expr in exprs {
                extract_calls_from_yul_expression(expr, calls);
            }
            extract_calls_from_yul_expression(value, calls);
        }
        YulStatement::VariableDeclaration(_, _, value) => {
            if let Some(val) = value {
                extract_calls_from_yul_expression(val, calls);
            }
        }
        YulStatement::FunctionDefinition(func) => {
            extract_calls_from_yul_statements(&func.body.statements, calls);
        }
        _ => {}
    }
}

/// Extract calls from a Yul expression.
fn extract_calls_from_yul_expression(
    expr: &solang_parser::pt::YulExpression,
    calls: &mut Vec<(String, CallKind)>,
) {
    use solang_parser::pt::YulExpression;

    match expr {
        YulExpression::FunctionCall(fc) => {
            let name = &fc.id.name;
            if let Some(kind) = classify_yul_call(name) {
                calls.push((name.clone(), kind));
            }
            for arg in &fc.arguments {
                extract_calls_from_yul_expression(arg, calls);
            }
        }
        _ => {
            // Other expressions (variables, literals, etc.) don't contain calls
        }
    }
}

/// Classify a Yul function name as a security-relevant call type.
fn classify_yul_call(name: &str) -> Option<CallKind> {
    match name {
        "delegatecall" | "call" | "staticcall" | "callcode" => Some(CallKind::External),
        "create" | "create2" => Some(CallKind::External),
        "selfdestruct" => Some(CallKind::External),
        _ => None,
    }
}

/// Extract operations from a Yul block for execution ordering.
///
/// Emits ExternalCall operations for security-relevant Yul instructions.
fn extract_operations_from_yul_block(
    block: &solang_parser::pt::YulBlock,
    func_name: &str,
    state_vars: &std::collections::HashSet<String>,
    operations: &mut Vec<RawOperation>,
    op_index: &mut usize,
) {
    extract_operations_from_yul_statements(
        &block.statements,
        func_name,
        state_vars,
        operations,
        op_index,
    );
}

/// Recursively extract operations from Yul statements.
fn extract_operations_from_yul_statements(
    statements: &[solang_parser::pt::YulStatement],
    func_name: &str,
    state_vars: &std::collections::HashSet<String>,
    operations: &mut Vec<RawOperation>,
    op_index: &mut usize,
) {
    for stmt in statements {
        extract_operations_from_yul_statement(stmt, func_name, state_vars, operations, op_index);
    }
}

/// Extract operations from a single Yul statement.
#[allow(clippy::only_used_in_recursion)]
fn extract_operations_from_yul_statement(
    stmt: &solang_parser::pt::YulStatement,
    func_name: &str,
    state_vars: &std::collections::HashSet<String>,
    operations: &mut Vec<RawOperation>,
    op_index: &mut usize,
) {
    use solang_parser::pt::YulStatement;

    match stmt {
        YulStatement::FunctionCall(fc) => {
            let name = &fc.id.name;

            match name.as_str() {
                "delegatecall" | "call" | "staticcall" | "callcode" | "create" | "create2"
                | "selfdestruct" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::ExternalCall,
                        target: name.clone(),
                    });
                    *op_index += 1;
                }
                "sstore" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::StateWrite,
                        target: "assembly_sstore".into(),
                    });
                    *op_index += 1;
                }
                "sload" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::StateRead,
                        target: "assembly_sload".into(),
                    });
                    *op_index += 1;
                }
                _ => {}
            }

            for arg in &fc.arguments {
                extract_operations_from_yul_expression(
                    arg, func_name, state_vars, operations, op_index,
                );
            }
        }
        YulStatement::Block(block) => {
            extract_operations_from_yul_statements(
                &block.statements,
                func_name,
                state_vars,
                operations,
                op_index,
            );
        }
        YulStatement::If(_, cond, body) => {
            extract_operations_from_yul_expression(
                cond, func_name, state_vars, operations, op_index,
            );
            extract_operations_from_yul_statements(
                &body.statements,
                func_name,
                state_vars,
                operations,
                op_index,
            );
        }
        YulStatement::For(yul_for) => {
            extract_operations_from_yul_statements(
                &yul_for.init_block.statements,
                func_name,
                state_vars,
                operations,
                op_index,
            );
            extract_operations_from_yul_expression(
                &yul_for.condition,
                func_name,
                state_vars,
                operations,
                op_index,
            );
            extract_operations_from_yul_statements(
                &yul_for.post_block.statements,
                func_name,
                state_vars,
                operations,
                op_index,
            );
            extract_operations_from_yul_statements(
                &yul_for.execution_block.statements,
                func_name,
                state_vars,
                operations,
                op_index,
            );
        }
        YulStatement::Switch(switch) => {
            extract_operations_from_yul_expression(
                &switch.condition,
                func_name,
                state_vars,
                operations,
                op_index,
            );
            for case in &switch.cases {
                match case {
                    solang_parser::pt::YulSwitchOptions::Case(_, expr, block) => {
                        extract_operations_from_yul_expression(
                            expr, func_name, state_vars, operations, op_index,
                        );
                        extract_operations_from_yul_statements(
                            &block.statements,
                            func_name,
                            state_vars,
                            operations,
                            op_index,
                        );
                    }
                    solang_parser::pt::YulSwitchOptions::Default(_, block) => {
                        extract_operations_from_yul_statements(
                            &block.statements,
                            func_name,
                            state_vars,
                            operations,
                            op_index,
                        );
                    }
                }
            }
        }
        YulStatement::Assign(_, exprs, value) => {
            for expr in exprs {
                extract_operations_from_yul_expression(
                    expr, func_name, state_vars, operations, op_index,
                );
            }
            extract_operations_from_yul_expression(
                value, func_name, state_vars, operations, op_index,
            );
        }
        YulStatement::VariableDeclaration(_, _, value) => {
            if let Some(val) = value {
                extract_operations_from_yul_expression(
                    val, func_name, state_vars, operations, op_index,
                );
            }
        }
        YulStatement::FunctionDefinition(func) => {
            extract_operations_from_yul_statements(
                &func.body.statements,
                func_name,
                state_vars,
                operations,
                op_index,
            );
        }
        _ => {}
    }
}

/// Extract operations from a Yul expression.
#[allow(clippy::only_used_in_recursion)]
fn extract_operations_from_yul_expression(
    expr: &solang_parser::pt::YulExpression,
    func_name: &str,
    state_vars: &std::collections::HashSet<String>,
    operations: &mut Vec<RawOperation>,
    op_index: &mut usize,
) {
    use solang_parser::pt::YulExpression;

    match expr {
        YulExpression::FunctionCall(fc) => {
            let name = &fc.id.name;
            match name.as_str() {
                "delegatecall" | "call" | "staticcall" | "callcode" | "create" | "create2"
                | "selfdestruct" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::ExternalCall,
                        target: name.clone(),
                    });
                    *op_index += 1;
                }
                "sstore" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::StateWrite,
                        target: "assembly_sstore".into(),
                    });
                    *op_index += 1;
                }
                "sload" => {
                    operations.push(RawOperation {
                        function: func_name.into(),
                        index: *op_index,
                        kind: OperationKind::StateRead,
                        target: "assembly_sload".into(),
                    });
                    *op_index += 1;
                }
                _ => {}
            }
            for arg in &fc.arguments {
                extract_operations_from_yul_expression(
                    arg, func_name, state_vars, operations, op_index,
                );
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_contract() {
        let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"#;
        let program = parse(code);
        assert_eq!(program.functions.len(), 3);
        assert!(program.state.len() >= 2);
        assert_eq!(program.metadata.contracts.len(), 1);
        assert_eq!(program.metadata.contracts[0].name, "Vault");
        assert_eq!(program.metadata.contracts[0].kind, "contract");

        // Check function metadata
        let constructor_meta = program
            .metadata
            .function_details
            .get("constructor")
            .unwrap();
        assert_eq!(constructor_meta.fn_type, "constructor");

        let deposit_meta = program.metadata.function_details.get("deposit").unwrap();
        assert_eq!(deposit_meta.mutability, "payable");
        let deposit = program
            .functions
            .iter()
            .find(|f| f.name == "deposit")
            .unwrap();
        assert_eq!(deposit.visibility, "public");
    }

    #[test]
    fn test_inheritance() {
        let code = r#"
contract Base {
    function foo() public virtual {}
}

contract Child is Base {
    function foo() public override {}
}
"#;
        let program = parse(code);
        assert_eq!(program.metadata.contracts.len(), 2);

        let child = program
            .metadata
            .contracts
            .iter()
            .find(|c| c.name == "Child")
            .unwrap();
        assert!(child.inheritance.contains(&"Base".to_string()));
    }

    #[test]
    fn test_modifiers() {
        let code = r#"
contract Ownable {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function changeOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}
"#;
        let program = parse(code);
        assert_eq!(program.functions.len(), 2);

        let change_owner_meta = program
            .metadata
            .function_details
            .get("changeOwner")
            .unwrap();
        assert!(change_owner_meta
            .modifiers
            .contains(&"onlyOwner".to_string()));
    }

    #[test]
    fn test_events_and_errors() {
        let code = r#"
contract Token {
    event Transfer(address indexed from, address indexed to, uint256 amount);
    error InsufficientBalance(uint256 available, uint256 required);

    function transfer(address to, uint256 amount) public {
        emit Transfer(msg.sender, to, amount);
    }
}
"#;
        let program = parse(code);
        assert_eq!(program.metadata.events.len(), 1);
        assert_eq!(program.metadata.events[0].name, "Transfer");
        assert_eq!(program.metadata.events[0].params.len(), 3);
        assert!(program.metadata.events[0].params[0].contains("indexed"));

        assert_eq!(program.metadata.errors.len(), 1);
        assert_eq!(program.metadata.errors[0].name, "InsufficientBalance");
    }

    #[test]
    fn test_structs_and_enums() {
        let code = r#"
contract Market {
    enum Status { Active, Paused, Closed }

    struct Order {
        address trader;
        uint256 amount;
        uint256 price;
    }

    Status public status;
}
"#;
        let program = parse(code);
        assert_eq!(program.metadata.enums.len(), 1);
        assert_eq!(program.metadata.enums[0].name, "Status");
        assert_eq!(program.metadata.enums[0].values.len(), 3);

        assert_eq!(program.metadata.structs.len(), 1);
        assert_eq!(program.metadata.structs[0].name, "Order");
        assert_eq!(program.metadata.structs[0].fields.len(), 3);
    }

    #[test]
    fn test_interface() {
        let code = r#"
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}
"#;
        let program = parse(code);
        assert_eq!(program.metadata.contracts.len(), 1);
        assert_eq!(program.metadata.contracts[0].kind, "interface");
        assert_eq!(program.functions.len(), 3);

        let transfer = program
            .functions
            .iter()
            .find(|f| f.name == "transfer")
            .unwrap();
        assert_eq!(transfer.visibility, "external");

        let transfer_meta = program.metadata.function_details.get("transfer").unwrap();
        assert_eq!(transfer_meta.return_types.len(), 1);
    }

    #[test]
    fn test_abstract_and_library() {
        let code = r#"
abstract contract Base {
    function foo() public virtual returns (uint256);
}

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}
"#;
        let program = parse(code);
        assert_eq!(program.metadata.contracts.len(), 2);

        let base = program
            .metadata
            .contracts
            .iter()
            .find(|c| c.name == "Base")
            .unwrap();
        assert_eq!(base.kind, "abstract");

        let lib = program
            .metadata
            .contracts
            .iter()
            .find(|c| c.name == "SafeMath")
            .unwrap();
        assert_eq!(lib.kind, "library");
    }

    #[test]
    fn test_fallback_and_receive() {
        let code = r#"
contract Receiver {
    event Received(address sender, uint256 amount);

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    fallback() external payable {
        emit Received(msg.sender, msg.value);
    }
}
"#;
        let program = parse(code);
        assert_eq!(program.functions.len(), 2);

        let receive_meta = program.metadata.function_details.get("receive").unwrap();
        assert_eq!(receive_meta.fn_type, "receive");
        assert_eq!(receive_meta.mutability, "payable");

        let fallback_meta = program.metadata.function_details.get("fallback").unwrap();
        assert_eq!(fallback_meta.fn_type, "fallback");
        assert_eq!(fallback_meta.mutability, "payable");
    }

    #[test]
    fn test_mappings() {
        let code = r#"
contract Registry {
    mapping(address => mapping(uint256 => bool)) public approvals;
    mapping(bytes32 => address) public nameToAddress;
}
"#;
        let program = parse(code);
        assert!(program.state.len() >= 2);

        let approvals = program
            .state
            .iter()
            .find(|s| s.name == "approvals")
            .unwrap();
        assert!(approvals.ty.contains("mapping"));

        let approvals_meta = program.metadata.state_details.get("approvals").unwrap();
        assert_eq!(approvals_meta.visibility, "public");
    }

    #[test]
    fn test_body_source_extraction() {
        let code = r#"
contract Test {
    function dangerous() public {
        (bool success, ) = msg.sender.call{value: 100}("");
        require(success);
    }
}
"#;
        let program = parse(code);
        let dangerous = program
            .functions
            .iter()
            .find(|f| f.name == "dangerous")
            .unwrap();
        assert!(
            dangerous.body.contains(".call") || dangerous.body.contains("msg.sender"),
            "Body should contain source code, got: {}",
            dangerous.body
        );
    }

    // ── Phase 6.1: AST-based call detection tests ──

    #[test]
    fn test_interface_call_detection() {
        // This is the mango-markets pattern
        let code = r#"
interface IOracle {
    function getSpotPrice() external view returns (uint256);
}

contract MangoMarkets {
    address public oracle;

    function borrow(uint256 amount) external {
        uint256 price = IOracle(oracle).getSpotPrice();
    }
}
"#;
        let program = parse(code);

        // Should detect the interface call
        let borrow_calls: Vec<_> = program
            .calls
            .iter()
            .filter(|c| c.from == "borrow")
            .collect();

        assert!(
            !borrow_calls.is_empty(),
            "Should detect IOracle(oracle).getSpotPrice() as a call"
        );

        let interface_call = borrow_calls
            .iter()
            .find(|c| c.to.contains("interface") && c.to.contains("IOracle"));
        assert!(
            interface_call.is_some(),
            "Should detect interface:IOracle.getSpotPrice, got: {:?}",
            borrow_calls
        );
    }

    #[test]
    fn test_low_level_call_still_detected() {
        let code = r#"
contract Test {
    function externalCall() public {
        (bool success, ) = msg.sender.call{value: 100}("");
    }
    function delegateCall() public {
        (bool success, ) = msg.sender.delegatecall("");
    }
    function staticCall() public view {
        (bool success, ) = msg.sender.staticcall("");
    }
    function transferCall() public {
        payable(msg.sender).transfer(100);
    }
}
"#;
        let program = parse(code);

        assert!(
            program
                .calls
                .iter()
                .any(|c| c.from == "externalCall" && c.kind == CallKind::External),
            "Should detect .call{{value:}}"
        );
        assert!(
            program
                .calls
                .iter()
                .any(|c| c.from == "delegateCall" && c.to == "delegate"),
            "Should detect .delegatecall()"
        );
        assert!(
            program
                .calls
                .iter()
                .any(|c| c.from == "staticCall" && c.to == "static"),
            "Should detect .staticcall()"
        );
        assert!(
            program
                .calls
                .iter()
                .any(|c| c.from == "transferCall" && c.to == "transfer"),
            "Should detect .transfer()"
        );
    }

    #[cfg_attr(
        not(feature = "corpus"),
        ignore = "requires corpus data at corpus/known-exploits/ (gitignored); run with --features corpus"
    )]
    #[test]
    fn test_mango_markets_full() {
        // Parse the actual mango-markets exploit source
        let code = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("corpus/known-exploits/oracle-manipulation/mango-markets/source.sol"),
        )
        .unwrap();

        let program = parse(&code);

        // Should detect IOracle(oracle).getSpotPrice() in borrow()
        let borrow_calls: Vec<_> = program
            .calls
            .iter()
            .filter(|c| c.from == "borrow")
            .collect();

        assert!(
            borrow_calls
                .iter()
                .any(|c| c.to.contains("interface") && c.to.contains("IOracle")),
            "mango-markets: Should detect IOracle interface call in borrow(), got: {:?}",
            borrow_calls
        );

        // Should also detect in liquidate()
        let liquidate_calls: Vec<_> = program
            .calls
            .iter()
            .filter(|c| c.from == "liquidate")
            .collect();

        assert!(
            liquidate_calls
                .iter()
                .any(|c| c.to.contains("interface") && c.to.contains("IOracle")),
            "mango-markets: Should detect IOracle interface call in liquidate(), got: {:?}",
            liquidate_calls
        );
    }

    #[test]
    fn test_no_false_positive_on_non_interface_calls() {
        let code = r#"
contract Test {
    uint256 public x;

    function foo() public {
        x = 42;
        uint256 y = x + 1;
        require(y > 0);
    }
}
"#;
        let program = parse(code);

        // Should not detect any external calls
        let external_calls: Vec<_> = program
            .calls
            .iter()
            .filter(|c| c.kind == CallKind::External)
            .collect();

        assert!(
            external_calls.is_empty(),
            "Should not detect external calls in pure state operations, got: {:?}",
            external_calls
        );
    }

    #[test]
    fn test_nested_interface_call() {
        let code = r#"
interface IPriceFeed {
    function getPrice(address token) external view returns (uint256);
}

interface IOracle {
    function getSpotPrice() external view returns (uint256);
}

contract Test {
    address public oracle;
    address public priceFeed;

    function complex() external {
        uint256 price1 = IOracle(oracle).getSpotPrice();
        uint256 price2 = IPriceFeed(priceFeed).getPrice(address(this));
    }
}
"#;
        let program = parse(code);

        let complex_calls: Vec<_> = program
            .calls
            .iter()
            .filter(|c| c.from == "complex")
            .collect();

        assert!(
            complex_calls.iter().any(|c| c.to.contains("IOracle")),
            "Should detect IOracle call"
        );
        assert!(
            complex_calls.iter().any(|c| c.to.contains("IPriceFeed")),
            "Should detect IPriceFeed call"
        );
    }

    #[test]
    fn test_metadata_isolation() {
        let code = r#"
contract Test {
    function foo() public payable onlyOwner returns (uint256) {
        return 42;
    }
}
"#;
        let program = parse(code);
        let foo = &program.functions[0];

        assert_eq!(foo.name, "foo");
        assert_eq!(foo.visibility, "public");

        let meta = program.metadata.function_details.get("foo").unwrap();
        assert_eq!(meta.mutability, "payable");
        assert_eq!(meta.fn_type, "function");
    }

    #[test]
    fn test_operations_extraction() {
        let code = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
"#;
        let program = parse(code);

        let withdraw_ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == "withdraw")
            .collect();
        for op in &withdraw_ops {
            eprintln!("  [{}] {:?} -> {}", op.index, op.kind, op.target);
        }

        // Should have operations for require, .call, and balances write
        assert!(
            !program.operations.is_empty(),
            "Should extract operations, got: {:?}",
            program.operations
        );

        let withdraw_ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == "withdraw")
            .collect();

        // Should have authority check (require), external call, and state write
        assert!(
            withdraw_ops
                .iter()
                .any(|o| o.kind == OperationKind::AuthorityCheck),
            "Should detect require as authority check"
        );
        assert!(
            withdraw_ops
                .iter()
                .any(|o| o.kind == OperationKind::ExternalCall),
            "Should detect .call as external call"
        );
        assert!(
            withdraw_ops
                .iter()
                .any(|o| o.kind == OperationKind::StateWrite),
            "Should detect balances write as state write"
        );
    }

    #[test]
    fn test_reentrant_pattern_operations() {
        // This is the exact pattern from the adversarial test
        let code = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() external {
        (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
"#;
        let program = parse(code);

        let withdraw_ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == "withdraw")
            .collect();

        eprintln!("Reentrant pattern operations:");
        for op in &withdraw_ops {
            eprintln!("  [{}] {:?} -> {}", op.index, op.kind, op.target);
        }

        // Must have a StateRead for balances (from value expression)
        let has_read = withdraw_ops
            .iter()
            .any(|o| o.kind == OperationKind::StateRead && o.target == "balances");
        assert!(has_read, "Should detect balances read in value expression");

        // Must have ExternalCall
        let has_ext = withdraw_ops
            .iter()
            .any(|o| o.kind == OperationKind::ExternalCall);
        assert!(has_ext, "Should detect external call");

        // Must have StateWrite for balances
        let has_write = withdraw_ops
            .iter()
            .any(|o| o.kind == OperationKind::StateWrite && o.target == "balances");
        assert!(has_write, "Should detect balances write");

        // Critical: StateRead must come BEFORE ExternalCall which comes BEFORE StateWrite
        let read_idx = withdraw_ops
            .iter()
            .find(|o| o.kind == OperationKind::StateRead && o.target == "balances")
            .map(|o| o.index)
            .unwrap();
        let ext_idx = withdraw_ops
            .iter()
            .find(|o| o.kind == OperationKind::ExternalCall)
            .map(|o| o.index)
            .unwrap();
        let write_idx = withdraw_ops
            .iter()
            .find(|o| o.kind == OperationKind::StateWrite && o.target == "balances")
            .map(|o| o.index)
            .unwrap();

        assert!(
            read_idx < ext_idx,
            "StateRead ({}) must come before ExternalCall ({})",
            read_idx,
            ext_idx
        );
        assert!(
            ext_idx < write_idx,
            "ExternalCall ({}) must come before StateWrite ({})",
            ext_idx,
            write_idx
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Phase 7.3: Assembly Call Extraction Tests
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_assembly_delegatecall_detected() {
        let code = r#"
contract Proxy {
    address public implementation;

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
"#;
        let program = parse(code);

        // Should detect delegatecall in assembly
        let fallback_ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == "fallback")
            .collect();

        let has_delegatecall = fallback_ops
            .iter()
            .any(|o| o.kind == OperationKind::ExternalCall && o.target == "delegatecall");

        assert!(
            has_delegatecall,
            "Should detect delegatecall in assembly, got ops: {:?}",
            fallback_ops
        );
    }

    #[test]
    fn test_assembly_call_detected() {
        let code = r#"
contract Test {
    function test() public {
        assembly {
            let result := call(gas(), addr, 0, 0, 0, 0, 0)
        }
    }
}
"#;
        let program = parse(code);

        let test_ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == "test")
            .collect();

        let has_call = test_ops
            .iter()
            .any(|o| o.kind == OperationKind::ExternalCall && o.target == "call");

        assert!(has_call, "Should detect call in assembly");
    }

    #[test]
    fn test_assembly_sstore_detected() {
        let code = r#"
contract Test {
    function test() public {
        assembly {
            sstore(0, 42)
        }
    }
}
"#;
        let program = parse(code);

        let test_ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == "test")
            .collect();

        let has_sstore = test_ops
            .iter()
            .any(|o| o.kind == OperationKind::StateWrite && o.target == "assembly_sstore");

        assert!(has_sstore, "Should detect sstore in assembly");
    }

    #[test]
    fn test_assembly_sload_detected() {
        let code = r#"
contract Test {
    function test() public {
        assembly {
            let val := sload(0)
        }
    }
}
"#;
        let program = parse(code);

        let test_ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == "test")
            .collect();

        let has_sload = test_ops
            .iter()
            .any(|o| o.kind == OperationKind::StateRead && o.target == "assembly_sload");

        assert!(has_sload, "Should detect sload in assembly");
    }

    #[test]
    fn test_assembly_create2_detected() {
        let code = r#"
contract Test {
    function test() public {
        assembly {
            let addr := create2(0, 0, 0, 0)
        }
    }
}
"#;
        let program = parse(code);

        let test_ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == "test")
            .collect();

        let has_create2 = test_ops
            .iter()
            .any(|o| o.kind == OperationKind::ExternalCall && o.target == "create2");

        assert!(has_create2, "Should detect create2 in assembly");
    }

    #[test]
    fn test_assembly_selfdestruct_detected() {
        let code = r#"
contract Test {
    function test() public {
        assembly {
            selfdestruct(0)
        }
    }
}
"#;
        let program = parse(code);

        let test_ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == "test")
            .collect();

        let has_selfdestruct = test_ops
            .iter()
            .any(|o| o.kind == OperationKind::ExternalCall && o.target == "selfdestruct");

        assert!(has_selfdestruct, "Should detect selfdestruct in assembly");
    }

    #[test]
    fn test_assembly_deterministic() {
        let code = r#"
contract Proxy {
    address public implementation;

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
        }
    }
}
"#;
        let p1 = parse(code);
        let p2 = parse(code);
        let p3 = parse(code);

        let ops1: Vec<_> = p1.operations.iter().collect();
        let ops2: Vec<_> = p2.operations.iter().collect();
        let ops3: Vec<_> = p3.operations.iter().collect();

        assert_eq!(ops1, ops2);
        assert_eq!(ops2, ops3);
    }

    #[test]
    fn test_assembly_unsupported_instruction_ignored() {
        let code = r#"
contract Test {
    function test() public {
        assembly {
            let x := add(1, 2)
            let y := mul(x, 3)
            let z := sub(y, 1)
        }
    }
}
"#;
        let program = parse(code);

        let test_ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == "test")
            .collect();

        // Arithmetic operations should NOT produce operations
        assert!(
            test_ops.is_empty(),
            "Unsupported assembly instructions should be ignored, got: {:?}",
            test_ops
        );
    }
}
