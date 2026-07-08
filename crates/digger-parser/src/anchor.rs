use crate::model::*;

pub fn parse(code: &str) -> RawProgram {
    let mut functions = vec![];
    let mut state = vec![];
    let mut calls = vec![];

    for line in code.lines() {
        let line = line.trim();

        // instruction handlers: pub fn name(...)
        if line.starts_with("pub fn") {
            let name = line
                .split_whitespace()
                .nth(2)
                .unwrap_or("unknown")
                .replace("(", "");

            functions.push(RawFunction {
                name,
                visibility: "public".into(),
                inputs: vec![],
                body: line.to_string(),
                ..Default::default()
            });
        }

        // account structs: #[account] or #[account(...)]
        if line.contains("#[account") {
            state.push(RawState {
                name: "account".into(),
                ty: "anchor_account".into(),
                ..Default::default()
            });
        }

        // CPI detection
        if line.contains("invoke") || line.contains("invoke_signed") {
            calls.push(RawCall {
                from: "anchor_program".into(),
                to: "cpi".into(),
                kind: digger_ir::CallKind::CrossProgram,
            });
        }

        // CpiContext
        if line.contains("CpiContext") {
            calls.push(RawCall {
                from: "anchor_program".into(),
                to: "cpi_context".into(),
                kind: digger_ir::CallKind::CrossProgram,
            });
        }
    }

    RawProgram {
        functions,
        state,
        calls,
        source: code.to_string(),
        ..Default::default()
    }
}
