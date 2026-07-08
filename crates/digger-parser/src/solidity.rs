use crate::model::*;
use regex::Regex;

pub fn parse(code: &str) -> RawProgram {
    let Ok(fn_regex) = Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\(") else {
        return RawProgram::default();
    };
    let Ok(state_regex) = Regex::new(
        r"(uint\d*|address|bool|mapping|bytes\d*|string)\s+(?:public\s+|private\s+|internal\s+)?([a-zA-Z0-9_]+)",
    ) else {
        return RawProgram::default();
    };
    let Ok(call_regex) = Regex::new(r"\.(call|delegatecall|staticcall)\s*[\(\{]") else {
        return RawProgram::default();
    };

    let mut functions = vec![];
    let mut state = vec![];
    let mut calls = vec![];

    for cap in fn_regex.captures_iter(code) {
        functions.push(RawFunction {
            name: cap[1].to_string(),
            visibility: "unknown".into(),
            inputs: vec![],
            body: "".into(),
            ..Default::default()
        });
    }

    for cap in state_regex.captures_iter(code) {
        state.push(RawState {
            ty: cap[1].to_string(),
            name: cap[2].to_string(),
            ..Default::default()
        });
    }

    if call_regex.is_match(code) {
        calls.push(RawCall {
            from: "contract".into(),
            to: "external".into(),
            kind: digger_ir::CallKind::External,
        });
    }

    RawProgram {
        functions,
        state,
        calls,
        source: code.to_string(),
        ..Default::default()
    }
}
