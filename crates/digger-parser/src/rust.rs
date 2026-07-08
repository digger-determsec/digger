use crate::model::*;

pub fn parse(code: &str) -> RawProgram {
    let mut functions = vec![];

    for line in code.lines() {
        let line = line.trim();

        if line.starts_with("fn ") {
            let name = line.split_whitespace().nth(1).unwrap_or("unknown");

            functions.push(RawFunction {
                name: name.replace("(", ""),
                visibility: "private".into(),
                inputs: vec![],
                body: line.to_string(),
                ..Default::default()
            });
        }

        if line.starts_with("pub fn ") {
            let name = line.split_whitespace().nth(2).unwrap_or("unknown");

            functions.push(RawFunction {
                name: name.replace("(", ""),
                visibility: "public".into(),
                inputs: vec![],
                body: line.to_string(),
                ..Default::default()
            });
        }
    }

    RawProgram {
        functions,
        state: vec![],
        calls: vec![],
        source: code.to_string(),
        ..Default::default()
    }
}
