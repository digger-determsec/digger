use digger_ir::*;
use digger_parser::model::*;

pub fn build(program: &RawProgram) -> Vec<Edge> {
    let mut edges = vec![];

    for call in &program.calls {
        let mut flags = vec![];

        if call.to.contains("cpi") {
            flags.push("cpi".to_string());
        }
        if call.to.contains("external") {
            flags.push("external_call".to_string());
        }
        if call.to.contains("oracle") {
            flags.push("oracle_dependency".to_string());
        }

        edges.push(Edge::External(ExternalCallEdge {
            function: call.from.clone(),
            target: call.to.clone(),
            risk_flags: flags,
        }));
    }

    // Detect CPI patterns in function bodies
    for f in &program.functions {
        if f.body.contains("invoke_signed") {
            edges.push(Edge::External(ExternalCallEdge {
                function: f.name.clone(),
                target: "invoke_signed".into(),
                risk_flags: vec!["cpi".into(), "signed".into()],
            }));
        } else if f.body.contains("invoke(") {
            edges.push(Edge::External(ExternalCallEdge {
                function: f.name.clone(),
                target: "invoke".into(),
                risk_flags: vec!["cpi".into()],
            }));
        }
    }

    edges
}
