use crate::analysis::state_access;
use digger_ir::*;
use digger_parser::model::*;

pub fn build(program: &RawProgram) -> Vec<Edge> {
    let result = state_access::analyze_state_access(program);

    state_access::to_state_edges(&result)
        .into_iter()
        .map(Edge::State)
        .collect()
}
