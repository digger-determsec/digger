use digger_ir::*;
use digger_parser::model::*;
use std::collections::{BTreeMap, BTreeSet};

pub fn build(program: &RawProgram) -> Vec<Edge> {
    let mut edges = vec![];

    for call in &program.calls {
        edges.push(Edge::Call(CallEdge {
            from: call.from.clone(),
            to: call.to.clone(),
        }));
    }

    // Detect internal calls between functions, CONTRACT-SCOPED.
    // A function in ContractA can only call functions in ContractA (or free functions).
    // This prevents cross-contract false edges when multiple contracts are
    // concatenated into a single source blob.

    // Build per-contract candidate sets for efficient lookup
    let free_fn_names: BTreeSet<&str> = program
        .functions
        .iter()
        .filter(|f| f.contract.is_empty())
        .map(|f| f.name.as_str())
        .collect();

    let contract_fn_names: BTreeMap<&str, BTreeSet<&str>> = {
        let mut map: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for f in &program.functions {
            if !f.contract.is_empty() {
                map.entry(f.contract.as_str())
                    .or_default()
                    .insert(f.name.as_str());
            }
        }
        map
    };

    for f in &program.functions {
        // Candidates: same-contract functions + free/lib functions
        let candidates: &BTreeSet<&str> = if f.contract.is_empty() {
            &free_fn_names
        } else {
            contract_fn_names
                .get(f.contract.as_str())
                .unwrap_or(&free_fn_names)
        };

        for other_name in candidates {
            if f.name.as_str() == *other_name {
                continue;
            }
            let call_pattern = format!("{}(", other_name);
            let dot_pattern_a = format!(" {}.", other_name);
            let dot_pattern_b = format!("({}.", other_name);
            if f.body.contains(&call_pattern)
                || f.body.contains(&dot_pattern_a)
                || f.body.contains(&dot_pattern_b)
            {
                edges.push(Edge::Call(CallEdge {
                    from: f.name.clone(),
                    to: other_name.to_string(),
                }));
            }
        }
    }

    edges
}
