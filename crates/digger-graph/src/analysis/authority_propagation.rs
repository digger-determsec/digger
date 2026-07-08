use crate::analysis::authority_analyzer;
use crate::analysis::authority_model::*;
use digger_parser::model::*;
/// Authority Propagation Engine — interprocedural authority analysis.
///
/// Propagates authority facts across internal call edges.
/// If function A calls function B, and B has enforced authority,
/// A inherits that authority through the call relationship.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no heuristics, no probabilistic reasoning
/// 3. Cycle detection prevents infinite recursion
/// 4. All outputs sorted for deterministic serialization
/// 5. Authority is propagated from callees to callers (not the reverse)
/// 6. Multiple authority sources are merged deterministically
use std::collections::{BTreeMap, BTreeSet};

/// Maximum propagation depth to prevent runaway recursion.
const MAX_DEPTH: usize = 20;

/// Propagate authority through internal call edges.
///
/// Takes the initial (intra-procedural) authority analysis and
/// propagates authority facts across the call graph.
pub fn propagate_authority(program: &RawProgram) -> AuthorityGraph {
    // Step 1: Run intra-procedural analysis
    let mut graph = authority_analyzer::analyze_authority(program);

    // Step 2: Build call graph from program.calls
    let call_graph = build_call_graph(program);

    // Step 3: Build reverse call graph (callee → callers)
    let reverse_graph = build_reverse_graph(&call_graph);

    // Step 4: Propagate authority from callees to callers
    let propagation = propagate_through_calls(&graph, &reverse_graph, &call_graph);

    // Step 5: Apply propagated authority to the graph
    apply_propagation(&mut graph, propagation);

    // Step 6: Rebuild summary after propagation
    rebuild_summary(&mut graph);

    graph
}

/// Build call graph: caller → list of callees (internal calls only).
///
/// Sources:
/// 1. program.calls — explicit call edges (external and internal)
/// 2. program.operations — InternalCall operations (AST-extracted)
fn build_call_graph(program: &RawProgram) -> BTreeMap<String, Vec<String>> {
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // Build known function set
    let known_funcs: BTreeSet<String> = program.functions.iter().map(|f| f.name.clone()).collect();

    // Source 1: Use program.calls to find internal call edges
    for call in &program.calls {
        let is_external = call.kind == digger_ir::CallKind::External
            || call.to == "external"
            || call.to == "delegate"
            || call.to == "static"
            || call.to == "transfer";

        if !is_external && known_funcs.contains(&call.to) {
            graph
                .entry(call.from.clone())
                .or_default()
                .push(call.to.clone());
        }
    }

    // Source 2: Use InternalCall operations to find call edges
    for op in &program.operations {
        if op.kind == OperationKind::InternalCall && known_funcs.contains(&op.target) {
            graph
                .entry(op.function.clone())
                .or_default()
                .push(op.target.clone());
        }
    }

    // Deduplicate and sort callees
    for callees in graph.values_mut() {
        callees.sort();
        callees.dedup();
    }

    graph
}

/// Build reverse call graph: callee → list of callers.
fn build_reverse_graph(
    call_graph: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, Vec<String>> {
    let mut reverse: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (caller, callees) in call_graph {
        for callee in callees {
            reverse
                .entry(callee.clone())
                .or_default()
                .push(caller.clone());
        }
    }

    // Sort callers for deterministic output
    for callers in reverse.values_mut() {
        callers.sort();
        callers.dedup();
    }

    reverse
}

/// Propagation result for a single function.
#[derive(Debug, Clone)]
struct PropagationResult {
    /// Function name.
    function: String,
    /// Inherited authority source (from callee).
    inherited_source: AuthoritySource,
    /// Inherited check type.
    inherited_check: AuthorityCheckType,
    /// The callee that provided authority.
    from_callee: String,
}

/// Propagate authority through the call graph.
///
/// Uses iterative BFS from authority-enforced functions.
/// Each iteration propagates one level deeper, allowing
/// newly-enforced functions to propagate to their callers.
fn propagate_through_calls(
    graph: &AuthorityGraph,
    reverse_graph: &BTreeMap<String, Vec<String>>,
    _call_graph: &BTreeMap<String, Vec<String>>,
) -> Vec<PropagationResult> {
    let mut results: Vec<PropagationResult> = vec![];

    // Build set of functions that already have authority
    let already_enforced: BTreeSet<String> = graph
        .relations
        .iter()
        .filter(|r| r.enforced && !r.is_invariant)
        .map(|r| r.function.clone())
        .collect();

    // Iterative propagation: each pass propagates one level
    let mut current_enforced = already_enforced.clone();
    let mut all_propagated: BTreeSet<String> = BTreeSet::new();

    for _depth in 0..MAX_DEPTH {
        let mut new_enforced = BTreeSet::new();

        for enforced_func in &current_enforced {
            if let Some(callers) = reverse_graph.get(enforced_func) {
                for caller in callers {
                    if current_enforced.contains(caller) || all_propagated.contains(caller) {
                        continue; // Already has authority
                    }

                    // Get the authority source from the callee
                    // Check both the original relations and propagation results
                    let (source, check_type) = if let Some(callee_rel) = graph
                        .relations
                        .iter()
                        .find(|r| r.function == *enforced_func && r.enforced && !r.is_invariant)
                    {
                        (callee_rel.source.clone(), callee_rel.check_type.clone())
                    } else if let Some(prop) = results.iter().find(|r| r.function == *enforced_func)
                    {
                        (prop.inherited_source.clone(), prop.inherited_check.clone())
                    } else {
                        continue;
                    };

                    results.push(PropagationResult {
                        function: caller.clone(),
                        inherited_source: source,
                        inherited_check: check_type,
                        from_callee: enforced_func.clone(),
                    });

                    new_enforced.insert(caller.clone());
                    all_propagated.insert(caller.clone());
                }
            }
        }

        if new_enforced.is_empty() {
            break; // No new propagations
        }

        // Add newly enforced functions for next iteration
        current_enforced.extend(new_enforced);
    }

    results
}

/// Apply propagation results to the authority graph.
fn apply_propagation(graph: &mut AuthorityGraph, propagation: Vec<PropagationResult>) {
    let mut new_chains = vec![];

    for prop in &propagation {
        // Find the relation for this function
        if let Some(relation) = graph
            .relations
            .iter_mut()
            .find(|r| r.function == prop.function)
        {
            // Only apply if the function doesn't already have authority
            if !relation.enforced && !relation.is_invariant {
                relation.source = prop.inherited_source.clone();
                relation.check_type = prop.inherited_check.clone();
                relation.enforced = true;
                relation.is_invariant = false;

                // Record propagation chain
                new_chains.push((prop.from_callee.clone(), prop.function.clone()));
            }
        }
    }

    // Add new propagation chains
    graph.propagation_chains.extend(new_chains);
    graph.propagation_chains.sort();
    graph.propagation_chains.dedup();
}

/// Rebuild summary statistics after propagation.
fn rebuild_summary(graph: &mut AuthorityGraph) {
    graph.enforced_functions = graph
        .relations
        .iter()
        .filter(|r| r.enforced && !r.is_invariant)
        .map(|r| r.function.clone())
        .collect();

    graph.missing_authority = graph
        .relations
        .iter()
        .filter(|r| !r.enforced && !r.is_invariant)
        .map(|r| r.function.clone())
        .collect();

    graph.invariant_only = graph
        .relations
        .iter()
        .filter(|r| r.is_invariant)
        .map(|r| r.function.clone())
        .collect();

    graph.enforced_functions.sort();
    graph.missing_authority.sort();
    graph.invariant_only.sort();

    let total = graph.relations.len();
    let enforced_count = graph.enforced_functions.len();
    let missing_count = graph.missing_authority.len();
    let invariant_count = graph.invariant_only.len();

    graph.summary = AuthoritySummary {
        total_functions: total,
        enforced_count,
        missing_count,
        invariant_count,
        enforcement_rate: if total > 0 {
            enforced_count as f64 / total as f64
        } else {
            0.0
        },
    };
}
