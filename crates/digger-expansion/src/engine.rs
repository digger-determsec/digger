use crate::models::*;
/// Cross-Function Expansion Engine.
///
/// Expands internal calls to reveal operations hidden inside callee functions.
/// Deterministic depth-first traversal. No symbolic execution. No path solving.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference, no heuristics
/// 3. Cycle detection prevents infinite recursion
/// 4. All outputs sorted and JSON serializable
use digger_parser::model::*;
use std::collections::{BTreeMap, HashSet};

/// Maximum expansion depth to prevent runaway recursion.
const MAX_DEPTH: usize = 20;

/// Expand all functions in a program, resolving internal calls.
///
/// For each function, builds an expanded operation stream by inlining
/// the operations of called functions (depth-first).
pub fn expand_program(program: &RawProgram, protocol_id: &str) -> ExpansionReport {
    // Build call graph: caller -> callees
    let call_graph = build_call_graph(program);

    // Build operation index: function -> operations
    let op_index = build_operation_index(program);

    let mut expanded_functions = vec![];
    let mut all_traces = vec![];
    let mut all_cycles = vec![];
    let mut all_cei_violations = vec![];

    // Expand each function
    for (func_name, _ops) in &op_index {
        let mut visited = HashSet::new();
        let mut cycle_path = vec![];
        let mut operations = vec![];
        let mut traces = vec![];

        expand_function(
            func_name,
            &call_graph,
            &op_index,
            &mut visited,
            &mut cycle_path,
            &mut operations,
            &mut traces,
            &mut all_cycles,
            0,
            std::slice::from_ref(func_name),
        );

        // Re-index operations sequentially
        for (i, op) in operations.iter_mut().enumerate() {
            op.index = i;
        }

        let has_expansions = traces.iter().any(|t| t.depth > 0);
        let max_depth = traces.iter().map(|t| t.depth).max().unwrap_or(0);

        // Detect expanded CEI violations
        let cei_violations = detect_expanded_cei(func_name, &operations);
        all_cei_violations.extend(cei_violations);

        expanded_functions.push(ExpandedFunctionStream {
            function_name: func_name.clone(),
            operations,
            has_expansions,
            max_depth,
        });

        all_traces.extend(traces);
    }

    // Sort for deterministic output
    expanded_functions.sort_by(|a, b| a.function_name.cmp(&b.function_name));
    all_traces.sort_by(|a, b| {
        a.caller_function
            .cmp(&b.caller_function)
            .then(a.callee_function.cmp(&b.callee_function))
            .then(a.depth.cmp(&b.depth))
    });
    all_cycles.sort_by(|a, b| a.cycle_path.cmp(&b.cycle_path));
    all_cei_violations.sort_by(|a, b| {
        a.base
            .function_name
            .cmp(&b.base.function_name)
            .then(a.base.external_call_index.cmp(&b.base.external_call_index))
    });

    // Deduplicate cycles
    all_cycles.dedup_by(|a, b| a.cycle_path == b.cycle_path);

    let summary = ExpansionSummary {
        total_functions: expanded_functions.len(),
        functions_with_expansions: expanded_functions
            .iter()
            .filter(|f| f.has_expansions)
            .count(),
        total_traces: all_traces.len(),
        total_cycles: all_cycles.len(),
        total_expanded_cei_violations: all_cei_violations.len(),
    };

    ExpansionReport {
        protocol_id: protocol_id.into(),
        expanded_functions,
        cycles: all_cycles,
        traces: all_traces,
        expanded_cei_violations: all_cei_violations,
        summary,
    }
}

/// Build call graph: caller -> list of callees (internal calls only).
fn build_call_graph(program: &RawProgram) -> BTreeMap<String, Vec<String>> {
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // Build known function set
    let known_funcs: HashSet<String> = program.functions.iter().map(|f| f.name.clone()).collect();

    // Source 1: Use the calls list to find internal call edges
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

/// Build operation index: function name -> list of operations.
fn build_operation_index(program: &RawProgram) -> BTreeMap<String, Vec<&RawOperation>> {
    let mut index: BTreeMap<String, Vec<&RawOperation>> = BTreeMap::new();
    for op in &program.operations {
        index.entry(op.function.clone()).or_default().push(op);
    }
    // Operations are already in order within each function
    index
}

/// Expand a single function by inlining callee operations.
fn expand_function(
    func_name: &str,
    call_graph: &BTreeMap<String, Vec<String>>,
    op_index: &BTreeMap<String, Vec<&RawOperation>>,
    visited: &mut HashSet<String>,
    cycle_path: &mut Vec<String>,
    operations: &mut Vec<ExpandedOperation>,
    traces: &mut Vec<ExpansionTrace>,
    cycles: &mut Vec<ExpansionCycle>,
    depth: usize,
    current_chain: &[String],
) {
    // Depth limit
    if depth > MAX_DEPTH {
        return;
    }

    // Cycle detection
    if visited.contains(func_name) {
        cycles.push(ExpansionCycle {
            cycle_path: current_chain.to_vec(),
        });
        return;
    }
    visited.insert(func_name.to_string());

    // Get operations for this function
    if let Some(ops) = op_index.get(func_name) {
        let start_idx = operations.len();

        for op in ops {
            match &op.kind {
                OperationKind::ExternalCall
                | OperationKind::StateWrite
                | OperationKind::StateRead
                | OperationKind::AuthorityCheck
                | OperationKind::ValueTransfer => {
                    // Direct operation — add to expanded stream
                    operations.push(ExpandedOperation {
                        index: operations.len(),
                        kind: op.kind.to_string(),
                        target: op.target.clone(),
                        origin_function: func_name.to_string(),
                        call_chain: current_chain.to_vec(),
                    });
                }
                OperationKind::InternalCall => {
                    // Internal call — expand the callee
                    let callee = &op.target;
                    if let Some(callees) = call_graph.get(func_name) {
                        if callees.contains(callee) {
                            let trace_start = operations.len();
                            let mut new_chain = current_chain.to_vec();
                            new_chain.push(callee.clone());

                            expand_function(
                                callee,
                                call_graph,
                                op_index,
                                visited,
                                cycle_path,
                                operations,
                                traces,
                                cycles,
                                depth + 1,
                                &new_chain,
                            );

                            let trace_end = operations.len();
                            if trace_end > trace_start {
                                traces.push(ExpansionTrace {
                                    caller_function: func_name.to_string(),
                                    callee_function: callee.clone(),
                                    depth: depth + 1,
                                    operation_indices: (trace_start..trace_end).collect(),
                                });
                            }
                        }
                    }
                }
            }
        }

        let _ = start_idx; // Used for trace creation above
    }

    visited.remove(func_name);
}

/// Detect CEI violations in an expanded operation stream.
fn detect_expanded_cei(
    func_name: &str,
    operations: &[ExpandedOperation],
) -> Vec<ExpandedCEIViolation> {
    let mut violations = vec![];

    // Find all external calls and state writes
    let external_calls: Vec<_> = operations
        .iter()
        .enumerate()
        .filter(|(_, op)| op.kind == "ExternalCall")
        .collect();

    let state_writes: Vec<_> = operations
        .iter()
        .enumerate()
        .filter(|(_, op)| op.kind == "StateWrite")
        .collect();

    // Check if any external call comes before any state write
    for (ext_idx, ext_op) in &external_calls {
        for (write_idx, write_op) in &state_writes {
            if ext_idx < write_idx {
                violations.push(ExpandedCEIViolation {
                    base: digger_execution::CEIViolation {
                        function_name: func_name.to_string(),
                        external_call_index: *ext_idx,
                        state_write_index: *write_idx,
                        external_call_target: ext_op.target.clone(),
                        state_variable: write_op.target.clone(),
                        severity: digger_ir::Severity::High,
                    },
                    external_call_origin: ext_op.origin_function.clone(),
                    state_write_origin: write_op.origin_function.clone(),
                });
            }
        }
    }

    // Deduplicate (same external call + same state write)
    violations.sort_by(|a, b| {
        a.base
            .external_call_index
            .cmp(&b.base.external_call_index)
            .then(a.base.state_write_index.cmp(&b.base.state_write_index))
    });
    violations.dedup_by(|a, b| {
        a.base.external_call_index == b.base.external_call_index
            && a.base.state_write_index == b.base.state_write_index
    });

    violations
}

/// Serialize report to JSON.
pub fn report_to_json(report: &ExpansionReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

/// Deserialize report from JSON.
pub fn report_from_json(json: &str) -> Result<ExpansionReport, crate::models::AnalysisError> {
    Ok(serde_json::from_str(json)?)
}
