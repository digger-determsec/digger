use crate::models::*;
/// State Transition Engine — behavioral analysis of how state changes.
///
/// Analyzes expanded operation streams to detect:
/// - Present state transitions (what writes exist)
/// - Missing state transitions (what writes should exist but don't)
///
/// Deterministic: same inputs → same output.
/// No AI, no inference, no heuristics.
use digger_expansion::*;

/// Analyze state transitions for a program.
///
/// Takes expanded operation streams and produces a StateTransitionReport
/// with per-function transition analysis and missing transition detection.
pub fn analyze_transitions(
    expansion: &ExpansionReport,
    protocol_id: &str,
) -> StateTransitionReport {
    let mut transitions = vec![];
    let mut missing_transitions = vec![];
    let mut functions_with_missing = std::collections::BTreeSet::new();

    for func_stream in &expansion.expanded_functions {
        let ops = &func_stream.operations;
        let func_name = &func_stream.function_name;

        // Collect operations by kind
        let reads: Vec<_> = ops.iter().filter(|o| o.kind == "StateRead").collect();
        let writes: Vec<_> = ops.iter().filter(|o| o.kind == "StateWrite").collect();
        let external_effects: Vec<_> = ops
            .iter()
            .filter(|o| o.kind == "ExternalCall" || o.kind == "ValueTransfer")
            .collect();
        let authority_checks: Vec<_> = ops.iter().filter(|o| o.kind == "AuthorityCheck").collect();

        // Detect present transitions
        for write in &writes {
            let read_before = reads
                .iter()
                .any(|r| r.target == write.target && r.index < write.index);

            let external_between = if read_before {
                let read_idx = reads
                    .iter()
                    .find(|r| r.target == write.target && r.index < write.index)
                    .map(|r| r.index)
                    .unwrap_or(0);
                external_effects
                    .iter()
                    .any(|e| e.index > read_idx && e.index < write.index)
            } else {
                false
            };

            let authority_before = authority_checks.iter().any(|a| a.index < write.index);

            transitions.push(StateTransition {
                state_var: write.target.clone(),
                function: func_name.clone(),
                kind: classify_transition(write),
                operation_index: write.index,
                read_before_write: read_before,
                external_between_read_write: external_between,
                authority_before_transition: authority_before,
                is_conditional: false,
                value_expression: None,
            });
        }

        // Detect missing transitions
        // Pattern 1: External effect without any state write
        if !external_effects.is_empty() && writes.is_empty() {
            missing_transitions.push(MissingTransition {
                function: func_name.clone(),
                expected_state_var: "*".into(),
                reason: MissingTransitionReason::ExternalEffectWithoutWrite,
                severity: digger_ir::Severity::High,
            });
            functions_with_missing.insert(func_name.clone());
        }

        // Pattern 2: Read followed by external effect, no write back
        for read in &reads {
            let has_write = writes.iter().any(|w| w.target == read.target);
            let has_external_after = external_effects.iter().any(|e| e.index > read.index);

            if !has_write && has_external_after {
                missing_transitions.push(MissingTransition {
                    function: func_name.clone(),
                    expected_state_var: read.target.clone(),
                    reason: MissingTransitionReason::ReadWithoutWrite,
                    severity: digger_ir::Severity::High,
                });
                functions_with_missing.insert(func_name.clone());
            }
        }
    }

    // Sort for deterministic output
    transitions.sort_by(|a, b| {
        a.function
            .cmp(&b.function)
            .then(a.state_var.cmp(&b.state_var))
            .then(a.operation_index.cmp(&b.operation_index))
    });
    missing_transitions.sort_by(|a, b| {
        a.function
            .cmp(&b.function)
            .then(a.expected_state_var.cmp(&b.expected_state_var))
    });

    let summary = StateTransitionSummary {
        total_transitions: transitions.len(),
        total_missing: missing_transitions.len(),
        transitions_with_external_between: transitions
            .iter()
            .filter(|t| t.external_between_read_write)
            .count(),
        transitions_without_authority: transitions
            .iter()
            .filter(|t| !t.authority_before_transition)
            .count(),
        functions_with_missing: functions_with_missing.len(),
    };

    StateTransitionReport {
        protocol_id: protocol_id.into(),
        transitions,
        missing_transitions,
        summary,
    }
}

/// Classify a transition kind from the operation target.
///
/// Phase 7.4: simplified to Assignment for all writes.
/// Future phases can extract specific kinds from AST.
fn classify_transition(_op: &ExpandedOperation) -> TransitionKind {
    // Phase 7.4: all writes classified as Assignment
    // Future: parse value expression for Increment/Decrement/Toggle/Deletion
    TransitionKind::Assignment
}

#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("JSON parse error: {0}")]
    Parse(String),
}

impl From<serde_json::Error> for AnalysisError {
    fn from(e: serde_json::Error) -> Self {
        AnalysisError::Parse(e.to_string())
    }
}

/// Serialize report to JSON.
pub fn report_to_json(report: &StateTransitionReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

/// Deserialize report from JSON.
pub fn report_from_json(json: &str) -> Result<StateTransitionReport, AnalysisError> {
    Ok(serde_json::from_str(json)?)
}
