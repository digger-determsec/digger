use crate::models::*;
/// Resource Lifecycle Engine — behavioral analysis of economic resource movement.
///
/// Analyzes expanded operation streams to detect resource lifecycles
/// and anomalies in how protocols manage economic resources.
///
/// Deterministic: same inputs → same output.
/// No AI, no inference, no heuristics.
/// Language-agnostic, protocol-agnostic.
use digger_expansion::*;

/// Analyze resource lifecycles for a protocol.
///
/// Takes expanded operation streams and produces a ResourceLifecycleReport
/// with per-function lifecycle analysis and anomaly detection.
pub fn analyze_lifecycles(
    expansion: &ExpansionReport,
    protocol_id: &str,
) -> ResourceLifecycleReport {
    let mut lifecycles = vec![];

    for func_stream in &expansion.expanded_functions {
        let ops = &func_stream.operations;
        let func_name = &func_stream.function_name;

        // Classify operations into lifecycle phases
        let mut phases = vec![];
        let mut tracking_vars = Vec::new();

        for op in ops {
            match op.kind.as_str() {
                "AuthorityCheck" => {
                    phases.push(LifecyclePhase {
                        kind: PhaseKind::Authorization,
                        operation_index: op.index,
                        state_var: None,
                        external_target: None,
                        authority_enforced: true,
                    });
                }
                "StateRead" => {
                    // State reads are not lifecycle phases themselves,
                    // but they identify tracking variables
                    if !tracking_vars.contains(&op.target) {
                        tracking_vars.push(op.target.clone());
                    }
                }
                "StateWrite" => {
                    // Classify as accounting update or state transition
                    // Behavioral: if the variable is also read, it's likely accounting
                    let is_accounting = ops.iter().any(|o| {
                        o.kind == "StateRead" && o.target == op.target && o.index < op.index
                    });

                    let has_auth_before = phases.iter().any(|p| {
                        p.kind == PhaseKind::Authorization && p.operation_index < op.index
                    });

                    phases.push(LifecyclePhase {
                        kind: if is_accounting {
                            PhaseKind::AccountingUpdate
                        } else {
                            PhaseKind::StateTransition
                        },
                        operation_index: op.index,
                        state_var: Some(op.target.clone()),
                        external_target: None,
                        authority_enforced: has_auth_before,
                    });

                    if !tracking_vars.contains(&op.target) {
                        tracking_vars.push(op.target.clone());
                    }
                }
                "ExternalCall" => {
                    // Determine if this is ingress, egress, or settlement
                    // Behavioral: check if there's a state write after this call
                    let has_write_after = ops
                        .iter()
                        .any(|o| o.kind == "StateWrite" && o.index > op.index);
                    let has_write_before = ops
                        .iter()
                        .any(|o| o.kind == "StateWrite" && o.index < op.index);

                    let has_auth_before = phases.iter().any(|p| {
                        p.kind == PhaseKind::Authorization && p.operation_index < op.index
                    });

                    let phase_kind = if has_write_before && !has_write_after {
                        // Write before, no write after → egress pattern
                        PhaseKind::Egress
                    } else if !has_write_before && has_write_after {
                        // No write before, write after → ingress pattern
                        PhaseKind::Ingress
                    } else {
                        // Both or neither → settlement
                        PhaseKind::Settlement
                    };

                    phases.push(LifecyclePhase {
                        kind: phase_kind,
                        operation_index: op.index,
                        state_var: None,
                        external_target: Some(op.target.clone()),
                        authority_enforced: has_auth_before,
                    });
                }
                "ValueTransfer" => {
                    let has_auth_before = phases.iter().any(|p| {
                        p.kind == PhaseKind::Authorization && p.operation_index < op.index
                    });

                    phases.push(LifecyclePhase {
                        kind: PhaseKind::Egress,
                        operation_index: op.index,
                        state_var: None,
                        external_target: Some(op.target.clone()),
                        authority_enforced: has_auth_before,
                    });
                }
                _ => {}
            }
        }

        // Detect anomalies
        let anomalies = detect_anomalies(&phases, ops);

        // Determine completeness
        let is_complete = !phases.is_empty();

        lifecycles.push(ResourceLifecycle {
            function: func_name.clone(),
            tracking_vars,
            phases,
            is_complete,
            anomalies,
        });
    }

    // Sort for deterministic output
    lifecycles.sort_by(|a, b| a.function.cmp(&b.function));

    let total_lifecycles = lifecycles.len();
    let total_anomalies = lifecycles.iter().map(|l| l.anomalies.len()).sum();
    let functions_with_anomalies = lifecycles
        .iter()
        .filter(|l| !l.anomalies.is_empty())
        .count();
    let complete_lifecycles = lifecycles.iter().filter(|l| l.is_complete).count();
    let incomplete_lifecycles = total_lifecycles - complete_lifecycles;

    ResourceLifecycleReport {
        protocol_id: protocol_id.into(),
        lifecycles,
        summary: LifecycleSummary {
            total_lifecycles,
            total_anomalies,
            functions_with_anomalies,
            complete_lifecycles,
            incomplete_lifecycles,
        },
    }
}

/// Detect anomalies in a resource lifecycle.
fn detect_anomalies(phases: &[LifecyclePhase], ops: &[ExpandedOperation]) -> Vec<LifecycleAnomaly> {
    let mut anomalies = vec![];

    let has_egress = phases.iter().any(|p| p.kind == PhaseKind::Egress);
    let has_ingress = phases.iter().any(|p| p.kind == PhaseKind::Ingress);
    let has_accounting = phases.iter().any(|p| p.kind == PhaseKind::AccountingUpdate);
    let has_authority = phases.iter().any(|p| p.kind == PhaseKind::Authorization);

    // Pattern 1: Egress without authorization
    if has_egress && !has_authority {
        if let Some(egress_phase) = phases.iter().find(|p| p.kind == PhaseKind::Egress) {
            anomalies.push(LifecycleAnomaly {
                kind: AnomalyKind::UnauthorizedEgress,
                operation_index: egress_phase.operation_index,
                severity: digger_ir::Severity::Critical,
                description: "Resource leaves without authorization check".into(),
            });
        }
    }

    // Pattern 2: Ingress without accounting
    if has_ingress && !has_accounting {
        if let Some(ingress_phase) = phases.iter().find(|p| p.kind == PhaseKind::Ingress) {
            anomalies.push(LifecycleAnomaly {
                kind: AnomalyKind::IngressWithoutAccounting,
                operation_index: ingress_phase.operation_index,
                severity: digger_ir::Severity::High,
                description: "Resource enters without accounting update".into(),
            });
        }
    }

    // Pattern 3: Egress without accounting decrease
    if has_egress && !has_accounting {
        if let Some(egress_phase) = phases.iter().find(|p| p.kind == PhaseKind::Egress) {
            anomalies.push(LifecycleAnomaly {
                kind: AnomalyKind::EgressWithoutAccountingDecrease,
                operation_index: egress_phase.operation_index,
                severity: digger_ir::Severity::High,
                description: "Resource leaves without accounting decrease".into(),
            });
        }
    }

    // Pattern 4: Accounting integrity risk (external between read and write)
    for op in ops {
        if op.kind == "ExternalCall" {
            let has_read_before = ops
                .iter()
                .any(|o| o.kind == "StateRead" && o.index < op.index);
            let has_write_after = ops
                .iter()
                .any(|o| o.kind == "StateWrite" && o.index > op.index);

            if has_read_before && has_write_after {
                anomalies.push(LifecycleAnomaly {
                    kind: AnomalyKind::AccountingIntegrityRisk,
                    operation_index: op.index,
                    severity: digger_ir::Severity::High,
                    description: "External call between state read and write".into(),
                });
            }
        }
    }

    // Pattern 5: Untracked movement (external call with no accounting)
    let has_external = ops
        .iter()
        .any(|o| o.kind == "ExternalCall" || o.kind == "ValueTransfer");
    if has_external && !has_accounting && !has_ingress && !has_egress {
        if let Some(ext_op) = ops
            .iter()
            .find(|o| o.kind == "ExternalCall" || o.kind == "ValueTransfer")
        {
            anomalies.push(LifecycleAnomaly {
                kind: AnomalyKind::UntrackedMovement,
                operation_index: ext_op.index,
                severity: digger_ir::Severity::High,
                description: "External effect without any accounting or lifecycle phase".into(),
            });
        }
    }

    // Sort anomalies by operation index for deterministic output
    anomalies.sort_by_key(|a| a.operation_index);
    anomalies
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
pub fn report_to_json(report: &ResourceLifecycleReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

/// Deserialize report from JSON.
pub fn report_from_json(json: &str) -> Result<ResourceLifecycleReport, AnalysisError> {
    Ok(serde_json::from_str(json)?)
}
