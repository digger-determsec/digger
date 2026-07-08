use digger_graph::analysis::VulnerabilityPathAnalysis;
/// EvidenceChain — Explainability Layer
///
/// Every finding is traceable through a chain of evidence steps.
/// This answers: "Why does Digger think this is risky?"
///
/// # Design
///
/// EvidenceChain is derived ENTIRELY from existing graph outputs:
/// - VulnerabilityPathAnalysis (vulnerability paths)
/// - AttackSurface (entry points, mutation zones, authority)
/// - Existing graph results (execution, state, authority, cross-program)
///
/// # Rules
///
/// 1. EvidenceChain does NOT add new detection logic
/// 2. EvidenceChain does NOT add new findings
/// 3. EvidenceChain does NOT add new heuristics
/// 4. EvidenceChain does NOT add new graph traversal
/// 5. EvidenceChain is explainability ONLY
use digger_ir::SystemIR;
use serde::{Deserialize, Serialize};

/// An evidence chain — traceable explanation for a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceChain {
    /// Finding identifier (matches path ID).
    pub finding_id: String,
    /// Path identifier.
    pub path_id: String,
    /// Severity label.
    pub severity: String,
    /// Ordered evidence steps.
    pub steps: Vec<EvidenceStep>,
    /// Human-readable summary.
    pub summary: String,
}

/// A single step in an evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceStep {
    /// Function involved.
    pub function: String,
    /// What was observed.
    pub action: EvidenceAction,
    /// Relevant detail.
    pub detail: String,
}

/// Type of evidence action — strict enum, no free-form strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceAction {
    /// Function is an entry point (externally callable).
    FunctionEntered,
    /// Function can be called by other functions.
    FunctionCallable,
    /// External call observed.
    ExternalCallObserved,
    /// Cross-program call observed (CPI).
    CrossProgramCallObserved,
    /// State read observed.
    StateReadObserved,
    /// State mutation observed.
    StateMutationObserved,
    /// Authority check present.
    AuthorityCheckObserved,
    /// Authority check missing.
    AuthorityGapObserved,
    /// Hypothesis triggered by pattern.
    HypothesisTriggered,
}

impl EvidenceChain {
    /// Derive all evidence chains from SystemIR.
    ///
    /// This is the ONLY entry point. Derives explainability from
    /// existing vulnerability paths — no new analysis.
    pub fn derive_all(ir: &SystemIR) -> Vec<Self> {
        let vuln = VulnerabilityPathAnalysis::derive(ir);

        vuln.paths.iter().enumerate().map(|(i, path)| {
            let path_type = match path.path_type {
                digger_graph::analysis::vuln_path::VulnerabilityPathType::Reentrancy => "reentrancy",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::UnauthorizedModification => "unauthorized_modification",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::CpiTrustViolation => "cpi_trust_violation",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::MissingAuthority => "missing_authority",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::UntrustedExternal => "untrusted_external",
            };

            let severity = match path.severity {
                digger_graph::analysis::vuln_path::PathSeverity::Critical => "CRITICAL",
                digger_graph::analysis::vuln_path::PathSeverity::High => "HIGH",
                digger_graph::analysis::vuln_path::PathSeverity::Medium => "MEDIUM",
                digger_graph::analysis::vuln_path::PathSeverity::Low => "LOW",
                digger_graph::analysis::vuln_path::PathSeverity::Info => "INFO",
            };

            let path_id = format!("PATH-{}-{}", path_type.to_uppercase(), i + 1);
            let finding_id = format!("FIND-{}-{}", path_type.to_uppercase(), i + 1);

            // Convert vulnerability path events to evidence steps
            let steps: Vec<EvidenceStep> = path.events.iter().map(|event| {
                let action = match event.event_type {
                    digger_graph::analysis::vuln_path::PathEventType::EntryPoint =>
                        EvidenceAction::FunctionEntered,
                    digger_graph::analysis::vuln_path::PathEventType::InternalCall =>
                        EvidenceAction::FunctionCallable,
                    digger_graph::analysis::vuln_path::PathEventType::ExternalCall =>
                        EvidenceAction::ExternalCallObserved,
                    digger_graph::analysis::vuln_path::PathEventType::CpiCall =>
                        EvidenceAction::CrossProgramCallObserved,
                    digger_graph::analysis::vuln_path::PathEventType::StateRead =>
                        EvidenceAction::StateReadObserved,
                    digger_graph::analysis::vuln_path::PathEventType::StateWrite =>
                        EvidenceAction::StateMutationObserved,
                    digger_graph::analysis::vuln_path::PathEventType::AuthorityCheck =>
                        EvidenceAction::AuthorityCheckObserved,
                    digger_graph::analysis::vuln_path::PathEventType::MissingAuthority =>
                        EvidenceAction::AuthorityGapObserved,
                };

                EvidenceStep {
                    function: event.function.clone(),
                    action,
                    detail: event.detail.clone(),
                }
            }).collect();

            // Generate summary
            let summary = generate_summary(path_type, &path.entry_function, &steps);

            EvidenceChain {
                finding_id,
                path_id,
                severity: severity.into(),
                steps,
                summary,
            }
        }).collect()
    }
}

/// Generate a human-readable summary for an evidence chain.
fn generate_summary(path_type: &str, entry: &str, steps: &[EvidenceStep]) -> String {
    let step_count = steps.len();
    let has_auth_gap = steps
        .iter()
        .any(|s| s.action == EvidenceAction::AuthorityGapObserved);
    let _has_external = steps
        .iter()
        .any(|s| s.action == EvidenceAction::ExternalCallObserved);
    let _has_cpi = steps
        .iter()
        .any(|s| s.action == EvidenceAction::CrossProgramCallObserved);
    let has_mutation = steps
        .iter()
        .any(|s| s.action == EvidenceAction::StateMutationObserved);

    match path_type {
        "reentrancy" => {
            format!(
                "Function '{}' has external call before state update. \
                 {} steps traced: entry → external call → state mutation{}. \
                 Potential reentrancy vector.",
                entry,
                step_count,
                if has_auth_gap {
                    " (no authority check)"
                } else {
                    ""
                }
            )
        }
        "unauthorized_modification" | "missing_authority" => {
            format!(
                "Function '{}' mutates state without authority enforcement. \
                 {} steps traced: entry → state mutation → authority gap. \
                 Public access without authorization.",
                entry, step_count
            )
        }
        "cpi_trust_violation" => {
            format!(
                "Function '{}' makes cross-program call without authority. \
                 {} steps traced: entry → CPI call{}. \
                 Trust boundary violation.",
                entry,
                step_count,
                if has_mutation {
                    " → state mutation"
                } else {
                    ""
                }
            )
        }
        _ => {
            format!(
                "Security path detected from '{}'. {} steps traced.",
                entry, step_count
            )
        }
    }
}
