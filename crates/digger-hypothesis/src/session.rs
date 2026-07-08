use crate::assumptions::*;
use crate::compound::*;
use crate::inversion::*;
use crate::models::*;
use crate::verification::*;
/// Research Session Engine — Investigator-Centric Research Organization
///
/// Transforms findings, hypotheses, assumptions, verification tasks,
/// inversions, and evidence chains into investigator-friendly investigations.
///
/// # Rules
///
/// 1. Group by primary function first
/// 2. Merge artifacts sharing function, state, path, or evidence chain
/// 3. Deterministic ordering
/// 4. Every artifact belongs to at least one investigation
/// 5. Same input → same output
/// 6. No AI, no ranking, no confidence scores
use serde::{Deserialize, Serialize};

/// Unique research session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResearchSessionId(pub String);

/// Unique investigation identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InvestigationId(pub String);

impl std::fmt::Display for InvestigationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A research session — the top-level container for an investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchSession {
    /// Unique session identifier.
    pub session_id: ResearchSessionId,
    /// Program identifier.
    pub program_id: String,
    /// All investigations grouped by primary function.
    pub investigations: Vec<Investigation>,
    /// Summary statistics.
    pub summary: ResearchSessionSummary,
}

/// A single investigation — focused on one primary function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Investigation {
    /// Unique investigation identifier.
    pub investigation_id: InvestigationId,
    /// Primary function under investigation.
    pub primary_function: String,
    /// Related functions (called by, calling, sharing state).
    pub related_functions: Vec<String>,
    /// Related state variables.
    pub related_state: Vec<String>,
    /// Findings relevant to this function.
    pub findings: Vec<FindingRef>,
    /// Hypotheses relevant to this function.
    pub hypotheses: Vec<HypothesisRef>,
    /// Compound hypotheses relevant to this function.
    pub compound_hypotheses: Vec<CompoundHypothesisRef>,
    /// Assumptions relevant to this function.
    pub assumptions: Vec<AssumptionRef>,
    /// Verification tasks relevant to this function.
    pub verification_tasks: Vec<VerificationTaskRef>,
    /// Inversions relevant to this function.
    pub inversions: Vec<InversionRef>,
    /// Evidence chains relevant to this function.
    pub evidence_chains: Vec<String>,
    /// Investigation summary.
    pub summary: InvestigationSummary,
}

/// A reference to a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRef {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub function: String,
}

/// A reference to a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisRef {
    pub id: HypothesisId,
    pub hypothesis_type: HypothesisType,
    pub severity: HypothesisSeverity,
    pub description: String,
}

/// A reference to a compound hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundHypothesisRef {
    pub id: CompoundHypothesisId,
    pub compound_type: CompoundHypothesisType,
    pub severity: HypothesisSeverity,
    pub description: String,
}

/// A reference to an assumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssumptionRef {
    pub id: AssumptionId,
    pub assumption_type: AssumptionType,
    pub explanation: String,
    pub invalidation_condition: String,
}

/// A reference to a verification task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationTaskRef {
    pub id: VerificationTaskId,
    pub task_type: VerificationTaskType,
    pub title: String,
    pub expected_validation: String,
    pub failure_implication: String,
}

/// A reference to an inversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InversionRef {
    pub id: InversionId,
    pub inversion_type: InversionType,
    pub invalidating_condition: String,
}

/// Summary for a single investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationSummary {
    pub total_findings: usize,
    pub total_hypotheses: usize,
    pub total_compound_hypotheses: usize,
    pub total_assumptions: usize,
    pub total_verification_tasks: usize,
    pub total_inversions: usize,
    pub total_evidence_chains: usize,
}

/// Summary for the entire research session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchSessionSummary {
    pub total_investigations: usize,
    pub total_findings: usize,
    pub total_hypotheses: usize,
    pub total_compound_hypotheses: usize,
    pub total_assumptions: usize,
    pub total_verification_tasks: usize,
    pub total_inversions: usize,
}

/// Result of session derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchSessionResult {
    pub session: ResearchSession,
}

/// Derive a research session from all pipeline outputs.
///
/// This is the ONLY entry point. Groups all artifacts by primary function.
pub fn derive_session(
    hypotheses: &HypothesisResult,
    compounds: &CompoundHypothesisResult,
    assumptions: &AssumptionResult,
    verification: &VerificationTaskResult,
    inversions: &InversionResult,
) -> ResearchSessionResult {
    // Collect all unique primary functions
    let mut functions: Vec<String> = Vec::new();

    // From hypotheses
    for h in &hypotheses.hypotheses {
        if !functions.contains(&h.primary_function) {
            functions.push(h.primary_function.clone());
        }
    }

    // From compounds
    for c in &compounds.compound_hypotheses {
        for fid in &c.evidence.source_hypothesis_ids {
            if let Some(h) = hypotheses.hypotheses.iter().find(|h| h.id == *fid) {
                if !functions.contains(&h.primary_function) {
                    functions.push(h.primary_function.clone());
                }
            }
        }
    }

    // Sort for deterministic ordering
    functions.sort();

    // Build investigations
    let mut investigations = Vec::new();

    for func in &functions {
        let investigation = build_investigation(
            func,
            hypotheses,
            compounds,
            assumptions,
            verification,
            inversions,
        );
        investigations.push(investigation);
    }

    // Collect any orphan artifacts (not assigned to any investigation)
    // This ensures every artifact belongs to at least one investigation
    assign_orphans(
        &mut investigations,
        hypotheses,
        compounds,
        assumptions,
        verification,
        inversions,
    );

    let summary = build_session_summary(&investigations);

    ResearchSessionResult {
        session: ResearchSession {
            session_id: ResearchSessionId(format!("SESSION-{}", hypotheses.program_id)),
            program_id: hypotheses.program_id.clone(),
            investigations,
            summary,
        },
    }
}

/// Build an investigation for a single primary function.
fn build_investigation(
    primary_function: &str,
    hypotheses: &HypothesisResult,
    compounds: &CompoundHypothesisResult,
    assumptions: &AssumptionResult,
    verification: &VerificationTaskResult,
    inversions: &InversionResult,
) -> Investigation {
    let investigation_id = InvestigationId(format!("INV-{}", primary_function));

    // Collect related functions and state from hypotheses
    let mut related_functions: Vec<String> = Vec::new();
    let mut related_state: Vec<String> = Vec::new();
    let mut evidence_chain_ids: Vec<String> = Vec::new();

    // Find hypotheses for this function
    let func_hypotheses: Vec<&Hypothesis> = hypotheses
        .hypotheses
        .iter()
        .filter(|h| h.primary_function == primary_function)
        .collect();

    for h in &func_hypotheses {
        for ev in &h.evidence {
            for func in &ev.involved_functions {
                if func != primary_function && !related_functions.contains(func) {
                    related_functions.push(func.clone());
                }
            }
            if !evidence_chain_ids.contains(&ev.evidence_chain_id) {
                evidence_chain_ids.push(ev.evidence_chain_id.clone());
            }
            for fact in &ev.graph_facts {
                if fact.fact_type == "state_write" && !related_state.contains(&fact.detail) {
                    related_state.push(fact.detail.clone());
                }
            }
        }
    }

    // Build hypothesis refs
    let hyp_refs: Vec<HypothesisRef> = func_hypotheses
        .iter()
        .map(|h| HypothesisRef {
            id: h.id.clone(),
            hypothesis_type: h.hypothesis_type.clone(),
            severity: h.severity.clone(),
            description: h.description.clone(),
        })
        .collect();

    // Build compound hypothesis refs
    let compound_refs: Vec<CompoundHypothesisRef> = compounds
        .compound_hypotheses
        .iter()
        .filter(|c| {
            c.evidence
                .source_hypothesis_ids
                .iter()
                .any(|id| func_hypotheses.iter().any(|h| h.id == *id))
        })
        .map(|c| CompoundHypothesisRef {
            id: c.id.clone(),
            compound_type: c.compound_type.clone(),
            severity: c.severity.clone(),
            description: c.description.clone(),
        })
        .collect();

    // Build assumption refs
    let assumption_refs: Vec<AssumptionRef> = assumptions
        .all_assumptions
        .iter()
        .filter(|a| {
            func_hypotheses
                .iter()
                .any(|h| h.id == a.source_hypothesis_id)
        })
        .map(|a| AssumptionRef {
            id: a.id.clone(),
            assumption_type: a.assumption_type.clone(),
            explanation: a.explanation.clone(),
            invalidation_condition: a.invalidation_condition.clone(),
        })
        .collect();

    // Build verification task refs
    let task_refs: Vec<VerificationTaskRef> = verification
        .tasks
        .iter()
        .filter(|t| {
            assumption_refs
                .iter()
                .any(|a| a.id == t.source_assumption_id)
        })
        .map(|t| VerificationTaskRef {
            id: t.task_id.clone(),
            task_type: t.task_type.clone(),
            title: t.title.clone(),
            expected_validation: t.expected_validation.clone(),
            failure_implication: t.failure_implication.clone(),
        })
        .collect();

    // Build inversion refs
    let inversion_refs: Vec<InversionRef> = inversions
        .inversions
        .iter()
        .filter(|inv| {
            func_hypotheses
                .iter()
                .any(|h| h.id == inv.source_hypothesis_id)
        })
        .map(|inv| InversionRef {
            id: inv.id.clone(),
            inversion_type: inv.inversion_type.clone(),
            invalidating_condition: inv.invalidating_condition.clone(),
        })
        .collect();

    // Build finding refs (from hypothesis descriptions)
    let finding_refs: Vec<FindingRef> = func_hypotheses
        .iter()
        .map(|h| FindingRef {
            id: h.id.0.clone(),
            kind: h.hypothesis_type.to_string(),
            severity: h.severity.to_string(),
            function: h.primary_function.clone(),
        })
        .collect();

    let summary = InvestigationSummary {
        total_findings: finding_refs.len(),
        total_hypotheses: hyp_refs.len(),
        total_compound_hypotheses: compound_refs.len(),
        total_assumptions: assumption_refs.len(),
        total_verification_tasks: task_refs.len(),
        total_inversions: inversion_refs.len(),
        total_evidence_chains: evidence_chain_ids.len(),
    };

    related_functions.sort();
    related_state.sort();
    evidence_chain_ids.sort();

    Investigation {
        investigation_id,
        primary_function: primary_function.to_string(),
        related_functions,
        related_state,
        findings: finding_refs,
        hypotheses: hyp_refs,
        compound_hypotheses: compound_refs,
        assumptions: assumption_refs,
        verification_tasks: task_refs,
        inversions: inversion_refs,
        evidence_chains: evidence_chain_ids,
        summary,
    }
}

/// Ensure every artifact belongs to at least one investigation.
fn assign_orphans(
    investigations: &mut [Investigation],
    hypotheses: &HypothesisResult,
    _compounds: &CompoundHypothesisResult,
    assumptions: &AssumptionResult,
    verification: &VerificationTaskResult,
    inversions: &InversionResult,
) {
    // Check for orphan hypotheses
    for h in &hypotheses.hypotheses {
        let assigned = investigations
            .iter()
            .any(|inv| inv.hypotheses.iter().any(|r| r.id == h.id));
        if !assigned && !investigations.is_empty() {
            investigations[0].hypotheses.push(HypothesisRef {
                id: h.id.clone(),
                hypothesis_type: h.hypothesis_type.clone(),
                severity: h.severity.clone(),
                description: h.description.clone(),
            });
        }
    }

    // Check for orphan assumptions
    for a in &assumptions.all_assumptions {
        let assigned = investigations
            .iter()
            .any(|inv| inv.assumptions.iter().any(|r| r.id == a.id));
        if !assigned && !investigations.is_empty() {
            investigations[0].assumptions.push(AssumptionRef {
                id: a.id.clone(),
                assumption_type: a.assumption_type.clone(),
                explanation: a.explanation.clone(),
                invalidation_condition: a.invalidation_condition.clone(),
            });
        }
    }

    // Check for orphan verification tasks
    for t in &verification.tasks {
        let assigned = investigations
            .iter()
            .any(|inv| inv.verification_tasks.iter().any(|r| r.id == t.task_id));
        if !assigned && !investigations.is_empty() {
            investigations[0]
                .verification_tasks
                .push(VerificationTaskRef {
                    id: t.task_id.clone(),
                    task_type: t.task_type.clone(),
                    title: t.title.clone(),
                    expected_validation: t.expected_validation.clone(),
                    failure_implication: t.failure_implication.clone(),
                });
        }
    }

    // Check for orphan inversions
    for inv in &inversions.inversions {
        let assigned = investigations
            .iter()
            .any(|i| i.inversions.iter().any(|r| r.id == inv.id));
        if !assigned && !investigations.is_empty() {
            investigations[0].inversions.push(InversionRef {
                id: inv.id.clone(),
                inversion_type: inv.inversion_type.clone(),
                invalidating_condition: inv.invalidating_condition.clone(),
            });
        }
    }
}

/// Build session summary.
fn build_session_summary(investigations: &[Investigation]) -> ResearchSessionSummary {
    ResearchSessionSummary {
        total_investigations: investigations.len(),
        total_findings: investigations
            .iter()
            .map(|i| i.summary.total_findings)
            .sum(),
        total_hypotheses: investigations
            .iter()
            .map(|i| i.summary.total_hypotheses)
            .sum(),
        total_compound_hypotheses: investigations
            .iter()
            .map(|i| i.summary.total_compound_hypotheses)
            .sum(),
        total_assumptions: investigations
            .iter()
            .map(|i| i.summary.total_assumptions)
            .sum(),
        total_verification_tasks: investigations
            .iter()
            .map(|i| i.summary.total_verification_tasks)
            .sum(),
        total_inversions: investigations
            .iter()
            .map(|i| i.summary.total_inversions)
            .sum(),
    }
}
