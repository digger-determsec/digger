/// Bridge between legacy Hypothesis type and the ranking engine.
///
/// Adapts legacy hypotheses to the ranking input format so the
/// ranking engine can be used by both the legacy and v2 engines.
use crate::ranking::{rank_hypotheses, RankedHypothesisInput, RankingWeights, ScoredHypothesis};
use digger_ir::SystemIR;

/// Legacy hypothesis type (from digger-hypothesis-legacy).
#[derive(Debug, Clone)]
pub struct LegacyHypothesis {
    pub id: String,
    pub kind: String,
    pub severity: SeverityScore,
    pub confidence: f32,
    pub affected_function: String,
    pub evidence: Vec<String>,
    pub reasoning: String,
}

/// Severity as a numeric score.
#[derive(Debug, Clone, Copy)]
pub enum SeverityScore {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityScore {
    pub fn to_f64(self) -> f64 {
        match self {
            Self::Critical => 1.0,
            Self::High => 0.8,
            Self::Medium => 0.5,
            Self::Low => 0.3,
            Self::Info => 0.1,
        }
    }
}

/// Convert legacy hypotheses to ranked output using structural evidence.
///
/// This is the main entry point for using the ranking engine
/// with the legacy hypothesis engine.
pub fn rank_legacy_hypotheses(
    hypotheses: &[LegacyHypothesis],
    ir: &SystemIR,
    weights: &RankingWeights,
) -> Vec<ScoredHypothesis> {
    let inputs: Vec<RankedHypothesisInput> = hypotheses
        .iter()
        .map(|h| convert_to_ranking_input(h, ir))
        .collect();

    rank_hypotheses(&inputs, weights)
}

fn convert_to_ranking_input(h: &LegacyHypothesis, ir: &SystemIR) -> RankedHypothesisInput {
    // Count edges touching the affected function
    let graph_edge_count = ir
        .edges
        .iter()
        .filter(|e| match e {
            digger_ir::Edge::Call(c) => {
                c.from == h.affected_function || c.to == h.affected_function
            }
            digger_ir::Edge::State(s) => s.function == h.affected_function,
            digger_ir::Edge::Authority(a) => a.function == h.affected_function,
            digger_ir::Edge::External(e) => e.function == h.affected_function,
        })
        .count();

    // Extract distinct evidence fact types
    let evidence_fact_types: Vec<String> = h
        .evidence
        .iter()
        .map(|e| classify_evidence_type(e))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    // Determine trust boundary crossing
    let crosses_trust_boundary = h.kind.contains("External")
        || h.kind.contains("CPI")
        || h.kind.contains("cpi")
        || h.evidence
            .iter()
            .any(|e| e.contains("external") || e.contains("CPI"));

    // Determine invariant violation
    let violates_invariant = h.kind.contains("State")
        || h.kind.contains("Corruption")
        || h.evidence
            .iter()
            .any(|e| e.contains("invariant") || e.contains("state"));

    RankedHypothesisInput {
        id: h.id.clone(),
        severity: h.severity.to_f64(),
        evidence_count: h.evidence.len(),
        evidence_fact_types,
        graph_edge_count,
        reasoning_length: h.reasoning.len(),
        crosses_trust_boundary,
        violates_invariant,
        benchmark_confirmed: false, // Legacy engine doesn't have benchmark data
    }
}

/// Classify an evidence string into a fact type.
fn classify_evidence_type(evidence: &str) -> String {
    let lower = evidence.to_lowercase();
    if lower.contains("external") || lower.contains("call") {
        "external_call".into()
    } else if lower.contains("state") || lower.contains("write") || lower.contains("mutation") {
        "state_write".into()
    } else if lower.contains("authority") || lower.contains("signer") || lower.contains("access") {
        "authority_gap".into()
    } else if lower.contains("cpi") || lower.contains("cross-program") {
        "cpi_call".into()
    } else if lower.contains("reentrancy") || lower.contains("reentrant") {
        "reentrancy".into()
    } else {
        "other".into()
    }
}
