/// Explanation Generation — structured reasoning traces for hypotheses.
///
/// Every hypothesis produces a complete explanation with:
/// - Reasoning trace
/// - Evidence chain
/// - Violated invariants
/// - Trust boundaries crossed
/// - Protocol assumptions
/// - Confidence breakdown
/// - Benchmark matches
/// - Historical exploit similarities
/// - Mitigation rationale
///
/// All explanations are deterministic and explainable.
use serde::{Deserialize, Serialize};

/// A complete explanation for a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HypothesisExplanation {
    /// Hypothesis ID this explanation belongs to.
    pub hypothesis_id: String,
    /// Reasoning trace — step-by-step how this hypothesis was derived.
    pub reasoning_trace: Vec<ReasoningStep>,
    /// Evidence chain — ordered evidence supporting this hypothesis.
    pub evidence_chain: Vec<EvidenceChainEntry>,
    /// Violated invariants — protocol invariants that may be broken.
    pub violated_invariants: Vec<InvariantViolation>,
    /// Trust boundaries crossed — external calls, CPI, cross-contract.
    pub trust_boundaries_crossed: Vec<TrustBoundary>,
    /// Protocol assumptions — assumptions about protocol behavior.
    pub protocol_assumptions: Vec<ProtocolAssumption>,
    /// Confidence breakdown — how confidence is composed.
    pub confidence_breakdown: ConfidenceBreakdown,
    /// Benchmark matches — known exploits with similar patterns.
    pub benchmark_matches: Vec<BenchmarkMatch>,
    /// Historical exploit similarities — past exploits with similar structures.
    pub historical_similarities: Vec<HistoricalSimilarity>,
    /// Mitigation rationale — how this vulnerability could be fixed.
    pub mitigation_rationale: MitigationRationale,
}

/// A single step in the reasoning trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningStep {
    /// Step number.
    pub step: usize,
    /// What was observed.
    pub observation: String,
    /// What was inferred.
    pub inference: String,
    /// Supporting evidence references.
    pub evidence_refs: Vec<String>,
}

/// An entry in the evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceChainEntry {
    /// Order in the chain.
    pub order: usize,
    /// Evidence text.
    pub evidence: String,
    /// Source of evidence.
    pub source: String,
    /// Quality tier.
    pub tier: String,
    /// Functions involved.
    pub involved_functions: Vec<String>,
}

/// A violated invariant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvariantViolation {
    /// Invariant description.
    pub invariant: String,
    /// How it's violated.
    pub violation: String,
    /// Severity.
    pub severity: String,
}

/// A trust boundary that was crossed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustBoundary {
    /// Source of the trust boundary crossing.
    pub source: String,
    /// Target of the trust boundary crossing.
    pub target: String,
    /// Kind of crossing (external call, CPI, cross-contract).
    pub kind: String,
    /// Whether authority is enforced at the boundary.
    pub authority_enforced: bool,
}

/// A protocol assumption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolAssumption {
    /// Assumption description.
    pub assumption: String,
    /// Validation status (proven, unsupported, contradicted, unknown).
    pub status: String,
    /// Supporting evidence.
    pub supporting_evidence: Vec<String>,
}

/// Confidence breakdown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidenceBreakdown {
    /// Base confidence from severity.
    pub severity_contribution: f64,
    /// Confidence from evidence quality.
    pub evidence_contribution: f64,
    /// Confidence adjustment from assumptions.
    pub assumption_adjustment: f64,
    /// Confidence adjustment from contradictions.
    pub contradiction_adjustment: f64,
    /// Final confidence score.
    pub final_confidence: f64,
    /// Explanation of the breakdown.
    pub explanation: String,
}

/// A benchmark match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkMatch {
    /// Exploit ID from benchmark.
    pub exploit_id: String,
    /// Protocol name.
    pub protocol: String,
    /// Similarity description.
    pub similarity: String,
    /// Match confidence.
    pub confidence: f64,
}

/// A historical exploit similarity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalSimilarity {
    /// Exploit name or ID.
    pub exploit: String,
    /// Year.
    pub year: u32,
    /// Loss amount.
    pub loss_usd: f64,
    /// Similarity description.
    pub similarity: String,
}

/// Mitigation rationale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MitigationRationale {
    /// Recommended fix.
    pub recommendation: String,
    /// Specific code changes suggested.
    pub code_suggestions: Vec<String>,
    /// Reference to similar fixes.
    pub references: Vec<String>,
    /// Confidence that this mitigation would be effective.
    pub effectiveness_confidence: f64,
}

/// Generate a complete explanation for a hypothesis.
///
/// Takes the hypothesis data and available context to produce
/// a structured, explainable reasoning trace.
pub fn generate_explanation(input: ExplanationInput) -> HypothesisExplanation {
    let reasoning_trace = generate_reasoning_trace(&input);
    let evidence_chain = generate_evidence_chain(&input);
    let violated_invariants = detect_violated_invariants(&input);
    let trust_boundaries = detect_trust_boundaries(&input);
    let protocol_assumptions = extract_protocol_assumptions(&input);
    let confidence_breakdown = compute_confidence_breakdown(&input);
    let benchmark_matches = find_benchmark_matches(&input);
    let historical_similarities = find_historical_similarities(&input);
    let mitigation_rationale = generate_mitigation(&input);

    HypothesisExplanation {
        hypothesis_id: input.hypothesis_id.clone(),
        reasoning_trace,
        evidence_chain,
        violated_invariants,
        trust_boundaries_crossed: trust_boundaries,
        protocol_assumptions,
        confidence_breakdown,
        benchmark_matches,
        historical_similarities,
        mitigation_rationale,
    }
}

/// Input data for explanation generation.
#[derive(Debug, Clone)]
pub struct ExplanationInput {
    /// Hypothesis ID.
    pub hypothesis_id: String,
    /// Hypothesis kind/type.
    pub hypothesis_kind: String,
    /// Affected function.
    pub affected_function: String,
    /// Severity level.
    pub severity: String,
    /// Evidence strings.
    pub evidence: Vec<String>,
    /// Reasoning text.
    pub reasoning: String,
    /// Edge types touching the affected function.
    pub edge_types: Vec<String>,
    /// Whether there's an external call.
    pub has_external_call: bool,
    /// Whether there's a CPI call.
    pub has_cpi: bool,
    /// Whether state is mutated.
    pub state_mutated: bool,
    /// Whether authority is enforced.
    pub authority_enforced: bool,
    /// Functions involved.
    pub involved_functions: Vec<String>,
    /// Base confidence.
    pub base_confidence: f64,
    /// Assumption validation adjustment.
    pub assumption_adjustment: f64,
    /// Contradiction adjustment.
    pub contradiction_adjustment: f64,
}

fn generate_reasoning_trace(input: &ExplanationInput) -> Vec<ReasoningStep> {
    let mut steps = Vec::new();
    let mut step_num = 1;

    // Step 1: Entry point detection
    steps.push(ReasoningStep {
        step: step_num,
        observation: format!(
            "Function '{}' identified as entry point for analysis",
            input.affected_function
        ),
        inference: format!(
            "Function has {} edges connecting it to other program components",
            input.edge_types.len()
        ),
        evidence_refs: vec![format!("function:{}", input.affected_function)],
    });
    step_num += 1;

    // Step 2: Pattern detection
    if input.has_external_call {
        steps.push(ReasoningStep {
            step: step_num,
            observation: "External call detected in function".into(),
            inference: "Trust boundary crossed — external code may execute".into(),
            evidence_refs: vec!["edge:external_call".into()],
        });
        step_num += 1;
    }

    if input.has_cpi {
        steps.push(ReasoningStep {
            step: step_num,
            observation: "CPI (Cross-Program Invocation) detected".into(),
            inference: "Cross-program trust boundary — called program may behave unexpectedly"
                .into(),
            evidence_refs: vec!["edge:cpi".into()],
        });
        step_num += 1;
    }

    if input.state_mutated {
        steps.push(ReasoningStep {
            step: step_num,
            observation: "State mutation detected".into(),
            inference: "Protocol state is modified — incorrect mutation could corrupt state".into(),
            evidence_refs: vec!["edge:state_write".into()],
        });
        step_num += 1;
    }

    // Step 3: Vulnerability pattern
    steps.push(ReasoningStep {
        step: step_num,
        observation: format!(
            "Pattern matches vulnerability class: {}",
            input.hypothesis_kind
        ),
        inference: input.reasoning.clone(),
        evidence_refs: input.evidence.iter().take(3).cloned().collect(),
    });

    steps
}

fn generate_evidence_chain(input: &ExplanationInput) -> Vec<EvidenceChainEntry> {
    input
        .evidence
        .iter()
        .enumerate()
        .map(|(i, e)| EvidenceChainEntry {
            order: i + 1,
            evidence: e.clone(),
            source: "structural_analysis".into(),
            tier: "inferred".into(),
            involved_functions: input.involved_functions.clone(),
        })
        .collect()
}

fn detect_violated_invariants(input: &ExplanationInput) -> Vec<InvariantViolation> {
    let mut invariants = Vec::new();

    if input.has_external_call && input.state_mutated && !input.authority_enforced {
        invariants.push(InvariantViolation {
            invariant: "State must be updated before external call (CEI pattern)".into(),
            violation: "External call occurs before state update".into(),
            severity: "High".into(),
        });
    }

    if input.state_mutated && !input.authority_enforced {
        invariants.push(InvariantViolation {
            invariant: "State mutations must be authorized".into(),
            violation: "State mutation without authority enforcement".into(),
            severity: "Critical".into(),
        });
    }

    invariants
}

fn detect_trust_boundaries(input: &ExplanationInput) -> Vec<TrustBoundary> {
    let mut boundaries = Vec::new();

    if input.has_external_call {
        boundaries.push(TrustBoundary {
            source: input.affected_function.clone(),
            target: "external".into(),
            kind: "external_call".into(),
            authority_enforced: input.authority_enforced,
        });
    }

    if input.has_cpi {
        boundaries.push(TrustBoundary {
            source: input.affected_function.clone(),
            target: "cpi_target".into(),
            kind: "cross_program_invocation".into(),
            authority_enforced: input.authority_enforced,
        });
    }

    boundaries
}

fn extract_protocol_assumptions(input: &ExplanationInput) -> Vec<ProtocolAssumption> {
    let mut assumptions = Vec::new();

    if input.has_external_call {
        assumptions.push(ProtocolAssumption {
            assumption: "External call target behaves as expected".into(),
            status: "unknown".into(),
            supporting_evidence: vec![],
        });
    }

    if input.state_mutated {
        assumptions.push(ProtocolAssumption {
            assumption: "State transitions maintain protocol invariants".into(),
            status: if input.authority_enforced {
                "supported"
            } else {
                "unsupported"
            }
            .into(),
            supporting_evidence: if input.authority_enforced {
                vec!["Authority check present".into()]
            } else {
                vec![]
            },
        });
    }

    assumptions
}

fn compute_confidence_breakdown(input: &ExplanationInput) -> ConfidenceBreakdown {
    let severity_contribution = match input.severity.as_str() {
        "Critical" => 0.35,
        "High" => 0.25,
        "Medium" => 0.15,
        "Low" => 0.08,
        _ => 0.03,
    };

    let evidence_contribution = (input.evidence.len() as f64 * 0.05).min(0.30);

    let final_confidence =
        (input.base_confidence + input.assumption_adjustment + input.contradiction_adjustment)
            .clamp(0.0, 1.0);

    let explanation = format!(
        "Base confidence: {:.2}, Evidence contribution: {:.2}, Assumption adjustment: {:+.2}, Contradiction adjustment: {:+.2}",
        input.base_confidence, evidence_contribution, input.assumption_adjustment, input.contradiction_adjustment
    );

    ConfidenceBreakdown {
        severity_contribution,
        evidence_contribution,
        assumption_adjustment: input.assumption_adjustment,
        contradiction_adjustment: input.contradiction_adjustment,
        final_confidence,
        explanation,
    }
}

fn find_benchmark_matches(_input: &ExplanationInput) -> Vec<BenchmarkMatch> {
    // Placeholder — in production, this would query the benchmark corpus
    vec![]
}

fn find_historical_similarities(_input: &ExplanationInput) -> Vec<HistoricalSimilarity> {
    // Placeholder — in production, this would query the knowledge base
    vec![]
}

fn generate_mitigation(input: &ExplanationInput) -> MitigationRationale {
    let (recommendation, suggestions) = match input.hypothesis_kind.as_str() {
        k if k.contains("Reentrancy") || k.contains("reentrancy") => (
            "Add reentrancy guard and follow checks-effects-interactions pattern".into(),
            vec![
                "Add nonReentrant modifier".into(),
                "Move state updates before external calls".into(),
                "Consider using reentrancy lock".into(),
            ],
        ),
        k if k.contains("Authority") || k.contains("authority") || k.contains("Missing") => (
            "Add access control checks".into(),
            vec![
                "Add require(msg.sender == owner) or equivalent".into(),
                "Use role-based access control".into(),
                "Add modifier for authorization".into(),
            ],
        ),
        k if k.contains("CPI") || k.contains("cpi") => (
            "Validate CPI targets and enforce authority".into(),
            vec![
                "Verify CPI target program ID".into(),
                "Add authority checks before CPI".into(),
                "Use invoke_signed for PDA accounts".into(),
            ],
        ),
        k if k.contains("State") || k.contains("state") => (
            "Ensure state mutations are properly authorized and ordered".into(),
            vec![
                "Add authority checks before state writes".into(),
                "Follow CEI pattern".into(),
                "Validate state transitions".into(),
            ],
        ),
        _ => (
            "Review code for security best practices".into(),
            vec!["Follow security guidelines".into()],
        ),
    };

    MitigationRationale {
        recommendation,
        code_suggestions: suggestions,
        references: vec![],
        effectiveness_confidence: 0.70,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explanation_generation() {
        let input = ExplanationInput {
            hypothesis_id: "H1".into(),
            hypothesis_kind: "ReentrancyCandidate".into(),
            affected_function: "withdraw".into(),
            severity: "High".into(),
            evidence: vec![
                "External call detected".into(),
                "State mutation detected".into(),
            ],
            reasoning: "Function has external call before state update".into(),
            edge_types: vec!["external_call".into(), "state_write".into()],
            has_external_call: true,
            has_cpi: false,
            state_mutated: true,
            authority_enforced: false,
            involved_functions: vec!["withdraw".into()],
            base_confidence: 0.75,
            assumption_adjustment: 0.0,
            contradiction_adjustment: 0.0,
        };

        let explanation = generate_explanation(input);

        assert_eq!(explanation.hypothesis_id, "H1");
        assert!(!explanation.reasoning_trace.is_empty());
        assert!(!explanation.evidence_chain.is_empty());
        assert!(!explanation.violated_invariants.is_empty());
        assert!(!explanation.trust_boundaries_crossed.is_empty());
        assert!(!explanation.protocol_assumptions.is_empty());
        assert!(!explanation.mitigation_rationale.code_suggestions.is_empty());
    }

    #[test]
    fn test_deterministic_explanation() {
        let input = ExplanationInput {
            hypothesis_id: "H1".into(),
            hypothesis_kind: "AuthorityBypassCandidate".into(),
            affected_function: "setOwner".into(),
            severity: "Critical".into(),
            evidence: vec!["No authority check".into()],
            reasoning: "Public function writes state without authority".into(),
            edge_types: vec!["state_write".into()],
            has_external_call: false,
            has_cpi: false,
            state_mutated: true,
            authority_enforced: false,
            involved_functions: vec!["setOwner".into()],
            base_confidence: 0.85,
            assumption_adjustment: 0.0,
            contradiction_adjustment: 0.0,
        };

        let e1 = generate_explanation(input.clone());
        let e2 = generate_explanation(input);

        assert_eq!(e1.reasoning_trace.len(), e2.reasoning_trace.len());
        assert_eq!(
            e1.confidence_breakdown.final_confidence,
            e2.confidence_breakdown.final_confidence
        );
    }
}
