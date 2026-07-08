/// End-to-End Reasoning Pipeline — single deterministic orchestration flow.
///
/// Every hypothesis flows through exactly one pipeline:
///   generation → assumption validation → contradiction detection →
///   evidence collection → evidence ranking → hypothesis ranking →
///   explanation generation → benchmark validation
///
/// No duplicated computation. Single reasoning context shared across stages.
/// All stages are deterministic and traceable.
use serde::{Deserialize, Serialize};

use crate::analytics::{self, HypothesisInput as AnalyticsInput, ReasoningAnalyticsReport};
use crate::assumption_validation::{self, ValidationResult as AssumptionValidation};
use crate::contradiction::{self, ContradictionResult};
use crate::evidence_ranking::{
    self, EvidenceInput, EvidenceQualitySummary, EvidenceSource, RankedEvidence,
};
use crate::explanation::{self, ExplanationInput, HypothesisExplanation};
use crate::ranking::{self, RankedHypothesisInput, RankingWeights};

/// Shared reasoning context — flows through the entire pipeline.
///
/// Every stage reads from and writes to this context.
/// No stage computes information that another stage already computed.
#[derive(Debug, Clone)]
pub struct ReasoningContext {
    /// Program identifier.
    pub program_id: String,
    /// Language (Solidity, Anchor, Rust, etc.).
    pub language: String,
    /// IR edge types touching the affected function.
    pub edge_types: Vec<String>,
    /// Whether external calls exist.
    pub has_external_call: bool,
    /// Whether CPI calls exist.
    pub has_cpi: bool,
    /// Whether state is mutated.
    pub state_mutated: bool,
    /// Whether authority is enforced.
    pub authority_enforced: bool,
    /// Functions involved in the analysis.
    pub involved_functions: Vec<String>,
    /// Base confidence from the engine.
    pub base_confidence: f64,
    /// Ranking weights.
    pub ranking_weights: RankingWeights,
}

impl Default for ReasoningContext {
    fn default() -> Self {
        Self {
            program_id: String::new(),
            language: String::new(),
            edge_types: vec![],
            has_external_call: false,
            has_cpi: false,
            state_mutated: false,
            authority_enforced: false,
            involved_functions: vec![],
            base_confidence: 0.5,
            ranking_weights: RankingWeights::default(),
        }
    }
}

/// Raw hypothesis from the engine (before pipeline processing).
#[derive(Debug, Clone)]
pub struct RawHypothesis {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub confidence: f64,
    pub affected_function: String,
    pub evidence: Vec<String>,
    pub reasoning: String,
}

/// A fully processed hypothesis with all pipeline outputs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessedHypothesis {
    /// Original hypothesis data.
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub affected_function: String,
    /// Ranked score.
    pub ranking_score: f64,
    pub ranking_factors: ranking::RankingFactors,
    /// Assumption validation result.
    pub assumption_validation: AssumptionValidation,
    /// Contradictions detected.
    pub contradiction_result: ContradictionResult,
    /// Ranked evidence.
    pub evidence: Vec<RankedEvidence>,
    pub evidence_quality: EvidenceQualitySummary,
    /// Full explanation.
    pub explanation: HypothesisExplanation,
    /// Adjusted confidence after all pipeline stages.
    pub final_confidence: f64,
    /// Whether this hypothesis was eliminated.
    pub eliminated: bool,
    /// Reason for elimination (if eliminated).
    pub elimination_reason: Option<String>,
}

/// Pipeline output — all processed hypotheses plus analytics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineOutput {
    /// Program identifier.
    pub program_id: String,
    /// All processed hypotheses (including eliminated ones).
    pub hypotheses: Vec<ProcessedHypothesis>,
    /// Active hypotheses (not eliminated).
    pub active_hypotheses: Vec<ProcessedHypothesis>,
    /// Eliminated hypotheses.
    pub eliminated_hypotheses: Vec<ProcessedHypothesis>,
    /// Reasoning analytics across all hypotheses.
    pub analytics: ReasoningAnalyticsReport,
    /// Pipeline metadata.
    pub metadata: PipelineMetadata,
}

/// Pipeline metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineMetadata {
    /// Total hypotheses entering the pipeline.
    pub total_input: usize,
    /// Total hypotheses after processing.
    pub total_output: usize,
    /// Total hypotheses eliminated.
    pub total_eliminated: usize,
    /// Pipeline stages executed.
    pub stages_executed: Vec<String>,
}

/// Run the complete reasoning pipeline.
///
/// This is the ONLY entry point for hypothesis processing.
/// All stages are executed in order with shared context.
/// Optimized to minimize allocations and redundant computation.
///
/// Deterministic: same inputs → same output.
pub fn run_pipeline(
    raw_hypotheses: Vec<RawHypothesis>,
    context: &ReasoningContext,
) -> PipelineOutput {
    let mut stages_executed = Vec::new();
    let n = raw_hypotheses.len();

    // Pre-compute shared values (cached across all hypotheses)
    let crosses_trust_boundary = context.has_external_call || context.has_cpi;
    let violates_invariant = context.state_mutated && !context.authority_enforced;
    let graph_edge_count = context.edge_types.len();

    // Stage 1+2: Combined Assumption Validation + Contradiction Detection
    // Single pass over hypotheses instead of two separate passes
    stages_executed.push("assumption_validation+contradiction_detection".into());
    let mut assumption_results: Vec<AssumptionValidation> = Vec::with_capacity(n);
    let mut contradiction_results: Vec<ContradictionResult> = Vec::with_capacity(n);

    for h in &raw_hypotheses {
        // Assumption validation
        let assumptions = assumption_validation::extract_assumptions(&h.kind, &h.evidence);
        assumption_results.push(assumption_validation::validate_assumptions(
            assumptions,
            &h.evidence,
            h.confidence,
        ));

        // Contradiction detection
        contradiction_results.push(contradiction::detect_contradictions(&h.evidence));
    }

    // Stage 3+4: Combined Evidence Ranking + Hypothesis Ranking
    // Cache evidence classification to avoid redundant computation
    stages_executed.push("evidence_ranking+hypothesis_ranking".into());
    let mut evidence_results: Vec<(Vec<RankedEvidence>, EvidenceQualitySummary)> =
        Vec::with_capacity(n);
    let mut ranking_inputs: Vec<RankedHypothesisInput> = Vec::with_capacity(n);

    for h in &raw_hypotheses {
        // Evidence ranking (reuses classification from ranking stage)
        let inputs: Vec<EvidenceInput> = h
            .evidence
            .iter()
            .map(|e| EvidenceInput {
                text: e.clone(),
                source: EvidenceSource::StructuralAnalysis,
                is_verified_exploit: false,
                benchmark_confirmed: false,
                is_protocol_specific: false,
                involved_functions: vec![h.affected_function.clone()],
            })
            .collect();
        let ranked = evidence_ranking::rank_evidence(&inputs);
        let quality = evidence_ranking::aggregate_evidence_quality(&ranked);
        evidence_results.push((ranked, quality));

        // Hypothesis ranking (reuse classification)
        let fact_types: Vec<String> = h
            .evidence
            .iter()
            .map(|e| classify_evidence_type(e))
            .collect();
        ranking_inputs.push(RankedHypothesisInput {
            id: h.id.clone(),
            severity: severity_to_f64(&h.severity),
            evidence_count: h.evidence.len(),
            evidence_fact_types: fact_types,
            graph_edge_count,
            reasoning_length: h.reasoning.len(),
            crosses_trust_boundary,
            violates_invariant,
            benchmark_confirmed: false,
        });
    }

    let ranked_hypotheses = ranking::rank_hypotheses(&ranking_inputs, &context.ranking_weights);

    // Stage 5: Explanation Generation (single pass)
    stages_executed.push("explanation_generation".into());
    let mut explanations: Vec<HypothesisExplanation> = Vec::with_capacity(n);

    for h in &raw_hypotheses {
        let input = ExplanationInput {
            hypothesis_id: h.id.clone(),
            hypothesis_kind: h.kind.clone(),
            affected_function: h.affected_function.clone(),
            severity: h.severity.clone(),
            evidence: h.evidence.clone(),
            reasoning: h.reasoning.clone(),
            edge_types: context.edge_types.clone(),
            has_external_call: context.has_external_call,
            has_cpi: context.has_cpi,
            state_mutated: context.state_mutated,
            authority_enforced: context.authority_enforced,
            involved_functions: context.involved_functions.clone(),
            base_confidence: h.confidence,
            assumption_adjustment: 0.0,
            contradiction_adjustment: 0.0,
        };
        explanations.push(explanation::generate_explanation(input));
    }

    // Stage 6: Counterfactual Reasoning (single pass)
    stages_executed.push("counterfactual_reasoning".into());
    let mut counterfactual_adjustments: Vec<f64> = Vec::with_capacity(n);

    for h in &raw_hypotheses {
        let cf_result = crate::counterfactual::analyze_counterfactuals(
            &h.kind,
            &h.evidence,
            &context.edge_types,
            context.has_external_call,
            context.has_cpi,
            context.state_mutated,
            context.authority_enforced,
            h.confidence,
        );
        counterfactual_adjustments.push(cf_result.adjusted_confidence - h.confidence);
    }

    // Stage 6: Assemble processed hypotheses (indexed access, no ID lookups)
    stages_executed.push("assembly".into());
    let mut processed = Vec::with_capacity(n);

    for i in 0..n {
        let h = &raw_hypotheses[i];

        // Compute final confidence (with counterfactual adjustment)
        let assumption_adj = assumption_results[i].adjusted_confidence - h.confidence;
        let contradiction_adj = (contradiction_results[i].confidence_factor - 1.0) * h.confidence;
        let counterfactual_adj = counterfactual_adjustments[i];
        let final_confidence =
            (h.confidence + assumption_adj + contradiction_adj + counterfactual_adj)
                .clamp(0.0, 1.0);

        // Determine elimination
        let (eliminated, elimination_reason) = if contradiction_results[i].high_count > 0 {
            (
                true,
                Some(format!(
                    "{} high-severity contradictions detected",
                    contradiction_results[i].high_count
                )),
            )
        } else if assumption_results[i].contradicted_count > 0 {
            (
                true,
                Some(format!(
                    "{} assumptions contradicted by evidence",
                    assumption_results[i].contradicted_count
                )),
            )
        } else if final_confidence < 0.2 {
            (
                true,
                Some(format!(
                    "Final confidence {:.2} below threshold 0.2",
                    final_confidence
                )),
            )
        } else {
            (false, None)
        };

        processed.push(ProcessedHypothesis {
            id: h.id.clone(),
            kind: h.kind.clone(),
            severity: h.severity.clone(),
            affected_function: h.affected_function.clone(),
            ranking_score: ranking_inputs[i].severity, // Will be replaced by actual score
            ranking_factors: ranking::RankingFactors {
                severity_score: ranking_inputs[i].severity,
                evidence_count_score: 0.0,
                evidence_diversity_score: 0.0,
                graph_connectivity_score: 0.0,
                reasoning_depth_score: 0.0,
                trust_boundary_score: 0.0,
                invariant_violation_score: 0.0,
                benchmark_support_score: 0.0,
            },
            assumption_validation: assumption_results[i].clone(),
            contradiction_result: contradiction_results[i].clone(),
            evidence: evidence_results[i].0.clone(),
            evidence_quality: evidence_results[i].1.clone(),
            explanation: explanations[i].clone(),
            final_confidence,
            eliminated,
            elimination_reason,
        });
    }

    // Update ranking scores from ranked results
    for p in &mut processed {
        if let Some(ranked) = ranked_hypotheses.iter().find(|r| r.hypothesis_id == p.id) {
            p.ranking_score = ranked.score;
            p.ranking_factors = ranked.factors.clone();
        }
    }

    // Stage 7: Analytics
    stages_executed.push("analytics".into());
    let analytics_input: Vec<AnalyticsInput> = processed
        .iter()
        .map(|p| AnalyticsInput {
            id: p.id.clone(),
            severity: p.severity.clone(),
            evidence_count: p.evidence.len(),
            evidence_fact_types: p.evidence.iter().map(|e| e.tier.to_string()).collect(),
            reasoning_length: p
                .explanation
                .reasoning_trace
                .iter()
                .map(|s| s.observation.len() + s.inference.len())
                .sum(),
            has_reasoning_trace: !p.explanation.reasoning_trace.is_empty(),
            has_evidence_chain: !p.explanation.evidence_chain.is_empty(),
            has_violated_invariants: !p.explanation.violated_invariants.is_empty(),
            has_trust_boundaries: !p.explanation.trust_boundaries_crossed.is_empty(),
            has_protocol_assumptions: !p.explanation.protocol_assumptions.is_empty(),
            has_confidence_breakdown: true,
            has_mitigation_rationale: !p
                .explanation
                .mitigation_rationale
                .code_suggestions
                .is_empty(),
            ranking_score: p.ranking_score,
            assumption_proven: p.assumption_validation.proven_count,
            assumption_unsupported: p.assumption_validation.unsupported_count,
            assumption_contradicted: p.assumption_validation.contradicted_count,
            assumption_unknown: p.assumption_validation.unknown_count,
            contradiction_count: p.contradiction_result.total_count,
            benchmark_confirmed: false,
            is_protocol_specific: false,
            trust_boundary_violations: p.explanation.trust_boundaries_crossed.len(),
            invariant_violations: p.explanation.violated_invariants.len(),
            historical_similarities: p.explanation.historical_similarities.len(),
            benchmark_matches: p.explanation.benchmark_matches.len(),
        })
        .collect();
    let analytics = analytics::compute_analytics(&analytics_input);

    // Split active vs eliminated
    let active: Vec<ProcessedHypothesis> = processed
        .iter()
        .filter(|p| !p.eliminated)
        .cloned()
        .collect();
    let eliminated: Vec<ProcessedHypothesis> =
        processed.iter().filter(|p| p.eliminated).cloned().collect();

    PipelineOutput {
        program_id: context.program_id.clone(),
        hypotheses: processed.clone(),
        active_hypotheses: active,
        eliminated_hypotheses: eliminated,
        analytics,
        metadata: PipelineMetadata {
            total_input: raw_hypotheses.len(),
            total_output: processed.len(),
            total_eliminated: processed.iter().filter(|p| p.eliminated).count(),
            stages_executed,
        },
    }
}

fn classify_evidence_type(evidence: &str) -> String {
    let lower = evidence.to_lowercase();
    if lower.contains("external") || lower.contains("call") {
        "external_call".into()
    } else if lower.contains("state") || lower.contains("write") {
        "state_write".into()
    } else if lower.contains("authority") || lower.contains("signer") {
        "authority_gap".into()
    } else if lower.contains("cpi") {
        "cpi_call".into()
    } else {
        "other".into()
    }
}

fn severity_to_f64(severity: &str) -> f64 {
    match severity {
        "Critical" => 1.0,
        "High" => 0.8,
        "Medium" => 0.5,
        "Low" => 0.3,
        "Info" => 0.1,
        _ => 0.5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_deterministic() {
        let hypotheses = vec![
            RawHypothesis {
                id: "H1".into(),
                kind: "ReentrancyCandidate".into(),
                severity: "High".into(),
                confidence: 0.75,
                affected_function: "withdraw".into(),
                evidence: vec![
                    "External call detected".into(),
                    "State mutation detected".into(),
                ],
                reasoning: "Function has external call before state update".into(),
            },
            RawHypothesis {
                id: "H2".into(),
                kind: "AuthorityBypassCandidate".into(),
                severity: "Critical".into(),
                confidence: 0.85,
                affected_function: "setOwner".into(),
                evidence: vec!["No authority check".into()],
                reasoning: "Public function writes state without authority".into(),
            },
        ];

        let context = ReasoningContext {
            program_id: "test".into(),
            language: "Solidity".into(),
            edge_types: vec!["external_call".into(), "state_write".into()],
            has_external_call: true,
            has_cpi: false,
            state_mutated: true,
            authority_enforced: false,
            involved_functions: vec!["withdraw".into(), "setOwner".into()],
            base_confidence: 0.7,
            ranking_weights: RankingWeights::default(),
        };

        let out1 = run_pipeline(hypotheses.clone(), &context);
        let out2 = run_pipeline(hypotheses, &context);

        assert_eq!(out1.hypotheses.len(), out2.hypotheses.len());
        for i in 0..out1.hypotheses.len() {
            assert_eq!(out1.hypotheses[i].id, out2.hypotheses[i].id);
            assert!(
                (out1.hypotheses[i].final_confidence - out2.hypotheses[i].final_confidence).abs()
                    < 0.001
            );
        }
    }

    #[test]
    fn test_contradiction_eliminates_hypothesis() {
        let hypotheses = vec![RawHypothesis {
            id: "H1".into(),
            kind: "SafePattern".into(),
            severity: "Low".into(),
            confidence: 0.3,
            affected_function: "fn1".into(),
            evidence: vec![
                "Function is safe".into(),
                "Function has unsafe reentrancy pattern".into(),
            ],
            reasoning: "Contradictory evidence".into(),
        }];

        let context = ReasoningContext::default();
        let out = run_pipeline(hypotheses, &context);

        assert!(out.hypotheses[0].eliminated);
        assert!(out.hypotheses[0].elimination_reason.is_some());
    }

    #[test]
    fn test_active_vs_eliminated() {
        let hypotheses = vec![
            RawHypothesis {
                id: "GOOD".into(),
                kind: "ReentrancyCandidate".into(),
                severity: "High".into(),
                confidence: 0.75,
                affected_function: "fn1".into(),
                evidence: vec!["External call".into()],
                reasoning: "Reentrancy pattern".into(),
            },
            RawHypothesis {
                id: "BAD".into(),
                kind: "SafePattern".into(),
                severity: "Low".into(),
                confidence: 0.3,
                affected_function: "fn1".into(),
                evidence: vec!["Safe".into(), "Unsafe".into()],
                reasoning: "Contradiction".into(),
            },
        ];

        let context = ReasoningContext::default();
        let out = run_pipeline(hypotheses, &context);

        assert_eq!(out.active_hypotheses.len(), 1);
        assert!(out.active_hypotheses[0].id == "GOOD");
    }
}
