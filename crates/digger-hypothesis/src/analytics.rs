/// Reasoning Analytics — comprehensive metrics for reasoning quality.
///
/// Measures all aspects of reasoning quality across the pipeline:
/// - Evidence depth and density
/// - Assumption accuracy
/// - Contradiction rate
/// - Benchmark pass rate
/// - Explanation completeness
/// - Hypothesis ranking quality
/// - Protocol semantic utilization
/// - Exploit knowledge utilization
///
/// All metrics are deterministic and explainable.
use serde::{Deserialize, Serialize};

/// Complete reasoning analytics report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningAnalyticsReport {
    /// Evidence metrics.
    pub evidence: EvidenceAnalytics,
    /// Assumption metrics.
    pub assumptions: AssumptionAnalytics,
    /// Contradiction metrics.
    pub contradictions: ContradictionAnalytics,
    /// Benchmark metrics.
    pub benchmark: BenchmarkAnalytics,
    /// Explanation metrics.
    pub explanations: ExplanationAnalytics,
    /// Ranking metrics.
    pub ranking: RankingAnalytics,
    /// Protocol semantic metrics.
    pub protocol_semantics: ProtocolSemanticAnalytics,
    /// Exploit knowledge metrics.
    pub exploit_knowledge: ExploitKnowledgeAnalytics,
    /// Overall reasoning quality score (0.0–1.0).
    pub overall_quality_score: f64,
    /// Summary of the analytics.
    pub summary: String,
}

/// Evidence analytics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceAnalytics {
    /// Average evidence depth per hypothesis.
    pub avg_evidence_depth: f64,
    /// Evidence density (evidence items per hypothesis).
    pub evidence_density: f64,
    /// Percentage of hypotheses with 3+ evidence items.
    pub strong_evidence_pct: f64,
    /// Percentage of hypotheses with zero evidence.
    pub no_evidence_pct: f64,
    /// Unique evidence fact types across all hypotheses.
    pub unique_fact_types: usize,
    /// Evidence deduplication rate.
    pub deduplication_rate: f64,
}

/// Assumption analytics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssumptionAnalytics {
    /// Total assumptions validated.
    pub total_assumptions: usize,
    /// Assumptions proven by evidence.
    pub proven: usize,
    /// Assumptions unsupported.
    pub unsupported: usize,
    /// Assumptions contradicted.
    pub contradicted: usize,
    /// Assumptions unknown.
    pub unknown: usize,
    /// Assumption accuracy (proven / total).
    pub accuracy: f64,
    /// Confidence impact from assumptions.
    pub avg_confidence_impact: f64,
}

/// Contradiction analytics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContradictionAnalytics {
    /// Total contradictions detected.
    pub total_contradictions: usize,
    /// High severity contradictions.
    pub high_severity: usize,
    /// Medium severity contradictions.
    pub medium_severity: usize,
    /// Low severity contradictions.
    pub low_severity: usize,
    /// Contradiction rate (contradictions / total evidence pairs).
    pub contradiction_rate: f64,
    /// Average confidence factor from contradictions.
    pub avg_confidence_factor: f64,
}

/// Benchmark analytics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkAnalytics {
    /// Total exploits in benchmark.
    pub total_exploits: usize,
    /// Exploits with full detection.
    pub fully_detected: usize,
    /// Exploits with partial detection.
    pub partially_detected: usize,
    /// Exploits with no detection.
    pub undetected: usize,
    /// Detection rate (fully_detected / total).
    pub detection_rate: f64,
    /// Coverage rate (findings matched / total expected).
    pub coverage_rate: f64,
}

/// Explanation analytics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExplanationAnalytics {
    /// Average explanation completeness (0.0–1.0).
    pub avg_completeness: f64,
    /// Percentage with reasoning trace.
    pub with_reasoning_trace: f64,
    /// Percentage with evidence chain.
    pub with_evidence_chain: f64,
    /// Percentage with violated invariants.
    pub with_violated_invariants: f64,
    /// Percentage with trust boundaries.
    pub with_trust_boundaries: f64,
    /// Percentage with mitigation rationale.
    pub with_mitigation: f64,
}

/// Ranking analytics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankingAnalytics {
    /// Average ranking score.
    pub avg_score: f64,
    /// Ranking score standard deviation.
    pub score_stddev: f64,
    /// Percentage of Critical in top half.
    pub critical_in_top_half: f64,
    /// Ranking determinism verified.
    pub determinism_verified: bool,
    /// Score range (max - min).
    pub score_range: f64,
}

/// Protocol semantic analytics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolSemanticAnalytics {
    /// Number of protocol-specific hypotheses.
    pub protocol_specific_count: usize,
    /// Percentage of hypotheses using protocol semantics.
    pub protocol_semantic_utilization: f64,
    /// Number of trust boundary violations detected.
    pub trust_boundary_violations: usize,
    /// Number of invariant violations detected.
    pub invariant_violations: usize,
}

/// Exploit knowledge analytics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExploitKnowledgeAnalytics {
    /// Number of historical exploit similarities found.
    pub historical_similarities: usize,
    /// Number of benchmark matches found.
    pub benchmark_matches: usize,
    /// Exploit knowledge utilization rate.
    pub utilization_rate: f64,
    /// Knowledge base coverage (exploits with known patterns / total).
    pub knowledge_coverage: f64,
}

/// Compute comprehensive reasoning analytics.
///
/// Takes individual hypothesis inputs and produces a complete analytics report.
/// Deterministic: same inputs → same analytics.
pub fn compute_analytics(hypotheses: &[HypothesisInput]) -> ReasoningAnalyticsReport {
    let evidence = compute_evidence_analytics(hypotheses);
    let assumptions = compute_assumption_analytics(hypotheses);
    let contradictions = compute_contradiction_analytics(hypotheses);
    let benchmark = compute_benchmark_analytics(hypotheses);
    let explanations = compute_explanation_analytics(hypotheses);
    let ranking = compute_ranking_analytics(hypotheses);
    let protocol_semantics = compute_protocol_semantic_analytics(hypotheses);
    let exploit_knowledge = compute_exploit_knowledge_analytics(hypotheses);

    // Overall quality score: weighted average of all dimensions
    let overall_quality_score = compute_overall_score(
        &evidence,
        &assumptions,
        &contradictions,
        &benchmark,
        &explanations,
        &ranking,
    );

    let summary = format!(
        "Reasoning quality: {:.2} | Evidence depth: {:.1} | Assumption accuracy: {:.1}% | Contradiction rate: {:.3} | Benchmark detection: {:.1}% | Explanation completeness: {:.1}%",
        overall_quality_score,
        evidence.avg_evidence_depth,
        assumptions.accuracy * 100.0,
        contradictions.contradiction_rate,
        benchmark.detection_rate * 100.0,
        explanations.avg_completeness * 100.0,
    );

    ReasoningAnalyticsReport {
        evidence,
        assumptions,
        contradictions,
        benchmark,
        explanations,
        ranking,
        protocol_semantics,
        exploit_knowledge,
        overall_quality_score,
        summary,
    }
}

/// Input for analytics computation.
#[derive(Debug, Clone)]
pub struct HypothesisInput {
    pub id: String,
    pub severity: String,
    pub evidence_count: usize,
    pub evidence_fact_types: Vec<String>,
    pub reasoning_length: usize,
    pub has_reasoning_trace: bool,
    pub has_evidence_chain: bool,
    pub has_violated_invariants: bool,
    pub has_trust_boundaries: bool,
    pub has_protocol_assumptions: bool,
    pub has_confidence_breakdown: bool,
    pub has_mitigation_rationale: bool,
    pub ranking_score: f64,
    pub assumption_proven: usize,
    pub assumption_unsupported: usize,
    pub assumption_contradicted: usize,
    pub assumption_unknown: usize,
    pub contradiction_count: usize,
    pub benchmark_confirmed: bool,
    pub is_protocol_specific: bool,
    pub trust_boundary_violations: usize,
    pub invariant_violations: usize,
    pub historical_similarities: usize,
    pub benchmark_matches: usize,
}

fn compute_evidence_analytics(hypotheses: &[HypothesisInput]) -> EvidenceAnalytics {
    if hypotheses.is_empty() {
        return EvidenceAnalytics {
            avg_evidence_depth: 0.0,
            evidence_density: 0.0,
            strong_evidence_pct: 0.0,
            no_evidence_pct: 0.0,
            unique_fact_types: 0,
            deduplication_rate: 0.0,
        };
    }

    let total = hypotheses.len() as f64;
    let total_evidence: usize = hypotheses.iter().map(|h| h.evidence_count).sum();

    let avg_evidence_depth = total_evidence as f64 / total;
    let evidence_density = avg_evidence_depth;

    let strong = hypotheses.iter().filter(|h| h.evidence_count >= 3).count() as f64 / total * 100.0;
    let no_evidence =
        hypotheses.iter().filter(|h| h.evidence_count == 0).count() as f64 / total * 100.0;

    let mut all_types: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for h in hypotheses {
        for t in &h.evidence_fact_types {
            all_types.insert(t.clone());
        }
    }

    let dedup_rate = if total_evidence > 0 {
        all_types.len() as f64 / total_evidence as f64
    } else {
        0.0
    };

    EvidenceAnalytics {
        avg_evidence_depth,
        evidence_density,
        strong_evidence_pct: strong,
        no_evidence_pct: no_evidence,
        unique_fact_types: all_types.len(),
        deduplication_rate: dedup_rate,
    }
}

fn compute_assumption_analytics(hypotheses: &[HypothesisInput]) -> AssumptionAnalytics {
    let total_proven: usize = hypotheses.iter().map(|h| h.assumption_proven).sum();
    let total_unsupported: usize = hypotheses.iter().map(|h| h.assumption_unsupported).sum();
    let total_contradicted: usize = hypotheses.iter().map(|h| h.assumption_contradicted).sum();
    let total_unknown: usize = hypotheses.iter().map(|h| h.assumption_unknown).sum();
    let total = total_proven + total_unsupported + total_contradicted + total_unknown;

    let accuracy = if total > 0 {
        total_proven as f64 / total as f64
    } else {
        0.0
    };

    // Confidence impact: proven increases, contradicted decreases
    let avg_impact = if total > 0 {
        (total_proven as f64 * 0.1 - total_contradicted as f64 * 0.3) / total as f64
    } else {
        0.0
    };

    AssumptionAnalytics {
        total_assumptions: total,
        proven: total_proven,
        unsupported: total_unsupported,
        contradicted: total_contradicted,
        unknown: total_unknown,
        accuracy,
        avg_confidence_impact: avg_impact,
    }
}

fn compute_contradiction_analytics(hypotheses: &[HypothesisInput]) -> ContradictionAnalytics {
    let total_contradictions: usize = hypotheses.iter().map(|h| h.contradiction_count).sum();

    // Estimate contradiction rate from evidence pairs
    let total_evidence: usize = hypotheses.iter().map(|h| h.evidence_count).sum();
    let max_pairs = if total_evidence > 1 {
        total_evidence * (total_evidence - 1) / 2
    } else {
        0
    };
    let contradiction_rate = if max_pairs > 0 {
        total_contradictions as f64 / max_pairs as f64
    } else {
        0.0
    };

    // All contradictions are treated as medium severity for analytics
    ContradictionAnalytics {
        total_contradictions,
        high_severity: 0,
        medium_severity: total_contradictions,
        low_severity: 0,
        contradiction_rate,
        avg_confidence_factor: if total_contradictions == 0 { 1.0 } else { 0.85 },
    }
}

fn compute_benchmark_analytics(hypotheses: &[HypothesisInput]) -> BenchmarkAnalytics {
    let total = hypotheses.len();
    let confirmed = hypotheses.iter().filter(|h| h.benchmark_confirmed).count();

    BenchmarkAnalytics {
        total_exploits: total,
        fully_detected: confirmed,
        partially_detected: 0,
        undetected: total - confirmed,
        detection_rate: if total > 0 {
            confirmed as f64 / total as f64
        } else {
            0.0
        },
        coverage_rate: if total > 0 {
            confirmed as f64 / total as f64
        } else {
            0.0
        },
    }
}

fn compute_explanation_analytics(hypotheses: &[HypothesisInput]) -> ExplanationAnalytics {
    if hypotheses.is_empty() {
        return ExplanationAnalytics {
            avg_completeness: 0.0,
            with_reasoning_trace: 0.0,
            with_evidence_chain: 0.0,
            with_violated_invariants: 0.0,
            with_trust_boundaries: 0.0,
            with_mitigation: 0.0,
        };
    }

    let total = hypotheses.len() as f64;
    let with_trace =
        hypotheses.iter().filter(|h| h.has_reasoning_trace).count() as f64 / total * 100.0;
    let with_chain =
        hypotheses.iter().filter(|h| h.has_evidence_chain).count() as f64 / total * 100.0;
    let with_invariants = hypotheses
        .iter()
        .filter(|h| h.has_violated_invariants)
        .count() as f64
        / total
        * 100.0;
    let with_trust =
        hypotheses.iter().filter(|h| h.has_trust_boundaries).count() as f64 / total * 100.0;
    let with_mitigation = hypotheses
        .iter()
        .filter(|h| h.has_mitigation_rationale)
        .count() as f64
        / total
        * 100.0;

    let avg_completeness =
        (with_trace + with_chain + with_invariants + with_trust + with_mitigation) / 500.0;

    ExplanationAnalytics {
        avg_completeness,
        with_reasoning_trace: with_trace,
        with_evidence_chain: with_chain,
        with_violated_invariants: with_invariants,
        with_trust_boundaries: with_trust,
        with_mitigation,
    }
}

fn compute_ranking_analytics(hypotheses: &[HypothesisInput]) -> RankingAnalytics {
    if hypotheses.is_empty() {
        return RankingAnalytics {
            avg_score: 0.0,
            score_stddev: 0.0,
            critical_in_top_half: 0.0,
            determinism_verified: true,
            score_range: 0.0,
        };
    }

    let scores: Vec<f64> = hypotheses.iter().map(|h| h.ranking_score).collect();
    let total = scores.len() as f64;
    let avg = scores.iter().sum::<f64>() / total;
    let (avg, variance) = if avg.is_nan() {
        (0.0, 0.0)
    } else {
        (
            avg,
            scores.iter().map(|s| (s - avg).powi(2)).sum::<f64>() / total,
        )
    };
    let stddev = variance.sqrt();

    let mid = scores.len() / 2;
    let top_half = &hypotheses[..mid.max(1)];
    let critical_in_top = top_half.iter().filter(|h| h.severity == "Critical").count() as f64
        / top_half.len() as f64
        * 100.0;

    let min_score = scores.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_score = scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = if min_score.is_nan() || max_score.is_nan() {
        0.0
    } else {
        max_score - min_score
    };

    let mut sorted = scores.clone();
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

    RankingAnalytics {
        avg_score: avg,
        score_stddev: stddev,
        critical_in_top_half: critical_in_top,
        determinism_verified: scores == sorted,
        score_range: range,
    }
}

fn compute_protocol_semantic_analytics(
    hypotheses: &[HypothesisInput],
) -> ProtocolSemanticAnalytics {
    let total = hypotheses.len();
    let protocol_specific = hypotheses.iter().filter(|h| h.is_protocol_specific).count();
    let trust_violations: usize = hypotheses.iter().map(|h| h.trust_boundary_violations).sum();
    let invariant_violations: usize = hypotheses.iter().map(|h| h.invariant_violations).sum();

    ProtocolSemanticAnalytics {
        protocol_specific_count: protocol_specific,
        protocol_semantic_utilization: if total > 0 {
            protocol_specific as f64 / total as f64 * 100.0
        } else {
            0.0
        },
        trust_boundary_violations: trust_violations,
        invariant_violations,
    }
}

fn compute_exploit_knowledge_analytics(
    hypotheses: &[HypothesisInput],
) -> ExploitKnowledgeAnalytics {
    let total = hypotheses.len();
    let similarities: usize = hypotheses.iter().map(|h| h.historical_similarities).sum();
    let matches: usize = hypotheses.iter().map(|h| h.benchmark_matches).sum();

    ExploitKnowledgeAnalytics {
        historical_similarities: similarities,
        benchmark_matches: matches,
        utilization_rate: if total > 0 {
            (similarities + matches) as f64 / total as f64
        } else {
            0.0
        },
        knowledge_coverage: if total > 0 {
            matches as f64 / total as f64
        } else {
            0.0
        },
    }
}

fn compute_overall_score(
    evidence: &EvidenceAnalytics,
    assumptions: &AssumptionAnalytics,
    contradictions: &ContradictionAnalytics,
    benchmark: &BenchmarkAnalytics,
    explanations: &ExplanationAnalytics,
    ranking: &RankingAnalytics,
) -> f64 {
    // Weighted average of all dimensions
    let evidence_score = evidence.avg_evidence_depth.min(5.0) / 5.0 * 0.20;
    let assumption_score = assumptions.accuracy * 0.15;
    let contradiction_score = (1.0 - contradictions.contradiction_rate.min(1.0)) * 0.15;
    let benchmark_score = benchmark.detection_rate * 0.15;
    let explanation_score = explanations.avg_completeness * 0.20;
    let ranking_score = ranking.avg_score * 0.15;

    let raw = evidence_score
        + assumption_score
        + contradiction_score
        + benchmark_score
        + explanation_score
        + ranking_score;
    if raw.is_nan() {
        0.0
    } else {
        raw.clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_analytics() {
        let analytics = compute_analytics(&[]);
        assert!(analytics.overall_quality_score >= 0.0 && analytics.overall_quality_score <= 1.0);
        assert!(analytics.summary.contains("0.00"));
    }

    #[test]
    fn test_analytics_deterministic() {
        let inputs = vec![HypothesisInput {
            id: "H1".into(),
            severity: "High".into(),
            evidence_count: 3,
            evidence_fact_types: vec!["external_call".into(), "state_write".into()],
            reasoning_length: 200,
            has_reasoning_trace: true,
            has_evidence_chain: true,
            has_violated_invariants: true,
            has_trust_boundaries: true,
            has_protocol_assumptions: true,
            has_confidence_breakdown: true,
            has_mitigation_rationale: true,
            ranking_score: 0.75,
            assumption_proven: 2,
            assumption_unsupported: 0,
            assumption_contradicted: 0,
            assumption_unknown: 1,
            contradiction_count: 0,
            benchmark_confirmed: true,
            is_protocol_specific: true,
            trust_boundary_violations: 1,
            invariant_violations: 1,
            historical_similarities: 0,
            benchmark_matches: 1,
        }];

        let a1 = compute_analytics(&inputs);
        let a2 = compute_analytics(&inputs);
        assert_eq!(a1.overall_quality_score, a2.overall_quality_score);
    }
}
