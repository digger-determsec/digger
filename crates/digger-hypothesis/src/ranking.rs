/// Deterministic Hypothesis Ranking Engine.
///
/// Ranks hypotheses by structural evidence rather than discovery order.
/// Every score is explainable and traceable to explicit evidence.
///
/// Weights are configurable but deterministic — same inputs always
/// produce the same ranking.
use serde::{Deserialize, Serialize};

/// Ranking configuration — fixed weights for each factor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankingWeights {
    /// Weight for severity (0.0–1.0).
    pub severity: f64,
    /// Weight for evidence count (0.0–1.0).
    pub evidence_count: f64,
    /// Weight for evidence diversity (different fact types) (0.0–1.0).
    pub evidence_diversity: f64,
    /// Weight for graph connectivity (edges touching affected function) (0.0–1.0).
    pub graph_connectivity: f64,
    /// Weight for reasoning depth (text length as proxy) (0.0–1.0).
    pub reasoning_depth: f64,
    /// Weight for trust boundary violation (0.0–1.0).
    pub trust_boundary: f64,
    /// Weight for invariant violation (0.0–1.0).
    pub invariant_violation: f64,
    /// Weight for benchmark support (0.0–1.0).
    pub benchmark_support: f64,
}

impl Default for RankingWeights {
    fn default() -> Self {
        Self {
            severity: 0.25,
            evidence_count: 0.15,
            evidence_diversity: 0.15,
            graph_connectivity: 0.10,
            reasoning_depth: 0.10,
            trust_boundary: 0.10,
            invariant_violation: 0.10,
            benchmark_support: 0.05,
        }
    }
}

impl RankingWeights {
    /// Validate and normalize weights: clamp to [0.0, 1.0], then normalize sum to 1.0.
    pub fn validate(self) -> Self {
        let mut w = self;
        w.severity = w.severity.clamp(0.0, 1.0);
        w.evidence_count = w.evidence_count.clamp(0.0, 1.0);
        w.evidence_diversity = w.evidence_diversity.clamp(0.0, 1.0);
        w.graph_connectivity = w.graph_connectivity.clamp(0.0, 1.0);
        w.reasoning_depth = w.reasoning_depth.clamp(0.0, 1.0);
        w.trust_boundary = w.trust_boundary.clamp(0.0, 1.0);
        w.invariant_violation = w.invariant_violation.clamp(0.0, 1.0);
        w.benchmark_support = w.benchmark_support.clamp(0.0, 1.0);

        let sum = w.severity
            + w.evidence_count
            + w.evidence_diversity
            + w.graph_connectivity
            + w.reasoning_depth
            + w.trust_boundary
            + w.invariant_violation
            + w.benchmark_support;

        if sum > 0.0 && (sum - 1.0).abs() > f64::EPSILON {
            let inv = 1.0 / sum;
            w.severity *= inv;
            w.evidence_count *= inv;
            w.evidence_diversity *= inv;
            w.graph_connectivity *= inv;
            w.reasoning_depth *= inv;
            w.trust_boundary *= inv;
            w.invariant_violation *= inv;
            w.benchmark_support *= inv;
        }
        w
    }
}

/// A scored hypothesis with explainable ranking factors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoredHypothesis {
    /// Original hypothesis ID.
    pub hypothesis_id: String,
    /// Composite ranking score (0.0–1.0).
    pub score: f64,
    /// Individual factor scores.
    pub factors: RankingFactors,
    /// Human-readable explanation of why this score was assigned.
    pub explanation: String,
}

/// Individual ranking factor scores.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankingFactors {
    /// Severity score (0.0–1.0).
    pub severity_score: f64,
    /// Evidence count score (0.0–1.0).
    pub evidence_count_score: f64,
    /// Evidence diversity score (0.0–1.0).
    pub evidence_diversity_score: f64,
    /// Graph connectivity score (0.0–1.0).
    pub graph_connectivity_score: f64,
    /// Reasoning depth score (0.0–1.0).
    pub reasoning_depth_score: f64,
    /// Trust boundary violation score (0.0–1.0).
    pub trust_boundary_score: f64,
    /// Invariant violation score (0.0–1.0).
    pub invariant_violation_score: f64,
    /// Benchmark support score (0.0–1.0).
    pub benchmark_support_score: f64,
}

/// Rank hypotheses using structural evidence factors.
///
/// Deterministic: same inputs → same ranking.
/// No ML, no probabilistic scoring, no external services.
pub fn rank_hypotheses(
    hypotheses: &[RankedHypothesisInput],
    weights: &RankingWeights,
) -> Vec<ScoredHypothesis> {
    let mut scored: Vec<ScoredHypothesis> = hypotheses
        .iter()
        .map(|h| score_hypothesis(h, weights))
        .collect();

    // Sort by score descending, then by ID for deterministic tiebreaking
    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.hypothesis_id.cmp(&b.hypothesis_id))
    });

    scored
}

/// Input data needed to rank a single hypothesis.
#[derive(Debug, Clone)]
pub struct RankedHypothesisInput {
    /// Hypothesis ID.
    pub id: String,
    /// Severity level (Critical=1.0, High=0.8, Medium=0.5, Low=0.3, Info=0.1).
    pub severity: f64,
    /// Number of evidence items supporting this hypothesis.
    pub evidence_count: usize,
    /// Distinct evidence fact types (e.g., "external_call", "state_write", "authority_gap").
    pub evidence_fact_types: Vec<String>,
    /// Number of edges touching the affected function in the IR.
    pub graph_edge_count: usize,
    /// Length of reasoning text (characters).
    pub reasoning_length: usize,
    /// Whether this hypothesis crosses a trust boundary (external call, CPI).
    pub crosses_trust_boundary: bool,
    /// Whether this hypothesis violates a protocol invariant.
    pub violates_invariant: bool,
    /// Whether this hypothesis is confirmed by benchmark data.
    pub benchmark_confirmed: bool,
}

fn score_hypothesis(input: &RankedHypothesisInput, weights: &RankingWeights) -> ScoredHypothesis {
    let severity_score = input.severity;

    // Evidence count: normalize to 0.0–1.0 with diminishing returns
    // 1 evidence = 0.3, 5 = 0.7, 10+ = 1.0
    let evidence_count_score = if input.evidence_count == 0 {
        0.0
    } else {
        ((input.evidence_count as f64).ln_1p() / 10.0_f64.ln_1p()).min(1.0)
    };

    // Evidence diversity: unique fact types / max expected types (6)
    let unique_types: std::collections::BTreeSet<&str> = input
        .evidence_fact_types
        .iter()
        .map(|s| s.as_str())
        .collect();
    let evidence_diversity_score = (unique_types.len() as f64 / 6.0).min(1.0);

    // Graph connectivity: normalize edge count to 0.0–1.0
    // 0 edges = 0.0, 5 = 0.5, 10+ = 1.0
    let graph_connectivity_score = (input.graph_edge_count as f64 / 10.0).min(1.0);

    // Reasoning depth: normalize text length to 0.0–1.0
    // 0 chars = 0.0, 200 = 0.5, 400+ = 1.0
    let reasoning_depth_score = (input.reasoning_length as f64 / 400.0).min(1.0);

    // Trust boundary: binary (0.0 or 1.0)
    let trust_boundary_score = if input.crosses_trust_boundary {
        1.0
    } else {
        0.0
    };

    // Invariant violation: binary (0.0 or 1.0)
    let invariant_violation_score = if input.violates_invariant { 1.0 } else { 0.0 };

    // Benchmark support: binary (0.0 or 1.0)
    let benchmark_support_score = if input.benchmark_confirmed { 1.0 } else { 0.0 };

    // Composite score
    let score = severity_score * weights.severity
        + evidence_count_score * weights.evidence_count
        + evidence_diversity_score * weights.evidence_diversity
        + graph_connectivity_score * weights.graph_connectivity
        + reasoning_depth_score * weights.reasoning_depth
        + trust_boundary_score * weights.trust_boundary
        + invariant_violation_score * weights.invariant_violation
        + benchmark_support_score * weights.benchmark_support;

    // Build explanation
    let explanation = build_explanation(
        severity_score,
        evidence_count_score,
        evidence_diversity_score,
        graph_connectivity_score,
        reasoning_depth_score,
        trust_boundary_score,
        invariant_violation_score,
        benchmark_support_score,
        score,
    );

    ScoredHypothesis {
        hypothesis_id: input.id.clone(),
        score,
        factors: RankingFactors {
            severity_score,
            evidence_count_score,
            evidence_diversity_score,
            graph_connectivity_score,
            reasoning_depth_score,
            trust_boundary_score,
            invariant_violation_score,
            benchmark_support_score,
        },
        explanation,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_explanation(
    severity: f64,
    evidence_count: f64,
    evidence_diversity: f64,
    graph_connectivity: f64,
    reasoning_depth: f64,
    trust_boundary: f64,
    invariant_violation: f64,
    benchmark_support: f64,
    total: f64,
) -> String {
    let mut factors = Vec::new();

    if severity > 0.7 {
        factors.push(format!("high severity ({:.2})", severity));
    }
    if evidence_count > 0.5 {
        factors.push(format!("strong evidence count ({:.2})", evidence_count));
    }
    if evidence_diversity > 0.5 {
        factors.push(format!(
            "diverse evidence types ({:.2})",
            evidence_diversity
        ));
    }
    if graph_connectivity > 0.5 {
        factors.push(format!(
            "high graph connectivity ({:.2})",
            graph_connectivity
        ));
    }
    if reasoning_depth > 0.5 {
        factors.push(format!("deep reasoning ({:.2})", reasoning_depth));
    }
    if trust_boundary > 0.5 {
        factors.push("trust boundary violation".into());
    }
    if invariant_violation > 0.5 {
        factors.push("invariant violation".into());
    }
    if benchmark_support > 0.5 {
        factors.push("benchmark confirmed".into());
    }

    if factors.is_empty() {
        format!("low confidence across all factors (score: {:.3})", total)
    } else {
        format!("scored {:.3} based on: {}", total, factors.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranking_deterministic() {
        let inputs = vec![
            RankedHypothesisInput {
                id: "H1".into(),
                severity: 1.0,
                evidence_count: 5,
                evidence_fact_types: vec!["external_call".into(), "state_write".into()],
                graph_edge_count: 8,
                reasoning_length: 300,
                crosses_trust_boundary: true,
                violates_invariant: false,
                benchmark_confirmed: false,
            },
            RankedHypothesisInput {
                id: "H2".into(),
                severity: 0.5,
                evidence_count: 2,
                evidence_fact_types: vec!["state_write".into()],
                graph_edge_count: 3,
                reasoning_length: 100,
                crosses_trust_boundary: false,
                violates_invariant: true,
                benchmark_confirmed: false,
            },
        ];

        let weights = RankingWeights::default();
        let result1 = rank_hypotheses(&inputs, &weights);
        let result2 = rank_hypotheses(&inputs, &weights);

        assert_eq!(result1.len(), result2.len());
        for i in 0..result1.len() {
            assert_eq!(result1[i].hypothesis_id, result2[i].hypothesis_id);
            assert!((result1[i].score - result2[i].score).abs() < 0.001);
        }
    }

    #[test]
    fn test_severity_dominates() {
        let inputs = vec![
            RankedHypothesisInput {
                id: "LOW".into(),
                severity: 0.3,
                evidence_count: 1,
                evidence_fact_types: vec!["state_write".into()],
                graph_edge_count: 2,
                reasoning_length: 50,
                crosses_trust_boundary: false,
                violates_invariant: false,
                benchmark_confirmed: false,
            },
            RankedHypothesisInput {
                id: "CRIT".into(),
                severity: 1.0,
                evidence_count: 1,
                evidence_fact_types: vec!["external_call".into()],
                graph_edge_count: 2,
                reasoning_length: 50,
                crosses_trust_boundary: false,
                violates_invariant: false,
                benchmark_confirmed: false,
            },
        ];

        let weights = RankingWeights::default();
        let result = rank_hypotheses(&inputs, &weights);

        // CRIT should rank higher due to severity weight (all other factors equal)
        assert_eq!(result[0].hypothesis_id, "CRIT");
    }

    #[test]
    fn test_benchmark_confirmation_boosts() {
        let base = RankedHypothesisInput {
            id: "BASE".into(),
            severity: 0.5,
            evidence_count: 3,
            evidence_fact_types: vec!["state_write".into()],
            graph_edge_count: 5,
            reasoning_length: 200,
            crosses_trust_boundary: false,
            violates_invariant: false,
            benchmark_confirmed: false,
        };

        let confirmed = RankedHypothesisInput {
            id: "CONFIRMED".into(),
            severity: 0.5,
            evidence_count: 3,
            evidence_fact_types: vec!["state_write".into()],
            graph_edge_count: 5,
            reasoning_length: 200,
            crosses_trust_boundary: false,
            violates_invariant: false,
            benchmark_confirmed: true,
        };

        let weights = RankingWeights::default();
        let base_score = score_hypothesis(&base, &weights).score;
        let confirmed_score = score_hypothesis(&confirmed, &weights).score;

        assert!(
            confirmed_score > base_score,
            "Benchmark confirmation should increase score"
        );
    }
}
