/// Competing Hypothesis Evaluation.
///
/// Generates multiple plausible hypotheses, scores each independently,
/// compares them, eliminates weaker ones using explicit evidence,
/// and produces a final ranked shortlist with explanations for rejected candidates.
///
/// All evaluation is deterministic and explainable.
use serde::{Deserialize, Serialize};

use crate::pipeline::{run_pipeline, ProcessedHypothesis, RawHypothesis, ReasoningContext};

/// A group of competing hypotheses about the same target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompetingGroup {
    /// Target function or pattern being analyzed.
    pub target: String,
    /// All competing hypotheses.
    pub hypotheses: Vec<ProcessedHypothesis>,
    /// Winner (highest-scoring non-eliminated hypothesis).
    pub winner: Option<ProcessedHypothesis>,
    /// Eliminated hypotheses with reasons.
    pub eliminated: Vec<EliminatedHypothesis>,
    /// Group-level analysis.
    pub analysis: GroupAnalysis,
}

/// An eliminated hypothesis with explanation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EliminatedHypothesis {
    /// Original hypothesis.
    pub hypothesis: ProcessedHypothesis,
    /// Reason for elimination.
    pub reason: String,
    /// What evidence defeated this hypothesis.
    pub defeating_evidence: Vec<String>,
    /// Which hypothesis defeated it (if eliminated by competition).
    pub defeated_by: Option<String>,
}

/// Group-level analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupAnalysis {
    /// Total hypotheses evaluated.
    pub total_evaluated: usize,
    /// Hypotheses eliminated.
    pub total_eliminated: usize,
    /// Winner's score margin over second place.
    pub score_margin: f64,
    /// Whether the winner is significantly stronger than alternatives.
    pub winner_clear: bool,
    /// Explanation of the group evaluation.
    pub explanation: String,
}

/// Evaluate competing hypotheses for a single target.
///
/// Takes multiple hypotheses about the same function/pattern,
/// runs them through the pipeline, and determines the winner.
///
/// Deterministic: same inputs → same evaluation.
pub fn evaluate_competing(
    hypotheses: Vec<RawHypothesis>,
    context: &ReasoningContext,
) -> CompetingGroup {
    if hypotheses.is_empty() {
        return CompetingGroup {
            target: String::new(),
            hypotheses: vec![],
            winner: None,
            eliminated: vec![],
            analysis: GroupAnalysis {
                total_evaluated: 0,
                total_eliminated: 0,
                score_margin: 0.0,
                winner_clear: false,
                explanation: "No hypotheses to evaluate".into(),
            },
        };
    }

    let target = hypotheses[0].affected_function.clone();

    // Run pipeline on all hypotheses
    let pipeline_output = run_pipeline(hypotheses.clone(), context);

    // Separate active from eliminated
    let mut active: Vec<ProcessedHypothesis> =
        pipeline_output.active_hypotheses.into_iter().collect();
    let pipeline_eliminated_count = pipeline_output.eliminated_hypotheses.len();
    let eliminated_from_pipeline: Vec<ProcessedHypothesis> =
        pipeline_output.eliminated_hypotheses.into_iter().collect();

    // Sort active by ranking score (descending)
    active.sort_by(|a, b| {
        b.ranking_score
            .partial_cmp(&a.ranking_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Winner is the highest-scoring active hypothesis
    let winner = active.first().cloned();

    // Build eliminated list with reasons
    let mut eliminated = Vec::new();

    // Hypotheses eliminated by pipeline (contradictions, low confidence)
    for h in eliminated_from_pipeline {
        let reason = h
            .elimination_reason
            .clone()
            .unwrap_or("Unknown reason".into());
        eliminated.push(EliminatedHypothesis {
            hypothesis: h.clone(),
            reason,
            defeating_evidence: h.evidence.iter().map(|e| e.text.clone()).collect(),
            defeated_by: None,
        });
    }

    // Hypotheses eliminated by competition (lower score than winner)
    if let Some(ref winner_h) = winner {
        for h in active.iter().skip(1) {
            let margin = winner_h.ranking_score - h.ranking_score;
            let reason = if margin > 0.2 {
                format!(
                    "Significantly weaker than winner (score margin: {:.3})",
                    margin
                )
            } else if margin > 0.05 {
                format!("Weaker than winner (score margin: {:.3})", margin)
            } else {
                "Comparable to winner but lower score".into()
            };

            eliminated.push(EliminatedHypothesis {
                hypothesis: h.clone(),
                reason,
                defeating_evidence: vec![format!(
                    "Winner score: {:.3}, this score: {:.3}",
                    winner_h.ranking_score, h.ranking_score
                )],
                defeated_by: Some(winner_h.id.clone()),
            });
        }
    }

    // Group analysis
    let total_evaluated = hypotheses.len();
    let total_eliminated = eliminated.len();
    let score_margin = if active.len() >= 2 {
        active[0].ranking_score - active[1].ranking_score
    } else {
        1.0 // Only one hypothesis = clear winner
    };
    let winner_clear = score_margin > 0.1 || active.len() == 1;

    let explanation = if let Some(ref w) = winner {
        format!(
            "Hypothesis '{}' won with score {:.3}. {} eliminated ({} by pipeline, {} by competition). Score margin: {:.3}",
            w.id,
            w.ranking_score,
            total_eliminated,
            pipeline_eliminated_count,
            total_eliminated - pipeline_eliminated_count,
            score_margin
        )
    } else {
        format!(
            "No winner — all {} hypotheses were eliminated",
            total_eliminated
        )
    };

    CompetingGroup {
        target,
        hypotheses: active,
        winner,
        eliminated,
        analysis: GroupAnalysis {
            total_evaluated,
            total_eliminated,
            score_margin,
            winner_clear,
            explanation,
        },
    }
}

/// Evaluate multiple competing groups (one per function/pattern).
///
/// Groups hypotheses by target function and evaluates each group.
pub fn evaluate_all_competing(
    hypotheses: Vec<RawHypothesis>,
    context: &ReasoningContext,
) -> Vec<CompetingGroup> {
    // Group by affected function
    let mut groups: std::collections::BTreeMap<String, Vec<RawHypothesis>> =
        std::collections::BTreeMap::new();
    for h in hypotheses {
        groups
            .entry(h.affected_function.clone())
            .or_default()
            .push(h);
    }

    // Evaluate each group
    let mut results: Vec<CompetingGroup> = groups
        .into_values()
        .map(|group_hypotheses| evaluate_competing(group_hypotheses, context))
        .collect();

    // Sort by target for deterministic output
    results.sort_by(|a, b| a.target.cmp(&b.target));

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_competing_evaluation_deterministic() {
        let hypotheses = vec![
            RawHypothesis {
                id: "H1".into(),
                kind: "ReentrancyCandidate".into(),
                severity: "High".into(),
                confidence: 0.75,
                affected_function: "withdraw".into(),
                evidence: vec!["External call detected".into()],
                reasoning: "Reentrancy pattern".into(),
            },
            RawHypothesis {
                id: "H2".into(),
                kind: "AuthorityBypassCandidate".into(),
                severity: "Medium".into(),
                confidence: 0.60,
                affected_function: "withdraw".into(),
                evidence: vec!["No authority check".into()],
                reasoning: "Authority bypass".into(),
            },
        ];

        let context = ReasoningContext::default();
        let g1 = evaluate_competing(hypotheses.clone(), &context);
        let g2 = evaluate_competing(hypotheses, &context);

        assert_eq!(g1.winner.is_some(), g2.winner.is_some());
        if let (Some(w1), Some(w2)) = (&g1.winner, &g2.winner) {
            assert_eq!(w1.id, w2.id);
        }
    }

    #[test]
    fn test_winner_is_highest_scored() {
        let hypotheses = vec![
            RawHypothesis {
                id: "LOW".into(),
                kind: "LowSeverity".into(),
                severity: "Low".into(),
                confidence: 0.3,
                affected_function: "fn".into(),
                evidence: vec!["Weak evidence".into()],
                reasoning: "Weak".into(),
            },
            RawHypothesis {
                id: "HIGH".into(),
                kind: "ReentrancyCandidate".into(),
                severity: "Critical".into(),
                confidence: 0.9,
                affected_function: "fn".into(),
                evidence: vec!["Strong evidence".into(), "Multiple facts".into()],
                reasoning: "Strong reentrancy pattern".into(),
            },
        ];

        let context = ReasoningContext::default();
        let group = evaluate_competing(hypotheses, &context);

        assert!(group.winner.is_some());
        assert_eq!(group.winner.unwrap().id, "HIGH");
    }

    #[test]
    fn test_elimination_provides_reasons() {
        let hypotheses = vec![
            RawHypothesis {
                id: "H1".into(),
                kind: "ReentrancyCandidate".into(),
                severity: "High".into(),
                confidence: 0.75,
                affected_function: "fn".into(),
                evidence: vec!["External call".into()],
                reasoning: "Reentrancy".into(),
            },
            RawHypothesis {
                id: "H2".into(),
                kind: "LowSeverity".into(),
                severity: "Low".into(),
                confidence: 0.3,
                affected_function: "fn".into(),
                evidence: vec!["Weak".into()],
                reasoning: "Weak".into(),
            },
        ];

        let context = ReasoningContext::default();
        let group = evaluate_competing(hypotheses, &context);

        assert!(group.eliminated.iter().any(|e| e.hypothesis.id == "H2"));
        let h2_elim = group
            .eliminated
            .iter()
            .find(|e| e.hypothesis.id == "H2")
            .unwrap();
        assert!(!h2_elim.reason.is_empty());
    }
}
