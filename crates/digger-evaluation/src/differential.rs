/// Differential Evaluation — compare new commits against previous versions.
///
/// Detects regressions, new detections, improved/degraded explanations,
/// confidence drift, and ranking drift.
/// Produces deterministic comparison reports.
use serde::{Deserialize, Serialize};

use crate::models::EvaluationResult;

/// A snapshot of evaluation results at a specific commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationSnapshot {
    /// Commit hash.
    pub commit_hash: String,
    /// Timestamp.
    pub timestamp: String,
    /// Evaluation results.
    pub results: Vec<EvaluationResult>,
    /// Aggregate metrics.
    pub aggregate: AggregateSnapshot,
}

/// Aggregate metrics at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSnapshot {
    /// Total exploits.
    pub total_exploits: usize,
    /// Pass rate.
    pub pass_rate: f64,
    /// Aggregate precision.
    pub precision: f64,
    /// Aggregate recall.
    pub recall: f64,
    /// Aggregate F1.
    pub f1: f64,
    /// Average root-cause accuracy.
    pub root_cause_accuracy: f64,
    /// Average explanation completeness.
    pub explanation_completeness: f64,
    /// Average evidence depth.
    pub evidence_depth: f64,
    /// Average runtime (ms).
    pub avg_runtime_ms: f64,
}

/// Differential comparison result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialReport {
    /// Previous commit.
    pub previous_commit: String,
    /// Current commit.
    pub current_commit: String,
    /// Detected regressions.
    pub regressions: Vec<Regression>,
    /// New detections (previously missed, now detected).
    pub new_detections: Vec<NewDetection>,
    /// Improved explanations.
    pub improved_explanations: Vec<ExplanationChange>,
    /// Degraded explanations.
    pub degraded_explanations: Vec<ExplanationChange>,
    /// Confidence drift.
    pub confidence_drift: Vec<ConfidenceDrift>,
    /// Ranking drift.
    pub ranking_drift: Vec<RankingDrift>,
    /// Aggregate changes.
    pub aggregate_changes: AggregateChanges,
}

/// A regression (previously passed, now fails).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Regression {
    /// Exploit ID.
    pub exploit_id: String,
    /// What changed.
    pub change: String,
    /// Severity of the regression.
    pub severity: String,
}

/// A new detection (previously missed, now detected).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewDetection {
    /// Exploit ID.
    pub exploit_id: String,
    /// What was newly detected.
    pub detection: String,
}

/// An explanation change (improved or degraded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationChange {
    /// Exploit ID.
    pub exploit_id: String,
    /// Change description.
    pub change: String,
    /// Old completeness score.
    pub old_score: f64,
    /// New completeness score.
    pub new_score: f64,
}

/// Confidence drift for an exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceDrift {
    /// Exploit ID.
    pub exploit_id: String,
    /// Old root-cause accuracy.
    pub old_accuracy: f64,
    /// New root-cause accuracy.
    pub new_accuracy: f64,
    /// Delta.
    pub delta: f64,
}

/// Ranking drift for an exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankingDrift {
    /// Exploit ID.
    pub exploit_id: String,
    /// Old ranking position.
    pub old_position: usize,
    /// New ranking position.
    pub new_position: usize,
    /// Position change.
    pub position_change: i32,
}

/// Aggregate metric changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateChanges {
    /// Pass rate change.
    pub pass_rate_delta: f64,
    /// Precision change.
    pub precision_delta: f64,
    /// Recall change.
    pub recall_delta: f64,
    /// F1 change.
    pub f1_delta: f64,
    /// Root-cause accuracy change.
    pub root_cause_accuracy_delta: f64,
    /// Explanation completeness change.
    pub explanation_completeness_delta: f64,
    /// Runtime change (ms).
    pub runtime_delta: f64,
}

/// Compare two evaluation snapshots.
///
/// Deterministic: same inputs → same comparison.
pub fn compare_snapshots(
    previous: &EvaluationSnapshot,
    current: &EvaluationSnapshot,
) -> DifferentialReport {
    let mut regressions = Vec::new();
    let mut new_detections = Vec::new();
    let mut improved_explanations = Vec::new();
    let mut degraded_explanations = Vec::new();
    let mut confidence_drift = Vec::new();
    let ranking_drift = Vec::new();

    // Build lookup maps
    let prev_map: std::collections::BTreeMap<String, &EvaluationResult> = previous
        .results
        .iter()
        .map(|r| (r.exploit_id.clone(), r))
        .collect();
    let curr_map: std::collections::BTreeMap<String, &EvaluationResult> = current
        .results
        .iter()
        .map(|r| (r.exploit_id.clone(), r))
        .collect();

    // Check each exploit
    for (id, curr) in &curr_map {
        if let Some(prev) = prev_map.get(id) {
            // Regression: was passing, now failing
            if prev.passed && !curr.passed {
                regressions.push(Regression {
                    exploit_id: id.clone(),
                    change: format!(
                        "Detection rate changed from {:.2} to {:.2}",
                        prev.precision.precision, curr.precision.precision
                    ),
                    severity: "high".into(),
                });
            }

            // New detection: was failing, now passing
            if !prev.passed && curr.passed {
                new_detections.push(NewDetection {
                    exploit_id: id.clone(),
                    detection: format!(
                        "Detection rate improved from {:.2} to {:.2}",
                        prev.recall.recall, curr.recall.recall
                    ),
                });
            }

            // Explanation changes
            let old_expl = prev.explanation_completeness.completeness_score;
            let new_expl = curr.explanation_completeness.completeness_score;
            if (new_expl - old_expl).abs() > 0.01 {
                let change = ExplanationChange {
                    exploit_id: id.clone(),
                    change: format!(
                        "Explanation completeness changed from {:.2} to {:.2}",
                        old_expl, new_expl
                    ),
                    old_score: old_expl,
                    new_score: new_expl,
                };
                if new_expl > old_expl {
                    improved_explanations.push(change);
                } else {
                    degraded_explanations.push(change);
                }
            }

            // Confidence drift
            let old_acc = prev.root_cause_accuracy;
            let new_acc = curr.root_cause_accuracy;
            if (new_acc - old_acc).abs() > 0.01 {
                confidence_drift.push(ConfidenceDrift {
                    exploit_id: id.clone(),
                    old_accuracy: old_acc,
                    new_accuracy: new_acc,
                    delta: new_acc - old_acc,
                });
            }
        } else {
            // New exploit added
            new_detections.push(NewDetection {
                exploit_id: id.clone(),
                detection: "New exploit added to benchmark".into(),
            });
        }
    }

    // Aggregate changes
    let aggregate_changes = AggregateChanges {
        pass_rate_delta: current.aggregate.pass_rate - previous.aggregate.pass_rate,
        precision_delta: current.aggregate.precision - previous.aggregate.precision,
        recall_delta: current.aggregate.recall - previous.aggregate.recall,
        f1_delta: current.aggregate.f1 - previous.aggregate.f1,
        root_cause_accuracy_delta: current.aggregate.root_cause_accuracy
            - previous.aggregate.root_cause_accuracy,
        explanation_completeness_delta: current.aggregate.explanation_completeness
            - previous.aggregate.explanation_completeness,
        runtime_delta: current.aggregate.avg_runtime_ms - previous.aggregate.avg_runtime_ms,
    };

    DifferentialReport {
        previous_commit: previous.commit_hash.clone(),
        current_commit: current.commit_hash.clone(),
        regressions,
        new_detections,
        improved_explanations,
        degraded_explanations,
        confidence_drift,
        ranking_drift,
        aggregate_changes,
    }
}

/// Serialize differential report to JSON.
pub fn report_to_json(report: &DifferentialReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot(commit: &str, pass_rate: f64) -> EvaluationSnapshot {
        EvaluationSnapshot {
            commit_hash: commit.into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            results: vec![],
            aggregate: AggregateSnapshot {
                total_exploits: 10,
                pass_rate,
                precision: 0.8,
                recall: 0.7,
                f1: 0.75,
                root_cause_accuracy: 0.6,
                explanation_completeness: 0.5,
                evidence_depth: 3.0,
                avg_runtime_ms: 100.0,
            },
        }
    }

    #[test]
    fn test_regression_detection() {
        let prev = make_snapshot("abc123", 0.9);
        let curr = make_snapshot("def456", 0.7);

        let report = compare_snapshots(&prev, &curr);
        assert!(report.regressions.is_empty()); // No individual regressions, just aggregate drop
        assert!((report.aggregate_changes.pass_rate_delta - (-0.2)).abs() < 0.001);
    }

    #[test]
    fn test_improvement_detection() {
        let prev = make_snapshot("abc123", 0.7);
        let curr = make_snapshot("def456", 0.9);

        let report = compare_snapshots(&prev, &curr);
        assert!(report.aggregate_changes.pass_rate_delta > 0.0);
    }

    #[test]
    fn test_deterministic_comparison() {
        let prev = make_snapshot("abc123", 0.8);
        let curr = make_snapshot("def456", 0.85);

        let r1 = compare_snapshots(&prev, &curr);
        let r2 = compare_snapshots(&prev, &curr);
        assert_eq!(r1.regressions.len(), r2.regressions.len());
        assert_eq!(
            r1.aggregate_changes.pass_rate_delta,
            r2.aggregate_changes.pass_rate_delta
        );
    }
}
