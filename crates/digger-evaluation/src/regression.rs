/// Regression Testing and Benchmark Integrity.
///
/// Detects regressions, tracks improvements, and ensures benchmark integrity.
/// Every commit should be compared against the previous version.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::models::*;

/// Regression test result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionReport {
    /// Current commit hash.
    pub current_commit: String,
    /// Previous commit hash.
    pub previous_commit: String,
    /// Precision change.
    pub precision_delta: f64,
    /// Recall change.
    pub recall_delta: f64,
    /// F1 change.
    pub f1_delta: f64,
    /// Runtime change (ms).
    pub runtime_delta: f64,
    /// Root-cause accuracy change.
    pub root_cause_delta: f64,
    /// Explanation completeness change.
    pub explanation_delta: f64,
    /// Evidence quality change.
    pub evidence_delta: f64,
    /// Determinism change.
    pub determinism_delta: f64,
    /// Regressions detected.
    pub regressions: Vec<Regression>,
    /// Improvements detected.
    pub improvements: Vec<Improvement>,
    /// Overall verdict.
    pub verdict: String,
}

/// A specific regression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Regression {
    /// What regressed.
    pub metric: String,
    /// Old value.
    pub old_value: f64,
    /// New value.
    pub new_value: f64,
    /// Severity.
    pub severity: String,
}

/// A specific improvement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Improvement {
    /// What improved.
    pub metric: String,
    /// Old value.
    pub old_value: f64,
    /// New value.
    pub new_value: f64,
    /// Magnitude.
    pub magnitude: String,
}

/// Benchmark integrity report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// New benchmark cases added.
    pub new_cases: Vec<String>,
    /// Cases removed.
    pub removed_cases: Vec<String>,
    /// Cases with modified expectations.
    pub modified_cases: Vec<ModifiedCase>,
    /// Cases with modified metadata.
    pub modified_metadata: Vec<String>,
    /// Total cases.
    pub total_cases: usize,
    /// Integrity status.
    pub status: String,
}

/// A case with modified expectations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifiedCase {
    /// Case ID.
    pub case_id: String,
    /// What changed.
    pub changes: Vec<String>,
    /// Justification.
    pub justification: String,
}

/// Coverage analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAnalysisReport {
    /// Missing exploit categories.
    pub missing_categories: Vec<MissingCategory>,
    /// Protocol families with weak coverage.
    pub weak_coverage: Vec<WeakCoverage>,
    /// Reasoning capabilities untested.
    pub untested_capabilities: Vec<String>,
    /// Overall coverage score.
    pub coverage_score: f64,
}

/// A missing exploit category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingCategory {
    /// Category name.
    pub category: String,
    /// Why it's important.
    pub importance: String,
    /// Suggested exploits to add.
    pub suggested_exploits: Vec<String>,
}

/// A protocol family with weak coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakCoverage {
    /// Protocol family.
    pub family: String,
    /// Current coverage count.
    pub current_count: usize,
    /// Target coverage count.
    pub target_count: usize,
    /// Gap.
    pub gap: usize,
}

/// Compare two evaluation reports and produce a regression report.
pub fn compare_reports(
    previous: &EvaluationReport,
    current: &EvaluationReport,
    previous_commit: &str,
    current_commit: &str,
) -> RegressionReport {
    let precision_delta = current.aggregate_precision - previous.aggregate_precision;
    let recall_delta = current.aggregate_recall - previous.aggregate_recall;
    let f1_delta = current.aggregate_f1 - previous.aggregate_f1;
    let runtime_delta = current.avg_runtime_ms - previous.avg_runtime_ms;
    let root_cause_delta = current.avg_root_cause_accuracy - previous.avg_root_cause_accuracy;
    let explanation_delta =
        current.avg_explanation_completeness - previous.avg_explanation_completeness;
    let evidence_delta = current.avg_evidence_depth - previous.avg_evidence_depth;
    let determinism_delta = current.determinism_rate - previous.determinism_rate;

    let mut regressions = Vec::new();
    let mut improvements = Vec::new();

    // Check for regressions (negative change in positive metrics)
    if precision_delta < -0.01 {
        regressions.push(Regression {
            metric: "precision".into(),
            old_value: previous.aggregate_precision,
            new_value: current.aggregate_precision,
            severity: if precision_delta < -0.1 {
                "critical"
            } else {
                "warning"
            }
            .into(),
        });
    } else if precision_delta > 0.01 {
        improvements.push(Improvement {
            metric: "precision".into(),
            old_value: previous.aggregate_precision,
            new_value: current.aggregate_precision,
            magnitude: format!("{:+.3}", precision_delta),
        });
    }

    if recall_delta < -0.01 {
        regressions.push(Regression {
            metric: "recall".into(),
            old_value: previous.aggregate_recall,
            new_value: current.aggregate_recall,
            severity: if recall_delta < -0.1 {
                "critical"
            } else {
                "warning"
            }
            .into(),
        });
    } else if recall_delta > 0.01 {
        improvements.push(Improvement {
            metric: "recall".into(),
            old_value: previous.aggregate_recall,
            new_value: current.aggregate_recall,
            magnitude: format!("{:+.3}", recall_delta),
        });
    }

    if f1_delta < -0.01 {
        regressions.push(Regression {
            metric: "f1".into(),
            old_value: previous.aggregate_f1,
            new_value: current.aggregate_f1,
            severity: if f1_delta < -0.1 {
                "critical"
            } else {
                "warning"
            }
            .into(),
        });
    } else if f1_delta > 0.01 {
        improvements.push(Improvement {
            metric: "f1".into(),
            old_value: previous.aggregate_f1,
            new_value: current.aggregate_f1,
            magnitude: format!("{:+.3}", f1_delta),
        });
    }

    // Runtime regression (increase is bad)
    if runtime_delta > 10.0 {
        regressions.push(Regression {
            metric: "runtime".into(),
            old_value: previous.avg_runtime_ms,
            new_value: current.avg_runtime_ms,
            severity: if runtime_delta > 100.0 {
                "critical"
            } else {
                "warning"
            }
            .into(),
        });
    } else if runtime_delta < -10.0 {
        improvements.push(Improvement {
            metric: "runtime".into(),
            old_value: previous.avg_runtime_ms,
            new_value: current.avg_runtime_ms,
            magnitude: format!("{:+.1}ms", runtime_delta),
        });
    }

    // Root cause accuracy
    if root_cause_delta < -0.01 {
        regressions.push(Regression {
            metric: "root_cause_accuracy".into(),
            old_value: previous.avg_root_cause_accuracy,
            new_value: current.avg_root_cause_accuracy,
            severity: "warning".into(),
        });
    }

    // Explanation completeness
    if explanation_delta < -0.01 {
        regressions.push(Regression {
            metric: "explanation_completeness".into(),
            old_value: previous.avg_explanation_completeness,
            new_value: current.avg_explanation_completeness,
            severity: "warning".into(),
        });
    }

    // Determinism
    if determinism_delta < -0.01 {
        regressions.push(Regression {
            metric: "determinism".into(),
            old_value: previous.determinism_rate,
            new_value: current.determinism_rate,
            severity: "critical".into(),
        });
    }

    let verdict = if regressions.is_empty() {
        "PASS — no regressions detected".into()
    } else if regressions.iter().any(|r| r.severity == "critical") {
        "FAIL — critical regressions detected".into()
    } else {
        "WARNING — minor regressions detected".into()
    };

    RegressionReport {
        current_commit: current_commit.into(),
        previous_commit: previous_commit.into(),
        precision_delta,
        recall_delta,
        f1_delta,
        runtime_delta,
        root_cause_delta,
        explanation_delta,
        evidence_delta,
        determinism_delta,
        regressions,
        improvements,
        verdict,
    }
}

/// Analyze benchmark coverage gaps.
pub fn analyze_coverage(results: &[EvaluationResult]) -> CoverageAnalysisReport {
    let mut category_counts: BTreeMap<String, usize> = BTreeMap::new();
    for r in results {
        // Use exploit_id prefix as category proxy
        let category = r
            .exploit_id
            .split('-')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *category_counts.entry(category).or_insert(0) += 1;
    }

    // Identify missing categories
    let important_categories = vec![
        "flash_loan",
        "oracle",
        "governance",
        "reentrancy",
        "access_control",
        "upgradeability",
        "composability",
        "mev",
        "bridge",
        "lending",
    ];

    let missing_categories: Vec<MissingCategory> = important_categories
        .iter()
        .filter(|cat| !category_counts.contains_key(**cat))
        .map(|cat| MissingCategory {
            category: (*cat).to_string(),
            importance: "High — common vulnerability class".into(),
            suggested_exploits: vec![],
        })
        .collect();

    // Identify weak coverage
    let weak_coverage: Vec<WeakCoverage> = category_counts
        .iter()
        .filter(|(_, count)| **count < 3)
        .map(|(cat, count)| WeakCoverage {
            family: cat.clone(),
            current_count: *count,
            target_count: 3,
            gap: 3 - count,
        })
        .collect();

    // Coverage score
    let covered = important_categories
        .iter()
        .filter(|cat| category_counts.contains_key(**cat))
        .count();
    let coverage_score = covered as f64 / important_categories.len() as f64;

    CoverageAnalysisReport {
        missing_categories,
        weak_coverage,
        untested_capabilities: vec![
            "Cross-contract reentrancy".into(),
            "Flash loan composability".into(),
            "Governance attack patterns".into(),
            "MEV extraction".into(),
        ],
        coverage_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eval(precision: f64, recall: f64) -> EvaluationReport {
        EvaluationReport {
            total_exploits: 10,
            results: vec![],
            aggregate_precision: precision,
            aggregate_recall: recall,
            aggregate_f1: 2.0 * precision * recall / (precision + recall),
            avg_root_cause_accuracy: 0.7,
            avg_explanation_completeness: 0.6,
            avg_evidence_depth: 3.0,
            determinism_rate: 1.0,
            avg_runtime_ms: 50.0,
            total_runtime_ms: 500.0,
            avg_peak_memory: 1024,
            pass_rate: 0.8,
        }
    }

    #[test]
    fn regression_detection() {
        let prev = make_eval(0.8, 0.7);
        let curr = make_eval(0.7, 0.6);

        let report = compare_reports(&prev, &curr, "abc", "def");
        assert!(!report.regressions.is_empty());
        assert!(report.verdict.contains("FAIL") || report.verdict.contains("WARNING"));
    }

    #[test]
    fn improvement_detection() {
        let prev = make_eval(0.7, 0.6);
        let curr = make_eval(0.8, 0.7);

        let report = compare_reports(&prev, &curr, "abc", "def");
        assert!(!report.improvements.is_empty());
        assert!(report.verdict.contains("PASS"));
    }

    #[test]
    fn no_regressions_for_identical() {
        let eval = make_eval(0.8, 0.7);
        let report = compare_reports(&eval, &eval, "abc", "abc");
        assert!(report.regressions.is_empty());
        assert!(report.verdict.contains("PASS"));
    }
}
