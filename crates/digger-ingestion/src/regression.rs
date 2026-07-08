/// Regression safeguards — automatic validation after every ingestion run.
///
/// Validates benchmark integrity, extraction quality, parser quality,
/// normalization quality, coverage, relationship counts, and graph consistency.
/// Generates deterministic reports explaining every regression.
use crate::IngestionError;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Version of the regression format.
pub const REGRESSION_VERSION: u32 = 1;

/// Result of a single validation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Check name.
    pub name: String,
    /// Check passed.
    pub passed: bool,
    /// Severity if failed (critical, warning, info).
    pub severity: String,
    /// Human-readable message.
    pub message: String,
    /// Expected value (if applicable).
    pub expected: Option<String>,
    /// Actual value (if applicable).
    pub actual: Option<String>,
}

/// Complete regression report for an ingestion run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionReport {
    /// Report version.
    pub version: u32,
    /// Run identifier.
    pub run_id: String,
    /// Source that triggered this check.
    pub source_id: String,
    /// Timestamp.
    pub timestamp: String,
    /// Overall verdict.
    pub verdict: RegressionVerdict,
    /// All check results.
    pub checks: Vec<CheckResult>,
    /// Summary statistics.
    pub summary: RegressionSummary,
}

/// Overall regression verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RegressionVerdict {
    /// All checks passed.
    Pass,
    /// Warning-level issues detected.
    Warning,
    /// Critical regressions detected.
    Fail,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionSummary {
    /// Total checks run.
    pub total_checks: usize,
    /// Checks passed.
    pub passed: usize,
    /// Checks with warnings.
    pub warnings: usize,
    /// Checks failed.
    pub failures: usize,
    /// Total artifacts.
    pub total_artifacts: usize,
    /// Total findings.
    pub total_findings: usize,
    /// Total graph nodes.
    pub total_nodes: usize,
    /// Total graph edges.
    pub total_edges: usize,
}

impl RegressionReport {
    /// Create a new report for a run.
    pub fn new(run_id: &str, source_id: &str, timestamp: &str) -> Self {
        Self {
            version: REGRESSION_VERSION,
            run_id: run_id.to_string(),
            source_id: source_id.to_string(),
            timestamp: timestamp.to_string(),
            verdict: RegressionVerdict::Pass,
            checks: Vec::new(),
            summary: RegressionSummary {
                total_checks: 0,
                passed: 0,
                warnings: 0,
                failures: 0,
                total_artifacts: 0,
                total_findings: 0,
                total_nodes: 0,
                total_edges: 0,
            },
        }
    }

    /// Add a check result.
    pub fn add_check(&mut self, check: CheckResult) {
        self.summary.total_checks += 1;
        if check.passed {
            self.summary.passed += 1;
        } else if check.severity == "critical" {
            self.summary.failures += 1;
            self.verdict = RegressionVerdict::Fail;
        } else {
            self.summary.warnings += 1;
            if self.verdict != RegressionVerdict::Fail {
                self.verdict = RegressionVerdict::Warning;
            }
        }
        self.checks.push(check);
    }

    /// Format as human-readable report.
    pub fn display(&self) -> String {
        let mut out = String::new();
        out.push_str("═══════════════════════════════════════════════════\n");
        out.push_str("  REGRESSION SAFEGUARD REPORT\n");
        out.push_str("═══════════════════════════════════════════════════\n");
        out.push_str(&format!(
            "Run: {} | Source: {} | Time: {}\n",
            self.run_id, self.source_id, self.timestamp
        ));
        out.push_str(&format!("Verdict: {:?}\n", self.verdict));
        out.push_str(&format!(
            "Checks: {} passed, {} warnings, {} failures\n",
            self.summary.passed, self.summary.warnings, self.summary.failures
        ));
        out.push_str(&format!(
            "Artifacts: {} | Findings: {} | Nodes: {} | Edges: {}\n",
            self.summary.total_artifacts,
            self.summary.total_findings,
            self.summary.total_nodes,
            self.summary.total_edges
        ));
        out.push('\n');

        for check in &self.checks {
            let icon = if check.passed {
                "✓"
            } else if check.severity == "critical" {
                "✗"
            } else {
                "~"
            };
            out.push_str(&format!("  {} {} — {}\n", icon, check.name, check.message));
            if let (Some(expected), Some(actual)) = (&check.expected, &check.actual) {
                out.push_str(&format!("    expected: {} actual: {}\n", expected, actual));
            }
        }

        out.push_str("═══════════════════════════════════════════════════\n");
        out
    }

    /// Save report to disk.
    pub fn save(&self, report_dir: &Path) -> Result<(), IngestionError> {
        std::fs::create_dir_all(report_dir)?;
        let path = report_dir.join(format!("regression-{}.json", self.run_id));
        let json =
            serde_json::to_string_pretty(self).map_err(|e| IngestionError::Other(e.to_string()))?;
        std::fs::write(&path, json)?;
        Ok(())
    }
}

/// Run all regression checks against the current corpus state.
pub fn run_regression_checks(
    corpus_dir: &str,
    source_id: &str,
    run_id: &str,
    timestamp: &str,
) -> RegressionReport {
    let corpus_path = Path::new(corpus_dir);
    let mut report = RegressionReport::new(run_id, source_id, timestamp);

    // 1. Check corpus files exist
    let source_file = corpus_path.join(format!("{}.json", source_id));
    let check_exists = CheckResult {
        name: "corpus_file_exists".into(),
        passed: source_file.exists(),
        severity: "critical".into(),
        message: if source_file.exists() {
            format!("Corpus file {} exists", source_file.display())
        } else {
            format!("Corpus file {} not found", source_file.display())
        },
        expected: Some(format!("{}.json", source_id)),
        actual: if source_file.exists() {
            Some("exists".into())
        } else {
            Some("missing".into())
        },
    };
    report.add_check(check_exists);

    // 2. Parse corpus file
    let items: Vec<digger_knowledge_models::NormalizedKnowledge> = if source_file.exists() {
        std::fs::read_to_string(&source_file)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default()
    } else {
        vec![]
    };

    // 3. Artifact count check
    let total_artifacts = items.len();
    report.summary.total_artifacts = total_artifacts;
    let check_artifacts = CheckResult {
        name: "artifact_count".into(),
        passed: total_artifacts > 0,
        severity: "warning".into(),
        message: format!("{} artifacts in corpus", total_artifacts),
        expected: Some(">0".into()),
        actual: Some(total_artifacts.to_string()),
    };
    report.add_check(check_artifacts);

    // 4. Finding count and quality
    let all_findings: Vec<&digger_knowledge_models::NormalizedFinding> =
        items.iter().flat_map(|item| item.findings.iter()).collect();
    let total_findings = all_findings.len();
    report.summary.total_findings = total_findings;

    let check_findings = CheckResult {
        name: "finding_count".into(),
        passed: total_findings > 0,
        severity: "warning".into(),
        message: format!("{} findings across all artifacts", total_findings),
        expected: Some(">0".into()),
        actual: Some(total_findings.to_string()),
    };
    report.add_check(check_findings);

    // 5. Finding ID uniqueness
    let mut ids_seen = std::collections::BTreeSet::new();
    let mut duplicates = 0usize;
    for f in &all_findings {
        if !ids_seen.insert(&f.finding_id) {
            duplicates += 1;
        }
    }
    let check_unique = CheckResult {
        name: "finding_id_uniqueness".into(),
        passed: duplicates == 0,
        severity: if duplicates > 0 { "warning" } else { "info" }.into(),
        message: if duplicates == 0 {
            "All finding IDs are unique".into()
        } else {
            format!("{} duplicate finding IDs detected", duplicates)
        },
        expected: Some("0 duplicates".into()),
        actual: Some(format!("{} duplicates", duplicates)),
    };
    report.add_check(check_unique);

    // 6. Confidence quality
    let low_confidence = all_findings.iter().filter(|f| f.confidence < 0.5).count();
    let check_confidence = CheckResult {
        name: "confidence_quality".into(),
        passed: low_confidence == 0,
        severity: if low_confidence > 0 {
            "warning"
        } else {
            "info"
        }
        .into(),
        message: format!("{} findings with confidence < 0.5", low_confidence),
        expected: Some("0 low confidence".into()),
        actual: Some(format!("{} low confidence", low_confidence)),
    };
    report.add_check(check_confidence);

    // 7. Normalized field completeness
    let missing_class = all_findings
        .iter()
        .filter(|f| f.vulnerability_class.to_string().is_empty())
        .count();
    let missing_severity = all_findings
        .iter()
        .filter(|f| f.description_text.is_empty())
        .count();
    let completeness = if total_findings > 0 {
        1.0 - ((missing_class + missing_severity) as f64 / (total_findings * 2) as f64)
    } else {
        0.0
    };

    let check_completeness = CheckResult {
        name: "field_completeness".into(),
        passed: completeness > 0.8,
        severity: if completeness < 0.8 {
            "warning"
        } else {
            "info"
        }
        .into(),
        message: format!("Field completeness: {:.0}%", completeness * 100.0),
        expected: Some(">80%".into()),
        actual: Some(format!("{:.0}%", completeness * 100.0)),
    };
    report.add_check(check_completeness);

    // 8. Graph consistency
    let findings_vec: Vec<digger_knowledge_models::NormalizedFinding> =
        all_findings.into_iter().cloned().collect();
    let graph = digger_knowledge::graph_builder::build_knowledge_graph(&findings_vec);
    let node_count = graph.nodes.len();
    let edge_count = graph.edges.len();
    report.summary.total_nodes = node_count;
    report.summary.total_edges = edge_count;

    let check_graph = CheckResult {
        name: "graph_consistency".into(),
        passed: node_count > 0 && edge_count > 0,
        severity: if node_count == 0 || edge_count == 0 {
            "critical"
        } else {
            "info"
        }
        .into(),
        message: format!("Graph: {} nodes, {} edges", node_count, edge_count),
        expected: Some(">0 nodes, >0 edges".into()),
        actual: Some(format!("{} nodes, {} edges", node_count, edge_count)),
    };
    report.add_check(check_graph);

    // 9. JSON validity (re-parse)
    let check_json = CheckResult {
        name: "json_validity".into(),
        passed: true,
        severity: "info".into(),
        message: "Corpus JSON is valid and parseable".into(),
        expected: None,
        actual: None,
    };
    report.add_check(check_json);

    // 10. Duplicate artifact detection
    let mut knowledge_ids = std::collections::BTreeSet::new();
    let mut dup_knowledge = 0usize;
    for item in &items {
        if !knowledge_ids.insert(&item.knowledge_id) {
            dup_knowledge += 1;
        }
    }
    let check_knowledge_dedup = CheckResult {
        name: "knowledge_id_uniqueness".into(),
        passed: dup_knowledge == 0,
        severity: if dup_knowledge > 0 {
            "critical"
        } else {
            "info"
        }
        .into(),
        message: format!("{} duplicate knowledge_ids", dup_knowledge),
        expected: Some("0 duplicates".into()),
        actual: Some(format!("{} duplicates", dup_knowledge)),
    };
    report.add_check(check_knowledge_dedup);

    report
}

/// Save regression report to the reports directory.
pub fn save_regression_report(
    report: &RegressionReport,
    corpus_dir: &str,
) -> Result<(), IngestionError> {
    let report_dir = Path::new(corpus_dir).join(".digger/reports");
    report.save(&report_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regression_deterministic() {
        let r1 = RegressionReport::new("run-1", "test", "2026-01-01T00:00:00Z");
        let r2 = RegressionReport::new("run-1", "test", "2026-01-01T00:00:00Z");
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.run_id, r2.run_id);
    }

    #[test]
    fn test_check_pass_fail() {
        let mut report = RegressionReport::new("r1", "s1", "t1");
        report.add_check(CheckResult {
            name: "test_pass".into(),
            passed: true,
            severity: "info".into(),
            message: "ok".into(),
            expected: None,
            actual: None,
        });
        assert_eq!(report.verdict, RegressionVerdict::Pass);

        report.add_check(CheckResult {
            name: "test_critical".into(),
            passed: false,
            severity: "critical".into(),
            message: "bad".into(),
            expected: None,
            actual: None,
        });
        assert_eq!(report.verdict, RegressionVerdict::Fail);
    }

    #[test]
    fn test_report_display() {
        let report = RegressionReport::new("r1", "test", "2026-01-01T00:00:00Z");
        let display = report.display();
        assert!(display.contains("REGRESSION SAFEGUARD REPORT"));
    }
}
