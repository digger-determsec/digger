/// Research Reports — deterministic reports for internal review.
use crate::eval_models::*;
use std::collections::BTreeMap;

/// Generate a comprehensive research report.
#[allow(clippy::too_many_arguments)]
pub fn generate_research_report(
    benchmark_total: usize,
    benchmark_passed: usize,
    runtime_ms: u64,
    unique_findings: &[String],
    missed_findings: &[String],
    exploit_accuracy: f64,
    reasoning_score: f64,
    validation_score: f64,
    execution_score: f64,
) -> ResearchReport {
    let detection_rate = if benchmark_total > 0 {
        benchmark_passed as f64 / benchmark_total as f64
    } else {
        0.0
    };

    let summary = format!(
        "Digger detected {}/{} benchmark exploits ({:.0}% detection rate). \
         Exploit synthesis accuracy: {:.0}%. Reasoning quality: {:.0}%. \
         Validation accuracy: {:.0}%. Execution verification: {:.0}%. \
         {} unique findings identified. {} findings missed.",
        benchmark_passed,
        benchmark_total,
        detection_rate * 100.0,
        exploit_accuracy * 100.0,
        reasoning_score * 100.0,
        validation_score * 100.0,
        execution_score * 100.0,
        unique_findings.len(),
        missed_findings.len()
    );

    let mut improvements = Vec::new();
    if detection_rate < 0.8 {
        improvements.push(crate::eval_models::ImprovementRecommendation {
            priority: 1,
            target: "detection_rate".into(),
            action: "Improve detection patterns for missed exploit categories".into(),
            expected_impact: format!(
                "Increase detection from {:.0}% to >80%",
                detection_rate * 100.0
            ),
            effort: "High".into(),
        });
    }
    if exploit_accuracy < 0.7 {
        improvements.push(crate::eval_models::ImprovementRecommendation {
            priority: 2,
            target: "exploit_accuracy".into(),
            action: "Improve exploit synthesis with more protocol semantics".into(),
            expected_impact: format!(
                "Increase exploit accuracy from {:.0}% to >70%",
                exploit_accuracy * 100.0
            ),
            effort: "High".into(),
        });
    }
    if validation_score < 0.8 {
        improvements.push(crate::eval_models::ImprovementRecommendation {
            priority: 3,
            target: "validation_accuracy".into(),
            action: "Tune validation thresholds and add missing precondition checks".into(),
            expected_impact: format!(
                "Increase validation from {:.0}% to >80%",
                validation_score * 100.0
            ),
            effort: "Medium".into(),
        });
    }

    ResearchReport {
        report_id: format!("report-{}", now_iso()),
        generated_at: now_iso(),
        executive_summary: summary,
        benchmark_metrics: ResearchBenchmarkMetrics {
            total_cases: benchmark_total,
            passed: benchmark_passed,
            failed: benchmark_total - benchmark_passed,
            detection_rate,
            avg_runtime_ms: runtime_ms as f64 / benchmark_total.max(1) as f64,
            coverage_by_class: BTreeMap::new(),
        },
        unique_findings: unique_findings.to_vec(),
        missed_findings: missed_findings.to_vec(),
        exploit_quality: QualityMetrics {
            score: exploit_accuracy,
            strengths: vec!["Deterministic synthesis".into(), "Evidence-backed".into()],
            weaknesses: vec!["Limited protocol semantics".into()],
            test_count: benchmark_total,
        },
        reasoning_quality: QualityMetrics {
            score: reasoning_score,
            strengths: vec![
                "Multi-factor ranking".into(),
                "Counterfactual analysis".into(),
            ],
            weaknesses: vec!["No cross-protocol reasoning".into()],
            test_count: benchmark_total,
        },
        validation_quality: QualityMetrics {
            score: validation_score,
            strengths: vec![
                "10-subsystem validation".into(),
                "Deterministic verdicts".into(),
            ],
            weaknesses: vec!["Conservative thresholds".into()],
            test_count: benchmark_total,
        },
        execution_quality: QualityMetrics {
            score: execution_score,
            strengths: vec![
                "Deterministic transcripts".into(),
                "Full state tracking".into(),
            ],
            weaknesses: vec!["Simplified gas model".into()],
            test_count: benchmark_total,
        },
        improvements,
    }
}

/// Display research report.
pub fn display_research_report(report: &ResearchReport) -> String {
    let mut out = String::new();
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str("  DIGGER RESEARCH REPORT\n");
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str(&format!(
        "Report: {} | Generated: {}\n\n",
        report.report_id, report.generated_at
    ));
    out.push_str(&format!(
        "Executive Summary:\n{}\n\n",
        report.executive_summary
    ));
    out.push_str(&format!(
        "Benchmark: {}/{} passed ({:.0}%) | Avg Runtime: {:.0}ms\n",
        report.benchmark_metrics.passed,
        report.benchmark_metrics.total_cases,
        report.benchmark_metrics.detection_rate * 100.0,
        report.benchmark_metrics.avg_runtime_ms
    ));
    out.push_str(&format!(
        "Unique Findings: {} | Missed Findings: {}\n\n",
        report.unique_findings.len(),
        report.missed_findings.len()
    ));
    out.push_str(&format!(
        "Quality Scores: Exploit={:.0}% Reasoning={:.0}% Validation={:.0}% Execution={:.0}%\n",
        report.exploit_quality.score * 100.0,
        report.reasoning_quality.score * 100.0,
        report.validation_quality.score * 100.0,
        report.execution_quality.score * 100.0
    ));
    if !report.improvements.is_empty() {
        out.push_str("\n─── Recommended Improvements ─────────────────────\n");
        for imp in &report.improvements {
            out.push_str(&format!(
                "  #{} [{}] {}: {}\n",
                imp.priority, imp.effort, imp.action, imp.expected_impact
            ));
        }
    }
    out.push_str("═══════════════════════════════════════════════════\n");
    out
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs();
    format!("{}s", secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_research_report() {
        let report = generate_research_report(
            10,
            8,
            5000,
            &["unique1".into()],
            &["missed1".into()],
            0.8,
            0.7,
            0.75,
            0.6,
        );
        assert_eq!(report.benchmark_metrics.total_cases, 10);
        assert_eq!(report.benchmark_metrics.passed, 8);
        assert!(!report.executive_summary.is_empty());
        let display = display_research_report(&report);
        assert!(display.contains("RESEARCH REPORT"));
    }
}
