/// Coverage Dashboard — comprehensive coverage metrics.
use crate::eval_models::*;

/// Generate coverage dashboard from corpus analysis.
pub fn generate_coverage_dashboard(corpus_stats: &CorpusStats) -> CoverageDashboard {
    let protocol_coverage = measure_coverage(
        "Protocol Coverage",
        &corpus_stats.protocols_found,
        &corpus_stats.protocols_total,
    );
    let exploit_cat_coverage = measure_coverage(
        "Exploit Category Coverage",
        &corpus_stats.exploit_categories_found,
        &corpus_stats.exploit_categories_total,
    );
    let benchmark_coverage = measure_coverage(
        "Benchmark Coverage",
        &corpus_stats.benchmark_cases_found,
        &corpus_stats.benchmark_cases_total,
    );
    let reasoning_coverage = measure_coverage(
        "Reasoning Coverage",
        &corpus_stats.reasoning_rules_found,
        &corpus_stats.reasoning_rules_total,
    );
    let validation_coverage = measure_coverage(
        "Validation Coverage",
        &corpus_stats.validation_checks_found,
        &corpus_stats.validation_checks_total,
    );
    let execution_coverage = measure_coverage(
        "Execution Coverage",
        &corpus_stats.execution_engines_found,
        &corpus_stats.execution_engines_total,
    );
    let knowledge_coverage = measure_coverage(
        "Knowledge Coverage",
        &corpus_stats.knowledge_sources_found,
        &corpus_stats.knowledge_sources_total,
    );

    let overall_score = (protocol_coverage.score
        + exploit_cat_coverage.score
        + benchmark_coverage.score
        + reasoning_coverage.score
        + validation_coverage.score
        + execution_coverage.score
        + knowledge_coverage.score)
        / 7.0;

    let highest_roi = generate_roi_recommendations(&[
        &protocol_coverage,
        &exploit_cat_coverage,
        &benchmark_coverage,
        &reasoning_coverage,
        &validation_coverage,
        &execution_coverage,
        &knowledge_coverage,
    ]);

    CoverageDashboard {
        generated_at: now_iso(),
        protocol_coverage,
        exploit_category_coverage: exploit_cat_coverage,
        benchmark_coverage,
        reasoning_coverage,
        validation_coverage,
        execution_coverage,
        knowledge_coverage,
        overall_score,
        highest_roi_areas: highest_roi,
    }
}

fn measure_coverage(name: &str, found: &[String], total: &[String]) -> CoverageDimension {
    let found_set: BTreeSet<String> = found.iter().cloned().collect();
    let total_set: BTreeSet<String> = total.iter().cloned().collect();
    let covered = found_set.len();
    let total_count = total_set.len().max(1);
    let score = covered as f64 / total_count as f64;
    let gaps: Vec<String> = total_set.difference(&found_set).cloned().collect();
    CoverageDimension {
        name: name.into(),
        covered,
        total: total_count,
        score,
        gaps,
    }
}

fn generate_roi_recommendations(dims: &[&CoverageDimension]) -> Vec<ROIRecommendation> {
    let mut recs: Vec<ROIRecommendation> = dims
        .iter()
        .enumerate()
        .map(|(i, dim)| {
            let potential =
                (dim.covered + dim.gaps.len()).min(dim.total) as f64 / dim.total.max(1) as f64;
            let effort = if dim.gaps.len() > 10 {
                "High"
            } else if dim.gaps.len() > 3 {
                "Medium"
            } else {
                "Low"
            }
            .into();
            ROIRecommendation {
                area: dim.name.clone(),
                current_coverage: dim.score,
                potential_coverage: potential,
                effort,
                expected_impact: format!(
                    "Improve {} from {:.0}% to {:.0}%",
                    dim.name,
                    dim.score * 100.0,
                    potential * 100.0
                ),
                priority: i + 1,
            }
        })
        .collect();
    recs.sort_by(|a, b| {
        let a_lift = a.potential_coverage - a.current_coverage;
        let b_lift = b.potential_coverage - b.current_coverage;
        b_lift
            .partial_cmp(&a_lift)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for (i, r) in recs.iter_mut().enumerate() {
        r.priority = i + 1;
    }
    recs
}

use std::collections::BTreeSet;

/// Stats about the corpus.
#[derive(Debug, Clone)]
pub struct CorpusStats {
    pub protocols_found: Vec<String>,
    pub protocols_total: Vec<String>,
    pub exploit_categories_found: Vec<String>,
    pub exploit_categories_total: Vec<String>,
    pub benchmark_cases_found: Vec<String>,
    pub benchmark_cases_total: Vec<String>,
    pub reasoning_rules_found: Vec<String>,
    pub reasoning_rules_total: Vec<String>,
    pub validation_checks_found: Vec<String>,
    pub validation_checks_total: Vec<String>,
    pub execution_engines_found: Vec<String>,
    pub execution_engines_total: Vec<String>,
    pub knowledge_sources_found: Vec<String>,
    pub knowledge_sources_total: Vec<String>,
}

/// Display the dashboard as a string.
pub fn display_dashboard(dashboard: &CoverageDashboard) -> String {
    let mut out = String::new();
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str("  COVERAGE DASHBOARD\n");
    out.push_str(&format!("Generated: {}\n", dashboard.generated_at));
    out.push_str(&format!(
        "Overall Score: {:.0}%\n\n",
        dashboard.overall_score * 100.0
    ));

    for dim in [
        &dashboard.protocol_coverage,
        &dashboard.exploit_category_coverage,
        &dashboard.benchmark_coverage,
        &dashboard.reasoning_coverage,
        &dashboard.validation_coverage,
        &dashboard.execution_coverage,
        &dashboard.knowledge_coverage,
    ] {
        let bar_len = (dim.score * 20.0) as usize;
        let bar: String = "#".repeat(bar_len) + &"-".repeat(20 - bar_len);
        out.push_str(&format!(
            "  {:.<30} [{}] {:.0}% ({}/{})\n",
            dim.name,
            bar,
            dim.score * 100.0,
            dim.covered,
            dim.total
        ));
    }

    out.push_str("\n─── Top ROI Improvements ─────────────────────────\n");
    for rec in dashboard.highest_roi_areas.iter().take(3) {
        out.push_str(&format!(
            "  #{}: {} — {}\n",
            rec.priority, rec.area, rec.expected_impact
        ));
    }

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
    fn test_dashboard_generation() {
        let stats = CorpusStats {
            protocols_found: vec!["P1".into(), "P2".into()],
            protocols_total: vec!["P1".into(), "P2".into(), "P3".into()],
            exploit_categories_found: vec!["Reentrancy".into()],
            exploit_categories_total: vec![
                "Reentrancy".into(),
                "AccessControl".into(),
                "Oracle".into(),
            ],
            benchmark_cases_found: vec!["b1".into()],
            benchmark_cases_total: vec!["b1".into(), "b2".into()],
            reasoning_rules_found: vec!["r1".into(), "r2".into()],
            reasoning_rules_total: vec!["r1".into(), "r2".into(), "r3".into()],
            validation_checks_found: vec!["v1".into()],
            validation_checks_total: vec!["v1".into(), "v2".into()],
            execution_engines_found: vec!["e1".into()],
            execution_engines_total: vec!["e1".into(), "e2".into()],
            knowledge_sources_found: vec!["k1".into(), "k2".into(), "k3".into()],
            knowledge_sources_total: vec!["k1".into(), "k2".into(), "k3".into(), "k4".into()],
        };
        let dashboard = generate_coverage_dashboard(&stats);
        assert!(dashboard.overall_score > 0.0 && dashboard.overall_score <= 1.0);
        let display = display_dashboard(&dashboard);
        assert!(display.contains("COVERAGE DASHBOARD"));
    }
}
