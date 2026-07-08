/// Research Dataset — store evaluated protocols as reproducible datasets.
use crate::eval_models::*;
use crate::live_eval::EvaluationSummary;
use std::collections::BTreeMap;

/// A research dataset for a single protocol evaluation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResearchDataset {
    pub dataset_id: String,
    pub protocol: String,
    pub chain: String,
    pub commit_hash: String,
    pub protocol_version: String,
    pub compiler_version: String,
    pub benchmark_metadata: BenchmarkMetadata,
    pub evaluation_metrics: DatasetMetrics,
    pub findings_comparison: Vec<FindingComparison>,
    pub timestamp: String,
    pub digger_version: String,
}

/// Benchmark metadata for reproducibility.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchmarkMetadata {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub detection_rate: f64,
    pub categories: BTreeMap<String, usize>,
}

/// Evaluation metrics for the dataset.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatasetMetrics {
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub unique_findings: usize,
    pub parse_time_ms: u64,
    pub reasoning_time_ms: u64,
    pub total_time_ms: u64,
}

/// Create a research dataset from evaluation results.
#[allow(clippy::too_many_arguments)]
pub fn create_dataset(
    protocol: &str,
    chain: &str,
    commit_hash: &str,
    protocol_version: &str,
    compiler_version: &str,
    comparisons: &[FindingComparison],
    summary: &EvaluationSummary,
    parse_ms: u64,
    reasoning_ms: u64,
    _total_ms: u64,
) -> ResearchDataset {
    let dataset_id = format!(
        "ds-{}-{}",
        protocol.replace(' ', "_"),
        &commit_hash[..8.min(commit_hash.len())]
    );

    ResearchDataset {
        dataset_id,
        protocol: protocol.to_string(),
        chain: chain.to_string(),
        commit_hash: commit_hash.to_string(),
        protocol_version: protocol_version.to_string(),
        compiler_version: compiler_version.to_string(),
        benchmark_metadata: BenchmarkMetadata {
            total_cases: 0,
            passed: 0,
            failed: 0,
            detection_rate: 0.0,
            categories: BTreeMap::new(),
        },
        evaluation_metrics: DatasetMetrics {
            precision: summary.precision,
            recall: summary.recall,
            f1: summary.f1,
            true_positives: summary.exact_matches + summary.partial_matches,
            false_positives: summary.false_positives,
            false_negatives: summary.missed_findings,
            unique_findings: summary.unique_findings,
            parse_time_ms: parse_ms,
            reasoning_time_ms: reasoning_ms,
            total_time_ms: parse_ms + reasoning_ms,
        },
        findings_comparison: comparisons.to_vec(),
        timestamp: now_iso(),
        digger_version: env!("CARGO_PKG_VERSION").into(),
    }
}

/// Accuracy Dashboard — track metrics over time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccuracyDashboard {
    pub generated_at: String,
    pub total_evaluations: usize,
    pub accuracy_over_time: Vec<TimestampedAccuracy>,
    pub overall: AggregateAccuracy,
    pub by_chain: BTreeMap<String, ChainAccuracy>,
    pub by_source: BTreeMap<String, SourceAccuracy>,
    pub trend: AccuracyTrend,
}

/// Accuracy at a point in time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimestampedAccuracy {
    pub timestamp: String,
    pub protocol: String,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// Aggregate accuracy metrics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregateAccuracy {
    pub avg_precision: f64,
    pub avg_recall: f64,
    pub avg_f1: f64,
    pub best_f1: f64,
    pub worst_f1: f64,
    pub total_true_positives: usize,
    pub total_false_positives: usize,
    pub total_false_negatives: usize,
    pub total_unique: usize,
}

/// Accuracy by chain type.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainAccuracy {
    pub chain: String,
    pub count: usize,
    pub avg_precision: f64,
    pub avg_recall: f64,
    pub avg_f1: f64,
}

/// Accuracy by source.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceAccuracy {
    pub source: String,
    pub count: usize,
    pub avg_precision: f64,
    pub avg_recall: f64,
    pub avg_f1: f64,
}

/// Accuracy trend.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccuracyTrend {
    pub improving: bool,
    pub f1_delta: f64,
    pub explanation: String,
}

/// Build accuracy dashboard from datasets.
pub fn build_accuracy_dashboard(datasets: &[ResearchDataset]) -> AccuracyDashboard {
    let mut accuracy_over_time = Vec::new();
    let mut by_chain: BTreeMap<String, Vec<&DatasetMetrics>> = BTreeMap::new();
    let mut by_source: BTreeMap<String, Vec<&DatasetMetrics>> = BTreeMap::new();

    for ds in datasets {
        accuracy_over_time.push(TimestampedAccuracy {
            timestamp: ds.timestamp.clone(),
            protocol: ds.protocol.clone(),
            precision: ds.evaluation_metrics.precision,
            recall: ds.evaluation_metrics.recall,
            f1: ds.evaluation_metrics.f1,
        });
        by_chain
            .entry(ds.chain.clone())
            .or_default()
            .push(&ds.evaluation_metrics);
        by_source
            .entry(ds.benchmark_metadata.total_cases.to_string())
            .or_default()
            .push(&ds.evaluation_metrics);
    }

    let avg_p = datasets
        .iter()
        .map(|d| d.evaluation_metrics.precision)
        .sum::<f64>()
        / datasets.len().max(1) as f64;
    let avg_r = datasets
        .iter()
        .map(|d| d.evaluation_metrics.recall)
        .sum::<f64>()
        / datasets.len().max(1) as f64;
    let avg_f1 = datasets
        .iter()
        .map(|d| d.evaluation_metrics.f1)
        .sum::<f64>()
        / datasets.len().max(1) as f64;
    let best_f1 = datasets
        .iter()
        .map(|d| d.evaluation_metrics.f1)
        .fold(0.0f64, f64::max);
    let worst_f1 = datasets
        .iter()
        .map(|d| d.evaluation_metrics.f1)
        .fold(1.0f64, f64::min);
    let tp: usize = datasets
        .iter()
        .map(|d| d.evaluation_metrics.true_positives)
        .sum();
    let fp: usize = datasets
        .iter()
        .map(|d| d.evaluation_metrics.false_positives)
        .sum();
    let fn_: usize = datasets
        .iter()
        .map(|d| d.evaluation_metrics.false_negatives)
        .sum();
    let unique: usize = datasets
        .iter()
        .map(|d| d.evaluation_metrics.unique_findings)
        .sum();

    let chain_acc: BTreeMap<String, ChainAccuracy> = by_chain
        .iter()
        .map(|(chain, metrics)| {
            let n = metrics.len() as f64;
            (
                chain.clone(),
                ChainAccuracy {
                    chain: chain.clone(),
                    count: metrics.len(),
                    avg_precision: metrics.iter().map(|m| m.precision).sum::<f64>() / n,
                    avg_recall: metrics.iter().map(|m| m.recall).sum::<f64>() / n,
                    avg_f1: metrics.iter().map(|m| m.f1).sum::<f64>() / n,
                },
            )
        })
        .collect();

    let source_acc: BTreeMap<String, SourceAccuracy> = BTreeMap::new();

    let trend = if accuracy_over_time.len() >= 2 {
        let first_f1 = accuracy_over_time.first().map_or(0.0, |a| a.f1);
        let last_f1 = accuracy_over_time.last().map_or(0.0, |a| a.f1);
        AccuracyTrend {
            improving: last_f1 >= first_f1,
            f1_delta: last_f1 - first_f1,
            explanation: if last_f1 > first_f1 {
                format!("F1 improved by {:.1}%", (last_f1 - first_f1) * 100.0)
            } else if last_f1 < first_f1 {
                format!("F1 declined by {:.1}%", (first_f1 - last_f1) * 100.0)
            } else {
                "F1 unchanged".into()
            },
        }
    } else {
        AccuracyTrend {
            improving: true,
            f1_delta: 0.0,
            explanation: "Insufficient data for trend".into(),
        }
    };

    AccuracyDashboard {
        generated_at: now_iso(),
        total_evaluations: datasets.len(),
        accuracy_over_time,
        overall: AggregateAccuracy {
            avg_precision: avg_p,
            avg_recall: avg_r,
            avg_f1,
            best_f1,
            worst_f1,
            total_true_positives: tp,
            total_false_positives: fp,
            total_false_negatives: fn_,
            total_unique: unique,
        },
        by_chain: chain_acc,
        by_source: source_acc,
        trend,
    }
}

/// Display accuracy dashboard.
pub fn display_accuracy_dashboard(dashboard: &AccuracyDashboard) -> String {
    let mut out = String::new();
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str("  ACCURACY DASHBOARD\n");
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str(&format!(
        "Evaluations: {} | Overall F1: {:.1}%\n",
        dashboard.total_evaluations,
        dashboard.overall.avg_f1 * 100.0
    ));
    out.push_str(&format!(
        "P: {:.1}% | R: {:.1}% | Best: {:.1}% | Worst: {:.1}%\n",
        dashboard.overall.avg_precision * 100.0,
        dashboard.overall.avg_recall * 100.0,
        dashboard.overall.best_f1 * 100.0,
        dashboard.overall.worst_f1 * 100.0
    ));
    out.push_str(&format!(
        "TP: {} | FP: {} | FN: {} | Unique: {}\n\n",
        dashboard.overall.total_true_positives,
        dashboard.overall.total_false_positives,
        dashboard.overall.total_false_negatives,
        dashboard.overall.total_unique
    ));
    out.push_str(&format!(
        "Trend: {} (Δ{:+.1}%)\n",
        dashboard.trend.explanation,
        dashboard.trend.f1_delta * 100.0
    ));
    if !dashboard.by_chain.is_empty() {
        out.push_str("\n─── By Chain ─────────────────────────────────────\n");
        for (chain, acc) in &dashboard.by_chain {
            out.push_str(&format!(
                "  {:.<15} P={:.0}% R={:.0}% F1={:.0}% (n={})\n",
                chain,
                acc.avg_precision * 100.0,
                acc.avg_recall * 100.0,
                acc.avg_f1 * 100.0,
                acc.count
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
    fn test_dataset_creation() {
        let ds = create_dataset(
            "TestProtocol",
            "evm",
            "abc123def456",
            "1.0.0",
            "0.8.20",
            &[],
            &EvaluationSummary {
                total_official: 5,
                total_digger: 4,
                exact_matches: 3,
                partial_matches: 1,
                unique_findings: 0,
                false_positives: 0,
                missed_findings: 1,
                precision: 1.0,
                recall: 0.8,
                f1: 0.89,
            },
            100,
            200,
            300,
        );
        assert_eq!(ds.protocol, "TestProtocol");
        assert!(ds.evaluation_metrics.precision > 0.0);
    }

    #[test]
    fn test_accuracy_dashboard() {
        let ds = create_dataset(
            "P1",
            "evm",
            "abc123",
            "1.0",
            "0.8.20",
            &[],
            &EvaluationSummary {
                total_official: 5,
                total_digger: 4,
                exact_matches: 3,
                partial_matches: 1,
                unique_findings: 0,
                false_positives: 0,
                missed_findings: 1,
                precision: 1.0,
                recall: 0.8,
                f1: 0.89,
            },
            100,
            200,
            300,
        );
        let dashboard = build_accuracy_dashboard(&[ds]);
        assert_eq!(dashboard.total_evaluations, 1);
        assert!(dashboard.overall.avg_f1 > 0.0);
        let display = display_accuracy_dashboard(&dashboard);
        assert!(display.contains("ACCURACY DASHBOARD"));
    }
}
