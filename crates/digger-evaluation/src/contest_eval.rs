/// Live Contest Evaluation — compares Digger findings against official judged reports.
use crate::eval_models::*;

/// Evaluate Digger against a historical contest.
pub fn evaluate_contest(
    contest_id: &str,
    source: &str,
    contest_date: &str,
    protocol: &str,
    digger_findings: &[String],
    official_findings: &[String],
) -> ContestEvaluation {
    let mut comparisons = Vec::new();
    let mut true_positives = 0usize;
    let mut partial_matches = 0usize;
    let mut false_positives = 0usize;
    let mut matched_official: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for digger_finding in digger_findings {
        let best_match = official_findings
            .iter()
            .enumerate()
            .map(|(i, official)| (i, compare_findings(digger_finding, official)))
            .max_by_key(|(_, score)| (score * 1000.0) as i64);

        match best_match {
            Some((idx, score)) if score >= 0.9 => {
                true_positives += 1;
                matched_official.insert(idx);
                comparisons.push(FindingComparison {
                    digger_finding: digger_finding.clone(),
                    matched_official: Some(official_findings[idx].clone()),
                    match_type: MatchType::ExactMatch,
                    confidence: score,
                    explanation: "Exact match with official finding".to_string(),
                });
            }
            Some((idx, score)) if score >= 0.5 => {
                partial_matches += 1;
                matched_official.insert(idx);
                comparisons.push(FindingComparison {
                    digger_finding: digger_finding.clone(),
                    matched_official: Some(official_findings[idx].clone()),
                    match_type: MatchType::PartialMatch,
                    confidence: score,
                    explanation: "Partial match: similar but not identical".to_string(),
                });
            }
            _ => {
                false_positives += 1;
                comparisons.push(FindingComparison {
                    digger_finding: digger_finding.clone(),
                    matched_official: None,
                    match_type: MatchType::NoMatch,
                    confidence: 0.0,
                    explanation: "No matching official finding found".into(),
                });
            }
        }
    }

    let false_negatives = official_findings.len() - matched_official.len();
    let unique_findings: Vec<String> = digger_findings
        .iter()
        .filter(|f| {
            !official_findings
                .iter()
                .any(|o| compare_findings(f, o) >= 0.5)
        })
        .cloned()
        .collect();

    let tp = true_positives as f64;
    let fp = false_positives as f64;
    let fn_count = false_negatives as f64;
    let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
    let recall = if tp + fn_count > 0.0 {
        tp / (tp + fn_count)
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    let comparison_report = format!(
        "Contest {}: {} precision={:.1}% recall={:.1}% F1={:.1}% (TP={}, PM={}, FP={}, FN={}, unique={})",
        contest_id, protocol, precision * 100.0, recall * 100.0, f1 * 100.0,
        true_positives, partial_matches, false_positives, false_negatives, unique_findings.len()
    );

    ContestEvaluation {
        contest_id: contest_id.to_string(),
        source: source.to_string(),
        contest_date: contest_date.to_string(),
        protocol: protocol.to_string(),
        digger_findings: comparisons,
        official_findings: official_findings.to_vec(),
        true_positives,
        partial_matches,
        false_positives,
        false_negatives,
        unique_findings,
        precision,
        recall,
        f1,
        comparison_report,
    }
}

/// Compare two findings for similarity.
fn compare_findings(a: &str, b: &str) -> f64 {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();

    if a_lower == b_lower {
        return 1.0;
    }
    if a_lower.contains(&b_lower) || b_lower.contains(&a_lower) {
        return 0.9;
    }

    // Token overlap
    let a_tokens: std::collections::HashSet<&str> = a_lower.split_whitespace().collect();
    let b_tokens: std::collections::HashSet<&str> = b_lower.split_whitespace().collect();
    let intersection: usize = a_tokens.intersection(&b_tokens).count();
    let union_size = a_tokens.len() + b_tokens.len() - intersection;
    if union_size > 0 {
        intersection as f64 / union_size as f64
    } else {
        0.0
    }
}

/// Run evaluation across multiple contests.
pub fn evaluate_contests(contests: &[ContestInput]) -> Vec<ContestEvaluation> {
    contests
        .iter()
        .map(|c| {
            evaluate_contest(
                &c.contest_id,
                &c.source,
                &c.date,
                &c.protocol,
                &c.digger_findings,
                &c.official_findings,
            )
        })
        .collect()
}

/// Aggregate evaluation results.
pub fn aggregate_contest_evaluations(evals: &[ContestEvaluation]) -> String {
    let total_tp: usize = evals.iter().map(|e| e.true_positives).sum();
    let total_fp: usize = evals.iter().map(|e| e.false_positives).sum();
    let total_fn: usize = evals.iter().map(|e| e.false_negatives).sum();
    let total_pm: usize = evals.iter().map(|e| e.partial_matches).sum();

    let avg_precision: f64 =
        evals.iter().map(|e| e.precision).sum::<f64>() / evals.len().max(1) as f64;
    let avg_recall: f64 = evals.iter().map(|e| e.recall).sum::<f64>() / evals.len().max(1) as f64;
    let avg_f1: f64 = evals.iter().map(|e| e.f1).sum::<f64>() / evals.len().max(1) as f64;

    format!(
        "═══ Contest Evaluation Summary ═══\nContests: {} | Total: TP={} PM={} FP={} FN={}\nAvg Precision: {:.1}% | Avg Recall: {:.1}% | Avg F1: {:.1}%\n",
        evals.len(), total_tp, total_pm, total_fp, total_fn,
        avg_precision * 100.0, avg_recall * 100.0, avg_f1 * 100.0
    )
}

/// Input for a contest evaluation.
#[derive(Debug, Clone)]
pub struct ContestInput {
    pub contest_id: String,
    pub source: String,
    pub date: String,
    pub protocol: String,
    pub digger_findings: Vec<String>,
    pub official_findings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let eval = evaluate_contest(
            "test-1",
            "code4rena",
            "2024-01",
            "Protocol",
            &[
                "Reentrancy in withdraw".into(),
                "Missing access control".into(),
            ],
            &[
                "Reentrancy in withdraw".into(),
                "Oracle manipulation".into(),
            ],
        );
        assert_eq!(eval.true_positives, 1);
        assert_eq!(eval.false_positives, 1);
        assert_eq!(eval.false_negatives, 1);
        assert!(eval.precision > 0.0 && eval.precision <= 1.0);
    }

    #[test]
    fn test_no_matches() {
        let eval = evaluate_contest(
            "test-2",
            "code4rena",
            "2024-01",
            "Protocol",
            &["Unique finding".into()],
            &["Official finding".into()],
        );
        assert_eq!(eval.true_positives, 0);
        assert_eq!(eval.false_positives, 1);
        assert_eq!(eval.false_negatives, 1);
    }

    #[test]
    fn test_perfect_match() {
        let eval = evaluate_contest(
            "test-3",
            "code4rena",
            "2024-01",
            "Protocol",
            &["Reentrancy in withdraw".into()],
            &["Reentrancy in withdraw".into()],
        );
        assert_eq!(eval.true_positives, 1);
        assert_eq!(eval.precision, 1.0);
        assert_eq!(eval.recall, 1.0);
    }

    #[test]
    fn test_aggregate() {
        let evals = vec![
            evaluate_contest("a", "c4", "2024", "P1", &["f1".into()], &["f1".into()]),
            evaluate_contest(
                "b",
                "c4",
                "2024",
                "P2",
                &["f1".into(), "f2".into()],
                &["f1".into()],
            ),
        ];
        let summary = aggregate_contest_evaluations(&evals);
        assert!(summary.contains("Contest Evaluation Summary"));
    }
}
