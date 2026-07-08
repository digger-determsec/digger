/// Live Evaluation Runner — run Digger against real protocols and compare.
use crate::eval_models::*;

/// Configuration for a live evaluation run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvaluationTarget {
    pub target_id: String,
    pub source: String,
    pub protocol: String,
    pub chain: String,
    pub commit_hash: Option<String>,
    pub protocol_version: Option<String>,
    pub compiler_version: Option<String>,
    pub source_files: Vec<String>,
    pub official_findings: Vec<OfficialFinding>,
}

/// An official finding from a judged report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OfficialFinding {
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub vulnerability_class: String,
    pub root_cause: String,
    pub affected_contracts: Vec<String>,
    pub affected_functions: Vec<String>,
    pub impact: String,
    pub mitigation: String,
}

/// Result of running Digger against a target.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvaluationResult {
    pub target: EvaluationTarget,
    pub digger_findings: Vec<DiggerFinding>,
    pub comparisons: Vec<FindingComparison>,
    pub summary: EvaluationSummary,
    pub performance: PerformanceMetrics,
    pub report: String,
}

/// A finding produced by Digger.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiggerFinding {
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub vulnerability_class: String,
    pub confidence: f64,
    pub evidence_count: usize,
    pub hypothesis_type: String,
}

/// Summary of comparison results.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvaluationSummary {
    pub total_official: usize,
    pub total_digger: usize,
    pub exact_matches: usize,
    pub partial_matches: usize,
    pub unique_findings: usize,
    pub false_positives: usize,
    pub missed_findings: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// Performance metrics for the evaluation run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerformanceMetrics {
    pub parse_time_ms: u64,
    pub graph_time_ms: u64,
    pub reasoning_time_ms: u64,
    pub synthesis_time_ms: u64,
    pub total_time_ms: u64,
    pub memory_bytes: u64,
}

/// Run evaluation against a single target.
pub fn evaluate_target(
    target: &EvaluationTarget,
    digger_findings: &[DiggerFinding],
    parse_ms: u64,
    graph_ms: u64,
    reasoning_ms: u64,
    synthesis_ms: u64,
) -> EvaluationResult {
    let comparisons = compare_findings(digger_findings, &target.official_findings);
    let summary = compute_summary(&comparisons);
    let report = generate_comparison_report(target, &comparisons, &summary);

    EvaluationResult {
        target: target.clone(),
        digger_findings: digger_findings.to_vec(),
        comparisons,
        summary,
        performance: PerformanceMetrics {
            parse_time_ms: parse_ms,
            graph_time_ms: graph_ms,
            reasoning_time_ms: reasoning_ms,
            synthesis_time_ms: synthesis_ms,
            total_time_ms: parse_ms + graph_ms + reasoning_ms + synthesis_ms,
            memory_bytes: 0,
        },
        report,
    }
}

/// Compare Digger findings against official findings.
fn compare_findings(
    digger: &[DiggerFinding],
    official: &[OfficialFinding],
) -> Vec<FindingComparison> {
    let mut comparisons = Vec::new();
    let mut matched_official: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for df in digger {
        let best = official
            .iter()
            .enumerate()
            .map(|(i, of)| (i, score_match(df, of)))
            .max_by_key(|(_, s)| (s * 10000.0) as i64);

        match best {
            Some((idx, score)) if score >= 0.9 => {
                matched_official.insert(idx);
                comparisons.push(FindingComparison {
                    digger_finding: df.title.clone(),
                    matched_official: Some(official[idx].title.clone()),
                    match_type: MatchType::ExactMatch,
                    confidence: score,
                    explanation: format!("Exact match with '{}'", official[idx].title),
                });
            }
            Some((idx, score)) if score >= 0.4 => {
                matched_official.insert(idx);
                comparisons.push(FindingComparison {
                    digger_finding: df.title.clone(),
                    matched_official: Some(official[idx].title.clone()),
                    match_type: MatchType::PartialMatch,
                    confidence: score,
                    explanation: format!(
                        "Partial match with '{}' ({:.0}% similarity)",
                        official[idx].title,
                        score * 100.0
                    ),
                });
            }
            _ => {
                comparisons.push(FindingComparison {
                    digger_finding: df.title.clone(),
                    matched_official: None,
                    match_type: MatchType::NoMatch,
                    confidence: 0.0,
                    explanation: "Unique finding not in official report".into(),
                });
            }
        }
    }

    // Mark missed official findings
    for (i, of) in official.iter().enumerate() {
        if !matched_official.contains(&i) {
            comparisons.push(FindingComparison {
                digger_finding: String::new(),
                matched_official: Some(of.title.clone()),
                match_type: MatchType::FalsePositive,
                confidence: 0.0,
                explanation: format!("Missed by Digger: {}", of.title),
            });
        }
    }

    comparisons
}

/// Score similarity between a Digger finding and an official finding.
fn score_match(digger: &DiggerFinding, official: &OfficialFinding) -> f64 {
    let mut score = 0.0;

    // Title similarity
    let title_score = token_similarity(&digger.title, &official.title);
    score += title_score * 0.4;

    // Vulnerability class match
    if normalize(&digger.vulnerability_class) == normalize(&official.vulnerability_class) {
        score += 0.3;
    } else if fuzzy_match(&digger.vulnerability_class, &official.vulnerability_class) > 0.5 {
        score += 0.15;
    }

    // Root cause similarity (if available)
    if !official.root_cause.is_empty() {
        let rc_score = token_similarity(&digger.title, &official.root_cause);
        score += rc_score * 0.2;
    }

    // Affected component overlap
    if !official.affected_functions.is_empty() {
        let has_overlap = official
            .affected_functions
            .iter()
            .any(|f| digger.title.to_lowercase().contains(&f.to_lowercase()));
        if has_overlap {
            score += 0.1;
        }
    }

    score.min(1.0)
}

/// Compute evaluation summary.
fn compute_summary(comparisons: &[FindingComparison]) -> EvaluationSummary {
    let exact = comparisons
        .iter()
        .filter(|c| c.match_type == MatchType::ExactMatch)
        .count();
    let partial = comparisons
        .iter()
        .filter(|c| c.match_type == MatchType::PartialMatch)
        .count();
    let unique = comparisons
        .iter()
        .filter(|c| c.match_type == MatchType::NoMatch && !c.digger_finding.is_empty())
        .count();
    let missed = comparisons
        .iter()
        .filter(|c| c.match_type == MatchType::FalsePositive)
        .count();

    let tp = exact + partial;
    let fp = unique;
    let fn_ = missed;

    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };
    let recall = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    EvaluationSummary {
        total_official: exact + partial + missed,
        total_digger: exact + partial + unique,
        exact_matches: exact,
        partial_matches: partial,
        unique_findings: unique,
        false_positives: unique,
        missed_findings: missed,
        precision,
        recall,
        f1,
    }
}

fn generate_comparison_report(
    target: &EvaluationTarget,
    comparisons: &[FindingComparison],
    summary: &EvaluationSummary,
) -> String {
    let mut out = format!("═══ Evaluation Report: {} ═══\n", target.protocol);
    out.push_str(&format!(
        "Source: {} | Chain: {} | Target: {}\n",
        target.source, target.chain, target.target_id
    ));
    out.push_str(&format!(
        "Official: {} findings | Digger: {} findings\n\n",
        summary.total_official, summary.total_digger
    ));
    out.push_str(&format!(
        "Results: {} exact, {} partial, {} unique, {} missed\n",
        summary.exact_matches,
        summary.partial_matches,
        summary.unique_findings,
        summary.missed_findings
    ));
    out.push_str(&format!(
        "Metrics: P={:.1}% R={:.1}% F1={:.1}%\n\n",
        summary.precision * 100.0,
        summary.recall * 100.0,
        summary.f1 * 100.0
    ));

    for c in comparisons {
        let icon = match c.match_type {
            MatchType::ExactMatch => "✓",
            MatchType::PartialMatch => "~",
            MatchType::NoMatch => "+",
            MatchType::FalsePositive => "✗",
            MatchType::SemanticMatch => "~",
        };
        if !c.digger_finding.is_empty() {
            out.push_str(&format!(
                "  {} Digger: {}{}\n",
                icon,
                c.digger_finding,
                c.matched_official
                    .as_ref()
                    .map(|o| format!(" → {}", o))
                    .unwrap_or_default()
            ));
        } else if let Some(o) = &c.matched_official {
            out.push_str(&format!("  {} Missed: {}\n", icon, o));
        }
    }
    out
}

fn token_similarity(a: &str, b: &str) -> f64 {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();
    let a_set: std::collections::HashSet<&str> = a_lower.split_whitespace().collect();
    let b_set: std::collections::HashSet<&str> = b_lower.split_whitespace().collect();
    let intersection = a_set.intersection(&b_set).count();
    let union = a_set.len() + b_set.len() - intersection;
    if union > 0 {
        intersection as f64 / union as f64
    } else {
        0.0
    }
}

fn normalize(s: &str) -> String {
    s.to_lowercase().replace(['_', '-'], " ").trim().to_string()
}

fn fuzzy_match(a: &str, b: &str) -> f64 {
    token_similarity(a, b)
}

/// Batch evaluate multiple targets.
pub fn evaluate_targets(
    targets: &[EvaluationTarget],
    results: &[Vec<DiggerFinding>],
    timings: &[PerformanceMetrics],
) -> Vec<EvaluationResult> {
    targets
        .iter()
        .zip(results.iter())
        .zip(timings.iter())
        .map(|((target, findings), perf)| {
            evaluate_target(
                target,
                findings,
                perf.parse_time_ms,
                perf.graph_time_ms,
                perf.reasoning_time_ms,
                perf.synthesis_time_ms,
            )
        })
        .collect()
}

/// Aggregate multiple evaluation results.
pub fn aggregate_results(results: &[EvaluationResult]) -> String {
    let total_official: usize = results.iter().map(|r| r.summary.total_official).sum();
    let total_digger: usize = results.iter().map(|r| r.summary.total_digger).sum();
    let total_tp: usize = results
        .iter()
        .map(|r| r.summary.exact_matches + r.summary.partial_matches)
        .sum();
    let total_fp: usize = results.iter().map(|r| r.summary.unique_findings).sum();
    let total_fn: usize = results.iter().map(|r| r.summary.missed_findings).sum();

    let avg_p =
        results.iter().map(|r| r.summary.precision).sum::<f64>() / results.len().max(1) as f64;
    let avg_r = results.iter().map(|r| r.summary.recall).sum::<f64>() / results.len().max(1) as f64;
    let avg_f1 = results.iter().map(|r| r.summary.f1).sum::<f64>() / results.len().max(1) as f64;
    let avg_time: u64 = results
        .iter()
        .map(|r| r.performance.total_time_ms)
        .sum::<u64>()
        / results.len().max(1) as u64;

    format!(
        "═══ Evaluation Aggregate ═══\nTargets: {} | Official: {} | Digger: {}\nTP: {} FP: {} FN: {}\nAvg P: {:.1}% R: {:.1}% F1: {:.1}% | Avg Time: {}ms\n",
        results.len(), total_official, total_digger, total_tp, total_fp, total_fn,
        avg_p * 100.0, avg_r * 100.0, avg_f1 * 100.0, avg_time
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match_evaluation() {
        let target = EvaluationTarget {
            target_id: "t1".into(),
            source: "c4".into(),
            protocol: "TestProtocol".into(),
            chain: "evm".into(),
            commit_hash: None,
            protocol_version: None,
            compiler_version: None,
            source_files: vec![],
            official_findings: vec![OfficialFinding {
                finding_id: "f1".into(),
                title: "Reentrancy in withdraw".into(),
                severity: "high".into(),
                vulnerability_class: "reentrancy".into(),
                root_cause: "missing guard".into(),
                affected_contracts: vec![],
                affected_functions: vec!["withdraw".into()],
                impact: "fund loss".into(),
                mitigation: "add guard".into(),
            }],
        };
        let digger = vec![DiggerFinding {
            finding_id: "d1".into(),
            title: "Reentrancy in withdraw".into(),
            severity: "high".into(),
            vulnerability_class: "reentrancy".into(),
            confidence: 0.9,
            evidence_count: 3,
            hypothesis_type: "ReentrancyCandidate".into(),
        }];
        let result = evaluate_target(&target, &digger, 100, 50, 200, 100);
        assert!(result.summary.exact_matches + result.summary.partial_matches >= 1);
        assert!(result.summary.precision > 0.0);
    }

    #[test]
    fn test_partial_match() {
        let target = EvaluationTarget {
            target_id: "t2".into(),
            source: "c4".into(),
            protocol: "Test".into(),
            chain: "evm".into(),
            commit_hash: None,
            protocol_version: None,
            compiler_version: None,
            source_files: vec![],
            official_findings: vec![OfficialFinding {
                finding_id: "f1".into(),
                title: "Access control bypass in admin".into(),
                severity: "critical".into(),
                vulnerability_class: "access_control".into(),
                root_cause: "missing check".into(),
                affected_contracts: vec![],
                affected_functions: vec![],
                impact: "privilege escalation".into(),
                mitigation: "add check".into(),
            }],
        };
        let digger = vec![DiggerFinding {
            finding_id: "d1".into(),
            title: "Authority bypass in admin function".into(),
            severity: "critical".into(),
            vulnerability_class: "access_control".into(),
            confidence: 0.8,
            evidence_count: 2,
            hypothesis_type: "AuthorityBypassCandidate".into(),
        }];
        let result = evaluate_target(&target, &digger, 50, 30, 100, 50);
        assert!(result.summary.exact_matches + result.summary.partial_matches >= 1);
        assert!(result.summary.precision > 0.0);
    }

    #[test]
    fn test_aggregate() {
        let target = EvaluationTarget {
            target_id: "t1".into(),
            source: "c4".into(),
            protocol: "P".into(),
            chain: "evm".into(),
            commit_hash: None,
            protocol_version: None,
            compiler_version: None,
            source_files: vec![],
            official_findings: vec![],
        };
        let digger = vec![];
        let r1 = evaluate_target(&target, &digger, 100, 50, 200, 100);
        let r2 = evaluate_target(&target, &digger, 80, 40, 150, 80);
        let agg = aggregate_results(&[r1, r2]);
        assert!(agg.contains("Evaluation Aggregate"));
    }
}
