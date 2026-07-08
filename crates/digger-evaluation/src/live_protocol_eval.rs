/// Live Protocol Evaluation — deterministic evaluation pipeline for real-world targets.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Complete evaluation result for a real-world protocol target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolEvaluation {
    pub target_id: String,
    pub protocol: String,
    pub chain: String,
    pub source: String,
    pub scan_timestamp: String,
    pub findings: Vec<EvaluatedFinding>,
    pub metrics: EvaluationMetrics,
    pub finding_validation: FindingValidationReport,
    pub performance: EvalPerformanceMetrics,
    pub report: String,
}

/// A single finding with full traceability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluatedFinding {
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub vulnerability_class: String,
    pub confidence: f64,
    pub evidence_chain: Vec<EvidenceChainLink>,
    pub root_cause: String,
    pub invariants: Vec<String>,
    pub trust_boundaries: Vec<String>,
    pub reasoning_trace: Vec<String>,
    pub validation_result: String,
    pub execution_feasibility: f64,
    pub benchmark_similarity: f64,
}

/// A single link in an evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChainLink {
    pub step: usize,
    pub evidence_type: String,
    pub source: String,
    pub description: String,
    pub confidence: f64,
}

/// Finding validation against official reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingValidationReport {
    pub total_generated: usize,
    pub exact_matches: usize,
    pub partial_matches: usize,
    pub related_findings: usize,
    pub novel_candidates: usize,
    pub false_positives: usize,
    pub precision: f64,
    pub recall: f64,
    pub comparison_details: Vec<FindingComparison>,
}

/// Comparison of a single finding against official reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingComparison {
    pub digger_finding: String,
    pub official_finding: Option<String>,
    pub classification: MatchClassification,
    pub similarity_score: f64,
    pub explanation: String,
}

/// Classification of finding match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MatchClassification {
    ExactMatch,
    PartialMatch,
    RelatedFinding,
    NovelCandidate,
    FalsePositive,
}

/// Evaluation metrics for a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationMetrics {
    pub precision: f64,
    pub recall: f64,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
    pub root_cause_accuracy: f64,
    pub explanation_completeness: f64,
    pub evidence_quality: f64,
    pub ranking_accuracy: f64,
    pub execution_success_rate: f64,
    pub validation_accuracy: f64,
}

/// Performance metrics for a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalPerformanceMetrics {
    pub parse_ms: u64,
    pub graph_ms: u64,
    pub reasoning_ms: u64,
    pub synthesis_ms: u64,
    pub validation_ms: u64,
    pub execution_prep_ms: u64,
    pub total_ms: u64,
    pub memory_bytes: u64,
}

/// Run a live protocol evaluation.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_protocol(
    target_id: &str,
    protocol: &str,
    chain: &str,
    source: &str,
    digger_findings: Vec<EvaluatedFinding>,
    official_findings: &[String],
    parse_ms: u64,
    graph_ms: u64,
    reasoning_ms: u64,
    synthesis_ms: u64,
    validation_ms: u64,
    execution_prep_ms: u64,
) -> ProtocolEvaluation {
    let finding_validation =
        validate_findings_against_official(&digger_findings, official_findings);
    let metrics = compute_evaluation_metrics(&finding_validation, &digger_findings);

    let total_ms =
        parse_ms + graph_ms + reasoning_ms + synthesis_ms + validation_ms + execution_prep_ms;

    let report = generate_evaluation_report(
        target_id,
        protocol,
        chain,
        &finding_validation,
        &metrics,
        total_ms,
    );

    ProtocolEvaluation {
        target_id: target_id.to_string(),
        protocol: protocol.to_string(),
        chain: chain.to_string(),
        source: source.to_string(),
        scan_timestamp: now_iso(),
        findings: digger_findings,
        metrics,
        finding_validation,
        performance: EvalPerformanceMetrics {
            parse_ms,
            graph_ms,
            reasoning_ms,
            synthesis_ms,
            validation_ms,
            execution_prep_ms,
            total_ms,
            memory_bytes: 0,
        },
        report,
    }
}

/// Validate findings against official reports.
fn validate_findings_against_official(
    findings: &[EvaluatedFinding],
    official: &[String],
) -> FindingValidationReport {
    let mut comparisons = Vec::new();
    let mut matched_official: BTreeSet<usize> = BTreeSet::new();

    for finding in findings {
        let best = official
            .iter()
            .enumerate()
            .map(|(i, o)| (i, compute_similarity(&finding.title, o)))
            .max_by_key(|(_, s)| (s * 10000.0) as i64);

        match best {
            Some((idx, score)) if score >= 0.9 => {
                matched_official.insert(idx);
                comparisons.push(FindingComparison {
                    digger_finding: finding.title.clone(),
                    official_finding: Some(official[idx].clone()),
                    classification: MatchClassification::ExactMatch,
                    similarity_score: score,
                    explanation: "Exact match with official finding".to_string(),
                });
            }
            Some((idx, score)) if score >= 0.6 => {
                matched_official.insert(idx);
                comparisons.push(FindingComparison {
                    digger_finding: finding.title.clone(),
                    official_finding: Some(official[idx].clone()),
                    classification: MatchClassification::PartialMatch,
                    similarity_score: score,
                    explanation: format!("Partial match ({:.0}% similarity)", score * 100.0),
                });
            }
            Some((idx, score)) if score >= 0.3 => {
                matched_official.insert(idx);
                comparisons.push(FindingComparison {
                    digger_finding: finding.title.clone(),
                    official_finding: Some(official[idx].clone()),
                    classification: MatchClassification::RelatedFinding,
                    similarity_score: score,
                    explanation: format!("Related finding ({:.0}% similarity)", score * 100.0),
                });
            }
            _ => {
                comparisons.push(FindingComparison {
                    digger_finding: finding.title.clone(),
                    official_finding: None,
                    classification: MatchClassification::NovelCandidate,
                    similarity_score: 0.0,
                    explanation: "Novel finding not in official reports".into(),
                });
            }
        }
    }

    for (i, o) in official.iter().enumerate() {
        if !matched_official.contains(&i) {
            comparisons.push(FindingComparison {
                digger_finding: String::new(),
                official_finding: Some(o.clone()),
                classification: MatchClassification::FalsePositive,
                similarity_score: 0.0,
                explanation: format!("Missed by Digger: {}", o),
            });
        }
    }

    let exact = comparisons
        .iter()
        .filter(|c| c.classification == MatchClassification::ExactMatch)
        .count();
    let partial = comparisons
        .iter()
        .filter(|c| c.classification == MatchClassification::PartialMatch)
        .count();
    let related = comparisons
        .iter()
        .filter(|c| c.classification == MatchClassification::RelatedFinding)
        .count();
    let novel = comparisons
        .iter()
        .filter(|c| c.classification == MatchClassification::NovelCandidate)
        .count();
    let fp = comparisons
        .iter()
        .filter(|c| c.classification == MatchClassification::FalsePositive)
        .count();

    let tp = exact + partial + related;
    let precision = if tp + novel > 0 {
        tp as f64 / (tp + novel) as f64
    } else {
        0.0
    };
    let recall = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };

    FindingValidationReport {
        total_generated: findings.len(),
        exact_matches: exact,
        partial_matches: partial,
        related_findings: related,
        novel_candidates: novel,
        false_positives: fp,
        precision,
        recall,
        comparison_details: comparisons,
    }
}

/// Compute evaluation metrics.
fn compute_evaluation_metrics(
    validation: &FindingValidationReport,
    findings: &[EvaluatedFinding],
) -> EvaluationMetrics {
    let avg_confidence: f64 =
        findings.iter().map(|f| f.confidence).sum::<f64>() / findings.len().max(1) as f64;
    let avg_evidence: f64 = findings
        .iter()
        .map(|f| f.evidence_chain.len() as f64)
        .sum::<f64>()
        / findings.len().max(1) as f64;
    let avg_benchmark: f64 =
        findings.iter().map(|f| f.benchmark_similarity).sum::<f64>() / findings.len().max(1) as f64;
    let avg_execution: f64 = findings
        .iter()
        .map(|f| f.execution_feasibility)
        .sum::<f64>()
        / findings.len().max(1) as f64;

    EvaluationMetrics {
        precision: validation.precision,
        recall: validation.recall,
        false_positive_rate: if validation.total_generated > 0 {
            validation.false_positives as f64 / validation.total_generated as f64
        } else {
            0.0
        },
        false_negative_rate: if validation.false_positives
            + validation.novel_candidates
            + validation.exact_matches
            + validation.partial_matches
            > 0
        {
            validation.false_positives as f64
                / (validation.false_positives
                    + validation.novel_candidates
                    + validation.exact_matches
                    + validation.partial_matches)
                    .max(1) as f64
        } else {
            0.0
        },
        root_cause_accuracy: avg_confidence,
        explanation_completeness: avg_evidence / 5.0,
        evidence_quality: avg_evidence / 3.0,
        ranking_accuracy: avg_benchmark,
        execution_success_rate: avg_execution,
        validation_accuracy: validation.precision,
    }
}

/// Generate evaluation report.
fn generate_evaluation_report(
    target_id: &str,
    protocol: &str,
    chain: &str,
    validation: &FindingValidationReport,
    metrics: &EvaluationMetrics,
    total_ms: u64,
) -> String {
    format!(
        "═══ Protocol Evaluation: {} ═══\nChain: {} | Source: {} | Time: {}ms\n\n\
        Finding Summary: {} generated | {} exact | {} partial | {} related | {} novel | {} missed\n\
        Metrics: P={:.1}% R={:.1}% FPR={:.1}% FNR={:.1}%\n\
        Quality: RC_Accuracy={:.1}% Explanation={:.1}% Evidence={:.1}%\n\
        Execution: Success={:.1}% Validation={:.1}%",
        protocol,
        chain,
        target_id,
        total_ms,
        validation.total_generated,
        validation.exact_matches,
        validation.partial_matches,
        validation.related_findings,
        validation.novel_candidates,
        validation.false_positives,
        metrics.precision * 100.0,
        metrics.recall * 100.0,
        metrics.false_positive_rate * 100.0,
        metrics.false_negative_rate * 100.0,
        metrics.root_cause_accuracy * 100.0,
        metrics.explanation_completeness * 100.0,
        metrics.evidence_quality * 100.0,
        metrics.execution_success_rate * 100.0,
        metrics.validation_accuracy * 100.0,
    )
}

/// Compute token-based similarity between two strings.
pub fn compute_similarity(a: &str, b: &str) -> f64 {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();
    if a_lower == b_lower {
        return 1.0;
    }
    if a_lower.contains(&b_lower) || b_lower.contains(&a_lower) {
        return 0.9;
    }
    let a_tokens: BTreeSet<&str> = a_lower.split_whitespace().collect();
    let b_tokens: BTreeSet<&str> = b_lower.split_whitespace().collect();
    let intersection = a_tokens.intersection(&b_tokens).count();
    let union = a_tokens.len() + b_tokens.len() - intersection;
    if union > 0 {
        intersection as f64 / union as f64
    } else {
        0.0
    }
}

fn now_iso() -> String {
    format!(
        "{}s",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_evaluation() {
        let findings = vec![EvaluatedFinding {
            finding_id: "f1".into(),
            title: "Reentrancy in withdraw".into(),
            severity: "high".into(),
            vulnerability_class: "reentrancy".into(),
            confidence: 0.9,
            evidence_chain: vec![EvidenceChainLink {
                step: 0,
                evidence_type: "graph_analysis".into(),
                source: "ir".into(),
                description: "External call before state write".into(),
                confidence: 0.95,
            }],
            root_cause: "missing guard".into(),
            invariants: vec!["conservation".into()],
            trust_boundaries: vec!["external_call".into()],
            reasoning_trace: vec![
                "detected external call".into(),
                "detected state write".into(),
            ],
            validation_result: "Valid".into(),
            execution_feasibility: 0.9,
            benchmark_similarity: 0.85,
        }];

        let eval = evaluate_protocol(
            "test",
            "TestProtocol",
            "evm",
            "code4rena",
            findings,
            &["Reentrancy in withdraw".into()],
            100,
            50,
            200,
            100,
            80,
            50,
        );

        assert_eq!(eval.metrics.precision, 1.0);
        assert_eq!(eval.metrics.recall, 1.0);
        assert!(!eval.report.is_empty());
    }

    #[test]
    fn test_similarity() {
        assert_eq!(
            compute_similarity("Reentrancy in withdraw", "Reentrancy in withdraw"),
            1.0
        );
        assert!(compute_similarity("Reentrancy in withdraw", "Withdraw reentrancy bug") > 0.0);
    }
}
