/// Evaluation metrics — deterministic computation of evaluation scores.
use crate::models::*;

/// Compute precision from true positives and false positives.
pub fn compute_precision(tp: usize, fp: usize) -> f64 {
    let total = tp + fp;
    if total == 0 {
        0.0
    } else {
        tp as f64 / total as f64
    }
}

/// Compute recall from true positives and false negatives.
pub fn compute_recall(tp: usize, fn_: usize) -> f64 {
    let total = tp + fn_;
    if total == 0 {
        0.0
    } else {
        tp as f64 / total as f64
    }
}

/// Compute F1 score from precision and recall.
pub fn compute_f1(precision: f64, recall: f64) -> f64 {
    if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    }
}

/// Compute root-cause accuracy.
///
/// Checks if the detected root cause matches the expected root cause.
pub fn compute_root_cause_accuracy(detected: &[String], expected: &str) -> f64 {
    let normalized_expected = normalize_finding(expected);
    let has_match = detected
        .iter()
        .any(|d| normalize_finding(d) == normalized_expected);
    if has_match {
        1.0
    } else {
        // Partial credit for related root causes
        let expected_lower = normalized_expected.to_lowercase();
        for d in detected {
            let d_lower = normalize_finding(d);
            if d_lower.contains(&expected_lower) || expected_lower.contains(&d_lower) {
                return 0.5;
            }
        }
        0.0
    }
}

/// Compute explanation completeness score.
pub fn compute_explanation_completeness(metrics: &ExplanationMetrics) -> f64 {
    let mut score = 0.0;
    if metrics.has_reasoning_trace {
        score += 0.2;
    }
    if metrics.has_evidence_chain {
        score += 0.2;
    }
    if metrics.has_violated_invariants {
        score += 0.2;
    }
    if metrics.has_trust_boundaries {
        score += 0.2;
    }
    if metrics.has_mitigation {
        score += 0.2;
    }
    score
}

/// Compute evidence quality score.
pub fn compute_evidence_quality(metrics: &EvidenceMetrics) -> f64 {
    if metrics.total_evidence == 0 {
        return 0.0;
    }

    let depth_score = (metrics.depth / 5.0).min(1.0);
    let diversity_score = (metrics.diversity as f64 / 6.0).min(1.0);
    let uniqueness_score = if metrics.total_evidence > 0 {
        metrics.unique_evidence as f64 / metrics.total_evidence as f64
    } else {
        0.0
    };

    (depth_score * 0.4 + diversity_score * 0.3 + uniqueness_score * 0.3).min(1.0)
}

/// Normalize a finding name for matching.
///
/// Rules:
/// - trim whitespace
/// - replace hyphens with underscores
/// - insert underscores before uppercase letters (camelCase → snake_case)
/// - lowercase everything
/// - collapse multiple underscores
/// - exact comparison after normalization
pub fn normalize_finding(name: &str) -> String {
    let trimmed = name.trim();
    let chars: Vec<char> = trimmed.chars().collect();
    let mut result = String::new();

    for (i, c) in chars.iter().enumerate() {
        if *c == '-' {
            result.push('_');
        } else if c.is_uppercase() {
            // Add underscore before uppercase if:
            // - not at start, AND
            // - previous char was lowercase OR (previous was uppercase AND next is lowercase)
            if i > 0 {
                let prev = chars[i - 1];
                let next = chars.get(i + 1).copied();
                if prev.is_lowercase()
                    || (prev.is_uppercase() && next.is_some_and(|n| n.is_lowercase()))
                {
                    result.push('_');
                }
            }
            result.push(c.to_lowercase().next().unwrap_or(*c));
        } else {
            result.push(*c);
        }
    }

    // Collapse multiple underscores and trim
    let mut collapsed = String::new();
    let mut prev_underscore = false;
    for c in result.chars() {
        if c == '_' {
            if !prev_underscore {
                collapsed.push(c);
            }
            prev_underscore = true;
        } else {
            collapsed.push(c);
            prev_underscore = false;
        }
    }

    collapsed.trim_matches('_').to_string()
}

/// Match detected against expected findings.
///
/// Uses normalized exact comparison after case-insensitive matching.
pub fn findings_match(detected: &str, expected: &str) -> bool {
    let d = normalize_finding(detected);
    let e = normalize_finding(expected);
    // Exact match after normalization
    if d == e {
        return true;
    }
    // Check if one contains the other (for partial matches like "Reentrancy" in "ReentrancyCandidate")
    if d.contains(&e) || e.contains(&d) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precision() {
        assert!((compute_precision(8, 2) - 0.8).abs() < 0.001);
        assert!((compute_precision(0, 0) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_recall() {
        assert!((compute_recall(8, 2) - 0.8).abs() < 0.001);
        assert!((compute_recall(0, 0) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_f1() {
        let f1 = compute_f1(0.8, 0.8);
        assert!((f1 - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_root_cause_accuracy() {
        assert_eq!(
            compute_root_cause_accuracy(&["reentrancy".into()], "reentrancy"),
            1.0
        );
        assert_eq!(
            compute_root_cause_accuracy(&["other".into()], "reentrancy"),
            0.0
        );
    }

    #[test]
    fn test_explanation_completeness() {
        let full = ExplanationMetrics {
            has_reasoning_trace: true,
            has_evidence_chain: true,
            has_violated_invariants: true,
            has_trust_boundaries: true,
            has_mitigation: true,
            completeness_score: 0.0,
        };
        assert!((compute_explanation_completeness(&full) - 1.0).abs() < 0.001);

        let empty = ExplanationMetrics {
            has_reasoning_trace: false,
            has_evidence_chain: false,
            has_violated_invariants: false,
            has_trust_boundaries: false,
            has_mitigation: false,
            completeness_score: 0.0,
        };
        assert!((compute_explanation_completeness(&empty) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_normalize() {
        assert_eq!(
            normalize_finding("ReentrancyCandidate"),
            "reentrancy_candidate"
        );
        assert_eq!(
            normalize_finding("reentrancy_candidate"),
            "reentrancy_candidate"
        );
        assert_eq!(
            normalize_finding("MissingAccessControl"),
            "missing_access_control"
        );
    }

    #[test]
    fn test_finding_matching() {
        assert!(findings_match(
            "ReentrancyCandidate",
            "reentrancy_candidate"
        ));
        assert!(findings_match(
            "reentrancy_candidate",
            "ReentrancyCandidate"
        ));
        assert!(!findings_match("ReentrancyCandidate", "authority_bypass"));
    }
}
