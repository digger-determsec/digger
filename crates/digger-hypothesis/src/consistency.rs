/// Reasoning Consistency — detect inconsistencies and duplicates.
use serde::{Deserialize, Serialize};

/// Consistency report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsistencyReport {
    /// Total hypotheses analyzed.
    pub total_hypotheses: usize,
    /// Internally inconsistent hypotheses.
    pub inconsistent_count: usize,
    /// Duplicate reasoning chains.
    pub duplicate_chains: Vec<DuplicateChain>,
    /// Competing hypotheses that should be mutually exclusive.
    pub conflicting_pairs: Vec<ConflictingPair>,
    /// Overall consistency score.
    pub consistency_score: f64,
}

/// A duplicate reasoning chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DuplicateChain {
    /// First hypothesis ID.
    pub first_id: String,
    /// Second hypothesis ID.
    pub second_id: String,
    /// Shared evidence.
    pub shared_evidence: Vec<String>,
    /// Similarity description.
    pub similarity: String,
}

/// A pair of hypotheses that conflict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConflictingPair {
    /// First hypothesis ID.
    pub first_id: String,
    /// Second hypothesis ID.
    pub second_id: String,
    /// Nature of conflict.
    pub conflict_type: String,
    /// Evidence for first hypothesis.
    pub evidence_for_first: Vec<String>,
    /// Evidence for second hypothesis.
    pub evidence_for_second: Vec<String>,
}

/// Detect inconsistencies and duplicates in hypotheses.
pub fn check_consistency(
    hypotheses: &[(String, String, Vec<String>)], // (id, kind, evidence)
) -> ConsistencyReport {
    let total = hypotheses.len();

    let mut duplicate_chains = Vec::new();
    let mut conflicting_pairs = Vec::new();

    // Check for duplicate reasoning chains
    for i in 0..hypotheses.len() {
        for j in (i + 1)..hypotheses.len() {
            let (id_a, kind_a, evidence_a) = &hypotheses[i];
            let (id_b, kind_b, evidence_b) = &hypotheses[j];

            // Same kind = potential duplicate
            if kind_a == kind_b {
                let shared: Vec<String> = evidence_a
                    .iter()
                    .filter(|e| evidence_b.contains(e))
                    .cloned()
                    .collect();

                if shared.len() >= 2 {
                    duplicate_chains.push(DuplicateChain {
                        first_id: id_a.clone(),
                        second_id: id_b.clone(),
                        shared_evidence: shared,
                        similarity: format!("Both hypotheses of type '{}' share evidence", kind_a),
                    });
                }
            }
        }
    }

    // Check for conflicting hypotheses
    for i in 0..hypotheses.len() {
        for j in (i + 1)..hypotheses.len() {
            let (id_a, kind_a, evidence_a) = &hypotheses[i];
            let (id_b, kind_b, evidence_b) = &hypotheses[j];

            // Check if one says safe and other says unsafe
            let a_safe = kind_a.contains("Safe") || kind_a.contains("safe");
            let b_safe = kind_b.contains("Safe") || kind_b.contains("safe");
            let a_unsafe = kind_a.contains("Risk")
                || kind_a.contains("Vulnerability")
                || kind_a.contains("Missing");
            let b_unsafe = kind_b.contains("Risk")
                || kind_b.contains("Vulnerability")
                || kind_b.contains("Missing");

            if (a_safe && b_unsafe) || (a_unsafe && b_safe) {
                conflicting_pairs.push(ConflictingPair {
                    first_id: id_a.clone(),
                    second_id: id_b.clone(),
                    conflict_type: "safety_contradiction".into(),
                    evidence_for_first: evidence_a.clone(),
                    evidence_for_second: evidence_b.clone(),
                });
            }
        }
    }

    let inconsistent = duplicate_chains.len() + conflicting_pairs.len();
    let consistency_score = if total > 0 {
        1.0 - (inconsistent as f64 / total as f64).min(1.0)
    } else {
        1.0
    };

    ConsistencyReport {
        total_hypotheses: total,
        inconsistent_count: inconsistent,
        duplicate_chains,
        conflicting_pairs,
        consistency_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_inconsistencies() {
        let hypotheses = vec![
            ("H1".into(), "Reentrancy".into(), vec!["evidence1".into()]),
            ("H2".into(), "Authority".into(), vec!["evidence2".into()]),
        ];
        let report = check_consistency(&hypotheses);
        assert_eq!(report.inconsistent_count, 0);
        assert_eq!(report.consistency_score, 1.0);
    }

    #[test]
    fn test_duplicate_detected() {
        let hypotheses = vec![
            (
                "H1".into(),
                "Reentrancy".into(),
                vec!["evidence1".into(), "evidence2".into()],
            ),
            (
                "H2".into(),
                "Reentrancy".into(),
                vec!["evidence1".into(), "evidence2".into()],
            ),
        ];
        let report = check_consistency(&hypotheses);
        assert!(!report.duplicate_chains.is_empty());
    }

    #[test]
    fn test_conflict_detected() {
        let hypotheses = vec![
            ("H1".into(), "SafePattern".into(), vec!["evidence1".into()]),
            (
                "H2".into(),
                "ReentrancyRisk".into(),
                vec!["evidence2".into()],
            ),
        ];
        let report = check_consistency(&hypotheses);
        assert!(!report.conflicting_pairs.is_empty());
    }
}
