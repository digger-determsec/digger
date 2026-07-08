/// Invariant Proof Coverage — determine proof status for protocol invariants.
use serde::{Deserialize, Serialize};

/// Proof status for an invariant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofStatus {
    /// Fully proven by evidence.
    Proven,
    /// Partially proven (some evidence, some gaps).
    PartiallyProven,
    /// Assumed but not proven.
    Assumed,
    /// No evidence available.
    Unsupported,
}

/// Coverage for a single invariant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvariantCoverage {
    /// Invariant description.
    pub invariant: String,
    /// Proof status.
    pub status: ProofStatus,
    /// Supporting evidence count.
    pub evidence_count: usize,
    /// Contradicting evidence count.
    pub contradicting_count: usize,
    /// Evidence sources.
    pub sources: Vec<String>,
}

/// Overall proof coverage metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofCoverageMetrics {
    /// Total invariants analyzed.
    pub total_invariants: usize,
    /// Proven invariants.
    pub proven_count: usize,
    /// Partially proven.
    pub partially_proven_count: usize,
    /// Assumed.
    pub assumed_count: usize,
    /// Unsupported.
    pub unsupported_count: usize,
    /// Proof coverage rate (proven / total).
    pub proof_coverage_rate: f64,
    /// Per-invariant details.
    pub invariants: Vec<InvariantCoverage>,
}

/// Evaluate proof coverage for a set of invariants.
pub fn evaluate_proof_coverage(invariants: &[String], evidence: &[String]) -> ProofCoverageMetrics {
    let mut coverage = Vec::new();
    let mut proven = 0;
    let mut partial = 0;
    let mut assumed = 0;
    let mut unsupported = 0;

    for invariant in invariants {
        let inv_lower = invariant.to_lowercase();
        let matching_evidence: Vec<String> = evidence
            .iter()
            .filter(|e| {
                let e_lower = e.to_lowercase();
                inv_lower.contains(&e_lower) || e_lower.contains(&inv_lower)
            })
            .cloned()
            .collect();

        let contradicting = evidence
            .iter()
            .filter(|e| {
                let e_lower = e.to_lowercase();
                e_lower.contains("not") && inv_lower.contains(&e_lower.replace("not ", ""))
            })
            .count();

        let status = if matching_evidence.len() >= 3 && contradicting == 0 {
            ProofStatus::Proven
        } else if !matching_evidence.is_empty() && contradicting == 0 {
            ProofStatus::PartiallyProven
        } else if matching_evidence.is_empty() && contradicting == 0 {
            ProofStatus::Unsupported
        } else {
            ProofStatus::Assumed
        };

        match status {
            ProofStatus::Proven => proven += 1,
            ProofStatus::PartiallyProven => partial += 1,
            ProofStatus::Assumed => assumed += 1,
            ProofStatus::Unsupported => unsupported += 1,
        }

        coverage.push(InvariantCoverage {
            invariant: invariant.clone(),
            status,
            evidence_count: matching_evidence.len(),
            contradicting_count: contradicting,
            sources: matching_evidence,
        });
    }

    let total = invariants.len();
    let proof_coverage_rate = if total > 0 {
        proven as f64 / total as f64
    } else {
        0.0
    };

    ProofCoverageMetrics {
        total_invariants: total,
        proven_count: proven,
        partially_proven_count: partial,
        assumed_count: assumed,
        unsupported_count: unsupported,
        proof_coverage_rate,
        invariants: coverage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_proven() {
        let invariants = vec!["conservation".into(), "solvency".into()];
        let evidence = vec![
            "conservation".into(),
            "conservation".into(),
            "conservation".into(),
            "solvency".into(),
            "solvency".into(),
            "solvency".into(),
        ];
        let metrics = evaluate_proof_coverage(&invariants, &evidence);
        assert_eq!(metrics.proven_count, 2);
        assert_eq!(metrics.proof_coverage_rate, 1.0);
    }

    #[test]
    fn test_partial_coverage() {
        let invariants = vec!["conservation".into(), "solvency".into()];
        let evidence = vec!["conservation".into()];
        let metrics = evaluate_proof_coverage(&invariants, &evidence);
        assert!(metrics.partially_proven_count > 0);
    }
}
