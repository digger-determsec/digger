/// Minimal Evidence Analysis — determine smallest evidence set, identify redundancy.
use serde::{Deserialize, Serialize};

/// Minimal evidence set for a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MinimalEvidenceSet {
    /// Hypothesis ID.
    pub hypothesis_id: String,
    /// Required evidence (must have all of these).
    pub required: Vec<String>,
    /// Sufficient evidence (any one of these suffices).
    pub sufficient: Vec<Vec<String>>,
    /// Redundant evidence (removable without affecting conclusion).
    pub redundant: Vec<String>,
    /// Evidence dependency chain.
    pub dependency_chain: Vec<EvidenceDependency>,
    /// Total evidence items.
    pub total_evidence: usize,
    /// Minimal set size.
    pub minimal_set_size: usize,
    /// Redundancy ratio (redundant / total).
    pub redundancy_ratio: f64,
}

/// A dependency between evidence items.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceDependency {
    /// Dependent evidence.
    pub dependent: String,
    /// Evidence it depends on.
    pub depends_on: Vec<String>,
    /// Dependency type (supports, contradicts, refines).
    pub dependency_type: String,
}

/// Compute minimal evidence set for a hypothesis.
pub fn compute_minimal_set(
    hypothesis_id: &str,
    evidence: &[String],
    _edge_types: &[String],
) -> MinimalEvidenceSet {
    if evidence.is_empty() {
        return MinimalEvidenceSet {
            hypothesis_id: hypothesis_id.into(),
            required: vec![],
            sufficient: vec![],
            redundant: vec![],
            dependency_chain: vec![],
            total_evidence: 0,
            minimal_set_size: 0,
            redundancy_ratio: 0.0,
        };
    }

    // Classify evidence into required vs redundant
    let mut required = Vec::new();
    let mut redundant = Vec::new();

    // Core evidence types that are always required
    let core_types = ["authority", "state", "external", "call", "cpi"];

    for e in evidence {
        let e_lower = e.to_lowercase();
        let is_core = core_types.iter().any(|ct| e_lower.contains(ct));
        if is_core {
            required.push(e.clone());
        } else {
            redundant.push(e.clone());
        }
    }

    // If no core evidence found, all evidence is required
    if required.is_empty() {
        required = evidence.to_vec();
        redundant.clear();
    }

    // Build dependency chain
    let mut dependency_chain = Vec::new();
    for (i, e) in required.iter().enumerate() {
        let deps: Vec<String> = required
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .filter(|(_, other)| {
                let e_lower = e.to_lowercase();
                let o_lower = other.to_lowercase();
                // Evidence items that share keywords are dependent
                keyword_overlap(&e_lower, &o_lower)
            })
            .map(|(_, o)| o.clone())
            .collect();

        if !deps.is_empty() {
            dependency_chain.push(EvidenceDependency {
                dependent: e.clone(),
                depends_on: deps,
                dependency_type: "supports".into(),
            });
        }
    }

    let minimal_set_size = required.len();
    let redundancy_ratio = if !evidence.is_empty() {
        redundant.len() as f64 / evidence.len() as f64
    } else {
        0.0
    };

    MinimalEvidenceSet {
        hypothesis_id: hypothesis_id.into(),
        required,
        sufficient: vec![], // Simplified: no OR-groups
        redundant,
        dependency_chain,
        total_evidence: evidence.len(),
        minimal_set_size,
        redundancy_ratio,
    }
}

fn keyword_overlap(a: &str, b: &str) -> bool {
    let keywords = ["external", "call", "state", "write", "authority", "cpi"];
    for kw in &keywords {
        if a.contains(kw) && b.contains(kw) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_set() {
        let result = compute_minimal_set(
            "H1",
            &[
                "authority check".into(),
                "state write".into(),
                "extra info".into(),
            ],
            &["state_write".into()],
        );
        assert!(result.minimal_set_size > 0);
        assert!(result.redundancy_ratio > 0.0);
    }

    #[test]
    fn test_no_redundancy() {
        let result = compute_minimal_set(
            "H1",
            &["authority check".into(), "state write".into()],
            &["state_write".into()],
        );
        assert_eq!(result.redundant.len(), 0);
    }
}
