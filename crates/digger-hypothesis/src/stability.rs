/// Reasoning Stability — compare outputs across small source-code changes.
use serde::{Deserialize, Serialize};

/// Stability report for a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StabilityReport {
    /// Total hypotheses analyzed.
    pub total_hypotheses: usize,
    /// Hypotheses that are stable (same output across changes).
    pub stable_count: usize,
    /// Hypotheses that are unstable (output changes).
    pub unstable_count: usize,
    /// Stability score (stable / total).
    pub stability_score: f64,
    /// Unstable hypotheses with details.
    pub unstable_details: Vec<UnstableHypothesis>,
}

/// A hypothesis that changes across source-code modifications.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnstableHypothesis {
    /// Hypothesis ID.
    pub hypothesis_id: String,
    /// What changed.
    pub change_description: String,
    /// Old value.
    pub old_value: String,
    /// New value.
    pub new_value: String,
    /// Sensitivity (high/medium/low).
    pub sensitivity: String,
}

/// Compare two sets of hypotheses for stability.
pub fn compare_stability(
    before: &[(String, String)], // (id, kind)
    after: &[(String, String)],
) -> StabilityReport {
    let before_map: std::collections::BTreeMap<String, String> = before
        .iter()
        .map(|(id, kind)| (id.clone(), kind.clone()))
        .collect();
    let after_map: std::collections::BTreeMap<String, String> = after
        .iter()
        .map(|(id, kind)| (id.clone(), kind.clone()))
        .collect();

    let mut stable = 0;
    let mut unstable_details = Vec::new();

    // Check hypotheses present in both
    for (id, before_kind) in &before_map {
        if let Some(after_kind) = after_map.get(id) {
            if before_kind == after_kind {
                stable += 1;
            } else {
                unstable_details.push(UnstableHypothesis {
                    hypothesis_id: id.clone(),
                    change_description: "Hypothesis kind changed".into(),
                    old_value: before_kind.clone(),
                    new_value: after_kind.clone(),
                    sensitivity: "high".into(),
                });
            }
        } else {
            // Hypothesis removed
            unstable_details.push(UnstableHypothesis {
                hypothesis_id: id.clone(),
                change_description: "Hypothesis removed".into(),
                old_value: before_kind.clone(),
                new_value: "removed".into(),
                sensitivity: "high".into(),
            });
        }
    }

    // Check for new hypotheses
    for (id, after_kind) in &after_map {
        if !before_map.contains_key(id) {
            unstable_details.push(UnstableHypothesis {
                hypothesis_id: id.clone(),
                change_description: "New hypothesis added".into(),
                old_value: "none".into(),
                new_value: after_kind.clone(),
                sensitivity: "medium".into(),
            });
        }
    }

    let total = before_map.len().max(after_map.len());
    let stability_score = if total > 0 {
        stable as f64 / total as f64
    } else {
        1.0
    };

    StabilityReport {
        total_hypotheses: total,
        stable_count: stable,
        unstable_count: unstable_details.len(),
        stability_score,
        unstable_details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_is_stable() {
        let h = vec![
            ("H1".into(), "Reentrancy".into()),
            ("H2".into(), "Authority".into()),
        ];
        let report = compare_stability(&h, &h);
        assert_eq!(report.stability_score, 1.0);
        assert_eq!(report.unstable_count, 0);
    }

    #[test]
    fn test_change_detected() {
        let before = vec![("H1".into(), "Reentrancy".into())];
        let after = vec![("H1".into(), "Authority".into())];
        let report = compare_stability(&before, &after);
        assert!(report.stability_score < 1.0);
        assert_eq!(report.unstable_count, 1);
    }
}
