/// Counterfactual Reasoning.
///
/// Tests whether removing a condition would invalidate an exploit.
/// Distinguishes causal factors from correlated observations.
/// Uses counterfactuals to improve confidence and reduce false positives.
///
/// All reasoning is deterministic and evidence-backed.
use serde::{Deserialize, Serialize};

/// A counterfactual test.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CounterfactualTest {
    /// Test identifier.
    pub id: String,
    /// The condition being removed.
    pub removed_condition: String,
    /// Category of the condition.
    pub condition_category: String,
    /// Original hypothesis validity.
    pub original_valid: bool,
    /// Hypothesis validity after removing the condition.
    pub counterfactual_valid: bool,
    /// Whether removing this condition invalidates the exploit.
    pub invalidates_exploit: bool,
    /// Confidence change.
    pub confidence_delta: f64,
    /// Explanation of the counterfactual.
    pub explanation: String,
}

/// Result of counterfactual analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CounterfactualResult {
    /// All counterfactual tests run.
    pub tests: Vec<CounterfactualTest>,
    /// Causal factors (removing these invalidates the exploit).
    pub causal_factors: Vec<String>,
    /// Correlated observations (removing these doesn't affect the exploit).
    pub correlated_observations: Vec<String>,
    /// Adjusted confidence after counterfactual analysis.
    pub adjusted_confidence: f64,
    /// Explanation of the analysis.
    pub explanation: String,
}

/// Run counterfactual analysis on a hypothesis.
///
/// For each condition in the hypothesis, tests whether removing it
/// would invalidate the exploit pattern.
///
/// Deterministic: same inputs → same counterfactuals.
#[allow(clippy::too_many_arguments)]
pub fn analyze_counterfactuals(
    hypothesis_kind: &str,
    evidence: &[String],
    _edge_types: &[String],
    has_external_call: bool,
    has_cpi: bool,
    state_mutated: bool,
    authority_enforced: bool,
    base_confidence: f64,
) -> CounterfactualResult {
    let mut tests = Vec::new();
    let mut causal_factors = Vec::new();
    let mut correlated = Vec::new();

    // Test 1: Remove external call
    if has_external_call {
        let test = test_condition_removal(
            "external_call",
            "External call removed",
            hypothesis_kind,
            evidence,
            has_external_call,
            has_cpi,
            state_mutated,
            authority_enforced,
            base_confidence,
        );
        if test.invalidates_exploit {
            causal_factors.push("external_call".into());
        } else {
            correlated.push("external_call".into());
        }
        tests.push(test);
    }

    // Test 2: Remove CPI
    if has_cpi {
        let test = test_condition_removal(
            "cpi",
            "CPI call removed",
            hypothesis_kind,
            evidence,
            has_external_call,
            has_cpi,
            state_mutated,
            authority_enforced,
            base_confidence,
        );
        if test.invalidates_exploit {
            causal_factors.push("cpi".into());
        } else {
            correlated.push("cpi".into());
        }
        tests.push(test);
    }

    // Test 3: Remove state mutation
    if state_mutated {
        let test = test_condition_removal(
            "state_mutation",
            "State mutation removed",
            hypothesis_kind,
            evidence,
            has_external_call,
            has_cpi,
            state_mutated,
            authority_enforced,
            base_confidence,
        );
        if test.invalidates_exploit {
            causal_factors.push("state_mutation".into());
        } else {
            correlated.push("state_mutation".into());
        }
        tests.push(test);
    }

    // Test 4: Add authority enforcement
    if !authority_enforced {
        let test = test_condition_addition(
            "authority",
            "Authority enforcement added",
            hypothesis_kind,
            evidence,
            has_external_call,
            has_cpi,
            state_mutated,
            authority_enforced,
            base_confidence,
        );
        if test.invalidates_exploit {
            causal_factors.push("authority_enforcement".into());
        } else {
            correlated.push("authority_enforcement".into());
        }
        tests.push(test);
    }

    // Test 5: Remove evidence items (one at a time)
    for (i, evidence_item) in evidence.iter().enumerate() {
        let remaining: Vec<String> = evidence
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, e)| e.clone())
            .collect();

        let still_valid = !remaining.is_empty() && has_pattern_support(hypothesis_kind, &remaining);
        let invalidates = !still_valid && evidence.len() > 1;

        let confidence_delta = if invalidates {
            -0.2
        } else if remaining.len() < evidence.len() {
            -0.05
        } else {
            0.0
        };

        tests.push(CounterfactualTest {
            id: format!("CF-EVIDENCE-{}", i),
            removed_condition: evidence_item.clone(),
            condition_category: "evidence".into(),
            original_valid: true,
            counterfactual_valid: still_valid,
            invalidates_exploit: invalidates,
            confidence_delta,
            explanation: format!(
                "Removing evidence '{}' {} the exploit pattern",
                evidence_item,
                if invalidates {
                    "invalidates"
                } else {
                    "does not invalidate"
                }
            ),
        });

        if invalidates {
            causal_factors.push(evidence_item.clone());
        } else {
            correlated.push(evidence_item.clone());
        }
    }

    // Compute adjusted confidence
    let causal_count = causal_factors.len() as f64;
    let total_tests = tests.len() as f64;
    let causal_ratio = if total_tests > 0.0 {
        causal_count / total_tests
    } else {
        0.0
    };

    // More causal factors = more confident (the exploit depends on real conditions)
    // Fewer causal factors = less confident (exploit may be coincidental)
    let adjustment = if causal_ratio > 0.5 {
        0.1 // Many causal factors = higher confidence
    } else if causal_ratio > 0.2 {
        0.0 // Moderate causal factors = no change
    } else {
        -0.1 // Few causal factors = lower confidence
    };

    let adjusted_confidence = (base_confidence + adjustment).clamp(0.0, 1.0);

    let explanation = format!(
        "Counterfactual analysis: {} causal factors, {} correlated observations. \
         Confidence adjusted from {:.2} to {:.2}.",
        causal_factors.len(),
        correlated.len(),
        base_confidence,
        adjusted_confidence
    );

    CounterfactualResult {
        tests,
        causal_factors,
        correlated_observations: correlated,
        adjusted_confidence,
        explanation,
    }
}

/// Test removing a specific condition.
#[allow(clippy::too_many_arguments)]
fn test_condition_removal(
    condition: &str,
    description: &str,
    hypothesis_kind: &str,
    _evidence: &[String],
    has_external_call: bool,
    has_cpi: bool,
    state_mutated: bool,
    authority_enforced: bool,
    _base_confidence: f64,
) -> CounterfactualTest {
    // Simulate removing the condition
    let (new_external, new_cpi, new_state, new_auth) = match condition {
        "external_call" => (false, has_cpi, state_mutated, authority_enforced),
        "cpi" => (has_external_call, false, state_mutated, authority_enforced),
        "state_mutation" => (has_external_call, has_cpi, false, authority_enforced),
        _ => (
            has_external_call,
            has_cpi,
            state_mutated,
            authority_enforced,
        ),
    };

    let still_valid =
        check_pattern_validity(hypothesis_kind, new_external, new_cpi, new_state, new_auth);
    let invalidates = !still_valid;

    let confidence_delta = if invalidates { -0.3 } else { 0.0 };

    CounterfactualTest {
        id: format!("CF-REMOVE-{}", condition.to_uppercase()),
        removed_condition: description.into(),
        condition_category: condition.into(),
        original_valid: true,
        counterfactual_valid: still_valid,
        invalidates_exploit: invalidates,
        confidence_delta,
        explanation: format!(
            "Removing '{}' {} the exploit pattern",
            condition,
            if invalidates {
                "invalidates"
            } else {
                "does not invalidate"
            }
        ),
    }
}

/// Test adding a condition (authority enforcement).
#[allow(clippy::too_many_arguments)]
fn test_condition_addition(
    condition: &str,
    description: &str,
    hypothesis_kind: &str,
    _evidence: &[String],
    has_external_call: bool,
    has_cpi: bool,
    state_mutated: bool,
    _authority_enforced: bool,
    _base_confidence: f64,
) -> CounterfactualTest {
    // Simulate adding authority enforcement
    let still_valid = check_pattern_validity(
        hypothesis_kind,
        has_external_call,
        has_cpi,
        state_mutated,
        true,
    );
    let invalidates = !still_valid;

    let confidence_delta = if invalidates { -0.3 } else { -0.1 };

    CounterfactualTest {
        id: format!("CF-ADD-{}", condition.to_uppercase()),
        removed_condition: description.into(),
        condition_category: condition.into(),
        original_valid: true,
        counterfactual_valid: still_valid,
        invalidates_exploit: invalidates,
        confidence_delta,
        explanation: format!(
            "Adding '{}' {} the exploit pattern",
            condition,
            if invalidates {
                "invalidates"
            } else {
                "does not invalidate"
            }
        ),
    }
}

/// Check if a vulnerability pattern is still valid given conditions.
fn check_pattern_validity(
    kind: &str,
    has_external: bool,
    has_cpi: bool,
    state_mutated: bool,
    authority_enforced: bool,
) -> bool {
    match kind {
        k if k.contains("Reentrancy") => has_external && state_mutated,
        k if k.contains("Authority") || k.contains("Missing") => {
            state_mutated && !authority_enforced
        }
        k if k.contains("CPI") => has_cpi,
        k if k.contains("State") => state_mutated,
        _ => true, // Unknown pattern — assume still valid
    }
}

/// Check if evidence supports a pattern.
fn has_pattern_support(kind: &str, evidence: &[String]) -> bool {
    let combined = evidence.join(" ").to_lowercase();
    match kind {
        k if k.contains("Reentrancy") => combined.contains("external") || combined.contains("call"),
        k if k.contains("Authority") || k.contains("Missing") => {
            combined.contains("authority") || combined.contains("access")
        }
        k if k.contains("CPI") => combined.contains("cpi") || combined.contains("cross-program"),
        k if k.contains("State") => combined.contains("state") || combined.contains("mutation"),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counterfactual_deterministic() {
        let r1 = analyze_counterfactuals(
            "ReentrancyCandidate",
            &[
                "External call detected".into(),
                "State mutation detected".into(),
            ],
            &["external_call".into(), "state_write".into()],
            true,
            false,
            true,
            false,
            0.75,
        );
        let r2 = analyze_counterfactuals(
            "ReentrancyCandidate",
            &[
                "External call detected".into(),
                "State mutation detected".into(),
            ],
            &["external_call".into(), "state_write".into()],
            true,
            false,
            true,
            false,
            0.75,
        );

        assert_eq!(r1.tests.len(), r2.tests.len());
        assert_eq!(r1.causal_factors.len(), r2.causal_factors.len());
    }

    #[test]
    fn test_reentrancy_requires_external_call() {
        let result = analyze_counterfactuals(
            "ReentrancyCandidate",
            &["External call".into()],
            &["external_call".into()],
            true,
            false,
            true,
            false,
            0.75,
        );

        // Removing external call should invalidate reentrancy
        assert!(result.causal_factors.contains(&"external_call".into()));
    }

    #[test]
    fn test_authority_enforcement_invalidates() {
        let result = analyze_counterfactuals(
            "MissingAuthorityCheck",
            &["No authority".into()],
            &["state_write".into()],
            false,
            false,
            true,
            false,
            0.75,
        );

        // Adding authority should invalidate missing authority pattern
        assert!(result
            .causal_factors
            .contains(&"authority_enforcement".into()));
    }
}
