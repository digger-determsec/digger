/// Assumption Validation Framework.
///
/// Every hypothesis explicitly lists its assumptions.
/// Each assumption is validated against available evidence.
/// Unsupported assumptions are prevented from inflating confidence.
///
/// All validation is deterministic and explainable.
use serde::{Deserialize, Serialize};

/// Validation status for an assumption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationStatus {
    /// Assumption is proven by evidence.
    Proven,
    /// Assumption has no supporting evidence.
    Unsupported,
    /// Assumption is contradicted by evidence.
    Contradicted,
    /// Assumption cannot be determined from available evidence.
    Unknown,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proven => write!(f, "proven"),
            Self::Unsupported => write!(f, "unsupported"),
            Self::Contradicted => write!(f, "contradicted"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// An assumption underlying a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Assumption {
    /// Assumption identifier.
    pub id: String,
    /// Human-readable description of the assumption.
    pub description: String,
    /// Category of assumption.
    pub category: AssumptionCategory,
    /// Validation status.
    pub status: ValidationStatus,
    /// Evidence supporting or contradicting this assumption.
    pub supporting_evidence: Vec<String>,
    /// Evidence contradicting this assumption.
    pub contradicting_evidence: Vec<String>,
    /// Explanation of why this status was assigned.
    pub explanation: String,
}

/// Category of assumption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssumptionCategory {
    /// Assumption about authority/access control.
    Authority,
    /// Assumption about state consistency.
    StateConsistency,
    /// Assumption about external call behavior.
    ExternalCall,
    /// Assumption about trust boundaries.
    TrustBoundary,
    /// Assumption about economic invariants.
    Economic,
    /// Assumption about temporal ordering.
    Temporal,
    /// Assumption about account ownership.
    AccountOwnership,
    /// Assumption about program behavior.
    ProgramBehavior,
}

impl std::fmt::Display for AssumptionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authority => write!(f, "authority"),
            Self::StateConsistency => write!(f, "state_consistency"),
            Self::ExternalCall => write!(f, "external_call"),
            Self::TrustBoundary => write!(f, "trust_boundary"),
            Self::Economic => write!(f, "economic"),
            Self::Temporal => write!(f, "temporal"),
            Self::AccountOwnership => write!(f, "account_ownership"),
            Self::ProgramBehavior => write!(f, "program_behavior"),
        }
    }
}

/// Result of validating a set of assumptions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ValidationResult {
    /// All assumptions with their validation status.
    pub assumptions: Vec<Assumption>,
    /// Count by status.
    pub proven_count: usize,
    pub unsupported_count: usize,
    pub contradicted_count: usize,
    pub unknown_count: usize,
    /// Adjusted confidence after assumption validation.
    /// Unsupported assumptions reduce confidence.
    /// Contradicted assumptions reduce confidence more.
    pub adjusted_confidence: f64,
    /// Explanation of the confidence adjustment.
    pub adjustment_explanation: String,
}

/// Validate assumptions for a hypothesis.
///
/// Takes the hypothesis's assumptions and available evidence,
/// then determines the validation status of each assumption.
///
/// Deterministic: same inputs → same validation result.
pub fn validate_assumptions(
    assumptions: Vec<AssumptionInput>,
    available_evidence: &[String],
    base_confidence: f64,
) -> ValidationResult {
    let mut validated = Vec::new();
    let mut proven = 0;
    let mut unsupported = 0;
    let mut contradicted = 0;
    let mut unknown = 0;

    for input in assumptions {
        let validation = validate_single_assumption(&input, available_evidence);
        match validation.status {
            ValidationStatus::Proven => proven += 1,
            ValidationStatus::Unsupported => unsupported += 1,
            ValidationStatus::Contradicted => contradicted += 1,
            ValidationStatus::Unknown => unknown += 1,
        }
        validated.push(validation);
    }

    // Compute adjusted confidence
    let total = validated.len().max(1) as f64;
    let proven_ratio = proven as f64 / total;
    let contradicted_ratio = contradicted as f64 / total;
    let unsupported_ratio = unsupported as f64 / total;

    // Proven assumptions increase confidence (up to 1.2x)
    // Contradicted assumptions decrease confidence (multiply by 0.5)
    // Unsupported assumptions decrease confidence slightly (multiply by 0.8)
    let adjustment =
        1.0 + (proven_ratio * 0.2) - (contradicted_ratio * 0.5) - (unsupported_ratio * 0.2);
    let adjusted_confidence = (base_confidence * adjustment).clamp(0.0, 1.0);

    let adjustment_explanation = if contradicted > 0 {
        format!(
            "Confidence reduced from {:.2} to {:.2}: {} contradicted, {} unsupported, {} proven assumptions",
            base_confidence, adjusted_confidence, contradicted, unsupported, proven
        )
    } else if unsupported > 0 {
        format!(
            "Confidence reduced from {:.2} to {:.2}: {} unsupported assumptions lack evidence",
            base_confidence, adjusted_confidence, unsupported
        )
    } else if proven > 0 {
        format!(
            "Confidence increased from {:.2} to {:.2}: {} assumptions confirmed by evidence",
            base_confidence, adjusted_confidence, proven
        )
    } else {
        format!(
            "Confidence unchanged at {:.2}: all assumptions unknown",
            base_confidence
        )
    };

    ValidationResult {
        assumptions: validated,
        proven_count: proven,
        unsupported_count: unsupported,
        contradicted_count: contradicted,
        unknown_count: unknown,
        adjusted_confidence,
        adjustment_explanation,
    }
}

/// Input for a single assumption to validate.
#[derive(Debug, Clone)]
pub struct AssumptionInput {
    /// Assumption description.
    pub description: String,
    /// Category.
    pub category: AssumptionCategory,
    /// Keywords that would indicate this assumption is supported.
    pub supporting_keywords: Vec<String>,
    /// Keywords that would indicate this assumption is contradicted.
    pub contradicting_keywords: Vec<String>,
}

fn validate_single_assumption(
    input: &AssumptionInput,
    available_evidence: &[String],
) -> Assumption {
    let mut supporting = Vec::new();
    let mut contradicting = Vec::new();

    for evidence in available_evidence {
        let evidence_lower = evidence.to_lowercase();

        // Check for supporting evidence
        for keyword in &input.supporting_keywords {
            if evidence_lower.contains(&keyword.to_lowercase()) {
                supporting.push(evidence.clone());
                break;
            }
        }

        // Check for contradicting evidence
        for keyword in &input.contradicting_keywords {
            if evidence_lower.contains(&keyword.to_lowercase()) {
                contradicting.push(evidence.clone());
                break;
            }
        }
    }

    let (status, explanation) = if !contradicting.is_empty() {
        (
            ValidationStatus::Contradicted,
            format!(
                "Assumption contradicted by {} evidence item(s): {}",
                contradicting.len(),
                contradicting.first().unwrap_or(&"unknown".into())
            ),
        )
    } else if !supporting.is_empty() {
        (
            ValidationStatus::Proven,
            format!(
                "Assumption supported by {} evidence item(s)",
                supporting.len()
            ),
        )
    } else if input.supporting_keywords.is_empty() && input.contradicting_keywords.is_empty() {
        (
            ValidationStatus::Unknown,
            "No keywords defined for validation — cannot determine status".into(),
        )
    } else {
        (
            ValidationStatus::Unsupported,
            "No supporting evidence found for this assumption".into(),
        )
    };

    Assumption {
        id: format!("ASSUMPTION-{}", input.description.len()),
        description: input.description.clone(),
        category: input.category.clone(),
        status,
        supporting_evidence: supporting,
        contradicting_evidence: contradicting,
        explanation,
    }
}

/// Extract common assumptions from a hypothesis kind and evidence.
///
/// This provides a default set of assumptions for each hypothesis type.
pub fn extract_assumptions(hypothesis_kind: &str, evidence: &[String]) -> Vec<AssumptionInput> {
    let mut assumptions = Vec::new();

    match hypothesis_kind {
        k if k.contains("Reentrancy") || k.contains("reentrancy") => {
            assumptions.push(AssumptionInput {
                description: "External call triggers callback to calling contract".into(),
                category: AssumptionCategory::ExternalCall,
                supporting_keywords: vec!["external_call".into(), "callback".into()],
                contradicting_keywords: vec!["no_callback".into(), "staticcall".into()],
            });
            assumptions.push(AssumptionInput {
                description: "State is not updated before external call completes".into(),
                category: AssumptionCategory::StateConsistency,
                supporting_keywords: vec!["state_write".into(), "before".into()],
                contradicting_keywords: vec![
                    "state_updated_before".into(),
                    "checks_effects".into(),
                ],
            });
            assumptions.push(AssumptionInput {
                description: "No reentrancy guard is present".into(),
                category: AssumptionCategory::Authority,
                supporting_keywords: vec!["no_guard".into(), "no_mutex".into()],
                contradicting_keywords: vec![
                    "reentrancy_guard".into(),
                    "nonReentrant".into(),
                    "mutex".into(),
                ],
            });
        }
        k if k.contains("Authority") || k.contains("authority") || k.contains("access") => {
            assumptions.push(AssumptionInput {
                description: "Function is publicly accessible".into(),
                category: AssumptionCategory::Authority,
                supporting_keywords: vec!["public".into(), "external".into()],
                contradicting_keywords: vec!["private".into(), "internal".into()],
            });
            assumptions.push(AssumptionInput {
                description: "No access control mechanism is enforced".into(),
                category: AssumptionCategory::Authority,
                supporting_keywords: vec!["no_authority".into(), "missing".into()],
                contradicting_keywords: vec![
                    "require".into(),
                    "onlyOwner".into(),
                    "signer".into(),
                    "has_one".into(),
                ],
            });
        }
        k if k.contains("CPI") || k.contains("cpi") => {
            assumptions.push(AssumptionInput {
                description: "CPI target is trusted".into(),
                category: AssumptionCategory::TrustBoundary,
                supporting_keywords: vec!["trusted".into(), "known_program".into()],
                contradicting_keywords: vec![
                    "unknown".into(),
                    "untrusted".into(),
                    "dynamic".into(),
                ],
            });
            assumptions.push(AssumptionInput {
                description: "CPI call does not escalate privileges".into(),
                category: AssumptionCategory::Authority,
                supporting_keywords: vec!["no_privilege".into(), "safe".into()],
                contradicting_keywords: vec![
                    "privilege".into(),
                    "escalation".into(),
                    "no_authority".into(),
                ],
            });
        }
        k if k.contains("State") || k.contains("state") || k.contains("Corruption") => {
            assumptions.push(AssumptionInput {
                description: "State writes are properly authorized".into(),
                category: AssumptionCategory::StateConsistency,
                supporting_keywords: vec!["authorized".into(), "authority".into()],
                contradicting_keywords: vec!["unauthorized".into(), "no_authority".into()],
            });
            assumptions.push(AssumptionInput {
                description: "State transitions maintain consistency".into(),
                category: AssumptionCategory::StateConsistency,
                supporting_keywords: vec!["consistent".into(), "invariant".into()],
                contradicting_keywords: vec!["inconsistent".into(), "corruption".into()],
            });
        }
        _ => {
            // Generic assumptions for unknown types
            assumptions.push(AssumptionInput {
                description: "Code behaves as intended".into(),
                category: AssumptionCategory::ProgramBehavior,
                supporting_keywords: vec![],
                contradicting_keywords: vec![],
            });
        }
    }

    // Add evidence-specific assumptions
    for e in evidence {
        let lower = e.to_lowercase();
        if lower.contains("external") || lower.contains("call") {
            assumptions.push(AssumptionInput {
                description: format!("External call behavior matches expectation: {}", e),
                category: AssumptionCategory::ExternalCall,
                supporting_keywords: vec!["expected".into(), "safe".into()],
                contradicting_keywords: vec!["unexpected".into(), "unsafe".into()],
            });
        }
    }

    assumptions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proven_assumption() {
        let assumptions = vec![AssumptionInput {
            description: "Function is public".into(),
            category: AssumptionCategory::Authority,
            supporting_keywords: vec!["public".into()],
            contradicting_keywords: vec!["private".into()],
        }];
        let evidence = vec!["Public function with no access control".into()];

        let result = validate_assumptions(assumptions, &evidence, 0.8);
        assert_eq!(result.proven_count, 1);
        assert!(result.adjusted_confidence >= 0.8);
    }

    #[test]
    fn test_contradicted_assumption_reduces_confidence() {
        let assumptions = vec![AssumptionInput {
            description: "No reentrancy guard".into(),
            category: AssumptionCategory::Authority,
            supporting_keywords: vec!["no_guard".into()],
            contradicting_keywords: vec!["nonReentrant".into()],
        }];
        let evidence = vec!["Function uses nonReentrant modifier".into()];

        let result = validate_assumptions(assumptions, &evidence, 0.8);
        assert_eq!(result.contradicted_count, 1);
        assert!(result.adjusted_confidence < 0.8);
    }

    #[test]
    fn test_unsupported_assumption_reduces_confidence() {
        let assumptions = vec![AssumptionInput {
            description: "External call triggers callback".into(),
            category: AssumptionCategory::ExternalCall,
            supporting_keywords: vec!["callback".into()],
            contradicting_keywords: vec![],
        }];
        let evidence: Vec<String> = vec![];

        let result = validate_assumptions(assumptions, &evidence, 0.8);
        assert_eq!(result.unsupported_count, 1);
        assert!(result.adjusted_confidence < 0.8);
    }

    #[test]
    fn test_deterministic_validation() {
        let assumptions = vec![AssumptionInput {
            description: "Test".into(),
            category: AssumptionCategory::Authority,
            supporting_keywords: vec!["yes".into()],
            contradicting_keywords: vec!["no".into()],
        }];
        let evidence = vec!["yes".into()];

        let r1 = validate_assumptions(assumptions.clone(), &evidence, 0.5);
        let r2 = validate_assumptions(assumptions, &evidence, 0.5);

        assert_eq!(r1.adjusted_confidence, r2.adjusted_confidence);
        assert_eq!(r1.proven_count, r2.proven_count);
    }
}
