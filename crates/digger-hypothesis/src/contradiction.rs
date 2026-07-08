/// Contradiction Detection System.
///
/// Detects conflicting evidence inside reasoning chains.
/// Reduces confidence when evidence conflicts.
/// Surfaces contradictions in explanations.
///
/// All detection is deterministic and explainable.
use serde::{Deserialize, Serialize};

/// A detected contradiction between evidence items.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contradiction {
    /// Contradiction identifier.
    pub id: String,
    /// Type of contradiction.
    pub kind: ContradictionKind,
    /// First evidence item.
    pub evidence_a: String,
    /// Second evidence item.
    pub evidence_b: String,
    /// Severity of the contradiction.
    pub severity: ContradictionSeverity,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Type of contradiction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContradictionKind {
    /// Evidence A says X is safe, evidence B says X is unsafe.
    SafetyConflict,
    /// Evidence A says function has authority, evidence B says it doesn't.
    AuthorityConflict,
    /// Evidence A says state is consistent, evidence B says it's inconsistent.
    StateConflict,
    /// Evidence A says external call exists, evidence B says it doesn't.
    ExternalCallConflict,
    /// Evidence A says trust boundary is crossed, evidence B says it isn't.
    TrustBoundaryConflict,
    /// Generic contradiction between two claims.
    Generic,
}

impl std::fmt::Display for ContradictionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SafetyConflict => write!(f, "safety_conflict"),
            Self::AuthorityConflict => write!(f, "authority_conflict"),
            Self::StateConflict => write!(f, "state_conflict"),
            Self::ExternalCallConflict => write!(f, "external_call_conflict"),
            Self::TrustBoundaryConflict => write!(f, "trust_boundary_conflict"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

/// Severity of a contradiction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContradictionSeverity {
    /// High severity — directly impacts hypothesis validity.
    High,
    /// Medium severity — may affect confidence.
    Medium,
    /// Low severity — minor inconsistency.
    Low,
}

/// Result of contradiction detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContradictionResult {
    /// All detected contradictions.
    pub contradictions: Vec<Contradiction>,
    /// Total count.
    pub total_count: usize,
    /// Count by severity.
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    /// Confidence adjustment factor (0.0–1.0).
    /// 1.0 = no contradictions, lower = more contradictions.
    pub confidence_factor: f64,
    /// Explanation of the adjustment.
    pub explanation: String,
}

/// Detect contradictions in a set of evidence strings.
///
/// Checks for opposing claims about:
/// - Safety (safe vs unsafe)
/// - Authority (has vs lacks)
/// - State (consistent vs inconsistent)
/// - External calls (present vs absent)
/// - Trust boundaries (crossed vs not crossed)
///
/// Deterministic: same inputs → same contradictions.
pub fn detect_contradictions(evidence: &[String]) -> ContradictionResult {
    let mut contradictions = Vec::new();

    // Check all pairs of evidence for contradictions
    for i in 0..evidence.len() {
        for j in (i + 1)..evidence.len() {
            if let Some(c) = check_pair(&evidence[i], &evidence[j], i, j) {
                contradictions.push(c);
            }
        }
    }

    let high_count = contradictions
        .iter()
        .filter(|c| c.severity == ContradictionSeverity::High)
        .count();
    let medium_count = contradictions
        .iter()
        .filter(|c| c.severity == ContradictionSeverity::Medium)
        .count();
    let low_count = contradictions
        .iter()
        .filter(|c| c.severity == ContradictionSeverity::Low)
        .count();

    // Confidence factor: each contradiction reduces confidence
    let total = contradictions.len() as f64;
    let confidence_factor = if total == 0.0 {
        1.0
    } else {
        // High severity: 0.7 reduction each
        // Medium: 0.85 reduction each
        // Low: 0.95 reduction each
        let high_factor = 0.7_f64.powi(high_count as i32);
        let medium_factor = 0.85_f64.powi(medium_count as i32);
        let low_factor = 0.95_f64.powi(low_count as i32);
        high_factor * medium_factor * low_factor
    };

    let explanation = if contradictions.is_empty() {
        "No contradictions detected in evidence".into()
    } else {
        format!(
            "Detected {} contradiction(s): {} high, {} medium, {} low severity. Confidence factor: {:.3}",
            total, high_count, medium_count, low_count, confidence_factor
        )
    };

    ContradictionResult {
        contradictions,
        total_count: high_count + medium_count + low_count,
        high_count,
        medium_count,
        low_count,
        confidence_factor,
        explanation,
    }
}

/// Check a pair of evidence strings for contradictions.
fn check_pair(a: &str, b: &str, idx_a: usize, idx_b: usize) -> Option<Contradiction> {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();

    // Safety conflict: "safe" vs "unsafe" or "vulnerable"
    if contains_opposite(
        &a_lower,
        &b_lower,
        &["safe", "no risk", "protected"],
        &["unsafe", "vulnerable", "risky", "dangerous"],
    ) {
        return Some(Contradiction {
            id: format!("CONTRADICTION-{}", idx_a * 1000 + idx_b),
            kind: ContradictionKind::SafetyConflict,
            evidence_a: a.to_string(),
            evidence_b: b.to_string(),
            severity: ContradictionSeverity::High,
            explanation: format!("Evidence conflicts on safety: '{}' vs '{}'", a, b),
        });
    }

    // Authority conflict: "has authority" vs "no authority"
    if contains_opposite(
        &a_lower,
        &b_lower,
        &["has authority", "enforced", "authorized", "signer"],
        &[
            "no authority",
            "missing",
            "unauthorized",
            "without authority",
        ],
    ) {
        return Some(Contradiction {
            id: format!("CONTRADICTION-{}", idx_a * 1000 + idx_b),
            kind: ContradictionKind::AuthorityConflict,
            evidence_a: a.to_string(),
            evidence_b: b.to_string(),
            severity: ContradictionSeverity::High,
            explanation: format!("Evidence conflicts on authority: '{}' vs '{}'", a, b),
        });
    }

    // State conflict: "consistent" vs "inconsistent"
    if contains_opposite(
        &a_lower,
        &b_lower,
        &["consistent", "invariant maintained", "state ok"],
        &["inconsistent", "invariant violated", "state corruption"],
    ) {
        return Some(Contradiction {
            id: format!("CONTRADICTION-{}", idx_a * 1000 + idx_b),
            kind: ContradictionKind::StateConflict,
            evidence_a: a.to_string(),
            evidence_b: b.to_string(),
            severity: ContradictionSeverity::High,
            explanation: format!(
                "Evidence conflicts on state consistency: '{}' vs '{}'",
                a, b
            ),
        });
    }

    // External call conflict: "has external call" vs "no external call"
    if contains_opposite(
        &a_lower,
        &b_lower,
        &["has external", "external call present", "makes external"],
        &["no external", "external call absent", "without external"],
    ) {
        return Some(Contradiction {
            id: format!("CONTRADICTION-{}", idx_a * 1000 + idx_b),
            kind: ContradictionKind::ExternalCallConflict,
            evidence_a: a.to_string(),
            evidence_b: b.to_string(),
            severity: ContradictionSeverity::Medium,
            explanation: format!("Evidence conflicts on external calls: '{}' vs '{}'", a, b),
        });
    }

    // Trust boundary conflict: "trust boundary crossed" vs "not crossed"
    if contains_opposite(
        &a_lower,
        &b_lower,
        &[
            "trust boundary crossed",
            "crosses trust",
            "trust delegation",
        ],
        &["trust boundary not", "no trust boundary", "within trust"],
    ) {
        return Some(Contradiction {
            id: format!("CONTRADICTION-{}", idx_a * 1000 + idx_b),
            kind: ContradictionKind::TrustBoundaryConflict,
            evidence_a: a.to_string(),
            evidence_b: b.to_string(),
            severity: ContradictionSeverity::Medium,
            explanation: format!("Evidence conflicts on trust boundaries: '{}' vs '{}'", a, b),
        });
    }

    None
}

/// Check if two strings contain opposite concepts.
fn contains_opposite(a: &str, b: &str, positive: &[&str], negative: &[&str]) -> bool {
    let a_has_positive = positive.iter().any(|p| a.contains(p));
    let a_has_negative = negative.iter().any(|n| a.contains(n));
    let b_has_positive = positive.iter().any(|p| b.contains(p));
    let b_has_negative = negative.iter().any(|n| b.contains(n));

    // One has positive, other has negative
    (a_has_positive && b_has_negative) || (a_has_negative && b_has_positive)
}

/// Detect contradictions between two hypotheses.
///
/// Two hypotheses contradict if they make opposing claims about
/// the same function's safety or authority.
pub fn detect_hypothesis_contradictions(
    kind_a: &str,
    function_a: &str,
    evidence_a: &[String],
    kind_b: &str,
    function_b: &str,
    evidence_b: &[String],
) -> Option<Contradiction> {
    // Same function but different safety conclusions
    if function_a == function_b && kind_a != kind_b {
        let a_safe = kind_a.contains("Safe") || kind_a.contains("safe");
        let b_safe = kind_b.contains("Safe") || kind_b.contains("safe");
        let a_unsafe = kind_a.contains("Risk")
            || kind_a.contains("Vulnerability")
            || kind_a.contains("Missing");
        let b_unsafe = kind_b.contains("Risk")
            || kind_b.contains("Vulnerability")
            || kind_b.contains("Missing");

        if (a_safe && b_unsafe) || (a_unsafe && b_safe) {
            return Some(Contradiction {
                id: format!("HYP-CONTRADICTION-{}-{}", function_a, function_b),
                kind: ContradictionKind::SafetyConflict,
                evidence_a: format!(
                    "{}: {}",
                    kind_a,
                    evidence_a.first().unwrap_or(&"no evidence".into())
                ),
                evidence_b: format!(
                    "{}: {}",
                    kind_b,
                    evidence_b.first().unwrap_or(&"no evidence".into())
                ),
                severity: ContradictionSeverity::High,
                explanation: format!(
                    "Hypotheses about '{}' contradict: '{}' says safe, '{}' says unsafe",
                    function_a, kind_a, kind_b
                ),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_contradictions() {
        let evidence = vec![
            "Function has external call".into(),
            "Function writes to state".into(),
            "No authority check detected".into(),
        ];
        let result = detect_contradictions(&evidence);
        assert_eq!(result.total_count, 0);
        assert_eq!(result.confidence_factor, 1.0);
    }

    #[test]
    fn test_safety_contradiction() {
        let evidence = vec![
            "Function is safe against reentrancy".into(),
            "Function has unsafe reentrancy pattern".into(),
        ];
        let result = detect_contradictions(&evidence);
        assert_eq!(result.total_count, 1);
        assert!(result.confidence_factor < 1.0);
    }

    #[test]
    fn test_authority_contradiction() {
        let evidence = vec![
            "Function has enforced authority check".into(),
            "Function has no authority check — missing access control".into(),
        ];
        let result = detect_contradictions(&evidence);
        assert_eq!(result.total_count, 1);
    }

    #[test]
    fn test_multiple_contradictions() {
        let evidence = vec![
            "Function is safe".into(),
            "Function is vulnerable to reentrancy".into(),
            "Function has authority enforcement".into(),
            "Function lacks authority — unauthorized access possible".into(),
        ];
        let result = detect_contradictions(&evidence);
        assert!(result.total_count >= 2);
        assert!(result.confidence_factor < 0.8);
    }

    #[test]
    fn test_deterministic() {
        let evidence = vec!["safe".into(), "unsafe".into()];
        let r1 = detect_contradictions(&evidence);
        let r2 = detect_contradictions(&evidence);
        assert_eq!(r1.total_count, r2.total_count);
        assert_eq!(r1.confidence_factor, r2.confidence_factor);
    }
}
