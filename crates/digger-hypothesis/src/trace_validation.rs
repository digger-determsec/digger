/// Reasoning Trace Validation — verify every inference step is supported by evidence.
use serde::{Deserialize, Serialize};

/// A validation report for reasoning traces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceValidationReport {
    /// Total steps validated.
    pub total_steps: usize,
    /// Steps with evidence support.
    pub supported_steps: usize,
    /// Steps without evidence support.
    pub unsupported_steps: usize,
    /// Support rate (supported / total).
    pub support_rate: f64,
    /// Unsupported steps with details.
    pub unsupported_details: Vec<UnsupportedStep>,
}

/// A step that lacks evidence support.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnsupportedStep {
    /// Step description.
    pub step: String,
    /// What evidence is missing.
    pub missing_evidence: String,
    /// Severity (high/medium/low).
    pub severity: String,
}

/// Validate a reasoning trace against available evidence.
pub fn validate_trace(trace_steps: &[String], evidence: &[String]) -> TraceValidationReport {
    let total = trace_steps.len();
    let mut supported = 0;
    let mut unsupported_details = Vec::new();

    for step in trace_steps {
        let step_lower = step.to_lowercase();
        let has_support = evidence.iter().any(|e| {
            let e_lower = e.to_lowercase();
            // Check if any evidence keyword appears in the step
            step_lower.contains(&e_lower)
                || e_lower.contains(&step_lower)
                // Check for semantic overlap
                || keyword_overlap(&step_lower, &e_lower)
        });

        if has_support {
            supported += 1;
        } else {
            unsupported_details.push(UnsupportedStep {
                step: step.clone(),
                missing_evidence: "No matching evidence found in evidence chain".into(),
                severity: if step_lower.contains("critical") || step_lower.contains("must") {
                    "high"
                } else {
                    "medium"
                }
                .into(),
            });
        }
    }

    let unsupported = total - supported;
    let support_rate = if total > 0 {
        supported as f64 / total as f64
    } else {
        1.0
    };

    TraceValidationReport {
        total_steps: total,
        supported_steps: supported,
        unsupported_steps: unsupported,
        support_rate,
        unsupported_details,
    }
}

/// Check for semantic keyword overlap between two strings.
fn keyword_overlap(a: &str, b: &str) -> bool {
    let keywords = [
        "external",
        "call",
        "state",
        "write",
        "authority",
        "signer",
        "reentrancy",
        "cpi",
        "trust",
        "boundary",
        "invariant",
        "violation",
        "safe",
        "unsafe",
        "risk",
        "vulnerability",
        "exploit",
        "attack",
    ];
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
    fn test_all_supported() {
        let trace = vec![
            "External call detected".into(),
            "State mutation found".into(),
        ];
        let evidence = vec!["external_call".into(), "state_write".into()];
        let report = validate_trace(&trace, &evidence);
        assert_eq!(report.support_rate, 1.0);
        assert!(report.unsupported_details.is_empty());
    }

    #[test]
    fn test_some_unsupported() {
        let trace = vec![
            "External call detected".into(),
            "Oracle price manipulation".into(),
        ];
        let evidence = vec!["external_call".into()];
        let report = validate_trace(&trace, &evidence);
        assert!(report.unsupported_steps > 0);
    }

    #[test]
    fn test_empty_trace() {
        let report = validate_trace(&[], &["evidence".into()]);
        assert_eq!(report.support_rate, 1.0);
    }
}
