//! Deterministic text templates for explanation generation.
//! All templates are plain functions — no interpolation engines, no probabilistic text.

pub fn severity_label(sev: &str) -> &str {
    match sev.to_lowercase().as_str() {
        "critical" | "high" => "Critical",
        "medium" | "moderate" => "Moderate",
        "low" | "informational" => "Low",
        _ => "Unknown severity",
    }
}

pub fn severity_emoji(sev: &str) -> &str {
    match sev.to_lowercase().as_str() {
        "critical" | "high" => "🔴",
        "medium" | "moderate" => "🟡",
        "low" | "informational" => "🟢",
        _ => "⚪",
    }
}

pub fn finding_type_description(finding_type: &str) -> &str {
    match finding_type {
        "ReentrancyCandidate" => "A function allows external calls before completing state updates, enabling reentrant callbacks to manipulate state mid-execution.",
        "AuthorityBypassCandidate" => "A privileged function lacks proper access control, allowing unauthorized callers to execute sensitive operations.",
        "CPITrustViolationCandidate" => "Cross-program invocation trusts an external program without verifying its authority or behavior.",
        "StateCorruptionCandidate" => "State variables are modified in an unsafe sequence that could leave the contract in an inconsistent state.",
        "EconomicInvariantViolationCandidate" => "An economic invariant (e.g., balance conservation, price consistency) may be violated under certain conditions.",
        "AdversarialPathCandidate" => "An attack path exists that combines multiple weaknesses into a profitable exploit chain.",
        _ => "A potential security concern was identified by the analysis engine.",
    }
}

pub fn verdict_explanation(verdict: &str) -> String {
    match verdict {
        "Valid" => "The exploit chain has been validated across all subsystems. Preconditions are satisfiable, state transitions are reachable, and no execution blockers prevent the attack from completing.".into(),
        "PartiallyValid" => "The exploit chain is partially validated. Some preconditions may not be fully satisfiable or certain state transitions remain uncertain. Manual review is recommended.".into(),
        "Invalid" => "The exploit chain could not be validated. Critical preconditions are unsatisfiable, state transitions are unreachable, or execution blockers prevent the attack.".into(),
        _ => format!("Validation produced verdict: {}. Review the detailed report for specifics.", verdict),
    }
}

pub fn count_word(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {}", singular)
    } else {
        format!("{} {}", n, plural)
    }
}

pub fn severity_distribution(findings: &[serde_json::Value]) -> (usize, usize, usize) {
    let mut critical = 0;
    let mut moderate = 0;
    let mut low = 0;
    for f in findings {
        match f.get("severity").and_then(|v| v.as_str()).unwrap_or("") {
            "Critical" | "High" => critical += 1,
            "Medium" | "Moderate" => moderate += 1,
            _ => low += 1,
        }
    }
    (critical, moderate, low)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn severity_label_maps_known_and_flags_unknown() {
        assert_eq!(severity_label("critical"), "Critical");
        assert_eq!(severity_label("HIGH"), "Critical");
        assert_eq!(severity_label("medium"), "Moderate");
        assert_eq!(severity_label("low"), "Low");
        assert_eq!(severity_label("banana"), "Unknown severity");
        assert_ne!(severity_label("low"), severity_label("critical"));
    }

    #[test]
    fn severity_emoji_distinct_per_tier() {
        assert_eq!(severity_emoji("high"), "\u{1F534}");
        assert_eq!(severity_emoji("moderate"), "\u{1F7E1}");
        assert_eq!(severity_emoji("informational"), "\u{1F7E2}");
        assert_eq!(severity_emoji("???"), "\u{26AA}");
        let distinct: std::collections::BTreeSet<&str> = [
            severity_emoji("high"),
            severity_emoji("medium"),
            severity_emoji("low"),
        ]
        .into_iter()
        .collect();
        assert_eq!(distinct.len(), 3);
    }

    #[test]
    fn finding_type_description_known_vs_fallback() {
        let reentrancy = finding_type_description("ReentrancyCandidate");
        assert!(reentrancy.to_lowercase().contains("reentrant"));
        let fallback = finding_type_description("TotallyMadeUpCandidate");
        assert!(fallback.contains("potential security concern"));
        assert_ne!(reentrancy, fallback);
    }

    #[test]
    fn verdict_explanation_distinguishes_outcomes() {
        let valid = verdict_explanation("Valid");
        let invalid = verdict_explanation("Invalid");
        assert!(valid.to_lowercase().contains("validated"));
        assert!(invalid.to_lowercase().contains("could not be validated"));
        assert_ne!(valid, invalid);
        let unknown = verdict_explanation("Weird");
        assert!(unknown.contains("Weird"));
        assert_ne!(unknown, valid);
    }

    #[test]
    fn count_word_singular_vs_plural() {
        assert_eq!(count_word(1, "finding", "findings"), "1 finding");
        assert_eq!(count_word(0, "finding", "findings"), "0 findings");
        assert_eq!(count_word(3, "step", "steps"), "3 steps");
    }

    #[test]
    fn severity_distribution_counts_real_buckets() {
        let findings = vec![
            json!({"severity": "Critical"}),
            json!({"severity": "High"}),
            json!({"severity": "Medium"}),
            json!({"severity": "Low"}),
            json!({"severity": "weird"}),
        ];
        let (critical, moderate, low) = severity_distribution(&findings);
        assert_eq!(critical + moderate + low, 5);
        assert_eq!(critical, 2);
        assert_eq!(moderate, 1);
        assert_eq!(low, 2);
    }

    #[test]
    fn severity_distribution_empty_is_zero() {
        let empty: Vec<serde_json::Value> = vec![];
        assert_eq!(severity_distribution(&empty), (0, 0, 0));
    }
}
