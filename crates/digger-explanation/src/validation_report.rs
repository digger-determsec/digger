/// Validation report explanation — translates chain validation results into NL.
use crate::templates::*;

#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub title: String,
    pub summary: String,
    pub verdict: String,
    pub score: String,
    pub chain_id: String,
    pub confidence_note: String,
}

pub fn explain_validation(result: &serde_json::Value) -> ValidationReport {
    let chain_id = result
        .get("chain_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let verdict = result
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();
    let score = result
        .get("validation_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let explanation = verdict_explanation(&verdict);
    let score_pct = format!("{:.1}%", score * 100.0);

    let confidence_note = match verdict.as_str() {
        "Valid" => "This chain achieved full validation across all subsystems: preconditions, state reachability, transaction sequencing, invariant replay, asset flow, capability validation, and trust boundary analysis.".into(),
        "PartiallyValid" => "This chain achieved partial validation. Some subsystems reported concerns. A security researcher should review the detailed validation report before confirming.".into(),
        "Invalid" => "This chain failed validation. One or more critical subsystems blocked the attack path. The chain is likely infeasible in practice.".into(),
        _ => format!("Verdict: {}. Detailed subsystem results are available in the validation report.", verdict),
    };

    let summary = format!(
        "Chain '{}' received verdict **{}** with a validation score of **{}**. {}",
        chain_id, verdict, score_pct, explanation
    );

    ValidationReport {
        title: format!("Validation Report — Chain {}", chain_id),
        summary,
        verdict,
        score: score_pct,
        chain_id,
        confidence_note,
    }
}

pub fn render_validation_markdown(report: &ValidationReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", report.title));
    out.push_str(&format!("## Summary\n\n{}\n\n", report.summary));
    out.push_str("| Metric | Value |\n|--------|-------|\n");
    out.push_str(&format!("| Verdict | **{}** |\n", report.verdict));
    out.push_str(&format!("| Score | {} |\n", report.score));
    out.push_str(&format!("| Chain | {} |\n\n", report.chain_id));
    out.push_str(&format!(
        "## Confidence Assessment\n\n{}\n\n",
        report.confidence_note
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_input() -> serde_json::Value {
        json!({
            "chain_id": "chain-42",
            "verdict": "Valid",
            "validation_score": 0.93
        })
    }

    #[test]
    fn explain_validation_populates_from_real_input() {
        let r = explain_validation(&valid_input());
        assert_eq!(r.chain_id, "chain-42");
        assert_eq!(r.verdict, "Valid");
        assert_eq!(r.score, "93.0%");
        assert!(r.summary.contains("chain-42"));
        assert!(r.summary.contains("93.0%"));
        assert!(!r.confidence_note.is_empty());
    }

    #[test]
    fn explain_validation_verdict_flip_changes_note() {
        let valid = explain_validation(&valid_input());
        let mut bad = valid_input();
        bad["verdict"] = json!("Invalid");
        let invalid = explain_validation(&bad);
        assert_ne!(valid.confidence_note, invalid.confidence_note);
        assert!(invalid
            .confidence_note
            .to_lowercase()
            .contains("failed validation"));
    }

    #[test]
    fn explain_validation_defaults_are_safe() {
        let r = explain_validation(&json!({}));
        assert_eq!(r.chain_id, "unknown");
        assert_eq!(r.verdict, "Unknown");
        assert_eq!(r.score, "0.0%");
        assert_ne!(r.verdict, "Valid");
    }

    #[test]
    fn render_validation_markdown_is_faithful_and_deterministic() {
        let r = explain_validation(&valid_input());
        let md = render_validation_markdown(&r);
        assert!(md.contains("# Validation Report"));
        assert!(md.contains("chain-42"));
        assert!(md.contains("| Verdict | **Valid** |"));
        assert!(md.contains("93.0%"));
        assert_eq!(md, render_validation_markdown(&r));
    }
}
