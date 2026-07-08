/// Scan report explanation — translates structured scan results into natural language.
use crate::templates::*;

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub title: String,
    pub summary: String,
    pub finding_count: usize,
    pub severity_breakdown: String,
    pub findings: Vec<FindingExplanation>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FindingExplanation {
    pub id: String,
    pub title: String,
    pub severity_badge: String,
    pub type_explanation: String,
    pub function: Option<String>,
    pub evidence_summary: String,
    pub recommendation: String,
}

pub fn explain_scan(result: &serde_json::Value) -> ScanReport {
    let findings = result
        .get("findings")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    let program_id = result
        .get("program_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let (critical, moderate, low) = severity_distribution(&findings);

    let summary = if findings.is_empty() {
        format!("No security findings were detected in program '{}'. The analysis engine found no hypothesis candidates matching known attack patterns.", program_id)
    } else {
        format!(
            "Analysis of program '{}' identified {} potential security {}.",
            program_id,
            count_word(findings.len(), "finding", "findings"),
            if findings.len() == 1 {
                "concern"
            } else {
                "concerns"
            }
        )
    };

    let severity_breakdown = if findings.is_empty() {
        "No findings.".into()
    } else {
        format!(
            "{} critical, {} moderate, {} low severity.",
            critical, moderate, low
        )
    };

    let findings_explanations: Vec<FindingExplanation> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let ftype = f.get("type").and_then(|v| v.as_str()).unwrap_or("Unknown");
            let sev = f
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let desc = f
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("No description available.");
            let func = f
                .get("function")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let evidence_count = f
                .get("evidence_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            FindingExplanation {
                id: format!("F{}", i + 1),
                title: desc.to_string(),
                severity_badge: format!("{} {}", severity_emoji(sev), severity_label(sev)),
                type_explanation: finding_type_description(ftype).to_string(),
                function: func,
                evidence_summary: format!(
                    "{} evidence {}",
                    evidence_count,
                    if evidence_count == 1 {
                        "reference"
                    } else {
                        "references"
                    }
                ),
                recommendation: recommendation_for_type(ftype),
            }
        })
        .collect();

    let recommendations = generate_scan_recommendations(&findings);

    ScanReport {
        title: format!("Security Scan Report — {}", program_id),
        summary,
        finding_count: findings.len(),
        severity_breakdown,
        findings: findings_explanations,
        recommendations,
    }
}

fn recommendation_for_type(ftype: &str) -> String {
    match ftype {
        "ReentrancyCandidate" => "Add a reentrancy guard (e.g., OpenZeppelin ReentrancyGuard) or use checks-effects-interactions pattern.".into(),
        "AuthorityBypassCandidate" => "Add explicit access control checks (onlyOwner, role-based) to the function.".into(),
        "CPITrustViolationCandidate" => "Validate CPI targets and verify program ownership before delegating execution.".into(),
        "StateCorruptionCandidate" => "Ensure state updates complete before external calls and validate all intermediate states.".into(),
        "EconomicInvariantViolationCandidate" => "Audit economic invariants and add assertions to preserve balance conservation.".into(),
        "AdversarialPathCandidate" => "Review the full attack path and address each step's prerequisites to break the chain.".into(),
        _ => "Review the finding details and apply standard security best practices.".into(),
    }
}

fn generate_scan_recommendations(findings: &[serde_json::Value]) -> Vec<String> {
    let mut recs = Vec::new();
    let types: Vec<&str> = findings
        .iter()
        .filter_map(|f| f.get("type").and_then(|v| v.as_str()))
        .collect();

    if types.contains(&"ReentrancyCandidate") {
        recs.push("Reentrancy risks detected: Consider using ReentrancyGuard or the checks-effects-interactions pattern.".into());
    }
    if types.contains(&"AuthorityBypassCandidate") {
        recs.push(
            "Authority bypass risks detected: Add access control modifiers to sensitive functions."
                .into(),
        );
    }
    if types.contains(&"EconomicInvariantViolationCandidate") {
        recs.push("Economic invariant violations detected: Audit balance conservation and token flow logic.".into());
    }
    if findings.len() > 5 {
        recs.push(
            "High finding count: Consider a comprehensive security audit with external reviewers."
                .into(),
        );
    }
    if recs.is_empty() && !findings.is_empty() {
        recs.push(
            "Review each finding carefully and apply defense-in-depth security measures.".into(),
        );
    }
    recs
}

/// Render scan report as markdown.
pub fn render_scan_markdown(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", report.title));
    out.push_str(&format!("## Summary\n\n{}\n\n", report.summary));
    out.push_str(&format!(
        "**Severity breakdown:** {}\n\n",
        report.severity_breakdown
    ));

    if !report.findings.is_empty() {
        out.push_str("## Findings\n\n");
        for f in &report.findings {
            out.push_str(&format!("### {} — {}\n\n", f.id, f.severity_badge));
            out.push_str(&format!("{}\n\n", f.title));
            out.push_str(&format!("**Type:** {}\n\n", f.type_explanation));
            if let Some(func) = &f.function {
                out.push_str(&format!("**Function:** `{}`\n\n", func));
            }
            out.push_str(&format!("**Evidence:** {}\n\n", f.evidence_summary));
            out.push_str(&format!("**Recommendation:** {}\n\n", f.recommendation));
        }
    }

    if !report.recommendations.is_empty() {
        out.push_str("## Recommendations\n\n");
        for r in &report.recommendations {
            out.push_str(&format!("- {}\n", r));
        }
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scan_input() -> serde_json::Value {
        json!({
            "program_id": "Prog111",
            "findings": [
                {"type": "ReentrancyCandidate", "severity": "Critical", "description": "Reentrant withdraw", "function": "withdraw", "evidence_count": 2},
                {"type": "AuthorityBypassCandidate", "severity": "Medium", "description": "Missing owner check", "evidence_count": 1}
            ]
        })
    }

    #[test]
    fn explain_scan_populated_builds_findings_and_recs() {
        let r = explain_scan(&scan_input());
        assert_eq!(r.finding_count, 2);
        assert_eq!(r.findings.len(), 2);
        assert_eq!(r.findings[0].id, "F1");
        assert!(r.findings[0].severity_badge.contains("Critical"));
        assert_eq!(r.findings[0].function.as_deref(), Some("withdraw"));
        assert!(r.findings[0]
            .type_explanation
            .to_lowercase()
            .contains("reentrant"));
        assert!(r.findings[0]
            .evidence_summary
            .contains("2 evidence references"));
        assert!(r.recommendations.iter().any(|x| x.contains("Reentrancy")));
        assert!(r.recommendations.iter().any(|x| x.contains("Authority")));
    }

    #[test]
    fn explain_scan_empty_is_clean_and_invents_nothing() {
        let r = explain_scan(&json!({"program_id": "P", "findings": []}));
        assert_eq!(r.finding_count, 0);
        assert!(r.findings.is_empty());
        assert!(r.summary.contains("No security findings"));
        assert_eq!(r.severity_breakdown, "No findings.");
        assert!(r.recommendations.is_empty());
    }

    #[test]
    fn explain_scan_unknown_severity_not_escalated() {
        let r = explain_scan(&json!({
            "program_id": "P",
            "findings": [{"type": "X", "severity": "bogus", "description": "d"}]
        }));
        assert!(r.findings[0].severity_badge.contains("Unknown severity"));
        assert!(!r.findings[0].severity_badge.contains("Critical"));
    }

    #[test]
    fn render_scan_markdown_faithful() {
        let r = explain_scan(&scan_input());
        let md = render_scan_markdown(&r);
        assert!(md.contains("# Security Scan Report — Prog111"));
        assert!(md.contains("### F1 —"));
        assert!(md.contains("**Function:** `withdraw`"));
        assert!(md.contains("## Recommendations"));
    }
}
