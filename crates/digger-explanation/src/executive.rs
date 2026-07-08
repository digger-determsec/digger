use crate::execution_report;
use crate::scan_report;
use crate::synthesis_report;
/// Executive summary — combines scan, synthesis, validation, and execution into one report.
use crate::templates::*;
use crate::validation_report;

#[derive(Debug, Clone)]
pub struct ExecutiveSummary {
    pub title: String,
    pub program_id: String,
    pub scan_section: scan_report::ScanReport,
    pub synthesis_section: synthesis_report::SynthesisReport,
    pub validation_section: Option<validation_report::ValidationReport>,
    pub execution_section: Option<execution_report::ExecutionReport>,
    pub overall_risk: String,
    pub key_findings: Vec<String>,
    pub next_steps: Vec<String>,
}

pub fn generate_executive_summary(
    scan_result: &serde_json::Value,
    synthesis_result: &serde_json::Value,
    validation_result: Option<&serde_json::Value>,
    execution_result: Option<&serde_json::Value>,
) -> ExecutiveSummary {
    let scan = scan_report::explain_scan(scan_result);
    let synthesis = synthesis_report::explain_synthesis(synthesis_result);
    let validation = validation_result.map(validation_report::explain_validation);
    let execution = execution_result.map(execution_report::explain_execution);

    let program_id = scan_result
        .get("program_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let findings_arr = scan_result
        .get("findings")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    let (critical, moderate, _low) = severity_distribution(&findings_arr);

    let overall_risk = if critical > 0 {
        "CRITICAL".into()
    } else if moderate > 0 {
        "MODERATE".into()
    } else if scan.finding_count > 0 {
        "LOW".into()
    } else {
        "MINIMAL".into()
    };

    let mut key_findings = Vec::new();
    if scan.finding_count > 0 {
        key_findings.push(format!(
            "{} identified ({} critical, {} moderate)",
            count_word(scan.finding_count, "finding", "findings"),
            critical,
            moderate
        ));
    } else {
        key_findings.push("No security findings detected by automated analysis.".into());
    }

    if synthesis.chain_count > 0 {
        key_findings.push(format!(
            "{} exploit chain{} synthesized ({} confirmed)",
            synthesis.chain_count,
            if synthesis.chain_count == 1 { "" } else { "s" },
            synthesis.confirmed_count
        ));
    }

    if let Some(ref v) = validation {
        key_findings.push(format!("Validation verdict: {}", v.verdict));
    }

    if let Some(ref e) = execution {
        key_findings.push(format!("Execution status: {}", e.status));
    }

    let mut next_steps = Vec::new();
    if critical > 0 {
        next_steps.push("IMMEDIATE: Address critical findings before deployment.".into());
    }
    if synthesis.confirmed_count > 0 {
        next_steps.push("Review confirmed exploit chains and implement mitigations.".into());
    }
    if scan.finding_count > 0 {
        next_steps.push("Engage external security auditors for comprehensive review.".into());
    }
    if scan.finding_count == 0 && synthesis.chain_count == 0 {
        next_steps.push("Consider expanding test coverage with additional edge cases.".into());
        next_steps.push("Run protocol-specific analysis for deeper coverage.".into());
    }
    next_steps.push("Integrate findings into CI/CD pipeline for continuous monitoring.".into());

    ExecutiveSummary {
        title: format!("Security Assessment — {}", program_id),
        program_id,
        scan_section: scan,
        synthesis_section: synthesis,
        validation_section: validation,
        execution_section: execution,
        overall_risk,
        key_findings,
        next_steps,
    }
}

pub fn render_executive_markdown(summary: &ExecutiveSummary) -> String {
    let mut out = String::new();

    out.push_str(&format!("# {}\n\n", summary.title));
    out.push_str(&format!(
        "**Overall Risk Level: {}**\n\n",
        summary.overall_risk
    ));

    out.push_str("## Key Findings\n\n");
    for f in &summary.key_findings {
        out.push_str(&format!("- {}\n", f));
    }
    out.push('\n');

    out.push_str(&format!(
        "---\n\n{}\n",
        scan_report::render_scan_markdown(&summary.scan_section)
    ));
    out.push_str(&format!(
        "---\n\n{}\n",
        synthesis_report::render_synthesis_markdown(&summary.synthesis_section)
    ));

    if let Some(ref v) = summary.validation_section {
        out.push_str(&format!(
            "---\n\n{}\n",
            validation_report::render_validation_markdown(v)
        ));
    }
    if let Some(ref e) = summary.execution_section {
        out.push_str(&format!(
            "---\n\n{}\n",
            execution_report::render_execution_markdown(e)
        ));
    }

    out.push_str("## Recommended Next Steps\n\n");
    for (i, step) in summary.next_steps.iter().enumerate() {
        out.push_str(&format!("{}. {}\n", i + 1, step));
    }
    out.push('\n');

    out.push_str("---\n\n*Generated by Digger Deterministic Security Analysis Platform. This report contains no AI-generated opinions — all findings are derived from deterministic analysis of the source code.*\n");

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scan_with_critical() -> serde_json::Value {
        json!({
            "program_id": "ProgX",
            "findings": [
                {"type": "ReentrancyCandidate", "severity": "Critical", "description": "d", "evidence_count": 1}
            ]
        })
    }

    fn synth() -> serde_json::Value {
        json!({
            "total_chains": 1,
            "viable_chains": 1,
            "eliminated_chains": 0,
            "confirmations": [{"chain_id": "c1"}],
            "rankings": [{"chain_id": "c1", "score": 0.8}],
            "explanations": []
        })
    }

    #[test]
    fn executive_summary_populated_risk_critical() {
        let s = generate_executive_summary(&scan_with_critical(), &synth(), None, None);
        assert_eq!(s.program_id, "ProgX");
        assert_eq!(s.overall_risk, "CRITICAL");
        assert!(!s.key_findings.is_empty());
        assert!(s.key_findings.iter().any(|k| k.contains("critical")));
        assert!(s.next_steps.iter().any(|n| n.contains("IMMEDIATE")));
    }

    #[test]
    fn executive_summary_flip_clean_scan_is_minimal() {
        let clean = json!({"program_id": "P", "findings": []});
        let no_chains = json!({"total_chains": 0});
        let s = generate_executive_summary(&clean, &no_chains, None, None);
        assert_eq!(s.overall_risk, "MINIMAL");
        assert!(s
            .key_findings
            .iter()
            .any(|k| k.contains("No security findings")));
        assert_ne!(s.overall_risk, "CRITICAL");
    }

    #[test]
    fn render_executive_markdown_carries_nonauthoritative_disclaimer() {
        let s = generate_executive_summary(&scan_with_critical(), &synth(), None, None);
        let md = render_executive_markdown(&s);
        assert!(md.contains("# Security Assessment — ProgX"));
        assert!(md.contains("**Overall Risk Level: CRITICAL**"));
        assert!(md.contains("no AI-generated opinions"));
        assert!(md.contains("derived from deterministic analysis"));
        assert_eq!(md, render_executive_markdown(&s));
    }

    #[test]
    fn executive_summary_includes_optional_sections() {
        let validation = json!({"chain_id": "c1", "verdict": "Valid", "validation_score": 0.9});
        let execution = json!({
            "execution_result": {
                "confirmation_status": "Verified",
                "total_gas": 10,
                "transcript_entries": 1,
                "execution_hash": "h",
                "state_diff": {"storage_changes": 0, "balance_changes": 0, "authority_changes": 0}
            }
        });
        let s = generate_executive_summary(
            &scan_with_critical(),
            &synth(),
            Some(&validation),
            Some(&execution),
        );
        assert!(s.validation_section.is_some());
        assert!(s.execution_section.is_some());
        assert!(s
            .key_findings
            .iter()
            .any(|k| k.contains("Validation verdict: Valid")));
        let md = render_executive_markdown(&s);
        assert!(md.contains("Validation Report"));
        assert!(md.contains("Execution & Verification Report"));
    }
}
