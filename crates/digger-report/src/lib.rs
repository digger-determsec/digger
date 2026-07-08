mod content;
mod ranking;
mod renderer;

pub use content::{content_library, RuleContent};
pub use ranking::{rank_findings, ConfidenceFilter};
pub use renderer::render_report;

use serde::{Deserialize, Serialize};

/// A minimal finding representation extracted from the AuditTriagePacket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportFinding {
    pub finding_id: String,
    pub rule_id: String,
    pub severity: String,
    pub confidence: String,
    pub component: String,
    pub file: String,
    pub line_start: u32,
    pub line_end: u32,
    pub description: String,
    pub evidence_lines: Vec<String>,
}

/// The rendered Markdown report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedReport {
    pub markdown: String,
    pub findings_count: usize,
    pub omitted_count: usize,
}

/// Full pipeline: take findings, rank, render.
pub fn generate_report(
    findings: &[ReportFinding],
    top_n: Option<usize>,
    min_confidence: Option<&str>,
) -> RenderedReport {
    let filtered = ranking::rank_findings(findings, min_confidence, top_n);
    let omitted = findings.len().saturating_sub(filtered.len());
    let markdown = renderer::render_report(&filtered);
    RenderedReport {
        markdown,
        findings_count: filtered.len(),
        omitted_count: omitted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding(id: &str, rule: &str, sev: &str, conf: &str) -> ReportFinding {
        ReportFinding {
            finding_id: id.into(),
            rule_id: rule.into(),
            severity: sev.into(),
            confidence: conf.into(),
            component: "Vault".into(),
            file: "contracts/Vault.sol".into(),
            line_start: 42,
            line_end: 50,
            description: format!("Test finding {id}"),
            evidence_lines: vec![
                "function withdraw() external {".into(),
                "    payable(msg.sender).transfer(address(this).balance);".into(),
                "}".into(),
            ],
        }
    }

    #[test]
    fn render_produces_valid_markdown() {
        let findings = vec![
            sample_finding("f1", "authority_bypass", "critical", "confirmed"),
            sample_finding("f2", "state_corruption", "high", "high"),
        ];
        let report = generate_report(&findings, None, None);
        assert!(report.markdown.contains("# Security Analysis Report"));
        assert!(report.markdown.contains("Authority Bypass in `Vault`"));
        assert!(report.markdown.contains("State Corruption in `Vault`"));
        assert!(report.markdown.contains("### Summary"));
        assert!(report.markdown.contains("### How to fix"));
        assert!(report.findings_count == 2);
        assert!(report.omitted_count == 0);
    }

    #[test]
    fn cross_process_byte_identical() {
        let findings = vec![
            sample_finding("f1", "authority_bypass", "critical", "confirmed"),
            sample_finding("f2", "price_manipulation", "medium", "experimental"),
        ];
        let r1 = generate_report(&findings, None, None);
        let r2 = generate_report(&findings, None, None);
        assert_eq!(r1.markdown, r2.markdown);
    }

    #[test]
    fn unknown_rule_uses_fallback() {
        let findings = vec![sample_finding(
            "f1",
            "unknown_detector_xyz",
            "low",
            "medium",
        )];
        let report = generate_report(&findings, None, None);
        assert!(report
            .markdown
            .contains("A security finding flagged by the analysis engine."));
    }

    #[test]
    fn top_n_filters_output() {
        let findings = vec![
            sample_finding("f1", "authority_bypass", "critical", "high"),
            sample_finding("f2", "state_corruption", "high", "high"),
            sample_finding("f3", "price_manipulation", "medium", "high"),
        ];
        let report = generate_report(&findings, Some(1), None);
        assert_eq!(report.findings_count, 1);
        assert_eq!(report.omitted_count, 2);
    }

    #[test]
    fn min_confidence_filters_output() {
        let findings = vec![
            sample_finding("f1", "authority_bypass", "critical", "confirmed"),
            sample_finding("f2", "state_corruption", "high", "experimental"),
        ];
        let report = generate_report(&findings, None, Some("high"));
        assert_eq!(report.findings_count, 1);
    }
}
