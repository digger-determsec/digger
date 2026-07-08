//! Echidna failure artifact parser.
//!
//! READ-ONLY parsing of existing Echidna invariant/property failure output.
//! Echidna is never executed. No vulnerability findings are emitted.

use crate::foundry::FuzzEvidenceReport;
use crate::parser_util::{clean_name, extract_after};
use std::path::Path;

/// Parse an Echidna failure artifact. Returns None if no failure signal found.
pub fn parse_echidna_failure(content: &str) -> Option<FuzzEvidenceReport> {
    let lc = content.to_lowercase();

    let has_failure = lc.contains("falsified!")
        || lc.contains("property") && (lc.contains("failed") || lc.contains("violat"))
        || lc.contains("echidna test failed")
        || lc.contains("test limit reached")
        || lc.contains("counterexample:")
        || lc.contains("transaction:");
    if !has_failure {
        return None;
    }

    let invariant_name = extract_after(
        content,
        &["Property ", "property ", "Property: ", "property: "],
    )
    .map(|s| clean_name(&s));

    let contract_name = extract_after(content, &["Contract: ", "contract: "])
        .map(|s| s.split_whitespace().next().unwrap_or("").to_string());

    let counterexample = extract_after(content, &["Counterexample:", "counterexample:"])
        .or_else(|| extract_after(content, &["arg:", "Arg:"]));

    let replay_command = extract_after(content, &["echidna-test", "replay"]);

    let confidence_ceiling = if replay_command.is_some() {
        "failure_replayed"
    } else {
        "invariant_failed"
    };

    let raw_excerpt = if content.len() > 2048 {
        format!("{}...", &content[..2048])
    } else {
        content.to_string()
    };

    Some(FuzzEvidenceReport {
        schema_version: "digger.fuzz_evidence.v1".into(),
        digger_version: env!("CARGO_PKG_VERSION").into(),
        report_kind: "fuzz_evidence".into(),
        chain: "evm".into(),
        tool: "echidna".into(),
        report_type: "fuzz_evidence".into(),
        is_vulnerability_finding: false,
        confidence_ceiling: confidence_ceiling.to_string(),
        invariant_name,
        test_name: contract_name,
        target_path: None,
        counterexample,
        replay_command,
        raw_excerpt,
        limitations: vec![
            "Parsed from Echidna failure output — not a full reproduction.".into(),
            "No automatic vulnerability finding — this is fuzz evidence for triage.".into(),
            "Replayability depends on the Echidna config and contract state.".into(),
        ],
    })
}

/// Parse from a file path.
pub fn parse_echidna_failure_file(path: &Path) -> Result<FuzzEvidenceReport, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    parse_echidna_failure(&content)
        .ok_or_else(|| format!("No Echidna failure found in {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_echidna_failure() {
        let fixture = include_str!("fixtures/echidna_failure.txt");
        let report = parse_echidna_failure(fixture).expect("should parse");
        assert_eq!(report.report_type, "fuzz_evidence");
        assert_eq!(report.tool, "echidna");
        assert_eq!(report.chain, "evm");
        assert!(!report.is_vulnerability_finding);
        assert_eq!(report.confidence_ceiling, "invariant_failed");
        assert!(report.invariant_name.is_some());
        assert!(report.counterexample.is_some());
    }

    #[test]
    fn test_parse_echidna_replay() {
        let fixture = include_str!("fixtures/echidna_replay.txt");
        let report = parse_echidna_failure(fixture).expect("should parse");
        assert_eq!(report.confidence_ceiling, "failure_replayed");
        assert!(report.replay_command.is_some());
    }

    #[test]
    fn test_no_failure_returns_none() {
        let report = parse_echidna_failure("Everything passed, no issues found.");
        assert!(report.is_none(), "non-failure should return None");
    }

    #[test]
    fn test_empty_returns_none() {
        assert!(parse_echidna_failure("").is_none());
    }

    #[test]
    fn test_no_higher_levels_emitted() {
        let fixture = include_str!("fixtures/echidna_failure.txt");
        let report = parse_echidna_failure(fixture).unwrap();
        assert!(!report.confidence_ceiling.contains("failure_minimized"));
        assert!(!report.confidence_ceiling.contains("poc_test_generated"));
    }
}
