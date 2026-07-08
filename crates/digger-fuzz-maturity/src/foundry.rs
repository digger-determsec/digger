//! Foundry invariant failure artifact parser.
//!
//! Reads existing local Foundry invariant failure output/artifacts and produces
//! a structured `FuzzEvidenceReport`. This is READ-ONLY artifact parsing —
//! Foundry is never executed, Echidna/Medusa are not parsed here, and no
//! vulnerability findings are emitted.
//!
//! Per ADR-0038: a fuzz failure becomes evidence only when artifact-backed.
//! No replayable failure = no high-confidence fuzz finding.

use crate::parser_util::{clean_name, extract_after};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Structured report from parsing a Foundry invariant failure artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FuzzEvidenceReport {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub chain: String,
    pub tool: String,
    pub report_type: String,
    pub is_vulnerability_finding: bool,
    pub confidence_ceiling: String,
    pub invariant_name: Option<String>,
    pub test_name: Option<String>,
    pub target_path: Option<String>,
    pub counterexample: Option<String>,
    pub replay_command: Option<String>,
    pub raw_excerpt: String,
    pub limitations: Vec<String>,
}

/// Parse a Foundry invariant failure artifact (text file / log output).
/// Returns None if the artifact does not contain a recognizable invariant failure.
pub fn parse_foundry_failure(content: &str) -> Option<FuzzEvidenceReport> {
    let lc = content.to_lowercase();

    // Must contain a Foundry invariant failure signal
    let has_failure = lc.contains("failing test")
        || lc.contains("test failure")
        || lc.contains("invariant violation")
        || lc.contains("foundry test failed")
        || lc.contains("invariant_")
        || lc.contains("counterexample")
        || lc.contains("failed:")
        || (lc.contains("trace") && lc.contains("revert"));
    if !has_failure {
        return None;
    }

    // Extract invariant/test name
    let invariant_name = extract_after(content, &["failing test:", "failing tests:", "failed "])
        .map(|s| clean_name(&s));

    let test_name = extract_after(content, &["running test:", "running "]).map(|s| clean_name(&s));

    // Extract counterexample if present
    let counterexample = extract_after(
        content,
        &["counterexample:", "Counterexample:", "counter value:"],
    );

    // Extract replay command
    let replay_command = extract_after(content, &["forge test --match-test", "replay"]);

    // Extract seed/runs/shrinks if present
    let _seed = extract_after(content, &["Seed:"]);
    let _runs = extract_after(content, &["runs:"]);
    let _shrinks = extract_after(content, &["shrinks:"]);

    // Extract target path if present
    let target_path = extract_after(content, &["target: ", "Target: "])
        .or_else(|| extract_after(content, &["contract: ", "Contract: "]));

    // Determine confidence ceiling
    let confidence_ceiling = if replay_command.is_some() {
        "failure_replayed"
    } else {
        "invariant_failed"
    };

    // Truncate raw excerpt for auditability
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
        tool: "foundry".into(),
        report_type: "fuzz_evidence".into(),
        is_vulnerability_finding: false,
        confidence_ceiling: confidence_ceiling.to_string(),
        invariant_name,
        test_name,
        target_path,
        counterexample,
        replay_command,
        raw_excerpt,
        limitations: vec![
            "Parsed from Foundry invariant failure output — not a full reproduction.".into(),
            "No automatic vulnerability finding — this is fuzz evidence for triage.".into(),
            "Replayability depends on the local Foundry project state.".into(),
        ],
    })
}

/// Parse from a file path.
pub fn parse_foundry_failure_file(path: &Path) -> Result<FuzzEvidenceReport, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    parse_foundry_failure(&content)
        .ok_or_else(|| format!("No Foundry invariant failure found in {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_foundry_invariant_failure() {
        let fixture = include_str!("fixtures/foundry_invariant_failure.txt");
        let report = parse_foundry_failure(fixture).expect("should parse");
        assert_eq!(report.report_type, "fuzz_evidence");
        assert_eq!(report.tool, "foundry");
        assert_eq!(report.chain, "evm");
        assert!(!report.is_vulnerability_finding);
        assert!(report.confidence_ceiling != "harness/config_present");
        assert!(report.confidence_ceiling != "suggested_invariant");
        assert!(report.invariant_name.is_some());
        assert!(report.counterexample.is_some());
    }

    #[test]
    fn test_parse_with_replay() {
        let fixture = include_str!("fixtures/foundry_invariant_replay.txt");
        let report = parse_foundry_failure(fixture).expect("should parse");
        assert_eq!(report.confidence_ceiling, "failure_replayed");
        assert!(report.replay_command.is_some());
    }

    #[test]
    fn test_no_failure_returns_none() {
        let report = parse_foundry_failure("everything is fine, no issues");
        assert!(report.is_none(), "non-failure output should return None");
    }

    #[test]
    fn test_empty_returns_none() {
        assert!(parse_foundry_failure("").is_none());
    }

    #[test]
    fn test_no_higher_levels_emitted() {
        let fixture = include_str!("fixtures/foundry_invariant_failure.txt");
        let report = parse_foundry_failure(fixture).unwrap();
        assert!(!report.confidence_ceiling.contains("failure_minimized"));
        assert!(!report.confidence_ceiling.contains("poc_test_generated"));
    }

    #[test]
    fn test_smoke_fixture_extracts_real_name() {
        let fixture = include_str!("fixtures/foundry_smoke_failure.txt");
        let report = parse_foundry_failure(fixture).expect("should parse smoke fixture");
        let name = report
            .invariant_name
            .as_ref()
            .expect("invariant_name must be present");
        assert!(
            name.contains("invariant_counter_never_negative"),
            "invariant_name should contain the real function name, got: {}",
            name
        );
        assert_ne!(name, "in", "invariant_name must not be the word 'in'");
    }

    #[test]
    fn test_fuzz_evidence_schema_contract() {
        let fixture = include_str!("fixtures/foundry_invariant_failure.txt");
        let report = parse_foundry_failure(fixture).expect("should parse");
        let json = serde_json::to_value(&report).unwrap();

        // Required top-level fields must exist and have correct types
        assert!(json["chain"].is_string(), "chain must be string");
        assert!(json["tool"].is_string(), "tool must be string");
        assert!(
            json["report_type"].is_string(),
            "report_type must be string"
        );
        assert!(
            json["is_vulnerability_finding"].is_boolean(),
            "is_vulnerability_finding must be boolean"
        );
        assert!(
            json["confidence_ceiling"].is_string(),
            "confidence_ceiling must be string"
        );
        assert!(
            json["raw_excerpt"].is_string(),
            "raw_excerpt must be string"
        );
        assert!(json["limitations"].is_array(), "limitations must be array");

        // Invariants pinned by schema
        assert_eq!(json["schema_version"], "digger.fuzz_evidence.v1");
        assert!(
            json["digger_version"].is_string(),
            "digger_version must be string"
        );
        assert_eq!(json["report_kind"], "fuzz_evidence");
        assert_eq!(json["report_type"], "fuzz_evidence");
        assert_eq!(json["is_vulnerability_finding"], false);
        assert_eq!(json["tool"], "foundry");
        assert_eq!(json["chain"], "evm");

        // confidence_ceiling must be one of two values
        let cc = json["confidence_ceiling"].as_str().unwrap();
        assert!(
            cc == "invariant_failed" || cc == "failure_replayed",
            "confidence_ceiling must be invariant_failed or failure_replayed, got: {}",
            cc
        );

        // null fields must be explicitly null, not missing
        assert!(
            json.get("invariant_name").is_some(),
            "invariant_name key must exist even if null"
        );
        assert!(
            json.get("test_name").is_some(),
            "test_name key must exist even if null"
        );
        assert!(
            json.get("target_path").is_some(),
            "target_path key must exist even if null"
        );
        assert!(
            json.get("counterexample").is_some(),
            "counterexample key must exist even if null"
        );
        assert!(
            json.get("replay_command").is_some(),
            "replay_command key must exist even if null"
        );
    }
}
