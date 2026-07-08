//! Crucible crash artifact parser.
//!
//! READ-ONLY parsing of existing Crucible `.meta.json` crash artifacts.
//! Crucible is never executed. No vulnerability findings are emitted.

use crate::foundry::FuzzEvidenceReport;
use crate::parser_util::extract_after;
use std::path::Path;

/// Minimal representation of a Crucible `ActionRecord` from `.meta.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionRecord {
    pub name: String,
    pub params: serde_json::Value,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<u32>,
}

/// Minimal representation of a Crucible `CrashMetadata` from `.meta.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrashMetadata {
    pub test_name: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub iteration: u64,
    #[serde(default)]
    pub seed: Option<u64>,
    pub actions: Vec<ActionRecord>,
    #[serde(default)]
    pub replay_command: Option<String>,
}

/// Parse a Crucible `.meta.json` crash artifact.
/// Returns None if the JSON is malformed or lacks required fields.
pub fn parse_crucible_failure(content: &str) -> Option<FuzzEvidenceReport> {
    let meta: CrashMetadata = serde_json::from_str(content).ok()?;

    if meta.test_name.is_empty() {
        return None;
    }

    let invariant_name = Some(meta.test_name.clone());

    let counterexample = format_crucible_actions(&meta.actions);

    let replay_command = meta
        .replay_command
        .filter(|s| !s.is_empty())
        .or_else(|| extract_after(content, &["replay_command:", "replay command:"]));

    let confidence_ceiling = if replay_command.is_some() {
        "failure_replayed"
    } else {
        "invariant_failed"
    };

    let seed_info = meta
        .seed
        .map(|s| format!("seed: {}", s))
        .unwrap_or_default();

    let iteration_info = format!("iteration: {}", meta.iteration);

    let mut excerpt_parts = vec![
        format!("test: {}", meta.test_name),
        format!("actions: {}", meta.actions.len()),
        iteration_info,
    ];
    if !seed_info.is_empty() {
        excerpt_parts.push(seed_info);
    }

    let raw_excerpt = excerpt_parts.join(", ");

    Some(FuzzEvidenceReport {
        schema_version: "digger.fuzz_evidence.v1".into(),
        digger_version: env!("CARGO_PKG_VERSION").into(),
        report_kind: "fuzz_evidence".into(),
        chain: "solana".into(),
        tool: "crucible".into(),
        report_type: "fuzz_evidence".into(),
        is_vulnerability_finding: false,
        confidence_ceiling: confidence_ceiling.to_string(),
        invariant_name,
        test_name: None,
        target_path: None,
        counterexample: Some(counterexample),
        replay_command,
        raw_excerpt,
        limitations: vec![
            "Parsed from Crucible crash metadata — not a full reproduction.".into(),
            "No automatic vulnerability finding — this is fuzz evidence for triage.".into(),
            "Replayability depends on the compiled harness binary and program .so.".into(),
            "Solana fuzzing execution is not supported by Digger — Crucible runs independently."
                .into(),
        ],
    })
}

/// Parse from a file path.
pub fn parse_crucible_failure_file(path: &Path) -> Result<FuzzEvidenceReport, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    parse_crucible_failure(&content)
        .ok_or_else(|| format!("No Crucible failure found in {}", path.display()))
}

fn format_crucible_actions(actions: &[ActionRecord]) -> String {
    actions
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let status = if a.success {
                "ok".to_string()
            } else {
                match a.error_code {
                    Some(code) => format!("err({})", code),
                    None => "err".to_string(),
                }
            };
            format!(
                "{}. {}({}) -> {}",
                i + 1,
                a.name,
                format_params(&a.params),
                status
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn format_params(params: &serde_json::Value) -> String {
    match params {
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(k, v)| {
                let val = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                format!("{}={}", k, val)
            })
            .collect::<Vec<_>>()
            .join(", "),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_crucible_failure() {
        let fixture = include_str!("fixtures/crucible_failure.json");
        let report = parse_crucible_failure(fixture).expect("should parse");
        assert_eq!(report.report_type, "fuzz_evidence");
        assert_eq!(report.tool, "crucible");
        assert_eq!(report.chain, "solana");
        assert!(!report.is_vulnerability_finding);
        assert_eq!(report.confidence_ceiling, "invariant_failed");
        assert!(report.invariant_name.is_some());
        assert!(report.counterexample.is_some());
    }

    #[test]
    fn test_parse_crucible_failure_extracted_fields() {
        let fixture = include_str!("fixtures/crucible_failure.json");
        let report = parse_crucible_failure(fixture).unwrap();
        let name = report.invariant_name.as_ref().unwrap();
        assert!(!name.is_empty(), "invariant_name must be non-empty");
        let ce = report.counterexample.as_ref().unwrap();
        assert!(!ce.is_empty(), "counterexample must be non-empty");
        assert!(ce.contains("deposit"), "should contain action name");
    }

    #[test]
    fn test_parse_crucible_empty_actions() {
        let fixture = include_str!("fixtures/crucible_empty.json");
        let report = parse_crucible_failure(fixture);
        assert!(report.is_none(), "empty actions should return None");
    }

    #[test]
    fn test_no_higher_levels_emitted() {
        let fixture = include_str!("fixtures/crucible_failure.json");
        let report = parse_crucible_failure(fixture).unwrap();
        assert!(!report.confidence_ceiling.contains("failure_minimized"));
        assert!(!report.confidence_ceiling.contains("poc_test_generated"));
    }

    #[test]
    fn test_parse_crucible_replay() {
        let fixture = include_str!("fixtures/crucible_replay.json");
        let report = parse_crucible_failure(fixture).expect("should parse");
        assert_eq!(report.confidence_ceiling, "failure_replayed");
        assert!(report.replay_command.is_some());
        assert!(report
            .replay_command
            .as_ref()
            .unwrap()
            .contains("crucible show"));
    }

    #[test]
    fn test_no_replay_gives_invariant_failed() {
        let fixture = include_str!("fixtures/crucible_failure.json");
        let report = parse_crucible_failure(fixture).unwrap();
        assert_eq!(report.confidence_ceiling, "invariant_failed");
        assert!(report.replay_command.is_none());
    }

    #[test]
    fn test_malformed_json_returns_none() {
        assert!(parse_crucible_failure("not json at all").is_none());
    }

    #[test]
    fn test_empty_string_returns_none() {
        assert!(parse_crucible_failure("").is_none());
    }

    #[test]
    fn test_smoke_fixture_parses_without_timestamp() {
        let fixture = include_str!("fixtures/crucible_smoke_failure.json");
        let report = parse_crucible_failure(fixture)
            .expect("minimal .meta.json without timestamp must parse");
        assert_eq!(report.tool, "crucible");
        assert_eq!(report.chain, "solana");
        assert_eq!(
            report.invariant_name.as_deref(),
            Some("staking_invariant_no_negative_balance")
        );
        assert!(!report.is_vulnerability_finding);
        assert_eq!(report.confidence_ceiling, "invariant_failed");
        let ce = report.counterexample.as_ref().unwrap();
        assert!(
            ce.contains("deposit"),
            "counterexample must contain actions"
        );
        assert!(ce.contains("withdraw"));
    }
}
