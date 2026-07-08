#![allow(clippy::needless_update, clippy::useless_vec, clippy::len_zero)]
use digger_graph::build_system_ir;
use digger_ir::*;
use digger_parser::model::{RawCall, RawFunction, RawProgram, RawState};
/// Surface Contract Tests — Prevent Accidental Breaking Changes
///
/// These tests treat SecurityIntelligenceOutput as a public API contract.
/// If any test fails, the export contract has been broken.
use digger_surface::*;

/// Build a test SystemIR with all edge types.
fn make_test_ir() -> SystemIR {
    let program = RawProgram {
        functions: vec![
            RawFunction {
                name: "deposit".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "balances[msg.sender] += msg.value".into(),
                ..Default::default()
            },
            RawFunction {
                name: "withdraw".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "require(balances[msg.sender] >= amount); (bool success, ) = msg.sender.call{value: amount}(\"\"); balances[msg.sender] -= amount".into(),
                ..Default::default()
            },
            RawFunction {
                name: "setOwner".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "owner = newOwner".into(),
                ..Default::default()
            },
        ],
        state: vec![
            RawState { name: "balances".into(), ty: "mapping".into(), ..Default::default() },
            RawState { name: "owner".into(), ty: "address".into(), ..Default::default() },
        ],
        calls: vec![
            RawCall { from: "withdraw".into(), to: "external".into(), kind: CallKind::External },
        ],
        ..Default::default()
    };
    build_system_ir(program)
}

// ─────────────────────────────────────────────────────────────
// 1. Serialization Stability — same input → same JSON
// ─────────────────────────────────────────────────────────────

#[test]
fn serialization_is_deterministic() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);

    let json1 = output.to_json();
    let json2 = output.to_json();
    let json3 = output.to_json();

    assert_eq!(
        json1, json2,
        "Serialization must be deterministic (run 1 vs 2)"
    );
    assert_eq!(
        json2, json3,
        "Serialization must be deterministic (run 2 vs 3)"
    );
}

#[test]
fn deserialization_roundtrip() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);

    let json = output.to_json();
    let deserialized: SecurityIntelligenceOutput = serde_json::from_str(&json)
        .expect("JSON must deserialize back to SecurityIntelligenceOutput");

    assert_eq!(output.version, deserialized.version);
    assert_eq!(output.program_id, deserialized.program_id);
    assert_eq!(output.paths.summary.total, deserialized.paths.summary.total);
    assert_eq!(output.evidence.len(), deserialized.evidence.len());
}

// ─────────────────────────────────────────────────────────────
// 2. Required Fields — top-level fields always exist
// ─────────────────────────────────────────────────────────────

#[test]
fn required_fields_always_present() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);
    let json = output.to_json();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Top-level required fields
    assert!(value.get("version").is_some(), "version field must exist");
    assert!(
        value.get("program_id").is_some(),
        "program_id field must exist"
    );
    assert!(
        value.get("attack_surface").is_some(),
        "attack_surface field must exist"
    );
    assert!(value.get("paths").is_some(), "paths field must exist");
    assert!(
        value.get("risk_groups").is_some(),
        "risk_groups field must exist"
    );
    assert!(
        value.get("cross_protocol").is_some(),
        "cross_protocol field must exist"
    );
    assert!(value.get("evidence").is_some(), "evidence field must exist");
    assert!(value.get("metadata").is_some(), "metadata field must exist");
}

#[test]
fn version_is_correct() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);

    assert_eq!(output.version, SCHEMA_VERSION);
    assert_eq!(output.version, "2.3");
}

#[test]
fn metadata_fields_present() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);
    let json = output.to_json();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    let metadata = value.get("metadata").unwrap();
    assert!(
        metadata.get("analysis_depth").is_some(),
        "analysis_depth must exist"
    );
    assert!(metadata.get("languages").is_some(), "languages must exist");
    assert!(
        metadata.get("total_functions").is_some(),
        "total_functions must exist"
    );
    assert!(
        metadata.get("total_edges").is_some(),
        "total_edges must exist"
    );
    assert!(
        metadata.get("total_findings").is_some(),
        "total_findings must exist"
    );
}

// ─────────────────────────────────────────────────────────────
// 3. Empty-State Stability — empty collections, not null
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_ir_serializes_cleanly() {
    let ir = SystemIR {
        program_id: "empty".into(),
        language: Language::Solidity,
        functions: vec![],
        state: vec![],
        edges: vec![],
    };

    let output = SecurityIntelligenceOutput::build(&ir);
    let json = output.to_json();

    // Must not contain null for collections
    assert!(
        !json.contains("null"),
        "Empty collections must be [], not null:\n{}",
        json
    );

    // Must contain empty arrays
    assert!(
        json.contains("\"paths\": []") || json.contains("\"paths\":[]"),
        "paths must be empty array, not null"
    );
    assert!(
        json.contains("\"evidence\": []") || json.contains("\"evidence\":[]"),
        "evidence must be empty array, not null"
    );
}

#[test]
fn empty_ir_deserializes() {
    let ir = SystemIR {
        program_id: "empty".into(),
        language: Language::Solidity,
        functions: vec![],
        state: vec![],
        edges: vec![],
    };

    let output = SecurityIntelligenceOutput::build(&ir);
    let json = output.to_json();

    let deserialized: SecurityIntelligenceOutput =
        serde_json::from_str(&json).expect("Empty IR output must deserialize");

    assert_eq!(deserialized.paths.paths.len(), 0);
    assert_eq!(deserialized.evidence.len(), 0);
    assert_eq!(deserialized.version, SCHEMA_VERSION);
}

// ─────────────────────────────────────────────────────────────
// 4. Backward Compatibility Guard — structure stability
// ─────────────────────────────────────────────────────────────

#[test]
fn attack_surface_has_required_subfields() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);
    let json = output.to_json();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    let surface = value.get("attack_surface").unwrap();
    assert!(
        surface.get("entry_points").is_some(),
        "entry_points must exist"
    );
    assert!(
        surface.get("state_mutations").is_some(),
        "state_mutations must exist"
    );
    assert!(
        surface.get("external_interactions").is_some(),
        "external_interactions must exist"
    );
    assert!(
        surface.get("authority_regions").is_some(),
        "authority_regions must exist"
    );
    assert!(surface.get("summary").is_some(), "summary must exist");
}

#[test]
fn paths_has_required_subfields() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);
    let json = output.to_json();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    let paths = value.get("paths").unwrap();
    assert!(paths.get("paths").is_some(), "paths.paths must exist");
    assert!(paths.get("by_type").is_some(), "paths.by_type must exist");
    assert!(paths.get("summary").is_some(), "paths.summary must exist");
}

#[test]
fn risk_groups_has_required_subfields() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);
    let json = output.to_json();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    let groups = value.get("risk_groups").unwrap();
    assert!(
        groups.get("high_fan_in").is_some(),
        "high_fan_in must exist"
    );
    assert!(
        groups.get("high_fan_out").is_some(),
        "high_fan_out must exist"
    );
    assert!(
        groups.get("high_state_density").is_some(),
        "high_state_density must exist"
    );
    assert!(
        groups.get("external_density").is_some(),
        "external_density must exist"
    );
    assert!(groups.get("summary").is_some(), "summary must exist");
}

#[test]
fn cross_protocol_has_required_subfields() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);
    let json = output.to_json();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    let cp = value.get("cross_protocol").unwrap();
    assert!(cp.get("nodes").is_some(), "nodes must exist");
    assert!(cp.get("edges").is_some(), "edges must exist");
    assert!(
        cp.get("cross_program").is_some(),
        "cross_program must exist"
    );
    assert!(
        cp.get("highlighted_paths").is_some(),
        "highlighted_paths must exist"
    );
    assert!(cp.get("summary").is_some(), "summary must exist");
}

#[test]
fn evidence_steps_have_required_fields() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);

    for chain in &output.evidence {
        assert!(!chain.finding_id.is_empty(), "finding_id must not be empty");
        assert!(!chain.path_id.is_empty(), "path_id must not be empty");
        assert!(!chain.severity.is_empty(), "severity must not be empty");
        assert!(!chain.summary.is_empty(), "summary must not be empty");

        for step in &chain.steps {
            assert!(!step.function.is_empty(), "step.function must not be empty");
            assert!(!step.detail.is_empty(), "step.detail must not be empty");
        }
    }
}

// ─────────────────────────────────────────────────────────────
// 5. Contract Validation
// ─────────────────────────────────────────────────────────────

#[test]
fn valid_output_passes_validation() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);

    let errors = output.validate();
    assert!(
        errors.is_empty(),
        "Valid output should pass validation: {:?}",
        errors
    );
}

#[test]
fn schema_version_constant_matches() {
    assert_eq!(SCHEMA_VERSION, "2.3");
}

// ─────────────────────────────────────────────────────────────
// 6. EvidenceChain Contract
// ─────────────────────────────────────────────────────────────

#[test]
fn evidence_chain_derives_from_vuln_paths() {
    let ir = make_test_ir();
    let evidence = EvidenceChain::derive_all(&ir);

    // Should derive evidence for every vulnerability path
    let vuln = digger_graph::analysis::VulnerabilityPathAnalysis::derive(&ir);
    assert_eq!(
        evidence.len(),
        vuln.paths.len(),
        "Evidence chains must match vulnerability paths"
    );
}

#[test]
fn evidence_steps_use_enums_not_strings() {
    let ir = make_test_ir();
    let evidence = EvidenceChain::derive_all(&ir);

    for chain in &evidence {
        for step in &chain.steps {
            // Verify action is a valid enum variant (not free-form text)
            let _ = match step.action {
                EvidenceAction::FunctionEntered => "ok",
                EvidenceAction::FunctionCallable => "ok",
                EvidenceAction::ExternalCallObserved => "ok",
                EvidenceAction::CrossProgramCallObserved => "ok",
                EvidenceAction::StateReadObserved => "ok",
                EvidenceAction::StateMutationObserved => "ok",
                EvidenceAction::AuthorityCheckObserved => "ok",
                EvidenceAction::AuthorityGapObserved => "ok",
                EvidenceAction::HypothesisTriggered => "ok",
            };
        }
    }
}

#[test]
fn evidence_chain_serializes() {
    let ir = make_test_ir();
    let evidence = EvidenceChain::derive_all(&ir);

    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let deserialized: Vec<EvidenceChain> = serde_json::from_str(&json).unwrap();

    assert_eq!(evidence.len(), deserialized.len());
}

// ─────────────────────────────────────────────────────────────
// 7. Full Export Contract Integration
// ─────────────────────────────────────────────────────────────

#[test]
fn full_export_contract() {
    let ir = make_test_ir();
    let output = SecurityIntelligenceOutput::build(&ir);

    // Validate contract
    let errors = output.validate();
    assert!(
        errors.is_empty(),
        "Contract validation failed: {:?}",
        errors
    );

    // Serialize
    let json = output.to_json();

    // Verify structure
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value.get("version").unwrap().as_str().unwrap(), "2.3");
    assert!(value.get("attack_surface").is_some());
    assert!(value.get("paths").is_some());
    assert!(value.get("risk_groups").is_some());
    assert!(value.get("cross_protocol").is_some());
    assert!(value.get("evidence").is_some());
    assert!(value.get("metadata").is_some());

    // Roundtrip
    let deserialized: SecurityIntelligenceOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, deserialized);
}
