#![allow(
    unused_imports,
    clippy::needless_update,
    clippy::match_like_matches_macro
)]

use digger_core::freeze::*;
/// Phase 3 Freeze Contract Tests
///
/// These tests enforce the Phase 3 freeze contract.
/// If any test fails, the freeze has been violated.
use digger_core::*;
use digger_graph::build_system_ir;
use digger_hypothesis::*;
use digger_ir::*;
use digger_parser::model::*;
use digger_surface::SecurityIntelligenceOutput;

fn make_test_ir() -> SystemIR {
    let program = RawProgram {
        functions: vec![
            RawFunction {
                name: "withdraw".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "(bool success, ) = msg.sender.call{value: amount}(\"\"); balances = new_balances".into(),
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
// 1. Freeze constants are correct
// ─────────────────────────────────────────────────────────────

#[test]
fn schema_version_locked() {
    assert_eq!(SCHEMA_VERSION, "2.3", "Schema version must remain 2.3");
}

#[test]
fn phase3_status_is_frozen() {
    assert_eq!(PHASE3_STATUS, "FROZEN");
}

#[test]
fn frozen_modules_documented() {
    assert_eq!(FROZEN_MODULES.len(), 4);
    assert!(FROZEN_MODULES.contains(&"digger-graph"));
    assert!(FROZEN_MODULES.contains(&"digger-hypothesis"));
    assert!(FROZEN_MODULES.contains(&"digger-surface"));
    assert!(FROZEN_MODULES.contains(&"digger-core"));
}

#[test]
fn frozen_schemas_documented() {
    assert_eq!(FROZEN_SCHEMAS.len(), 7);
}

#[test]
fn frozen_derivations_documented() {
    assert_eq!(FROZEN_DERIVATIONS.len(), 6);
}

// ─────────────────────────────────────────────────────────────
// 2. Hypothesis types frozen
// ─────────────────────────────────────────────────────────────

#[test]
fn hypothesis_types_count_frozen() {
    assert_eq!(FROZEN_HYPOTHESIS_TYPES.len(), 4);
}

#[test]
fn hypothesis_types_match_actual() {
    let ir = make_test_ir();
    let result = derive(&ir);

    let actual_types: Vec<String> = result
        .hypotheses
        .iter()
        .map(|h| format!("{:?}", h.hypothesis_type))
        .collect();

    // All hypothesis types must be from the frozen set
    for actual in &actual_types {
        let is_frozen = match actual.as_str() {
            "ReentrancyCandidate" => true,
            "AuthorityBypassCandidate" => true,
            "CPITrustViolationCandidate" => true,
            "StateCorruptionCandidate" => true,
            _ => false,
        };
        assert!(is_frozen, "Unknown hypothesis type: {}", actual);
    }
}

// ─────────────────────────────────────────────────────────────
// 3. Compound types frozen
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_types_count_frozen() {
    assert_eq!(FROZEN_COMPOUND_TYPES.len(), 4);
}

// ─────────────────────────────────────────────────────────────
// 4. Assumption types frozen
// ─────────────────────────────────────────────────────────────

#[test]
fn assumption_types_count_frozen() {
    assert_eq!(FROZEN_ASSUMPTION_TYPES.len(), 9);
}

// ─────────────────────────────────────────────────────────────
// 5. Inversion types frozen
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_types_count_frozen() {
    assert_eq!(FROZEN_INVERSION_TYPES.len(), 5);
}

// ─────────────────────────────────────────────────────────────
// 6. Verification types frozen
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_types_count_frozen() {
    assert_eq!(FROZEN_VERIFICATION_TYPES.len(), 8);
}

// ─────────────────────────────────────────────────────────────
// 7. Deterministic output across 5 runs
// ─────────────────────────────────────────────────────────────

#[test]
fn hypothesis_output_deterministic_5_runs() {
    let ir = make_test_ir();
    let results: Vec<String> = (0..5)
        .map(|_| serde_json::to_string(&derive(&ir)).unwrap())
        .collect();

    for i in 1..results.len() {
        assert_eq!(
            results[0], results[i],
            "Output must be identical across runs"
        );
    }
}

#[test]
fn compound_output_deterministic_5_runs() {
    let ir = make_test_ir();
    let hyp = derive(&ir);
    let results: Vec<String> = (0..5)
        .map(|_| serde_json::to_string(&derive_compound(&hyp)).unwrap())
        .collect();

    for i in 1..results.len() {
        assert_eq!(
            results[0], results[i],
            "Compound output must be identical across runs"
        );
    }
}

#[test]
fn assumption_output_deterministic_5_runs() {
    let ir = make_test_ir();
    let hyp = derive(&ir);
    let compound = derive_compound(&hyp);
    let results: Vec<String> = (0..5)
        .map(|_| serde_json::to_string(&derive_assumptions(&hyp, &compound)).unwrap())
        .collect();

    for i in 1..results.len() {
        assert_eq!(
            results[0], results[i],
            "Assumption output must be identical across runs"
        );
    }
}

#[test]
fn surface_output_deterministic_5_runs() {
    let ir = make_test_ir();
    let results: Vec<String> = (0..5)
        .map(|_| serde_json::to_string(&SecurityIntelligenceOutput::build(&ir)).unwrap())
        .collect();

    for i in 1..results.len() {
        assert_eq!(
            results[0], results[i],
            "Surface output must be identical across runs"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 8. No mutation of existing outputs
// ─────────────────────────────────────────────────────────────

#[test]
fn hypothesis_result_not_mutated_by_compound() {
    let ir = make_test_ir();
    let hyp = derive(&ir);
    let hyp_json = serde_json::to_string(&hyp).unwrap();

    let _compound = derive_compound(&hyp);

    assert_eq!(serde_json::to_string(&hyp).unwrap(), hyp_json);
}

#[test]
fn hypothesis_result_not_mutated_by_assumptions() {
    let ir = make_test_ir();
    let hyp = derive(&ir);
    let compound = derive_compound(&hyp);
    let hyp_json = serde_json::to_string(&hyp).unwrap();

    let _assumptions = derive_assumptions(&hyp, &compound);

    assert_eq!(serde_json::to_string(&hyp).unwrap(), hyp_json);
}

// ─────────────────────────────────────────────────────────────
// 9. Full roundtrip serialization stability
// ─────────────────────────────────────────────────────────────

#[test]
fn hypothesis_roundtrip_stable() {
    let ir = make_test_ir();
    let result = derive(&ir);

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: HypothesisResult = serde_json::from_str(&json).unwrap();

    assert_eq!(
        serde_json::to_string(&result).unwrap(),
        serde_json::to_string(&deserialized).unwrap()
    );
}

#[test]
fn surface_roundtrip_stable() {
    let ir = make_test_ir();
    let result = SecurityIntelligenceOutput::build(&ir);

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: SecurityIntelligenceOutput = serde_json::from_str(&json).unwrap();

    assert_eq!(
        serde_json::to_string(&result).unwrap(),
        serde_json::to_string(&deserialized).unwrap()
    );
}

// ─────────────────────────────────────────────────────────────
// 10. Phase 3 integrity validation
// ─────────────────────────────────────────────────────────────

#[test]
fn phase3_integrity_passes() {
    let result = validate_phase3_integrity();
    assert!(
        result.is_ok(),
        "Phase 3 integrity check failed: {:?}",
        result
    );
}

#[test]
fn schema_version_validation_passes() {
    let result = validate_schema_version();
    assert!(result.is_ok(), "Schema version check failed: {:?}", result);
}

#[test]
fn hypothesis_types_validation_passes() {
    let result = validate_hypothesis_types();
    assert!(
        result.is_ok(),
        "Hypothesis types check failed: {:?}",
        result
    );
}

#[test]
fn compound_types_validation_passes() {
    let result = validate_compound_types();
    assert!(result.is_ok(), "Compound types check failed: {:?}", result);
}

#[test]
fn assumption_types_validation_passes() {
    let result = validate_assumption_types();
    assert!(
        result.is_ok(),
        "Assumption types check failed: {:?}",
        result
    );
}

#[test]
fn inversion_types_validation_passes() {
    let result = validate_inversion_types();
    assert!(result.is_ok(), "Inversion types check failed: {:?}", result);
}

#[test]
fn verification_types_validation_passes() {
    let result = validate_verification_types();
    assert!(
        result.is_ok(),
        "Verification types check failed: {:?}",
        result
    );
}

#[test]
fn deterministic_outputs_validation_passes() {
    let ir = make_test_ir();
    let result = validate_deterministic_outputs(&ir);
    assert!(
        result.is_ok(),
        "Deterministic outputs check failed: {:?}",
        result
    );
}

// ─────────────────────────────────────────────────────────────
// 11. No AI / probabilistic systems
// ─────────────────────────────────────────────────────────────

#[test]
fn no_confidence_in_hypotheses() {
    let ir = make_test_ir();
    let result = derive(&ir);
    let json = serde_json::to_string(&result).unwrap();
    assert!(
        !json.contains("\"confidence\""),
        "Must not contain confidence scoring"
    );
}

#[test]
fn no_ranking_in_hypotheses() {
    let ir = make_test_ir();
    let result = derive(&ir);
    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains("\"rank\""), "Must not contain ranking");
}

#[test]
fn no_probability_in_hypotheses() {
    let ir = make_test_ir();
    let result = derive(&ir);
    let json = serde_json::to_string(&result).unwrap();
    assert!(
        !json.contains("\"probability\""),
        "Must not contain probability"
    );
}

// ─────────────────────────────────────────────────────────────
// 12. Schema version stability
// ─────────────────────────────────────────────────────────────

#[test]
fn surface_schema_version_matches() {
    assert_eq!(
        digger_surface::SCHEMA_VERSION,
        SCHEMA_VERSION,
        "Surface schema version must match core schema version"
    );
}
