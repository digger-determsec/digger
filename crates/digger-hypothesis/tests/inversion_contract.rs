#![allow(clippy::needless_update, clippy::useless_vec, clippy::len_zero)]
use digger_graph::build_system_ir;
/// Inversion Engine Contract Tests — Phase 3.5
///
/// These tests enforce the inversion engine contract.
/// If any test fails, the contract has been broken.
use digger_hypothesis::*;
use digger_ir::*;
use digger_parser::model::*;

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

fn make_full_pipeline() -> (
    HypothesisResult,
    CompoundHypothesisResult,
    AssumptionResult,
    VerificationTaskResult,
) {
    let ir = make_test_ir();
    let hyp = derive(&ir);
    let compound = derive_compound(&hyp);
    let assumptions = derive_assumptions(&hyp, &compound);
    let verification = derive_verification_tasks(&assumptions, &hyp, &compound);
    (hyp, compound, assumptions, verification)
}

// ─────────────────────────────────────────────────────────────
// 1. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_deterministic() {
    let (_, _, assumptions, verification, hyp) = {
        let (h, c, a, v) = make_full_pipeline();
        (h.clone(), c.clone(), a, v, h)
    };
    let hyp_ref = &hyp;

    let r1 = derive_inversions(&assumptions, &verification, hyp_ref);
    let r2 = derive_inversions(&assumptions, &verification, hyp_ref);
    let r3 = derive_inversions(&assumptions, &verification, hyp_ref);

    assert_eq!(r1.inversions.len(), r2.inversions.len());
    assert_eq!(r2.inversions.len(), r3.inversions.len());

    for i in 0..r1.inversions.len() {
        assert_eq!(r1.inversions[i].id, r2.inversions[i].id);
        assert_eq!(
            r1.inversions[i].inversion_type,
            r2.inversions[i].inversion_type
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 2. Stable IDs
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_ids_stable() {
    let (hyp, _, assumptions, verification) = make_full_pipeline();

    let r1 = derive_inversions(&assumptions, &verification, &hyp);
    let r2 = derive_inversions(&assumptions, &verification, &hyp);

    for i in 0..r1.inversions.len() {
        assert_eq!(r1.inversions[i].id, r2.inversions[i].id);
    }
}

// ─────────────────────────────────────────────────────────────
// 3. Stable serialization
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_serialization_stable() {
    let (hyp, _, assumptions, verification) = make_full_pipeline();
    let result = derive_inversions(&assumptions, &verification, &hyp);

    let json1 = serde_json::to_string_pretty(&result).unwrap();
    let json2 = serde_json::to_string_pretty(&result).unwrap();
    let json3 = serde_json::to_string_pretty(&result).unwrap();

    assert_eq!(json1, json2);
    assert_eq!(json2, json3);
}

// ─────────────────────────────────────────────────────────────
// 4. Roundtrip serialization
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_serialization_roundtrip() {
    let (hyp, _, assumptions, verification) = make_full_pipeline();
    let result = derive_inversions(&assumptions, &verification, &hyp);

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: InversionResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.program_id, result.program_id);
    assert_eq!(deserialized.inversions.len(), result.inversions.len());
    assert_eq!(deserialized.summary.total, result.summary.total);

    for i in 0..result.inversions.len() {
        assert_eq!(deserialized.inversions[i].id, result.inversions[i].id);
        assert_eq!(
            deserialized.inversions[i].inversion_type,
            result.inversions[i].inversion_type
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 5. No input mutation
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_no_input_mutation() {
    let (hyp, compound, assumptions, verification) = make_full_pipeline();

    let hyp_json = serde_json::to_string(&hyp).unwrap();
    let compound_json = serde_json::to_string(&compound).unwrap();
    let assumptions_json = serde_json::to_string(&assumptions).unwrap();
    let verification_json = serde_json::to_string(&verification).unwrap();

    let _result = derive_inversions(&assumptions, &verification, &hyp);

    assert_eq!(serde_json::to_string(&hyp).unwrap(), hyp_json);
    assert_eq!(serde_json::to_string(&compound).unwrap(), compound_json);
    assert_eq!(
        serde_json::to_string(&assumptions).unwrap(),
        assumptions_json
    );
    assert_eq!(
        serde_json::to_string(&verification).unwrap(),
        verification_json
    );
}

// ─────────────────────────────────────────────────────────────
// 6. Evidence completeness
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_evidence_complete() {
    let (hyp, _, assumptions, verification) = make_full_pipeline();
    let result = derive_inversions(&assumptions, &verification, &hyp);

    for inversion in &result.inversions {
        assert!(!inversion.id.0.is_empty(), "Inversion ID must not be empty");
        assert!(
            !inversion.source_hypothesis_id.0.is_empty(),
            "Source hypothesis ID must not be empty"
        );
        assert!(
            !inversion.source_assumption_ids.is_empty(),
            "Source assumption IDs must not be empty"
        );
        assert!(
            !inversion.invalidating_condition.is_empty(),
            "Invalidating condition must not be empty"
        );
        assert!(
            !inversion.explanation.is_empty(),
            "Explanation must not be empty"
        );
        assert!(
            !inversion.evidence_ids.is_empty(),
            "Evidence IDs must not be empty"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 7. Summary correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_summary_correct() {
    let (hyp, _, assumptions, verification) = make_full_pipeline();
    let result = derive_inversions(&assumptions, &verification, &hyp);

    assert_eq!(result.summary.total, result.inversions.len());
    assert_eq!(
        result.summary.invalidate_reentrancy
            + result.summary.invalidate_authority_bypass
            + result.summary.invalidate_cpi_trust_violation
            + result.summary.invalidate_state_corruption
            + result.summary.invalidate_caller_influence,
        result.summary.total
    );
}

// ─────────────────────────────────────────────────────────────
// 8. Empty input handling
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_inputs_produce_empty_inversions() {
    let empty_assumptions = AssumptionResult {
        program_id: "empty".into(),
        assumption_sets: vec![],
        all_assumptions: vec![],
        summary: AssumptionSummary {
            total: 0,
            external_target_controlled: 0,
            reentrant_execution_possible: 0,
            authority_check_absent: 0,
            shared_state_mutable: 0,
            cpi_trust_required: 0,
            state_mutation_after_call: 0,
            multiple_writers_exist: 0,
            coordination_missing: 0,
            caller_influence_possible: 0,
        },
    };

    let empty_verification = VerificationTaskResult {
        program_id: "empty".into(),
        tasks: vec![],
        summary: VerificationSummary {
            total: 0,
            verify_external_target_control: 0,
            verify_reentrancy_protection: 0,
            verify_authority_enforcement: 0,
            verify_state_mutation_ordering: 0,
            verify_shared_state_coordination: 0,
            verify_cpi_trust_boundary: 0,
            verify_caller_restrictions: 0,
            verify_single_writer_guarantee: 0,
        },
    };

    let empty_hyp = HypothesisResult {
        program_id: "empty".into(),
        hypotheses: vec![],
        summary: HypothesisSummary {
            total: 0,
            reentrancy_count: 0,
            authority_bypass_count: 0,
            cpi_trust_count: 0,
            state_corruption_count: 0,
            economic_invariant_violation_count: 0,
            adversarial_path_count: 0,
            oracle_manipulation_count: 0,
            flash_loan_governance_count: 0,
            missing_account_constraint_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
        },
    };

    let result = derive_inversions(&empty_assumptions, &empty_verification, &empty_hyp);
    assert_eq!(result.inversions.len(), 0);
    assert_eq!(result.summary.total, 0);
}

// ─────────────────────────────────────────────────────────────
// 9. Inversion ordering stability
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_ordering_stable() {
    let (hyp, _, assumptions, verification) = make_full_pipeline();

    let r1 = derive_inversions(&assumptions, &verification, &hyp);
    let r2 = derive_inversions(&assumptions, &verification, &hyp);

    for i in 0..r1.inversions.len() {
        assert_eq!(r1.inversions[i].id, r2.inversions[i].id);
        assert_eq!(
            r1.inversions[i].inversion_type,
            r2.inversions[i].inversion_type
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 10. Inversion type stability
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_type_variants_stable() {
    let types = vec![
        InversionType::InvalidateReentrancy,
        InversionType::InvalidateAuthorityBypass,
        InversionType::InvalidateCPITrustViolation,
        InversionType::InvalidateStateCorruption,
        InversionType::InvalidateCallerInfluence,
    ];
    assert_eq!(types.len(), 5);
}

// ─────────────────────────────────────────────────────────────
// 11. No confidence scoring
// ─────────────────────────────────────────────────────────────

#[test]
fn inversion_no_confidence_scoring() {
    let (hyp, _, assumptions, verification) = make_full_pipeline();
    let result = derive_inversions(&assumptions, &verification, &hyp);

    let json = serde_json::to_string(&result).unwrap();
    assert!(
        !json.contains("\"confidence\""),
        "Must not contain confidence scoring"
    );
    assert!(!json.contains("\"rank\""), "Must not contain ranking");
    assert!(
        !json.contains("\"probability\""),
        "Must not contain probability"
    );
}

// ─────────────────────────────────────────────────────────────
// 12. Reentrancy inversions derived correctly
// ─────────────────────────────────────────────────────────────

#[test]
fn reentrancy_inversions_derived() {
    let program = RawProgram {
        functions: vec![RawFunction {
            name: "withdraw".into(),
            visibility: "public".into(),
            inputs: vec![],
            body:
                "(bool success, ) = msg.sender.call{value: amount}(\"\"); balances = new_balances"
                    .into(),
            ..Default::default()
        }],
        state: vec![RawState {
            name: "balances".into(),
            ty: "mapping".into(),
            ..Default::default()
        }],
        calls: vec![RawCall {
            from: "withdraw".into(),
            to: "external".into(),
            kind: CallKind::External,
        }],
        ..Default::default()
    };
    let ir = build_system_ir(program);
    let hyp = derive(&ir);
    let compound = derive_compound(&hyp);
    let assumptions = derive_assumptions(&hyp, &compound);
    let verification = derive_verification_tasks(&assumptions, &hyp, &compound);
    let result = derive_inversions(&assumptions, &verification, &hyp);

    let types: Vec<_> = result
        .inversions
        .iter()
        .map(|i| &i.inversion_type)
        .collect();

    assert!(
        types.contains(&&InversionType::InvalidateReentrancy),
        "Should have InvalidateReentrancy inversion"
    );

    // Check that reentrancy inversions have correct invalidating conditions
    let reentrancy_inv: Vec<_> = result
        .inversions
        .iter()
        .filter(|i| i.inversion_type == InversionType::InvalidateReentrancy)
        .collect();

    for inv in &reentrancy_inv {
        assert!(
            inv.invalidating_condition.contains("reentrancy guard")
                || inv.invalidating_condition.contains("Reentrancy guard")
                || inv.invalidating_condition.contains("state is updated")
                || inv.invalidating_condition.contains("State")
                || inv
                    .invalidating_condition
                    .contains("checks-effects-interactions")
                || inv.invalidating_condition.contains("CEI")
                || inv.invalidating_condition.contains("pull-payment")
                || inv.invalidating_condition.contains("external call target")
                || inv.invalidating_condition.contains("External"),
            "Reentrancy inversion should reference protection mechanisms"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 13. Authority bypass inversions derived correctly
// ─────────────────────────────────────────────────────────────

#[test]
fn authority_bypass_inversions_derived() {
    let (hyp, _, assumptions, verification) = make_full_pipeline();
    let result = derive_inversions(&assumptions, &verification, &hyp);

    let types: Vec<_> = result
        .inversions
        .iter()
        .map(|i| &i.inversion_type)
        .collect();

    assert!(
        types.contains(&&InversionType::InvalidateAuthorityBypass),
        "Should have InvalidateAuthorityBypass inversion"
    );

    let auth_inv: Vec<_> = result
        .inversions
        .iter()
        .filter(|i| i.inversion_type == InversionType::InvalidateAuthorityBypass)
        .collect();

    for inv in &auth_inv {
        assert!(
            inv.invalidating_condition.contains("Authority")
                || inv.invalidating_condition.contains("authority")
                || inv.invalidating_condition.contains("require")
                || inv.invalidating_condition.contains("Signer")
                || inv.invalidating_condition.contains("access control"),
            "Authority inversion should reference authority mechanisms"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 14. One inversion per assumption
// ─────────────────────────────────────────────────────────────

#[test]
fn one_inversion_per_assumption() {
    let (hyp, _, assumptions, verification) = make_full_pipeline();
    let result = derive_inversions(&assumptions, &verification, &hyp);

    assert_eq!(
        result.inversions.len(),
        assumptions.all_assumptions.len(),
        "Each assumption should produce exactly one inversion"
    );
}
