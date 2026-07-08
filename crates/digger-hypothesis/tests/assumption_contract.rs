#![allow(clippy::needless_update, clippy::useless_vec, clippy::len_zero)]
use digger_graph::build_system_ir;
/// Assumption Engine Contract Tests — Phase 3.3
///
/// These tests enforce the assumption engine contract.
/// If any test fails, the contract has been broken.
use digger_hypothesis::*;
use digger_ir::*;
use digger_parser::model::*;

/// Build IR with multiple hypothesis types.
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

fn make_full_result() -> (HypothesisResult, CompoundHypothesisResult) {
    let ir = make_test_ir();
    let hyp = derive(&ir);
    let compound = derive_compound(&hyp);
    (hyp, compound)
}

// ─────────────────────────────────────────────────────────────
// 1. Deterministic derivation
// ─────────────────────────────────────────────────────────────

#[test]
fn assumptions_deterministic() {
    let (hyp, compound) = make_full_result();

    let r1 = derive_assumptions(&hyp, &compound);
    let r2 = derive_assumptions(&hyp, &compound);
    let r3 = derive_assumptions(&hyp, &compound);

    assert_eq!(r1.all_assumptions.len(), r2.all_assumptions.len());
    assert_eq!(r2.all_assumptions.len(), r3.all_assumptions.len());

    for i in 0..r1.all_assumptions.len() {
        assert_eq!(r1.all_assumptions[i].id, r2.all_assumptions[i].id);
        assert_eq!(
            r1.all_assumptions[i].assumption_type,
            r2.all_assumptions[i].assumption_type
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 2. Stable IDs
// ─────────────────────────────────────────────────────────────

#[test]
fn assumption_ids_stable() {
    let (hyp, compound) = make_full_result();

    let r1 = derive_assumptions(&hyp, &compound);
    let r2 = derive_assumptions(&hyp, &compound);

    for i in 0..r1.all_assumptions.len() {
        assert_eq!(r1.all_assumptions[i].id, r2.all_assumptions[i].id);
    }
}

// ─────────────────────────────────────────────────────────────
// 3. Stable serialization
// ─────────────────────────────────────────────────────────────

#[test]
fn assumption_serialization_stable() {
    let (hyp, compound) = make_full_result();
    let result = derive_assumptions(&hyp, &compound);

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
fn assumption_serialization_roundtrip() {
    let (hyp, compound) = make_full_result();
    let result = derive_assumptions(&hyp, &compound);

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: AssumptionResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.program_id, result.program_id);
    assert_eq!(
        deserialized.all_assumptions.len(),
        result.all_assumptions.len()
    );
    assert_eq!(deserialized.summary.total, result.summary.total);

    for i in 0..result.all_assumptions.len() {
        assert_eq!(
            deserialized.all_assumptions[i].id,
            result.all_assumptions[i].id
        );
        assert_eq!(
            deserialized.all_assumptions[i].assumption_type,
            result.all_assumptions[i].assumption_type
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 5. Evidence completeness
// ─────────────────────────────────────────────────────────────

#[test]
fn assumptions_evidence_complete() {
    let (hyp, compound) = make_full_result();
    let result = derive_assumptions(&hyp, &compound);

    for assumption in &result.all_assumptions {
        assert!(
            !assumption.id.0.is_empty(),
            "Assumption ID must not be empty"
        );
        assert!(
            !assumption.source_hypothesis_id.0.is_empty(),
            "Source hypothesis ID must not be empty"
        );
        assert!(
            !assumption.supporting_evidence_ids.is_empty(),
            "Supporting evidence IDs must not be empty"
        );
        assert!(
            !assumption.explanation.is_empty(),
            "Explanation must not be empty"
        );
        assert!(
            !assumption.invalidation_condition.is_empty(),
            "Invalidation condition must not be empty"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 6. No mutation of inputs
// ─────────────────────────────────────────────────────────────

#[test]
fn assumptions_no_input_mutation() {
    let (hyp, compound) = make_full_result();

    let hyp_json_before = serde_json::to_string(&hyp).unwrap();
    let compound_json_before = serde_json::to_string(&compound).unwrap();

    let _result = derive_assumptions(&hyp, &compound);

    let hyp_json_after = serde_json::to_string(&hyp).unwrap();
    let compound_json_after = serde_json::to_string(&compound).unwrap();

    assert_eq!(
        hyp_json_before, hyp_json_after,
        "HypothesisResult must not be modified"
    );
    assert_eq!(
        compound_json_before, compound_json_after,
        "CompoundHypothesisResult must not be modified"
    );
}

// ─────────────────────────────────────────────────────────────
// 7. Invalidation conditions present
// ─────────────────────────────────────────────────────────────

#[test]
fn all_assumptions_have_invalidation_conditions() {
    let (hyp, compound) = make_full_result();
    let result = derive_assumptions(&hyp, &compound);

    for assumption in &result.all_assumptions {
        assert!(
            !assumption.invalidation_condition.is_empty(),
            "Assumption {} must have invalidation condition",
            assumption.id
        );
        assert!(
            assumption.invalidation_condition.len() > 10,
            "Invalidation condition must be meaningful for {}",
            assumption.id
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 8. Assumption ordering stability
// ─────────────────────────────────────────────────────────────

#[test]
fn assumption_ordering_stable() {
    let (hyp, compound) = make_full_result();

    let r1 = derive_assumptions(&hyp, &compound);
    let r2 = derive_assumptions(&hyp, &compound);

    for i in 0..r1.all_assumptions.len() {
        assert_eq!(r1.all_assumptions[i].id, r2.all_assumptions[i].id);
        assert_eq!(
            r1.all_assumptions[i].assumption_type,
            r2.all_assumptions[i].assumption_type
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 9. Empty input behavior
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_inputs_produce_empty_assumptions() {
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

    let empty_compound = CompoundHypothesisResult {
        program_id: "empty".into(),
        compound_hypotheses: vec![],
        summary: CompoundHypothesisSummary {
            total: 0,
            reentrancy_authority_count: 0,
            cpi_authority_count: 0,
            state_corruption_count: 0,
            multi_path_count: 0,
        },
    };

    let result = derive_assumptions(&empty_hyp, &empty_compound);
    assert_eq!(result.all_assumptions.len(), 0);
    assert_eq!(result.summary.total, 0);
}

// ─────────────────────────────────────────────────────────────
// 10. Assumption types are correct per hypothesis type
// ─────────────────────────────────────────────────────────────

#[test]
fn reentrancy_hypothesis_generates_correct_assumptions() {
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
    let result = derive_assumptions(&hyp, &compound);

    // Should have ExternalTargetControlled, ReentrantExecutionPossible, StateMutationAfterCall
    let types: Vec<_> = result
        .all_assumptions
        .iter()
        .map(|a| &a.assumption_type)
        .collect();

    assert!(
        types.contains(&&AssumptionType::ExternalTargetControlled),
        "Should have ExternalTargetControlled assumption"
    );
    assert!(
        types.contains(&&AssumptionType::ReentrantExecutionPossible),
        "Should have ReentrantExecutionPossible assumption"
    );
    assert!(
        types.contains(&&AssumptionType::StateMutationAfterCall),
        "Should have StateMutationAfterCall assumption"
    );
}

#[test]
fn authority_bypass_generates_correct_assumptions() {
    let (hyp, compound) = make_full_result();
    let result = derive_assumptions(&hyp, &compound);

    let types: Vec<_> = result
        .all_assumptions
        .iter()
        .map(|a| &a.assumption_type)
        .collect();

    assert!(
        types.contains(&&AssumptionType::AuthorityCheckAbsent),
        "Should have AuthorityCheckAbsent assumption"
    );
    assert!(
        types.contains(&&AssumptionType::CallerInfluencePossible),
        "Should have CallerInfluencePossible assumption"
    );
}

// ─────────────────────────────────────────────────────────────
// 11. Summary correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn assumption_summary_correct() {
    let (hyp, compound) = make_full_result();
    let result = derive_assumptions(&hyp, &compound);

    assert_eq!(result.summary.total, result.all_assumptions.len());
    assert_eq!(
        result.summary.external_target_controlled
            + result.summary.reentrant_execution_possible
            + result.summary.authority_check_absent
            + result.summary.shared_state_mutable
            + result.summary.cpi_trust_required
            + result.summary.state_mutation_after_call
            + result.summary.multiple_writers_exist
            + result.summary.coordination_missing
            + result.summary.caller_influence_possible,
        result.summary.total
    );
}

// ─────────────────────────────────────────────────────────────
// 12. No confidence scoring
// ─────────────────────────────────────────────────────────────

#[test]
fn assumptions_no_confidence_scoring() {
    let (hyp, compound) = make_full_result();
    let result = derive_assumptions(&hyp, &compound);

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
// 13. AssumptionType variants stable
// ─────────────────────────────────────────────────────────────

#[test]
fn assumption_type_variants_stable() {
    let types = vec![
        AssumptionType::ExternalTargetControlled,
        AssumptionType::ReentrantExecutionPossible,
        AssumptionType::AuthorityCheckAbsent,
        AssumptionType::SharedStateMutable,
        AssumptionType::CPITrustRequired,
        AssumptionType::StateMutationAfterCall,
        AssumptionType::MultipleWritersExist,
        AssumptionType::CoordinationMissing,
        AssumptionType::CallerInfluencePossible,
    ];
    assert_eq!(types.len(), 9);
}
