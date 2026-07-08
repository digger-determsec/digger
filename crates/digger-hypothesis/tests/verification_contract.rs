#![allow(clippy::needless_update, clippy::useless_vec, clippy::len_zero)]
use digger_graph::build_system_ir;
/// Verification Task Engine Contract Tests — Phase 3.4
///
/// These tests enforce the verification task engine contract.
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

fn make_full_pipeline() -> (HypothesisResult, CompoundHypothesisResult, AssumptionResult) {
    let ir = make_test_ir();
    let hyp = derive(&ir);
    let compound = derive_compound(&hyp);
    let assumptions = derive_assumptions(&hyp, &compound);
    (hyp, compound, assumptions)
}

// ─────────────────────────────────────────────────────────────
// 1. Deterministic derivation
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_deterministic() {
    let (hyp, compound, assumptions) = make_full_pipeline();

    let r1 = derive_verification_tasks(&assumptions, &hyp, &compound);
    let r2 = derive_verification_tasks(&assumptions, &hyp, &compound);
    let r3 = derive_verification_tasks(&assumptions, &hyp, &compound);

    assert_eq!(r1.tasks.len(), r2.tasks.len());
    assert_eq!(r2.tasks.len(), r3.tasks.len());

    for i in 0..r1.tasks.len() {
        assert_eq!(r1.tasks[i].task_id, r2.tasks[i].task_id);
        assert_eq!(r1.tasks[i].task_type, r2.tasks[i].task_type);
    }
}

// ─────────────────────────────────────────────────────────────
// 2. Stable IDs
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_ids_stable() {
    let (hyp, compound, assumptions) = make_full_pipeline();

    let r1 = derive_verification_tasks(&assumptions, &hyp, &compound);
    let r2 = derive_verification_tasks(&assumptions, &hyp, &compound);

    for i in 0..r1.tasks.len() {
        assert_eq!(r1.tasks[i].task_id, r2.tasks[i].task_id);
    }
}

// ─────────────────────────────────────────────────────────────
// 3. Stable ordering
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_ordering_stable() {
    let (hyp, compound, assumptions) = make_full_pipeline();

    let r1 = derive_verification_tasks(&assumptions, &hyp, &compound);
    let r2 = derive_verification_tasks(&assumptions, &hyp, &compound);

    for i in 0..r1.tasks.len() {
        assert_eq!(r1.tasks[i].task_id, r2.tasks[i].task_id);
        assert_eq!(r1.tasks[i].task_type, r2.tasks[i].task_type);
    }
}

// ─────────────────────────────────────────────────────────────
// 4. Serialization stability
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_serialization_stable() {
    let (hyp, compound, assumptions) = make_full_pipeline();
    let result = derive_verification_tasks(&assumptions, &hyp, &compound);

    let json1 = serde_json::to_string_pretty(&result).unwrap();
    let json2 = serde_json::to_string_pretty(&result).unwrap();
    let json3 = serde_json::to_string_pretty(&result).unwrap();

    assert_eq!(json1, json2);
    assert_eq!(json2, json3);
}

// ─────────────────────────────────────────────────────────────
// 5. Roundtrip serialization
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_serialization_roundtrip() {
    let (hyp, compound, assumptions) = make_full_pipeline();
    let result = derive_verification_tasks(&assumptions, &hyp, &compound);

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: VerificationTaskResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.program_id, result.program_id);
    assert_eq!(deserialized.tasks.len(), result.tasks.len());
    assert_eq!(deserialized.summary.total, result.summary.total);

    for i in 0..result.tasks.len() {
        assert_eq!(deserialized.tasks[i].task_id, result.tasks[i].task_id);
        assert_eq!(deserialized.tasks[i].task_type, result.tasks[i].task_type);
    }
}

// ─────────────────────────────────────────────────────────────
// 6. Evidence completeness
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_evidence_complete() {
    let (hyp, compound, assumptions) = make_full_pipeline();
    let result = derive_verification_tasks(&assumptions, &hyp, &compound);

    for task in &result.tasks {
        assert!(!task.task_id.0.is_empty(), "Task ID must not be empty");
        assert!(
            !task.source_assumption_id.0.is_empty(),
            "Source assumption ID must not be empty"
        );
        assert!(
            !task.source_hypothesis_id.0.is_empty(),
            "Source hypothesis ID must not be empty"
        );
        assert!(
            !task.evidence_ids.is_empty(),
            "Evidence IDs must not be empty"
        );
        assert!(!task.title.is_empty(), "Title must not be empty");
        assert!(
            !task.description.is_empty(),
            "Description must not be empty"
        );
        assert!(
            !task.expected_validation.is_empty(),
            "Expected validation must not be empty"
        );
        assert!(
            !task.failure_implication.is_empty(),
            "Failure implication must not be empty"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 7. No input mutation
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_no_input_mutation() {
    let (hyp, compound, assumptions) = make_full_pipeline();

    let hyp_json_before = serde_json::to_string(&hyp).unwrap();
    let compound_json_before = serde_json::to_string(&compound).unwrap();
    let assumptions_json_before = serde_json::to_string(&assumptions).unwrap();

    let _result = derive_verification_tasks(&assumptions, &hyp, &compound);

    assert_eq!(serde_json::to_string(&hyp).unwrap(), hyp_json_before);
    assert_eq!(
        serde_json::to_string(&compound).unwrap(),
        compound_json_before
    );
    assert_eq!(
        serde_json::to_string(&assumptions).unwrap(),
        assumptions_json_before
    );
}

// ─────────────────────────────────────────────────────────────
// 8. Empty input behavior
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_inputs_produce_empty_tasks() {
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

    let result = derive_verification_tasks(&empty_assumptions, &empty_hyp, &empty_compound);
    assert_eq!(result.tasks.len(), 0);
    assert_eq!(result.summary.total, 0);
}

// ─────────────────────────────────────────────────────────────
// 9. Task generation correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn reentrancy_generates_correct_tasks() {
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
    let result = derive_verification_tasks(&assumptions, &hyp, &compound);

    let types: Vec<_> = result.tasks.iter().map(|t| &t.task_type).collect();

    assert!(
        types.contains(&&VerificationTaskType::VerifyExternalTargetControl),
        "Should have VerifyExternalTargetControl task"
    );
    assert!(
        types.contains(&&VerificationTaskType::VerifyReentrancyProtection),
        "Should have VerifyReentrancyProtection task"
    );
    assert!(
        types.contains(&&VerificationTaskType::VerifyStateMutationOrdering),
        "Should have VerifyStateMutationOrdering task"
    );
}

#[test]
fn authority_bypass_generates_correct_tasks() {
    let (hyp, compound, assumptions) = make_full_pipeline();
    let result = derive_verification_tasks(&assumptions, &hyp, &compound);

    let types: Vec<_> = result.tasks.iter().map(|t| &t.task_type).collect();

    assert!(
        types.contains(&&VerificationTaskType::VerifyAuthorityEnforcement),
        "Should have VerifyAuthorityEnforcement task"
    );
    assert!(
        types.contains(&&VerificationTaskType::VerifyCallerRestrictions),
        "Should have VerifyCallerRestrictions task"
    );
}

// ─────────────────────────────────────────────────────────────
// 10. Expected validation present
// ─────────────────────────────────────────────────────────────

#[test]
fn all_tasks_have_expected_validation() {
    let (hyp, compound, assumptions) = make_full_pipeline();
    let result = derive_verification_tasks(&assumptions, &hyp, &compound);

    for task in &result.tasks {
        assert!(
            !task.expected_validation.is_empty(),
            "Task {} must have expected validation",
            task.task_id
        );
        assert!(
            task.expected_validation.len() > 10,
            "Expected validation must be meaningful for {}",
            task.task_id
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 11. Failure implication present
// ─────────────────────────────────────────────────────────────

#[test]
fn all_tasks_have_failure_implication() {
    let (hyp, compound, assumptions) = make_full_pipeline();
    let result = derive_verification_tasks(&assumptions, &hyp, &compound);

    for task in &result.tasks {
        assert!(
            !task.failure_implication.is_empty(),
            "Task {} must have failure implication",
            task.task_id
        );
        assert!(
            task.failure_implication.len() > 10,
            "Failure implication must be meaningful for {}",
            task.task_id
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 12. Summary correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_summary_correct() {
    let (hyp, compound, assumptions) = make_full_pipeline();
    let result = derive_verification_tasks(&assumptions, &hyp, &compound);

    assert_eq!(result.summary.total, result.tasks.len());
    assert_eq!(
        result.summary.verify_external_target_control
            + result.summary.verify_reentrancy_protection
            + result.summary.verify_authority_enforcement
            + result.summary.verify_state_mutation_ordering
            + result.summary.verify_shared_state_coordination
            + result.summary.verify_cpi_trust_boundary
            + result.summary.verify_caller_restrictions
            + result.summary.verify_single_writer_guarantee,
        result.summary.total
    );
}

// ─────────────────────────────────────────────────────────────
// 13. No confidence scoring
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_no_confidence_scoring() {
    let (hyp, compound, assumptions) = make_full_pipeline();
    let result = derive_verification_tasks(&assumptions, &hyp, &compound);

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
// 14. TaskType variants stable
// ─────────────────────────────────────────────────────────────

#[test]
fn verification_task_type_variants_stable() {
    let types = vec![
        VerificationTaskType::VerifyExternalTargetControl,
        VerificationTaskType::VerifyReentrancyProtection,
        VerificationTaskType::VerifyAuthorityEnforcement,
        VerificationTaskType::VerifyStateMutationOrdering,
        VerificationTaskType::VerifySharedStateCoordination,
        VerificationTaskType::VerifyCPITrustBoundary,
        VerificationTaskType::VerifyCallerRestrictions,
        VerificationTaskType::VerifySingleWriterGuarantee,
    ];
    assert_eq!(types.len(), 8);
}

// ─────────────────────────────────────────────────────────────
// 15. Each assumption produces exactly one task
// ─────────────────────────────────────────────────────────────

#[test]
fn one_task_per_assumption() {
    let (hyp, compound, assumptions) = make_full_pipeline();
    let result = derive_verification_tasks(&assumptions, &hyp, &compound);

    assert_eq!(
        result.tasks.len(),
        assumptions.all_assumptions.len(),
        "Each assumption should produce exactly one verification task"
    );
}
