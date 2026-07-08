#![allow(clippy::needless_update, clippy::useless_vec, clippy::len_zero)]
use digger_graph::build_system_ir;
/// Research Session Engine Contract Tests — Phase 3.6
///
/// These tests enforce the research session engine contract.
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
    InversionResult,
) {
    let ir = make_test_ir();
    let hyp = derive(&ir);
    let compound = derive_compound(&hyp);
    let assumptions = derive_assumptions(&hyp, &compound);
    let verification = derive_verification_tasks(&assumptions, &hyp, &compound);
    let inversions = derive_inversions(&assumptions, &verification, &hyp);
    (hyp, compound, assumptions, verification, inversions)
}

// ─────────────────────────────────────────────────────────────
// 1. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn session_deterministic() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();

    let r1 = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);
    let r2 = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);
    let r3 = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

    assert_eq!(
        r1.session.investigations.len(),
        r2.session.investigations.len()
    );
    assert_eq!(
        r2.session.investigations.len(),
        r3.session.investigations.len()
    );

    for i in 0..r1.session.investigations.len() {
        assert_eq!(
            r1.session.investigations[i].investigation_id,
            r2.session.investigations[i].investigation_id
        );
        assert_eq!(
            r1.session.investigations[i].primary_function,
            r2.session.investigations[i].primary_function
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 2. Stable IDs
// ─────────────────────────────────────────────────────────────

#[test]
fn session_ids_stable() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();

    let r1 = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);
    let r2 = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

    assert_eq!(r1.session.session_id, r2.session.session_id);
    for i in 0..r1.session.investigations.len() {
        assert_eq!(
            r1.session.investigations[i].investigation_id,
            r2.session.investigations[i].investigation_id
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 3. Stable serialization
// ─────────────────────────────────────────────────────────────

#[test]
fn session_serialization_stable() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();
    let result = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

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
fn session_serialization_roundtrip() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();
    let result = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: ResearchSessionResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.session.program_id, result.session.program_id);
    assert_eq!(
        deserialized.session.investigations.len(),
        result.session.investigations.len()
    );
}

// ─────────────────────────────────────────────────────────────
// 5. Evidence completeness
// ─────────────────────────────────────────────────────────────

#[test]
fn session_evidence_complete() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();
    let result = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

    for inv in &result.session.investigations {
        assert!(
            !inv.investigation_id.0.is_empty(),
            "Investigation ID must not be empty"
        );
        assert!(
            !inv.primary_function.is_empty(),
            "Primary function must not be empty"
        );

        // Every investigation must have at least one artifact
        let total_artifacts = inv.findings.len()
            + inv.hypotheses.len()
            + inv.assumptions.len()
            + inv.verification_tasks.len()
            + inv.inversions.len();
        assert!(
            total_artifacts > 0,
            "Investigation {} must have at least one artifact",
            inv.investigation_id
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 6. Summary correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn session_summary_correct() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();
    let result = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

    let summary = &result.session.summary;
    assert_eq!(
        summary.total_investigations,
        result.session.investigations.len()
    );

    // Sum of per-investigation counts should match session totals
    let total_hyp: usize = result
        .session
        .investigations
        .iter()
        .map(|i| i.summary.total_hypotheses)
        .sum();
    assert_eq!(summary.total_hypotheses, total_hyp);

    let total_assumptions: usize = result
        .session
        .investigations
        .iter()
        .map(|i| i.summary.total_assumptions)
        .sum();
    assert_eq!(summary.total_assumptions, total_assumptions);
}

// ─────────────────────────────────────────────────────────────
// 7. No input mutation
// ─────────────────────────────────────────────────────────────

#[test]
fn session_no_input_mutation() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();

    let hyp_json = serde_json::to_string(&hyp).unwrap();
    let compound_json = serde_json::to_string(&compound).unwrap();
    let assumptions_json = serde_json::to_string(&assumptions).unwrap();
    let verification_json = serde_json::to_string(&verification).unwrap();
    let inversions_json = serde_json::to_string(&inversions).unwrap();

    let _result = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

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
    assert_eq!(serde_json::to_string(&inversions).unwrap(), inversions_json);
}

// ─────────────────────────────────────────────────────────────
// 8. Investigation grouping correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn investigations_grouped_by_function() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();
    let result = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

    // Each investigation should be for a unique primary function
    let functions: Vec<_> = result
        .session
        .investigations
        .iter()
        .map(|i| &i.primary_function)
        .collect();

    // Check no duplicates
    for i in 0..functions.len() {
        for j in (i + 1)..functions.len() {
            assert_ne!(
                functions[i], functions[j],
                "Duplicate investigation for function '{}'",
                functions[i]
            );
        }
    }
}

#[test]
fn artifacts_belong_to_investigations() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();
    let result = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

    // Every hypothesis should appear in at least one investigation
    for h in &hyp.hypotheses {
        let assigned = result
            .session
            .investigations
            .iter()
            .any(|inv| inv.hypotheses.iter().any(|r| r.id == h.id));
        assert!(
            assigned,
            "Hypothesis {} must belong to an investigation",
            h.id
        );
    }

    // Every assumption should appear in at least one investigation
    for a in &assumptions.all_assumptions {
        let assigned = result
            .session
            .investigations
            .iter()
            .any(|inv| inv.assumptions.iter().any(|r| r.id == a.id));
        assert!(
            assigned,
            "Assumption {} must belong to an investigation",
            a.id
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 9. Ordering stability
// ─────────────────────────────────────────────────────────────

#[test]
fn session_ordering_stable() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();

    let r1 = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);
    let r2 = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

    for i in 0..r1.session.investigations.len() {
        assert_eq!(
            r1.session.investigations[i].primary_function,
            r2.session.investigations[i].primary_function
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 10. Empty input handling
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_inputs_produce_empty_session() {
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

    let empty_inversions = InversionResult {
        program_id: "empty".into(),
        inversions: vec![],
        summary: InversionSummary {
            total: 0,
            invalidate_reentrancy: 0,
            invalidate_authority_bypass: 0,
            invalidate_cpi_trust_violation: 0,
            invalidate_state_corruption: 0,
            invalidate_caller_influence: 0,
        },
    };

    let result = derive_session(
        &empty_hyp,
        &empty_compound,
        &empty_assumptions,
        &empty_verification,
        &empty_inversions,
    );
    assert_eq!(result.session.investigations.len(), 0);
    assert_eq!(result.session.summary.total_investigations, 0);
}

// ─────────────────────────────────────────────────────────────
// 11. No confidence scoring
// ─────────────────────────────────────────────────────────────

#[test]
fn session_no_confidence_scoring() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();
    let result = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

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
// 12. No ranking logic
// ─────────────────────────────────────────────────────────────

#[test]
fn session_no_ranking() {
    let (hyp, compound, assumptions, verification, inversions) = make_full_pipeline();
    let result = derive_session(&hyp, &compound, &assumptions, &verification, &inversions);

    // Investigations should be ordered alphabetically by function name, not by severity
    if result.session.investigations.len() >= 2 {
        let names: Vec<_> = result
            .session
            .investigations
            .iter()
            .map(|i| i.primary_function.as_str())
            .collect();
        let mut sorted_names = names.clone();
        sorted_names.sort();
        assert_eq!(
            names, sorted_names,
            "Investigations should be sorted alphabetically"
        );
    }
}
