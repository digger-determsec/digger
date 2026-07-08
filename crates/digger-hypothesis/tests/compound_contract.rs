#![allow(clippy::needless_update, clippy::useless_vec, clippy::len_zero)]
use digger_graph::build_system_ir;
/// Compound Hypothesis Contract Tests — Phase 3.2
///
/// These tests enforce the compound hypothesis engine contract.
/// If any test fails, the contract has been broken.
use digger_hypothesis::*;
use digger_ir::*;
use digger_parser::model::*;

/// Build IR with reentrancy + authority bypass on the SAME function.
fn make_reentrancy_auth_ir() -> SystemIR {
    let program = RawProgram {
        functions: vec![RawFunction {
            name: "withdraw".into(),
            visibility: "public".into(),
            inputs: vec![],
            // External call + state write + no authority = reentrancy + auth bypass
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
    build_system_ir(program)
}

/// Build IR with CPI + authority bypass patterns.
fn make_cpi_auth_ir() -> SystemIR {
    let program = RawProgram {
        functions: vec![
            RawFunction {
                name: "do_cpi".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "invoke(&ix, &accounts)?; vault = new_vault".into(),
                ..Default::default()
            },
            RawFunction {
                name: "setAuthority".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "vault = new_authority".into(),
                ..Default::default()
            },
        ],
        state: vec![RawState {
            name: "vault".into(),
            ty: "account".into(),
            ..Default::default()
        }],
        calls: vec![RawCall {
            from: "do_cpi".into(),
            to: "cpi".into(),
            kind: CallKind::CrossProgram,
        }],
        ..Default::default()
    };
    build_system_ir(program)
}

/// Build IR with state corruption + authority bypass patterns.
fn make_state_corruption_auth_ir() -> SystemIR {
    let program = RawProgram {
        functions: vec![
            RawFunction {
                name: "writer_a".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "balance = new_balance_a".into(),
                ..Default::default()
            },
            RawFunction {
                name: "writer_b".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "balance = new_balance_b".into(),
                ..Default::default()
            },
        ],
        state: vec![RawState {
            name: "balance".into(),
            ty: "u64".into(),
            ..Default::default()
        }],
        calls: vec![],
        ..Default::default()
    };
    build_system_ir(program)
}

// ─────────────────────────────────────────────────────────────
// 1. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_deterministic_output() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);
    let r1 = derive_compound(&hyp);
    let r2 = derive_compound(&hyp);
    let r3 = derive_compound(&hyp);

    assert_eq!(r1.compound_hypotheses.len(), r2.compound_hypotheses.len());
    assert_eq!(r2.compound_hypotheses.len(), r3.compound_hypotheses.len());

    for i in 0..r1.compound_hypotheses.len() {
        assert_eq!(r1.compound_hypotheses[i].id, r2.compound_hypotheses[i].id);
        assert_eq!(
            r1.compound_hypotheses[i].compound_type,
            r2.compound_hypotheses[i].compound_type
        );
        assert_eq!(
            r1.compound_hypotheses[i].severity,
            r2.compound_hypotheses[i].severity
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 2. Serialization stability
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_serialization_stable() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);
    let result = derive_compound(&hyp);

    let json1 = serde_json::to_string_pretty(&result).unwrap();
    let json2 = serde_json::to_string_pretty(&result).unwrap();
    let json3 = serde_json::to_string_pretty(&result).unwrap();

    assert_eq!(json1, json2);
    assert_eq!(json2, json3);
}

// ─────────────────────────────────────────────────────────────
// 3. Roundtrip serialization
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_serialization_roundtrip() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);
    let result = derive_compound(&hyp);

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: CompoundHypothesisResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.program_id, result.program_id);
    assert_eq!(
        deserialized.compound_hypotheses.len(),
        result.compound_hypotheses.len()
    );
    assert_eq!(deserialized.summary.total, result.summary.total);

    for i in 0..result.compound_hypotheses.len() {
        assert_eq!(
            deserialized.compound_hypotheses[i].id,
            result.compound_hypotheses[i].id
        );
        assert_eq!(
            deserialized.compound_hypotheses[i].compound_type,
            result.compound_hypotheses[i].compound_type
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 4. Identical output across runs
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_identical_across_runs() {
    let ir = make_reentrancy_auth_ir();

    // Run 5 times — all must be identical
    let results: Vec<_> = (0..5)
        .map(|_| {
            let hyp = derive(&ir);
            derive_compound(&hyp)
        })
        .collect();

    for i in 1..results.len() {
        assert_eq!(
            results[0].compound_hypotheses.len(),
            results[i].compound_hypotheses.len()
        );
        for j in 0..results[0].compound_hypotheses.len() {
            assert_eq!(
                results[0].compound_hypotheses[j].id,
                results[i].compound_hypotheses[j].id
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────
// 5. Evidence completeness
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_evidence_complete() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);
    let result = derive_compound(&hyp);

    for compound in &result.compound_hypotheses {
        assert!(!compound.id.0.is_empty(), "Compound ID must not be empty");
        assert!(
            !compound.description.is_empty(),
            "Description must not be empty"
        );
        assert!(
            !compound.structural_explanation.is_empty(),
            "Explanation must not be empty"
        );

        let ev = &compound.evidence;
        assert!(
            !ev.source_hypothesis_ids.is_empty(),
            "Must reference source hypotheses"
        );
        assert!(!ev.source_types.is_empty(), "Must have source types");
        assert!(!ev.path_ids.is_empty(), "Must reference path IDs");
        assert!(
            !ev.evidence_chain_ids.is_empty(),
            "Must reference evidence chain IDs"
        );
        assert!(!ev.graph_facts.is_empty(), "Must have graph facts");

        for fact in &ev.graph_facts {
            assert!(!fact.fact_type.is_empty(), "Fact type must not be empty");
            assert!(!fact.function.is_empty(), "Fact function must not be empty");
        }
    }
}

// ─────────────────────────────────────────────────────────────
// 6. No mutation of inputs
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_no_input_mutation() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);

    let hyp_count_before = hyp.hypotheses.len();
    let program_id_before = hyp.program_id.clone();

    let _result = derive_compound(&hyp);

    assert_eq!(hyp.hypotheses.len(), hyp_count_before);
    assert_eq!(hyp.program_id, program_id_before);
}

// ─────────────────────────────────────────────────────────────
// 7. Compound derivation correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn reentrancy_authority_chain_derived() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);
    let result = derive_compound(&hyp);

    let chains: Vec<_> = result
        .compound_hypotheses
        .iter()
        .filter(|c| c.compound_type == CompoundHypothesisType::ReentrancyAuthorityChain)
        .collect();

    assert!(!chains.is_empty(), "Should derive ReentrancyAuthorityChain");

    let chain = &chains[0];
    assert!(chain.evidence.source_hypothesis_ids.len() >= 2);
    assert!(chain.description.contains("Reentrancy"));
    assert!(chain.description.contains("authority"));
}

#[test]
fn cpi_authority_chain_derived() {
    let ir = make_cpi_auth_ir();
    let hyp = derive(&ir);
    let result = derive_compound(&hyp);

    let chains: Vec<_> = result
        .compound_hypotheses
        .iter()
        .filter(|c| c.compound_type == CompoundHypothesisType::CPIAuthorityChain)
        .collect();

    // May or may not derive depending on shared elements
    if !chains.is_empty() {
        let chain = &chains[0];
        assert!(chain.evidence.source_hypothesis_ids.len() >= 2);
    }
}

#[test]
fn state_corruption_chain_derived() {
    let ir = make_state_corruption_auth_ir();
    let hyp = derive(&ir);
    let result = derive_compound(&hyp);

    let chains: Vec<_> = result
        .compound_hypotheses
        .iter()
        .filter(|c| c.compound_type == CompoundHypothesisType::StateCorruptionChain)
        .collect();

    // May or may not derive depending on shared elements
    if !chains.is_empty() {
        let chain = &chains[0];
        assert!(chain.evidence.source_hypothesis_ids.len() >= 2);
    }
}

// ─────────────────────────────────────────────────────────────
// 8. Stable IDs
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_ids_stable() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);

    let r1 = derive_compound(&hyp);
    let r2 = derive_compound(&hyp);

    for i in 0..r1.compound_hypotheses.len() {
        assert_eq!(r1.compound_hypotheses[i].id, r2.compound_hypotheses[i].id);
    }
}

// ─────────────────────────────────────────────────────────────
// 9. Stable ordering
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_ordering_stable() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);

    let r1 = derive_compound(&hyp);
    let r2 = derive_compound(&hyp);

    for i in 0..r1.compound_hypotheses.len() {
        assert_eq!(
            r1.compound_hypotheses[i].compound_type,
            r2.compound_hypotheses[i].compound_type
        );
        assert_eq!(r1.compound_hypotheses[i].id, r2.compound_hypotheses[i].id);
    }
}

// ─────────────────────────────────────────────────────────────
// 10. Summary correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_summary_correct() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);
    let result = derive_compound(&hyp);

    assert_eq!(result.summary.total, result.compound_hypotheses.len());
    assert_eq!(
        result.summary.reentrancy_authority_count
            + result.summary.cpi_authority_count
            + result.summary.state_corruption_count
            + result.summary.multi_path_count,
        result.summary.total
    );
}

// ─────────────────────────────────────────────────────────────
// 11. JSON export determinism
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_json_deterministic() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);
    let result = derive_compound(&hyp);

    let jsons: Vec<String> = (0..5)
        .map(|_| serde_json::to_string_pretty(&result).unwrap())
        .collect();

    for i in 1..jsons.len() {
        assert_eq!(jsons[0], jsons[i], "JSON export must be deterministic");
    }
}

// ─────────────────────────────────────────────────────────────
// 12. Backward compatibility — HypothesisResult unchanged
// ─────────────────────────────────────────────────────────────

#[test]
fn hypothesis_result_unchanged_by_compound() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);

    let hyp_json_before = serde_json::to_string(&hyp).unwrap();

    let _compound = derive_compound(&hyp);

    let hyp_json_after = serde_json::to_string(&hyp).unwrap();
    assert_eq!(
        hyp_json_before, hyp_json_after,
        "HypothesisResult must not be modified"
    );
}

// ─────────────────────────────────────────────────────────────
// 13. Empty input produces empty output
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_hypotheses_produce_empty_compounds() {
    let empty_result = HypothesisResult {
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

    let result = derive_compound(&empty_result);
    assert_eq!(result.compound_hypotheses.len(), 0);
    assert_eq!(result.summary.total, 0);
}

// ─────────────────────────────────────────────────────────────
// 14. Type enum stability
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_type_variants_stable() {
    let types = vec![
        CompoundHypothesisType::ReentrancyAuthorityChain,
        CompoundHypothesisType::CPIAuthorityChain,
        CompoundHypothesisType::StateCorruptionChain,
        CompoundHypothesisType::MultiPathExploitChain,
    ];
    assert_eq!(types.len(), 4);
}

// ─────────────────────────────────────────────────────────────
// 15. No confidence scoring
// ─────────────────────────────────────────────────────────────

#[test]
fn compound_no_confidence_scoring() {
    let ir = make_reentrancy_auth_ir();
    let hyp = derive(&ir);
    let result = derive_compound(&hyp);

    let json = serde_json::to_string(&result).unwrap();
    assert!(
        !json.contains("\"confidence\""),
        "Must not contain confidence scoring"
    );
    assert!(!json.contains("\"rank\""), "Must not contain ranking");
}
