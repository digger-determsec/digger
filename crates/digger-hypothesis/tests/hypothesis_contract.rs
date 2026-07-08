#![allow(clippy::needless_update, clippy::useless_vec, clippy::len_zero)]
use digger_graph::build_system_ir;
/// Hypothesis Engine Contract Tests — Phase 3.1 Freeze
///
/// These tests enforce the hypothesis engine contract.
/// If any test fails, the contract has been broken.
use digger_hypothesis::*;
use digger_ir::*;
use digger_parser::model::*;

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
                body: "require(balances[msg.sender] >= amount); (bool success, ) = msg.sender.call{value: amount}(\"\"); balances = new_balances".into(),
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
// 1. Deterministic ordering — same input → same output
// ─────────────────────────────────────────────────────────────

#[test]
fn deterministic_output_across_runs() {
    let ir = make_test_ir();

    let r1 = derive(&ir);
    let r2 = derive(&ir);
    let r3 = derive(&ir);

    assert_eq!(r1.hypotheses.len(), r2.hypotheses.len());
    assert_eq!(r2.hypotheses.len(), r3.hypotheses.len());

    for i in 0..r1.hypotheses.len() {
        assert_eq!(r1.hypotheses[i].id, r2.hypotheses[i].id);
        assert_eq!(r2.hypotheses[i].id, r3.hypotheses[i].id);
        assert_eq!(
            r1.hypotheses[i].hypothesis_type,
            r2.hypotheses[i].hypothesis_type
        );
        assert_eq!(r1.hypotheses[i].severity, r2.hypotheses[i].severity);
        assert_eq!(
            r1.hypotheses[i].primary_function,
            r2.hypotheses[i].primary_function
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 2. Serialization stability — same input → same JSON
// ─────────────────────────────────────────────────────────────

#[test]
fn serialization_is_stable() {
    let ir = make_test_ir();
    let result = derive(&ir);

    let json1 = serde_json::to_string_pretty(&result).unwrap();
    let json2 = serde_json::to_string_pretty(&result).unwrap();
    let json3 = serde_json::to_string_pretty(&result).unwrap();

    assert_eq!(json1, json2);
    assert_eq!(json2, json3);
}

#[test]
fn serialization_roundtrip() {
    let ir = make_test_ir();
    let result = derive(&ir);

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: HypothesisResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.program_id, result.program_id);
    assert_eq!(deserialized.hypotheses.len(), result.hypotheses.len());
    assert_eq!(deserialized.summary.total, result.summary.total);

    for i in 0..result.hypotheses.len() {
        assert_eq!(deserialized.hypotheses[i].id, result.hypotheses[i].id);
        assert_eq!(
            deserialized.hypotheses[i].hypothesis_type,
            result.hypotheses[i].hypothesis_type
        );
        assert_eq!(
            deserialized.hypotheses[i].severity,
            result.hypotheses[i].severity
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 3. Required fields — all fields must exist and be non-empty
// ─────────────────────────────────────────────────────────────

#[test]
fn required_fields_present() {
    let ir = make_test_ir();
    let result = derive(&ir);

    // Top-level
    assert!(
        !result.program_id.is_empty(),
        "program_id must not be empty"
    );

    // Every hypothesis
    for hyp in &result.hypotheses {
        assert!(!hyp.id.0.is_empty(), "hypothesis id must not be empty");
        assert!(!hyp.description.is_empty(), "description must not be empty");
        assert!(
            !hyp.primary_function.is_empty(),
            "primary_function must not be empty"
        );
        assert!(
            !hyp.structural_explanation.is_empty(),
            "structural_explanation must not be empty"
        );
    }
}

#[test]
fn json_has_required_fields() {
    let ir = make_test_ir();
    let result = derive(&ir);
    let json = serde_json::to_string_pretty(&result).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(value.get("program_id").is_some());
    assert!(value.get("hypotheses").is_some());
    assert!(value.get("summary").is_some());

    let summary = value.get("summary").unwrap();
    assert!(summary.get("total").is_some());
    assert!(summary.get("reentrancy_count").is_some());
    assert!(summary.get("authority_bypass_count").is_some());
    assert!(summary.get("cpi_trust_count").is_some());
    assert!(summary.get("state_corruption_count").is_some());
}

// ─────────────────────────────────────────────────────────────
// 4. Stable IDs — same input → same IDs
// ─────────────────────────────────────────────────────────────

#[test]
fn hypothesis_ids_are_stable() {
    let ir = make_test_ir();

    let r1 = derive(&ir);
    let r2 = derive(&ir);

    for i in 0..r1.hypotheses.len() {
        assert_eq!(r1.hypotheses[i].id, r2.hypotheses[i].id);
    }
}

// ─────────────────────────────────────────────────────────────
// 5. Summary correctness — counts match actual hypotheses
// ─────────────────────────────────────────────────────────────

#[test]
fn summary_counts_match() {
    let ir = make_test_ir();
    let result = derive(&ir);

    assert_eq!(result.summary.total, result.hypotheses.len());

    let reentrancy = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::ReentrancyCandidate)
        .count();
    assert_eq!(result.summary.reentrancy_count, reentrancy);

    let auth_bypass = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .count();
    assert_eq!(result.summary.authority_bypass_count, auth_bypass);

    let cpi_trust = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::CPITrustViolationCandidate)
        .count();
    assert_eq!(result.summary.cpi_trust_count, cpi_trust);

    let state_corrupt = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::StateCorruptionCandidate)
        .count();
    assert_eq!(result.summary.state_corruption_count, state_corrupt);
}

// ─────────────────────────────────────────────────────────────
// 6. Evidence validation — no hypothesis without evidence
// ─────────────────────────────────────────────────────────────

#[test]
fn every_hypothesis_has_evidence() {
    let ir = make_test_ir();
    let result = derive(&ir);

    for hyp in &result.hypotheses {
        assert!(
            !hyp.evidence.is_empty(),
            "Hypothesis {} must have at least one evidence chain",
            hyp.id
        );

        for ev in &hyp.evidence {
            assert!(
                !ev.path_id.is_empty(),
                "Evidence path_id must not be empty for hypothesis {}",
                hyp.id
            );
            assert!(
                !ev.evidence_chain_id.is_empty(),
                "Evidence chain_id must not be empty for hypothesis {}",
                hyp.id
            );
            assert!(
                !ev.involved_functions.is_empty(),
                "Evidence involved_functions must not be empty for hypothesis {}",
                hyp.id
            );
            assert!(
                !ev.graph_facts.is_empty(),
                "Evidence graph_facts must not be empty for hypothesis {}",
                hyp.id
            );

            for fact in &ev.graph_facts {
                assert!(
                    !fact.fact_type.is_empty(),
                    "GraphFact type must not be empty"
                );
                assert!(
                    !fact.function.is_empty(),
                    "GraphFact function must not be empty"
                );
            }
        }
    }
}

#[test]
fn empty_ir_produces_no_hypotheses() {
    let ir = SystemIR {
        program_id: "empty".into(),
        language: Language::Solidity,
        functions: vec![],
        state: vec![],
        edges: vec![],
    };

    let result = derive(&ir);
    assert_eq!(result.hypotheses.len(), 0);
    assert_eq!(result.summary.total, 0);
}

// ─────────────────────────────────────────────────────────────
// 7. No mutation of graph outputs
// ─────────────────────────────────────────────────────────────

#[test]
fn graph_outputs_unchanged_after_derivation() {
    let ir = make_test_ir();

    let fn_count_before = ir.functions.len();
    let state_count_before = ir.state.len();
    let edge_count_before = ir.edges.len();

    let _result = derive(&ir);

    assert_eq!(ir.functions.len(), fn_count_before);
    assert_eq!(ir.state.len(), state_count_before);
    assert_eq!(ir.edges.len(), edge_count_before);
}

// ─────────────────────────────────────────────────────────────
// 8. Export validation — deterministic JSON
// ─────────────────────────────────────────────────────────────

#[test]
fn json_export_is_deterministic() {
    let ir = make_test_ir();
    let result = derive(&ir);

    // Generate JSON 5 times — must all be identical
    let jsons: Vec<String> = (0..5)
        .map(|_| serde_json::to_string_pretty(&result).unwrap())
        .collect();

    for i in 1..jsons.len() {
        assert_eq!(jsons[0], jsons[i], "JSON export must be deterministic");
    }
}

// ─────────────────────────────────────────────────────────────
// 9. Type enum stability
// ─────────────────────────────────────────────────────────────

#[test]
fn hypothesis_type_variants_stable() {
    // Verify all expected variants exist
    let types = vec![
        HypothesisType::ReentrancyCandidate,
        HypothesisType::AuthorityBypassCandidate,
        HypothesisType::CPITrustViolationCandidate,
        HypothesisType::StateCorruptionCandidate,
    ];
    assert_eq!(types.len(), 4);
}

#[test]
fn severity_variants_stable() {
    let severities = vec![
        HypothesisSeverity::Info,
        HypothesisSeverity::Low,
        HypothesisSeverity::Medium,
        HypothesisSeverity::High,
        HypothesisSeverity::Critical,
    ];
    assert_eq!(severities.len(), 5);
}

// ─────────────────────────────────────────────────────────────
// 10. Freeze checklist verification
// ─────────────────────────────────────────────────────────────

#[test]
fn no_confidence_scoring() {
    // Hypothesis struct must NOT have confidence field
    let ir = make_test_ir();
    let result = derive(&ir);

    let json = serde_json::to_string(&result).unwrap();
    assert!(
        !json.contains("\"confidence\""),
        "Must not contain confidence scoring"
    );
}

#[test]
fn no_ranking_logic() {
    // Hypotheses sorted: severity tier → type priority → ID (deterministic)
    let ir = make_test_ir();
    let result = derive(&ir);

    fn severity_rank(s: &digger_ir::Severity) -> u8 {
        match s {
            digger_ir::Severity::Critical => 0,
            digger_ir::Severity::High => 1,
            digger_ir::Severity::Medium => 2,
            digger_ir::Severity::Low => 3,
            digger_ir::Severity::Info => 4,
        }
    }

    fn type_priority(t: &digger_hypothesis::models::HypothesisType) -> u8 {
        use digger_hypothesis::models::HypothesisType as T;
        match t {
            T::OracleManipulationCandidate => 0,
            T::FlashLoanGovernanceCandidate => 1,
            T::ReentrancyCandidate => 2,
            T::CPITrustViolationCandidate => 3,
            T::StateCorruptionCandidate => 4,
            T::EconomicInvariantViolationCandidate => 5,
            T::AdversarialPathCandidate => 6,
            T::AuthorityBypassCandidate => 7,
            T::MissingAccountConstraintCandidate => 8,
            T::UncheckedArithmeticCandidate => 9,
            T::PrecisionLossCandidate => 10,
        }
    }

    if result.hypotheses.len() >= 2 {
        for i in 1..result.hypotheses.len() {
            let prev = &result.hypotheses[i - 1];
            let curr = &result.hypotheses[i];
            let prev_sev = severity_rank(&prev.severity);
            let curr_sev = severity_rank(&curr.severity);
            let prev_tp = type_priority(&prev.hypothesis_type);
            let curr_tp = type_priority(&curr.hypothesis_type);
            assert!(
                prev_sev < curr_sev
                    || (prev_sev == curr_sev && prev_tp < curr_tp)
                    || (prev_sev == curr_sev && prev_tp == curr_tp && prev.id.0 <= curr.id.0),
                "Sorted by severity → type → ID: {:?} {:?} {} before {:?} {:?} {}",
                prev.severity,
                prev.hypothesis_type,
                prev.id,
                curr.severity,
                curr.hypothesis_type,
                curr.id
            );
        }
    }
}
