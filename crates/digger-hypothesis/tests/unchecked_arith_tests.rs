//! Behavioral tests for the UncheckedArithmeticCandidate detector.
//! Each test asserts concrete, runnable expectations.

use digger_hypothesis::models::{HypothesisSeverity, HypothesisType};
use digger_parser::model::{RawFunction, RawProgram, RawState};

/// Helper: build SystemIR from a RawProgram and run derive.
fn derive_for(program: RawProgram) -> Vec<digger_hypothesis::models::Hypothesis> {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    let ir = build_system_ir_with_language(program, Language::Solidity);
    digger_hypothesis::derive(&ir).hypotheses
}

/// T-1 POSITIVE: unchecked-overflow-vuln fires exactly ONE
/// UncheckedArithmeticCandidate with severity Low.
#[test]
fn unchecked_arith_fires_on_vuln_fixture() {
    let code = std::fs::read_to_string(
        "../../corpus/price-manipulation/unchecked-overflow-vuln/source.sol",
    )
    .expect("vuln fixture must exist");
    let raw = digger_parser::parse_program(&code, "solidity");
    let hypotheses = derive_for(raw);
    let hits: Vec<_> = hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::UncheckedArithmeticCandidate)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly 1 UncheckedArithmeticCandidate on vuln fixture, got {}: {:?}",
        hits.len(),
        hits.iter().map(|h| &h.description).collect::<Vec<_>>()
    );
    assert!(
        hits[0].severity == HypothesisSeverity::Low,
        "severity must be Low, got {:?}",
        hits[0].severity
    );
}

/// T-2 NEGATIVE: checked-arithmetic-safe fires NO UncheckedArithmeticCandidate.
#[test]
fn unchecked_arith_does_not_fire_on_safe_fixture() {
    let code = std::fs::read_to_string(
        "../../corpus/price-manipulation/checked-arithmetic-safe/source.sol",
    )
    .expect("safe fixture must exist");
    let raw = digger_parser::parse_program(&code, "solidity");
    let all = derive_for(raw);
    let hits: Vec<_> = all
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::UncheckedArithmeticCandidate)
        .collect();
    assert!(
        hits.is_empty(),
        "safe fixture must NOT emit UncheckedArithmeticCandidate, got: {:?}",
        hits.iter().map(|h| &h.description).collect::<Vec<_>>()
    );
}

/// T-3 GATE: has_unchecked_arithmetic=true but no state_mutation + no
/// value_transfer must NOT fire (value-relevance gate).
#[test]
fn unchecked_arith_requires_value_relevance() {
    let mut raw = RawProgram::default();
    raw.functions.push(RawFunction {
        name: "pure_compute".into(),
        contract: "Test".into(),
        visibility: "public".into(),
        inputs: vec![],
        body: String::new(),
        has_arithmetic: true,
    });
    raw.metadata.extra.insert(
        "ast_unchecked_arith:pure_compute".into(),
        serde_json::Value::Bool(true),
    );

    let all_hits = derive_for(raw);
    let hits: Vec<_> = all_hits
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::UncheckedArithmeticCandidate)
        .collect();
    assert!(
        hits.is_empty(),
        "pure_compute must NOT fire, got: {:?}",
        hits.iter().map(|h| &h.description).collect::<Vec<_>>()
    );
}

/// T-4 POLY ZERO-DELTA: Poly putCurEpochConnectPubKeys produces NO
/// UncheckedArithmeticCandidate, and its Critical authority bypass stays first.
#[test]
fn poly_put_cur_epoch_unaffected() {
    let mut raw = RawProgram::default();
    raw.functions.push(RawFunction {
        name: "putCurEpochConnectPubKeys".into(),
        visibility: "public".into(),
        inputs: vec![],
        body: "currentEpochConnectPublicKeys = _newKeys".into(),
        ..Default::default()
    });
    raw.functions.push(RawFunction {
        name: "setEthCrossChainAddress".into(),
        visibility: "public".into(),
        inputs: vec![],
        body: "ethCrossChainAddress = _addr".into(),
        ..Default::default()
    });
    raw.state.push(RawState {
        name: "currentEpochConnectPublicKeys".into(),
        ty: "bytes".into(),
    });
    raw.state.push(RawState {
        name: "ethCrossChainAddress".into(),
        ty: "address".into(),
    });

    let hypotheses = derive_for(raw);

    // (a) No UncheckedArithmeticCandidate
    let unchecked_hits: Vec<_> = hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::UncheckedArithmeticCandidate)
        .collect();
    assert!(
        unchecked_hits.is_empty(),
        "Poly must NOT get UncheckedArithmeticCandidate"
    );

    // (b) Access-control Critical is still ranked first
    let first = &hypotheses[0];
    assert_eq!(
        first.hypothesis_type,
        HypothesisType::AuthorityBypassCandidate,
        "first-ranked must be AuthorityBypassCandidate, got {:?}",
        first.hypothesis_type
    );
    assert_eq!(first.severity, HypothesisSeverity::Critical);

    // (c) Total count >= 2 (two functions without authority checks)
    assert!(hypotheses.len() >= 2);
}

/// T-5 BENIGN: standard ERC20-like function emits no UncheckedArithmeticCandidate.
#[test]
fn benign_erc20_no_unchecked_flag() {
    let mut raw = RawProgram::default();
    raw.functions.push(RawFunction {
        name: "transfer".into(),
        contract: "ERC20".into(),
        visibility: "public".into(),
        inputs: vec![],
        body: String::new(),
        ..Default::default()
    });
    raw.state.push(RawState {
        name: "balanceOf".into(),
        ty: "mapping".into(),
    });
    let all_hits = derive_for(raw);
    let hits: Vec<_> = all_hits
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::UncheckedArithmeticCandidate)
        .collect();
    assert!(
        hits.is_empty(),
        "benign ERC20 must NOT emit UncheckedArithmeticCandidate"
    );
}
