//! Behavioral tests for the PrecisionLossCandidate detector.

use digger_hypothesis::models::{HypothesisSeverity, HypothesisType};
use digger_parser::model::{RawFunction, RawProgram};

fn derive_for(program: RawProgram) -> Vec<digger_hypothesis::models::Hypothesis> {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    let ir = build_system_ir_with_language(program, Language::Solidity);
    digger_hypothesis::derive(&ir).hypotheses
}

/// T-1: div-before-mul feeding a state write fires exactly 1 at Medium.
#[test]
fn precision_loss_fires_on_div_before_mul_vuln() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    function claimReward(uint256 totalReward, uint256 totalShares, uint256 userShares) public {
        uint256 payout = (totalReward / totalShares) * userShares;
        balances[msg.sender] += payout;
    }
}
"#;
    let raw = digger_parser::parse_program(code, "solidity");
    let all = derive_for(raw);
    let hits: Vec<_> = all
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::PrecisionLossCandidate)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected 1 PrecisionLossCandidate, got {}",
        hits.len()
    );
    assert_eq!(
        hits[0].severity,
        HypothesisSeverity::Medium,
        "severity must be Medium"
    );
}

/// T-2: mul-then-div safe ordering fires 0.
#[test]
fn precision_loss_safe_mul_then_div() {
    let code = r#"
contract Vault {
    function compute(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return a * b / c;
    }
}
"#;
    let raw = digger_parser::parse_program(code, "solidity");
    let all = derive_for(raw);
    let hits: Vec<_> = all
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::PrecisionLossCandidate)
        .collect();
    assert!(hits.is_empty(), "mul-then-div must not fire");
}

/// T-3: flag set but no value_transfer → 0 (gate isolation).
#[test]
fn precision_loss_requires_value_transfer() {
    let mut raw = RawProgram::default();
    raw.functions.push(RawFunction {
        name: "pure_div_mul".into(),
        contract: "Test".into(),
        visibility: "public".into(),
        inputs: vec![],
        body: String::new(),
        has_arithmetic: true,
    });
    raw.metadata.extra.insert(
        "ast_prec_loss:pure_div_mul".into(),
        serde_json::Value::Bool(true),
    );
    let all = derive_for(raw);
    let hits: Vec<_> = all
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::PrecisionLossCandidate)
        .collect();
    assert!(hits.is_empty(), "must NOT fire without value_transfer");
}

/// T-4: Poly zero-delta.
#[test]
fn poly_precision_loss_unaffected() {
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
    raw.state.push(digger_parser::model::RawState {
        name: "currentEpochConnectPublicKeys".into(),
        ty: "bytes".into(),
    });
    raw.state.push(digger_parser::model::RawState {
        name: "ethCrossChainAddress".into(),
        ty: "address".into(),
    });

    let hypotheses = derive_for(raw);
    let hits: Vec<_> = hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::PrecisionLossCandidate)
        .collect();
    assert!(hits.is_empty(), "Poly must NOT get PrecisionLossCandidate");
    let first = &hypotheses[0];
    assert_eq!(
        first.hypothesis_type,
        HypothesisType::AuthorityBypassCandidate
    );
    assert_eq!(first.severity, HypothesisSeverity::Critical);
    assert!(hypotheses.len() >= 2);
}

/// T-5: benign ERC20 → 0.
#[test]
fn benign_erc20_no_precision_loss() {
    let mut raw = RawProgram::default();
    raw.functions.push(RawFunction {
        name: "transfer".into(),
        contract: "ERC20".into(),
        visibility: "public".into(),
        inputs: vec![],
        body: String::new(),
        ..Default::default()
    });
    raw.state.push(digger_parser::model::RawState {
        name: "balanceOf".into(),
        ty: "mapping".into(),
    });
    let all = derive_for(raw);
    let hits: Vec<_> = all
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::PrecisionLossCandidate)
        .collect();
    assert!(
        hits.is_empty(),
        "benign ERC20 must NOT emit PrecisionLossCandidate"
    );
}
