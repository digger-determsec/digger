//! Golden tests for the value_transfer heuristic fix.
//!
//! CRITICAL RULE: The 6 getter FPs must ALL be removed. Every TP must be
//! retained. If any TP drops, STOP.

use digger_graph::build_system_ir_with_language;
use digger_ir::Language;
use digger_parser::model::{RawFunction, RawProgram};

fn value_transfer_flag(body: &str) -> bool {
    let program = RawProgram {
        functions: vec![RawFunction {
            name: "test_fn".into(),
            body: body.to_string(),
            contract: "TestContract".into(),
            visibility: "public".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let ir = build_system_ir_with_language(program, Language::Solidity);
    ir.functions
        .first()
        .map(|f| f.effects.value_transfer)
        .unwrap_or(false)
}

// ═══════════════════════════════════════════════════════════════════
// FALSE POSITIVES — these 6 MUST NOT be classified as value_transfer
// ═══════════════════════════════════════════════════════════════════

#[test]
fn fp_is_anchor_parameter_name() {
    assert!(!value_transfer_flag(
        "function isAnchor(address value) external view returns (bool) { return false; }"
    ));
}

#[test]
fn fp_is_convertible_token_parameter_name() {
    assert!(!value_transfer_flag(
        "function isConvertibleToken(address value) external view returns (bool) { return false; }"
    ));
}

#[test]
fn fp_is_convertible_token_anchor() {
    assert!(!value_transfer_flag("function isConvertibleTokenAnchor(IReserveToken convertibleToken, address value) external view returns (bool) { return false; }"));
}

#[test]
fn fp_is_convertible_token_smart_token() {
    assert!(!value_transfer_flag("function isConvertibleTokenSmartToken(IReserveToken convertibleToken, address value) public view returns (bool) { return false; }"));
}

#[test]
fn fp_is_liquidity_pool_parameter_name() {
    assert!(!value_transfer_flag("function isLiquidityPool(address value) public view override returns (bool) { return false; }"));
}

#[test]
fn fp_is_smart_token_parameter_name() {
    assert!(!value_transfer_flag(
        "function isSmartToken(address value) public view returns (bool) { return false; }"
    ));
}

// ═══════════════════════════════════════════════════════════════════
// TRUE POSITIVES — these MUST remain classified as value_transfer
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tp_msg_value() {
    assert!(value_transfer_flag(
        "function deposit() public payable { require(msg.value > 0); balance += msg.value; }"
    ));
}

#[test]
fn tp_call_value_new_syntax() {
    assert!(value_transfer_flag(
        "function withdraw() external { (bool ok,) = addr.call{value: amount}(\"\"); }"
    ));
}

#[test]
fn tp_call_value_legacy_syntax() {
    assert!(value_transfer_flag(
        "function withdraw() external { bool ok = addr.call.value(amount)(\"\"); }"
    ));
}

#[test]
fn tp_transfer_function() {
    assert!(value_transfer_flag(
        "function withdraw() external { payable(msg.sender).transfer(address(this).balance); }"
    ));
}

#[test]
fn tp_payable_call() {
    assert!(value_transfer_flag(
        "function forward() external { address(this).call.value(msg.value)(\"\"); }"
    ));
}

#[test]
fn tp_token_transfer() {
    assert!(value_transfer_flag(
        "function transferTokens() external { token.transfer(recipient, amount); }"
    ));
}

#[test]
fn tp_raw_call_with_value() {
    assert!(value_transfer_flag(
        "function execute() external { (bool ok,) = target.call{value: msg.value}(data); }"
    ));
}
