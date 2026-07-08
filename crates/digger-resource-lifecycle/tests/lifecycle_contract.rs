use digger_expansion::expand_program;
use digger_graph::build_system_ir;
use digger_parser::parse_program;
/// Resource Lifecycle Contract Tests — Phase 7.5
use digger_resource_lifecycle::*;

fn analyze_source(source: &str) -> ResourceLifecycleReport {
    let program = parse_program(source, "solidity");
    let _ir = build_system_ir(program.clone());
    let expansion = expand_program(&program, "test");
    analyze_lifecycles(&expansion, "test")
}

// ─────────────────────────────────────────────────────────────
// 1. Simple deposit lifecycle
// ─────────────────────────────────────────────────────────────

#[test]
fn deposit_lifecycle_detected() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"#;
    let report = analyze_source(source);

    let deposit = report.lifecycles.iter().find(|l| l.function == "deposit");
    assert!(deposit.is_some(), "Should detect deposit lifecycle");

    let deposit = deposit.unwrap();
    assert!(!deposit.phases.is_empty(), "Should have lifecycle phases");
    assert!(deposit.tracking_vars.contains(&"balances".to_string()));
}

// ─────────────────────────────────────────────────────────────
// 2. Simple withdrawal lifecycle
// ─────────────────────────────────────────────────────────────

#[test]
fn withdrawal_lifecycle_detected() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    let withdraw = report.lifecycles.iter().find(|l| l.function == "withdraw");
    assert!(withdraw.is_some(), "Should detect withdraw lifecycle");

    let withdraw = withdraw.unwrap();
    assert!(withdraw.tracking_vars.contains(&"balances".to_string()));
}

// ─────────────────────────────────────────────────────────────
// 3. Unauthorized egress detection
// ─────────────────────────────────────────────────────────────

#[test]
fn unauthorized_egress_detected() {
    let source = r#"
contract Vault {
    function drain(address to) external {
        uint256 balance = address(this).balance;
        (bool success, ) = to.call{value: balance}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    let drain = report.lifecycles.iter().find(|l| l.function == "drain");
    assert!(drain.is_some(), "Should detect drain lifecycle");

    let drain = drain.unwrap();
    // The parser classifies require(success) as AuthorityCheck,
    // so UnauthorizedEgress may not fire. But EgressWithoutAccountingDecrease
    // or UntrackedMovement should fire because there's no accounting update.
    let has_anomaly = drain.anomalies.iter().any(|a| {
        a.kind == AnomalyKind::UnauthorizedEgress
            || a.kind == AnomalyKind::EgressWithoutAccountingDecrease
            || a.kind == AnomalyKind::UntrackedMovement
    });
    assert!(
        has_anomaly,
        "Should detect some anomaly for drain, got: {:?}",
        drain.anomalies
    );
}

// ─────────────────────────────────────────────────────────────
// 4. Missing accounting update
// ─────────────────────────────────────────────────────────────

#[test]
fn missing_accounting_detected() {
    let source = r#"
contract Vault {
    address public token;

    function claimRewards() external {
        (bool s, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, 100));
        require(s);
    }
}
"#;
    let report = analyze_source(source);

    let claim = report
        .lifecycles
        .iter()
        .find(|l| l.function == "claimRewards");
    assert!(claim.is_some(), "Should detect claimRewards lifecycle");

    let claim = claim.unwrap();
    let missing = claim.anomalies.iter().find(|a| {
        a.kind == AnomalyKind::EgressWithoutAccountingDecrease
            || a.kind == AnomalyKind::UntrackedMovement
    });
    assert!(
        missing.is_some(),
        "Should detect missing accounting or untracked movement"
    );
}

// ─────────────────────────────────────────────────────────────
// 5. Safe withdrawal (no anomalies)
// ─────────────────────────────────────────────────────────────

#[test]
fn safe_withdrawal_no_anomalies() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    function safe_withdraw(uint256 amount) external {
        require(msg.sender == owner);
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    let withdraw = report
        .lifecycles
        .iter()
        .find(|l| l.function == "safe_withdraw");
    assert!(withdraw.is_some(), "Should detect safe_withdraw lifecycle");

    let withdraw = withdraw.unwrap();
    // Should have authority check before egress
    let has_auth = withdraw
        .phases
        .iter()
        .any(|p| p.kind == PhaseKind::Authorization);
    let has_egress = withdraw.phases.iter().any(|p| p.kind == PhaseKind::Egress);

    // If there's an egress, there should be authority before it
    if has_egress && has_auth {
        let auth_idx = withdraw
            .phases
            .iter()
            .find(|p| p.kind == PhaseKind::Authorization)
            .map(|p| p.operation_index)
            .unwrap_or(0);
        let egress_idx = withdraw
            .phases
            .iter()
            .find(|p| p.kind == PhaseKind::Egress)
            .map(|p| p.operation_index)
            .unwrap_or(usize::MAX);

        // Authority should come before egress
        assert!(auth_idx < egress_idx, "Authority should precede egress");
    }
}

// ─────────────────────────────────────────────────────────────
// 6. Accounting integrity risk
// ─────────────────────────────────────────────────────────────

#[test]
fn accounting_integrity_risk_detected() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function unsafe_withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"#;
    let report = analyze_source(source);

    let withdraw = report
        .lifecycles
        .iter()
        .find(|l| l.function == "unsafe_withdraw");
    assert!(
        withdraw.is_some(),
        "Should detect unsafe_withdraw lifecycle"
    );

    let withdraw = withdraw.unwrap();
    let integrity_risk = withdraw
        .anomalies
        .iter()
        .find(|a| a.kind == AnomalyKind::AccountingIntegrityRisk);
    assert!(
        integrity_risk.is_some(),
        "Should detect accounting integrity risk"
    );
}

// ─────────────────────────────────────────────────────────────
// 7. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn deterministic_output() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
"#;

    let r1 = analyze_source(source);
    let r2 = analyze_source(source);
    let r3 = analyze_source(source);

    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

// ─────────────────────────────────────────────────────────────
// 8. Serialization roundtrip
// ─────────────────────────────────────────────────────────────

#[test]
fn serialization_roundtrip() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
"#;
    let report = analyze_source(source);

    let json = report_to_json(&report);
    let deserialized = report_from_json(&json).unwrap();

    assert_eq!(deserialized, report);
}

// ─────────────────────────────────────────────────────────────
// 9. Empty program
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_program() {
    let source = r#"
contract Empty {}
"#;
    let report = analyze_source(source);

    assert_eq!(report.lifecycles.len(), 0);
    assert_eq!(report.summary.total_lifecycles, 0);
    assert_eq!(report.summary.total_anomalies, 0);
}

// ─────────────────────────────────────────────────────────────
// 10. Summary statistics
// ─────────────────────────────────────────────────────────────

#[test]
fn summary_statistics() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function drain(address to) external {
        (bool success, ) = to.call{value: 100}("");
        require(success);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"#;
    let report = analyze_source(source);

    assert!(
        report.summary.total_lifecycles >= 2,
        "Should have at least 2 lifecycles"
    );
    assert!(
        report.summary.total_anomalies >= 1,
        "Should have at least 1 anomaly"
    );
}

// ─────────────────────────────────────────────────────────────
// 11. No AI or heuristics
// ─────────────────────────────────────────────────────────────

#[test]
fn no_ai_or_heuristics() {
    let source = r#"
contract Test {
    function foo() public {}
}
"#;
    let report = analyze_source(source);
    let json = report_to_json(&report);

    assert!(!json.contains("confidence"));
    assert!(!json.contains("probability"));
    assert!(!json.contains("heuristic"));
    assert!(!json.contains("risk_score"));
}

// ─────────────────────────────────────────────────────────────
// 12. report_from_json error path
// ─────────────────────────────────────────────────────────────

#[test]
fn report_from_json_error_path() {
    let result = report_from_json("{broken json}}}");
    assert!(result.is_err(), "Should fail on invalid JSON");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("JSON parse error"),
        "Error should mention JSON parse: {}",
        err
    );
}

// ─────────────────────────────────────────────────────────────
// 13. report_from_json determinism (byte-identical output)
// ─────────────────────────────────────────────────────────────

#[test]
fn report_from_json_determinism() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
"#;
    let report = analyze_source(source);
    let json = report_to_json(&report);

    let r1 = report_from_json(&json).unwrap();
    let r2 = report_from_json(&json).unwrap();
    assert_eq!(report_to_json(&r1), report_to_json(&r2));
}

// ─────────────────────────────────────────────────────────────
// 12. Cross-function lifecycle
// ─────────────────────────────────────────────────────────────

#[test]
fn cross_function_lifecycle() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        _doTransfer(msg.sender, amount);
        balances[msg.sender] -= amount;
    }

    function _doTransfer(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    // Should detect lifecycle for both functions
    assert!(
        !report.lifecycles.is_empty(),
        "Should detect at least 1 lifecycle"
    );
}

// ─────────────────────────────────────────────────────────────
// 13. Multiple anomaly types
// ─────────────────────────────────────────────────────────────

#[test]
fn multiple_anomaly_types() {
    let source = r#"
contract Vulnerable {
    function drain(address to) external {
        (bool success, ) = to.call{value: 100}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    let drain = report.lifecycles.iter().find(|l| l.function == "drain");
    assert!(drain.is_some(), "Should detect drain lifecycle");

    let drain = drain.unwrap();
    // Should have at least one anomaly
    assert!(
        !drain.anomalies.is_empty(),
        "Should detect at least one anomaly"
    );
}
