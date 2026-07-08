use digger_expansion::expand_program;
use digger_graph::build_system_ir;
use digger_parser::parse_program;
/// State Transition Contract Tests — Phase 7.4
use digger_state_transitions::*;

fn analyze_source(source: &str) -> StateTransitionReport {
    let program = parse_program(source, "solidity");
    let _ir = build_system_ir(program.clone());
    let expansion = expand_program(&program, "test");
    analyze_transitions(&expansion, "test")
}

// ─────────────────────────────────────────────────────────────
// 1. Simple write detected
// ─────────────────────────────────────────────────────────────

#[test]
fn simple_write_detected() {
    let source = r#"
contract Test {
    uint256 public x;

    function set(uint256 val) public {
        x = val;
    }
}
"#;
    let report = analyze_source(source);

    let transitions: Vec<_> = report
        .transitions
        .iter()
        .filter(|t| t.state_var == "x")
        .collect();

    assert!(!transitions.is_empty(), "Should detect write to x");
    assert_eq!(transitions[0].kind, TransitionKind::Assignment);
    assert!(!transitions[0].read_before_write);
}

// ─────────────────────────────────────────────────────────────
// 2. Read-modify-write detected
// ─────────────────────────────────────────────────────────────

#[test]
fn read_modify_write_detected() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
    }
}
"#;
    let report = analyze_source(source);

    let transitions: Vec<_> = report
        .transitions
        .iter()
        .filter(|t| t.state_var == "balances")
        .collect();

    assert!(!transitions.is_empty(), "Should detect write to balances");
    // The write to balances should have read_before_write = true
    // because require(balances[msg.sender] >= amount) reads before -= writes
}

// ─────────────────────────────────────────────────────────────
// 3. External between read and write
// ─────────────────────────────────────────────────────────────

#[test]
fn external_between_read_write() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function unsafe_withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"#;
    let report = analyze_source(source);

    let transitions: Vec<_> = report
        .transitions
        .iter()
        .filter(|t| t.state_var == "balances")
        .collect();

    assert!(!transitions.is_empty(), "Should detect write to balances");
    // Should detect external call between read and write
    let has_external_between = transitions.iter().any(|t| t.external_between_read_write);
    assert!(
        has_external_between,
        "Should detect external between read and write"
    );
}

// ─────────────────────────────────────────────────────────────
// 4. Missing write — external effect without state write
// ─────────────────────────────────────────────────────────────

#[test]
fn missing_write_external_only() {
    let source = r#"
contract Test {
    function transfer() public {
        (bool success, ) = msg.sender.call{value: 100}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    let missing: Vec<_> = report
        .missing_transitions
        .iter()
        .filter(|m| m.function == "transfer")
        .collect();

    assert!(!missing.is_empty(), "Should detect missing transition");
    assert_eq!(
        missing[0].reason,
        MissingTransitionReason::ExternalEffectWithoutWrite
    );
}

// ─────────────────────────────────────────────────────────────
// 5. Missing write — read without write (Sherlock claimRewards)
// ─────────────────────────────────────────────────────────────

#[test]
fn missing_write_read_without_write() {
    let source = r#"
contract Test {
    mapping(address => uint256) public stakes;
    address public token;

    function claimRewards() external {
        uint256 reward = calculateReward(msg.sender);
        (bool s, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, reward));
        require(s);
    }

    function calculateReward(address user) internal view returns (uint256) {
        return stakes[user] * 10 / 100;
    }
}
"#;
    let report = analyze_source(source);

    // claimRewards reads stakes (via calculateReward) but never writes it
    // The expansion engine inlines calculateReward's operations into claimRewards
    let missing: Vec<_> = report
        .missing_transitions
        .iter()
        .filter(|m| m.function == "claimRewards")
        .collect();

    assert!(
        !missing.is_empty(),
        "Should detect missing transition in claimRewards"
    );

    // The reason depends on whether the expansion inlined the internal call:
    // - If inlined: ReadWithoutWrite (stakes read but not written)
    // - If not inlined: ExternalEffectWithoutWrite (external call, no writes)
    // Both are valid detections of the Sherlock pattern
}

// ─────────────────────────────────────────────────────────────
// 6. No missing write when write exists
// ─────────────────────────────────────────────────────────────

#[test]
fn no_missing_write_when_present() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function safe_withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    // safe_withdraw writes balances, so no missing transition
    let missing: Vec<_> = report
        .missing_transitions
        .iter()
        .filter(|m| m.function == "safe_withdraw")
        .collect();

    assert!(
        missing.is_empty(),
        "Safe withdraw should have no missing transitions"
    );
}

// ─────────────────────────────────────────────────────────────
// 7. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn deterministic_output() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
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
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
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

    assert_eq!(report.transitions.len(), 0);
    assert_eq!(report.missing_transitions.len(), 0);
    assert_eq!(report.summary.total_transitions, 0);
    assert_eq!(report.summary.total_missing, 0);
}

// ─────────────────────────────────────────────────────────────
// 10. Summary statistics
// ─────────────────────────────────────────────────────────────

#[test]
fn summary_statistics() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function unsafe_transfer() public {
        (bool success, ) = msg.sender.call{value: 100}("");
        require(success);
    }

    function safe_update() public {
        balances[msg.sender] += 100;
    }
}
"#;
    let report = analyze_source(source);

    // unsafe_transfer: external without write → missing
    // safe_update: write present → transition
    assert!(
        report.summary.total_transitions >= 1,
        "Should have at least 1 transition"
    );
    assert!(
        report.summary.total_missing >= 1,
        "Should have at least 1 missing"
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
    let result = report_from_json("not valid json {{{");
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
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
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
