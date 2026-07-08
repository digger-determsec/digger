/// Execution Ordering Contract Tests — Phase 6.3
use digger_execution::*;
use digger_ir::Severity;
use digger_parser::parse_program;

// ─────────────────────────────────────────────────────────────
// 1. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn execution_report_deterministic() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"#;
    let program = parse_program(source, "solidity");
    let r1 = analyze_execution(&program, "test");
    let r2 = analyze_execution(&program, "test");
    let r3 = analyze_execution(&program, "test");

    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

// ─────────────────────────────────────────────────────────────
// 2. Stable ordering
// ─────────────────────────────────────────────────────────────

#[test]
fn function_analyses_sorted() {
    let source = r#"
contract Test {
    function alpha() public {}
    function beta() public {}
    function gamma() public {}
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");

    for i in 1..report.function_analyses.len() {
        assert!(
            report.function_analyses[i - 1].function_name
                <= report.function_analyses[i].function_name
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 3. CEI violation detection — external call before state write
// ─────────────────────────────────────────────────────────────

#[test]
fn cei_violation_detected() {
    // Classic reentrancy: external call BEFORE state write
    let source = r#"
contract Vulnerable {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "vulnerable");
    eprintln!("CEI violations: {:#?}", report.cei_violations);

    assert!(
        !report.cei_violations.is_empty(),
        "Should detect CEI violation in withdraw(), got: {:?}",
        report.cei_violations
    );

    let violation = &report.cei_violations[0];
    assert_eq!(violation.function_name, "withdraw");
    assert_eq!(violation.severity, Severity::High);
    assert!(violation.external_call_target.contains("call"));
    assert_eq!(violation.state_variable, "balances");
}

// ─────────────────────────────────────────────────────────────
// 4. No CEI violation when state write is first
// ─────────────────────────────────────────────────────────────

#[test]
fn no_cei_violation_when_safe() {
    // Safe pattern: state write BEFORE external call
    let source = r#"
contract Safe {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "safe");

    assert!(
        report.cei_violations.is_empty(),
        "Should NOT detect CEI violation when state write is before external call, got: {:?}",
        report.cei_violations
    );
}

// ─────────────────────────────────────────────────────────────
// 5. Operation ordering correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn operations_in_correct_order() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");

    let withdraw = report
        .function_analyses
        .iter()
        .find(|f| f.function_name == "withdraw")
        .unwrap();

    // Operations should be in order:
    // 1. StateRead (balances[msg.sender] in require)
    // 2. AuthorityCheck (require)
    // 3. ExternalCall (.call)
    // 4. StateWrite (balances[msg.sender] -= amount)
    assert!(withdraw.has_external_call);
    assert!(withdraw.has_state_write);
    assert!(withdraw.has_authority_check);

    // External call should be before state write
    assert!(withdraw.external_before_state_write);
}

// ─────────────────────────────────────────────────────────────
// 6. Serialization roundtrip
// ─────────────────────────────────────────────────────────────

#[test]
fn serialization_roundtrip() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");

    let json = report_to_json(&report);
    let deserialized = report_from_json(&json).unwrap();

    assert_eq!(deserialized.protocol_id, report.protocol_id);
    assert_eq!(
        deserialized.cei_violations.len(),
        report.cei_violations.len()
    );
}

#[test]
fn serialization_stable() {
    let source = r#"
contract Test {
    function foo() public {}
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");

    let json1 = report_to_json(&report);
    let json2 = report_to_json(&report);
    assert_eq!(json1, json2);
}

// ─────────────────────────────────────────────────────────────
// 7. Empty program handling
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_program() {
    let source = r#"
contract Empty {}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "empty");

    assert_eq!(report.function_analyses.len(), 0);
    assert_eq!(report.cei_violations.len(), 0);
    assert_eq!(report.summary.total_functions, 0);
}

// ─────────────────────────────────────────────────────────────
// 8. Summary correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn summary_correct() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function safe_withdraw(uint256 amount) public {
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
    }

    function unsafe_withdraw(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    function read_only() public view returns (uint256) {
        return balances[msg.sender];
    }
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");

    assert_eq!(report.summary.total_functions, 3);
    assert_eq!(report.summary.functions_with_external_calls, 2);
    assert_eq!(report.summary.functions_with_state_writes, 2);
    assert_eq!(report.summary.functions_with_cei_violations, 1);
    assert_eq!(report.summary.total_cei_violations, 1);
}

// ─────────────────────────────────────────────────────────────
// 9. Interface call detected as external
// ─────────────────────────────────────────────────────────────

#[test]
fn interface_call_detected_as_external() {
    let source = r#"
interface IOracle {
    function getSpotPrice() external view returns (uint256);
}

contract Test {
    address public oracle;
    mapping(address => uint256) public balances;

    function borrow(uint256 amount) external {
        uint256 price = IOracle(oracle).getSpotPrice();
        balances[msg.sender] += amount;
    }
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");

    let borrow = report
        .function_analyses
        .iter()
        .find(|f| f.function_name == "borrow")
        .unwrap();

    assert!(
        borrow.has_external_call,
        "Should detect IOracle interface call as external"
    );
}

// ─────────────────────────────────────────────────────────────
// 10. No AI or heuristics
// ─────────────────────────────────────────────────────────────

#[test]
fn no_ai_or_heuristics() {
    let source = r#"
contract Test {
    function foo() public {}
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");
    let json = report_to_json(&report);

    assert!(!json.contains("confidence"));
    assert!(!json.contains("probability"));
    assert!(!json.contains("heuristic"));
    assert!(!json.contains("risk_score"));
}

// ─────────────────────────────────────────────────────────────
// 11. delegatecall detected as external
// ─────────────────────────────────────────────────────────────

#[test]
fn delegatecall_detected_as_external() {
    let source = r#"
contract Test {
    address public implementation;

    function execute() public {
        (bool success, ) = implementation.delegatecall("");
        require(success);
    }
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");

    let execute = report
        .function_analyses
        .iter()
        .find(|f| f.function_name == "execute")
        .unwrap();

    assert!(
        execute.has_external_call,
        "Should detect delegatecall as external"
    );
}

// ─────────────────────────────────────────────────────────────
// 12. Multiple CEI violations in same function
// ─────────────────────────────────────────────────────────────

#[test]
fn multiple_operations_tracked() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;
    address public owner;

    function complex() public {
        balances[msg.sender] -= 100;
        (bool success, ) = msg.sender.call{value: 100}("");
        owner = msg.sender;
    }
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");

    let complex = report
        .function_analyses
        .iter()
        .find(|f| f.function_name == "complex")
        .unwrap();

    // State write before external call → no CEI violation for balances
    // But external call before owner = msg.sender → CEI violation
    assert!(complex.has_external_call);
    assert!(complex.has_state_write);
}
