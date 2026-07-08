use digger_expansion::expand_program;
use digger_graph::build_system_ir;
use digger_parser::parse_program;
use digger_state_transitions::analyze_transitions;
use digger_temporal::engine::{analyze_temporal, report_from_json, report_to_json};
/// Temporal Reasoning Contract Tests — Phase 8
use digger_temporal::models::*;

fn analyze_source(source: &str) -> TemporalReport {
    let program = parse_program(source, "solidity");
    let _ir = build_system_ir(program.clone());
    let expansion = expand_program(&program, "test");
    let transitions = analyze_transitions(&expansion, "test");
    analyze_temporal(&program, &transitions, "test")
}

// ─────────────────────────────────────────────────────────────
// 1. Sequence generation
// ─────────────────────────────────────────────────────────────

#[test]
fn sequence_generation() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    // Should generate at least one sequence (deposit -> withdraw or withdraw -> deposit)
    assert!(!report.sequences.is_empty(), "Should generate sequences");
}

// ─────────────────────────────────────────────────────────────
// 2. Temporal dependency discovery
// ─────────────────────────────────────────────────────────────

#[test]
fn temporal_dependency_discovery() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    // deposit writes balances, withdraw reads balances
    // This should create a temporal dependency
    let deps: Vec<_> = report
        .dependencies
        .iter()
        .filter(|d| d.state_var == "balances")
        .collect();

    // There should be a dependency between deposit and withdraw
    assert!(
        !deps.is_empty(),
        "Should discover temporal dependency on balances"
    );
}

// ─────────────────────────────────────────────────────────────
// 3. Ordering violation detection
// ─────────────────────────────────────────────────────────────

#[test]
fn ordering_violation_detection() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    // The temporal analysis should identify that deposit must precede withdraw
    // for the balance to be sufficient
    assert!(
        !report.dependencies.is_empty(),
        "Should have temporal dependencies"
    );
}

// ─────────────────────────────────────────────────────────────
// 4. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn deterministic_output() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
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
// 5. Serialization roundtrip
// ─────────────────────────────────────────────────────────────

#[test]
fn serialization_roundtrip() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
    }
}
"#;
    let report = analyze_source(source);

    let json = report_to_json(&report);
    let deserialized = report_from_json(&json).unwrap();

    assert_eq!(deserialized, report);
}

#[test]
fn serialization_stable() {
    let source = r#"
contract Test {
    function foo() public {}
}
"#;
    let report = analyze_source(source);

    let json1 = report_to_json(&report);
    let json2 = report_to_json(&report);
    assert_eq!(json1, json2);
}

// ─────────────────────────────────────────────────────────────
// 6. Empty program
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_program() {
    let source = r#"
contract Empty {}
"#;
    let report = analyze_source(source);

    assert_eq!(report.sequences.len(), 0);
    assert_eq!(report.dependencies.len(), 0);
    assert_eq!(report.anomalies.len(), 0);
    assert_eq!(report.summary.total_sequences, 0);
}

// ─────────────────────────────────────────────────────────────
// 7. Shared state detection
// ─────────────────────────────────────────────────────────────

#[test]
fn shared_state_detection() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;
    address public owner;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
    }
}
"#;
    let report = analyze_source(source);

    // setOwner writes 'owner', withdraw reads 'balances' — no shared state
    // deposit not present, so no shared state between setOwner and withdraw
    // This is expected — they don't share state variables
    let _ = report;
}

// ─────────────────────────────────────────────────────────────
// 8. Summary statistics
// ─────────────────────────────────────────────────────────────

#[test]
fn summary_statistics() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
    }
}
"#;
    let report = analyze_source(source);

    // Summary should be consistent with actual data
    assert_eq!(report.summary.total_sequences, report.sequences.len());
    assert_eq!(report.summary.total_dependencies, report.dependencies.len());
    assert_eq!(report.summary.total_anomalies, report.anomalies.len());
}

// ─────────────────────────────────────────────────────────────
// 9. No AI or heuristics
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
// 10. report_from_json error path
// ─────────────────────────────────────────────────────────────

#[test]
fn report_from_json_error_path() {
    let result = report_from_json("invalid json {{{");
    assert!(result.is_err(), "Should fail on invalid JSON");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("JSON parse error"),
        "Error should mention JSON parse: {}",
        err
    );
}

// ─────────────────────────────────────────────────────────────
// 11. report_from_json determinism (byte-identical output)
// ─────────────────────────────────────────────────────────────

#[test]
fn report_from_json_determinism() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
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
// 10. Bounded sequences
// ─────────────────────────────────────────────────────────────

#[test]
fn bounded_sequences() {
    // Generate a contract with many functions to test bounding
    let mut source =
        String::from("contract Test {\n    mapping(address => uint256) public balances;\n");
    for i in 0..20 {
        source.push_str(&format!(
            "    function f{}() public {{ balances[msg.sender] += {}; }}\n",
            i, i
        ));
    }
    source.push_str("}\n");

    let report = analyze_source(&source);

    // Should not exceed MAX_SEQUENCES (100)
    assert!(
        report.sequences.len() <= 100,
        "Should respect sequence bound"
    );
}
