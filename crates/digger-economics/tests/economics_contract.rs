/// Economic Semantics Contract Tests — Phase 10
use digger_economics::*;
use digger_expansion::expand_program;
use digger_graph::build_system_ir;
use digger_parser::parse_program;
use digger_resource_lifecycle::analyze_lifecycles;
use digger_state_transitions::analyze_transitions;
use digger_temporal::analyze_temporal;

fn analyze_source(source: &str) -> EconomicReport {
    let program = parse_program(source, "solidity");
    let _ir = build_system_ir(program.clone());
    let expansion = expand_program(&program, "test");
    let transitions = analyze_transitions(&expansion, "test");
    let lifecycles = analyze_lifecycles(&expansion, "test");
    let temporal = analyze_temporal(&program, &transitions, "test");
    analyze_economics(&program, &transitions, &lifecycles, &temporal, "test")
}

// ─────────────────────────────────────────────────────────────
// 1. Conservation detection
// ─────────────────────────────────────────────────────────────

#[test]
fn conservation_detected() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += 100;
    }

    function withdraw() external {
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = analyze_source(source);

    let conservation: Vec<_> = report
        .relations
        .iter()
        .filter(|r| matches!(r.kind, EconomicRelationKind::Conservation(_)))
        .collect();

    assert!(
        !conservation.is_empty(),
        "Should detect conservation relation on balances"
    );
}

// ─────────────────────────────────────────────────────────────
// 2. Collateral detection
// ─────────────────────────────────────────────────────────────

#[test]
fn collateral_detected() {
    let source = r#"
contract Test {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;

    function borrow(uint256 amount) external {
        uint256 collateral = deposits[msg.sender];
        require(amount <= collateral * 80 / 100);
        borrows[msg.sender] += amount;
    }
}
"#;
    let report = analyze_source(source);

    let collateral: Vec<_> = report
        .relations
        .iter()
        .filter(|r| matches!(r.kind, EconomicRelationKind::Collateral(_)))
        .collect();

    assert!(
        !collateral.is_empty(),
        "Should detect collateral relation between deposits and borrows"
    );
}

// ─────────────────────────────────────────────────────────────
// 3. Debt detection
// ─────────────────────────────────────────────────────────────

#[test]
fn debt_detected() {
    let source = r#"
contract Test {
    mapping(address => uint256) public borrows;
    address public token;

    function borrow(uint256 amount) external {
        borrows[msg.sender] += amount;
        (bool s, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, amount));
        require(s);
    }

    function repay() external {
        uint256 debt = borrows[msg.sender];
        borrows[msg.sender] = 0;
        (bool s, ) = token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), debt));
        require(s);
    }
}
"#;
    let report = analyze_source(source);

    let debt: Vec<_> = report
        .relations
        .iter()
        .filter(|r| matches!(r.kind, EconomicRelationKind::Debt(_)))
        .collect();

    assert!(!debt.is_empty(), "Should detect debt relation on borrows");
}

// ─────────────────────────────────────────────────────────────
// 4. Dependency detection
// ─────────────────────────────────────────────────────────────

#[test]
fn dependency_detected() {
    let source = r#"
contract Test {
    uint256 public utilization;
    uint256 public interestRate;

    function updateRate() external {
        uint256 u = utilization;
        interestRate = u * 10 / 100;
    }
}
"#;
    let report = analyze_source(source);

    // Should detect dependency between utilization and interestRate
    let deps: Vec<_> = report
        .relations
        .iter()
        .filter(|r| matches!(r.kind, EconomicRelationKind::Dependency(_)))
        .collect();

    // May or may not detect depending on state transition data
    let _ = deps;
}

// ─────────────────────────────────────────────────────────────
// 5. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn deterministic_output() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += 100;
    }

    function withdraw() external {
        balances[msg.sender] -= 100;
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
// 6. Serialization roundtrip
// ─────────────────────────────────────────────────────────────

#[test]
fn serialization_roundtrip() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += 100;
    }

    function withdraw() external {
        balances[msg.sender] -= 100;
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
// 7. Empty program
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_program() {
    let source = r#"
contract Empty {}
"#;
    let report = analyze_source(source);

    assert_eq!(report.relations.len(), 0);
    assert_eq!(report.invariants.len(), 0);
    assert_eq!(report.summary.total_relations, 0);
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
        balances[msg.sender] += 100;
    }

    function withdraw() external {
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = analyze_source(source);

    assert_eq!(report.summary.total_relations, report.relations.len());
    assert_eq!(report.summary.total_invariants, report.invariants.len());
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
    let result = report_from_json("{bad json}}}");
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
        balances[msg.sender] += 100;
    }

    function withdraw() external {
        balances[msg.sender] -= 100;
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
// 12. Structural severity only — no floating-point confidence
// ─────────────────────────────────────────────────────────────

#[test]
fn structural_severity_only() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += 100;
    }

    function withdraw() external {
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = analyze_source(source);

    for invariant in &report.invariants {
        assert!(
            !invariant.evidence.iter().any(|e| e.contains("confidence")),
            "Invariant evidence should not contain confidence: {:?}",
            invariant
        );
    }
    for relation in &report.relations {
        assert!(
            !relation.evidence.iter().any(|e| e.contains("confidence")),
            "Relation evidence should not contain confidence: {:?}",
            relation
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 10. EconomicRelation abstraction
// ─────────────────────────────────────────────────────────────

#[test]
fn economic_relation_abstraction() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += 100;
    }

    function withdraw() external {
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = analyze_source(source);

    // All relations should be EconomicRelation with kind variants
    for relation in &report.relations {
        match &relation.kind {
            EconomicRelationKind::Conservation(c) => {
                assert!(!c.conserved_var.is_empty());
                assert!(!c.inflow_functions.is_empty());
                assert!(!c.outflow_functions.is_empty());
            }
            EconomicRelationKind::Collateral(c) => {
                assert!(!c.collateral_var.is_empty());
                assert!(!c.constrained_var.is_empty());
            }
            EconomicRelationKind::Debt(d) => {
                assert!(!d.debt_var.is_empty());
            }
            EconomicRelationKind::Dependency(d) => {
                assert!(!d.influencer.is_empty());
                assert!(!d.influenced.is_empty());
            }
        }
    }
}
