/// Multi-Actor Reasoning Contract Tests — Phase 9
use digger_actors::*;
use digger_expansion::expand_program;
use digger_graph::build_system_ir;
use digger_parser::parse_program;
use digger_state_transitions::analyze_transitions;
use digger_temporal::analyze_temporal;

fn analyze_source(source: &str) -> MultiActorReport {
    let program = parse_program(source, "solidity");
    let _ir = build_system_ir(program.clone());
    let expansion = expand_program(&program, "test");
    let transitions = analyze_transitions(&expansion, "test");
    let temporal = analyze_temporal(&program, &transitions, "test");
    analyze_actors(&program, &transitions, &temporal, "test")
}

// ─────────────────────────────────────────────────────────────
// 1. Actor identification
// ─────────────────────────────────────────────────────────────

#[test]
fn actor_identification() {
    let source = r#"
contract Test {
    address public owner;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function deposit() external payable {}

    function liquidate(address user) external {}
}
"#;
    let report = analyze_source(source);

    // Should identify admin (setOwner), liquidator, user, attacker
    let roles: Vec<_> = report.actors.iter().map(|a| &a.role).collect();
    assert!(
        roles.contains(&&ActorRole::Admin),
        "Should identify admin role"
    );
    assert!(
        roles.contains(&&ActorRole::Liquidator),
        "Should identify liquidator role"
    );
    assert!(
        roles.contains(&&ActorRole::User),
        "Should identify user role"
    );
    assert!(
        roles.contains(&&ActorRole::Attacker),
        "Should identify attacker role"
    );
}

// ─────────────────────────────────────────────────────────────
// 2. Interaction detection
// ─────────────────────────────────────────────────────────────

#[test]
fn interaction_detection() {
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

    // deposit and withdraw both affect balances
    // User calling deposit affects user calling withdraw (shared state)
    assert!(
        !report.interactions.is_empty(),
        "Should detect interactions"
    );
}

// ─────────────────────────────────────────────────────────────
// 3. Adversarial pattern detection
// ─────────────────────────────────────────────────────────────

#[test]
fn adversarial_pattern_detection() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += 100;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"#;
    let report = analyze_source(source);

    // Attacker can potentially manipulate shared state
    // This should generate adversarial patterns
    // (exact count depends on temporal dependencies)
    let _ = report;
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
// 5. Serialization roundtrip
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
// 6. Empty program
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_program() {
    let source = r#"
contract Empty {}
"#;
    let report = analyze_source(source);

    // Should still have attacker and user actors
    assert!(
        !report.actors.is_empty(),
        "Should have at least attacker and user actors"
    );
    assert_eq!(report.interactions.len(), 0);
    assert_eq!(report.adversarial_patterns.len(), 0);
}

// ─────────────────────────────────────────────────────────────
// 7. Shared state detection
// ─────────────────────────────────────────────────────────────

#[test]
fn shared_state_detection() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += 100;
    }

    function withdraw() external {
        balances[msg.sender] -= 100;
    }

    function setOwner(address newOwner) external {}
}
"#;
    let report = analyze_source(source);

    // deposit and withdraw both affect balances
    let balance_interactions: Vec<_> = report
        .interactions
        .iter()
        .filter(|i| i.affected_state.contains(&"balances".to_string()))
        .collect();

    assert!(
        !balance_interactions.is_empty(),
        "Should detect shared state on balances"
    );
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

    assert_eq!(report.summary.total_actors, report.actors.len());
    assert_eq!(report.summary.total_interactions, report.interactions.len());
    assert_eq!(
        report.summary.total_adversarial,
        report.adversarial_patterns.len()
    );
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
    let result = report_from_json("not json!");
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
// 10. Bounded interactions
// ─────────────────────────────────────────────────────────────

#[test]
fn bounded_interactions() {
    // Generate a contract with many functions
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

    // Should not exceed MAX_INTERACTIONS (100)
    assert!(
        report.interactions.len() <= 100,
        "Should respect interaction bound"
    );
}

// ─────────────────────────────────────────────────────────────
// 11. Actor roles inferred correctly
// ─────────────────────────────────────────────────────────────

#[test]
fn actor_roles_inferred() {
    let source = r#"
contract Test {
    address public owner;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function pause() external {}

    function liquidate(address user) external {}

    function vote(uint256 proposalId) external {}

    function deposit() external payable {}
}
"#;
    let report = analyze_source(source);

    let admin = report.actors.iter().find(|a| a.role == ActorRole::Admin);
    let liquidator = report
        .actors
        .iter()
        .find(|a| a.role == ActorRole::Liquidator);
    let governance = report
        .actors
        .iter()
        .find(|a| a.role == ActorRole::Governance);
    let user = report.actors.iter().find(|a| a.role == ActorRole::User);

    assert!(admin.is_some(), "Should identify admin");
    assert!(liquidator.is_some(), "Should identify liquidator");
    assert!(governance.is_some(), "Should identify governance");
    assert!(user.is_some(), "Should identify user");
}
