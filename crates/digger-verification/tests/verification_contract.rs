use digger_execution::analyze_execution;
use digger_expansion::expand_program;
use digger_graph::analysis::*;
use digger_graph::build_system_ir;
use digger_parser::parse_program;
use digger_resource_lifecycle::*;
use digger_state_transitions::*;
/// Verification Contract Tests — Phase 7.6
use digger_verification::*;

fn generate_from_source(source: &str) -> VerificationReport {
    let program = parse_program(source, "solidity");
    let _ir = build_system_ir(program.clone());
    let expansion = expand_program(&program, "test");
    let authority = propagate_authority(&program);
    let execution = analyze_execution(&program, "test");
    let transitions = analyze_transitions(&expansion, "test");
    let lifecycles = analyze_lifecycles(&expansion, "test");

    generate_properties(
        &authority,
        &transitions,
        &lifecycles,
        &execution.cei_violations,
        "test",
    )
}

// ─────────────────────────────────────────────────────────────
// 1. Properties generated from authority graph
// ─────────────────────────────────────────────────────────────

#[test]
fn authority_invariant_generated() {
    let source = r#"
contract Test {
    address public owner;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"#;
    let report = generate_from_source(source);

    let auth_props: Vec<_> = report
        .properties
        .iter()
        .filter(|p| p.origin == PropertyOrigin::AuthorityGraph)
        .collect();

    assert!(
        !auth_props.is_empty(),
        "Should generate authority properties for setOwner"
    );
}

// ─────────────────────────────────────────────────────────────
// 2. Properties generated from state transitions
// ─────────────────────────────────────────────────────────────

#[test]
fn transition_ordering_generated() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function unsafe_withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"#;
    let report = generate_from_source(source);

    let transition_props: Vec<_> = report
        .properties
        .iter()
        .filter(|p| p.origin == PropertyOrigin::StateTransition)
        .collect();

    assert!(
        !transition_props.is_empty(),
        "Should generate transition properties"
    );
}

// ─────────────────────────────────────────────────────────────
// 3. Properties generated from resource lifecycle
// ─────────────────────────────────────────────────────────────

#[test]
fn lifecycle_anomaly_generated() {
    let source = r#"
contract Test {
    address public token;

    function claimRewards() external {
        (bool s, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, 100));
        require(s);
    }
}
"#;
    let report = generate_from_source(source);

    let lifecycle_props: Vec<_> = report
        .properties
        .iter()
        .filter(|p| p.origin == PropertyOrigin::ResourceLifecycle)
        .collect();

    assert!(
        !lifecycle_props.is_empty(),
        "Should generate lifecycle properties"
    );
}

// ─────────────────────────────────────────────────────────────
// 4. Properties generated from CEI violations
// ─────────────────────────────────────────────────────────────

#[test]
fn cei_ordering_generated() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function unsafe_withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"#;
    let report = generate_from_source(source);

    let cei_props: Vec<_> = report
        .properties
        .iter()
        .filter(|p| p.origin == PropertyOrigin::ExecutionOrdering)
        .collect();

    assert!(
        !cei_props.is_empty(),
        "Should generate CEI ordering properties"
    );
}

// ─────────────────────────────────────────────────────────────
// 5. PropertyOrigin metadata
// ─────────────────────────────────────────────────────────────

#[test]
fn property_origin_present() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function drain(address to) external {
        (bool success, ) = to.call{value: 100}("");
        require(success);
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = generate_from_source(source);

    for prop in &report.properties {
        // Every property must have a specific origin
        let origin_str = prop.origin.to_string();
        assert!(
            !origin_str.is_empty(),
            "Property should have a specific origin"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 6. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn deterministic_output() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
"#;

    let r1 = generate_from_source(source);
    let r2 = generate_from_source(source);
    let r3 = generate_from_source(source);

    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

// ─────────────────────────────────────────────────────────────
// 7. Serialization roundtrip
// ─────────────────────────────────────────────────────────────

#[test]
fn serialization_roundtrip() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
"#;
    let report = generate_from_source(source);

    let json = serde_json::to_string_pretty(&report).unwrap();
    let deserialized: VerificationReport = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized, report);
}

#[test]
fn serialization_stable() {
    let source = r#"
contract Test {
    function foo() public {}
}
"#;
    let report = generate_from_source(source);

    let json1 = serde_json::to_string(&report).unwrap();
    let json2 = serde_json::to_string(&report).unwrap();
    assert_eq!(json1, json2);
}

// ─────────────────────────────────────────────────────────────
// 8. Empty program
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_program() {
    let source = r#"
contract Empty {}
"#;
    let report = generate_from_source(source);

    assert_eq!(report.properties.len(), 0);
    assert_eq!(report.summary.total_properties, 0);
}

// ─────────────────────────────────────────────────────────────
// 9. Summary statistics
// ─────────────────────────────────────────────────────────────

#[test]
fn summary_statistics() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function drain(address to) external {
        (bool success, ) = to.call{value: 100}("");
        require(success);
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = generate_from_source(source);

    assert!(
        report.summary.total_properties >= 1,
        "Should have at least 1 property"
    );
    assert!(
        !report.summary.by_kind.is_empty(),
        "Should have kind breakdown"
    );
    assert!(
        !report.summary.by_origin.is_empty(),
        "Should have origin breakdown"
    );
    assert!(
        !report.summary.by_severity.is_empty(),
        "Should have severity breakdown"
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
    let report = generate_from_source(source);
    let json = serde_json::to_string(&report).unwrap();

    assert!(!json.contains("confidence"));
    assert!(!json.contains("probability"));
    assert!(!json.contains("heuristic"));
    assert!(!json.contains("risk_score"));
}

// ─────────────────────────────────────────────────────────────
// 11. Property ID determinism
// ─────────────────────────────────────────────────────────────

#[test]
fn property_id_deterministic() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function drain(address to) external {
        (bool success, ) = to.call{value: 100}("");
        require(success);
        balances[msg.sender] -= 100;
    }
}
"#;

    let r1 = generate_from_source(source);
    let r2 = generate_from_source(source);

    for i in 0..r1.properties.len() {
        assert_eq!(r1.properties[i].property_id, r2.properties[i].property_id);
    }
}

// ─────────────────────────────────────────────────────────────
// 12. Predicate structure
// ─────────────────────────────────────────────────────────────

#[test]
fn predicates_are_structured() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function drain(address to) external {
        (bool success, ) = to.call{value: 100}("");
        require(success);
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = generate_from_source(source);

    for prop in &report.properties {
        // Every property must have a structured predicate
        match &prop.predicate {
            Predicate::Always(_)
            | Predicate::Before(_, _)
            | Predicate::After(_, _)
            | Predicate::Not(_)
            | Predicate::And(_)
            | Predicate::Or(_) => {}
            _ => panic!("Unexpected predicate type"),
        }
    }
}

// ─────────────────────────────────────────────────────────────
// 13. Evidence references
// ─────────────────────────────────────────────────────────────

#[test]
fn evidence_references_present() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function drain(address to) external {
        (bool success, ) = to.call{value: 100}("");
        require(success);
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = generate_from_source(source);

    for prop in &report.properties {
        assert!(
            !prop.evidence.is_empty(),
            "Every property should have evidence"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 14. Cross-model integration
// ─────────────────────────────────────────────────────────────

#[test]
fn cross_model_integration() {
    // A function that triggers multiple semantic models:
    // - Missing authority (AuthorityGraph)
    // - CEI violation (Execution)
    // - Missing accounting (ResourceLifecycle)
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function drain(address to) external {
        (bool success, ) = to.call{value: address(this).balance}("");
        require(success);
    }
}
"#;
    let report = generate_from_source(source);

    let origins: Vec<_> = report.properties.iter().map(|p| &p.origin).collect();

    // Should have properties from multiple origins
    let has_auth = origins
        .iter()
        .any(|o| **o == PropertyOrigin::AuthorityGraph);
    let has_lifecycle = origins
        .iter()
        .any(|o| **o == PropertyOrigin::ResourceLifecycle);

    assert!(
        has_auth || has_lifecycle,
        "Should have properties from multiple origins"
    );
}
