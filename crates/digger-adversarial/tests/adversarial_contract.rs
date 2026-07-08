use digger_actors::analyze_actors;
/// Adversarial Modeling Contract Tests — Generation 2 Baseline
use digger_adversarial::*;
use digger_economics::analyze_economics;
use digger_expansion::expand_program;
use digger_graph::build_system_ir;
use digger_parser::parse_program;
use digger_resource_lifecycle::analyze_lifecycles;
use digger_state_transitions::analyze_transitions;
use digger_temporal::analyze_temporal;
use digger_verification::{VerificationReport, VerificationSummary};

fn empty_verification() -> VerificationReport {
    VerificationReport {
        protocol_id: "test".into(),
        properties: vec![],
        summary: VerificationSummary {
            total_properties: 0,
            by_kind: std::collections::BTreeMap::new(),
            by_origin: std::collections::BTreeMap::new(),
            by_severity: std::collections::BTreeMap::new(),
        },
    }
}

fn analyze_source(source: &str) -> CapabilityReport {
    let program = parse_program(source, "solidity");
    let _ir = build_system_ir(program.clone());
    let expansion = expand_program(&program, "test");
    let transitions = analyze_transitions(&expansion, "test");
    let lifecycles = analyze_lifecycles(&expansion, "test");
    let temporal = analyze_temporal(&program, &transitions, "test");
    let actors = analyze_actors(&program, &transitions, &temporal, "test");
    let economics = analyze_economics(&program, &transitions, &lifecycles, &temporal, "test");
    let verification = empty_verification();
    analyze_adversarial(
        &program,
        &transitions,
        &lifecycles,
        &temporal,
        &actors,
        &economics,
        &verification,
        None,
        "test",
    )
}

// ─────────────────────────────────────────────────────────────
// 1. ReasoningSession
// ─────────────────────────────────────────────────────────────

#[test]
fn reasoning_session_present() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;
    function withdraw() external {
        (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
"#;
    let report = analyze_source(source);

    // Session should be present with deterministic ID
    assert!(!report.session.session_id.is_empty());
    assert_eq!(report.session.protocol_id, "test");

    // Input snapshot should have counts
    assert!(!report.session.input.input_hash.is_empty());

    // Context should have baseline version
    assert_eq!(report.session.context.baseline_version, "gen2-baseline");
}

// ─────────────────────────────────────────────────────────────
// 2. CapabilityGraph with compositions
// ─────────────────────────────────────────────────────────────

#[test]
fn capability_graph_with_compositions() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;
    function deposit() external payable {
        balances[msg.sender] += 100;
    }
    function withdraw() external {
        (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
"#;
    let report = analyze_source(source);

    // Should have capability graph
    assert!(!report.session.capability_graph.nodes.is_empty());

    // Should have compositions (reenter + split if both present)
    let has_reenter = report
        .session
        .capability_graph
        .has(&CapabilityKind::CanReenter);
    let has_split = report
        .session
        .capability_graph
        .has(&CapabilityKind::CanSplitAcrossTransactions);
    if has_reenter && has_split {
        assert!(!report.session.capability_graph.compositions.is_empty());
        let comp = &report.session.capability_graph.compositions[0];
        assert_eq!(
            comp.composite,
            CompositeCapabilityKind::MultiTransactionReentrancy
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 3. CapabilityComposition primitive
// ─────────────────────────────────────────────────────────────

#[test]
fn capability_composition_structure() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;
    function withdraw() external {
        (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
"#;
    let report = analyze_source(source);

    for comp in &report.session.capability_graph.compositions {
        assert!(!comp.composition_id.is_empty());
        assert!(!comp.capabilities.is_empty());
        assert!(!comp.reason.is_empty());
        assert!(!comp.discovered_by.is_empty());
    }
}

// ─────────────────────────────────────────────────────────────
// 4. ConfidenceWeights
// ─────────────────────────────────────────────────────────────

#[test]
fn confidence_weights_default() {
    let weights = ConfidenceWeights::default();
    assert_eq!(weights.model_diversity, 0.4);
    assert_eq!(weights.prerequisite_satisfaction, 0.3);
    assert_eq!(weights.path_parsimony, 0.2);
    assert_eq!(weights.evidence_edge_density, 0.1);
    let sum = weights.model_diversity
        + weights.prerequisite_satisfaction
        + weights.path_parsimony
        + weights.evidence_edge_density;
    assert!((sum - 1.0).abs() < 0.001, "Weights should sum to 1.0");
}

// ─────────────────────────────────────────────────────────────
// 5. EvidenceGraph with TemporalSequence
// ─────────────────────────────────────────────────────────────

#[test]
fn evidence_source_temporal_sequence() {
    // TemporalSequence is a valid evidence source
    let src = EvidenceSource::TemporalSequence;
    assert_eq!(src.to_string(), "temporal_sequence");
}

// ─────────────────────────────────────────────────────────────
// 6. ReasoningContext
// ─────────────────────────────────────────────────────────────

#[test]
fn reasoning_context_present() {
    let source = r#"
contract Test {
    function foo() public {}
}
"#;
    let report = analyze_source(source);

    assert_eq!(report.session.context.scope, "single_file");
    assert_eq!(report.session.context.baseline_version, "gen2-baseline");
    assert_eq!(report.session.context.max_capabilities, 50);
    assert_eq!(report.session.context.max_attack_paths, 100);
}

// ─────────────────────────────────────────────────────────────
// 7. InputSnapshot
// ─────────────────────────────────────────────────────────────

#[test]
fn input_snapshot_counts() {
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

    let input = &report.session.input;
    // Should have at least some transitions
    assert!(input.transition_count > 0);
    // Input hash should be deterministic
    assert!(!input.input_hash.is_empty());
}

// ─────────────────────────────────────────────────────────────
// 8. Deterministic output
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
// 9. Serialization roundtrip
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

// ─────────────────────────────────────────────────────────────
// 10. Summary statistics
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

    assert_eq!(report.summary.total_capabilities, report.capabilities.len());
    assert_eq!(report.summary.total_attack_paths, report.attack_paths.len());
    assert_eq!(report.summary.total_hypotheses, report.hypotheses.len());
    assert!(report.summary.total_rules_applied > 0);
}

// ─────────────────────────────────────────────────────────────
// 11. No exploit signatures
// ─────────────────────────────────────────────────────────────

#[test]
fn no_exploit_signatures() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;
    function withdraw() external {
        (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
"#;
    let report = analyze_source(source);
    let json = report_to_json(&report);

    assert!(!json.contains("reentrancy_attack"));
    assert!(!json.contains("flash_loan"));
    assert!(!json.contains("heuristic"));
    assert!(!json.contains("probability"));
}

// ─────────────────────────────────────────────────────────────
// 12. Backward compatibility
// ─────────────────────────────────────────────────────────────

#[test]
fn backward_compat_flat_capabilities() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;
    function withdraw() external {
        (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
"#;
    let report = analyze_source(source);

    assert_eq!(
        report.capabilities.len(),
        report.session.capability_graph.nodes.len()
    );
    let has_call = report
        .capabilities
        .iter()
        .any(|c| c.kind == CapabilityKind::CanCallPublicFunction);
    assert!(has_call);
}

// ─────────────────────────────────────────────────────────────
// 13. GoalCapabilityPattern
// ─────────────────────────────────────────────────────────────

#[test]
fn goal_capability_pattern_serializable() {
    let pattern = GoalCapabilityPattern {
        pattern_id: "test:pattern".into(),
        goal: AttackGoal::DrainAssets,
        required_capabilities: vec![CapabilityKind::CanReenter],
        constraint_source: EvidenceSource::EconomicRelation,
        constraint_type: "conservation".into(),
        violated_constraint: "conservation".into(),
        rule_id: "search:drain_assets".into(),
    };

    let json = serde_json::to_string(&pattern).unwrap();
    let deserialized: GoalCapabilityPattern = serde_json::from_str(&json).unwrap();
    assert_eq!(pattern, deserialized);
}
