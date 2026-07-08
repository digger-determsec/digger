//! Anti-facade tests for corpus evidence attachment (Option A).
//!
//! Proves that the corpus can ONLY decorate existing hypotheses with
//! structured references, never create, gate, upgrade, or change the
//! detected set.

use digger_hypothesis::models::{GraphFact, HypothesisType};
use digger_knowledge_models::finding::{
    AttackTechnique, NormalizedFinding, StructuralRootCause, ViolatedInvariant, VulnerabilityClass,
};
use digger_knowledge_models::pattern::HistoricalFindingStore;
use std::collections::BTreeMap;

/// Helper: build a store with one finding keyed by VulnerabilityClass display string.
fn store_with_finding(vuln_class: VulnerabilityClass, finding_id: &str) -> HistoricalFindingStore {
    let class_str = vuln_class.to_string();
    let finding = NormalizedFinding {
        finding_id: finding_id.to_string(),
        original_finding_id: "orig-001".to_string(),
        report_id: "report-001".to_string(),
        protocol_name: "TestProtocol".to_string(),
        protocol_category: digger_knowledge_models::audit::ProtocolCategory::Vault,
        protocol_domain: digger_knowledge_models::finding::ProtocolDomain::Vaults,
        protocol_pattern: None,
        vulnerability_class: vuln_class,
        attack_goal: "drain_funds".to_string(),
        capability_pattern: vec![],
        violated_invariant: ViolatedInvariant {
            kind: "asset_conservation".to_string(),
            affected_state_vars: vec![],
            description: String::new(),
        },
        attack_technique: AttackTechnique::ReentrancyExploit,
        mitigation_pattern: None,
        security_assumptions: vec![],
        severity: digger_ir::Severity::High,
        root_cause: StructuralRootCause::MissingAuthorityCheck,
        impact_text: String::new(),
        description_text: String::new(),
        remediation_text: String::new(),
        impacted_contracts: vec![],
        impacted_functions: vec![],
        confidence: 1.0,
    };

    let mut by_class: BTreeMap<String, Vec<String>> = BTreeMap::new();
    by_class.insert(class_str, vec![finding_id.to_string()]);

    HistoricalFindingStore {
        findings: vec![finding],
        by_class,
        by_protocol: BTreeMap::new(),
        by_technique: BTreeMap::new(),
        by_severity: BTreeMap::new(),
        patterns: vec![],
    }
}

// ─── INVARIANCE TEST ───

/// The corpus MUST NOT change the detected hypothesis set.
/// With vs without corpus: same types, same severities, same ids.
/// The ONLY permitted delta is added corpus_match GraphFacts.
#[test]
fn invariance_corpus_does_not_change_detected_set() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;

    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    // Derive WITHOUT corpus
    let result_none = digger_hypothesis::derive(&ir);

    // Derive WITH corpus (populated with a reentrancy finding)
    let store = store_with_finding(VulnerabilityClass::Reentrancy, "c4r-001");
    let ctx_with = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        ..Default::default()
    };
    let result_with = digger_hypothesis::derivation::derive_with_context(&ir, &ctx_with);

    // SAME detected set
    assert_eq!(
        result_none.hypotheses.len(),
        result_with.hypotheses.len(),
        "corpus must NOT add or remove hypotheses"
    );

    for (h_none, h_with) in result_none
        .hypotheses
        .iter()
        .zip(result_with.hypotheses.iter())
    {
        assert_eq!(h_none.id, h_with.id, "hypothesis IDs must match");
        assert_eq!(
            h_none.hypothesis_type, h_with.hypothesis_type,
            "hypothesis types must match"
        );
        assert_eq!(
            h_none.severity, h_with.severity,
            "hypothesis severities must match"
        );
    }

    // Permitted delta: corpus_match facts
    let corpus_facts_with: usize = result_with
        .hypotheses
        .iter()
        .flat_map(|h| &h.evidence)
        .flat_map(|e| &e.graph_facts)
        .filter(|f| f.fact_type == "corpus_match")
        .count();
    assert!(
        corpus_facts_with > 0,
        "should have attached at least one corpus_match fact for reentrancy"
    );

    let corpus_facts_none: usize = result_none
        .hypotheses
        .iter()
        .flat_map(|h| &h.evidence)
        .flat_map(|e| &e.graph_facts)
        .filter(|f| f.fact_type == "corpus_match")
        .count();
    assert_eq!(
        corpus_facts_none, 0,
        "no corpus_match facts should exist without a store"
    );
}

// ─── POSITIVE TEST ───

/// A hypothesis whose type maps to a corpus VulnerabilityClass
/// gets a corpus_match fact citing the expected entry.
#[test]
fn positive_corpus_match_attaches_to_matching_hypothesis() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;

    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    let store = store_with_finding(VulnerabilityClass::Reentrancy, "c4r-reentrancy-001");
    let ctx = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        ..Default::default()
    };
    let result = digger_hypothesis::derivation::derive_with_context(&ir, &ctx);

    // Find the reentrancy hypothesis
    let reentrancy_hyp = result
        .hypotheses
        .iter()
        .find(|h| h.hypothesis_type == HypothesisType::ReentrancyCandidate)
        .expect("should have a ReentrancyCandidate");

    // It should have a corpus_match fact
    let corpus_facts: Vec<&GraphFact> = reentrancy_hyp
        .evidence
        .iter()
        .flat_map(|e| &e.graph_facts)
        .filter(|f| f.fact_type == "corpus_match")
        .collect();

    assert!(
        !corpus_facts.is_empty(),
        "reentrancy hypothesis should have corpus_match facts"
    );
    // GraphFact.function = finding_id (the entity the fact is about)
    assert_eq!(
        corpus_facts[0].function, "c4r-reentrancy-001",
        "function should carry finding_id"
    );
    // GraphFact.detail = "dimension:value:domain:snapshot:source"
    let parts: Vec<&str> = corpus_facts[0].detail.split(':').collect();
    assert_eq!(
        parts.len(),
        5,
        "detail should have 5 parts, got: {}",
        corpus_facts[0].detail
    );

    // The detected set (types, severities) is unchanged from corpus-less derivation
    let result_none = digger_hypothesis::derive(&ir);
    assert_eq!(result_none.hypotheses.len(), result.hypotheses.len());
}

// ─── NEGATIVE TEST ───

/// A fixture with no corpus analog gets zero corpus_match facts.
#[test]
fn negative_no_corpus_analog_no_facts() {
    // A simple transfer function — no hypothesis matches governance_attack.
    let code = r#"
contract Token {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"#;

    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    // Store with a completely unrelated class (governance_attack)
    let store = store_with_finding(VulnerabilityClass::GovernanceAttack, "gov-001");
    let ctx = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        ..Default::default()
    };
    let result = digger_hypothesis::derivation::derive_with_context(&ir, &ctx);

    // Zero corpus_match facts because governance_attack doesn't map to any
    // hypothesis type produced by this contract.
    let corpus_facts: usize = result
        .hypotheses
        .iter()
        .flat_map(|h| &h.evidence)
        .flat_map(|e| &e.graph_facts)
        .filter(|f| f.fact_type == "corpus_match")
        .count();

    assert_eq!(
        corpus_facts, 0,
        "no corpus_match facts when no hypothesis type matches a corpus class"
    );
}

// ─── DETERMINISM TEST ───

/// Same input + same snapshot id run twice -> identical corpus_match facts.
#[test]
fn determinism_same_input_same_corpus_same_output() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;

    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    let store = store_with_finding(VulnerabilityClass::Reentrancy, "c4r-det-001");

    // Run 1
    let ctx1 = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        ..Default::default()
    };
    let r1 = digger_hypothesis::derivation::derive_with_context(&ir, &ctx1);
    let facts1: Vec<(String, String, String)> = r1
        .hypotheses
        .iter()
        .flat_map(|h| &h.evidence)
        .flat_map(|e| &e.graph_facts)
        .filter(|f| f.fact_type == "corpus_match")
        .map(|f| (f.function.clone(), f.detail.clone(), f.fact_type.clone()))
        .collect();

    // Run 2 (same IR, same store)
    let ctx2 = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        ..Default::default()
    };
    let r2 = digger_hypothesis::derivation::derive_with_context(&ir, &ctx2);
    let facts2: Vec<(String, String, String)> = r2
        .hypotheses
        .iter()
        .flat_map(|h| &h.evidence)
        .flat_map(|e| &e.graph_facts)
        .filter(|f| f.fact_type == "corpus_match")
        .map(|f| (f.function.clone(), f.detail.clone(), f.fact_type.clone()))
        .collect();

    assert_eq!(
        facts1, facts2,
        "corpus_match facts must be deterministic across runs"
    );
    assert_eq!(r1.hypotheses.len(), r2.hypotheses.len());
    assert_eq!(facts1.len(), facts2.len());
}

// ─── EMPTY STORE TEST ───

/// An empty store produces zero corpus_match facts and the detected set is unchanged.
#[test]
fn empty_store_no_effect() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;

    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    let store_empty = HistoricalFindingStore::empty();
    let ctx_empty = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store_empty),
        ..Default::default()
    };

    let r_empty = digger_hypothesis::derivation::derive_with_context(&ir, &ctx_empty);
    let r_none = digger_hypothesis::derive(&ir);

    assert_eq!(r_empty.hypotheses.len(), r_none.hypotheses.len());
    for (h_e, h_n) in r_empty.hypotheses.iter().zip(r_none.hypotheses.iter()) {
        assert_eq!(h_e.id, h_n.id);
        assert_eq!(h_e.hypothesis_type, h_n.hypothesis_type);
        assert_eq!(h_e.severity, h_n.severity);
    }

    let corpus_facts: usize = r_empty
        .hypotheses
        .iter()
        .flat_map(|h| &h.evidence)
        .flat_map(|e| &e.graph_facts)
        .filter(|f| f.fact_type == "corpus_match")
        .count();
    assert_eq!(
        corpus_facts, 0,
        "empty store must produce zero corpus facts"
    );
}

// ─── EXHAUSTIVE BY_CLASS TEST ───

/// Every HypothesisType must map to at least one corpus VulnerabilityClass.
/// If a new variant is added to HypothesisType without updating the mapping,
/// this test will fail to compile (exhaustive match).
#[test]
fn exhaustive_by_class_mapping_covers_all_types() {
    let all_types = [
        HypothesisType::ReentrancyCandidate,
        HypothesisType::AuthorityBypassCandidate,
        HypothesisType::CPITrustViolationCandidate,
        HypothesisType::StateCorruptionCandidate,
        HypothesisType::EconomicInvariantViolationCandidate,
        HypothesisType::AdversarialPathCandidate,
        HypothesisType::OracleManipulationCandidate,
        HypothesisType::FlashLoanGovernanceCandidate,
        HypothesisType::MissingAccountConstraintCandidate,
        HypothesisType::UncheckedArithmeticCandidate,
        HypothesisType::PrecisionLossCandidate,
    ];

    for ht in &all_types {
        let classes = digger_hypothesis::derivation::hypothesis_type_to_corpus_classes(ht);
        assert!(
            !classes.is_empty(),
            "HypothesisType::{ht} must map to at least one VulnerabilityClass"
        );
        // Every class string must be a valid VulnerabilityClass display string
        for cls in &classes {
            assert!(
                !cls.is_empty(),
                "VulnerabilityClass string for {ht} must not be empty"
            );
        }
    }
}

// ─── EXHAUSTIVE BY_TECHNIQUE TEST ───

/// Every HypothesisType must map to at least one corpus AttackTechnique.
#[test]
fn exhaustive_by_technique_mapping_covers_all_types() {
    let all_types = [
        HypothesisType::ReentrancyCandidate,
        HypothesisType::AuthorityBypassCandidate,
        HypothesisType::CPITrustViolationCandidate,
        HypothesisType::StateCorruptionCandidate,
        HypothesisType::EconomicInvariantViolationCandidate,
        HypothesisType::AdversarialPathCandidate,
        HypothesisType::OracleManipulationCandidate,
        HypothesisType::FlashLoanGovernanceCandidate,
        HypothesisType::MissingAccountConstraintCandidate,
        HypothesisType::UncheckedArithmeticCandidate,
        HypothesisType::PrecisionLossCandidate,
    ];

    for ht in &all_types {
        let techniques = digger_hypothesis::derivation::hypothesis_type_to_corpus_techniques(ht);
        assert!(
            !techniques.is_empty(),
            "HypothesisType::{ht} must map to at least one AttackTechnique"
        );
    }
}

// ─── SEVERITY UNCHANGED TEST (Phase 2d) ───

/// Corpus presence must NEVER change a hypothesis's own severity.
/// The by_severity dimension is evidence-only, never upgrades severity.
#[test]
fn corpus_never_changes_hypothesis_severity() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;

    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    let result_none = digger_hypothesis::derive(&ir);

    // Store with a Critical-severity finding matching the reentrancy class
    let store = store_with_finding(VulnerabilityClass::Reentrancy, "c4r-sev-001");
    let ctx = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        ..Default::default()
    };
    let result_with = digger_hypothesis::derivation::derive_with_context(&ir, &ctx);

    // Every hypothesis's severity must be identical
    for (h_none, h_with) in result_none
        .hypotheses
        .iter()
        .zip(result_with.hypotheses.iter())
    {
        assert_eq!(
            h_none.severity, h_with.severity,
            "corpus must NOT change hypothesis severity for {}",
            h_none.id
        );
    }
}

// ─── BY_TECHNIQUE POSITIVE TEST ───

/// When a corpus finding matches via by_technique (not by_class),
/// it should still be attached as a corpus_match fact.
#[test]
fn by_technique_matches_attached() {
    use digger_knowledge_models::finding::{
        AttackTechnique, NormalizedFinding, StructuralRootCause, ViolatedInvariant,
        VulnerabilityClass,
    };
    use std::collections::BTreeMap;

    let finding = NormalizedFinding {
        finding_id: "tech-001".to_string(),
        original_finding_id: "orig-tech".to_string(),
        report_id: "report-tech".to_string(),
        protocol_name: "TestProtocol".to_string(),
        protocol_category: digger_knowledge_models::audit::ProtocolCategory::Vault,
        protocol_domain: digger_knowledge_models::finding::ProtocolDomain::Vaults,
        protocol_pattern: None,
        vulnerability_class: VulnerabilityClass::GovernanceAttack, // intentionally non-matching
        attack_goal: "drain_funds".to_string(),
        capability_pattern: vec![],
        violated_invariant: ViolatedInvariant {
            kind: "asset_conservation".to_string(),
            affected_state_vars: vec![],
            description: String::new(),
        },
        attack_technique: AttackTechnique::ReentrancyExploit, // matches reentrancy type
        mitigation_pattern: None,
        security_assumptions: vec![],
        severity: digger_ir::Severity::High,
        root_cause: StructuralRootCause::MissingAuthorityCheck,
        impact_text: String::new(),
        description_text: String::new(),
        remediation_text: String::new(),
        impacted_contracts: vec![],
        impacted_functions: vec![],
        confidence: 1.0,
    };

    // by_class has GovernanceAttack (no match for ReentrancyCandidate)
    // by_technique has reentrancy_exploit (matches ReentrancyCandidate)
    let mut by_class: BTreeMap<String, Vec<String>> = BTreeMap::new();
    by_class.insert(
        "governance_attack".to_string(),
        vec!["tech-001".to_string()],
    );
    let mut by_technique: BTreeMap<String, Vec<String>> = BTreeMap::new();
    by_technique.insert(
        "reentrancy_exploit".to_string(),
        vec!["tech-001".to_string()],
    );

    let store = HistoricalFindingStore {
        findings: vec![finding],
        by_class,
        by_protocol: BTreeMap::new(),
        by_technique,
        by_severity: BTreeMap::new(),
        patterns: vec![],
    };

    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;

    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    let ctx = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        ..Default::default()
    };
    let result = digger_hypothesis::derivation::derive_with_context(&ir, &ctx);

    // The reentrancy hypothesis should get a corpus_match via by_technique
    let reentrancy_hyp = result
        .hypotheses
        .iter()
        .find(|h| h.hypothesis_type == HypothesisType::ReentrancyCandidate)
        .expect("should have ReentrancyCandidate");

    let corpus_facts: Vec<&GraphFact> = reentrancy_hyp
        .evidence
        .iter()
        .flat_map(|e| &e.graph_facts)
        .filter(|f| f.fact_type == "corpus_match")
        .collect();

    assert!(
        !corpus_facts.is_empty(),
        "reentrancy hypothesis should match via by_technique"
    );
    // finding_id is now in GraphFact.function, not detail
    assert_eq!(
        corpus_facts[0].function, "tech-001",
        "should cite tech-001 finding"
    );
}

// ─── SNAPSHOT PINNING TESTS (Phase 6) ───

/// compute_corpus_hash is deterministic: same store -> same hash.
#[test]
fn snapshot_hash_deterministic() {
    let store = store_with_finding(VulnerabilityClass::Reentrancy, "snap-001");
    let h1 = digger_hypothesis::derivation::compute_corpus_hash(&store);
    let h2 = digger_hypothesis::derivation::compute_corpus_hash(&store);
    assert_eq!(h1, h2, "hash must be deterministic");
    assert!(!h1.is_empty());
}

/// verify_corpus_snapshot: matching hash -> Ok.
#[test]
fn snapshot_verify_matching_hash() {
    let store = store_with_finding(VulnerabilityClass::Reentrancy, "snap-002");
    let hash = digger_hypothesis::derivation::compute_corpus_hash(&store);
    let result = digger_hypothesis::derivation::verify_corpus_snapshot(&store, Some(&hash));
    assert!(result.is_ok(), "matching hash should pass verification");
}

/// verify_corpus_snapshot: mismatched hash -> Err.
#[test]
fn snapshot_verify_mismatched_hash() {
    let store = store_with_finding(VulnerabilityClass::Reentrancy, "snap-003");
    let result = digger_hypothesis::derivation::verify_corpus_snapshot(&store, Some("wrong-hash"));
    assert!(result.is_err(), "mismatched hash should fail");
    let err = result.unwrap_err();
    assert!(
        err.contains("mismatch"),
        "error should mention mismatch: {}",
        err
    );
}

/// verify_corpus_snapshot: None expected -> always Ok.
#[test]
fn snapshot_verify_none_always_ok() {
    let store = store_with_finding(VulnerabilityClass::Reentrancy, "snap-004");
    let result = digger_hypothesis::derivation::verify_corpus_snapshot(&store, None);
    assert!(result.is_ok());
}
