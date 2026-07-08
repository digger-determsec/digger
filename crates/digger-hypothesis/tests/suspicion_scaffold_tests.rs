//! Phase 3A — Suspicion firing logic tests (scaffold + invariance).

use digger_knowledge_models::finding::{
    AttackTechnique, NormalizedFinding, StructuralRootCause, ViolatedInvariant, VulnerabilityClass,
};
use digger_knowledge_models::pattern::HistoricalFindingStore;
use std::collections::BTreeMap;

const VULN_CONTRACT: &str = r#"
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

fn make_store(classes: &[&str]) -> HistoricalFindingStore {
    let mut findings = Vec::new();
    let mut by_class: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (i, cls) in classes.iter().enumerate() {
        let fid = format!("store-{:03}", i);
        findings.push(NormalizedFinding {
            finding_id: fid.clone(),
            original_finding_id: format!("O-{}", i),
            report_id: "r-001".to_string(),
            protocol_name: "Test".to_string(),
            protocol_category: digger_knowledge_models::audit::ProtocolCategory::Vault,
            protocol_domain: digger_knowledge_models::finding::ProtocolDomain::Vaults,
            protocol_pattern: None,
            vulnerability_class: VulnerabilityClass::Reentrancy,
            attack_goal: "drain".to_string(),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: "conservation".to_string(),
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
        });
        by_class.entry(cls.to_string()).or_default().push(fid);
    }
    HistoricalFindingStore {
        findings,
        by_class,
        by_protocol: BTreeMap::new(),
        by_technique: BTreeMap::new(),
        by_severity: BTreeMap::new(),
        patterns: vec![],
    }
}

fn derive_hypotheses(code: &str) -> digger_hypothesis::models::HypothesisResult {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    digger_hypothesis::derive(&ir)
}

fn derive_susp(
    code: &str,
    store: HistoricalFindingStore,
    snap: &str,
    src: &str,
) -> digger_hypothesis::suspicion::SuspicionResult {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let hyp = digger_hypothesis::derive(&ir);
    digger_hypothesis::suspicion::derive_suspicions(&ir, &hyp, Some(&store), Some(snap), Some(src))
}

// -- Invariance: hypothesis set identical with vs without store --

#[test]
fn invariance_hypothesis_set_unchanged() {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;
    let program = parse_program(VULN_CONTRACT, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    let ctx_none = digger_hypothesis::derivation::DerivationContext::default();
    let hyp_none = digger_hypothesis::derivation::derive_with_context(&ir, &ctx_none);

    let store = make_store(&["oracle_manipulation"]);
    let ctx_with = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        ..Default::default()
    };
    let hyp_with = digger_hypothesis::derivation::derive_with_context(&ir, &ctx_with);

    assert_eq!(hyp_none.hypotheses.len(), hyp_with.hypotheses.len());
    for (a, b) in hyp_none.hypotheses.iter().zip(hyp_with.hypotheses.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.hypothesis_type, b.hypothesis_type);
        assert_eq!(a.severity, b.severity);
    }
}

// -- Default off --

#[test]
fn default_off_empty() {
    let hyp = derive_hypotheses(VULN_CONTRACT);
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;
    let program = parse_program(VULN_CONTRACT, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = digger_hypothesis::suspicion::derive_suspicions(&ir, &hyp, None, None, None);
    assert_eq!(result.suspicions.len(), 0);
}

// -- Empty store --

#[test]
fn empty_store_no_suspicions() {
    let result = derive_susp(VULN_CONTRACT, HistoricalFindingStore::empty(), "s", "s");
    assert_eq!(result.suspicions.len(), 0);
}

// -- is_finding always false --

#[test]
fn is_finding_always_false() {
    let result = derive_susp(
        VULN_CONTRACT,
        make_store(&["oracle_manipulation"]),
        "s",
        "s",
    );
    for s in &result.suspicions {
        assert!(!s.is_finding, "suspicion {} has is_finding=true", s.id);
    }
}

// -- Determinism --

#[test]
fn determinism_same_input_same_output() {
    let store = make_store(&["oracle_manipulation"]);
    let r1 = derive_susp(VULN_CONTRACT, store.clone(), "snap", "src");
    let r2 = derive_susp(VULN_CONTRACT, store, "snap", "src");
    assert_eq!(r1.suspicions.len(), r2.suspicions.len());
    for (a, b) in r1.suspicions.iter().zip(r2.suspicions.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.class, b.class);
        assert_eq!(a.primary_function, b.primary_function);
    }
}
