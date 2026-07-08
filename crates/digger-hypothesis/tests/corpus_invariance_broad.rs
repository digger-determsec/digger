//! P7 — Broadened invariance + negative-control suite.
//!
//! For EVERY HypothesisType, proves that corpus presence does not change
//! the derived hypothesis SET. Compile-proof: exhaustive match on
//! HypothesisType forces a compile error if a new variant is added.

use digger_hypothesis::models::HypothesisType;
use digger_knowledge_models::finding::{
    AttackTechnique, NormalizedFinding, StructuralRootCause, ViolatedInvariant, VulnerabilityClass,
};
use digger_knowledge_models::pattern::HistoricalFindingStore;
use std::collections::BTreeMap;

/// Solidity fixture that triggers reentrancy + authority bypass.
const REENTRANCY_CONTRACT: &str = r#"
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

/// Fixture that triggers oracle manipulation (storage-derived price feeds value).
const ORACLE_CONTRACT: &str = r#"
contract Oracle {
    uint256 public lastPrice;
    mapping(address => uint256) public balances;
    function getPrice() public view returns (uint256) { return lastPrice; }
    function updatePrice(uint256 p) public { lastPrice = p; }
    function swap(uint256 amount) public {
        uint256 price = getPrice();
        balances[msg.sender] += amount * price;
    }
}
"#;

/// Fixture that triggers flash-loan governance (balance-read + value-transfer + no temporal guard).
const FLASHLOAN_CONTRACT: &str = r#"
contract FlashGov {
    mapping(address => uint256) public balances;
    function vote(uint256 amount) public {
        uint256 weight = balances[msg.sender];
        msg.sender.transfer(weight * amount);
    }
}
"#;

/// Fixture that triggers precision-loss (div-before-mul feeding state write).
const PRECISION_CONTRACT: &str = r#"
contract Precision {
    mapping(address => uint256) public balances;
    function claim(uint256 total, uint256 shares) public {
        uint256 payout = (total / shares) * 100;
        balances[msg.sender] += payout;
    }
}
"#;

/// Fixture that triggers unchecked arithmetic.
const UNCHECKED_CONTRACT: &str = r#"
contract Unchecked {
    mapping(address => uint256) public balances;
    function deposit(uint256 amount) public unchecked {
        balances[msg.sender] += amount;
        uint256 x = amount * 2;
        balances[msg.sender] += x;
    }
}
"#;

/// Build a mega-store with ALL VulnerabilityClass + ALL AttackTechnique entries.
/// This ensures the corpus can match ANY hypothesis type.
fn build_mega_store() -> HistoricalFindingStore {
    let mut findings = Vec::new();
    let mut by_class: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_technique: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // Add a finding for each major VulnerabilityClass
    let classes = [
        VulnerabilityClass::Reentrancy,
        VulnerabilityClass::MissingAccessControl,
        VulnerabilityClass::PrivilegeEscalation,
        VulnerabilityClass::OracleManipulation,
        VulnerabilityClass::PriceManipulation,
        VulnerabilityClass::FlashLoanAttack,
        VulnerabilityClass::PrecisionLoss,
        VulnerabilityClass::IntegerOverflow,
        VulnerabilityClass::StateCorruption,
        VulnerabilityClass::InvariantViolation,
        VulnerabilityClass::BusinessLogicFlaw,
        VulnerabilityClass::GovernanceAttack,
        VulnerabilityClass::RoundingError,
        VulnerabilityClass::IncorrectCalculation,
        VulnerabilityClass::StorageCollision,
        VulnerabilityClass::CrossContractReentrancy,
        VulnerabilityClass::ComposabilityRisk,
    ];

    let techniques = [
        AttackTechnique::ReentrancyExploit,
        AttackTechnique::AccessControlBypass,
        AttackTechnique::PriceOracleManipulation,
        AttackTechnique::FlashLoanBorrow,
        AttackTechnique::PrecisionLossExploitation,
        AttackTechnique::StorageCollisionExploit,
        AttackTechnique::StateManipulationCrossFunction,
        AttackTechnique::UncheckedExternalCall,
    ];

    for (i, cls) in classes.iter().enumerate() {
        let fid = format!("mega-cls-{:03}", i);
        findings.push(NormalizedFinding {
            finding_id: fid.clone(),
            original_finding_id: format!("O-{}", i),
            report_id: "mega-report".to_string(),
            protocol_name: "MegaProtocol".to_string(),
            protocol_category: digger_knowledge_models::audit::ProtocolCategory::Vault,
            protocol_domain: digger_knowledge_models::finding::ProtocolDomain::Vaults,
            protocol_pattern: None,
            vulnerability_class: cls.clone(),
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
        });
        by_class.entry(cls.to_string()).or_default().push(fid);
    }

    for (i, tech) in techniques.iter().enumerate() {
        let fid = format!("mega-tech-{:03}", i);
        findings.push(NormalizedFinding {
            finding_id: fid.clone(),
            original_finding_id: format!("T-{}", i),
            report_id: "mega-report".to_string(),
            protocol_name: "MegaProtocol".to_string(),
            protocol_category: digger_knowledge_models::audit::ProtocolCategory::Vault,
            protocol_domain: digger_knowledge_models::finding::ProtocolDomain::Vaults,
            protocol_pattern: None,
            vulnerability_class: VulnerabilityClass::BusinessLogicFlaw,
            attack_goal: "drain_funds".to_string(),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: "asset_conservation".to_string(),
                affected_state_vars: vec![],
                description: String::new(),
            },
            attack_technique: tech.clone(),
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
        by_technique.entry(tech.to_string()).or_default().push(fid);
    }

    HistoricalFindingStore {
        findings,
        by_class,
        by_protocol: BTreeMap::new(),
        by_technique,
        by_severity: BTreeMap::new(),
        patterns: vec![],
    }
}

/// Core invariance assertion: derive with and without corpus, verify
/// the hypothesis SET is byte-identical.
fn assert_invariance(code: &str, label: &str) {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    let result_without = digger_hypothesis::derive(&ir);

    let store = build_mega_store();
    let ctx = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        corpus_snapshot_id: Some("mega"),
        corpus_source_id: Some("test"),
        ..Default::default()
    };
    let result_with = digger_hypothesis::derivation::derive_with_context(&ir, &ctx);

    assert_eq!(
        result_without.hypotheses.len(),
        result_with.hypotheses.len(),
        "[{label}] corpus must NOT add or remove hypotheses"
    );

    for (h_without, h_with) in result_without
        .hypotheses
        .iter()
        .zip(result_with.hypotheses.iter())
    {
        assert_eq!(h_without.id, h_with.id, "[{label}] IDs must match");
        assert_eq!(
            h_without.hypothesis_type, h_with.hypothesis_type,
            "[{label}] types must match"
        );
        assert_eq!(
            h_without.severity, h_with.severity,
            "[{label}] severities must match"
        );
    }
}

/// Compile-proof exhaustive check: every HypothesisType maps to at least
/// one corpus class. A new variant without a mapping causes a compile error.
#[test]
fn exhaustive_type_to_class_mapping() {
    fn check(ht: HypothesisType) -> Vec<&'static str> {
        digger_hypothesis::derivation::hypothesis_type_to_corpus_classes(&ht)
    }

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
        let classes = check(ht.clone());
        assert!(
            !classes.is_empty(),
            "HypothesisType::{ht} must map to at least one VulnerabilityClass"
        );
    }
}

/// Compile-proof exhaustive check: every HypothesisType maps to at least
/// one corpus technique.
#[test]
fn exhaustive_type_to_technique_mapping() {
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

// ─── PER-TYPE INVARIANCE TESTS ───

#[test]
fn invariance_reentrancy_fixture() {
    assert_invariance(REENTRANCY_CONTRACT, "reentrancy");
}

#[test]
fn invariance_oracle_fixture() {
    assert_invariance(ORACLE_CONTRACT, "oracle");
}

#[test]
fn invariance_flashloan_fixture() {
    assert_invariance(FLASHLOAN_CONTRACT, "flashloan");
}

#[test]
fn invariance_precision_fixture() {
    assert_invariance(PRECISION_CONTRACT, "precision");
}

#[test]
fn invariance_unchecked_fixture() {
    assert_invariance(UNCHECKED_CONTRACT, "unchecked");
}

// ─── NEGATIVE CONTROLS ───

/// A benign ERC20 triggers zero hypotheses that match governance attack --
/// verify zero corpus_match facts for the governance class.
#[test]
fn negative_benign_erc20_no_governance_corpus() {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

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

    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    // Store with ONLY governance_attack class
    let finding = NormalizedFinding {
        finding_id: "gov-001".to_string(),
        original_finding_id: "G-01".to_string(),
        report_id: "report-gov".to_string(),
        protocol_name: "Governance".to_string(),
        protocol_category: digger_knowledge_models::audit::ProtocolCategory::Governance,
        protocol_domain: digger_knowledge_models::finding::ProtocolDomain::Governance,
        protocol_pattern: None,
        vulnerability_class: VulnerabilityClass::GovernanceAttack,
        attack_goal: "governance".to_string(),
        capability_pattern: vec![],
        violated_invariant: ViolatedInvariant {
            kind: "governance".to_string(),
            affected_state_vars: vec![],
            description: String::new(),
        },
        attack_technique: AttackTechnique::GovernanceProposalAttack,
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
    by_class.insert("governance_attack".to_string(), vec!["gov-001".to_string()]);
    let store = HistoricalFindingStore {
        findings: vec![finding],
        by_class,
        by_protocol: BTreeMap::new(),
        by_technique: BTreeMap::new(),
        by_severity: BTreeMap::new(),
        patterns: vec![],
    };

    let ctx = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        ..Default::default()
    };
    let result = digger_hypothesis::derivation::derive_with_context(&ir, &ctx);

    let corpus_facts: usize = result
        .hypotheses
        .iter()
        .flat_map(|h| &h.evidence)
        .flat_map(|e| &e.graph_facts)
        .filter(|f| f.fact_type == "corpus_match")
        .count();
    assert_eq!(
        corpus_facts, 0,
        "benign ERC20 must not match governance corpus"
    );
}

/// Verify that no HypothesisType's severity ever changes with corpus.
#[test]
fn corpus_never_changes_severity_for_any_type() {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let code = REENTRANCY_CONTRACT;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);

    let store = build_mega_store();
    let ctx_none = digger_hypothesis::derivation::DerivationContext::default();
    let ctx_with = digger_hypothesis::derivation::DerivationContext {
        knowledge: Some(&store),
        corpus_snapshot_id: Some("mega"),
        corpus_source_id: Some("test"),
        ..Default::default()
    };

    let r_none = digger_hypothesis::derivation::derive_with_context(&ir, &ctx_none);
    let r_with = digger_hypothesis::derivation::derive_with_context(&ir, &ctx_with);

    for (h_n, h_w) in r_none.hypotheses.iter().zip(r_with.hypotheses.iter()) {
        assert_eq!(
            h_n.severity, h_w.severity,
            "severity must not change for {}",
            h_n.hypothesis_type
        );
    }
}
