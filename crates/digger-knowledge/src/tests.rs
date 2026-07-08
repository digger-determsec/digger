use crate::analytics::compute_analytics;
use crate::classifier::{are_semantically_equivalent, classify_from_findings, find_equivalents};
use crate::defillama::{fetch_hacks, ingest_defillama_hack, parse_hacks_json, DefiLlamaHack};
use crate::graph_builder::{
    build_knowledge_graph, compute_findings_hash, save_cached_graph, CachedGraph,
};
use crate::graph_traversal::{shortest_evidence_path, TraversalGraph};
use crate::normalizer::{
    classify_vulnerability, infer_capabilities, infer_mitigation_pattern, infer_violated_invariant,
    map_to_attack_goal, normalize_finding,
};
use crate::pattern_extractor::extract_patterns;
use crate::store_builder::build_store;
use crate::KnowledgeError;
use digger_ir::Severity;
use digger_knowledge_models::*;
use std::collections::BTreeMap;

fn make_extracted_finding(title: &str, description: &str) -> ExtractedFinding {
    ExtractedFinding {
        finding_id: "F-01".into(),
        title: title.into(),
        severity: FindingSeverity::High,
        impact: "Loss of funds".into(),
        likelihood: None,
        description: description.into(),
        root_cause: "unknown".into(),
        exploit_path: None,
        impacted_contracts: vec!["Vault.sol".into()],
        impacted_functions: vec!["withdraw()".into()],
        remediation: "Add access control".into(),
        status: FindingStatus::Open,
        references: vec![],
        code_snippets: vec![],
    }
}

fn make_audit_report(findings: Vec<ExtractedFinding>) -> AuditReport {
    AuditReport {
        report_id: "report:test:001".into(),
        protocol_name: "TestProtocol".into(),
        protocol_category: ProtocolCategory::Lending,
        auditor: "TestAuditor".into(),
        reviewers: vec![],
        audit_date: None,
        source_repo: "test/repo".into(),
        source_path: "test.md".into(),
        commit_hash: None,
        scope: vec![],
        findings,
        privileged_roles: vec![],
        centralization_notes: vec![],
        raw_sections: BTreeMap::new(),
    }
}

fn make_normalized_finding(vuln_class: VulnerabilityClass) -> NormalizedFinding {
    NormalizedFinding {
        finding_id: format!("nf:{:?}", vuln_class),
        original_finding_id: "F-01".into(),
        report_id: "report:test:001".into(),
        protocol_name: "TestProtocol".into(),
        protocol_category: ProtocolCategory::Lending,
        protocol_domain: ProtocolDomain::Lending,
        protocol_pattern: None,
        vulnerability_class: vuln_class.clone(),
        attack_goal: map_to_attack_goal(&vuln_class),
        capability_pattern: infer_capabilities(&vuln_class),
        violated_invariant: infer_violated_invariant(&vuln_class),
        attack_technique: AttackTechnique::ReentrancyExploit,
        mitigation_pattern: infer_mitigation_pattern(&vuln_class),
        security_assumptions: vec![],
        severity: Severity::High,
        root_cause: StructuralRootCause::Other("test".into()),
        impact_text: "Loss of funds".into(),
        description_text: "Test finding".into(),
        remediation_text: String::new(),
        impacted_contracts: vec![],
        impacted_functions: vec![],
        confidence: 1.0,
    }
}

fn make_normalized_knowledge(findings: Vec<NormalizedFinding>) -> NormalizedKnowledge {
    NormalizedKnowledge {
        knowledge_id: "knowledge:test:001".into(),
        source_id: "test".into(),
        source_kind: KnowledgeSourceKind::AuditRepository,
        source_identifier: "test.md".into(),
        subject: "TestProtocol".into(),
        subject_category: "lending".into(),
        findings,
        evidence: vec![],
        invariants: vec![],
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![],
        claims: vec![],
        raw_sections: BTreeMap::new(),
    }
}

fn make_defillama_hack(technique: &str, classification: &str, amount: f64) -> DefiLlamaHack {
    DefiLlamaHack {
        date: 1672531200,
        name: "TestHack".into(),
        classification: Some(classification.into()),
        technique: Some(technique.into()),
        amount: Some(amount),
        chain: Some(vec!["Ethereum".into()]),
        bridge_hack: None,
        target_type: Some("DeFi".into()),
        source: None,
        returned_funds: None,
        defillama_id: Some(1),
        language: None,
    }
}

// ═══════════════════════════════════════════════════════════════
// a) Non-authoritative guard
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_knowledge_output_cannot_be_mistaken_for_engine_verdict() {
    let finding =
        make_extracted_finding("Reentrancy in vault", "reentrancy exploit allows draining");
    let report = make_audit_report(vec![finding]);
    let normalized = normalize_finding(&report.findings[0], &report);

    // NormalizedFinding must NOT contain verdict labels
    let json = serde_json::to_string(&normalized).unwrap();
    assert!(
        !json.contains("Graduated"),
        "Normalized output must not contain 'Graduated'"
    );
    assert!(
        !json.contains("Confirmed"),
        "Normalized output must not contain 'Confirmed'"
    );

    // confidence field reflects source confidence (1.0 for confirmed), NOT engine verdict
    assert_eq!(
        normalized.confidence, 1.0,
        "Source confidence should be 1.0 for human-reported finding"
    );
}

// ═══════════════════════════════════════════════════════════════
// b) Determinism test
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_normalization_determinism() {
    let finding = make_extracted_finding("Reentrancy", "reentrancy exploit");
    let report = make_audit_report(vec![finding]);
    let n1 = normalize_finding(&report.findings[0], &report);
    let n2 = normalize_finding(&report.findings[0], &report);
    let j1 = serde_json::to_string(&n1).unwrap();
    let j2 = serde_json::to_string(&n2).unwrap();
    assert_eq!(
        j1, j2,
        "Two normalizations of same input must be byte-identical"
    );
}

// ═══════════════════════════════════════════════════════════════
// c) Corpus graph determinism
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_knowledge_graph_determinism() {
    let findings = vec![
        make_normalized_finding(VulnerabilityClass::Reentrancy),
        make_normalized_finding(VulnerabilityClass::FlashLoanAttack),
    ];
    let g1 = build_knowledge_graph(&findings);
    let g2 = build_knowledge_graph(&findings);
    let j1 = serde_json::to_string(&g1).unwrap();
    let j2 = serde_json::to_string(&g2).unwrap();
    assert_eq!(j1, j2, "Knowledge graph must be deterministic");
}

// ═══════════════════════════════════════════════════════════════
// d) Graph traversal determinism
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_traversal_determinism() {
    let f1 = make_normalized_finding(VulnerabilityClass::Reentrancy);
    let f2 = make_normalized_finding(VulnerabilityClass::FlashLoanAttack);
    let kn1 = make_normalized_knowledge(vec![f1.clone()]);
    let kn2 = make_normalized_knowledge(vec![f2.clone()]);

    let links = vec![SemanticLink {
        source_id: f1.finding_id.clone(),
        target_id: f2.finding_id.clone(),
        kind: LinkKind::Causes,
        score: RelationshipScore {
            score: 0.8,
            factors: vec![ScoreFactor {
                name: "test".into(),
                weight: 1.0,
                value: 0.8,
                evidence: "test evidence".into(),
            }],
        },
        description: "test link".into(),
        confidence: 1.0,
    }];

    let graph = TraversalGraph::from_links(&links, &[kn1, kn2]);
    let r1 = shortest_evidence_path(&graph, &f1.finding_id, &f2.finding_id);
    let r2 = shortest_evidence_path(&graph, &f1.finding_id, &f2.finding_id);

    match (r1, r2) {
        (Some(p1), Some(p2)) => {
            assert_eq!(p1.path.len(), p2.path.len());
            assert_eq!(p1.hops.len(), p2.hops.len());
            let j1 = serde_json::to_string(&p1).unwrap();
            let j2 = serde_json::to_string(&p2).unwrap();
            assert_eq!(j1, j2, "Traversal must be deterministic");
        }
        (None, None) => {}
        _ => panic!("Traversal results should match"),
    }
}

// ═══════════════════════════════════════════════════════════════
// e) Store builder determinism
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_store_builder_determinism() {
    let findings = vec![
        make_normalized_finding(VulnerabilityClass::Reentrancy),
        make_normalized_finding(VulnerabilityClass::FlashLoanAttack),
    ];
    let s1 = build_store(findings.clone(), vec![]);
    let s2 = build_store(findings, vec![]);
    let j1 = serde_json::to_string(&s1).unwrap();
    let j2 = serde_json::to_string(&s2).unwrap();
    assert_eq!(j1, j2, "Store builder must be deterministic");
}

// ═══════════════════════════════════════════════════════════════
// f) Round-trip tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_normalized_finding_round_trip() {
    let nf = make_normalized_finding(VulnerabilityClass::Reentrancy);
    let j1 = serde_json::to_string(&nf).unwrap();
    let nf2: NormalizedFinding = serde_json::from_str(&j1).unwrap();
    let j2 = serde_json::to_string(&nf2).unwrap();
    assert_eq!(j1, j2, "NormalizedFinding round-trip must preserve data");
}

#[test]
fn test_normalized_knowledge_round_trip() {
    let kn = make_normalized_knowledge(vec![make_normalized_finding(
        VulnerabilityClass::Reentrancy,
    )]);
    let j1 = serde_json::to_string(&kn).unwrap();
    let kn2: NormalizedKnowledge = serde_json::from_str(&j1).unwrap();
    let j2 = serde_json::to_string(&kn2).unwrap();
    assert_eq!(j1, j2, "NormalizedKnowledge round-trip must preserve data");
}

#[test]
fn test_knowledge_graph_round_trip() {
    let findings = vec![make_normalized_finding(VulnerabilityClass::Reentrancy)];
    let g = build_knowledge_graph(&findings);
    let j1 = serde_json::to_string(&g).unwrap();
    let g2: KnowledgeGraph = serde_json::from_str(&j1).unwrap();
    let j2 = serde_json::to_string(&g2).unwrap();
    assert_eq!(j1, j2, "KnowledgeGraph round-trip must preserve data");
}

#[test]
fn test_historical_finding_store_round_trip() {
    let findings = vec![make_normalized_finding(VulnerabilityClass::Reentrancy)];
    let store = build_store(findings, vec![]);
    let j1 = serde_json::to_string(&store).unwrap();
    let store2: HistoricalFindingStore = serde_json::from_str(&j1).unwrap();
    let j2 = serde_json::to_string(&store2).unwrap();
    assert_eq!(
        j1, j2,
        "HistoricalFindingStore round-trip must preserve data"
    );
}

// ═══════════════════════════════════════════════════════════════
// g) Normalization correctness
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_normalize_finding_reentrancy() {
    let finding = make_extracted_finding(
        "Reentrancy in vault",
        "reentrancy exploit allows draining funds",
    );
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);

    assert_eq!(nf.vulnerability_class, VulnerabilityClass::Reentrancy);
    assert!(!nf.attack_goal.is_empty(), "attack_goal must be non-empty");
    assert_eq!(nf.severity, Severity::High, "severity must match input");
}

#[test]
fn test_normalize_finding_flash_loan() {
    let finding = make_extracted_finding("Flash loan exploit", "flash loan attack on protocol");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(nf.vulnerability_class, VulnerabilityClass::FlashLoanAttack);
}

#[test]
fn test_normalize_finding_oracle_manipulation() {
    let finding =
        make_extracted_finding("Oracle exploit", "oracle manipulation causes price impact");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(
        nf.vulnerability_class,
        VulnerabilityClass::OracleManipulation
    );
}

#[test]
fn test_normalize_finding_access_control() {
    let finding = make_extracted_finding(
        "Unauthorized access",
        "missing access control allows unauthorized",
    );
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(
        nf.vulnerability_class,
        VulnerabilityClass::MissingAccessControl
    );
}

#[test]
fn test_normalize_finding_governance() {
    let finding = make_extracted_finding(
        "Governance exploit",
        "governance attack via proposal voting",
    );
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(nf.vulnerability_class, VulnerabilityClass::GovernanceAttack);
}

#[test]
fn test_normalize_finding_missing_validation() {
    let finding = make_extracted_finding(
        "Missing check",
        "missing validation of user input parameter",
    );
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(
        nf.vulnerability_class,
        VulnerabilityClass::MissingValidation
    );
}

#[test]
fn test_normalize_finding_denial_of_service() {
    let finding = make_extracted_finding("DoS attack", "denial of service via unexpected revert");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(nf.vulnerability_class, VulnerabilityClass::DenialOfService);
}

#[test]
fn test_normalize_finding_integer_overflow() {
    let finding = make_extracted_finding("Overflow bug", "overflow in arithmetic operation");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(nf.vulnerability_class, VulnerabilityClass::IntegerOverflow);
}

#[test]
fn test_normalize_finding_sandwich_attack() {
    let finding = make_extracted_finding("Sandwich", "sandwich attack on swap transaction");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(nf.vulnerability_class, VulnerabilityClass::SandwichAttack);
}

#[test]
fn test_normalize_finding_precision_loss() {
    let finding = make_extracted_finding("Precision loss", "precision loss due to rounding error");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(nf.vulnerability_class, VulnerabilityClass::PrecisionLoss);
}

#[test]
fn test_normalize_finding_front_running() {
    let finding = make_extracted_finding("Front-run", "front-run vulnerability in MEV context");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(nf.vulnerability_class, VulnerabilityClass::FrontRunning);
}

#[test]
fn test_normalize_finding_storage_collision() {
    let finding = make_extracted_finding("Storage clash", "storage collision in proxy upgrade");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(nf.vulnerability_class, VulnerabilityClass::StorageCollision);
}

#[test]
fn test_normalize_finding_centralization_risk() {
    let finding = make_extracted_finding("Centralization", "centralized admin can drain funds");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(
        nf.vulnerability_class,
        VulnerabilityClass::CentralizationRisk
    );
}

#[test]
fn test_normalize_finding_unprotected_initialization() {
    let finding = make_extracted_finding("Init bug", "uninitialized proxy allows takeover");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(
        nf.vulnerability_class,
        VulnerabilityClass::UnprotectedInitialization
    );
}

#[test]
fn test_normalize_finding_privilege_escalation() {
    let finding = make_extracted_finding("Privilege", "privilege escalation via missing check");
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(
        nf.vulnerability_class,
        VulnerabilityClass::PrivilegeEscalation
    );
}

// ═══════════════════════════════════════════════════════════════
// h) Edge cases
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_normalize_empty_finding() {
    let finding = ExtractedFinding {
        finding_id: "F-empty".into(),
        title: String::new(),
        severity: FindingSeverity::Low,
        impact: String::new(),
        likelihood: None,
        description: String::new(),
        root_cause: String::new(),
        exploit_path: None,
        impacted_contracts: vec![],
        impacted_functions: vec![],
        remediation: String::new(),
        status: FindingStatus::Unknown,
        references: vec![],
        code_snippets: vec![],
    };
    let report = make_audit_report(vec![finding]);
    let nf = normalize_finding(&report.findings[0], &report);
    assert_eq!(nf.severity, Severity::Low);
    assert_eq!(
        nf.vulnerability_class,
        VulnerabilityClass::Other(String::new())
    );
}

#[test]
fn test_build_store_empty_corpus() {
    let store = build_store(vec![], vec![]);
    assert!(store.is_empty());
    assert_eq!(store.total_findings(), 0);
    assert_eq!(store.total_patterns(), 0);
    let j = serde_json::to_string(&store).unwrap();
    let store2: HistoricalFindingStore = serde_json::from_str(&j).unwrap();
    assert!(store2.is_empty());
}

#[test]
fn test_classify_from_findings_empty() {
    let result = classify_from_findings(&[]);
    assert_eq!(result, ProtocolCategory::Unknown);
}

#[test]
fn test_find_equivalents_no_duplicates() {
    let findings = vec![
        make_normalized_finding(VulnerabilityClass::Reentrancy),
        make_normalized_finding(VulnerabilityClass::FlashLoanAttack),
        make_normalized_finding(VulnerabilityClass::DenialOfService),
    ];
    let equivs = find_equivalents(&findings);
    assert!(
        equivs.is_empty(),
        "Different vulnerability classes should have no equivalents"
    );
}

// ═══════════════════════════════════════════════════════════════
// i) Pattern extractor
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_extract_patterns_groups_by_class() {
    let findings = vec![
        make_normalized_finding(VulnerabilityClass::Reentrancy),
        make_normalized_finding(VulnerabilityClass::Reentrancy),
        make_normalized_finding(VulnerabilityClass::FlashLoanAttack),
        make_normalized_finding(VulnerabilityClass::FlashLoanAttack),
    ];
    let patterns = extract_patterns(&findings);
    assert_eq!(
        patterns.len(),
        2,
        "Should produce 2 patterns for 2 classes with 2+ findings each"
    );
    assert_eq!(patterns[0].vulnerability_class, "flash_loan_attack");
    assert_eq!(patterns[1].vulnerability_class, "reentrancy");
}

// ═══════════════════════════════════════════════════════════════
// j) Classifier
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_are_semantically_equivalent_same() {
    let f1 = make_normalized_finding(VulnerabilityClass::Reentrancy);
    let f2 = make_normalized_finding(VulnerabilityClass::Reentrancy);
    assert!(
        are_semantically_equivalent(&f1, &f2),
        "Same vulnerability class should be equivalent"
    );
}

#[test]
fn test_are_semantically_equivalent_different() {
    let f1 = make_normalized_finding(VulnerabilityClass::Reentrancy);
    let f2 = make_normalized_finding(VulnerabilityClass::FlashLoanAttack);
    assert!(
        !are_semantically_equivalent(&f1, &f2),
        "Different classes should not be equivalent"
    );
}

// ═══════════════════════════════════════════════════════════════
// k) Analytics
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_compute_analytics_non_empty() {
    let findings = vec![
        make_normalized_finding(VulnerabilityClass::Reentrancy),
        make_normalized_finding(VulnerabilityClass::FlashLoanAttack),
    ];
    let knowledge = make_normalized_knowledge(findings);
    let report = compute_analytics(&[knowledge]);
    assert!(
        report.overview.total_findings > 0,
        "total_findings must be non-zero"
    );
    assert_eq!(report.overview.total_reports, 1);
}

#[test]
fn test_compute_analytics_empty() {
    let report = compute_analytics(&[]);
    assert_eq!(report.overview.total_findings, 0);
    assert_eq!(report.overview.total_reports, 0);
}

// ═══════════════════════════════════════════════════════════════
// DefiLlama tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_parse_hacks_json_valid() {
    let json = r#"[{"date":1672531200,"name":"Hack1","classification":"Access Control","technique":"Private Key","amount":1000000}]"#;
    let hacks = parse_hacks_json(json);
    assert_eq!(hacks.len(), 1);
    assert_eq!(hacks[0].name, "Hack1");
    assert_eq!(hacks[0].amount, Some(1_000_000.0));
}

#[test]
fn test_parse_hacks_json_invalid() {
    let hacks = parse_hacks_json("not json");
    assert!(hacks.is_empty());
}

#[test]
fn test_parse_hacks_json_empty_array() {
    let hacks = parse_hacks_json("[]");
    assert!(hacks.is_empty());
}

#[test]
fn test_ingest_defillama_hack_reentrancy() {
    let hack = make_defillama_hack("reentrancy", "Reentrancy", 5_000_000.0);
    let knowledge = ingest_defillama_hack(&hack);
    assert_eq!(knowledge.findings.len(), 1);
    assert_eq!(
        knowledge.findings[0].vulnerability_class,
        VulnerabilityClass::Reentrancy
    );
    assert_eq!(knowledge.findings[0].severity, Severity::High);
    assert_eq!(knowledge.findings[0].confidence, 1.0);
}

#[test]
fn test_ingest_defillama_hack_flash_loan() {
    let hack = make_defillama_hack("flash loan", "Flash Loan", 2_000_000.0);
    let knowledge = ingest_defillama_hack(&hack);
    assert_eq!(
        knowledge.findings[0].vulnerability_class,
        VulnerabilityClass::FlashLoanAttack
    );
    assert_eq!(knowledge.findings[0].severity, Severity::High);
}

#[test]
fn test_fetch_hacks_returns_error() {
    let result = fetch_hacks();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("parse_hacks_json"));
}

#[test]
fn test_classify_defillama_severity() {
    let hack = make_defillama_hack("reentrancy", "Reentrancy", 10_000_000.0);
    let k = ingest_defillama_hack(&hack);
    assert_eq!(k.findings[0].severity, Severity::Critical);

    let hack = make_defillama_hack("reentrancy", "Reentrancy", 1_000_000.0);
    let k = ingest_defillama_hack(&hack);
    assert_eq!(k.findings[0].severity, Severity::High);

    let hack = make_defillama_hack("reentrancy", "Reentrancy", 100_000.0);
    let k = ingest_defillama_hack(&hack);
    assert_eq!(k.findings[0].severity, Severity::Medium);

    let hack = make_defillama_hack("reentrancy", "Reentrancy", 10_000.0);
    let k = ingest_defillama_hack(&hack);
    assert_eq!(k.findings[0].severity, Severity::Low);
}

#[test]
fn test_ingest_defillama_hack_bridge() {
    let hack = make_defillama_hack("bridge exploit", "Bridge", 500_000.0);
    let knowledge = ingest_defillama_hack(&hack);
    assert_eq!(
        knowledge.findings[0].vulnerability_class,
        VulnerabilityClass::ComposabilityRisk
    );
}

#[test]
fn test_ingest_defillama_hack_governance() {
    let hack = make_defillama_hack("governance attack", "Governance", 3_000_000.0);
    let knowledge = ingest_defillama_hack(&hack);
    assert_eq!(
        knowledge.findings[0].vulnerability_class,
        VulnerabilityClass::GovernanceAttack
    );
}

// ═══════════════════════════════════════════════════════════════
// Graph builder tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_build_knowledge_graph_single_finding() {
    let findings = vec![make_normalized_finding(VulnerabilityClass::Reentrancy)];
    let graph = build_knowledge_graph(&findings);
    assert!(!graph.nodes.is_empty());
    assert!(!graph.edges.is_empty());
}

#[test]
fn test_build_knowledge_graph_multiple_findings() {
    let findings = vec![
        make_normalized_finding(VulnerabilityClass::Reentrancy),
        make_normalized_finding(VulnerabilityClass::Reentrancy),
        make_normalized_finding(VulnerabilityClass::FlashLoanAttack),
    ];
    let graph = build_knowledge_graph(&findings);
    assert!(graph.nodes.len() > 3);
    assert!(graph.edges.len() > 3);
}

#[test]
fn test_compute_findings_hash_deterministic() {
    let findings = vec![make_normalized_finding(VulnerabilityClass::Reentrancy)];
    let h1 = compute_findings_hash(&findings);
    let h2 = compute_findings_hash(&findings);
    assert_eq!(h1, h2, "Hash must be deterministic");
}

#[test]
fn test_compute_findings_hash_different() {
    let f1 = vec![make_normalized_finding(VulnerabilityClass::Reentrancy)];
    let f2 = vec![make_normalized_finding(VulnerabilityClass::FlashLoanAttack)];
    let h1 = compute_findings_hash(&f1);
    let h2 = compute_findings_hash(&f2);
    assert_ne!(h1, h2, "Different findings should produce different hashes");
}

// ═══════════════════════════════════════════════════════════════
// Store builder tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_build_store_indices() {
    let findings = vec![
        make_normalized_finding(VulnerabilityClass::Reentrancy),
        make_normalized_finding(VulnerabilityClass::FlashLoanAttack),
    ];
    let store = build_store(findings, vec![]);
    assert_eq!(store.findings.len(), 2);
    assert!(!store.by_class.is_empty());
    assert!(!store.by_protocol.is_empty());
    assert!(!store.by_severity.is_empty());
}

// ═══════════════════════════════════════════════════════════════
// Classifier tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_find_equivalents_with_equivalents() {
    let mut f1 = make_normalized_finding(VulnerabilityClass::Reentrancy);
    f1.finding_id = "nf1".into();
    let mut f2 = make_normalized_finding(VulnerabilityClass::Reentrancy);
    f2.finding_id = "nf2".into();
    let equivs = find_equivalents(&[f1, f2]);
    assert_eq!(
        equivs.len(),
        1,
        "Two equivalent findings should produce one pair"
    );
}

#[test]
fn test_classify_from_findings_with_lending() {
    let mut f = make_normalized_finding(VulnerabilityClass::Reentrancy);
    f.impacted_contracts = vec!["LendingPool.sol".into()];
    let result = classify_from_findings(&[f]);
    assert_eq!(result, ProtocolCategory::Lending);
}

#[test]
fn test_classify_from_findings_with_dex() {
    let mut f = make_normalized_finding(VulnerabilityClass::Reentrancy);
    f.impacted_contracts = vec!["SwapRouter.sol".into()];
    let result = classify_from_findings(&[f]);
    assert_eq!(result, ProtocolCategory::DEX);
}

// ═══════════════════════════════════════════════════════════════
// Error type tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_knowledge_error_display() {
    let err = KnowledgeError::Other("test error".into());
    assert_eq!(err.to_string(), "test error");
}

#[test]
fn test_knowledge_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let err: KnowledgeError = io_err.into();
    assert!(err.to_string().contains("IO error"));
}

#[test]
fn test_knowledge_error_from_json() {
    let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
    let err: KnowledgeError = json_err.into();
    assert!(err.to_string().contains("JSON error"));
}

// ═══════════════════════════════════════════════════════════════
// save_cached_graph error test
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_save_cached_graph_to_invalid_path() {
    let findings = vec![make_normalized_finding(VulnerabilityClass::Reentrancy)];
    let graph = build_knowledge_graph(&findings);
    let cached = CachedGraph {
        content_hash: "test".into(),
        finding_count: 1,
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
        graph,
    };
    let tmp = std::env::temp_dir().join("digger_test_not_a_dir");
    std::fs::write(&tmp, "x").unwrap();
    let result = save_cached_graph(&cached, &tmp);
    assert!(result.is_err());
    std::fs::remove_file(&tmp).ok();
}

// ═══════════════════════════════════════════════════════════════
// classify_vulnerability tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_classify_vulnerability_cross_function_reentrancy() {
    let finding = make_extracted_finding("CF Reentrancy", "cross-function reentrancy attack");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::CrossFunctionReentrancy
    );
}

#[test]
fn test_classify_vulnerability_cross_contract_reentrancy() {
    let finding =
        make_extracted_finding("CC Reentrancy", "cross-contract reentrancy vulnerability");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::CrossContractReentrancy
    );
}

#[test]
fn test_classify_vulnerability_liquidation() {
    let finding =
        make_extracted_finding("Liquidation", "liquidation manipulation attack on lending");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::LiquidationManipulation
    );
}

#[test]
fn test_classify_vulnerability_price_manipulation() {
    let finding = make_extracted_finding("Price bug", "price manipulation of token price feed");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::PriceManipulation
    );
}

#[test]
fn test_classify_vulnerability_business_logic() {
    let finding = make_extracted_finding("Logic bug", "business logic flaw in withdrawal");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::BusinessLogicFlaw
    );
}

#[test]
fn test_classify_vulnerability_invariant_violation() {
    let finding =
        make_extracted_finding("Invariant broken", "invariant is violated during deposit");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::InvariantViolation
    );
}

#[test]
fn test_classify_vulnerability_state_corruption() {
    let finding = make_extracted_finding("State bug", "state corruption in storage");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::StateCorruption
    );
}

#[test]
fn test_classify_vulnerability_upgradeability() {
    let finding = make_extracted_finding("Upgrade bug", "upgrade risk in proxy pattern");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::UpgradeabilityRisk
    );
}

#[test]
fn test_classify_vulnerability_proxy_init() {
    let finding = make_extracted_finding("Proxy init", "proxy initializ vulnerability");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::ProxyInitialization
    );
}

#[test]
fn test_classify_vulnerability_timelock() {
    let finding = make_extracted_finding("Timelock", "timelock bypass in admin function");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::TimelockBypass
    );
}

#[test]
fn test_classify_vulnerability_composability() {
    let finding = make_extracted_finding("Composability", "composability risk in cross-chain");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::ComposabilityRisk
    );
}

#[test]
fn test_classify_vulnerability_mev() {
    let finding = make_extracted_finding("MEV bug", "mev extraction via frontrunning");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::FrontRunning
    );
}

#[test]
fn test_classify_vulnerability_unchecked_return() {
    let finding = make_extracted_finding(
        "Return value",
        "return value not checked from external call",
    );
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::UncheckedReturn
    );
}

#[test]
fn test_classify_vulnerability_incorrect_calculation() {
    let finding = make_extracted_finding("Calc error", "incorrect calculation in fee distribution");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::IncorrectCalculation
    );
}

#[test]
fn test_classify_vulnerability_missing_events() {
    let finding = make_extracted_finding(
        "No event",
        "missing event emission for critical state change",
    );
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::MissingValidation
    );
}

#[test]
fn test_classify_vulnerability_slippage() {
    let finding = make_extracted_finding("Slippage", "slippage protection missing on swap");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::MissingValidation
    );
}

#[test]
fn test_classify_vulnerability_zero_address() {
    let finding = make_extracted_finding("Zero addr", "zero address check missing in constructor");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::MissingValidation
    );
}

#[test]
fn test_classify_vulnerability_signature() {
    let finding = make_extracted_finding("Sig bug", "signature malleability in ecrecover");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::MissingValidation
    );
}

#[test]
fn test_classify_vulnerability_stuck_funds() {
    let finding = make_extracted_finding("Stuck", "stuck tokens in vault contract");
    assert_eq!(
        classify_vulnerability(&finding),
        VulnerabilityClass::DenialOfService
    );
}

#[test]
fn test_classify_vulnerability_fallback_other() {
    let finding = make_extracted_finding("SomethingElse", "unique novel vulnerability type");
    let result = classify_vulnerability(&finding);
    match result {
        VulnerabilityClass::Other(_) => {}
        other => panic!("Expected Other, got {:?}", other),
    }
}
