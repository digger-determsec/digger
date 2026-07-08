use crate::*;
use digger_ir::Severity;

fn make_finding(id: &str) -> NormalizedFinding {
    NormalizedFinding {
        finding_id: id.to_string(),
        original_finding_id: format!("orig-{}", id),
        report_id: "report-1".to_string(),
        protocol_name: "TestProtocol".to_string(),
        protocol_category: ProtocolCategory::Lending,
        protocol_domain: ProtocolDomain::Lending,
        protocol_pattern: Some("flashloan".to_string()),
        vulnerability_class: VulnerabilityClass::Reentrancy,
        attack_goal: "drain funds".to_string(),
        capability_pattern: vec!["flash_loan".to_string()],
        violated_invariant: ViolatedInvariant {
            kind: "conservation".to_string(),
            description: "total supply must equal sum of balances".to_string(),
            affected_state_vars: vec!["totalSupply".to_string()],
        },
        attack_technique: AttackTechnique::ReentrancyExploit,
        mitigation_pattern: Some(MitigationPattern {
            technique: "reentrancy_guard".to_string(),
            description: "Use OpenZeppelin ReentrancyGuard".to_string(),
            is_standard: true,
        }),
        security_assumptions: vec![SecurityAssumption {
            assumption: "callback will not re-enter".to_string(),
            is_valid: false,
            violated_by: Some("malicious_callback".to_string()),
        }],
        severity: Severity::High,
        root_cause: StructuralRootCause::SharedMutableState,
        impact_text: "loss of funds".to_string(),
        description_text: "reentrancy in withdraw function".to_string(),
        remediation_text: "add reentrancy guard".to_string(),
        impacted_contracts: vec!["Vault.sol".to_string()],
        impacted_functions: vec!["withdraw".to_string()],
        confidence: 1.0,
    }
}

fn make_knowledge(id: &str) -> NormalizedKnowledge {
    NormalizedKnowledge {
        knowledge_id: id.to_string(),
        source_id: "test-source".to_string(),
        source_kind: KnowledgeSourceKind::AuditRepository,
        source_identifier: "audit-report.md".to_string(),
        subject: "TestProtocol".to_string(),
        subject_category: "defi".to_string(),
        findings: vec![make_finding(&format!("{}-f1", id))],
        evidence: vec![KnowledgeEvidence {
            evidence_id: format!("{}-ev", id),
            kind: KnowledgeEvidenceKind::HistoricalFinding(HistoricalFindingEvidence {
                finding_id: format!("{}-f1", id),
                protocol_name: "TestProtocol".to_string(),
                vulnerability_class: "reentrancy".to_string(),
                attack_goal: "drain funds".to_string(),
                root_cause: "shared_mutable_state".to_string(),
                severity: Severity::High,
                impacted_functions: vec!["withdraw".to_string()],
            }),
            description: "historical evidence".to_string(),
            confidence: KnowledgeConfidence::single_finding("test-source"),
            source: "test-source".to_string(),
            related_findings: vec![],
        }],
        invariants: vec![SecurityInvariant {
            invariant_id: "inv-1".to_string(),
            description: "conservation".to_string(),
            kind: "economic".to_string(),
            properties: vec!["totalSupply".to_string()],
            is_violated: true,
            context: "Vault.sol".to_string(),
        }],
        architectural_patterns: vec![ArchitecturalPattern {
            pattern_id: "arch-1".to_string(),
            name: "ERC4626 Vault".to_string(),
            description: "standard vault pattern".to_string(),
            category: "vault".to_string(),
            known_vulnerabilities: vec!["reentrancy".to_string()],
            security_properties: vec!["conservation".to_string()],
        }],
        mitigation_patterns: vec![MitigationPattern {
            technique: "reentrancy_guard".to_string(),
            description: "Use ReentrancyGuard".to_string(),
            is_standard: true,
        }],
        references: vec![KnowledgeReference {
            reference_id: "ref-1".to_string(),
            kind: ReferenceKind::AuditReport,
            description: "original audit".to_string(),
        }],
        claims: vec![SecurityClaim {
            claim_id: "claim-1".to_string(),
            claim: "reentrancy vulnerability exists".to_string(),
            kind: ClaimKind::VulnerabilityExists,
            confidence: ClaimConfidence::Verified,
            evidence: vec!["finding-1".to_string()],
            context: "Vault.sol withdraw()".to_string(),
        }],
        raw_sections: {
            let mut m = std::collections::BTreeMap::new();
            m.insert("findings".to_string(), "reentrancy in withdraw".to_string());
            m
        },
    }
}

// ═══════════════════════════════════════════════════════════
// Round-trip serialization tests
// ═══════════════════════════════════════════════════════════

#[test]
fn round_trip_normalized_finding() {
    let original = make_finding("rt-nf-1");
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: NormalizedFinding = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_normalized_knowledge() {
    let original = make_knowledge("rt-nk-1");
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: NormalizedKnowledge = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_extracted_finding() {
    let original = ExtractedFinding {
        finding_id: "H-01".to_string(),
        title: "Reentrancy in withdraw".to_string(),
        severity: FindingSeverity::High,
        impact: "loss of funds".to_string(),
        likelihood: Some("high".to_string()),
        description: "reentrancy vulnerability".to_string(),
        root_cause: "shared mutable state".to_string(),
        exploit_path: None,
        impacted_contracts: vec!["Vault.sol".to_string()],
        impacted_functions: vec!["withdraw".to_string()],
        remediation: "add reentrancy guard".to_string(),
        status: FindingStatus::Open,
        references: vec![],
        code_snippets: vec![],
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: ExtractedFinding = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_audit_report() {
    let original = AuditReport {
        report_id: "rpt-1".to_string(),
        protocol_name: "TestProtocol".to_string(),
        protocol_category: ProtocolCategory::Lending,
        auditor: "Auditor1".to_string(),
        reviewers: vec!["Reviewer1".to_string()],
        audit_date: Some("2024-01-15".to_string()),
        source_repo: "github.com/test".to_string(),
        source_path: "audits/test.md".to_string(),
        commit_hash: Some("abc123".to_string()),
        scope: vec![ScopedFile {
            path: "contracts/Vault.sol".to_string(),
            language: "Solidity".to_string(),
        }],
        findings: vec![],
        privileged_roles: vec![PrivilegedRole {
            role_name: "admin".to_string(),
            description: "can pause".to_string(),
            functions: vec!["pause".to_string()],
            risk_level: "high".to_string(),
        }],
        centralization_notes: vec!["owner can pause".to_string()],
        raw_sections: std::collections::BTreeMap::new(),
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: AuditReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_knowledge_evidence() {
    let original = KnowledgeEvidence {
        evidence_id: "ev-1".to_string(),
        kind: KnowledgeEvidenceKind::HistoricalFinding(HistoricalFindingEvidence {
            finding_id: "f-1".to_string(),
            protocol_name: "Test".to_string(),
            vulnerability_class: "reentrancy".to_string(),
            attack_goal: "drain".to_string(),
            root_cause: "state".to_string(),
            severity: Severity::High,
            impacted_functions: vec!["withdraw".to_string()],
        }),
        description: "test evidence".to_string(),
        confidence: KnowledgeConfidence::established(5, vec!["src1".to_string()]),
        source: "test".to_string(),
        related_findings: vec![],
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: KnowledgeEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_knowledge_graph() {
    let original = KnowledgeGraph {
        nodes: vec![KnowledgeNode::Protocol(ProtocolNode {
            protocol_id: "p-1".to_string(),
            name: "Test".to_string(),
            category: "lending".to_string(),
            audit_count: 1,
            total_findings: 5,
        })],
        edges: vec![KnowledgeEdge::HasFinding {
            protocol_id: "p-1".to_string(),
            finding_id: "f-1".to_string(),
        }],
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: KnowledgeGraph = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_historical_finding_store() {
    let original = HistoricalFindingStore::empty();
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: HistoricalFindingStore = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_violated_invariant() {
    let original = ViolatedInvariant {
        kind: "conservation".to_string(),
        description: "supply invariants".to_string(),
        affected_state_vars: vec!["totalSupply".to_string()],
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: ViolatedInvariant = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_mitigation_pattern() {
    let original = MitigationPattern {
        technique: "reentrancy_guard".to_string(),
        description: "Use guard".to_string(),
        is_standard: true,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: MitigationPattern = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_security_assumption() {
    let original = SecurityAssumption {
        assumption: "oracle is honest".to_string(),
        is_valid: true,
        violated_by: None,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: SecurityAssumption = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_exploit_metadata() {
    let original = ExploitMetadata {
        timeline: ExploitTimeline {
            introduced: None,
            exploited: Some("2024-01-01".to_string()),
            discovered: None,
            patched: None,
            live_duration: None,
        },
        prerequisites: vec![],
        attack_path: vec![],
        state_transitions: vec![],
        affected_components: vec![],
        trust_boundary_violations: vec![],
        broken_invariants: vec![],
        economic_assumptions_violated: vec![],
        privilege_assumptions_violated: vec![],
        required_capabilities: vec![],
        affected_assets: vec![],
        outcome: ExploitOutcome {
            total_loss: Some("100 ETH".to_string()),
            returned: None,
            net_loss: Some("100 ETH".to_string()),
            successful: true,
            recovered: false,
            description: "funds drained".to_string(),
        },
        mitigation: None,
        patched_behavior: None,
        version_info: None,
        affected_standards: vec![],
        protocol_mechanisms: vec![],
        lifecycle_phase: None,
        complexity: ExploitComplexity::Simple,
        repeatability: ExploitRepeatability::Repeatable,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: ExploitMetadata = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_semantic_link() {
    let original = SemanticLink {
        source_id: "s-1".to_string(),
        target_id: "t-1".to_string(),
        kind: LinkKind::Causes,
        description: "exploit causes loss".to_string(),
        score: RelationshipScore {
            score: 0.9,
            factors: vec![ScoreFactor {
                name: "structural".to_string(),
                weight: 0.5,
                value: 1.0,
                evidence: "same root cause".to_string(),
            }],
        },
        confidence: 0.95,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: SemanticLink = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

#[test]
fn round_trip_relationship_score() {
    let original = RelationshipScore {
        score: 0.85,
        factors: vec![],
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: RelationshipScore = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, deserialized);
}

// ═══════════════════════════════════════════════════════════
// Enum pin tests
// ═══════════════════════════════════════════════════════════

#[test]
fn pin_finding_severity_variants() {
    let count = match FindingSeverity::Critical {
        FindingSeverity::Critical
        | FindingSeverity::High
        | FindingSeverity::Medium
        | FindingSeverity::Low
        | FindingSeverity::Informational => 5,
    };
    assert_eq!(count, 5);
}

#[test]
fn pin_finding_status_variants() {
    let count = match FindingStatus::Resolved {
        FindingStatus::Resolved
        | FindingStatus::Acknowledged
        | FindingStatus::Fixed
        | FindingStatus::Open
        | FindingStatus::Unknown => 5,
    };
    assert_eq!(count, 5);
}

#[test]
fn pin_protocol_category_variants() {
    let count = match ProtocolCategory::Lending {
        ProtocolCategory::Lending
        | ProtocolCategory::Stablecoin
        | ProtocolCategory::DEX
        | ProtocolCategory::Yield
        | ProtocolCategory::Bridge
        | ProtocolCategory::Governance
        | ProtocolCategory::Infrastructure
        | ProtocolCategory::NFT
        | ProtocolCategory::Gaming
        | ProtocolCategory::RWA
        | ProtocolCategory::Perps
        | ProtocolCategory::Options
        | ProtocolCategory::Insurance
        | ProtocolCategory::Token
        | ProtocolCategory::Vault
        | ProtocolCategory::Unknown => 16,
    };
    assert_eq!(count, 16);
}

#[test]
fn pin_protocol_domain_variants() {
    let count = match ProtocolDomain::Vaults {
        ProtocolDomain::Vaults
        | ProtocolDomain::AMMs
        | ProtocolDomain::Lending
        | ProtocolDomain::LiquidStaking
        | ProtocolDomain::Restaking
        | ProtocolDomain::Bridges
        | ProtocolDomain::Governance
        | ProtocolDomain::CrossChainMessaging
        | ProtocolDomain::Derivatives
        | ProtocolDomain::Stablecoins
        | ProtocolDomain::YieldAggregators
        | ProtocolDomain::Options
        | ProtocolDomain::Perpetuals
        | ProtocolDomain::Auctions
        | ProtocolDomain::AccountAbstraction
        | ProtocolDomain::TokenStandards
        | ProtocolDomain::Oracles
        | ProtocolDomain::MEVInfrastructure
        | ProtocolDomain::Generic => 19,
    };
    assert_eq!(count, 19);
}

#[test]
fn pin_claim_confidence_variants() {
    let count = match ClaimConfidence::Proven {
        ClaimConfidence::Proven
        | ClaimConfidence::Verified
        | ClaimConfidence::Asserted
        | ClaimConfidence::Speculative => 4,
    };
    assert_eq!(count, 4);
}

#[test]
fn pin_claim_kind_variants() {
    let count = match ClaimKind::VulnerabilityExists {
        ClaimKind::VulnerabilityExists
        | ClaimKind::SafeAgainstAttack
        | ClaimKind::InvariantRequired
        | ClaimKind::PatternSecureWhen
        | ClaimKind::MitigationEffective
        | ClaimKind::AssumptionRequired
        | ClaimKind::Other => 7,
    };
    assert_eq!(count, 7);
}

#[test]
fn pin_knowledge_source_kind_variants() {
    let count = match KnowledgeSourceKind::AuditRepository {
        KnowledgeSourceKind::AuditRepository
        | KnowledgeSourceKind::ExploitPostmortem
        | KnowledgeSourceKind::ProtocolDocumentation
        | KnowledgeSourceKind::Standard
        | KnowledgeSourceKind::FormalVerification
        | KnowledgeSourceKind::AcademicResearch
        | KnowledgeSourceKind::TechnicalWriteup
        | KnowledgeSourceKind::InternalAnalysis
        | KnowledgeSourceKind::RegressionCorpus
        | KnowledgeSourceKind::Other => 10,
    };
    assert_eq!(count, 10);
}

#[test]
fn pin_reference_kind_variants() {
    let count = match ReferenceKind::AuditReport {
        ReferenceKind::AuditReport
        | ReferenceKind::ExploitTransaction
        | ReferenceKind::SourceCode
        | ReferenceKind::Documentation
        | ReferenceKind::Standard
        | ReferenceKind::AcademicPaper
        | ReferenceKind::BlogPost
        | ReferenceKind::GitHubReference
        | ReferenceKind::Other => 9,
    };
    assert_eq!(count, 9);
}

#[test]
fn pin_knowledge_edge_variants() {
    let count = count_knowledge_edge_variants();
    assert_eq!(count, 10);
}

fn count_knowledge_edge_variants() -> usize {
    let mut n = 0;
    let edges = [
        KnowledgeEdge::HasFinding {
            protocol_id: String::new(),
            finding_id: String::new(),
        },
        KnowledgeEdge::ClassifiedAs {
            finding_id: String::new(),
            class: String::new(),
        },
        KnowledgeEdge::UsesTechnique {
            finding_id: String::new(),
            technique: String::new(),
        },
        KnowledgeEdge::MitigatedBy {
            finding_id: String::new(),
            pattern: String::new(),
        },
        KnowledgeEdge::MitigatedByPattern {
            class: String::new(),
            pattern: String::new(),
        },
        KnowledgeEdge::ViolatesInvariant {
            class: String::new(),
            invariant: String::new(),
        },
        KnowledgeEdge::RequiresCapability {
            technique: String::new(),
            capability: String::new(),
        },
        KnowledgeEdge::UsesArchitecture {
            protocol_id: String::new(),
            pattern: String::new(),
        },
        KnowledgeEdge::SemanticallyEquivalent {
            finding_a: String::new(),
            finding_b: String::new(),
        },
        KnowledgeEdge::Generalizes {
            specific: String::new(),
            general: String::new(),
        },
    ];
    for edge in &edges {
        match edge {
            KnowledgeEdge::HasFinding { .. }
            | KnowledgeEdge::ClassifiedAs { .. }
            | KnowledgeEdge::UsesTechnique { .. }
            | KnowledgeEdge::MitigatedBy { .. }
            | KnowledgeEdge::MitigatedByPattern { .. }
            | KnowledgeEdge::ViolatesInvariant { .. }
            | KnowledgeEdge::RequiresCapability { .. }
            | KnowledgeEdge::UsesArchitecture { .. }
            | KnowledgeEdge::SemanticallyEquivalent { .. }
            | KnowledgeEdge::Generalizes { .. } => {
                n += 1;
            }
        }
    }
    n
}

#[test]
fn pin_knowledge_evidence_kind_variants() {
    let variant = KnowledgeEvidenceKind::HistoricalFinding(HistoricalFindingEvidence {
        finding_id: String::new(),
        protocol_name: String::new(),
        vulnerability_class: String::new(),
        attack_goal: String::new(),
        root_cause: String::new(),
        severity: Severity::Critical,
        impacted_functions: vec![],
    });
    let count = match variant {
        KnowledgeEvidenceKind::HistoricalFinding(_)
        | KnowledgeEvidenceKind::ReasoningPattern(_)
        | KnowledgeEvidenceKind::SimilarProtocol(_)
        | KnowledgeEvidenceKind::ArchitecturePattern(_)
        | KnowledgeEvidenceKind::MitigationPattern(_)
        | KnowledgeEvidenceKind::FormalProof(_)
        | KnowledgeEvidenceKind::AcademicReference(_) => 7,
    };
    assert_eq!(count, 7);
}

#[test]
fn pin_link_kind_variants() {
    let count = match LinkKind::Causes {
        LinkKind::Causes
        | LinkKind::Enables
        | LinkKind::DependsOn
        | LinkKind::Requires
        | LinkKind::Mitigates
        | LinkKind::ProtectsAgainst
        | LinkKind::Violates
        | LinkKind::Preserves
        | LinkKind::DerivesFrom
        | LinkKind::Specializes
        | LinkKind::Generalizes
        | LinkKind::EquivalentTo
        | LinkKind::Contradicts
        | LinkKind::Supersedes
        | LinkKind::Precedes
        | LinkKind::Follows
        | LinkKind::Influences
        | LinkKind::Impacts
        | LinkKind::ExploitToAuditFinding
        | LinkKind::ExploitToRootCause
        | LinkKind::ExploitToAttackTechnique
        | LinkKind::ExploitToExploit
        | LinkKind::ProtocolToProtocol => 23,
    };
    assert_eq!(count, 23);
}

#[test]
fn pin_prerequisite_kind_variants() {
    let count = match PrerequisiteKind::ContractState {
        PrerequisiteKind::ContractState
        | PrerequisiteKind::MarketCondition
        | PrerequisiteKind::TokenProperty
        | PrerequisiteKind::OracleBehavior
        | PrerequisiteKind::GovernanceState
        | PrerequisiteKind::LiquidityCondition
        | PrerequisiteKind::BlockCondition
        | PrerequisiteKind::ExternalContract
        | PrerequisiteKind::Timing
        | PrerequisiteKind::Other => 10,
    };
    assert_eq!(count, 10);
}

#[test]
fn pin_component_kind_variants() {
    let count = match ComponentKind::Contract {
        ComponentKind::Contract
        | ComponentKind::Function
        | ComponentKind::StateVariable
        | ComponentKind::Modifier
        | ComponentKind::Library
        | ComponentKind::Interface
        | ComponentKind::Proxy
        | ComponentKind::Oracle
        | ComponentKind::Token => 9,
    };
    assert_eq!(count, 9);
}

#[test]
fn pin_mitigation_kind_variants() {
    let count = match MitigationKind::CodeFix {
        MitigationKind::CodeFix
        | MitigationKind::ConfigurationChange
        | MitigationKind::CircuitBreaker
        | MitigationKind::GovernanceAction
        | MitigationKind::Migration
        | MitigationKind::Monitoring
        | MitigationKind::Other => 7,
    };
    assert_eq!(count, 7);
}

#[test]
fn pin_exploit_complexity_variants() {
    let count = match ExploitComplexity::Simple {
        ExploitComplexity::Simple | ExploitComplexity::Moderate | ExploitComplexity::Complex => 3,
    };
    assert_eq!(count, 3);
}

#[test]
fn pin_exploit_repeatability_variants() {
    let count = match ExploitRepeatability::Repeatable {
        ExploitRepeatability::Repeatable
        | ExploitRepeatability::OneShot
        | ExploitRepeatability::Conditional => 3,
    };
    assert_eq!(count, 3);
}

// ═══════════════════════════════════════════════════════════
// Constructor/invariant tests
// ═══════════════════════════════════════════════════════════

#[test]
fn historical_finding_store_empty() {
    let store = HistoricalFindingStore::empty();
    assert!(store.is_empty());
    assert_eq!(store.total_findings(), 0);
    assert_eq!(store.total_patterns(), 0);
}

#[test]
fn knowledge_confidence_established() {
    let c = KnowledgeConfidence::established(5, vec!["src1".to_string()]);
    assert_eq!(c.support_count, 5);
    assert_eq!(c.confidence_level, "established");
}

#[test]
fn knowledge_confidence_observed_below_threshold() {
    let c = KnowledgeConfidence::established(3, vec!["src1".to_string()]);
    assert_eq!(c.confidence_level, "observed");
}

#[test]
fn knowledge_confidence_single_finding() {
    let c = KnowledgeConfidence::single_finding("audit");
    assert_eq!(c.support_count, 1);
    assert_eq!(c.confidence_level, "observed");
    assert_eq!(c.contributing_sources, vec!["audit".to_string()]);
}

#[test]
fn knowledge_graph_empty() {
    let g = KnowledgeGraph::empty();
    assert!(g.is_empty());
    assert!(g.nodes.is_empty());
    assert!(g.edges.is_empty());
}

// ═══════════════════════════════════════════════════════════
// Ord/ordering tests
// ═══════════════════════════════════════════════════════════

#[test]
fn severity_ordering() {
    let mut severities = [
        FindingSeverity::Informational,
        FindingSeverity::Low,
        FindingSeverity::Critical,
        FindingSeverity::Medium,
        FindingSeverity::High,
    ];
    severities.sort();
    let expected = [
        FindingSeverity::Critical,
        FindingSeverity::High,
        FindingSeverity::Medium,
        FindingSeverity::Low,
        FindingSeverity::Informational,
    ];
    assert_eq!(severities, expected);
}

#[test]
fn vulnerability_class_ordering() {
    let mut classes = [
        VulnerabilityClass::Reentrancy,
        VulnerabilityClass::MissingAccessControl,
        VulnerabilityClass::FlashLoanAttack,
    ];
    classes.sort();
    assert_eq!(classes[0], VulnerabilityClass::MissingAccessControl);
    assert_eq!(classes[1], VulnerabilityClass::Reentrancy);
    assert_eq!(classes[2], VulnerabilityClass::FlashLoanAttack);
}

#[test]
fn attack_technique_ordering() {
    let mut techniques = [
        AttackTechnique::ReentrancyExploit,
        AttackTechnique::FlashLoanBorrow,
        AttackTechnique::AccessControlBypass,
    ];
    techniques.sort();
    assert_eq!(techniques[0], AttackTechnique::ReentrancyExploit);
    assert_eq!(techniques[1], AttackTechnique::FlashLoanBorrow);
    assert_eq!(techniques[2], AttackTechnique::AccessControlBypass);
}

#[test]
fn knowledge_source_kind_ordering() {
    let mut kinds = [
        KnowledgeSourceKind::ExploitPostmortem,
        KnowledgeSourceKind::AuditRepository,
        KnowledgeSourceKind::Standard,
    ];
    kinds.sort();
    assert_eq!(kinds[0], KnowledgeSourceKind::AuditRepository);
    assert_eq!(kinds[1], KnowledgeSourceKind::ExploitPostmortem);
    assert_eq!(kinds[2], KnowledgeSourceKind::Standard);
}

// ═══════════════════════════════════════════════════════════
// Display trait tests
// ═══════════════════════════════════════════════════════════

#[test]
fn display_vulnerability_class_other() {
    let vc = VulnerabilityClass::Other("custom_vuln".to_string());
    assert_eq!(vc.to_string(), "other(custom_vuln)");
}

#[test]
fn display_attack_technique_other() {
    let at = AttackTechnique::Other("custom_tech".to_string());
    assert_eq!(at.to_string(), "other(custom_tech)");
}

#[test]
fn display_structural_root_cause_other() {
    let rc = StructuralRootCause::Other("custom_cause".to_string());
    assert_eq!(rc.to_string(), "other(custom_cause)");
}
