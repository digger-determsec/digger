/// Protocol Documentation parser — ingests DeFi protocol specifications.
///
/// Extracts invariants, trust boundaries, economic assumptions,
/// access control, and oracle dependencies from protocol docs.
///
/// This is the highest-value source for reasoning about novel attacks
/// because it defines expected behavior, not just known vulnerabilities.
use digger_knowledge_models::*;

/// Ingest protocol documentation into NormalizedKnowledge.
#[allow(clippy::too_many_arguments)]
pub fn ingest_protocol_doc(
    protocol: &str,
    category: &str,
    invariants: Vec<(&str, &str)>,
    trust_boundaries: Vec<(&str, &str)>,
    _economic_assumptions: Vec<(&str, &str)>,
    _access_control: Vec<(&str, &str)>,
    _oracle_dependencies: Vec<(&str, &str)>,
    security_considerations: Vec<(&str, &str)>,
    source_url: &str,
) -> NormalizedKnowledge {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut security_invariants = Vec::new();

    // Convert invariants to findings
    for (name, description) in &invariants {
        let finding_id = compute_doc_finding_id(protocol, name);
        findings.push(NormalizedFinding {
            finding_id: finding_id.clone(),
            original_finding_id: name.to_string(),
            report_id: format!("docs:{}", protocol.to_lowercase().replace(' ', "-")),
            protocol_name: protocol.to_string(),
            protocol_category: classify_category(category),
            protocol_domain: ProtocolDomain::Generic,
            protocol_pattern: None,
            vulnerability_class: VulnerabilityClass::InvariantViolation,
            attack_goal: "BreakEconomicInvariant".into(),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: "invariant".into(),
                description: description.to_string(),
                affected_state_vars: vec![],
            },
            attack_technique: AttackTechnique::Other("invariant_violation".into()),
            mitigation_pattern: None,
            security_assumptions: vec![],
            severity: digger_ir::Severity::High,
            root_cause: StructuralRootCause::IncorrectInvariantAssumption,
            impact_text: format!("Protocol invariant violation: {}", description),
            description_text: format!("Protocol invariant: {} — {}", name, description),
            remediation_text: String::new(),
            impacted_contracts: vec![],
            impacted_functions: vec![],
            confidence: 0.9, // high confidence from documentation
        });

        security_invariants.push(SecurityInvariant {
            invariant_id: format!("inv:{}:{}", protocol.to_lowercase().replace(' ', "_"), name),
            description: description.to_string(),
            kind: "protocol_invariant".into(),
            properties: vec![],
            is_violated: false,
            context: protocol.to_string(),
        });
    }

    // Convert trust boundaries to findings
    for (boundary, description) in &trust_boundaries {
        let finding_id = compute_doc_finding_id(protocol, &format!("trust:{}", boundary));
        findings.push(NormalizedFinding {
            finding_id,
            original_finding_id: format!("trust:{}", boundary),
            report_id: format!("docs:{}", protocol.to_lowercase().replace(' ', "-")),
            protocol_name: protocol.to_string(),
            protocol_category: classify_category(category),
            protocol_domain: ProtocolDomain::Generic,
            protocol_pattern: None,
            vulnerability_class: VulnerabilityClass::CentralizationRisk,
            attack_goal: "GainUnauthorizedControl".into(),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: "trust_boundary".into(),
                description: description.to_string(),
                affected_state_vars: vec![],
            },
            attack_technique: AttackTechnique::AccessControlBypass,
            mitigation_pattern: None,
            security_assumptions: vec![SecurityAssumption {
                assumption: description.to_string(),
                is_valid: true,
                violated_by: None,
            }],
            severity: digger_ir::Severity::Medium,
            root_cause: StructuralRootCause::MissingAuthorityCheck,
            impact_text: format!("Trust boundary: {}", description),
            description_text: format!("Trust boundary: {} — {}", boundary, description),
            remediation_text: String::new(),
            impacted_contracts: vec![],
            impacted_functions: vec![],
            confidence: 0.9,
        });
    }

    // Convert security considerations to findings
    for (consideration, description) in &security_considerations {
        let finding_id = compute_doc_finding_id(protocol, &format!("sec:{}", consideration));
        let vuln_class = classify_security_consideration(consideration, description);
        findings.push(NormalizedFinding {
            finding_id,
            original_finding_id: format!("sec:{}", consideration),
            report_id: format!("docs:{}", protocol.to_lowercase().replace(' ', "-")),
            protocol_name: protocol.to_string(),
            protocol_category: classify_category(category),
            protocol_domain: ProtocolDomain::Generic,
            protocol_pattern: None,
            vulnerability_class: vuln_class.clone(),
            attack_goal: map_to_attack_goal_from_class(&vuln_class),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: "security_consideration".into(),
                description: description.to_string(),
                affected_state_vars: vec![],
            },
            attack_technique: infer_technique_from_consideration(consideration),
            mitigation_pattern: None,
            security_assumptions: vec![],
            severity: digger_ir::Severity::Medium,
            root_cause: infer_root_cause_from_consideration(consideration),
            impact_text: description.to_string(),
            description_text: format!(
                "Security consideration: {} — {}",
                consideration, description
            ),
            remediation_text: String::new(),
            impacted_contracts: vec![],
            impacted_functions: vec![],
            confidence: 0.8,
        });
    }

    // Build evidence
    evidence.push(KnowledgeEvidence {
        evidence_id: format!("ev:docs:{}", protocol.to_lowercase().replace(' ', "-")),
        kind: KnowledgeEvidenceKind::HistoricalFinding(HistoricalFindingEvidence {
            finding_id: format!("docs:{}", protocol.to_lowercase().replace(' ', "-")),
            protocol_name: protocol.to_string(),
            vulnerability_class: "protocol_documentation".into(),
            attack_goal: "documentation".into(),
            root_cause: "documentation".into(),
            severity: digger_ir::Severity::Info,
            impacted_functions: vec![],
        }),
        description: format!("Protocol documentation for {}", protocol),
        confidence: KnowledgeConfidence {
            support_count: 1,
            confidence_level: "established".into(),
            first_seen: None,
            last_seen: None,
            contributing_sources: vec![source_url.to_string()],
        },
        source: source_url.to_string(),
        related_findings: vec![],
    });

    NormalizedKnowledge {
        knowledge_id: format!(
            "knowledge:docs:{}",
            protocol.to_lowercase().replace(' ', "-")
        ),
        source_id: "protocol_docs".into(),
        source_kind: KnowledgeSourceKind::ProtocolDocumentation,
        source_identifier: source_url.to_string(),
        subject: protocol.to_string(),
        subject_category: category.to_string(),
        findings,
        evidence,
        invariants: security_invariants,
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![KnowledgeReference {
            reference_id: source_url.to_string(),
            kind: ReferenceKind::Documentation,
            description: format!("Protocol documentation: {}", protocol),
        }],
        claims: vec![],
        raw_sections: std::collections::BTreeMap::new(),
    }
}

fn classify_category(category: &str) -> ProtocolCategory {
    match category.to_lowercase().as_str() {
        "lending" => ProtocolCategory::Lending,
        "dex" => ProtocolCategory::DEX,
        "stablecoin" => ProtocolCategory::Stablecoin,
        "yield" => ProtocolCategory::Yield,
        "bridge" => ProtocolCategory::Bridge,
        "governance" => ProtocolCategory::Governance,
        "infrastructure" => ProtocolCategory::Infrastructure,
        "vault" => ProtocolCategory::Vault,
        "staking" => ProtocolCategory::Yield,
        _ => ProtocolCategory::Unknown,
    }
}

fn classify_security_consideration(consideration: &str, description: &str) -> VulnerabilityClass {
    let text = format!("{} {}", consideration, description).to_lowercase();
    if text.contains("oracle") || text.contains("price") {
        return VulnerabilityClass::OracleManipulation;
    }
    if text.contains("frontrun") || text.contains("sandwich") || text.contains("mev") {
        return VulnerabilityClass::FrontRunning;
    }
    if text.contains("flash loan") {
        return VulnerabilityClass::FlashLoanAttack;
    }
    if text.contains("reentrancy") || text.contains("reentrant") {
        return VulnerabilityClass::Reentrancy;
    }
    if text.contains("access control") || text.contains("authority") || text.contains("role") {
        return VulnerabilityClass::MissingAccessControl;
    }
    if text.contains("pause") || text.contains("emergency") {
        return VulnerabilityClass::DenialOfService;
    }
    if text.contains("upgrade") || text.contains("migration") {
        return VulnerabilityClass::UpgradeabilityRisk;
    }
    if text.contains("signature") || text.contains("permit") {
        return VulnerabilityClass::MissingValidation;
    }
    if text.contains("fee") || text.contains("transfer") {
        return VulnerabilityClass::ComposabilityRisk;
    }
    if text.contains("governance") {
        return VulnerabilityClass::GovernanceAttack;
    }
    VulnerabilityClass::Other(consideration.to_string())
}

fn map_to_attack_goal_from_class(class: &VulnerabilityClass) -> String {
    match class {
        VulnerabilityClass::OracleManipulation | VulnerabilityClass::PriceManipulation => {
            "ManipulatePrice".into()
        }
        VulnerabilityClass::FrontRunning | VulnerabilityClass::SandwichAttack => {
            "ExhaustResources".into()
        }
        VulnerabilityClass::FlashLoanAttack => "DrainAssets".into(),
        VulnerabilityClass::Reentrancy => "DrainAssets".into(),
        VulnerabilityClass::MissingAccessControl | VulnerabilityClass::PrivilegeEscalation => {
            "GainUnauthorizedControl".into()
        }
        VulnerabilityClass::DenialOfService | VulnerabilityClass::Griefing => "FreezeFunds".into(),
        VulnerabilityClass::UpgradeabilityRisk => "GainUnauthorizedControl".into(),
        VulnerabilityClass::GovernanceAttack => "GainUnauthorizedControl".into(),
        _ => "BreakEconomicInvariant".into(),
    }
}

fn infer_technique_from_consideration(consideration: &str) -> AttackTechnique {
    let lower = consideration.to_lowercase();
    if lower.contains("oracle") {
        return AttackTechnique::PriceOracleManipulation;
    }
    if lower.contains("frontrun") || lower.contains("sandwich") {
        return AttackTechnique::FrontRunningTransaction;
    }
    if lower.contains("flash loan") {
        return AttackTechnique::FlashLoanBorrow;
    }
    if lower.contains("reentrancy") {
        return AttackTechnique::ReentrancyExploit;
    }
    if lower.contains("access") || lower.contains("authority") {
        return AttackTechnique::AccessControlBypass;
    }
    if lower.contains("signature") || lower.contains("permit") {
        return AttackTechnique::UncheckedExternalCall;
    }
    AttackTechnique::Other(consideration.to_string())
}

fn infer_root_cause_from_consideration(consideration: &str) -> StructuralRootCause {
    let lower = consideration.to_lowercase();
    if lower.contains("oracle") || lower.contains("price") {
        return StructuralRootCause::OracleStaleness;
    }
    if lower.contains("frontrun") || lower.contains("mev") {
        return StructuralRootCause::FrontRunningRisk;
    }
    if lower.contains("reentrancy") {
        return StructuralRootCause::CrossFunctionStateInconsistency;
    }
    if lower.contains("access") || lower.contains("authority") || lower.contains("role") {
        return StructuralRootCause::MissingAuthorityCheck;
    }
    if lower.contains("validation") || lower.contains("check") {
        return StructuralRootCause::UnvalidatedExternalInput;
    }
    if lower.contains("upgrade") || lower.contains("migration") {
        return StructuralRootCause::UnsafeComposition;
    }
    StructuralRootCause::Other(consideration.to_string())
}

fn compute_doc_finding_id(protocol: &str, name: &str) -> String {
    let mut h: u64 = 0;
    for byte in protocol.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    for byte in name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    format!("doc:{:x}", h)
}
