/// Cyfrin Audit Checklist ingestion — compiler bugs, OZ bugs, researcher checklists.
///
/// Three knowledge types from the Cyfrin audit checklist repository:
/// 1. Solidity compiler bugs — known compiler-level vulnerabilities
/// 2. OpenZeppelin bugs — known library-level vulnerabilities
/// 3. Researcher checklists — expert reasoning patterns
///
/// All three are deterministic, structured, and directly ingestible.
use digger_knowledge_models::*;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Solidity Compiler Bugs
// ═══════════════════════════════════════════════════════════════

/// A known Solidity compiler bug.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SolidityBug {
    pub uid: String,
    pub name: String,
    pub summary: String,
    pub description: String,
    pub link: Option<String>,
    pub introduced: Option<String>,
    pub fixed: String,
    pub severity: String,
}

/// Parse the Solidity bugs JSON from the Cyfrin checklist.
pub fn parse_solidity_bugs_json(json_str: &str) -> Vec<SolidityBug> {
    serde_json::from_str(json_str).unwrap_or_default()
}

/// Ingest Solidity compiler bugs as NormalizedKnowledge.
pub fn ingest_solidity_bugs(bugs: &[SolidityBug]) -> NormalizedKnowledge {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();

    for bug in bugs {
        let finding_id = format!("compiler:{}", bug.uid);
        let severity = match bug.severity.to_lowercase().as_str() {
            "critical" => digger_ir::Severity::Critical,
            "high" | "medium/high" => digger_ir::Severity::High,
            "medium" => digger_ir::Severity::Medium,
            "low" => digger_ir::Severity::Low,
            _ => digger_ir::Severity::Info,
        };

        findings.push(NormalizedFinding {
            finding_id: finding_id.clone(),
            original_finding_id: bug.uid.clone(),
            report_id: "cyfrin:solidity-bugs".into(),
            protocol_name: "Solidity Compiler".into(),
            protocol_category: ProtocolCategory::Infrastructure,
            protocol_domain: ProtocolDomain::Generic,
            protocol_pattern: None,
            vulnerability_class: classify_compiler_bug(&bug.name, &bug.summary),
            attack_goal: "BreakEconomicInvariant".into(),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: "compiler_invariant".into(),
                description: bug.summary.clone(),
                affected_state_vars: vec![],
            },
            attack_technique: AttackTechnique::Other("compiler_bug".into()),
            mitigation_pattern: Some(MitigationPattern {
                technique: format!("Upgrade to Solidity {}", bug.fixed),
                description: format!("Bug fixed in version {}", bug.fixed),
                is_standard: true,
            }),
            security_assumptions: vec![SecurityAssumption {
                assumption: format!(
                    "Compiler version {} is not affected (introduced: {})",
                    bug.fixed,
                    bug.introduced.as_deref().unwrap_or("unknown")
                ),
                is_valid: true,
                violated_by: None,
            }],
            severity,
            root_cause: StructuralRootCause::UnsafeComposition,
            impact_text: bug.summary.clone(),
            description_text: bug.description.clone(),
            remediation_text: format!("Upgrade compiler to {} or later", bug.fixed),
            impacted_contracts: vec![],
            impacted_functions: vec![],
            confidence: 1.0,
        });

        evidence.push(KnowledgeEvidence {
            evidence_id: format!("ev:compiler:{}", bug.uid),
            kind: KnowledgeEvidenceKind::HistoricalFinding(HistoricalFindingEvidence {
                finding_id,
                protocol_name: "Solidity Compiler".into(),
                vulnerability_class: "compiler_bug".into(),
                attack_goal: "BreakEconomicInvariant".into(),
                root_cause: "unsafe_composition".into(),
                severity: digger_ir::Severity::Medium,
                impacted_functions: vec![],
            }),
            description: format!("Known compiler bug: {}", bug.name),
            confidence: KnowledgeConfidence {
                support_count: 1,
                confidence_level: "verified".into(),
                first_seen: None,
                last_seen: None,
                contributing_sources: vec![bug.link.clone().unwrap_or_default()],
            },
            source: bug.link.clone().unwrap_or_default(),
            related_findings: vec![],
        });
    }

    NormalizedKnowledge {
        knowledge_id: "knowledge:cyfrin:solidity-bugs".into(),
        source_id: "cyfrin".into(),
        source_kind: KnowledgeSourceKind::Standard,
        source_identifier: "1-solidity_bugs.json".into(),
        subject: "Solidity Compiler".into(),
        subject_category: "infrastructure".into(),
        findings,
        evidence,
        invariants: vec![],
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![KnowledgeReference {
            reference_id: "https://github.com/Cyfrin/audit-checklist".into(),
            kind: ReferenceKind::Standard,
            description: "Cyfrin audit checklist - Solidity compiler bugs".into(),
        }],
        claims: vec![],
        raw_sections: std::collections::BTreeMap::new(),
    }
}

fn classify_compiler_bug(name: &str, summary: &str) -> VulnerabilityClass {
    let text = format!("{} {}", name, summary).to_lowercase();
    if text.contains("storage") || text.contains("memory") {
        return VulnerabilityClass::StorageCollision;
    }
    if text.contains("overflow") || text.contains("underflow") {
        return VulnerabilityClass::IntegerOverflow;
    }
    if text.contains("optimizer") || text.contains("inline") {
        return VulnerabilityClass::InvariantViolation;
    }
    if text.contains("abi") || text.contains("encoding") {
        return VulnerabilityClass::MissingValidation;
    }
    VulnerabilityClass::Other(format!("compiler_bug: {}", name))
}

// ═══════════════════════════════════════════════════════════════
// OpenZeppelin Bugs
// ═══════════════════════════════════════════════════════════════

/// A known OpenZeppelin bug.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenZeppelinBug {
    pub version: String,
    pub vulnerability: String,
}

/// Parse the OpenZeppelin bugs JSON from the Cyfrin checklist.
pub fn parse_openzeppelin_bugs_json(json_str: &str) -> Vec<OpenZeppelinBug> {
    #[derive(Deserialize)]
    struct OZWrapper {
        issues: Vec<OpenZeppelinBug>,
    }
    serde_json::from_str::<OZWrapper>(json_str)
        .map(|w| w.issues)
        .unwrap_or_default()
}

/// Ingest OpenZeppelin bugs as NormalizedKnowledge.
pub fn ingest_openzeppelin_bugs(bugs: &[OpenZeppelinBug]) -> NormalizedKnowledge {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();

    for (i, bug) in bugs.iter().enumerate() {
        let finding_id = format!("oz:bug:{:03}", i);
        let vuln_class = classify_oz_vulnerability(&bug.vulnerability);

        findings.push(NormalizedFinding {
            finding_id: finding_id.clone(),
            original_finding_id: format!("OZ-{:03}", i),
            report_id: "cyfrin:openzeppelin-bugs".into(),
            protocol_name: "OpenZeppelin".into(),
            protocol_category: ProtocolCategory::Infrastructure,
            protocol_domain: ProtocolDomain::Generic,
            protocol_pattern: None,
            vulnerability_class: vuln_class.clone(),
            attack_goal: map_goal_from_class(&vuln_class),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: "library_invariant".into(),
                description: bug.vulnerability.clone(),
                affected_state_vars: vec![],
            },
            attack_technique: AttackTechnique::Other("library_bug".into()),
            mitigation_pattern: Some(MitigationPattern {
                technique: "Upgrade OpenZeppelin".into(),
                description: format!("Affected versions: {}", bug.version),
                is_standard: true,
            }),
            security_assumptions: vec![],
            severity: digger_ir::Severity::High,
            root_cause: StructuralRootCause::UnsafeComposition,
            impact_text: format!(
                "OpenZeppelin {} in versions {}",
                bug.vulnerability, bug.version
            ),
            description_text: format!(
                "Known OpenZeppelin vulnerability: {} affecting {}",
                bug.vulnerability, bug.version
            ),
            remediation_text: format!(
                "Upgrade OpenZeppelin to a version not affected by {}",
                bug.vulnerability
            ),
            impacted_contracts: vec![],
            impacted_functions: vec![],
            confidence: 1.0,
        });

        evidence.push(KnowledgeEvidence {
            evidence_id: format!("ev:oz:bug:{:03}", i),
            kind: KnowledgeEvidenceKind::HistoricalFinding(HistoricalFindingEvidence {
                finding_id,
                protocol_name: "OpenZeppelin".into(),
                vulnerability_class: vuln_class.to_string(),
                attack_goal: "BreakEconomicInvariant".into(),
                root_cause: "unsafe_composition".into(),
                severity: digger_ir::Severity::High,
                impacted_functions: vec![],
            }),
            description: format!("Known OZ bug: {} in {}", bug.vulnerability, bug.version),
            confidence: KnowledgeConfidence {
                support_count: 1,
                confidence_level: "verified".into(),
                first_seen: None,
                last_seen: None,
                contributing_sources: vec![
                    "https://security.snyk.io/package/npm/@openzeppelin%2Fcontracts".into(),
                ],
            },
            source: "https://security.snyk.io".into(),
            related_findings: vec![],
        });
    }

    NormalizedKnowledge {
        knowledge_id: "knowledge:cyfrin:openzeppelin-bugs".into(),
        source_id: "cyfrin".into(),
        source_kind: KnowledgeSourceKind::Standard,
        source_identifier: "1-openzeppelin_bugs.json".into(),
        subject: "OpenZeppelin".into(),
        subject_category: "infrastructure".into(),
        findings,
        evidence,
        invariants: vec![],
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![KnowledgeReference {
            reference_id: "https://github.com/Cyfrin/audit-checklist".into(),
            kind: ReferenceKind::Standard,
            description: "Cyfrin audit checklist - OpenZeppelin bugs".into(),
        }],
        claims: vec![],
        raw_sections: std::collections::BTreeMap::new(),
    }
}

fn classify_oz_vulnerability(vuln: &str) -> VulnerabilityClass {
    let lower = vuln.to_lowercase();
    if lower.contains("authorization") || lower.contains("access control") {
        return VulnerabilityClass::MissingAccessControl;
    }
    if lower.contains("denial") || lower.contains("dos") {
        return VulnerabilityClass::DenialOfService;
    }
    if lower.contains("input validation") {
        return VulnerabilityClass::MissingValidation;
    }
    if lower.contains("calculation") || lower.contains("incorrect") {
        return VulnerabilityClass::IncorrectCalculation;
    }
    if lower.contains("signature") || lower.contains("cryptographic") {
        return VulnerabilityClass::MissingValidation;
    }
    if lower.contains("encoding") || lower.contains("escaping") {
        return VulnerabilityClass::MissingValidation;
    }
    if lower.contains("resource transfer") {
        return VulnerabilityClass::ComposabilityRisk;
    }
    if lower.contains("information exposure") {
        return VulnerabilityClass::MissingValidation;
    }
    if lower.contains("argument") {
        return VulnerabilityClass::MissingValidation;
    }
    VulnerabilityClass::ComposabilityRisk
}

fn map_goal_from_class(class: &VulnerabilityClass) -> String {
    match class {
        VulnerabilityClass::MissingAccessControl | VulnerabilityClass::PrivilegeEscalation => {
            "GainUnauthorizedControl".into()
        }
        VulnerabilityClass::DenialOfService | VulnerabilityClass::Griefing => "FreezeFunds".into(),
        VulnerabilityClass::ComposabilityRisk => "BreakEconomicInvariant".into(),
        _ => "BreakEconomicInvariant".into(),
    }
}

// ═══════════════════════════════════════════════════════════════
// Researcher Checklists
// ═══════════════════════════════════════════════════════════════

/// A researcher checklist item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChecklistItem {
    pub researcher: String,
    pub category: String,
    pub item: String,
    pub description: String,
}

/// Parse a researcher checklist Markdown file.
pub fn parse_checklist(content: &str, researcher: &str) -> Vec<ChecklistItem> {
    let mut items = Vec::new();
    let mut current_category = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip empty lines, headers, metadata
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("**") {
            // Check if this is a section header (## or ###)
            if trimmed.starts_with("## ") {
                current_category = trimmed.trim_start_matches("#").trim().to_string();
            }
            continue;
        }

        // Parse checklist items: "- item" or "  - item"
        if trimmed.starts_with("- ") {
            let item_text = trimmed.trim_start_matches("- ").trim().to_string();
            if !item_text.is_empty() && item_text.len() > 3 {
                items.push(ChecklistItem {
                    researcher: researcher.to_string(),
                    category: current_category.clone(),
                    item: item_text.clone(),
                    description: item_text,
                });
            }
        }
    }

    items
}

/// Ingest researcher checklists as NormalizedKnowledge.
pub fn ingest_checklists(items: &[ChecklistItem]) -> NormalizedKnowledge {
    let mut findings = Vec::new();
    let evidence = Vec::new();

    for (i, item) in items.iter().enumerate() {
        let finding_id = format!("checklist:{}:{:03}", item.researcher, i);
        let vuln_class = classify_checklist_item(&item.item, &item.description);

        findings.push(NormalizedFinding {
            finding_id: finding_id.clone(),
            original_finding_id: format!("{}-{:03}", item.researcher, i),
            report_id: format!("cyfrin:checklist:{}", item.researcher),
            protocol_name: format!("{} checklist", item.researcher),
            protocol_category: ProtocolCategory::Unknown,
            protocol_domain: ProtocolDomain::Generic,
            protocol_pattern: None,
            vulnerability_class: vuln_class.clone(),
            attack_goal: map_goal_from_class(&vuln_class),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: "checklist_item".into(),
                description: item.description.clone(),
                affected_state_vars: vec![],
            },
            attack_technique: AttackTechnique::Other("checklist_pattern".into()),
            mitigation_pattern: None,
            security_assumptions: vec![],
            severity: digger_ir::Severity::Medium,
            root_cause: StructuralRootCause::Other(item.category.clone()),
            impact_text: item.description.clone(),
            description_text: format!("[{}] {}: {}", item.researcher, item.category, item.item),
            remediation_text: String::new(),
            impacted_contracts: vec![],
            impacted_functions: vec![],
            confidence: 0.8,
        });
    }

    NormalizedKnowledge {
        knowledge_id: "knowledge:cyfrin:checklists".to_string(),
        source_id: "cyfrin".into(),
        source_kind: KnowledgeSourceKind::TechnicalWriteup,
        source_identifier: "ref/*.md".into(),
        subject: "Security Research Checklists".into(),
        subject_category: "security".into(),
        findings,
        evidence,
        invariants: vec![],
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![KnowledgeReference {
            reference_id: "https://github.com/Cyfrin/audit-checklist".into(),
            kind: ReferenceKind::BlogPost,
            description: "Cyfrin audit checklist - researcher checklists".into(),
        }],
        claims: vec![],
        raw_sections: std::collections::BTreeMap::new(),
    }
}

fn classify_checklist_item(item: &str, description: &str) -> VulnerabilityClass {
    let text = format!("{} {}", item, description).to_lowercase();

    if text.contains("reentrancy") || text.contains("reentrant") {
        return VulnerabilityClass::Reentrancy;
    }
    if text.contains("flash loan") {
        return VulnerabilityClass::FlashLoanAttack;
    }
    if text.contains("oracle") || text.contains("price") {
        return VulnerabilityClass::OracleManipulation;
    }
    if text.contains("front-run")
        || text.contains("frontrun")
        || text.contains("frontrunning")
        || text.contains("sandwich")
    {
        return VulnerabilityClass::FrontRunning;
    }
    if text.contains("access control")
        || text.contains("authorization")
        || text.contains("unauthorized")
    {
        return VulnerabilityClass::MissingAccessControl;
    }
    if text.contains("overflow") || text.contains("underflow") {
        return VulnerabilityClass::IntegerOverflow;
    }
    if text.contains("denial") || text.contains("dos") || text.contains("grief") {
        return VulnerabilityClass::DenialOfService;
    }
    if text.contains("signature")
        || text.contains("ecrecover")
        || text.contains("replay")
        || text.contains("malleab")
    {
        return VulnerabilityClass::MissingValidation;
    }
    if text.contains("delegate") {
        return VulnerabilityClass::ComposabilityRisk;
    }
    if text.contains("proxy") || text.contains("upgrade") {
        return VulnerabilityClass::UpgradeabilityRisk;
    }
    if text.contains("governance") || text.contains("voting") || text.contains("admin") {
        return VulnerabilityClass::GovernanceAttack;
    }
    if text.contains("erc20") || text.contains("erc-20") || text.contains("token") {
        return VulnerabilityClass::ComposabilityRisk;
    }
    if text.contains("rounding") || text.contains("precision") || text.contains("decimal") {
        return VulnerabilityClass::PrecisionLoss;
    }
    if text.contains("random") || text.contains("randomness") {
        return VulnerabilityClass::MissingValidation;
    }
    if text.contains("gas") || text.contains("grief") {
        return VulnerabilityClass::DenialOfService;
    }
    if text.contains("tx.origin") || text.contains("msg.sender") {
        return VulnerabilityClass::MissingAccessControl;
    }
    if text.contains("storage") || text.contains("layout") {
        return VulnerabilityClass::StorageCollision;
    }
    if text.contains("compiler") || text.contains("solidity") {
        return VulnerabilityClass::InvariantViolation;
    }
    if text.contains("immutable") || text.contains("constant") {
        return VulnerabilityClass::UpgradeabilityRisk;
    }
    if text.contains("library") {
        return VulnerabilityClass::ComposabilityRisk;
    }

    VulnerabilityClass::Other(item.to_string())
}
