/// DeFiHackLabs ingestion — 700+ runnable exploit PoCs.
///
/// Parses Foundry/Solidity exploit test files from the DeFiHackLabs repository.
/// Each file contains a reproducible exploit with analysis links, attack summary,
/// and working PoC code.
///
/// Format per file:
///   // @Analysis: twitter/etherscan links
///   // @TX: transaction hash
///   // @Summary: attack steps
///   // @Attacker: attacker address
///   // @Victim: victim contract
///   // @Amount: loss amount
///
/// Deterministic parsing. No ML. No heuristics.
use digger_knowledge_models::*;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// A DeFiHackLabs exploit entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HackLabEntry {
    pub filename: String,
    pub date: String,
    pub protocol: String,
    pub analysis_links: Vec<String>,
    pub tx_hash: Option<String>,
    pub summary: Vec<String>,
    pub attacker_address: Option<String>,
    pub victim_contract: Option<String>,
    pub amount: Option<String>,
    pub chain: String,
    pub source_code: String,
}

/// Parse a DeFiHackLabs exploit file.
pub fn parse_hacklab_file(content: &str, filename: &str, date_dir: &str) -> HackLabEntry {
    let protocol = extract_protocol_name(filename);
    let analysis_links = extract_analysis_links(content);
    let tx_hash = extract_tx_hash(content);
    let summary = extract_summary(content);
    let attacker = extract_field(content, &["Attacker", "attacker"]);
    let victim = extract_field(content, &["Victim", "victim", "Target", "target"]);
    let amount = extract_field(content, &["Amount", "amount", "Lost", "lost"]);
    let chain = infer_chain(content, filename);

    HackLabEntry {
        filename: filename.to_string(),
        date: date_dir.to_string(),
        protocol,
        analysis_links,
        tx_hash,
        summary,
        attacker_address: attacker,
        victim_contract: victim,
        amount,
        chain,
        source_code: content.to_string(),
    }
}

/// Ingest a DeFiHackLabs entry into NormalizedKnowledge.
pub fn ingest_hacklab_entry(entry: &HackLabEntry) -> NormalizedKnowledge {
    let vuln_class = classify_hacklab_vulnerability(&entry.source_code, &entry.summary);
    let attack_goal = super::normalizer::map_to_attack_goal(&vuln_class);
    let root_cause = classify_hacklab_root_cause(&entry.source_code, &entry.summary);
    let attack_technique = classify_hacklab_technique(&entry.source_code, &entry.summary);

    let finding_id = compute_finding_id(&entry.protocol, &entry.filename);

    let finding = NormalizedFinding {
        finding_id: finding_id.clone(),
        original_finding_id: entry.filename.clone(),
        report_id: format!("defihacklabs:{}", entry.date),
        protocol_name: entry.protocol.clone(),
        protocol_category: classify_category(&entry.source_code),
        protocol_domain: classify_domain(&entry.source_code),
        protocol_pattern: None,
        vulnerability_class: vuln_class.clone(),
        attack_goal: attack_goal.clone(),
        capability_pattern: super::normalizer::infer_capabilities(&vuln_class),
        violated_invariant: super::normalizer::infer_violated_invariant(&vuln_class),
        attack_technique: attack_technique.clone(),
        mitigation_pattern: super::normalizer::infer_mitigation_pattern(&vuln_class),
        security_assumptions: vec![],
        severity: digger_ir::Severity::Critical, // confirmed exploit
        root_cause: root_cause.clone(),
        impact_text: entry.amount.clone().unwrap_or_default(),
        description_text: entry.summary.join("\n"),
        remediation_text: String::new(),
        impacted_contracts: entry.victim_contract.iter().cloned().collect(),
        impacted_functions: vec![],
        confidence: 1.0, // confirmed exploit
    };

    let evidence = vec![KnowledgeEvidence {
        evidence_id: format!("ev:hacklab:{}", finding_id),
        kind: KnowledgeEvidenceKind::HistoricalFinding(HistoricalFindingEvidence {
            finding_id: finding_id.clone(),
            protocol_name: entry.protocol.clone(),
            vulnerability_class: vuln_class.to_string(),
            attack_goal: attack_goal.clone(),
            root_cause: root_cause.to_string(),
            severity: digger_ir::Severity::Critical,
            impacted_functions: vec![],
        }),
        description: format!("Confirmed exploit: {} ({})", entry.protocol, entry.date),
        confidence: KnowledgeConfidence {
            support_count: 1,
            confidence_level: "verified".into(),
            first_seen: Some(entry.date.clone()),
            last_seen: Some(entry.date.clone()),
            contributing_sources: vec!["DeFiHackLabs".into()],
        },
        source: "DeFiHackLabs".into(),
        related_findings: vec![finding_id],
    }];

    NormalizedKnowledge {
        knowledge_id: format!(
            "knowledge:hacklab:{}",
            entry.protocol.to_lowercase().replace(' ', "-")
        ),
        source_id: "defihacklabs".into(),
        source_kind: KnowledgeSourceKind::ExploitPostmortem,
        source_identifier: entry.filename.clone(),
        subject: entry.protocol.clone(),
        subject_category: classify_category(&entry.source_code).to_string(),
        findings: vec![finding],
        evidence,
        invariants: vec![],
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: entry
            .analysis_links
            .iter()
            .map(|url| KnowledgeReference {
                reference_id: url.clone(),
                kind: ReferenceKind::BlogPost,
                description: format!("Analysis: {}", url),
            })
            .collect(),
        claims: vec![],
        raw_sections: std::collections::BTreeMap::new(),
    }
}

fn extract_protocol_name(filename: &str) -> String {
    filename
        .replace("_exp.sol", "")
        .replace("_exp_", "")
        .replace(".sol", "")
        .replace('_', " ")
}

fn extract_analysis_links(content: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r"https?://[^\s\)]+") else {
        return vec![];
    };
    re.find_iter(content)
        .map(|m| m.as_str().to_string())
        .filter(|url| {
            url.contains("twitter")
                || url.contains("etherscan")
                || url.contains("bscscan")
                || url.contains("polygonscan")
                || url.contains("arbiscan")
        })
        .collect()
}

fn extract_tx_hash(content: &str) -> Option<String> {
    let Ok(re) = Regex::new(r"0x[a-fA-F0-9]{64}") else {
        return None;
    };
    re.find(content).map(|m| m.as_str().to_string())
}

fn extract_summary(content: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r"(?m)^//\s*\d+\)\s*(.+)$") else {
        return vec![];
    };
    re.captures_iter(content)
        .map(|c| c[1].trim().to_string())
        .collect()
}

fn extract_field(content: &str, names: &[&str]) -> Option<String> {
    for name in names {
        let Ok(re) = Regex::new(&format!(r"(?i)//\s*@?{}\s*:\s*(.+)$", regex::escape(name))) else {
            continue;
        };
        if let Some(caps) = re.captures(content) {
            return Some(caps[1].trim().to_string());
        }
    }
    None
}

fn infer_chain(content: &str, filename: &str) -> String {
    let text = format!("{} {}", content, filename).to_lowercase();
    if text.contains("bsc") || text.contains("bnb") {
        return "BSC".into();
    }
    if text.contains("polygon") || text.contains("matic") {
        return "Polygon".into();
    }
    if text.contains("arbitrum") {
        return "Arbitrum".into();
    }
    if text.contains("optimism") {
        return "Optimism".into();
    }
    if text.contains("avalanche") || text.contains("avax") {
        return "Avalanche".into();
    }
    if text.contains("fantom") {
        return "Fantom".into();
    }
    if text.contains("solana") {
        return "Solana".into();
    }
    "Ethereum".into()
}

fn classify_hacklab_vulnerability(content: &str, summary: &[String]) -> VulnerabilityClass {
    let text = format!("{} {}", content, summary.join(" ")).to_lowercase();
    if text.contains("reentrancy") || text.contains("reentrant") {
        return VulnerabilityClass::Reentrancy;
    }
    if text.contains("flash loan") || text.contains("flashloan") {
        return VulnerabilityClass::FlashLoanAttack;
    }
    if text.contains("oracle") || text.contains("price manipulation") {
        return VulnerabilityClass::OracleManipulation;
    }
    if text.contains("access control") || text.contains("unauthorized") {
        return VulnerabilityClass::MissingAccessControl;
    }
    if text.contains("infinite mint") || text.contains("mint exploit") {
        return VulnerabilityClass::IntegerOverflow;
    }
    if text.contains("sandwich") {
        return VulnerabilityClass::SandwichAttack;
    }
    if text.contains("front-run") || text.contains("frontrun") {
        return VulnerabilityClass::FrontRunning;
    }
    if text.contains("governance") || text.contains("voting") {
        return VulnerabilityClass::GovernanceAttack;
    }
    if text.contains("overflow") || text.contains("underflow") {
        return VulnerabilityClass::IntegerOverflow;
    }
    if text.contains("precision") || text.contains("rounding") {
        return VulnerabilityClass::PrecisionLoss;
    }
    if text.contains("denial") || text.contains("dos") || text.contains("grief") {
        return VulnerabilityClass::DenialOfService;
    }
    if text.contains("delegatecall") {
        return VulnerabilityClass::ComposabilityRisk;
    }
    if text.contains("storage collision") {
        return VulnerabilityClass::StorageCollision;
    }
    if text.contains("upgrade") {
        return VulnerabilityClass::UpgradeabilityRisk;
    }
    VulnerabilityClass::Other("exploit_poc".into())
}

fn classify_hacklab_root_cause(content: &str, summary: &[String]) -> StructuralRootCause {
    let text = format!("{} {}", content, summary.join(" ")).to_lowercase();
    if text.contains("missing check")
        || text.contains("no check")
        || text.contains("missing validation")
    {
        return StructuralRootCause::MissingAuthorityCheck;
    }
    if text.contains("reentrancy") || text.contains("reentrant") {
        return StructuralRootCause::CrossFunctionStateInconsistency;
    }
    if text.contains("oracle") || text.contains("price manipulation") {
        return StructuralRootCause::OracleStaleness;
    }
    if text.contains("overflow") || text.contains("underflow") {
        return StructuralRootCause::MissingBoundaryCheck;
    }
    if text.contains("access control") || text.contains("unauthorized") {
        return StructuralRootCause::MissingAuthorityCheck;
    }
    if text.contains("precision") || text.contains("rounding") {
        return StructuralRootCause::IncorrectRoundingDirection;
    }
    if text.contains("flash loan") {
        return StructuralRootCause::UnvalidatedExternalInput;
    }
    if text.contains("infinite mint") {
        return StructuralRootCause::IncorrectInvariantAssumption;
    }
    StructuralRootCause::Other("exploit_poc".into())
}

fn classify_hacklab_technique(content: &str, summary: &[String]) -> AttackTechnique {
    let text = format!("{} {}", content, summary.join(" ")).to_lowercase();
    if text.contains("reentrancy") || text.contains("reentrant") {
        return AttackTechnique::ReentrancyExploit;
    }
    if text.contains("flash loan") || text.contains("flashloan") {
        return AttackTechnique::FlashLoanBorrow;
    }
    if text.contains("oracle") || text.contains("price manipulation") {
        return AttackTechnique::PriceOracleManipulation;
    }
    if text.contains("access control") || text.contains("unauthorized") {
        return AttackTechnique::AccessControlBypass;
    }
    if text.contains("delegatecall") {
        return AttackTechnique::DelegatecallExploitation;
    }
    if text.contains("sandwich") {
        return AttackTechnique::SandwichAttackVector;
    }
    if text.contains("front-run") || text.contains("frontrun") {
        return AttackTechnique::FrontRunningTransaction;
    }
    if text.contains("governance") {
        return AttackTechnique::GovernanceProposalAttack;
    }
    AttackTechnique::Other("exploit_poc".into())
}

fn classify_category(content: &str) -> ProtocolCategory {
    let lower = content.to_lowercase();
    if lower.contains("lending") || lower.contains("borrow") || lower.contains("collateral") {
        return ProtocolCategory::Lending;
    }
    if lower.contains("dex") || lower.contains("swap") || lower.contains("amm") {
        return ProtocolCategory::DEX;
    }
    if lower.contains("bridge") || lower.contains("cross-chain") {
        return ProtocolCategory::Bridge;
    }
    if lower.contains("governance") || lower.contains("voting") {
        return ProtocolCategory::Governance;
    }
    if lower.contains("vault") || lower.contains("strategy") {
        return ProtocolCategory::Vault;
    }
    if lower.contains("stablecoin") || lower.contains("peg") {
        return ProtocolCategory::Stablecoin;
    }
    if lower.contains("yield") || lower.contains("staking") {
        return ProtocolCategory::Yield;
    }
    ProtocolCategory::Unknown
}

fn classify_domain(content: &str) -> ProtocolDomain {
    let lower = content.to_lowercase();
    if lower.contains("lending") || lower.contains("borrow") || lower.contains("collateral") {
        return ProtocolDomain::Lending;
    }
    if lower.contains("dex") || lower.contains("swap") || lower.contains("amm") {
        return ProtocolDomain::AMMs;
    }
    if lower.contains("bridge") || lower.contains("cross-chain") {
        return ProtocolDomain::Bridges;
    }
    if lower.contains("governance") || lower.contains("voting") {
        return ProtocolDomain::Governance;
    }
    if lower.contains("vault") || lower.contains("strategy") {
        return ProtocolDomain::Vaults;
    }
    if lower.contains("oracle") || lower.contains("price feed") {
        return ProtocolDomain::Oracles;
    }
    if lower.contains("stablecoin") || lower.contains("peg") {
        return ProtocolDomain::Stablecoins;
    }
    ProtocolDomain::Generic
}

fn compute_finding_id(protocol: &str, filename: &str) -> String {
    let mut h: u64 = 0;
    for byte in protocol.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    for byte in filename.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    format!("hacklab:{:x}", h)
}

/// DeFiHackLabs knowledge source.
pub struct DeFiHackLabsSource {
    pub repo_path: String,
}

impl KnowledgeSource for DeFiHackLabsSource {
    fn source_id(&self) -> &str {
        "defihacklabs"
    }
    fn source_kind(&self) -> KnowledgeSourceKind {
        KnowledgeSourceKind::ExploitPostmortem
    }
    fn description(&self) -> &str {
        "DeFiHackLabs — 700+ runnable exploit PoCs"
    }
    fn supported_formats(&self) -> Vec<&str> {
        vec!["sol"]
    }
    fn extract(
        &self,
        content: &str,
        identifier: &str,
    ) -> Result<NormalizedKnowledge, ExtractionError> {
        // Infer date directory from identifier
        let date_dir = identifier.split('/').next().unwrap_or("unknown");
        let filename = identifier.split('/').next_back().unwrap_or(identifier);
        let entry = parse_hacklab_file(content, filename, date_dir);
        Ok(ingest_hacklab_entry(&entry))
    }
}
