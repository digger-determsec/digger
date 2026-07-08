/// GitHub Security Advisories source fetcher.
///
/// Fetches from GitHub's public advisories API:
/// https://api.github.com/advisories
///
/// Contains security advisories across all ecosystems. We filter for
/// blockchain/smart contract advisories (Ethereum, Solidity, Solana, etc.)
/// and extract structured security knowledge.
use crate::IngestionError;
use digger_knowledge_models::*;
use std::process::Command;

/// Ecosystem keywords that indicate blockchain/smart contract advisories.
const BLOCKCHAIN_ECOSYSTEMS: &[&str] = &[
    "solidity",
    "ethereum",
    "evm",
    "solana",
    "anchor",
    "defi",
    "smart-contract",
    "smart contract",
    "token",
    "erc20",
    "erc721",
    "erc4626",
    "erc1155",
    "reentrancy",
    "flashloan",
    "flash-loan",
    "uniswap",
    "aave",
    "compound",
    "maker",
    "curve",
    "balancer",
    "opensea",
    "blur",
    "lido",
    "stake",
    "bridge",
    "multisig",
    "governance",
    "timelock",
    "proxy",
    "upgradeable",
    "beacon",
    "spl-token",
    "cpi",
    "pda",
    "program",
];

/// Ingest GitHub Security Advisories for blockchain ecosystems.
pub fn ingest() -> Result<Vec<NormalizedKnowledge>, IngestionError> {
    let mut items = Vec::new();
    let mut page = 1u32;
    let per_page = 100;
    let max_pages = 50; // Limit to avoid excessive API calls

    loop {
        if page > max_pages {
            break;
        }

        let advisories = fetch_advisories_page(page, per_page)?;
        if advisories.is_empty() {
            break;
        }

        for advisory in &advisories {
            if is_blockchain_advisory(advisory) {
                if let Some(k) = parse_advisory(advisory) {
                    items.push(k);
                }
            }
        }

        if advisories.len() < per_page as usize {
            break;
        }

        page += 1;
    }

    Ok(items)
}

/// Fetch a single page of advisories via gh api.
fn fetch_advisories_page(
    page: u32,
    per_page: u32,
) -> Result<Vec<serde_json::Value>, IngestionError> {
    let output = Command::new("gh")
        .args([
            "api",
            &format!("/advisories?per_page={}&page={}", per_page, page),
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(IngestionError::Process(format!("gh api error: {}", stderr)));
    }

    let advisories: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .map_err(|e| IngestionError::Parse(format!("JSON parse error: {}", e)))?;

    Ok(advisories)
}

/// Check if an advisory is related to blockchain/smart contracts.
fn is_blockchain_advisory(advisory: &serde_json::Value) -> bool {
    let summary = advisory["summary"].as_str().unwrap_or("").to_lowercase();
    let description = advisory["description"]
        .as_str()
        .unwrap_or("")
        .to_lowercase();
    let combined = format!("{} {}", summary, description);

    BLOCKCHAIN_ECOSYSTEMS
        .iter()
        .any(|eco| combined.contains(eco))
}

/// Parse a GitHub advisory into NormalizedKnowledge.
fn parse_advisory(advisory: &serde_json::Value) -> Option<NormalizedKnowledge> {
    let ghsa_id = extract_identifier(advisory, "GHSA")?;
    let cve_id = extract_identifier(advisory, "CVE");
    let summary = advisory["summary"].as_str().unwrap_or("").to_string();
    let description = advisory["description"].as_str().unwrap_or("").to_string();
    let severity_str = advisory["severity"]
        .as_str()
        .unwrap_or("medium")
        .to_string();
    let published = advisory["published_at"].as_str().unwrap_or("").to_string();
    let updated = advisory["updated_at"].as_str().unwrap_or("").to_string();

    if summary.is_empty() {
        return None;
    }

    let knowledge_id = compute_id(&ghsa_id, &summary);
    let severity = map_severity(&severity_str);
    let vuln_class = classify_from_summary(&summary, &description);
    let root_cause = infer_root_cause(&summary, &description);

    let impact_text = extract_impact(advisory);

    let findings = vec![NormalizedFinding {
        finding_id: knowledge_id.clone(),
        original_finding_id: ghsa_id.clone(),
        report_id: format!("ghsa:{}", ghsa_id),
        protocol_name: extract_protocol_name(&summary),
        protocol_category: ProtocolCategory::Unknown,
        protocol_domain: ProtocolDomain::Generic,
        protocol_pattern: None,
        vulnerability_class: vuln_class.clone(),
        attack_goal: extract_attack_goal(&summary, &description),
        capability_pattern: vec![],
        violated_invariant: ViolatedInvariant {
            kind: root_cause_kind(&vuln_class),
            description: summary.clone(),
            affected_state_vars: vec![],
        },
        attack_technique: classify_attack_technique_from_summary(&summary),
        mitigation_pattern: extract_mitigation(advisory),
        security_assumptions: vec![],
        severity,
        root_cause,
        impact_text,
        description_text: if description.len() > 2000 {
            description[..2000].to_string()
        } else {
            description.clone()
        },
        remediation_text: String::new(),
        impacted_contracts: vec![],
        impacted_functions: vec![],
        confidence: 1.0,
    }];

    let mut raw_sections = std::collections::BTreeMap::new();
    raw_sections.insert("Summary".into(), summary.clone());
    if !description.is_empty() {
        raw_sections.insert("Description".into(), description);
    }
    raw_sections.insert("Severity".into(), severity_str.clone());
    raw_sections.insert("Published".into(), published.clone());
    if let Some(cve) = &cve_id {
        raw_sections.insert("CVE".into(), cve.clone());
    }
    if !updated.is_empty() {
        raw_sections.insert("Updated".into(), updated);
    }

    let mut references = vec![];
    references.push(KnowledgeReference {
        reference_id: format!("https://github.com/advisories/{}", ghsa_id),
        kind: ReferenceKind::AuditReport,
        description: format!("GitHub Security Advisory {}", ghsa_id),
    });
    if let Some(cve) = cve_id {
        references.push(KnowledgeReference {
            reference_id: format!("https://nvd.nist.gov/vuln/detail/{}", cve),
            kind: ReferenceKind::AuditReport,
            description: format!("NVD Entry {}", cve),
        });
    }

    Some(NormalizedKnowledge {
        knowledge_id,
        source_id: "github-advisories".into(),
        source_kind: KnowledgeSourceKind::ExploitPostmortem,
        source_identifier: format!("ghsa:{}", ghsa_id),
        subject: extract_protocol_name(&summary),
        subject_category: "Security Advisory".into(),
        findings,
        evidence: vec![],
        invariants: vec![],
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references,
        claims: vec![],
        raw_sections,
    })
}

fn extract_identifier(advisory: &serde_json::Value, kind: &str) -> Option<String> {
    advisory["identifiers"]
        .as_array()?
        .iter()
        .find(|id| id["type"].as_str() == Some(kind))
        .and_then(|id| id["value"].as_str().map(String::from))
}

fn extract_protocol_name(summary: &str) -> String {
    // Try to extract the protocol/product name from the advisory title
    // Common patterns: "ProtocolName has a...", "ProtocolName: ...", "In ProtocolName"
    let words: Vec<&str> = summary.split_whitespace().collect();
    if !words.is_empty() {
        let name = words[0].trim_end_matches(':');
        if name.len() >= 2 {
            return name.to_string();
        }
    }
    "Unknown".into()
}

fn map_severity(severity: &str) -> digger_ir::Severity {
    match severity {
        "critical" => digger_ir::Severity::Critical,
        "high" => digger_ir::Severity::High,
        "medium" => digger_ir::Severity::Medium,
        "low" => digger_ir::Severity::Low,
        _ => digger_ir::Severity::Info,
    }
}

fn classify_from_summary(summary: &str, description: &str) -> VulnerabilityClass {
    let combined = format!("{} {}", summary, description).to_lowercase();

    if combined.contains("reentrancy") || combined.contains("reentrant") {
        VulnerabilityClass::Reentrancy
    } else if combined.contains("access control")
        || combined.contains("unauthorized")
        || combined.contains("privilege")
        || combined.contains("authentication bypass")
    {
        VulnerabilityClass::MissingAccessControl
    } else if combined.contains("flash loan") || combined.contains("flashloan") {
        VulnerabilityClass::FlashLoanAttack
    } else if combined.contains("oracle")
        || combined.contains("price feed")
        || combined.contains("price manipulat")
    {
        VulnerabilityClass::OracleManipulation
    } else if combined.contains("sandwich")
        || combined.contains("front-runn")
        || combined.contains("mev")
    {
        VulnerabilityClass::SandwichAttack
    } else if combined.contains("cross-site scripting")
        || combined.contains("xss")
        || combined.contains("sql injection")
    {
        VulnerabilityClass::Other("web_vulnerability".into())
    } else if combined.contains("denial of service")
        || combined.contains("dos")
        || combined.contains("resource exhaustion")
    {
        VulnerabilityClass::DenialOfService
    } else if combined.contains("integer overflow")
        || combined.contains("overflow")
        || combined.contains("underflow")
    {
        VulnerabilityClass::IntegerOverflow
    } else if combined.contains("cross-chain") || combined.contains("bridge") {
        VulnerabilityClass::ComposabilityRisk
    } else if combined.contains("governance") || combined.contains("voting") {
        VulnerabilityClass::GovernanceAttack
    } else {
        VulnerabilityClass::Other("ghsa_classified".into())
    }
}

fn classify_attack_technique_from_summary(summary: &str) -> AttackTechnique {
    let lower = summary.to_lowercase();
    if lower.contains("reentrancy") {
        AttackTechnique::ReentrancyExploit
    } else if lower.contains("access control")
        || lower.contains("unauthorized")
        || lower.contains("authentication bypass")
    {
        AttackTechnique::AccessControlBypass
    } else if lower.contains("flash loan") || lower.contains("flashloan") {
        AttackTechnique::FlashLoanBorrow
    } else if lower.contains("oracle") || lower.contains("price") {
        AttackTechnique::PriceOracleManipulation
    } else if lower.contains("sandwich") || lower.contains("front-runn") || lower.contains("mev") {
        AttackTechnique::FrontRunningTransaction
    } else {
        AttackTechnique::Other("ghsa_technique".into())
    }
}

fn infer_root_cause(summary: &str, description: &str) -> StructuralRootCause {
    let combined = format!("{} {}", summary, description).to_lowercase();
    if combined.contains("missing") && combined.contains("valid") {
        StructuralRootCause::Other("missing_validation".into())
    } else if combined.contains("improper") || combined.contains("incorrect") {
        StructuralRootCause::Other("incorrect_implementation".into())
    } else if combined.contains("missing") && combined.contains("access") {
        StructuralRootCause::Other("missing_access_control".into())
    } else {
        StructuralRootCause::Other("ghsa_root_cause".into())
    }
}

fn root_cause_kind(vuln_class: &VulnerabilityClass) -> String {
    match vuln_class {
        VulnerabilityClass::Reentrancy => "reentrancy".into(),
        VulnerabilityClass::MissingAccessControl => "access_control".into(),
        VulnerabilityClass::FlashLoanAttack => "flash_loan".into(),
        VulnerabilityClass::OracleManipulation => "oracle_manipulation".into(),
        VulnerabilityClass::DenialOfService => "denial_of_service".into(),
        _ => "general".into(),
    }
}

fn extract_attack_goal(summary: &str, description: &str) -> String {
    let combined = format!("{} {}", summary, description).to_lowercase();
    if combined.contains("steal") || combined.contains("drain") || combined.contains("extract fund")
    {
        "Steal funds".into()
    } else if combined.contains("bypass") || combined.contains("circumvent") {
        "Bypass security controls".into()
    } else if combined.contains("manipulate") {
        "Manipulate system state".into()
    } else if combined.contains("denial of service") || combined.contains("dos") {
        "Disrupt service availability".into()
    } else {
        "Exploit vulnerability".into()
    }
}

fn extract_impact(advisory: &serde_json::Value) -> String {
    let severity = advisory["severity"].as_str().unwrap_or("");
    let cvss = advisory["cvss"]
        .as_object()
        .and_then(|o| o.get("score"))
        .and_then(|s| s.as_f64());
    match (severity, cvss) {
        ("critical", Some(score)) => format!("Critical severity (CVSS {})", score),
        ("high", Some(score)) => format!("High severity (CVSS {})", score),
        ("medium", Some(score)) => format!("Medium severity (CVSS {})", score),
        ("low", Some(score)) => format!("Low severity (CVSS {})", score),
        (_, Some(score)) => format!("CVSS {}", score),
        (sev, None) => format!("{} severity", sev),
    }
}

fn extract_mitigation(advisory: &serde_json::Value) -> Option<MitigationPattern> {
    advisory["withdrawn_at"]
        .as_str()
        .map(|_| MitigationPattern {
            technique: "advisory_withdrawn".into(),
            description: "Advisory has been withdrawn".into(),
            is_standard: true,
        })
}

fn compute_id(ghsa_id: &str, summary: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(ghsa_id.as_bytes());
    hasher.update(summary.as_bytes());
    format!("ghsa-{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_mapping() {
        assert_eq!(map_severity("critical"), digger_ir::Severity::Critical);
        assert_eq!(map_severity("high"), digger_ir::Severity::High);
        assert_eq!(map_severity("medium"), digger_ir::Severity::Medium);
        assert_eq!(map_severity("low"), digger_ir::Severity::Low);
    }

    #[test]
    fn test_vuln_classification() {
        assert_eq!(
            classify_from_summary("Reentrancy in contract", ""),
            VulnerabilityClass::Reentrancy
        );
        assert_eq!(
            classify_from_summary("Access control bypass", ""),
            VulnerabilityClass::MissingAccessControl
        );
        assert_eq!(
            classify_from_summary("Flash loan attack", ""),
            VulnerabilityClass::FlashLoanAttack
        );
    }

    #[test]
    fn test_protocol_name_extraction() {
        assert_eq!(
            extract_protocol_name("Uniswap has a vulnerability"),
            "Uniswap"
        );
        assert_eq!(extract_protocol_name("Aave: integer overflow"), "Aave");
    }

    #[test]
    fn test_id_deterministic() {
        let id1 = compute_id("GHSA-1234", "test summary");
        let id2 = compute_id("GHSA-1234", "test summary");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_adversarial_empty_advisory() {
        let advisory = serde_json::json!({});
        assert!(parse_advisory(&advisory).is_none());
    }

    #[test]
    fn test_adversarial_empty_identifiers() {
        let advisory = serde_json::json!({
            "identifiers": [],
            "summary": "Test",
            "description": ""
        });
        assert!(parse_advisory(&advisory).is_none());
    }

    #[test]
    fn test_adversarial_garbage_json() {
        let advisory = serde_json::json!({
            "random_field": "garbage"
        });
        assert!(parse_advisory(&advisory).is_none());
    }

    #[test]
    fn test_adversarial_null_identifiers() {
        let advisory = serde_json::json!({
            "identifiers": null,
            "summary": "Test"
        });
        assert!(parse_advisory(&advisory).is_none());
    }

    #[test]
    fn test_blockchain_detection_positive() {
        let advisory = serde_json::json!({
            "summary": "Reentrancy in Uniswap smart contract",
            "description": "A reentrancy vulnerability was found in the Solidity contract"
        });
        assert!(is_blockchain_advisory(&advisory));
    }

    #[test]
    fn test_blockchain_detection_negative() {
        let advisory = serde_json::json!({
            "summary": "Buffer overflow in nginx web server",
            "description": "A buffer overflow vulnerability in HTTP parsing"
        });
        assert!(!is_blockchain_advisory(&advisory));
    }

    #[test]
    fn test_valid_advisory_fixture() {
        let advisory = serde_json::json!({
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-TEST-1234"}
            ],
            "summary": "Reentrancy vulnerability in TestProtocol",
            "description": "A reentrancy vulnerability allows attackers to drain funds from the vault contract using flash loans",
            "severity": "critical",
            "published_at": "2024-01-15T00:00:00Z",
            "updated_at": "2024-01-16T00:00:00Z"
        });
        let result = parse_advisory(&advisory);
        assert!(result.is_some());
        let k = result.expect("should parse");
        assert_eq!(k.source_id, "github-advisories");
        assert!(!k.findings.is_empty());
        assert_eq!(
            k.findings[0].vulnerability_class,
            VulnerabilityClass::Reentrancy
        );
    }
}
