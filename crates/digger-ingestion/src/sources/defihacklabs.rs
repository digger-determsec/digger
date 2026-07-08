/// DeFiHackLabs source fetcher.
///
/// Fetches PoC exploit reproductions from SunWeb3Sec/DeFiHackLabs.
use crate::fetcher;
use crate::IngestionError;
use digger_knowledge_models::*;

pub fn ingest() -> Result<Vec<NormalizedKnowledge>, IngestionError> {
    let result = fetcher::fetch_github_repo("SunWeb3Sec", "DeFiHackLabs", "src/test")?;
    let mut items = Vec::new();
    for (name, content) in &result.items {
        if name.ends_with(".sol") {
            if let Some(k) = parse_entry(name, content) {
                items.push(k);
            }
        }
    }
    Ok(items)
}

fn parse_entry(filename: &str, content: &str) -> Option<NormalizedKnowledge> {
    let protocol_name = filename.replace(".sol", "").replace('_', " ");
    let knowledge_id = compute_id(filename, content);
    let exploit_type = detect_exploit_type(content);

    let findings = vec![NormalizedFinding {
        finding_id: knowledge_id.clone(),
        original_finding_id: filename.replace(".sol", ""),
        report_id: format!("defihacklabs:{}", filename),
        protocol_name: protocol_name.clone(),
        protocol_category: ProtocolCategory::Unknown,
        protocol_domain: ProtocolDomain::Generic,
        protocol_pattern: Some(exploit_type.clone()),
        vulnerability_class: classify_exploit(&exploit_type),
        attack_goal: format!("Exploit via {}", exploit_type),
        capability_pattern: extract_capabilities(content),
        violated_invariant: ViolatedInvariant {
            kind: "conservation".into(),
            description: format!("Unauthorized fund extraction from {}", protocol_name),
            affected_state_vars: vec![],
        },
        attack_technique: AttackTechnique::Other("defihacklabs_ingestion".into()),
        mitigation_pattern: None,
        security_assumptions: vec![],
        severity: digger_ir::Severity::Critical,
        root_cause: StructuralRootCause::Other("defihacklabs_ingestion".into()),
        impact_text: String::new(),
        description_text: content.chars().take(500).collect(),
        remediation_text: String::new(),
        impacted_contracts: extract_contracts(content),
        impacted_functions: vec![],
        confidence: 1.0,
    }];

    Some(NormalizedKnowledge {
        knowledge_id,
        source_id: "defihacklabs".into(),
        source_kind: KnowledgeSourceKind::ExploitPostmortem,
        source_identifier: format!("defihacklabs:{}", filename),
        subject: protocol_name,
        subject_category: "DeFi".into(),
        findings,
        evidence: vec![],
        invariants: vec![],
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![],
        claims: vec![],
        raw_sections: std::collections::BTreeMap::new(),
    })
}

fn detect_exploit_type(content: &str) -> String {
    let lower = content.to_lowercase();
    if lower.contains("flashloan") || lower.contains("flash_loan") || lower.contains("flash loan") {
        "FlashLoan".into()
    } else if lower.contains("reentrancy") || lower.contains("reentrant") {
        "Reentrancy".into()
    } else if lower.contains("oracle") {
        "OracleManipulation".into()
    } else if lower.contains("access") && lower.contains("control") {
        "AccessControl".into()
    } else {
        "GenericExploit".into()
    }
}

fn classify_exploit(exploit_type: &str) -> VulnerabilityClass {
    match exploit_type {
        "FlashLoan" => VulnerabilityClass::FlashLoanAttack,
        "Reentrancy" => VulnerabilityClass::Reentrancy,
        "OracleManipulation" => VulnerabilityClass::OracleManipulation,
        "AccessControl" => VulnerabilityClass::MissingAccessControl,
        _ => VulnerabilityClass::Other("generic_exploit".into()),
    }
}

fn extract_capabilities(content: &str) -> Vec<String> {
    let mut caps = Vec::new();
    let lower = content.to_lowercase();
    if lower.contains("flashloan") || lower.contains("flash loan") {
        caps.push("flash_loan".into());
    }
    if lower.contains("uniswap") || lower.contains("sushiswap") || lower.contains("pancakeswap") {
        caps.push("dex_interaction".into());
    }
    caps
}

fn extract_contracts(content: &str) -> Vec<String> {
    let mut contracts = Vec::new();
    let mut words = content.split_whitespace();
    while let Some(word) = words.next() {
        if word == "contract" || word == "interface" {
            if let Some(name) = words.next() {
                let clean: String = name
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !clean.is_empty() && !contracts.contains(&clean) {
                    contracts.push(clean);
                }
            }
        }
    }
    contracts
}

fn compute_id(filename: &str, content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"defihacklabs");
    hasher.update(filename.as_bytes());
    let snippet: String = content.chars().take(200).collect();
    hasher.update(snippet.as_bytes());
    format!("hacklabs-{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_entry_valid_fixture() {
        let content = "contract TestContract { function exploit() external { } }";
        let result = parse_entry("TestProtocol_exploit.sol", content);
        assert!(result.is_some());
        let k = result.expect("should parse");
        assert_eq!(k.source_id, "defihacklabs");
        assert!(!k.findings.is_empty());
    }

    #[test]
    fn test_parse_entry_flashloan() {
        let content = "function test() public { IFlashLoan flashloan = ... }";
        let k = parse_entry("FlashLoan_exploit.sol", content).expect("should parse");
        assert_eq!(
            k.findings[0].vulnerability_class,
            VulnerabilityClass::FlashLoanAttack
        );
    }

    #[test]
    fn test_parse_entry_reentrancy() {
        let content = "function test() public { require(reentrancy == true); }";
        let k = parse_entry("Reentrancy_exploit.sol", content).expect("should parse");
        assert_eq!(
            k.findings[0].vulnerability_class,
            VulnerabilityClass::Reentrancy
        );
    }

    #[test]
    fn test_parse_entry_oracle() {
        let content = "function test() public { price = oracle.getLatestPrice(); }";
        let k = parse_entry("Oracle_exploit.sol", content).expect("should parse");
        assert_eq!(
            k.findings[0].vulnerability_class,
            VulnerabilityClass::OracleManipulation
        );
    }

    #[test]
    fn test_adversarial_empty_content() {
        let result = parse_entry("test.sol", "");
        assert!(
            result.is_some(),
            "even empty content should produce a result"
        );
    }

    #[test]
    fn test_adversarial_garbage_content() {
        let result = parse_entry("test.sol", "not solidity code at all");
        assert!(result.is_some());
    }

    #[test]
    fn test_adversarial_non_sol_file() {
        let result = parse_entry("test.js", "function test() {}");
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_contracts_empty() {
        let contracts = extract_contracts("");
        assert!(contracts.is_empty());
    }

    #[test]
    fn test_extract_contracts_multiple() {
        let content = "contract A { } contract B { } interface C { }";
        let contracts = extract_contracts(content);
        assert!(contracts.contains(&"A".to_string()));
        assert!(contracts.contains(&"B".to_string()));
        assert!(contracts.contains(&"C".to_string()));
    }
}
