/// SlowMist hacked repository source fetcher.
///
/// Fetches from the SlowMist community-maintained hack database:
/// https://github.com/TegveerG/SlowMist (slowmist.csv)
/// Contains 14K+ DeFi hack incident records with date, protocol,
/// description, funds lost, attack method, and source URL.
use crate::fetcher;
use crate::IngestionError;
use digger_knowledge_models::*;

/// Ingest SlowMist hack disclosures from community CSV.
pub fn ingest() -> Result<Vec<NormalizedKnowledge>, IngestionError> {
    let result = fetcher::fetch_github_repo("TegveerG", "SlowMist", ".")?;

    let mut items = Vec::new();
    for (name, content) in &result.items {
        if name == "slowmist.csv" {
            items = parse_slowmist_csv(content);
            break;
        }
    }

    // Also include the papers repo as secondary source
    if let Ok(papers_result) = fetcher::fetch_github_repo("slowmist", "papers", ".") {
        for (name, content) in &papers_result.items {
            if name.ends_with(".md") {
                if let Some(k) = parse_slowmist_md(name, content) {
                    items.push(k);
                }
            }
            if name.ends_with(".pdf") {
                let title = name.replace(".pdf", "");
                if let Some(k) = parse_slowmist_filename(&title) {
                    items.push(k);
                }
            }
        }
    }

    Ok(items)
}

/// Parse the SlowMist CSV file into NormalizedKnowledge items.
fn parse_slowmist_csv(csv_content: &str) -> Vec<NormalizedKnowledge> {
    let mut items = Vec::new();
    let mut lines = csv_content.lines();

    // Skip header
    let _header = lines.next();

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(k) = parse_csv_line(line) {
            items.push(k);
        }
    }

    items
}

/// Parse a single CSV line into NormalizedKnowledge.
///
/// CSV format: Date, Hacked_Target, Description, Funds_Lost, Attack_Method, Source
fn parse_csv_line(line: &str) -> Option<NormalizedKnowledge> {
    let fields = split_csv_line(line);
    if fields.len() < 4 {
        return None;
    }

    let date = fields[0].trim().to_string();
    let target = fields[1].trim().to_string();
    let description = fields[2].trim().to_string();
    let funds_lost = fields[3].trim().to_string();
    let attack_method = if fields.len() > 4 {
        fields[4].trim().to_string()
    } else {
        String::new()
    };
    let source_url = if fields.len() > 5 {
        fields[5].trim().to_string()
    } else {
        String::new()
    };

    if target.is_empty() || target.len() < 2 {
        return None;
    }

    let knowledge_id = compute_id("slowmist", &date, &target, &description);
    let finding_id = knowledge_id.clone();

    let vuln_class = classify_attack_method(&attack_method, &description);
    let severity = if !funds_lost.is_empty() {
        infer_severity_from_amount(&funds_lost)
    } else {
        digger_ir::Severity::Medium
    };

    let findings = vec![NormalizedFinding {
        finding_id,
        original_finding_id: format!("{}-{}", date, target.replace(' ', "_")),
        report_id: format!("slowmist:{}", date),
        protocol_name: target.clone(),
        protocol_category: ProtocolCategory::Unknown,
        protocol_domain: ProtocolDomain::Generic,
        protocol_pattern: Some(attack_method.clone()),
        vulnerability_class: vuln_class,
        attack_goal: if !funds_lost.is_empty() {
            format!("Steal {} USD", funds_lost)
        } else {
            "Steal funds".into()
        },
        capability_pattern: vec![],
        violated_invariant: ViolatedInvariant {
            kind: "conservation".into(),
            description: format!("Unauthorized fund extraction from {}", target),
            affected_state_vars: vec![],
        },
        attack_technique: classify_attack_technique(&attack_method),
        mitigation_pattern: None,
        security_assumptions: vec![],
        severity,
        root_cause: StructuralRootCause::Other("slowmist_incident".into()),
        impact_text: if !funds_lost.is_empty() {
            format!("${} lost", funds_lost)
        } else {
            String::new()
        },
        description_text: description.clone(),
        remediation_text: String::new(),
        impacted_contracts: vec![],
        impacted_functions: vec![],
        confidence: 1.0,
    }];

    let mut raw_sections = std::collections::BTreeMap::new();
    if !description.is_empty() {
        raw_sections.insert("Description".into(), description);
    }
    if !attack_method.is_empty() {
        raw_sections.insert("Attack Method".into(), attack_method);
    }
    if !source_url.is_empty() {
        raw_sections.insert("Source".into(), source_url);
    }

    Some(NormalizedKnowledge {
        knowledge_id,
        source_id: "slowmist".into(),
        source_kind: KnowledgeSourceKind::ExploitPostmortem,
        source_identifier: format!("slowmist:{}:{}", date, target),
        subject: target,
        subject_category: "DeFi".into(),
        findings,
        evidence: vec![],
        invariants: vec![],
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![],
        claims: vec![],
        raw_sections,
    })
}

/// Split a CSV line respecting quoted fields.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

fn classify_attack_method(method: &str, description: &str) -> VulnerabilityClass {
    let combined = format!("{} {}", method, description).to_lowercase();
    if combined.contains("reentrancy") {
        VulnerabilityClass::Reentrancy
    } else if combined.contains("flash loan") || combined.contains("flashloan") {
        VulnerabilityClass::FlashLoanAttack
    } else if combined.contains("oracle") || combined.contains("price manipulat") {
        VulnerabilityClass::OracleManipulation
    } else if combined.contains("access control") || combined.contains("privilege") {
        VulnerabilityClass::MissingAccessControl
    } else if combined.contains("sandwich")
        || combined.contains("front-run")
        || combined.contains("frontrun")
        || combined.contains("mev")
    {
        VulnerabilityClass::SandwichAttack
    } else if combined.contains("logic") || combined.contains("business logic") {
        VulnerabilityClass::BusinessLogicFlaw
    } else if combined.contains("bridge") {
        VulnerabilityClass::ComposabilityRisk
    } else if combined.contains("governance")
        || combined.contains("flash loan") && combined.contains("governance")
    {
        VulnerabilityClass::GovernanceAttack
    } else if combined.contains("rug pull")
        || combined.contains("rugpull")
        || combined.contains("rug")
    {
        VulnerabilityClass::BusinessLogicFlaw
    } else if combined.contains("phish") {
        VulnerabilityClass::Other("social_engineering".into())
    } else if combined.contains("private key")
        || combined.contains("key leak")
        || combined.contains("compromised")
    {
        VulnerabilityClass::MissingAccessControl
    } else {
        VulnerabilityClass::Other("slowmist_classified".into())
    }
}

fn classify_attack_technique(method: &str) -> AttackTechnique {
    let lower = method.to_lowercase();
    if lower.contains("flash") {
        AttackTechnique::FlashLoanBorrow
    } else if lower.contains("reentrancy") {
        AttackTechnique::ReentrancyExploit
    } else if lower.contains("oracle") {
        AttackTechnique::PriceOracleManipulation
    } else if lower.contains("access") || lower.contains("privilege") {
        AttackTechnique::AccessControlBypass
    } else if lower.contains("sandwich") || lower.contains("mev") || lower.contains("front") {
        AttackTechnique::FrontRunningTransaction
    } else {
        AttackTechnique::Other("slowmist_method".into())
    }
}

fn infer_severity_from_amount(amount_str: &str) -> digger_ir::Severity {
    let cleaned: String = amount_str
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    match cleaned.parse::<f64>() {
        Ok(amount) if amount >= 10_000_000.0 => digger_ir::Severity::Critical,
        Ok(amount) if amount >= 1_000_000.0 => digger_ir::Severity::High,
        Ok(amount) if amount >= 100_000.0 => digger_ir::Severity::Medium,
        Ok(_) => digger_ir::Severity::Low,
        Err(_) => digger_ir::Severity::Medium,
    }
}

fn compute_id(source: &str, date: &str, target: &str, desc: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    hasher.update(date.as_bytes());
    hasher.update(target.as_bytes());
    let snippet: String = desc.chars().take(100).collect();
    hasher.update(snippet.as_bytes());
    format!("slowmist-{:x}", hasher.finalize())
}

fn parse_slowmist_md(filename: &str, content: &str) -> Option<NormalizedKnowledge> {
    let title = extract_title(content);
    let knowledge_id = compute_id("slowmist-papers", filename, &title, content);

    let findings = vec![NormalizedFinding {
        finding_id: knowledge_id.clone(),
        original_finding_id: filename.replace(".md", ""),
        report_id: format!("slowmist-papers:{}", filename),
        protocol_name: title.clone(),
        protocol_category: ProtocolCategory::Unknown,
        protocol_domain: ProtocolDomain::Generic,
        protocol_pattern: None,
        vulnerability_class: VulnerabilityClass::Other("slowmist_advisory".into()),
        attack_goal: "Security advisory".into(),
        capability_pattern: vec![],
        violated_invariant: ViolatedInvariant {
            kind: "advisory".into(),
            description: title.to_string(),
            affected_state_vars: vec![],
        },
        attack_technique: AttackTechnique::Other("slowmist_advisory".into()),
        mitigation_pattern: None,
        security_assumptions: vec![],
        severity: digger_ir::Severity::Medium,
        root_cause: StructuralRootCause::Other("slowmist_advisory".into()),
        impact_text: String::new(),
        description_text: content.chars().take(500).collect(),
        remediation_text: String::new(),
        impacted_contracts: vec![],
        impacted_functions: vec![],
        confidence: 0.7,
    }];

    Some(NormalizedKnowledge {
        knowledge_id,
        source_id: "slowmist".into(),
        source_kind: KnowledgeSourceKind::TechnicalWriteup,
        source_identifier: format!("slowmist-papers:{}", filename),
        subject: title,
        subject_category: "Security Advisory".into(),
        findings,
        evidence: vec![],
        invariants: vec![],
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![],
        claims: vec![],
        raw_sections: extract_raw_sections(content),
    })
}

fn parse_slowmist_filename(title: &str) -> Option<NormalizedKnowledge> {
    if title.is_empty() || title.len() < 5 {
        return None;
    }
    let knowledge_id = compute_id("slowmist-papers", title, title, title);

    let findings = vec![NormalizedFinding {
        finding_id: knowledge_id.clone(),
        original_finding_id: title.to_string(),
        report_id: format!("slowmist-papers:{}", title),
        protocol_name: title.to_string(),
        protocol_category: ProtocolCategory::Unknown,
        protocol_domain: ProtocolDomain::Generic,
        protocol_pattern: None,
        vulnerability_class: VulnerabilityClass::Other("slowmist_advisory".into()),
        attack_goal: "Security advisory".into(),
        capability_pattern: vec![],
        violated_invariant: ViolatedInvariant {
            kind: "advisory".into(),
            description: title.to_string(),
            affected_state_vars: vec![],
        },
        attack_technique: AttackTechnique::Other("slowmist_advisory".into()),
        mitigation_pattern: None,
        security_assumptions: vec![],
        severity: digger_ir::Severity::Medium,
        root_cause: StructuralRootCause::Other("slowmist_advisory".into()),
        impact_text: String::new(),
        description_text: title.to_string(),
        remediation_text: String::new(),
        impacted_contracts: vec![],
        impacted_functions: vec![],
        confidence: 0.7,
    }];

    Some(NormalizedKnowledge {
        knowledge_id,
        source_id: "slowmist".into(),
        source_kind: KnowledgeSourceKind::TechnicalWriteup,
        source_identifier: format!("slowmist-papers:{}", title),
        subject: title.to_string(),
        subject_category: "Security Advisory".into(),
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

fn extract_title(content: &str) -> String {
    for line in content.lines() {
        if line.starts_with('#') {
            return line.trim_start_matches('#').trim().to_string();
        }
    }
    "Unknown".into()
}

fn extract_raw_sections(content: &str) -> std::collections::BTreeMap<String, String> {
    let mut sections = std::collections::BTreeMap::new();
    let mut current = String::new();
    let mut body = String::new();
    for line in content.lines() {
        if line.starts_with('#') {
            if !current.is_empty() {
                sections.insert(current.clone(), body.trim().to_string());
            }
            current = line.trim_start_matches('#').trim().to_string();
            body.clear();
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }
    if !current.is_empty() {
        sections.insert(current, body.trim().to_string());
    }
    sections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_line_parsing() {
        let line = r#"2023-01-01,Test Protocol,Some hack description,1500000,Flash Loan,https://example.com"#;
        let k = parse_csv_line(line).unwrap();
        assert_eq!(k.subject, "Test Protocol");
        assert_eq!(
            k.findings[0].vulnerability_class,
            VulnerabilityClass::FlashLoanAttack
        );
        assert_eq!(k.findings[0].severity, digger_ir::Severity::High);
    }

    #[test]
    fn test_severity_inference() {
        assert_eq!(
            infer_severity_from_amount("25000000"),
            digger_ir::Severity::Critical
        );
        assert_eq!(
            infer_severity_from_amount("5000000"),
            digger_ir::Severity::High
        );
        assert_eq!(
            infer_severity_from_amount("500000"),
            digger_ir::Severity::Medium
        );
        assert_eq!(
            infer_severity_from_amount("50000"),
            digger_ir::Severity::Low
        );
    }

    #[test]
    fn test_attack_classification() {
        assert_eq!(
            classify_attack_method("Flash Loan", ""),
            VulnerabilityClass::FlashLoanAttack
        );
        assert_eq!(
            classify_attack_method("Reentrancy", ""),
            VulnerabilityClass::Reentrancy
        );
        assert_eq!(
            classify_attack_method("Rug Pull", ""),
            VulnerabilityClass::BusinessLogicFlaw
        );
    }

    #[test]
    fn test_quoted_csv_field() {
        let line = r#"2023-01-01,Test,"Description, with comma",1000000,Other,http://x.com"#;
        let fields = split_csv_line(line);
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[2], "Description, with comma");
    }

    #[test]
    fn test_adversarial_empty_string() {
        assert!(parse_csv_line("").is_none());
    }

    #[test]
    fn test_adversarial_garbage() {
        assert!(parse_csv_line("not,a,csv").is_none());
        assert!(parse_csv_line(",,,,").is_none());
    }

    #[test]
    fn test_adversarial_truncated() {
        assert!(parse_csv_line("2023-01-01").is_none());
        assert!(parse_csv_line("2023-01-01,X").is_none());
    }

    #[test]
    fn test_adversarial_only_commas() {
        assert!(parse_csv_line(",,,,,").is_none());
    }

    #[test]
    fn test_parse_slowmist_csv_valid_fixture() {
        let csv = "Date,Hacked_Target,Description,Funds_Lost,Attack_Method,Source\n2023-06-01,TestProtocol,Flash loan reentrancy,5000000,Flash Loan,https://example.com\n";
        let items = parse_slowmist_csv(csv);
        assert!(
            !items.is_empty(),
            "valid CSV should produce non-empty output"
        );
    }

    #[test]
    fn test_parse_slowmist_csv_empty() {
        let csv = "Date,Hacked_Target,Description,Funds_Lost,Attack_Method,Source\n";
        let items = parse_slowmist_csv(csv);
        assert!(
            items.is_empty(),
            "header-only CSV should produce empty output"
        );
    }

    #[test]
    fn test_parse_slowmist_csv_garbage() {
        let csv = "this is not csv data\njust random text\n";
        let items = parse_slowmist_csv(csv);
        assert!(items.is_empty());
    }

    #[test]
    fn test_parse_slowmist_md_fixture() {
        let md = "# Security Advisory Title\n\nThis is a security advisory about reentrancy.\n";
        let result = parse_slowmist_md("advisory.md", md);
        assert!(result.is_some());
        let k = result.expect("should parse");
        assert_eq!(k.source_id, "slowmist");
        assert!(!k.findings.is_empty());
    }

    #[test]
    fn test_parse_slowmist_filename_valid() {
        let result = parse_slowmist_filename("DeFi Security Best Practices");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_slowmist_filename_too_short() {
        let result = parse_slowmist_filename("ab");
        assert!(result.is_none());
    }
}
