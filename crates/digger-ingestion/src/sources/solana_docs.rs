/// Solana documentation source fetcher.
///
/// Fetches security-relevant documentation from key Solana ecosystem repos:
/// - coral-xyz/anchor: Framework docs, account constraints, footguns
/// - solana-labs/solana-program-library: SPL Token, Token-2022, governance
///
/// Extracts security invariants, constraint patterns, and best practices
/// into NormalizedKnowledge for the reasoning engine.
use crate::fetcher;
use crate::IngestionError;
use digger_knowledge_models::*;

/// Ingest Solana ecosystem documentation.
pub fn ingest() -> Result<Vec<NormalizedKnowledge>, IngestionError> {
    let mut items = Vec::new();

    // 1. Anchor framework documentation
    if let Ok(anchor_result) = fetcher::fetch_github_repo("coral-xyz", "anchor", ".") {
        for (name, content) in &anchor_result.items {
            if is_security_relevant_doc(name) {
                if let Some(k) = parse_anchor_doc(name, content) {
                    items.push(k);
                }
            }
        }
    }

    // 2. SPL Token-2022 documentation
    if let Ok(spl_result) =
        fetcher::fetch_github_repo("solana-labs", "solana-program-library", "token/emoji-2022")
    {
        for (name, content) in &spl_result.items {
            if name.ends_with(".md") || name.ends_with(".mdx") {
                if let Some(k) = parse_spl_doc(name, content, "token-2022") {
                    items.push(k);
                }
            }
        }
    }

    Ok(items)
}

/// Check if a documentation file contains security-relevant content.
fn is_security_relevant_doc(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("footgun")
        || lower.contains("security")
        || lower.contains("constraint")
        || lower.contains("account")
        || lower.contains("authority")
        || lower.contains("signer")
        || lower.contains("owner")
        || lower.contains("seeds")
        || lower.contains("pda")
        || lower.contains("cpi")
        || lower.contains("token")
        || lower.contains("access")
        || lower.contains("feature")
}

/// Parse Anchor framework documentation into NormalizedKnowledge.
fn parse_anchor_doc(filename: &str, content: &str) -> Option<NormalizedKnowledge> {
    let title = extract_title(content);
    let security_invariants = extract_security_invariants(content);
    let knowledge_id = compute_id("anchor-docs", filename, &title);

    let findings: Vec<NormalizedFinding> = security_invariants
        .iter()
        .enumerate()
        .map(|(i, invariant)| NormalizedFinding {
            finding_id: format!("{}-{}", knowledge_id, i),
            original_finding_id: format!("anchor-doc-{}", i),
            report_id: format!("anchor-docs:{}", filename),
            protocol_name: "Anchor Framework".into(),
            protocol_category: ProtocolCategory::Unknown,
            protocol_domain: ProtocolDomain::Generic,
            protocol_pattern: Some(invariant.pattern.clone()),
            vulnerability_class: VulnerabilityClass::Other("security_guideline".into()),
            attack_goal: invariant.attack_vector.clone(),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: invariant.kind.clone(),
                description: invariant.description.clone(),
                affected_state_vars: vec![],
            },
            attack_technique: AttackTechnique::Other("anchor_guideline".into()),
            mitigation_pattern: Some(MitigationPattern {
                technique: invariant.mitigation.clone(),
                description: invariant.description.clone(),
                is_standard: true,
            }),
            security_assumptions: vec![],
            severity: digger_ir::Severity::Medium,
            root_cause: StructuralRootCause::Other("anchor_documented_pattern".into()),
            impact_text: invariant.attack_vector.clone(),
            description_text: invariant.description.clone(),
            remediation_text: invariant.mitigation.clone(),
            impacted_contracts: vec![],
            impacted_functions: vec![],
            confidence: 0.9,
        })
        .collect();

    let mut raw_sections = std::collections::BTreeMap::new();
    raw_sections.insert("title".into(), title.clone());
    raw_sections.insert("source_file".into(), filename.to_string());
    if !content.is_empty() {
        let truncated: String = content.chars().take(5000).collect();
        raw_sections.insert("content".into(), truncated);
    }

    Some(NormalizedKnowledge {
        knowledge_id: knowledge_id.clone(),
        source_id: "anchor-docs".into(),
        source_kind: KnowledgeSourceKind::ProtocolDocumentation,
        source_identifier: format!("anchor-docs:{}", filename),
        subject: "Anchor Framework".into(),
        subject_category: "Solana".into(),
        findings,
        evidence: vec![],
        invariants: security_invariants
            .iter()
            .enumerate()
            .map(|(i, inv)| SecurityInvariant {
                invariant_id: format!("{}-{}", knowledge_id, i),
                description: inv.description.clone(),
                kind: inv.kind.clone(),
                properties: vec![],
                is_violated: false,
                context: "Anchor framework documentation".into(),
            })
            .collect(),
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![],
        claims: vec![],
        raw_sections,
    })
}

/// Parse SPL Token documentation into NormalizedKnowledge.
fn parse_spl_doc(filename: &str, content: &str, program: &str) -> Option<NormalizedKnowledge> {
    let title = extract_title(content);
    if title.is_empty() || title.len() < 5 {
        return None;
    }

    let knowledge_id = compute_id(&format!("spl-{}", program), filename, &title);
    let security_invariants = extract_security_invariants(content);

    let findings: Vec<NormalizedFinding> = security_invariants
        .iter()
        .enumerate()
        .map(|(i, invariant)| NormalizedFinding {
            finding_id: format!("{}-{}", knowledge_id, i),
            original_finding_id: format!("spl-doc-{}", i),
            report_id: format!("spl-docs:{}", filename),
            protocol_name: format!("SPL {}", program),
            protocol_category: ProtocolCategory::Unknown,
            protocol_domain: ProtocolDomain::Generic,
            protocol_pattern: Some(invariant.pattern.clone()),
            vulnerability_class: VulnerabilityClass::Other("security_guideline".into()),
            attack_goal: invariant.attack_vector.clone(),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: invariant.kind.clone(),
                description: invariant.description.clone(),
                affected_state_vars: vec![],
            },
            attack_technique: AttackTechnique::Other("spl_guideline".into()),
            mitigation_pattern: Some(MitigationPattern {
                technique: invariant.mitigation.clone(),
                description: invariant.description.clone(),
                is_standard: true,
            }),
            security_assumptions: vec![],
            severity: digger_ir::Severity::Medium,
            root_cause: StructuralRootCause::Other("spl_documented_pattern".into()),
            impact_text: invariant.attack_vector.clone(),
            description_text: invariant.description.clone(),
            remediation_text: invariant.mitigation.clone(),
            impacted_contracts: vec![],
            impacted_functions: vec![],
            confidence: 0.9,
        })
        .collect();

    let mut raw_sections = std::collections::BTreeMap::new();
    raw_sections.insert("title".into(), title);
    raw_sections.insert("source_file".into(), filename.to_string());

    Some(NormalizedKnowledge {
        knowledge_id: knowledge_id.clone(),
        source_id: format!("spl-{}-docs", program),
        source_kind: KnowledgeSourceKind::ProtocolDocumentation,
        source_identifier: format!("spl-{}-docs:{}", program, filename),
        subject: format!("SPL {}", program),
        subject_category: "Solana".into(),
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

/// Security invariant extracted from documentation.
struct SecurityInvariantExtract {
    kind: String,
    description: String,
    pattern: String,
    attack_vector: String,
    mitigation: String,
}

/// Extract security invariants from documentation text.
fn extract_security_invariants(content: &str) -> Vec<SecurityInvariantExtract> {
    let mut invariants = Vec::new();
    let lower = content.to_lowercase();

    // Anchor constraint patterns
    if lower.contains("has_one") || lower.contains("constraint") {
        invariants.push(SecurityInvariantExtract {
            kind: "authority_enforcement".into(),
            description: "Account constraints (has_one, seeds, signer) must be properly configured to prevent unauthorized access".into(),
            pattern: "account_constraint".into(),
            attack_vector: "Bypass account validation to access unauthorized accounts".into(),
            mitigation: "Use #[account(has_one = authority)] and #[account(seeds = [...], bump)] constraints".into(),
        });
    }

    if lower.contains("seeds") && lower.contains("pda") {
        invariants.push(SecurityInvariantExtract {
            kind: "pda_derivation".into(),
            description: "PDA derivation must use deterministic seeds and canonical bump values"
                .into(),
            pattern: "pda_seeds".into(),
            attack_vector: "PDA collision or spoofing through seed manipulation".into(),
            mitigation: "Always use canonical bump seeds and verify PDA derivation on-chain".into(),
        });
    }

    if lower.contains("signer") || lower.contains("is_signer") {
        invariants.push(SecurityInvariantExtract {
            kind: "signer_validation".into(),
            description: "Critical operations must verify the transaction signer matches expected authority".into(),
            pattern: "signer_check".into(),
            attack_vector: "Execute privileged operations without proper authorization".into(),
            mitigation: "Verify signer matches expected authority using has_one constraint or explicit check".into(),
        });
    }

    if lower.contains("rent") || lower.contains("lamport") {
        invariants.push(SecurityInvariantExtract {
            kind: "rent_exemption".into(),
            description: "Accounts must maintain rent-exempt minimum balance to persist on-chain"
                .into(),
            pattern: "rent_exemption".into(),
            attack_vector: "Account garbage collection through insufficient rent".into(),
            mitigation: "Ensure accounts are funded to at least rent-exempt minimum".into(),
        });
    }

    if lower.contains("close") || lower.contains("close_account") {
        invariants.push(SecurityInvariantExtract {
            kind: "account_closure".into(),
            description: "Account closure must transfer lamports to a designated recipient and zero the account".into(),
            pattern: "close_account".into(),
            attack_vector: "Reopen closed accounts or drain lamports without proper closure".into(),
            mitigation: "Use close constraint with proper destination account".into(),
        });
    }

    if lower.contains("reentrancy")
        || lower.contains("reentrant")
        || lower.contains("cross-program invocation")
    {
        invariants.push(SecurityInvariantExtract {
            kind: "cpi_reentrancy".into(),
            description: "Cross-program invocations must guard against reentrancy attacks".into(),
            pattern: "cpi_guard".into(),
            attack_vector: "Re-enter program during CPI to manipulate state".into(),
            mitigation: "Use reentrancy guards or state flags to prevent re-entry during CPI"
                .into(),
        });
    }

    if lower.contains("close") && lower.contains("reassign") {
        invariants.push(SecurityInvariantExtract {
            kind: "close_reassign".into(),
            description:
                "Closing an account should reassign ownership to System Program to prevent reuse"
                    .into(),
            pattern: "close_reassign".into(),
            attack_vector: "Reuse a closed account that hasn't been properly reassigned".into(),
            mitigation: "Reassign account owner to system program after closure".into(),
        });
    }

    // Token-2022 specific
    if lower.contains("transfer hook") || lower.contains("transfer-hook") {
        invariants.push(SecurityInvariantExtract {
            kind: "transfer_hook".into(),
            description: "Transfer hooks execute additional logic on every token transfer".into(),
            pattern: "transfer_hook".into(),
            attack_vector: "Bypass transfer hook by directly manipulating token accounts".into(),
            mitigation: "Validate transfer hook execution in program logic".into(),
        });
    }

    if lower.contains("mint close authority") || lower.contains("mint-close-authority") {
        invariants.push(SecurityInvariantExtract {
            kind: "mint_close_authority".into(),
            description: "Mint close authority extension allows closing token mints".into(),
            pattern: "mint_close_authority".into(),
            attack_vector: "Unauthorized mint closure could disrupt token supply".into(),
            mitigation: "Restrict mint close authority to authorized parties only".into(),
        });
    }

    // Footgun patterns (common mistakes)
    if lower.contains("integer overflow") || lower.contains("overflow") {
        invariants.push(SecurityInvariantExtract {
            kind: "overflow_protection".into(),
            description:
                "Arithmetic operations must use checked or saturating math to prevent overflow"
                    .into(),
            pattern: "checked_math".into(),
            attack_vector: "Integer overflow to mint excess tokens or bypass limits".into(),
            mitigation: "Use checked_add, checked_sub, checked_mul, saturating_add".into(),
        });
    }

    invariants
}

fn extract_title(content: &str) -> String {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# ") || trimmed.starts_with("title:") {
            return trimmed
                .trim_start_matches("# ")
                .trim_start_matches("title:")
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
        }
    }
    "Unknown".into()
}

fn compute_id(source: &str, filename: &str, title: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    hasher.update(filename.as_bytes());
    hasher.update(title.as_bytes());
    format!("solana-doc-{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_relevant_detection() {
        assert!(is_security_relevant_doc("account-validation.md"));
        assert!(is_security_relevant_doc("security-footguns.mdx"));
        assert!(is_security_relevant_doc("pda-constraints.md"));
        assert!(!is_security_relevant_doc("setup.md"));
    }

    #[test]
    fn test_constraint_extraction() {
        let content = "Use has_one constraint to verify account ownership. Seeds and bump are required for PDA derivation.";
        let invariants = extract_security_invariants(content);
        assert!(invariants.len() >= 2);
        assert!(invariants.iter().any(|i| i.kind == "authority_enforcement"));
        assert!(invariants.iter().any(|i| i.kind == "pda_derivation"));
    }

    #[test]
    fn test_footgun_extraction() {
        let content = "Integer overflow can occur in unchecked arithmetic. Use checked_add to prevent overflow.";
        let invariants = extract_security_invariants(content);
        assert!(invariants.iter().any(|i| i.kind == "overflow_protection"));
    }

    #[test]
    fn test_id_deterministic() {
        let id1 = compute_id("anchor", "account-validation.md", "Account Validation");
        let id2 = compute_id("anchor", "account-validation.md", "Account Validation");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_parse_anchor_doc_valid_fixture() {
        let content = "# Account Validation\n\nUse has_one constraint to verify account ownership.\nSeeds and bump are required for PDA derivation.\n";
        let result = parse_anchor_doc("account-validation.md", content);
        assert!(result.is_some());
        let k = result.expect("should parse");
        assert_eq!(k.source_id, "anchor-docs");
        assert!(!k.findings.is_empty());
    }

    #[test]
    fn test_parse_anchor_doc_adversarial_empty() {
        let result = parse_anchor_doc("empty.md", "");
        assert!(
            result.is_some(),
            "empty content should still produce a result with Unknown title"
        );
    }

    #[test]
    fn test_parse_anchor_doc_adversarial_garbage() {
        let result = parse_anchor_doc("garbage.md", "not documentation at all");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_spl_doc_valid_fixture() {
        let content = "# SPL Token Transfer Hooks\n\nTransfer hooks execute additional logic on every token transfer.\n";
        let result = parse_spl_doc("transfer-hooks.md", content, "token-2022");
        assert!(result.is_some());
        let k = result.expect("should parse");
        assert_eq!(k.source_id, "spl-token-2022-docs");
        assert!(!k.findings.is_empty());
    }

    #[test]
    fn test_parse_spl_doc_adversarial_empty_title() {
        let content = "# A\n\nVery short";
        let result = parse_spl_doc("short.md", content, "token-2022");
        assert!(
            result.is_none(),
            "should return None for docs with title shorter than 5 chars"
        );
    }

    #[test]
    fn test_parse_spl_doc_adversarial_garbage() {
        let content = "# X\n\nY";
        let result = parse_spl_doc("garbage.md", content, "token-2022");
        assert!(result.is_none(), "should return None for very short title");
    }

    #[test]
    fn test_security_relevant_detection_adversarial() {
        assert!(!is_security_relevant_doc(""));
        assert!(!is_security_relevant_doc("random_file.xyz"));
    }
}
