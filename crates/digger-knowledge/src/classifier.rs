/// Classifier — additional classification beyond normalization.
use digger_knowledge_models::*;

/// Classify protocol category from normalized findings.
pub fn classify_from_findings(findings: &[NormalizedFinding]) -> ProtocolCategory {
    let mut category_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();

    for finding in findings {
        for contract in &finding.impacted_contracts {
            let lower = contract.to_lowercase();
            if lower.contains("lend") || lower.contains("borrow") || lower.contains("collateral") {
                *category_counts.entry("lending".into()).or_insert(0) += 1;
            }
            if lower.contains("swap") || lower.contains("pool") || lower.contains("amm") {
                *category_counts.entry("dex".into()).or_insert(0) += 1;
            }
            if lower.contains("vault") || lower.contains("strategy") {
                *category_counts.entry("vault".into()).or_insert(0) += 1;
            }
            if lower.contains("bridge") {
                *category_counts.entry("bridge".into()).or_insert(0) += 1;
            }
            if lower.contains("governance") || lower.contains("vote") {
                *category_counts.entry("governance".into()).or_insert(0) += 1;
            }
        }
    }

    category_counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(cat, _)| match cat.as_str() {
            "lending" => ProtocolCategory::Lending,
            "dex" => ProtocolCategory::DEX,
            "vault" => ProtocolCategory::Vault,
            "bridge" => ProtocolCategory::Bridge,
            "governance" => ProtocolCategory::Governance,
            _ => ProtocolCategory::Unknown,
        })
        .unwrap_or(ProtocolCategory::Unknown)
}

/// Detect semantic equivalence between two findings.
///
/// Two findings are semantically equivalent if they share 4/5 of:
/// 1. Same VulnerabilityClass
/// 2. Same AttackGoal
/// 3. Same StructuralRootCause
/// 4. Same ViolatedInvariant kind
/// 5. Same AttackTechnique
pub fn are_semantically_equivalent(a: &NormalizedFinding, b: &NormalizedFinding) -> bool {
    let mut matches = 0;

    if a.vulnerability_class == b.vulnerability_class {
        matches += 1;
    }
    if a.attack_goal == b.attack_goal {
        matches += 1;
    }
    if a.root_cause == b.root_cause {
        matches += 1;
    }
    if a.violated_invariant.kind == b.violated_invariant.kind {
        matches += 1;
    }
    if a.attack_technique == b.attack_technique {
        matches += 1;
    }

    matches >= 4
}

/// Find all semantically equivalent finding pairs.
pub fn find_equivalents(findings: &[NormalizedFinding]) -> Vec<(String, String)> {
    let mut pairs = Vec::new();

    for i in 0..findings.len() {
        for j in (i + 1)..findings.len() {
            if are_semantically_equivalent(&findings[i], &findings[j]) {
                pairs.push((
                    findings[i].finding_id.clone(),
                    findings[j].finding_id.clone(),
                ));
            }
        }
    }

    pairs
}
