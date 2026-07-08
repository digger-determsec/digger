/// Semantic Extraction Deepening — extract structured semantic data from artifacts.
use digger_knowledge_models::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Comprehensive semantic extraction result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticExtraction {
    pub artifact_id: String,
    pub source_id: String,
    pub affected_contracts: Vec<String>,
    pub affected_functions: Vec<String>,
    pub affected_state_vars: Vec<String>,
    pub privileged_actors: Vec<PrivilegedActor>,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub invariants: Vec<ExtractedInvariant>,
    pub attack_prerequisites: Vec<String>,
    pub attack_sequence: Vec<AttackSequenceStep>,
    pub economic_assumptions: Vec<String>,
    pub protocol_assumptions: Vec<String>,
    pub exploit_capabilities: Vec<String>,
    pub mitigation_strategies: Vec<MitigationStrategy>,
    pub patch_descriptions: Vec<String>,
    pub extraction_quality: ExtractionQuality,
}

/// A privileged actor extracted from documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegedActor {
    pub role: String,
    pub permissions: Vec<String>,
    pub functions: Vec<String>,
    pub description: String,
}

/// A trust boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundary {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub validation_required: bool,
    pub description: String,
}

/// An extracted invariant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedInvariant {
    pub invariant_id: String,
    pub description: String,
    pub kind: String,
    pub affected_state: Vec<String>,
    pub enforcement_mechanism: String,
}

/// A step in an extracted attack sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSequenceStep {
    pub step_index: usize,
    pub function: String,
    pub action: String,
    pub required_capability: String,
    pub evidence: Vec<String>,
}

/// A mitigation strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationStrategy {
    pub strategy: String,
    pub effectiveness: String,
    pub standard: bool,
    pub references: Vec<String>,
}

/// Extraction quality metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionQuality {
    pub completeness: f64,
    pub contracts_extracted: usize,
    pub functions_extracted: usize,
    pub state_vars_extracted: usize,
    pub invariants_extracted: usize,
    pub assumptions_extracted: usize,
}

/// Extract semantic data from a NormalizedKnowledge artifact.
pub fn extract_semantics(knowledge: &NormalizedKnowledge) -> SemanticExtraction {
    let mut affected_contracts = Vec::new();
    let mut affected_functions = Vec::new();
    let mut affected_state_vars = Vec::new();

    for finding in &knowledge.findings {
        for contract in &finding.impacted_contracts {
            if !affected_contracts.contains(contract) {
                affected_contracts.push(contract.clone());
            }
        }
        for func in &finding.impacted_functions {
            if !affected_functions.contains(func) {
                affected_functions.push(func.clone());
            }
        }
        for var in &finding.violated_invariant.affected_state_vars {
            if !affected_state_vars.contains(var) {
                affected_state_vars.push(var.clone());
            }
        }
    }

    // Extract invariants from knowledge
    let invariants: Vec<ExtractedInvariant> = knowledge
        .invariants
        .iter()
        .map(|inv| ExtractedInvariant {
            invariant_id: inv.invariant_id.clone(),
            description: inv.description.clone(),
            kind: inv.kind.clone(),
            affected_state: inv.properties.clone(),
            enforcement_mechanism: inv.context.clone(),
        })
        .collect();

    // Extract mitigation strategies
    let mitigation_strategies: Vec<MitigationStrategy> = knowledge
        .mitigation_patterns
        .iter()
        .map(|m| MitigationStrategy {
            strategy: m.technique.clone(),
            effectiveness: m.description.clone(),
            standard: m.is_standard,
            references: vec![],
        })
        .collect();

    // Extract from raw sections
    let mut attack_prerequisites = Vec::new();
    let mut protocol_assumptions = Vec::new();
    let mut economic_assumptions = Vec::new();
    let mut patch_descriptions = Vec::new();
    let mut attack_sequence = Vec::new();

    for (section, content) in &knowledge.raw_sections {
        let lower = section.to_lowercase();
        if lower.contains("prerequisite") || lower.contains("requirement") {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && trimmed.len() > 5 {
                    attack_prerequisites.push(trimmed.to_string());
                }
            }
        }
        if lower.contains("assumption") {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && trimmed.len() > 10 {
                    protocol_assumptions.push(trimmed.to_string());
                }
            }
        }
        if lower.contains("economic") || lower.contains("invariant") {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && trimmed.len() > 10 {
                    economic_assumptions.push(trimmed.to_string());
                }
            }
        }
        if lower.contains("patch") || lower.contains("fix") || lower.contains("mitigation") {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && trimmed.len() > 10 {
                    patch_descriptions.push(trimmed.to_string());
                }
            }
        }
        if lower.contains("attack") || lower.contains("exploit") || lower.contains("step") {
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && trimmed.len() > 10 {
                    attack_sequence.push(AttackSequenceStep {
                        step_index: i,
                        function: extract_function_from_text(trimmed),
                        action: trimmed.to_string(),
                        required_capability: "unknown".into(),
                        evidence: vec![],
                    });
                }
            }
        }
    }

    let total_expected = affected_contracts.len()
        + affected_functions.len()
        + affected_state_vars.len()
        + invariants.len()
        + mitigation_strategies.len()
        + attack_prerequisites.len();

    let quality = ExtractionQuality {
        completeness: if total_expected > 0 { 1.0 } else { 0.5 },
        contracts_extracted: affected_contracts.len(),
        functions_extracted: affected_functions.len(),
        state_vars_extracted: affected_state_vars.len(),
        invariants_extracted: invariants.len(),
        assumptions_extracted: protocol_assumptions.len() + economic_assumptions.len(),
    };

    SemanticExtraction {
        artifact_id: knowledge.knowledge_id.clone(),
        source_id: knowledge.source_id.clone(),
        affected_contracts,
        affected_functions,
        affected_state_vars,
        privileged_actors: vec![],
        trust_boundaries: vec![],
        invariants,
        attack_prerequisites,
        attack_sequence,
        economic_assumptions,
        protocol_assumptions,
        exploit_capabilities: vec![],
        mitigation_strategies,
        patch_descriptions,
        extraction_quality: quality,
    }
}

fn extract_function_from_text(text: &str) -> String {
    if let Some(pos) = text.find("()") {
        let before = &text[..pos];
        if let Some(name_pos) = before.rfind(' ') {
            return before[name_pos + 1..].to_string();
        }
    }
    "unknown".into()
}

/// Deterministic deduplication across sources.
pub fn deduplicate_cross_source(artifacts: &mut Vec<NormalizedKnowledge>) -> DeduplicationResult {
    let initial_count = artifacts.len();
    let mut seen_hashes: BTreeSet<String> = BTreeSet::new();
    let mut duplicates = Vec::new();

    // First pass: exact hash dedup
    let mut to_remove = Vec::new();
    for (i, artifact) in artifacts.iter().enumerate() {
        let content_hash = compute_artifact_hash(artifact);
        if !seen_hashes.insert(content_hash.clone()) {
            duplicates.push(DuplicateRecord {
                artifact_id: artifact.knowledge_id.clone(),
                duplicate_of: find_duplicate_by_hash(&seen_hashes, &content_hash, artifacts),
                duplicate_type: DuplicateType::Identical,
                confidence: 1.0,
                evidence: format!("Same content hash: {}", content_hash),
            });
            to_remove.push(i);
        }
    }

    // Remove duplicates (in reverse order to preserve indices)
    for i in to_remove.into_iter().rev() {
        artifacts.remove(i);
    }

    // Second pass: same root cause dedup
    let mut root_cause_groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, artifact) in artifacts.iter().enumerate() {
        for finding in &artifact.findings {
            let root_cause = normalize_root_cause(&finding.vulnerability_class.to_string());
            root_cause_groups.entry(root_cause).or_default().push(i);
        }
    }

    // Identify duplicates within root cause groups
    let mut potential_rc_duplicates = Vec::new();
    for indices in root_cause_groups.values() {
        if indices.len() > 1 {
            // Check if artifacts share the same protocol
            let protocols: Vec<String> = indices
                .iter()
                .filter_map(|i| artifacts.get(*i).map(|a| a.subject.clone()))
                .collect();
            let unique_protocols: BTreeSet<String> = protocols.iter().cloned().collect();
            if unique_protocols.len() == 1 && indices.len() > 1 {
                // Same root cause AND same protocol — likely duplicate
                for i in indices.iter().skip(1) {
                    potential_rc_duplicates.push(DuplicateRecord {
                        artifact_id: artifacts[*i].knowledge_id.clone(),
                        duplicate_of: artifacts[indices[0]].knowledge_id.clone(),
                        duplicate_type: DuplicateType::SameRootCause,
                        confidence: 0.7,
                        evidence: "Same root cause and protocol".to_string(),
                    });
                }
            }
        }
    }

    let total_duplicates = duplicates.len() + potential_rc_duplicates.len();

    DeduplicationResult {
        initial_count,
        final_count: artifacts.len(),
        duplicates_removed: total_duplicates,
        identical_duplicates: duplicates.len(),
        root_cause_duplicates: potential_rc_duplicates.len(),
        all_duplicates: duplicates
            .into_iter()
            .chain(potential_rc_duplicates)
            .collect(),
    }
}

/// Compute deterministic hash for an artifact.
pub fn compute_artifact_hash(artifact: &NormalizedKnowledge) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(artifact.knowledge_id.as_bytes());
    for finding in &artifact.findings {
        hasher.update(finding.finding_id.as_bytes());
        hasher.update(finding.description_text.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn find_duplicate_by_hash(
    seen: &BTreeSet<String>,
    hash: &str,
    _artifacts: &[NormalizedKnowledge],
) -> String {
    // The first artifact with this hash is the "original"
    seen.iter()
        .find(|h| **h == hash)
        .cloned()
        .unwrap_or_default()
}

fn normalize_root_cause(class: &str) -> String {
    class
        .to_lowercase()
        .replace(['_', '-'], " ")
        .trim()
        .to_string()
}

/// Deduplication result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationResult {
    pub initial_count: usize,
    pub final_count: usize,
    pub duplicates_removed: usize,
    pub identical_duplicates: usize,
    pub root_cause_duplicates: usize,
    pub all_duplicates: Vec<DuplicateRecord>,
}

/// A duplicate record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateRecord {
    pub artifact_id: String,
    pub duplicate_of: String,
    pub duplicate_type: DuplicateType,
    pub confidence: f64,
    pub evidence: String,
}

/// Type of duplicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DuplicateType {
    Identical,
    Rewritten,
    SameRootCause,
    SameExploitFamily,
}

/// Display deduplication result.
pub fn display_dedup_result(result: &DeduplicationResult) -> String {
    format!(
        "═══ Deduplication Result ═══\nInitial: {} → Final: {} | Removed: {} ({} identical, {} same-root-cause)\n",
        result.initial_count, result.final_count, result.duplicates_removed,
        result.identical_duplicates, result.root_cause_duplicates
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_extraction() {
        let knowledge = NormalizedKnowledge {
            knowledge_id: "k1".into(),
            source_id: "test".into(),
            source_kind: KnowledgeSourceKind::ExploitPostmortem,
            source_identifier: "test.md".into(),
            subject: "Test".into(),
            subject_category: "DeFi".into(),
            findings: vec![NormalizedFinding {
                finding_id: "f1".into(),
                original_finding_id: "f1".into(),
                report_id: "r1".into(),
                protocol_name: "Test".into(),
                protocol_category: ProtocolCategory::Unknown,
                protocol_domain: ProtocolDomain::Generic,
                protocol_pattern: None,
                vulnerability_class: VulnerabilityClass::Reentrancy,
                attack_goal: "test".into(),
                capability_pattern: vec![],
                violated_invariant: ViolatedInvariant {
                    kind: "test".into(),
                    description: "test".into(),
                    affected_state_vars: vec!["balance".into()],
                },
                attack_technique: AttackTechnique::Other("test".into()),
                mitigation_pattern: None,
                security_assumptions: vec![],
                severity: digger_ir::Severity::High,
                root_cause: StructuralRootCause::Other("test".into()),
                impact_text: String::new(),
                description_text: "test".into(),
                remediation_text: String::new(),
                impacted_contracts: vec!["Vault".into()],
                impacted_functions: vec!["withdraw".into()],
                confidence: 1.0,
            }],
            evidence: vec![],
            invariants: vec![SecurityInvariant {
                invariant_id: "inv1".into(),
                description: "conservation".into(),
                kind: "economic".into(),
                properties: vec!["total".into()],
                is_violated: true,
                context: "test".into(),
            }],
            architectural_patterns: vec![],
            mitigation_patterns: vec![MitigationPattern {
                technique: "reentrancy guard".into(),
                description: "add guard".into(),
                is_standard: true,
            }],
            references: vec![],
            claims: vec![],
            raw_sections: {
                let mut m = std::collections::BTreeMap::new();
                m.insert("Prerequisites".into(), "Must have flash loan access".into());
                m.insert("Assumptions".into(), "Oracle price is manipulable".into());
                m
            },
        };

        let extraction = extract_semantics(&knowledge);
        assert_eq!(extraction.affected_contracts, vec!["Vault"]);
        assert_eq!(extraction.affected_functions, vec!["withdraw"]);
        assert_eq!(extraction.affected_state_vars, vec!["balance"]);
        assert_eq!(extraction.invariants.len(), 1);
        assert_eq!(extraction.mitigation_strategies.len(), 1);
        assert_eq!(extraction.attack_prerequisites.len(), 1);
        assert_eq!(extraction.protocol_assumptions.len(), 1);
    }

    #[test]
    fn test_dedup_identical() {
        let mut artifacts = vec![NormalizedKnowledge {
            knowledge_id: "k1".into(),
            source_id: "test".into(),
            source_kind: KnowledgeSourceKind::ExploitPostmortem,
            source_identifier: "test.md".into(),
            subject: "Test".into(),
            subject_category: "DeFi".into(),
            findings: vec![NormalizedFinding {
                finding_id: "f1".into(),
                original_finding_id: "f1".into(),
                report_id: "r1".into(),
                protocol_name: "Test".into(),
                protocol_category: ProtocolCategory::Unknown,
                protocol_domain: ProtocolDomain::Generic,
                protocol_pattern: None,
                vulnerability_class: VulnerabilityClass::Reentrancy,
                attack_goal: "test".into(),
                capability_pattern: vec![],
                violated_invariant: ViolatedInvariant {
                    kind: "t".into(),
                    description: "t".into(),
                    affected_state_vars: vec![],
                },
                attack_technique: AttackTechnique::Other("t".into()),
                mitigation_pattern: None,
                security_assumptions: vec![],
                severity: digger_ir::Severity::Medium,
                root_cause: StructuralRootCause::Other("t".into()),
                impact_text: String::new(),
                description_text: "test content".into(),
                remediation_text: String::new(),
                impacted_contracts: vec![],
                impacted_functions: vec![],
                confidence: 1.0,
            }],
            evidence: vec![],
            invariants: vec![],
            architectural_patterns: vec![],
            mitigation_patterns: vec![],
            references: vec![],
            claims: vec![],
            raw_sections: std::collections::BTreeMap::new(),
        }];
        // Add exact duplicate
        artifacts.push(artifacts[0].clone());

        let result = deduplicate_cross_source(&mut artifacts);
        assert_eq!(result.initial_count, 2);
        assert_eq!(result.final_count, 1);
        assert_eq!(result.duplicates_removed, 1);
    }

    #[test]
    fn test_dedup_no_duplicates() {
        let mut artifacts = vec![NormalizedKnowledge {
            knowledge_id: "k1".into(),
            source_id: "test".into(),
            source_kind: KnowledgeSourceKind::ExploitPostmortem,
            source_identifier: "test.md".into(),
            subject: "Test".into(),
            subject_category: "DeFi".into(),
            findings: vec![NormalizedFinding {
                finding_id: "f1".into(),
                original_finding_id: "f1".into(),
                report_id: "r1".into(),
                protocol_name: "Test".into(),
                protocol_category: ProtocolCategory::Unknown,
                protocol_domain: ProtocolDomain::Generic,
                protocol_pattern: None,
                vulnerability_class: VulnerabilityClass::Reentrancy,
                attack_goal: "t".into(),
                capability_pattern: vec![],
                violated_invariant: ViolatedInvariant {
                    kind: "t".into(),
                    description: "t".into(),
                    affected_state_vars: vec![],
                },
                attack_technique: AttackTechnique::Other("t".into()),
                mitigation_pattern: None,
                security_assumptions: vec![],
                severity: digger_ir::Severity::Medium,
                root_cause: StructuralRootCause::Other("t".into()),
                impact_text: String::new(),
                description_text: "content A".into(),
                remediation_text: String::new(),
                impacted_contracts: vec![],
                impacted_functions: vec![],
                confidence: 1.0,
            }],
            evidence: vec![],
            invariants: vec![],
            architectural_patterns: vec![],
            mitigation_patterns: vec![],
            references: vec![],
            claims: vec![],
            raw_sections: std::collections::BTreeMap::new(),
        }];
        artifacts.push({
            let mut a = artifacts[0].clone();
            a.knowledge_id = "k2".into();
            a.subject = "Other".into();
            a.findings[0].finding_id = "f2".into();
            a.findings[0].description_text = "content B".into();
            a.findings[0].root_cause = StructuralRootCause::Other("different".into());
            a
        });

        let result = deduplicate_cross_source(&mut artifacts);
        assert_eq!(result.initial_count, 2);
        assert_eq!(result.final_count, 2);
        assert_eq!(result.duplicates_removed, 0);
    }

    #[test]
    fn test_extraction_quality() {
        let knowledge = NormalizedKnowledge {
            knowledge_id: "k1".into(),
            source_id: "test".into(),
            source_kind: KnowledgeSourceKind::ExploitPostmortem,
            source_identifier: "test.md".into(),
            subject: "Test".into(),
            subject_category: "DeFi".into(),
            findings: vec![NormalizedFinding {
                finding_id: "f1".into(),
                original_finding_id: "f1".into(),
                report_id: "r1".into(),
                protocol_name: "Test".into(),
                protocol_category: ProtocolCategory::Unknown,
                protocol_domain: ProtocolDomain::Generic,
                protocol_pattern: None,
                vulnerability_class: VulnerabilityClass::Other("test".into()),
                attack_goal: "t".into(),
                capability_pattern: vec![],
                violated_invariant: ViolatedInvariant {
                    kind: "t".into(),
                    description: "t".into(),
                    affected_state_vars: vec![],
                },
                attack_technique: AttackTechnique::Other("t".into()),
                mitigation_pattern: None,
                security_assumptions: vec![],
                severity: digger_ir::Severity::Medium,
                root_cause: StructuralRootCause::Other("t".into()),
                impact_text: String::new(),
                description_text: "test".into(),
                remediation_text: String::new(),
                impacted_contracts: vec!["C1".into(), "C2".into()],
                impacted_functions: vec!["f1".into(), "f2".into(), "f3".into()],
                confidence: 1.0,
            }],
            evidence: vec![],
            invariants: vec![],
            architectural_patterns: vec![],
            mitigation_patterns: vec![],
            references: vec![],
            claims: vec![],
            raw_sections: std::collections::BTreeMap::new(),
        };

        let quality = extract_semantics(&knowledge).extraction_quality;
        assert_eq!(quality.contracts_extracted, 2);
        assert_eq!(quality.functions_extracted, 3);
    }

    #[test]
    fn test_semantic_extraction_deterministic() {
        let knowledge = NormalizedKnowledge {
            knowledge_id: "k1".into(),
            source_id: "test".into(),
            source_kind: KnowledgeSourceKind::ExploitPostmortem,
            source_identifier: "test.md".into(),
            subject: "Test".into(),
            subject_category: "DeFi".into(),
            findings: vec![NormalizedFinding {
                finding_id: "f1".into(),
                original_finding_id: "f1".into(),
                report_id: "r1".into(),
                protocol_name: "Test".into(),
                protocol_category: ProtocolCategory::Unknown,
                protocol_domain: ProtocolDomain::Generic,
                protocol_pattern: None,
                vulnerability_class: VulnerabilityClass::Reentrancy,
                attack_goal: "test".into(),
                capability_pattern: vec![],
                violated_invariant: ViolatedInvariant {
                    kind: "test".into(),
                    description: "test".into(),
                    affected_state_vars: vec!["balance".into()],
                },
                attack_technique: AttackTechnique::Other("test".into()),
                mitigation_pattern: None,
                security_assumptions: vec![],
                severity: digger_ir::Severity::High,
                root_cause: StructuralRootCause::Other("test".into()),
                impact_text: String::new(),
                description_text: "test".into(),
                remediation_text: String::new(),
                impacted_contracts: vec!["Vault".into()],
                impacted_functions: vec!["withdraw".into()],
                confidence: 1.0,
            }],
            evidence: vec![],
            invariants: vec![],
            architectural_patterns: vec![],
            mitigation_patterns: vec![],
            references: vec![],
            claims: vec![],
            raw_sections: std::collections::BTreeMap::new(),
        };
        let e1 = extract_semantics(&knowledge);
        let e2 = extract_semantics(&knowledge);
        let json1 = serde_json::to_string(&e1).expect("serialize 1");
        let json2 = serde_json::to_string(&e2).expect("serialize 2");
        assert_eq!(json1, json2, "semantic extraction must be deterministic");
    }

    #[test]
    fn test_dedup_adversarial_empty() {
        let mut artifacts = vec![];
        let result = deduplicate_cross_source(&mut artifacts);
        assert_eq!(result.initial_count, 0);
        assert_eq!(result.final_count, 0);
    }

    #[test]
    fn test_compute_artifact_hash_deterministic() {
        let k = NormalizedKnowledge {
            knowledge_id: "k1".into(),
            source_id: "test".into(),
            source_kind: KnowledgeSourceKind::AuditRepository,
            source_identifier: "test.md".into(),
            subject: "Test".into(),
            subject_category: "test".into(),
            findings: vec![NormalizedFinding {
                finding_id: "f1".into(),
                original_finding_id: "f1".into(),
                report_id: "r1".into(),
                protocol_name: "Test".into(),
                protocol_category: ProtocolCategory::Unknown,
                protocol_domain: ProtocolDomain::Generic,
                protocol_pattern: None,
                vulnerability_class: VulnerabilityClass::Reentrancy,
                attack_goal: "test".into(),
                capability_pattern: vec![],
                violated_invariant: ViolatedInvariant {
                    kind: "test".into(),
                    description: "test".into(),
                    affected_state_vars: vec![],
                },
                attack_technique: AttackTechnique::ReentrancyExploit,
                mitigation_pattern: None,
                security_assumptions: vec![],
                severity: digger_ir::Severity::High,
                root_cause: StructuralRootCause::SharedMutableState,
                impact_text: String::new(),
                description_text: "test".into(),
                remediation_text: String::new(),
                impacted_contracts: vec![],
                impacted_functions: vec![],
                confidence: 1.0,
            }],
            evidence: vec![],
            invariants: vec![],
            architectural_patterns: vec![],
            mitigation_patterns: vec![],
            references: vec![],
            claims: vec![],
            raw_sections: std::collections::BTreeMap::new(),
        };
        let h1 = compute_artifact_hash(&k);
        let h2 = compute_artifact_hash(&k);
        assert_eq!(h1, h2, "artifact hash must be deterministic");
    }
}
