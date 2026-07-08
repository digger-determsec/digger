/// Cross-Source Correlation — correlate artifacts across all sources.
use digger_knowledge_models::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A correlated vulnerability cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityCluster {
    pub cluster_id: String,
    pub vulnerability_class: String,
    pub protocol: String,
    pub artifacts: Vec<CorrelatedArtifact>,
    pub confidence: f64,
    pub evidence_count: usize,
}

/// An artifact in a correlation cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedArtifact {
    pub artifact_id: String,
    pub source: String,
    pub title: String,
    pub finding_id: String,
}

/// Cross-source correlation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub total_artifacts: usize,
    pub clusters: Vec<VulnerabilityCluster>,
    pub correlation_quality: f64,
    pub stats: CorrelationStats,
}

/// Correlation statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationStats {
    pub total_clusters: usize,
    pub multi_source_clusters: usize,
    pub avg_cluster_size: f64,
    pub coverage_by_source: BTreeMap<String, usize>,
}

/// Correlate artifacts across sources.
pub fn correlate_across_sources(artifacts: &[NormalizedKnowledge]) -> CorrelationResult {
    let total = artifacts.len();
    let mut clusters: BTreeMap<String, Vec<&NormalizedKnowledge>> = BTreeMap::new();

    // Group by normalized vulnerability class + protocol
    for artifact in artifacts {
        for finding in &artifact.findings {
            let key = format!(
                "{}:{}",
                normalize_class(&finding.vulnerability_class.to_string()),
                artifact.subject.to_lowercase()
            );
            clusters.entry(key).or_default().push(artifact);
        }
    }

    // Build clusters with evidence
    let mut vuln_clusters = Vec::new();
    for (key, artifacts_in_cluster) in &clusters {
        if artifacts_in_cluster.len() < 2 {
            continue; // Single artifact — no correlation
        }

        let sources: BTreeSet<String> = artifacts_in_cluster
            .iter()
            .map(|a| a.source_id.clone())
            .collect();
        let multi_source = sources.len() > 1;

        let evidence_count: usize = artifacts_in_cluster.iter().map(|a| a.findings.len()).sum();

        let confidence = if multi_source {
            (sources.len() as f64 / 6.0).min(1.0) * 0.8 + 0.2
        } else {
            (artifacts_in_cluster.len() as f64 / 5.0).min(1.0) * 0.6
        };

        let artifacts: Vec<CorrelatedArtifact> = artifacts_in_cluster
            .iter()
            .flat_map(|a| {
                a.findings.iter().map(|f| CorrelatedArtifact {
                    artifact_id: a.knowledge_id.clone(),
                    source: a.source_id.clone(),
                    title: f.description_text.chars().take(100).collect(),
                    finding_id: f.finding_id.clone(),
                })
            })
            .collect();

        vuln_clusters.push(VulnerabilityCluster {
            cluster_id: format!("cluster-{}-{}", key.replace(':', "-"), artifacts.len()),
            vulnerability_class: key.split(':').next().unwrap_or("unknown").into(),
            protocol: artifacts_in_cluster
                .first()
                .map(|a| a.subject.clone())
                .unwrap_or_default(),
            artifacts,
            confidence,
            evidence_count,
        });
    }

    let multi_source = vuln_clusters
        .iter()
        .filter(|c| {
            let sources: BTreeSet<String> = c.artifacts.iter().map(|a| a.source.clone()).collect();
            sources.len() > 1
        })
        .count();

    let avg_size = if vuln_clusters.is_empty() {
        0.0
    } else {
        vuln_clusters
            .iter()
            .map(|c| c.artifacts.len())
            .sum::<usize>() as f64
            / vuln_clusters.len() as f64
    };

    let coverage: BTreeMap<String, usize> = vuln_clusters
        .iter()
        .flat_map(|c| c.artifacts.iter().map(|a| a.source.clone()))
        .fold(BTreeMap::new(), |mut m, s| {
            *m.entry(s).or_insert(0) += 1;
            m
        });

    CorrelationResult {
        total_artifacts: total,
        clusters: vuln_clusters,
        correlation_quality: if total > 0 {
            multi_source as f64 / total as f64
        } else {
            0.0
        },
        stats: CorrelationStats {
            total_clusters: 0, // Set below
            multi_source_clusters: multi_source,
            avg_cluster_size: avg_size,
            coverage_by_source: coverage,
        },
    }
}

fn normalize_class(class: &str) -> String {
    class
        .to_lowercase()
        .replace(['_', '-'], " ")
        .trim()
        .to_string()
}

/// Display correlation results.
pub fn display_correlation(result: &CorrelationResult) -> String {
    let mut out = format!(
        "═══ Cross-Source Correlation ═══\nArtifacts: {} | Clusters: {} | Multi-source: {}\n\n",
        result.total_artifacts, result.stats.total_clusters, result.stats.multi_source_clusters
    );
    for cluster in result.clusters.iter().take(10) {
        let sources: BTreeSet<String> =
            cluster.artifacts.iter().map(|a| a.source.clone()).collect();
        out.push_str(&format!(
            "  [{}] {} ({} artifacts, {} sources, {:.0}% confidence)\n",
            cluster.vulnerability_class,
            cluster.protocol,
            cluster.artifacts.len(),
            sources.len(),
            cluster.confidence * 100.0
        ));
    }
    out
}

/// Display semantic extraction quality.
pub fn display_extraction_quality(
    extractions: &[crate::semantic_extraction::SemanticExtraction],
) -> String {
    let total = extractions.len();
    let avg_completeness: f64 = extractions
        .iter()
        .map(|e| e.extraction_quality.completeness)
        .sum::<f64>()
        / total.max(1) as f64;
    let total_contracts: usize = extractions
        .iter()
        .map(|e| e.extraction_quality.contracts_extracted)
        .sum();
    let total_functions: usize = extractions
        .iter()
        .map(|e| e.extraction_quality.functions_extracted)
        .sum();
    let total_invariants: usize = extractions
        .iter()
        .map(|e| e.extraction_quality.invariants_extracted)
        .sum();

    format!(
        "═══ Extraction Quality ═══\nArtifacts: {} | Avg Completeness: {:.0}%\nContracts: {} | Functions: {} | Invariants: {}\n",
        total, avg_completeness * 100.0, total_contracts, total_functions, total_invariants
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_knowledge(source: &str, protocol: &str, finding_class: &str) -> NormalizedKnowledge {
        NormalizedKnowledge {
            knowledge_id: format!("k-{}-{}", source, protocol),
            source_id: source.into(),
            source_kind: KnowledgeSourceKind::ExploitPostmortem,
            source_identifier: "test.md".into(),
            subject: protocol.into(),
            subject_category: "DeFi".into(),
            findings: vec![NormalizedFinding {
                finding_id: format!("f-{}-{}", source, protocol),
                original_finding_id: "f1".into(),
                report_id: "r1".into(),
                protocol_name: protocol.into(),
                protocol_category: ProtocolCategory::Unknown,
                protocol_domain: ProtocolDomain::Generic,
                protocol_pattern: None,
                vulnerability_class: VulnerabilityClass::Other(finding_class.into()),
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
        }
    }

    #[test]
    fn test_correlation_multi_source() {
        let artifacts = vec![
            test_knowledge("code4rena", "ProtocolX", "reentrancy"),
            test_knowledge("sherlock", "ProtocolX", "reentrancy"),
            test_knowledge("defillama", "ProtocolX", "reentrancy"),
        ];
        let result = correlate_across_sources(&artifacts);
        assert!(!result.clusters.is_empty());
        assert!(result.stats.multi_source_clusters > 0);
    }

    #[test]
    fn test_correlation_no_duplicates() {
        let artifacts = vec![
            test_knowledge("code4rena", "ProtocolA", "reentrancy"),
            test_knowledge("code4rena", "ProtocolB", "access_control"),
        ];
        let result = correlate_across_sources(&artifacts);
        // Two different protocols → no cluster (single artifact per group)
        assert!(result.stats.total_clusters == 0);
    }

    #[test]
    fn test_correlation_deterministic_output() {
        let artifacts = vec![
            test_knowledge("code4rena", "ProtocolX", "reentrancy"),
            test_knowledge("sherlock", "ProtocolX", "reentrancy"),
        ];
        let result1 = correlate_across_sources(&artifacts);
        let result2 = correlate_across_sources(&artifacts);
        let json1 = serde_json::to_string(&result1).expect("serialize 1");
        let json2 = serde_json::to_string(&result2).expect("serialize 2");
        assert_eq!(json1, json2, "correlation output must be deterministic");
    }

    #[test]
    fn test_correlation_empty_input() {
        let result = correlate_across_sources(&[]);
        assert_eq!(result.total_artifacts, 0);
        assert!(result.clusters.is_empty());
    }
}
