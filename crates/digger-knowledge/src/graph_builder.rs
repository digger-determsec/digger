/// Graph builder — constructs the knowledge graph from normalized findings.
///
/// Supports incremental updates: caches the built graph and only rebuilds
/// when the corpus content hash changes.
use digger_knowledge_models::*;
use std::path::Path;

/// Cached graph with content hash for change detection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedGraph {
    /// Content hash of the findings used to build this graph.
    pub content_hash: String,
    /// The built knowledge graph.
    pub graph: KnowledgeGraph,
    /// Number of findings in the graph.
    pub finding_count: usize,
    /// Number of nodes.
    pub node_count: usize,
    /// Number of edges.
    pub edge_count: usize,
}

/// Compute a deterministic content hash of findings for graph caching.
pub fn compute_findings_hash(findings: &[NormalizedFinding]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for f in findings {
        hasher.update(f.finding_id.as_bytes());
        hasher.update(f.vulnerability_class.to_string().as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Load cached graph from disk, or None if not found.
pub fn load_cached_graph(cache_dir: &Path) -> Option<CachedGraph> {
    let path = cache_dir.join("knowledge_graph.json");
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Save cached graph to disk.
pub fn save_cached_graph(
    cache: &CachedGraph,
    cache_dir: &Path,
) -> Result<(), super::KnowledgeError> {
    std::fs::create_dir_all(cache_dir)?;
    let path = cache_dir.join("knowledge_graph.json");
    let json = serde_json::to_string_pretty(cache)?;
    std::fs::write(&path, json)?;
    Ok(())
}

/// Build or load knowledge graph incrementally.
///
/// If the cached graph exists and its content hash matches the current findings,
/// returns the cached graph without rebuilding. Otherwise rebuilds from scratch.
pub fn build_or_load_graph(findings: &[NormalizedFinding], cache_dir: &Path) -> CachedGraph {
    let current_hash = compute_findings_hash(findings);

    // Try to load cache
    if let Some(cached) = load_cached_graph(cache_dir) {
        if cached.content_hash == current_hash && cached.finding_count == findings.len() {
            return cached;
        }
    }

    // Cache miss or content changed — rebuild
    let graph = build_knowledge_graph(findings);
    let node_count = graph.nodes.len();
    let edge_count = graph.edges.len();

    let cached = CachedGraph {
        content_hash: current_hash,
        finding_count: findings.len(),
        node_count,
        edge_count,
        graph,
    };

    // Save cache (best effort)
    let _ = save_cached_graph(&cached, cache_dir);

    cached
}

/// Build a knowledge graph from normalized findings.
pub fn build_knowledge_graph(findings: &[NormalizedFinding]) -> KnowledgeGraph {
    let mut graph = KnowledgeGraph::empty();

    // Add protocol nodes
    let mut protocols: std::collections::BTreeMap<String, (String, usize)> =
        std::collections::BTreeMap::new();
    for finding in findings {
        let entry = protocols
            .entry(finding.protocol_name.clone())
            .or_insert_with(|| (finding.protocol_category.to_string(), 0));
        entry.1 += 1;
    }

    for (name, (category, count)) in &protocols {
        let protocol_id = format!("proto:{}", name.to_lowercase().replace(' ', "_"));
        graph.nodes.push(KnowledgeNode::Protocol(ProtocolNode {
            protocol_id: protocol_id.clone(),
            name: name.clone(),
            category: category.clone(),
            audit_count: 1,
            total_findings: *count,
        }));
    }

    // Add finding nodes and edges
    for finding in findings {
        let protocol_id = format!(
            "proto:{}",
            finding.protocol_name.to_lowercase().replace(' ', "_")
        );

        graph.nodes.push(KnowledgeNode::Finding(FindingNode {
            finding_id: finding.finding_id.clone(),
            report_id: finding.report_id.clone(),
            protocol_id: protocol_id.clone(),
            vulnerability_class: finding.vulnerability_class.to_string(),
            severity: finding.severity.clone(),
        }));

        graph.edges.push(KnowledgeEdge::HasFinding {
            protocol_id,
            finding_id: finding.finding_id.clone(),
        });

        graph.edges.push(KnowledgeEdge::ClassifiedAs {
            finding_id: finding.finding_id.clone(),
            class: finding.vulnerability_class.to_string(),
        });

        graph.edges.push(KnowledgeEdge::UsesTechnique {
            finding_id: finding.finding_id.clone(),
            technique: finding.attack_technique.to_string(),
        });

        if let Some(ref mitigation) = finding.mitigation_pattern {
            graph.edges.push(KnowledgeEdge::MitigatedBy {
                finding_id: finding.finding_id.clone(),
                pattern: mitigation.technique.clone(),
            });
        }
    }

    // Add vulnerability class nodes
    let mut class_counts: std::collections::BTreeMap<String, (usize, Vec<String>)> =
        std::collections::BTreeMap::new();
    for finding in findings {
        let entry = class_counts
            .entry(finding.vulnerability_class.to_string())
            .or_insert_with(|| (0, vec![]));
        entry.0 += 1;
        if !entry.1.contains(&finding.protocol_name) {
            entry.1.push(finding.protocol_name.clone());
        }
    }

    for (class, (count, protocols)) in &class_counts {
        graph
            .nodes
            .push(KnowledgeNode::VulnerabilityClass(VulnerabilityClassNode {
                class: class.clone(),
                occurrence_count: *count,
                affected_protocols: protocols.clone(),
                typical_severity: digger_ir::Severity::Medium,
            }));
    }

    // Add attack technique nodes
    let mut technique_findings: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for finding in findings {
        technique_findings
            .entry(finding.attack_technique.to_string())
            .or_default()
            .push(finding.finding_id.clone());
    }

    for (technique, finding_ids) in &technique_findings {
        graph
            .nodes
            .push(KnowledgeNode::AttackTechnique(AttackTechniqueNode {
                technique: technique.clone(),
                used_in_findings: finding_ids.clone(),
                required_capabilities: vec![],
            }));
    }

    // Add semantic equivalence edges
    let equivalents = super::classifier::find_equivalents(findings);
    for (a, b) in equivalents {
        graph.edges.push(KnowledgeEdge::SemanticallyEquivalent {
            finding_a: a,
            finding_b: b,
        });
    }

    graph
}
