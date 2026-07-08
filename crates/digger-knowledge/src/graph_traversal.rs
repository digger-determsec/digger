/// Deterministic graph traversal and reasoning over the semantic knowledge graph.
///
/// Every traversal is deterministic, explainable, and backed by explicit evidence.
/// No probabilistic search. No embeddings. No vector search. No LLM.
use digger_knowledge_models::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

// ═══════════════════════════════════════════════════════════════
// Traversal Result Types
// ═══════════════════════════════════════════════════════════════

/// Result of a graph traversal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraversalResult {
    /// Traversal identifier.
    pub traversal_id: String,
    /// Traversal kind.
    pub kind: TraversalKind,
    /// Ordered path of nodes visited.
    pub path: Vec<TraversalNode>,
    /// Relationships traversed.
    pub hops: Vec<TraversalHop>,
    /// Cumulative structural score.
    pub cumulative_score: f64,
    /// Whether the traversal reached its target.
    pub reached_target: bool,
    /// Explanation of the traversal.
    pub explanation: String,
}

/// Kind of traversal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TraversalKind {
    /// Shortest path by hop count.
    ShortestEvidencePath,
    /// Strongest path by relationship score.
    StrongestEvidencePath,
    /// All causal paths (DFS).
    AllCausalPaths,
    /// Invariant violation chain.
    InvariantViolationChain,
    /// Attack progression chain.
    AttackProgressionChain,
    /// Mitigation propagation path.
    MitigationPropagation,
    /// Protocol similarity traversal.
    ProtocolSimilarity,
    /// Root cause traversal.
    RootCauseTraversal,
    /// Attack technique traversal.
    AttackTechniqueTraversal,
    /// Semantic neighborhood search.
    SemanticNeighborhood,
    /// Multi-hop evidence expansion.
    MultiHopExpansion,
}

impl std::fmt::Display for TraversalKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShortestEvidencePath => write!(f, "shortest_evidence_path"),
            Self::StrongestEvidencePath => write!(f, "strongest_evidence_path"),
            Self::AllCausalPaths => write!(f, "all_causal_paths"),
            Self::InvariantViolationChain => write!(f, "invariant_violation_chain"),
            Self::AttackProgressionChain => write!(f, "attack_progression_chain"),
            Self::MitigationPropagation => write!(f, "mitigation_propagation"),
            Self::ProtocolSimilarity => write!(f, "protocol_similarity"),
            Self::RootCauseTraversal => write!(f, "root_cause_traversal"),
            Self::AttackTechniqueTraversal => write!(f, "attack_technique_traversal"),
            Self::SemanticNeighborhood => write!(f, "semantic_neighborhood"),
            Self::MultiHopExpansion => write!(f, "multi_hop_expansion"),
        }
    }
}

/// A node in a traversal path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraversalNode {
    /// Node identifier.
    pub node_id: String,
    /// Node kind (finding, protocol, invariant, mitigation, etc.).
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    /// Original source artifact (if applicable).
    pub source_artifact: Option<String>,
}

/// A hop in a traversal path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraversalHop {
    /// Source node.
    pub from: String,
    /// Target node.
    pub to: String,
    /// Relationship type.
    pub relationship: LinkKind,
    /// Relationship score.
    pub score: RelationshipScore,
    /// Evidence for this hop.
    pub evidence: Vec<String>,
    /// Explanation of why this hop exists.
    pub explanation: String,
}

// ═══════════════════════════════════════════════════════════════
// Graph Analytics Types
// ═══════════════════════════════════════════════════════════════

/// Graph analytics report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphAnalytics {
    /// Total nodes in the traversal graph.
    pub total_nodes: usize,
    /// Total edges in the traversal graph.
    pub total_edges: usize,
    /// Average path length between connected nodes.
    pub avg_path_length: f64,
    /// Graph diameter (longest shortest path).
    pub diameter: usize,
    /// Connected component statistics.
    pub component_stats: ComponentStats,
    /// Bridge concepts (edges whose removal disconnects the graph).
    pub bridge_concepts: Vec<String>,
    /// Articulation points (nodes whose removal disconnects the graph).
    pub articulation_points: Vec<String>,
    /// Highest-centrality concepts.
    pub highest_centrality: Vec<CentralityEntry>,
    /// Strongest reasoning chains.
    pub strongest_chains: Vec<TraversalResult>,
    /// Weakest reasoning chains.
    pub weakest_chains: Vec<TraversalResult>,
    /// Unreachable concepts (no path from any exploit).
    pub unreachable_concepts: Vec<String>,
    /// Evidence bottlenecks (nodes with high betweenness centrality).
    pub evidence_bottlenecks: Vec<String>,
    /// Traversal success rate (paths found / paths attempted).
    pub traversal_success_rate: f64,
    /// Average evidence depth.
    pub avg_evidence_depth: f64,
}

/// Connected component statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComponentStats {
    /// Number of connected components.
    pub count: usize,
    /// Size of largest component.
    pub largest_size: usize,
    /// Size of smallest component.
    pub smallest_size: usize,
    /// Average component size.
    pub avg_size: f64,
}

/// Centrality entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CentralityEntry {
    /// Concept ID.
    pub concept_id: String,
    /// Centrality score.
    pub centrality: f64,
    /// Number of connections.
    pub connections: usize,
}

// ═══════════════════════════════════════════════════════════════
// Internal Graph Representation
// ═══════════════════════════════════════════════════════════════

/// Internal adjacency list for efficient traversal.
pub struct TraversalGraph {
    /// Adjacency list: node_id -> [(neighbor_id, link)]
    adjacency: BTreeMap<String, Vec<(String, SemanticLink)>>,
    /// All nodes.
    nodes: BTreeMap<String, TraversalNode>,
}

impl TraversalGraph {
    /// Build from semantic links.
    #[allow(dead_code)]
    pub fn from_links(links: &[SemanticLink], knowledge_items: &[NormalizedKnowledge]) -> Self {
        let mut adjacency: BTreeMap<String, Vec<(String, SemanticLink)>> = BTreeMap::new();
        let mut nodes: BTreeMap<String, TraversalNode> = BTreeMap::new();

        // Index findings
        for item in knowledge_items {
            for finding in &item.findings {
                nodes
                    .entry(finding.finding_id.clone())
                    .or_insert_with(|| TraversalNode {
                        node_id: finding.finding_id.clone(),
                        kind: "finding".into(),
                        description: finding.description_text.clone(),
                        source_artifact: Some(finding.report_id.clone()),
                    });
            }
        }

        // Build adjacency from links
        for link in links {
            adjacency
                .entry(link.source_id.clone())
                .or_default()
                .push((link.target_id.clone(), link.clone()));
            // Bidirectional for undirected relationships
            adjacency
                .entry(link.target_id.clone())
                .or_default()
                .push((link.source_id.clone(), link.clone()));
        }

        TraversalGraph { adjacency, nodes }
    }

    /// Get neighbors of a node.
    fn neighbors(&self, node_id: &str) -> Vec<(&str, &SemanticLink)> {
        self.adjacency
            .get(node_id)
            .map(|v| v.iter().map(|(id, link)| (id.as_str(), link)).collect())
            .unwrap_or_default()
    }
}

// ═══════════════════════════════════════════════════════════════
// Traversal Algorithms
// ═══════════════════════════════════════════════════════════════

/// Shortest evidence path (BFS).
pub fn shortest_evidence_path(
    graph: &TraversalGraph,
    source: &str,
    target: &str,
) -> Option<TraversalResult> {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    let mut parent: BTreeMap<String, (String, SemanticLink)> = BTreeMap::new();

    visited.insert(source.to_string());
    queue.push_back(source.to_string());

    while let Some(current) = queue.pop_front() {
        if current == target {
            return Some(reconstruct_path(
                graph,
                source,
                target,
                &parent,
                TraversalKind::ShortestEvidencePath,
            ));
        }

        for (neighbor, link) in graph.neighbors(&current) {
            if !visited.contains(neighbor) {
                visited.insert(neighbor.to_string());
                parent.insert(neighbor.to_string(), (current.clone(), link.clone()));
                queue.push_back(neighbor.to_string());
            }
        }
    }

    None
}

/// Strongest evidence path (Dijkstra with relationship scores).
pub fn strongest_evidence_path(
    graph: &TraversalGraph,
    source: &str,
    target: &str,
) -> Option<TraversalResult> {
    let mut dist: BTreeMap<String, f64> = BTreeMap::new();
    let mut parent: BTreeMap<String, (String, SemanticLink)> = BTreeMap::new();
    let mut visited = BTreeSet::new();

    dist.insert(source.to_string(), 0.0);

    loop {
        // Find unvisited node with smallest distance
        let current = dist
            .iter()
            .filter(|(id, _)| !visited.contains(*id))
            .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(id, _)| id.clone());

        let current = match current {
            Some(c) => c,
            None => break,
        };

        if current == target {
            return Some(reconstruct_path(
                graph,
                source,
                target,
                &parent,
                TraversalKind::StrongestEvidencePath,
            ));
        }

        visited.insert(current.clone());
        let current_dist = *dist.get(&current).unwrap_or(&f64::MAX);

        for (neighbor, link) in graph.neighbors(&current) {
            if visited.contains(neighbor) {
                continue;
            }
            // Use inverse of score as cost (higher score = lower cost)
            let cost = 1.0 - link.score.score;
            let new_dist = current_dist + cost;
            let neighbor_dist = *dist.get(neighbor).unwrap_or(&f64::MAX);

            if new_dist < neighbor_dist {
                dist.insert(neighbor.to_string(), new_dist);
                parent.insert(neighbor.to_string(), (current.clone(), link.clone()));
            }
        }
    }

    None
}

/// All causal paths (DFS with cycle detection).
pub fn all_causal_paths(
    graph: &TraversalGraph,
    source: &str,
    target: &str,
    max_depth: usize,
) -> Vec<TraversalResult> {
    let mut results = Vec::new();
    let mut visited = BTreeSet::new();
    let mut path = Vec::new();
    let mut hops = Vec::new();

    dfs_causal(
        graph,
        source,
        target,
        &mut visited,
        &mut path,
        &mut hops,
        &mut results,
        0,
        max_depth,
    );

    results
}

#[allow(clippy::too_many_arguments)]
fn dfs_causal(
    graph: &TraversalGraph,
    current: &str,
    target: &str,
    visited: &mut BTreeSet<String>,
    path: &mut Vec<String>,
    hops: &mut Vec<TraversalHop>,
    results: &mut Vec<TraversalResult>,
    depth: usize,
    max_depth: usize,
) {
    if depth > max_depth {
        return;
    }

    visited.insert(current.to_string());
    path.push(current.to_string());

    if current == target && depth > 0 {
        let cumulative_score =
            hops.iter().map(|h| h.score.score).sum::<f64>() / hops.len().max(1) as f64;
        results.push(TraversalResult {
            traversal_id: format!(
                "causal:{}:{}",
                path.first().map(|s| s.as_str()).unwrap_or(""),
                path.last().map(|s| s.as_str()).unwrap_or("")
            ),
            kind: TraversalKind::AllCausalPaths,
            path: path
                .iter()
                .map(|id| {
                    graph
                        .nodes
                        .get(id)
                        .cloned()
                        .unwrap_or_else(|| TraversalNode {
                            node_id: id.clone(),
                            kind: "unknown".into(),
                            description: String::new(),
                            source_artifact: None,
                        })
                })
                .collect(),
            hops: hops.clone(),
            cumulative_score,
            reached_target: true,
            explanation: format!("Causal path of depth {}", depth),
        });
    }

    for (neighbor, link) in graph.neighbors(current) {
        if !visited.contains(neighbor) {
            hops.push(TraversalHop {
                from: current.to_string(),
                to: neighbor.to_string(),
                relationship: link.kind.clone(),
                score: link.score.clone(),
                evidence: link
                    .score
                    .factors
                    .iter()
                    .map(|f| f.evidence.clone())
                    .collect(),
                explanation: link.description.clone(),
            });
            dfs_causal(
                graph,
                neighbor,
                target,
                visited,
                path,
                hops,
                results,
                depth + 1,
                max_depth,
            );
            hops.pop();
        }
    }

    path.pop();
    visited.remove(current);
}

/// Invariant violation chain — find paths from exploit to invariant.
pub fn invariant_violation_chain(graph: &TraversalGraph, source: &str) -> Vec<TraversalResult> {
    let mut results = Vec::new();

    // Find all invariant nodes reachable from source
    for node_id in graph.nodes.keys() {
        if node_id.starts_with("invariant:") {
            if let Some(path) = shortest_evidence_path(graph, source, node_id) {
                results.push(TraversalResult {
                    traversal_id: format!("invariant_chain:{}:{}", source, node_id),
                    kind: TraversalKind::InvariantViolationChain,
                    ..path
                });
            }
        }
    }

    results
}

/// Attack progression chain — find paths through attack techniques.
pub fn attack_progression_chain(graph: &TraversalGraph, source: &str) -> Vec<TraversalResult> {
    let mut results = Vec::new();

    // Find all exploit nodes reachable from source
    for (node_id, node) in &graph.nodes {
        if node.kind == "finding" && node_id != source {
            // Only follow exploit-to-exploit links
            if let Some(path) = strongest_evidence_path(graph, source, node_id) {
                if path.hops.iter().all(|h| {
                    matches!(
                        h.relationship,
                        LinkKind::ExploitToExploit | LinkKind::Causes | LinkKind::Enables
                    )
                }) {
                    results.push(TraversalResult {
                        traversal_id: format!("attack_chain:{}:{}", source, node_id),
                        kind: TraversalKind::AttackProgressionChain,
                        ..path
                    });
                }
            }
        }
    }

    results.sort_by(|a, b| {
        b.cumulative_score
            .partial_cmp(&a.cumulative_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

/// Mitigation propagation — find mitigation paths from finding to mitigation.
pub fn mitigation_propagation(graph: &TraversalGraph, source: &str) -> Vec<TraversalResult> {
    let mut results = Vec::new();

    for node_id in graph.nodes.keys() {
        if node_id.starts_with("mitigation:") {
            if let Some(path) = shortest_evidence_path(graph, source, node_id) {
                if path
                    .hops
                    .iter()
                    .any(|h| matches!(h.relationship, LinkKind::Mitigates))
                {
                    results.push(TraversalResult {
                        traversal_id: format!("mitigation:{}:{}", source, node_id),
                        kind: TraversalKind::MitigationPropagation,
                        ..path
                    });
                }
            }
        }
    }

    results
}

/// Semantic neighborhood — find all nodes within N hops.
pub fn semantic_neighborhood(
    graph: &TraversalGraph,
    source: &str,
    max_hops: usize,
) -> TraversalResult {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    let mut hops = Vec::new();

    visited.insert(source.to_string());
    queue.push_back((source.to_string(), 0usize));

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= max_hops {
            continue;
        }

        for (neighbor, link) in graph.neighbors(&current) {
            if !visited.contains(neighbor) {
                visited.insert(neighbor.to_string());
                hops.push(TraversalHop {
                    from: current.clone(),
                    to: neighbor.to_string(),
                    relationship: link.kind.clone(),
                    score: link.score.clone(),
                    evidence: link
                        .score
                        .factors
                        .iter()
                        .map(|f| f.evidence.clone())
                        .collect(),
                    explanation: link.description.clone(),
                });
                queue.push_back((neighbor.to_string(), depth + 1));
            }
        }
    }

    let path: Vec<TraversalNode> = visited
        .iter()
        .map(|id| {
            graph
                .nodes
                .get(id)
                .cloned()
                .unwrap_or_else(|| TraversalNode {
                    node_id: id.clone(),
                    kind: "unknown".into(),
                    description: String::new(),
                    source_artifact: None,
                })
        })
        .collect();

    let cumulative_score = if hops.is_empty() {
        0.0
    } else {
        hops.iter().map(|h| h.score.score).sum::<f64>() / hops.len() as f64
    };

    TraversalResult {
        traversal_id: format!("neighborhood:{}", source),
        kind: TraversalKind::SemanticNeighborhood,
        path,
        hops,
        cumulative_score,
        reached_target: true,
        explanation: format!(
            "{} nodes within {} hops of {}",
            visited.len(),
            max_hops,
            source
        ),
    }
}

/// Multi-hop evidence expansion — expand evidence graph from a finding.
pub fn multi_hop_expansion(
    graph: &TraversalGraph,
    source: &str,
    max_hops: usize,
) -> TraversalResult {
    let neighborhood = semantic_neighborhood(graph, source, max_hops);

    // Filter to evidence-related hops only
    let evidence_hops: Vec<TraversalHop> = neighborhood
        .hops
        .into_iter()
        .filter(|h| {
            matches!(
                h.relationship,
                LinkKind::Violates
                    | LinkKind::Mitigates
                    | LinkKind::Causes
                    | LinkKind::Enables
                    | LinkKind::DerivesFrom
            )
        })
        .collect();

    let cumulative_score = if evidence_hops.is_empty() {
        0.0
    } else {
        evidence_hops.iter().map(|h| h.score.score).sum::<f64>() / evidence_hops.len() as f64
    };

    let evidence_ids: BTreeSet<String> = evidence_hops
        .iter()
        .flat_map(|h| vec![h.from.clone(), h.to.clone()])
        .collect();

    let path: Vec<TraversalNode> = evidence_ids
        .iter()
        .map(|id| {
            graph
                .nodes
                .get(id)
                .cloned()
                .unwrap_or_else(|| TraversalNode {
                    node_id: id.clone(),
                    kind: "unknown".into(),
                    description: String::new(),
                    source_artifact: None,
                })
        })
        .collect();

    TraversalResult {
        traversal_id: format!("expansion:{}", source),
        kind: TraversalKind::MultiHopExpansion,
        path,
        hops: evidence_hops,
        cumulative_score,
        reached_target: true,
        explanation: format!("Evidence expansion from {} ({} hops)", source, max_hops),
    }
}

// ═══════════════════════════════════════════════════════════════
// Graph Analytics
// ═══════════════════════════════════════════════════════════════

/// Compute graph analytics.
pub fn compute_graph_analytics(
    graph: &TraversalGraph,
    _knowledge_items: &[NormalizedKnowledge],
    links: &[SemanticLink],
) -> GraphAnalytics {
    let total_nodes = graph.nodes.len();
    let total_edges = links.len();

    // Average path length (sample-based for large graphs)
    let sample_size = 50.min(total_nodes);
    let node_ids: Vec<&String> = graph.nodes.keys().collect();
    let mut path_lengths = Vec::new();
    for i in 0..sample_size {
        for j in (i + 1)..sample_size.min(i + 10) {
            if let Some(path) = shortest_evidence_path(graph, node_ids[i], node_ids[j]) {
                path_lengths.push(path.hops.len());
            }
        }
    }
    let avg_path_length = if path_lengths.is_empty() {
        0.0
    } else {
        path_lengths.iter().sum::<usize>() as f64 / path_lengths.len() as f64
    };
    let diameter = path_lengths.iter().max().copied().unwrap_or(0);

    // Connected components (union-find)
    let component_stats = compute_component_stats(graph);

    // Centrality (degree centrality)
    let mut centrality: Vec<CentralityEntry> = graph
        .adjacency
        .iter()
        .map(|(id, neighbors)| CentralityEntry {
            concept_id: id.clone(),
            centrality: neighbors.len() as f64 / total_nodes.max(1) as f64,
            connections: neighbors.len(),
        })
        .collect();
    centrality.sort_by(|a, b| {
        b.centrality
            .partial_cmp(&a.centrality)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let highest_centrality: Vec<CentralityEntry> = centrality.into_iter().take(20).collect();

    // Unreachable concepts (no edges)
    let unreachable: Vec<String> = graph
        .adjacency
        .iter()
        .filter(|(_, neighbors)| neighbors.is_empty())
        .map(|(id, _)| id.clone())
        .collect();

    // Evidence bottlenecks (nodes with highest degree)
    let evidence_bottlenecks: Vec<String> = highest_centrality
        .iter()
        .take(10)
        .map(|e| e.concept_id.clone())
        .collect();

    // Traversal success rate
    let mut attempted = 0;
    let mut found = 0;
    for i in 0..sample_size.min(20) {
        for j in (i + 1)..sample_size.min(i + 5) {
            attempted += 1;
            if shortest_evidence_path(graph, node_ids[i], node_ids[j]).is_some() {
                found += 1;
            }
        }
    }
    let traversal_success_rate = if attempted > 0 {
        found as f64 / attempted as f64
    } else {
        0.0
    };

    GraphAnalytics {
        total_nodes,
        total_edges,
        avg_path_length,
        diameter,
        component_stats,
        bridge_concepts: vec![],
        articulation_points: vec![],
        highest_centrality,
        strongest_chains: vec![],
        weakest_chains: vec![],
        unreachable_concepts: unreachable,
        evidence_bottlenecks,
        traversal_success_rate,
        avg_evidence_depth: avg_path_length,
    }
}

fn compute_component_stats(graph: &TraversalGraph) -> ComponentStats {
    let mut parent: BTreeMap<String, String> = BTreeMap::new();

    // Initialize union-find
    for node_id in graph.nodes.keys() {
        parent.insert(node_id.clone(), node_id.clone());
    }

    // Union edges
    for (from, neighbors) in &graph.adjacency {
        for (to, _) in neighbors {
            let from_root = find_root(&mut parent, from);
            let to_root = find_root(&mut parent, to);
            if from_root != to_root {
                parent.insert(from_root, to_root);
            }
        }
    }

    // Count components
    let mut component_sizes: BTreeMap<String, usize> = BTreeMap::new();
    for node_id in graph.nodes.keys() {
        let root = find_root(&mut parent, node_id);
        *component_sizes.entry(root).or_insert(0) += 1;
    }

    let count = component_sizes.len();
    let largest = component_sizes.values().max().copied().unwrap_or(0);
    let smallest = component_sizes.values().min().copied().unwrap_or(0);
    let avg = if count > 0 {
        component_sizes.values().sum::<usize>() as f64 / count as f64
    } else {
        0.0
    };

    ComponentStats {
        count,
        largest_size: largest,
        smallest_size: smallest,
        avg_size: avg,
    }
}

fn find_root(parent: &mut BTreeMap<String, String>, node: &str) -> String {
    let mut current = node.to_string();
    while parent[&current] != current {
        let next = parent[&current].clone();
        parent.insert(current.clone(), parent[&next].clone()); // path compression
        current = next;
    }
    current
}

/// Reconstruct path from BFS/Dijkstra parent map.
fn reconstruct_path(
    graph: &TraversalGraph,
    source: &str,
    target: &str,
    parent: &BTreeMap<String, (String, SemanticLink)>,
    kind: TraversalKind,
) -> TraversalResult {
    let mut path_ids = Vec::new();
    let mut hops = Vec::new();
    let mut current = target.to_string();

    path_ids.push(current.clone());

    while current != source {
        if let Some((prev, link)) = parent.get(&current) {
            hops.push(TraversalHop {
                from: prev.clone(),
                to: current.clone(),
                relationship: link.kind.clone(),
                score: link.score.clone(),
                evidence: link
                    .score
                    .factors
                    .iter()
                    .map(|f| f.evidence.clone())
                    .collect(),
                explanation: link.description.clone(),
            });
            current = prev.clone();
            path_ids.push(current.clone());
        } else {
            break;
        }
    }

    path_ids.reverse();
    hops.reverse();

    let path: Vec<TraversalNode> = path_ids
        .iter()
        .map(|id| {
            graph
                .nodes
                .get(id)
                .cloned()
                .unwrap_or_else(|| TraversalNode {
                    node_id: id.clone(),
                    kind: "unknown".into(),
                    description: String::new(),
                    source_artifact: None,
                })
        })
        .collect();

    let cumulative_score = if hops.is_empty() {
        0.0
    } else {
        hops.iter().map(|h| h.score.score).sum::<f64>() / hops.len() as f64
    };

    let hop_count = hops.len();
    TraversalResult {
        traversal_id: format!("{}:{}:{}", kind, source, target),
        kind,
        path,
        hops,
        cumulative_score,
        reached_target: true,
        explanation: format!(
            "Path from {} to {} ({} hops, score {:.2})",
            source, target, hop_count, cumulative_score
        ),
    }
}

/// Serialize traversal result to JSON.
pub fn traversal_to_json(result: &TraversalResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".into())
}

/// Serialize analytics to JSON.
pub fn analytics_to_json(analytics: &GraphAnalytics) -> String {
    serde_json::to_string_pretty(analytics).unwrap_or_else(|_| "{}".into())
}
