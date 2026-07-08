//! The `ResearchGraph` -- Digger's deterministic long-term memory. It holds
//! nodes, edges, and architecture fingerprints, all of which are
//! [`RecoveredFact`]s. Enrichment ([`ResearchGraph::merge`]) is PURE: it returns
//! a NEW graph and never mutates its inputs, so historical nodes are immutable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::edge::{EdgeKind, GraphEdge};
use crate::fact_impl::derive_provenance;
use crate::fingerprint::ArchitectureFingerprint;
use crate::ids::{join_ids, node_id};
use crate::node::{GraphNode, NodeKind};
use crate::Provenance;

/// A deterministic semantic graph of recovered protocol/investigation facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchGraph {
    /// Deterministic content-addressed id (`graph:<digest>`).
    pub id: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub fingerprints: Vec<ArchitectureFingerprint>,
    pub provenance: Provenance,
}

impl_graph_fact!(ResearchGraph);

impl ResearchGraph {
    /// Assemble a graph from already-deduplicated parts, sorting everything by
    /// id and content-addressing the graph id over its members. Deterministic.
    pub fn assemble(
        mut nodes: Vec<GraphNode>,
        mut edges: Vec<GraphEdge>,
        mut fingerprints: Vec<ArchitectureFingerprint>,
    ) -> Self {
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        nodes.dedup_by(|a, b| a.id == b.id);
        edges.sort_by(|a, b| a.id.cmp(&b.id));
        edges.dedup_by(|a, b| a.id == b.id);
        fingerprints.sort_by(|a, b| a.id.cmp(&b.id));
        fingerprints.dedup_by(|a, b| a.id == b.id);

        let mut member_ids: Vec<String> = Vec::new();
        member_ids.extend(nodes.iter().map(|n| n.id.clone()));
        member_ids.extend(edges.iter().map(|e| e.id.clone()));
        member_ids.extend(fingerprints.iter().map(|f| f.id.clone()));
        let basis = join_ids(&member_ids);
        let provenance = derive_provenance(&format!("graph|{}", basis), &basis);

        ResearchGraph {
            id: node_id("graph", &basis),
            nodes,
            edges,
            fingerprints,
            provenance,
        }
    }

    pub fn node(&self, id: &str) -> Option<&GraphNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    pub fn nodes_of_kind(&self, kind: NodeKind) -> Vec<&GraphNode> {
        self.nodes.iter().filter(|n| n.kind == kind).collect()
    }

    pub fn node_by_ref(&self, ref_id: &str) -> Option<&GraphNode> {
        self.nodes.iter().find(|n| n.ref_id == ref_id)
    }

    pub fn edges_of_kind(&self, kind: EdgeKind) -> Vec<&GraphEdge> {
        self.edges.iter().filter(|e| e.kind == kind).collect()
    }

    pub fn edges_from(&self, node_id: &str) -> Vec<&GraphEdge> {
        self.edges.iter().filter(|e| e.from_id == node_id).collect()
    }

    /// ENRICHMENT (pure): merge any number of graphs into a NEW graph WITHOUT
    /// mutating the inputs. Nodes/edges/fingerprints de-duplicate by their
    /// content-addressed id (first occurrence preserved, so historical nodes
    /// are immutable), then deterministic CROSS-protocol relationship facts are
    /// recovered between protocols whose fingerprints match:
    /// - `shares_capability`   when capability_fp matches,
    /// - `shares_dependency`   when dependency_fp matches,
    /// - `shares_architecture` when composite_fp matches,
    /// - `shares_invariant_family` when invariant_fp matches,
    /// - `extends`             when one capability-label set strictly contains
    ///   another (the larger architecture extends the smaller),
    /// - `references`          linking investigations of architecturally
    ///   matching protocols (future investigations reference prior ones).
    pub fn merge(graphs: &[&ResearchGraph]) -> ResearchGraph {
        let mut nodes: BTreeMap<String, GraphNode> = BTreeMap::new();
        let mut edges: BTreeMap<String, GraphEdge> = BTreeMap::new();
        let mut fingerprints: BTreeMap<String, ArchitectureFingerprint> = BTreeMap::new();

        for g in graphs {
            for n in &g.nodes {
                nodes.entry(n.id.clone()).or_insert_with(|| n.clone());
            }
            for e in &g.edges {
                edges.entry(e.id.clone()).or_insert_with(|| e.clone());
            }
            for f in &g.fingerprints {
                fingerprints
                    .entry(f.id.clone())
                    .or_insert_with(|| f.clone());
            }
        }

        // protocol fact id -> protocol node id
        let mut protocol_node: BTreeMap<String, String> = BTreeMap::new();
        let mut node_kind: BTreeMap<String, NodeKind> = BTreeMap::new();
        for n in nodes.values() {
            node_kind.insert(n.id.clone(), n.kind);
            if n.kind == NodeKind::Protocol {
                protocol_node.insert(n.ref_id.clone(), n.id.clone());
            }
        }
        // protocol node id -> its investigation node id (via References edges)
        let mut investigation_of: BTreeMap<String, String> = BTreeMap::new();
        for e in edges.values() {
            if e.kind == EdgeKind::References
                && node_kind.get(&e.from_id) == Some(&NodeKind::Protocol)
                && node_kind.get(&e.to_id) == Some(&NodeKind::Investigation)
            {
                investigation_of.insert(e.from_id.clone(), e.to_id.clone());
            }
        }

        let fps: Vec<&ArchitectureFingerprint> = fingerprints.values().collect();
        let mut cross: Vec<GraphEdge> = Vec::new();
        for i in 0..fps.len() {
            for j in (i + 1)..fps.len() {
                let a = fps[i];
                let b = fps[j];
                let pa = match protocol_node.get(&a.protocol_id) {
                    Some(p) => p.clone(),
                    None => continue,
                };
                let pb = match protocol_node.get(&b.protocol_id) {
                    Some(p) => p.clone(),
                    None => continue,
                };
                if pa == pb {
                    continue;
                }
                // deterministic, undirected endpoints for symmetric relations
                let (x, y) = if pa <= pb {
                    (pa.clone(), pb.clone())
                } else {
                    (pb.clone(), pa.clone())
                };
                if a.capability_fp == b.capability_fp {
                    cross.push(GraphEdge::new(
                        EdgeKind::SharesCapability,
                        x.clone(),
                        y.clone(),
                    ));
                }
                if a.dependency_fp == b.dependency_fp {
                    cross.push(GraphEdge::new(
                        EdgeKind::SharesDependency,
                        x.clone(),
                        y.clone(),
                    ));
                }
                if a.invariant_fp == b.invariant_fp {
                    cross.push(GraphEdge::new(
                        EdgeKind::SharesInvariantFamily,
                        x.clone(),
                        y.clone(),
                    ));
                }
                if a.composite_fp == b.composite_fp {
                    cross.push(GraphEdge::new(
                        EdgeKind::SharesArchitecture,
                        x.clone(),
                        y.clone(),
                    ));
                    // future investigations reference prior matching ones
                    if let (Some(ia), Some(ib)) =
                        (investigation_of.get(&pa), investigation_of.get(&pb))
                    {
                        if ia != ib {
                            let (ix, iy) = if ia <= ib {
                                (ia.clone(), ib.clone())
                            } else {
                                (ib.clone(), ia.clone())
                            };
                            cross.push(GraphEdge::new(EdgeKind::References, ix, iy));
                        }
                    }
                }
                // directed `extends`: strict capability-label superset
                if a.capability_labels != b.capability_labels {
                    if strict_superset(&a.capability_labels, &b.capability_labels) {
                        cross.push(GraphEdge::new(EdgeKind::Extends, pa.clone(), pb.clone()));
                    } else if strict_superset(&b.capability_labels, &a.capability_labels) {
                        cross.push(GraphEdge::new(EdgeKind::Extends, pb.clone(), pa.clone()));
                    }
                }
            }
        }
        for e in cross {
            edges.entry(e.id.clone()).or_insert(e);
        }

        ResearchGraph::assemble(
            nodes.into_values().collect(),
            edges.into_values().collect(),
            fingerprints.into_values().collect(),
        )
    }
}

/// True iff `sup` is a strict superset of `sub` (both sorted, deduped).
fn strict_superset(sup: &[String], sub: &[String]) -> bool {
    if sup.len() <= sub.len() {
        return false;
    }
    sub.iter().all(|s| sup.binary_search(s).is_ok())
}
