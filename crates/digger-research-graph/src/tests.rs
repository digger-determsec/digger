//! Deterministic unit tests for the research graph (run under `cargo test` in
//! CI; no toolchain in the build sandbox).

use super::*;
use crate::edge::EdgeKind;
use crate::node::NodeKind;
use ::digger_investigation::build_investigation_plan;
use ::digger_protocol_model::model::{ProtocolModel, ProtocolModelInput};
use ::digger_reconstruct::fact::RecoveredFact;

fn empty_graph() -> ResearchGraph {
    let input = ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    };
    let pm = ProtocolModel::build(&input);
    let plan = build_investigation_plan(&pm);
    build_research_graph(&pm, &plan)
}

#[test]
fn empty_model_yields_core_skeleton() {
    let g = empty_graph();
    // Protocol + Architecture + Investigation, nothing else.
    assert_eq!(g.nodes_of_kind(NodeKind::Protocol).len(), 1);
    assert_eq!(g.nodes_of_kind(NodeKind::Architecture).len(), 1);
    assert_eq!(g.nodes_of_kind(NodeKind::Investigation).len(), 1);
    assert_eq!(g.nodes.len(), 3);
    assert_eq!(g.fingerprints.len(), 1);
    // protocol references architecture + investigation
    assert_eq!(g.edges_of_kind(EdgeKind::References).len(), 2);
}

#[test]
fn graph_construction_is_deterministic() {
    let a = empty_graph();
    let b = empty_graph();
    assert_eq!(a, b);
    assert_eq!(a.id, b.id);
}

#[test]
fn nodes_and_edges_are_recovered_facts() {
    let g = empty_graph();
    for n in &g.nodes {
        assert_eq!(n.fact_id(), n.id);
        assert!(!n.provenance().id.is_empty());
        // confidence + reproducibility come for free via the trait.
        let _ = n.confidence();
        assert!(!n.reproducibility().reconstructor_crate.is_empty());
    }
    for e in &g.edges {
        assert_eq!(e.fact_id(), e.id);
        assert!(!e.provenance().id.is_empty());
    }
}

#[test]
fn fingerprint_has_all_facets() {
    let g = empty_graph();
    let fp = &g.fingerprints[0];
    for facet in [
        &fp.capability_fp,
        &fp.dependency_fp,
        &fp.upgrade_fp,
        &fp.trust_fp,
        &fp.state_machine_fp,
        &fp.invariant_fp,
        &fp.composite_fp,
    ] {
        assert_eq!(facet.len(), 16, "fnv1a-64 hex is 16 chars");
    }
}

#[test]
fn merge_is_pure_and_idempotent() {
    let g = empty_graph();
    let before_nodes = g.nodes.len();
    let before_edges = g.edges.len();
    let merged = ResearchGraph::merge(&[&g, &g]);
    // inputs untouched (immutable history)
    assert_eq!(g.nodes.len(), before_nodes);
    assert_eq!(g.edges.len(), before_edges);
    // merging a graph with itself de-duplicates back to the same content.
    assert_eq!(merged.nodes.len(), before_nodes);
    assert_eq!(merged.edges.len(), before_edges);
    assert_eq!(merged.nodes, g.nodes);
}

#[test]
fn edge_id_is_content_addressed() {
    let e1 = crate::edge::GraphEdge::new(EdgeKind::DependsOn, "node:a", "node:b");
    let e2 = crate::edge::GraphEdge::new(EdgeKind::DependsOn, "node:a", "node:b");
    let e3 = crate::edge::GraphEdge::new(EdgeKind::Controls, "node:a", "node:b");
    assert_eq!(e1.id, e2.id);
    assert_ne!(e1.id, e3.id);
}
