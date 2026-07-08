//! Deterministic Research Graph construction from a ProtocolModel + its
//! InvestigationPlan. Builds nodes for every recovered fact and recovers the
//! within-protocol semantic edges. Cross-protocol relationships are recovered
//! later, during pure enrichment ([`crate::graph::ResearchGraph::merge`]).
//!
//! No findings, no exploitability, no SystemIR, no AI: every node and edge is a
//! deterministic fact derived solely from recovered protocol/investigation
//! facts.

use std::collections::BTreeMap;

use ::digger_protocol_model::DependencyKind;

use crate::edge::{EdgeKind, GraphEdge};
use crate::fingerprint::derive_fingerprint;
use crate::graph::ResearchGraph;
use crate::node::{GraphNode, NodeKind};
use crate::{InvestigationPlan, ProtocolModel};

fn add_node(
    nodes: &mut Vec<GraphNode>,
    index: &mut BTreeMap<String, String>,
    kind: NodeKind,
    ref_id: &str,
    label: String,
) -> String {
    let n = GraphNode::new(kind, ref_id, label);
    let id = n.id.clone();
    index.insert(ref_id.to_string(), id.clone());
    nodes.push(n);
    id
}

fn link(edges: &mut Vec<GraphEdge>, kind: EdgeKind, from: &str, to: &str) {
    edges.push(GraphEdge::new(kind, from, to));
}

/// Build the deterministic Research Graph for one protocol + its plan.
pub fn build_research_graph(pm: &ProtocolModel, plan: &InvestigationPlan) -> ResearchGraph {
    let mut nodes: Vec<GraphNode> = Vec::new();
    let mut edges: Vec<GraphEdge> = Vec::new();
    // recovered fact id -> graph node id
    let mut index: BTreeMap<String, String> = BTreeMap::new();

    let fingerprint = derive_fingerprint(pm);

    let protocol = add_node(
        &mut nodes,
        &mut index,
        NodeKind::Protocol,
        &pm.id,
        "protocol".into(),
    );
    let architecture = add_node(
        &mut nodes,
        &mut index,
        NodeKind::Architecture,
        &fingerprint.id,
        format!("architecture:{}", fingerprint.composite_fp),
    );
    let investigation = add_node(
        &mut nodes,
        &mut index,
        NodeKind::Investigation,
        &plan.id,
        "investigation".into(),
    );
    link(&mut edges, EdgeKind::References, &protocol, &architecture);
    link(&mut edges, EdgeKind::References, &protocol, &investigation);

    // Capabilities: the protocol controls each recovered capability.
    for c in &pm.capability_graph.capabilities {
        let id = add_node(
            &mut nodes,
            &mut index,
            NodeKind::Capability,
            &c.id,
            format!("{:?}", c.kind),
        );
        link(&mut edges, EdgeKind::Controls, &protocol, &id);
    }
    // Actors: a privileged actor controls the protocol.
    for a in &pm.actors {
        let id = add_node(
            &mut nodes,
            &mut index,
            NodeKind::Actor,
            &a.id,
            format!("{:?}", a.kind),
        );
        link(&mut edges, EdgeKind::Controls, &id, &protocol);
    }
    // Assets: the protocol owns each recovered asset.
    for a in &pm.assets {
        let id = add_node(
            &mut nodes,
            &mut index,
            NodeKind::Asset,
            &a.id,
            format!("{:?}", a.kind),
        );
        link(&mut edges, EdgeKind::Owns, &protocol, &id);
    }
    // Dependencies: the protocol depends_on each; external ones it interacts_with.
    for d in &pm.dependencies {
        let id = add_node(
            &mut nodes,
            &mut index,
            NodeKind::Dependency,
            &d.id,
            format!("{:?}", d.kind),
        );
        link(&mut edges, EdgeKind::DependsOn, &protocol, &id);
        if is_external(d.kind) {
            link(&mut edges, EdgeKind::InteractsWith, &protocol, &id);
        }
    }
    // Trust boundaries protect the protocol core.
    for b in &pm.trust_boundaries {
        let id = add_node(
            &mut nodes,
            &mut index,
            NodeKind::TrustBoundary,
            &b.id,
            format!("{:?}", b.kind),
        );
        link(&mut edges, EdgeKind::Protects, &id, &protocol);
    }
    // Upgrade paths upgrade the protocol.
    for u in &pm.upgrade_paths {
        let id = add_node(
            &mut nodes,
            &mut index,
            NodeKind::UpgradePath,
            &u.id,
            "upgrade_path".into(),
        );
        link(&mut edges, EdgeKind::Upgrades, &id, &protocol);
    }
    // State machines + invariant candidates reference the protocol.
    for m in &pm.state_machines {
        let id = add_node(
            &mut nodes,
            &mut index,
            NodeKind::StateMachine,
            &m.id,
            format!("{:?}", m.machine_kind),
        );
        link(&mut edges, EdgeKind::References, &id, &protocol);
    }
    for inv in &pm.invariant_candidates {
        let id = add_node(
            &mut nodes,
            &mut index,
            NodeKind::InvariantCandidate,
            &inv.id,
            format!("{:?}", inv.kind),
        );
        link(&mut edges, EdgeKind::References, &id, &protocol);
    }

    // Investigation targets: the investigation references each target, and each
    // target references the recovered facts that support it (capabilities,
    // trust boundaries, assets) -- only when those facts have nodes.
    for t in &plan.targets {
        let tid = add_node(
            &mut nodes,
            &mut index,
            NodeKind::InvestigationTarget,
            &t.id,
            format!("{:?}", t.kind),
        );
        link(&mut edges, EdgeKind::References, &investigation, &tid);
        for support in t
            .support
            .capability_fact_ids
            .iter()
            .chain(t.support.trust_boundary_fact_ids.iter())
            .chain(t.support.asset_fact_ids.iter())
        {
            if let Some(node_id) = index.get(support) {
                link(&mut edges, EdgeKind::References, &tid, &node_id.clone());
            }
        }
    }

    ResearchGraph::assemble(nodes, edges, vec![fingerprint])
}

/// External (cross-contract) dependency kinds the protocol interacts_with.
fn is_external(kind: DependencyKind) -> bool {
    !matches!(kind, DependencyKind::Token | DependencyKind::Vault)
}
