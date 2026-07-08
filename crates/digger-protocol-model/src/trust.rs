//! Trust Model -- deterministic trust relationships represented as a GRAPH,
//! never as prose. Nodes are the protocol core, its privileged actors, and the
//! external systems / shared dependencies it relies on. Edges record the
//! deterministic trust relations (controls, trusts-externally, depends-on,
//! can-upgrade, can-halt). Trust Boundaries are the edges that cross from the
//! protocol core into a privileged or external zone.

use serde::{Deserialize, Serialize};

use crate::actors::{Actor, ActorKind};
use crate::capability_graph::{CapabilityGraph, CapabilityKind};
use crate::ids::node_id;
use crate::{
    derive_provenance, DependencyKind, Provenance, RecoveredDependency, RecoveredDeployment,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustNodeKind {
    ProtocolCore,
    PrivilegedActor,
    ExternalSystem,
    UpgradeAuthority,
    EmergencyControl,
    SharedDependency,
}

/// A node in the trust graph. `reference` is a stable fact id or address tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustNode {
    /// Deterministic content-addressed id (`trustnode:<digest>`).
    pub id: String,
    pub kind: TrustNodeKind,
    /// The fact id / address tag this node represents.
    pub reference: String,
}

impl TrustNode {
    pub fn new(kind: TrustNodeKind, reference: impl Into<String>) -> Self {
        let reference = reference.into();
        let canon = format!("trustnode|{:?}|{}", kind, reference);
        TrustNode {
            id: node_id("trustnode", &canon),
            kind,
            reference,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustEdgeKind {
    Controls,
    TrustsExternally,
    DependsOn,
    CanUpgrade,
    CanHalt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEdge {
    pub from_id: String,
    pub to_id: String,
    pub kind: TrustEdgeKind,
}

/// The deterministic trust graph (the Trust Model representation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGraph {
    /// Deterministic content-addressed id (`trustgraph:<digest>`).
    pub id: String,
    pub nodes: Vec<TrustNode>,
    pub edges: Vec<TrustEdge>,
    pub provenance: Provenance,
}

impl_protocol_fact!(TrustGraph);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustBoundaryKind {
    PrivilegedControl,
    ExternalDependency,
    UpgradeAuthority,
    EmergencyControl,
    SharedDependency,
}

/// A deterministic trust boundary: a crossing from the protocol core into a
/// privileged or external zone. Derived from trust edges (never prose).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustBoundary {
    /// Deterministic content-addressed id (`trustbound:<digest>`).
    pub id: String,
    pub kind: TrustBoundaryKind,
    pub inside_id: String,
    pub outside_id: String,
    pub provenance: Provenance,
}

impl TrustBoundary {
    pub fn new(kind: TrustBoundaryKind, inside_id: String, outside_id: String) -> Self {
        let canon = format!("trustbound|{:?}|{}|{}", kind, inside_id, outside_id);
        let provenance = derive_provenance(&canon, &format!("{},{}", inside_id, outside_id));
        TrustBoundary {
            id: node_id("trustbound", &canon),
            kind,
            inside_id,
            outside_id,
            provenance,
        }
    }
}

impl_protocol_fact!(TrustBoundary);

/// Result of trust derivation: the graph plus the boundary facts it implies.
pub struct TrustModel {
    pub graph: TrustGraph,
    pub boundaries: Vec<TrustBoundary>,
}

/// Deterministically derive the trust graph + boundaries from recovered facts.
pub fn derive_trust(
    _deployment: Option<&RecoveredDeployment>,
    dependencies: &[RecoveredDependency],
    actors: &[Actor],
    capabilities: &CapabilityGraph,
) -> TrustModel {
    let core = TrustNode::new(TrustNodeKind::ProtocolCore, "protocol-core");
    let mut nodes: Vec<TrustNode> = vec![core.clone()];
    let mut edges: Vec<TrustEdge> = Vec::new();
    let mut boundaries: Vec<TrustBoundary> = Vec::new();

    // Privileged actors -> Controls edges + privileged-control boundaries.
    for a in actors {
        let (node_kind, edge_kind, boundary_kind) = match a.kind {
            ActorKind::UpgradeAuthority => (
                TrustNodeKind::UpgradeAuthority,
                TrustEdgeKind::CanUpgrade,
                TrustBoundaryKind::UpgradeAuthority,
            ),
            ActorKind::ExternalProtocol => (
                TrustNodeKind::ExternalSystem,
                TrustEdgeKind::TrustsExternally,
                TrustBoundaryKind::ExternalDependency,
            ),
            _ => (
                TrustNodeKind::PrivilegedActor,
                TrustEdgeKind::Controls,
                TrustBoundaryKind::PrivilegedControl,
            ),
        };
        let n = TrustNode::new(node_kind, a.id.clone());
        edges.push(TrustEdge {
            from_id: core.id.clone(),
            to_id: n.id.clone(),
            kind: edge_kind,
        });
        boundaries.push(TrustBoundary::new(
            boundary_kind,
            core.id.clone(),
            n.id.clone(),
        ));
        nodes.push(n);
    }

    // External / shared dependencies -> trust boundaries.
    for d in dependencies {
        let (node_kind, edge_kind, boundary_kind) = match d.kind {
            DependencyKind::PriceOracle
            | DependencyKind::Bridge
            | DependencyKind::ExternalProtocol => (
                TrustNodeKind::ExternalSystem,
                TrustEdgeKind::TrustsExternally,
                TrustBoundaryKind::ExternalDependency,
            ),
            DependencyKind::SharedInfrastructure => (
                TrustNodeKind::SharedDependency,
                TrustEdgeKind::DependsOn,
                TrustBoundaryKind::SharedDependency,
            ),
            _ => continue,
        };
        let n = TrustNode::new(node_kind, d.id.clone());
        edges.push(TrustEdge {
            from_id: core.id.clone(),
            to_id: n.id.clone(),
            kind: edge_kind,
        });
        boundaries.push(TrustBoundary::new(
            boundary_kind,
            core.id.clone(),
            n.id.clone(),
        ));
        nodes.push(n);
    }

    // Emergency control (Pause capability) -> can-halt boundary.
    if let Some(pause_id) = capabilities.fact_id_for(CapabilityKind::Pause) {
        let n = TrustNode::new(TrustNodeKind::EmergencyControl, pause_id.to_string());
        edges.push(TrustEdge {
            from_id: core.id.clone(),
            to_id: n.id.clone(),
            kind: TrustEdgeKind::CanHalt,
        });
        boundaries.push(TrustBoundary::new(
            TrustBoundaryKind::EmergencyControl,
            core.id.clone(),
            n.id.clone(),
        ));
        nodes.push(n);
    }

    // Deterministic ordering.
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    nodes.dedup_by(|a, b| a.id == b.id);
    edges.sort_by(|a, b| {
        (a.from_id.as_str(), a.to_id.as_str(), a.kind as u8).cmp(&(
            b.from_id.as_str(),
            b.to_id.as_str(),
            b.kind as u8,
        ))
    });
    edges.dedup();
    boundaries.sort_by(|a, b| a.id.cmp(&b.id));
    boundaries.dedup_by(|a, b| a.id == b.id);

    let canon = format!(
        "trustgraph|{}|{}",
        nodes
            .iter()
            .map(|n| n.id.clone())
            .collect::<Vec<_>>()
            .join(","),
        edges
            .iter()
            .map(|e| format!("{}>{}", e.from_id, e.to_id))
            .collect::<Vec<_>>()
            .join(","),
    );
    let provenance = derive_provenance(&canon, &core.id);
    let graph = TrustGraph {
        id: node_id("trustgraph", &canon),
        nodes,
        edges,
        provenance,
    };
    TrustModel { graph, boundaries }
}
