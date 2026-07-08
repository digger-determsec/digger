//! Research-graph NODES. Every node is a deterministic [`RecoveredFact`]: a
//! content-addressed id + provenance (+ confidence + reproducibility via the
//! trait). A node never stores a finding; it points (via `ref_id`) at the
//! recovered fact it represents.

use serde::{Deserialize, Serialize};

use crate::fact_impl::derive_provenance;
use crate::ids::{canon, node_id};
use crate::Provenance;

/// The kind of recovered fact a node represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NodeKind {
    Protocol,
    Architecture,
    Investigation,
    Capability,
    TrustBoundary,
    Dependency,
    InvariantCandidate,
    UpgradePath,
    StateMachine,
    InvestigationTarget,
    Actor,
    Asset,
}

impl NodeKind {
    pub fn label(&self) -> &'static str {
        match self {
            NodeKind::Protocol => "protocol",
            NodeKind::Architecture => "architecture",
            NodeKind::Investigation => "investigation",
            NodeKind::Capability => "capability",
            NodeKind::TrustBoundary => "trust_boundary",
            NodeKind::Dependency => "dependency",
            NodeKind::InvariantCandidate => "invariant_candidate",
            NodeKind::UpgradePath => "upgrade_path",
            NodeKind::StateMachine => "state_machine",
            NodeKind::InvestigationTarget => "investigation_target",
            NodeKind::Actor => "actor",
            NodeKind::Asset => "asset",
        }
    }
}

/// A deterministic semantic-graph node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    /// Deterministic content-addressed id (`node:<digest>`).
    pub id: String,
    pub kind: NodeKind,
    /// The recovered fact id this node represents (Protocol/Investigation/
    /// Capability/... id, or an ArchitectureFingerprint id).
    pub ref_id: String,
    /// Deterministic, structured label (never prose) for explainability.
    pub label: String,
    pub provenance: Provenance,
}

impl GraphNode {
    /// Construct a node. The id is content-addressed over `(kind, ref_id)` so a
    /// given recovered fact always maps to the same node id (idempotent).
    pub fn new(kind: NodeKind, ref_id: impl Into<String>, label: impl Into<String>) -> Self {
        let ref_id = ref_id.into();
        let id_canon = canon(&[kind.label(), &ref_id]);
        let provenance = derive_provenance(&format!("node|{}", id_canon), &ref_id);
        GraphNode {
            id: node_id("node", &id_canon),
            kind,
            ref_id,
            label: label.into(),
            provenance,
        }
    }
}

impl_graph_fact!(GraphNode);
