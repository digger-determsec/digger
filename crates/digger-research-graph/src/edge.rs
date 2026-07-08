//! Research-graph EDGES. Each edge is a deterministic relationship FACT (never
//! AI-generated) and a [`RecoveredFact`]: content-addressed id + provenance.
//! An edge id is derived from `(kind, from_id, to_id)`, so identical
//! relationships are idempotent and de-duplicate on merge.

use serde::{Deserialize, Serialize};

use crate::fact_impl::derive_provenance;
use crate::ids::{canon, node_id};
use crate::Provenance;

/// The deterministic semantic relationship an edge encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EdgeKind {
    DependsOn,
    Controls,
    Upgrades,
    Owns,
    Protects,
    InteractsWith,
    SharesCapability,
    SharesDependency,
    SharesArchitecture,
    SharesInvariantFamily,
    Extends,
    References,
}

impl EdgeKind {
    pub fn label(&self) -> &'static str {
        match self {
            EdgeKind::DependsOn => "depends_on",
            EdgeKind::Controls => "controls",
            EdgeKind::Upgrades => "upgrades",
            EdgeKind::Owns => "owns",
            EdgeKind::Protects => "protects",
            EdgeKind::InteractsWith => "interacts_with",
            EdgeKind::SharesCapability => "shares_capability",
            EdgeKind::SharesDependency => "shares_dependency",
            EdgeKind::SharesArchitecture => "shares_architecture",
            EdgeKind::SharesInvariantFamily => "shares_invariant_family",
            EdgeKind::Extends => "extends",
            EdgeKind::References => "references",
        }
    }
}

/// A deterministic directed semantic edge between two graph nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    /// Deterministic content-addressed id (`edge:<digest>`).
    pub id: String,
    pub kind: EdgeKind,
    pub from_id: String,
    pub to_id: String,
    pub provenance: Provenance,
}

impl GraphEdge {
    /// Construct an edge. The id is content-addressed over `(kind, from, to)`.
    pub fn new(kind: EdgeKind, from_id: impl Into<String>, to_id: impl Into<String>) -> Self {
        let from_id = from_id.into();
        let to_id = to_id.into();
        let id_canon = canon(&[kind.label(), &from_id, &to_id]);
        let provenance =
            derive_provenance(&format!("edge|{}", id_canon), &canon(&[&from_id, &to_id]));
        GraphEdge {
            id: node_id("edge", &id_canon),
            kind,
            from_id,
            to_id,
            provenance,
        }
    }
}

impl_graph_fact!(GraphEdge);
