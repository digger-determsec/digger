#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

//! digger-research-graph -- Generation 5 Phase A6: Deterministic Research Graph
//! Foundation.
//!
//! Digger's deterministic LONG-TERM MEMORY. This is NOT a knowledge database
//! and NOT a findings store: it is a deterministic SEMANTIC GRAPH connecting
//! protocols, architectures, investigations, capabilities, trust boundaries,
//! dependencies, invariant candidates, upgrade paths, state machines,
//! investigation targets, actors, and assets. It sits AFTER the Investigation
//! Plan and BEFORE the SystemIR bridge:
//!
//! ```text
//! Evidence -> Reconstruction -> Protocol Model -> Investigation Plan
//!   -> Research Graph -> SystemIR Bridge -> Gen 2 -> Gen 3 -> Gen 4
//! ```
//!
//! Determinism contract (identical to the rest of Generation 5):
//! - Every node and edge is a [`RecoveredFact`]: deterministic content-addressed
//!   id + provenance + confidence + reproducibility key.
//! - Edges are deterministic relationship FACTS, never AI-generated.
//! - Architecture fingerprints are deterministic content digests over recovered
//!   structure -- NO machine learning, NO embeddings, NO probabilistic
//!   similarity. "Similarity" is exact equality of deterministic fingerprints.
//! - Investigation memory is ENRICHMENT ONLY: merging graphs produces a NEW
//!   graph; historical nodes are never mutated.
//! - No duplicate IR, no SystemIR construction, no alternate pipeline.
//! - Chain-agnostic: the graph is built from chain-agnostic ProtocolModel and
//!   InvestigationPlan facts.

pub use ::digger_investigation::InvestigationPlan;
pub use ::digger_protocol_model::model::ProtocolModel;
pub use ::digger_reconstruct::confidence::ConfidenceTier;
pub use ::digger_reconstruct::fact::RecoveredFact;
pub use ::digger_reconstruct::provenance::{
    EvidenceSource, Provenance, ReconstructionStage, ReproducibilityKey,
};

#[macro_use]
mod fact_impl;

pub mod builder;
pub mod edge;
pub mod fingerprint;
pub mod graph;
pub mod ids;
pub mod node;

#[cfg(test)]
mod tests;

pub use builder::build_research_graph;
pub use edge::{EdgeKind, GraphEdge};
pub use fingerprint::{derive_fingerprint, ArchitectureFingerprint};
pub use graph::ResearchGraph;
pub use node::{GraphNode, NodeKind};

pub const RESEARCH_GRAPH_CRATE: &str = "digger-research-graph";
pub const RESEARCH_GRAPH_VERSION: &str = env!("CARGO_PKG_VERSION");
