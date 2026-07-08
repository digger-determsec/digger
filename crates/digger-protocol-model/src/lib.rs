#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

//! digger-protocol-model -- Generation 5 Phase A4: Deterministic Protocol Intelligence.
//!
//! Reconstruction answers "what exists?"; Protocol Intelligence answers "what
//! matters?". This crate sits immediately AFTER reconstruction and BEFORE
//! `SystemIR`:
//!
//! ```text
//! Evidence -> Reconstruction -> Recovered Architecture -> Protocol Model
//!   -> SystemIR -> Graph -> Gen 2 -> Gen 3 -> Gen 4
//! ```
//!
//! Everything here is DETERMINISTIC, reproducible, explainable, and derived
//! ONLY from recovered facts (`digger_reconstruct`). There is NO AI reasoning,
//! NO probabilistic inference, NO heuristic scoring, and NO speculative
//! conclusion. Every model object is a [`RecoveredFact`]: deterministic
//! content-addressed id + provenance + confidence + reproducibility key.
//!
//! The crate is blockchain-agnostic: its public types never name a chain.
//! Derivation consumes chain-agnostic recovered facts, so future Solana / Move
//! / WASM lifters feed the SAME model with no type changes.
//!
//! This phase reconstructs SEMANTICS; it does NOT analyze vulnerabilities and
//! never determines exploitability.

// Re-export the reconstruction primitives the model is built on, so downstream
// crates depend on one surface.
pub use ::digger_reconstruct::confidence::ConfidenceTier;
pub use ::digger_reconstruct::dependency::{DependencyKind, RecoveredDependency};
pub use ::digger_reconstruct::deployment::{
    AuthorityKind, DeploymentDetail, EvmDeployment, ProxyFamily, RecoveredAddress,
    RecoveredAuthority, RecoveredDeployment, SolanaDeployment, SolanaLoader,
};
pub use ::digger_reconstruct::fact::RecoveredFact;
pub use ::digger_reconstruct::interface::{
    InterfaceDetail, RecoveredAbi, RecoveredFunction, RecoveredInterface,
};
pub use ::digger_reconstruct::provenance::{
    EvidenceSource, Provenance, ReconstructionStage, ReproducibilityKey,
};

#[macro_use]
mod fact_impl;

pub mod actors;
pub mod assets;
pub mod attack_surface;
pub mod capability_graph;
pub mod dependencies;
pub mod economics;
pub mod ids;
pub mod invariants;
pub mod model;
pub mod permissions;
pub mod selectors;
pub mod state_machine;
pub mod trust;
pub mod upgrade;

#[cfg(test)]
mod tests;

pub use fact_impl::derive_provenance;

// Explicit re-exports of the intended public API types.
// Consumers should prefer importing via module paths (e.g.,
// `digger_protocol_model::model::ProtocolModel`) for clarity.
pub use actors::{Actor, ActorKind};
pub use assets::{Asset, AssetKind};
pub use attack_surface::{AttackSurface, SurfaceKind};
pub use capability_graph::{
    Capability, CapabilityEdge, CapabilityEdgeKind, CapabilityGraph, CapabilityKind,
};
pub use dependencies::normalize_dependencies;
pub use economics::{EconomicFlow, EconomicFlowKind};
pub use invariants::{InvariantCandidate, InvariantKind};
pub use model::{ProtocolModel, ProtocolModelInput};
pub use permissions::{Permission, PermissionAction};
pub use state_machine::{ProtocolState, StateMachine, StateMachineKind, StateTransition};
pub use trust::{TrustBoundary, TrustBoundaryKind, TrustGraph, TrustNode, TrustNodeKind};
pub use upgrade::{UpgradePath, UpgradePathStep};

/// Identifies the protocol-model algorithm for documentation / provenance notes.
pub const PROTOCOL_MODEL_CRATE: &str = "digger-protocol-model";
pub const PROTOCOL_MODEL_VERSION: &str = env!("CARGO_PKG_VERSION");
