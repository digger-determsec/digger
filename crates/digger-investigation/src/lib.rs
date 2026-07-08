#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

//! digger-investigation -- Generation 5 Phase A5: Deterministic Investigation
//! Planner.
//!
//! Protocol understanding (Phase A4) answers "what matters?". The Investigation
//! Planner answers "what deserves investigation FIRST?" -- it models how elite
//! auditors prioritize research BEFORE analyzing exploitability. It sits
//! between the Protocol Model and `SystemIR`:
//!
//! ```text
//! Evidence -> Reconstruction -> Protocol Model -> Investigation Planner
//!   -> SystemIR -> Gen 2 -> Gen 3 -> Gen 4
//! ```
//!
//! The planner consumes ONLY deterministic [`ProtocolModel`] facts. It NEVER
//! analyzes exploitability, NEVER creates findings, and NEVER generates
//! hypotheses. It produces a deterministic [`InvestigationPlan`].
//!
//! Determinism contract (identical to the rest of Generation 5):
//! - No AI, no machine learning, no probabilistic ranking, no scoring.
//! - Priority is a deterministic, total ordering derived purely from integer
//!   fact counts (capability/permission/asset concentration, trust-boundary
//!   density, external-dependency count, upgrade complexity, cross-contract
//!   interaction density, state-machine complexity), compared lexicographically
//!   and tie-broken by a stable target-kind order then content-addressed id.
//! - Every [`InvestigationTarget`] is a [`RecoveredFact`]: deterministic
//!   content-addressed id + provenance + confidence + reproducibility key, and
//!   is fully explainable through its contributing fact ids.
//! - No duplicate IR, no alternate pipeline: the planner references
//!   ProtocolModel facts by id and stops at the plan object.
//! - Chain-agnostic: derivation consumes the chain-agnostic ProtocolModel, so
//!   all supported (and future) chains feed the same planner unchanged.

// One dependency surface for downstream crates.
pub use ::digger_protocol_model::model::ProtocolModel;
pub use ::digger_reconstruct::confidence::ConfidenceTier;
pub use ::digger_reconstruct::fact::RecoveredFact;
pub use ::digger_reconstruct::provenance::{
    EvidenceSource, Provenance, ReconstructionStage, ReproducibilityKey,
};

#[macro_use]
mod fact_impl;

pub mod ids;
pub mod plan;
pub mod planner;
pub mod priority;
pub mod scope;
pub mod target;

#[cfg(test)]
mod tests;

pub use plan::InvestigationPlan;
pub use planner::build_investigation_plan;
pub use priority::{FactorKind, PriorityFactor, PriorityKey, PriorityRank};
pub use scope::{ScopeBand, ScopeEstimate};
pub use target::{FactorInputs, InvestigationTarget, TargetKind, TargetSupport};

/// Crate identity recorded (indirectly, via reconstruction reproducibility keys)
/// for reproducibility metadata.
pub const INVESTIGATION_CRATE: &str = "digger-investigation";
pub const INVESTIGATION_VERSION: &str = env!("CARGO_PKG_VERSION");
