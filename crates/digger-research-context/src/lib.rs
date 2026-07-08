#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

//! digger-research-context -- Generation 5 Phase A7: Deterministic Research
//! Context Engine.
//!
//! A deterministic context assembler. Given the current [`ProtocolModel`] +
//! [`InvestigationPlan`] + a [`ResearchGraph`] (the long-term memory), select the
//! minimal RELEVANT subset and return one immutable, bounded [`ResearchContext`].
//!
//! ```text
//! Evidence -> Reconstruction -> Protocol Model -> Investigation Plan
//!   -> Research Graph -> Research Context -> SystemIR Bridge -> Gen 2
//! ```
//!
//! Models how an elite auditor reasons only over the relevant subset -- never
//! over everything. The context stores REFERENCES ONLY (ids, not full objects)
//! and records structured selection reasons explaining WHY each reference was
//! included.
//!
//! Determinism contract (identical to the rest of Generation 5):
//! - No AI, no machine learning, no probabilistic ranking, no scoring.
//! - Selection is equality-only: exact fingerprint equality, exact target-kind
//!   overlap, exact invariant/trust fingerprint equality.
//! - Every [`ResearchContext`] is a [`RecoveredFact`]: deterministic
//!   content-addressed id + provenance + confidence + reproducibility key.
//! - No duplicate IR, no alternate pipeline, no SystemIR construction.
//! - Chain-agnostic: derivation consumes chain-agnostic ProtocolModel,
//!   InvestigationPlan, and ResearchGraph.
//! - Never embeds or forwards the whole graph. Bounded output.

pub use ::digger_investigation::InvestigationPlan;
pub use ::digger_protocol_model::model::ProtocolModel;
pub use ::digger_reconstruct::confidence::ConfidenceTier;
pub use ::digger_reconstruct::fact::RecoveredFact;
pub use ::digger_reconstruct::provenance::{
    EvidenceSource, Provenance, ReconstructionStage, ReproducibilityKey,
};
pub use ::digger_research_graph::graph::ResearchGraph;

#[macro_use]
mod fact_impl;

pub mod context;
pub mod ids;
pub mod selection;

#[cfg(test)]
mod tests;

pub use context::{assemble_research_context, ResearchContext};
pub use selection::{SelectionFilter, SelectionReason};

pub const RESEARCH_CONTEXT_CRATE: &str = "digger-research-context";
pub const RESEARCH_CONTEXT_VERSION: &str = env!("CARGO_PKG_VERSION");
