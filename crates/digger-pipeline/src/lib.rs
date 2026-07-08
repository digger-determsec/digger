#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

//! Generation 5 — the single, blockchain-agnostic deterministic investigation
//! orchestrator (ADR-0025). Chain-specific logic lives ONLY in reconstruction
//! providers/recoverers; everything in this crate is target-agnostic.

pub mod analyze;
pub mod reconstruct;
pub mod source;
pub mod spine;

/// A supported blockchain target. This enum is the ONLY place targets are
/// enumerated above reconstruction; it keys provider/recoverer selection during
/// evidence collection (C1.2) and never leaks chain-specific behavior upward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    Evm,
    Solana,
}

impl Target {
    pub fn label(&self) -> &'static str {
        match self {
            Target::Evm => "evm",
            Target::Solana => "solana",
        }
    }
}

// Re-export the most common entry points at crate root for convenience.
pub use analyze::{
    analyze, analyze_systems, investigate_and_analyze, InvestigationOutcome, SystemAnalysis,
};
pub use reconstruct::{investigate, EvidenceInput, ReconstructError};
pub use source::{investigate_source, investigate_source_with_corpus};
pub use spine::{run_gen5_spine, Gen5Spine, RecoveredFacts};
