#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Temporal Reasoning — Phase 8
///
/// Multi-transaction analysis: understanding how protocol state
/// evolves across transaction boundaries.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference, no heuristics
/// 3. Bounded: max 2 transactions per sequence, max 100 sequences
/// 4. All outputs sorted and JSON serializable
/// 5. Consumes Generation 1 models, does not modify them
pub mod engine;
pub mod models;

pub use engine::{analyze_temporal, report_from_json, report_to_json, AnalysisError};
pub use models::*;
