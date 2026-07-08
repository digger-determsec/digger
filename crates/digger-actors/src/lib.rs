#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Multi-Actor Reasoning — Phase 9
///
/// Identifies actor roles, detects shared state interactions,
/// and flags adversarial patterns.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference, no heuristics
/// 3. Bounded: max 5 actors, max 100 interactions
/// 4. All outputs sorted and JSON serializable
/// 5. Builds on Phase 8 temporal reasoning
pub mod engine;
pub mod models;

pub use engine::{analyze_actors, report_from_json, report_to_json, AnalysisError};
pub use models::*;
