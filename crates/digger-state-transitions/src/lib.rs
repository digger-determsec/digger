#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// State Transitions — Phase 7.4
///
/// Behavioral analysis of how state changes.
/// Detects present transitions and missing transitions.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference, no heuristics
/// 3. Behavioral analysis, not naming heuristics
/// 4. All outputs sorted and JSON serializable
pub mod engine;
pub mod models;

pub use engine::{analyze_transitions, report_from_json, report_to_json, AnalysisError};
pub use models::*;
