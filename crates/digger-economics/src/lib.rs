#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Economic Semantics — Phase 10
///
/// Behavioral economic constraint inference.
/// Derives economic relationships from state transitions, resource lifecycles,
/// execution ordering, and temporal dependencies.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference beyond structural patterns
/// 3. Economic meaning from behavioral relationships, not variable names
/// 4. All outputs sorted and JSON serializable
/// 5. Builds on Phase 8 (temporal) and Phase 9 (actors)
pub mod engine;
pub mod models;

pub use engine::{analyze_economics, report_from_json, report_to_json, AnalysisError};
pub use models::*;
