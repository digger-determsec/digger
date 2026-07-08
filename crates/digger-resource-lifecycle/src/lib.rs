#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Resource Lifecycle — Phase 7.5
///
/// Behavioral analysis of economic resource movement through protocols.
/// Models how resources are consumed, produced, and transformed.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference, no heuristics
/// 3. Language-agnostic, protocol-agnostic
/// 4. All outputs sorted and JSON serializable
pub mod engine;
pub mod models;

pub use engine::{analyze_lifecycles, report_from_json, report_to_json, AnalysisError};
pub use models::*;
