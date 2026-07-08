#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Adversarial Modeling — Phase 11
///
/// Models attacker capabilities and searches for executions
/// that violate semantic constraints.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference, no heuristics
/// 3. Capabilities, not exploit signatures
/// 4. All outputs sorted and JSON serializable
/// 5. Consumes all Generation 1-2 semantic models
pub mod engine;
pub mod models;

pub use engine::{analyze_adversarial, report_from_json, report_to_json};
pub use models::*;
