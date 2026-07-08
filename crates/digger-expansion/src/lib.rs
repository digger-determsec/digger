#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]
#![allow(
    clippy::for_kv_map,
    clippy::clone_on_copy,
    clippy::too_many_arguments,
    clippy::only_used_in_recursion
)]

/// Cross-Function Expansion — Phase 6.4
///
/// Expands internal calls to reveal operations hidden inside callee functions.
/// Enables cross-function CEI violation detection.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference, no heuristics
/// 3. No symbolic execution, no path solving
/// 4. Cycle detection prevents infinite recursion
/// 5. All outputs sorted and JSON serializable
pub mod engine;
pub mod models;

pub use engine::{expand_program, report_from_json, report_to_json};
pub use models::*;
