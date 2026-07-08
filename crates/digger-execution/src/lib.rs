#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Execution Ordering — Phase 6.3
///
/// Analyzes the ordered operations within each function to detect
/// checks-effects-interactions (CEI) violations.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference, no heuristics
/// 3. Does NOT modify frozen SystemIR
/// 4. All outputs are JSON serializable
/// 5. Operations come from parser (AST-based, not substring matching)
pub mod engine;
pub mod models;

pub use engine::{analyze_execution, report_from_json, report_to_json};
pub use models::*;
