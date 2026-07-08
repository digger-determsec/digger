#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]
#![allow(
    clippy::redundant_field_names,
    clippy::unnecessary_sort_by,
    clippy::if_same_then_else
)]

/// Protocol Analysis — cross-program reasoning layer.
///
/// Analyzes multiple contracts within a protocol to detect
/// storage collisions, proxy patterns, and cross-program vulnerabilities.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference, no heuristics
/// 3. Does NOT modify frozen SystemIR
/// 4. All outputs are JSON serializable
pub mod analyzer;
pub mod models;

pub use analyzer::{analyze_programs, analyze_protocol};
pub use models::*;
