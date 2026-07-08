#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]
#![allow(clippy::iter_cloned_collect, clippy::collapsible_if)]

pub mod extractor;
/// Phase 4.1 — Protocol Model Extractor
///
/// Semantic layer on top of deterministic outputs that models protocol intent.
///
/// # Rules
///
/// 1. Purely interpretive mapping — no new analysis
/// 2. Deterministic: same input → same output
/// 3. No AI, no LLMs
/// 4. Must NOT modify IR, graph engine, hypothesis engine, or session engine
/// 5. JSON serializable
pub mod models;

pub use extractor::extract;
pub use models::*;
