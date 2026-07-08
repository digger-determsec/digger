#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Verification — Phase 7.6
///
/// Verifier-agnostic Verification IR for Generation 1 completion.
/// Generates structured verification properties from semantic models.
/// No specific verification backend dependency.
///
/// # Dependency Direction
///
/// This crate depends ONLY on lower-layer semantic models:
/// - digger-graph (AuthorityGraph)
/// - digger-execution (CEIViolation)
/// - digger-state-transitions (StateTransitionReport)
/// - digger-resource-lifecycle (ResourceLifecycleReport)
///
/// Lower layers must NEVER depend on this crate.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no inference, no heuristics
/// 3. Properties generated from semantic models only, never from source/AST
/// 4. All outputs sorted and JSON serializable
/// 5. Backend-agnostic: no SMT solver, symbolic executor, or model checker
pub mod generator;
pub mod models;

pub use generator::generate_properties;
pub use models::*;
