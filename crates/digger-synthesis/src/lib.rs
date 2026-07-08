#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod attack_plan;
pub mod chain;
pub mod confirmation;
pub mod differential;
pub mod economic;
pub mod elimination;
pub mod engine;
pub mod execution_engine;
pub mod execution_prep;
pub mod exporters;
pub mod feasibility;
/// Generation 3 — Exploit Synthesis Engine
///
/// Builds on Gen 1 (static analysis) and Gen 2 (reasoning engine) to
/// deterministically synthesize complete exploit chains from evidence.
///
/// # Architecture
///
/// Gen 3 does NOT replace Gen 1 or Gen 2. It consumes their outputs:
/// - SystemIR + graph analyses (Gen 1)
/// - Hypotheses, capabilities, evidence graphs (Gen 2)
/// - Knowledge graph, protocol packs, ingestion corpus
///
/// And produces:
/// - Complete exploit chains with ordered steps
/// - Logical simulations of exploit progression
/// - Assumption-validated attack plans
/// - Ranked exploit explanations with provenance
pub mod models;
pub mod preconditions;
pub mod prep_validation;
pub mod ranking;
pub mod replay;
pub mod search;
pub mod simulation;
pub mod simulation_plan;
pub mod state_validation;
pub mod transaction_builders;
pub mod validation;

pub use confirmation::confirm_exploit;
pub use engine::synthesize;
pub use execution_engine::execute_exploit;
pub use execution_prep::prepare_execution;
pub use models::*;
pub use validation::validate_exploit;
