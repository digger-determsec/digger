#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

//! digger-reconstruct -- Generation 5 reconstruction front-end.
//!
//! This crate PRODUCES `digger_ir::SystemIR`; it never defines an alternate IR
//! and never re-implements the analysis pipeline (ADR-0008). The engine is
//! blockchain-agnostic: it depends only on the `BytecodeLifter` and
//! `InterfaceRecoverer` traits (ADR-0011, ADR-0013).
//!
//! # FROZEN at end of Generation 5 Phase A3 (ADR-0019)
//!
//! The reconstruction layer is FROZEN. It answers only "what exists?". No new
//! reconstruction feature, recovered-fact type, lifter, or recovery domain may
//! be added to this crate without an accepting ADR. Higher-level meaning --
//! "what matters?" -- belongs to `digger-protocol-model` (Phase A4) and beyond,
//! NOT here.

pub mod anchor;
pub mod body;
pub mod capabilities;
pub mod completeness;
pub mod confidence;
pub mod dep_recoverer;
pub mod dependency;
pub mod deployment;
pub mod digest;
pub mod engine;
pub mod engine_knowledge;
pub mod evidence;
pub mod evidence_requirement;
pub mod evm;
pub mod evm_ops;
pub mod explorer;
pub mod fact;
pub mod foundry;
pub mod hardhat;
pub mod ingest;
pub mod interface;
pub mod known_programs;
pub mod known_selectors;
pub mod lifter;
pub mod price_manipulation;
pub mod provenance;
pub mod providers;
pub mod readonly_reentrancy;
pub mod rpc;
pub mod solana;
pub mod solana_rpc;

pub use anchor::AnchorProject;
pub use body::{
    detect_and_suppress_cei, detect_cei_violations, detect_solana_access_violations,
    detect_type_cosplay, detect_unchecked_owner, detect_unvalidated_cpi, recover_source_body_graph,
    suppress_cei_violations, CeivViolation, RecoveredBody, RecoveredBodyGraph, RecoveredOperation,
    SolanaAccessViolation, TypeCosplayViolation, UncheckedOwnerViolation, UnvalidatedCpiViolation,
};
#[cfg(feature = "live-fetch")]
pub use explorer::EtherscanClient;
pub use explorer::{Chain, ExplorerError, FetchedSource, SourceFetcher};
pub use foundry::FoundryProject;
pub use hardhat::HardhatProject;
pub use price_manipulation::{detect_price_manipulation, PriceManipulationFinding};
pub use readonly_reentrancy::{detect_readonly_reentrancy, ReadonlyReentrancyFinding};
#[cfg(feature = "live-fetch")]
pub use solana_rpc::SolanaRpcClient;
pub use solana_rpc::{
    is_git_url, validate_program_id, FetchedSolanaProgram, SolanaSourceFetcher, SourceProvenance,
};

pub use completeness::*;
pub use confidence::*;
pub use dep_recoverer::{
    recover_dependencies_with, recover_solana_dependencies_with, DependencyRecoverer,
    EvmDependencyRecoverer, SolanaDependencyRecoverer,
};
pub use dependency::*;
pub use deployment::*;
pub use digest::*;
pub use engine::{
    lift_with, recover_deployment_with, recover_interface_with, ReconstructionEngine,
};
pub use engine_knowledge::*;
pub use evidence::*;
pub use evidence_requirement::*;
pub use evm::{
    recover_evm_deployment_via_provider, EvmAddressResolver, EvmBytecodeLifter,
    EvmDeploymentRecoverer, EvmInterfaceRecoverer, EvmResolutionEvidence, ResolvedHop,
};
pub use evm_ops::recover_evm_body_graph;
pub use fact::*;
pub use ingest::{
    ArtifactMetadata, FixtureAdapter, IngestionAdapter, IngestionArtifact, IngestionError,
    IngestionTarget,
};
pub use interface::*;
pub use lifter::*;
pub use provenance::*;
pub use providers::*;
pub use rpc::*;
pub use solana::*;

/// Identifies the reconstructor algorithm for reproducibility keys (ADR-0009).
pub const RECONSTRUCTOR_CRATE: &str = "digger-reconstruct";
pub const RECONSTRUCTOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Deterministic proxy recursion bound (ADR-0011).
pub const MAX_PROXY_DEPTH: u8 = 8;

/// Exact message emitted when the proxy recursion bound is exceeded (ADR-0011).
pub const MANUAL_REVIEW_PROXY_DEPTH: &str =
    "Manual Review Required \u{2014} proxy recursion exceeded deterministic limit.";
