pub mod auth_boundary;
pub mod authority_analyzer;
pub mod authority_model;
pub mod authority_propagation;
pub mod cross_program;
/// Phase 2.2 — Structural Graph Analysis
///
/// This module provides multi-dimensional graph analysis over the existing
/// SystemIR. It does NOT modify SystemIR, add new IR types, or introduce
/// new edge types. All analysis is derived purely from traversal of existing
/// edges.
///
/// # Architecture
///
/// ```text
/// SystemIR (frozen)
///      ↓
/// ┌─────────────────────────────────┐
/// │  Graph Analysis Layer           │
/// │  (this module)                  │
/// │                                 │
/// │  execution.rs    — call chains  │
/// │  state_dep.rs    — state paths  │
/// │  auth_boundary.rs — auth gaps   │
/// │  authority_analyzer.rs — auth   │
/// │  cross_program.rs — unified CPI │
/// │  vuln_path.rs    — vuln paths   │
/// └─────────────────────────────────┘
///      ↓
/// Structured analysis results (read-only)
/// ```
///
/// # Rules
///
/// 1. Analysis reads SystemIR only — never writes to it
/// 2. No new IR types are introduced
/// 3. No language-specific behavior — all edges are treated uniformly
/// 4. All results are deterministic — no AI, no randomness
/// 5. No metadata is consumed — only IR edges matter
pub mod execution;
pub mod state_access;
pub mod state_dep;
pub mod vuln_path;

pub use auth_boundary::AuthorityBoundaryGraph;
pub use authority_analyzer::analyze_authority;
pub use authority_model::*;
pub use authority_propagation::propagate_authority;
pub use cross_program::CrossProgramGraph;
pub use execution::ExecutionGraph;
pub use state_access::{
    analyze_state_access, to_state_edges, StateAccess, StateAccessResult, StateAccessSummary,
    StateAccessType,
};
pub use state_dep::StateDependencyGraph;
pub use vuln_path::{VulnerabilityPath, VulnerabilityPathAnalysis};
