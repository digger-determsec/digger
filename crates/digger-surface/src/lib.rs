#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Phase 2.3 — Security Intelligence Surface Layer
///
/// This layer turns deterministic graph results into structured, usable
/// security intelligence views. It does NOT improve detection logic,
/// add new vulnerability classes, or modify analysis behavior.
///
/// # Architecture
///
/// ```text
/// Graph Analysis (Phase 2.2)
///      ↓
/// ┌─────────────────────────────────┐
/// │  Surface Layer (this crate)     │
/// │                                 │
/// │  attack_surface  — aggregation  │
/// │  path_standard   — formatting   │
/// │  risk_grouping   — clustering   │
/// │  cross_protocol  — unification  │
/// │  schema          — output types │
/// └─────────────────────────────────┘
///      ↓
/// Structured, UI-ready security intelligence
/// ```
///
/// # Rules
///
/// 1. Surface layer READS graph outputs only — never modifies them
/// 2. No new analysis algorithms — only aggregation and formatting
/// 3. No scoring — only structural grouping
/// 4. No AI / probabilistic reasoning
/// 5. All output is deterministic
pub mod attack_surface;
pub mod cross_protocol;
pub mod evidence;
pub mod path_standard;
pub mod risk_grouping;
pub mod schema;

pub use attack_surface::AttackSurface;
pub use cross_protocol::CrossProtocolView;
pub use evidence::{EvidenceAction, EvidenceChain, EvidenceStep};
pub use path_standard::StandardizedPaths;
pub use risk_grouping::RiskGroups;
pub use schema::*;
