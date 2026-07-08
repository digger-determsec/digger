#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod gate;
pub mod loader;
pub mod measure;
/// Digger Benchmark — Known Exploit Validation
///
/// Validates Digger against known exploits to measure detection capability.
///
/// # Rules
///
/// 1. Deterministic: same input → same output
/// 2. No AI, no probabilistic reasoning
/// 3. No modifications to frozen Phase 3 schemas
/// 4. Preserves all existing tests
pub mod models;
pub mod runner;

pub use gate::*;
pub use loader::findings_match;
pub use loader::load_corpus;
pub use loader::normalize_finding;
pub use models::*;
pub use runner::run_benchmark;
