#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod crucible;
pub mod echidna;
pub mod foundry;
pub mod medusa;
pub(crate) mod parser_util;
pub mod scanner;
pub use crucible::{parse_crucible_failure, parse_crucible_failure_file};
pub use echidna::{parse_echidna_failure, parse_echidna_failure_file};
pub use foundry::{parse_foundry_failure, parse_foundry_failure_file, FuzzEvidenceReport};
pub use medusa::{parse_medusa_failure, parse_medusa_failure_file};
pub use scanner::{scan_fuzzing_maturity, MaturityReport, VacuityWarning};
