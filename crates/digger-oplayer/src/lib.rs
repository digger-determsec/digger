#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod detector;
pub mod parser;
pub mod types;

pub use detector::{
    detect_control_plane_authority, detect_fail_open_bootstrap, detect_silent_failover,
    detect_unverified_attestation,
};
pub use parser::parse_op_program;
pub use types::{
    AllowlistCheck, DataRead, Handler, InitGuardCheck, OpProgram, OpViolation, PermissiveReturn,
    PrivilegedSink, ReadCategory, SafetyGateCheck, ThresholdAdjustment, VerificationCheck,
};
