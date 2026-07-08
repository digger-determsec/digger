use serde::{Deserialize, Serialize};

/// Typed error for the op-layer crate.
#[derive(Debug, Clone, thiserror::Error)]
pub enum OpLayerError {
    #[error("parse failed: {0}")]
    ParseFailed(String),
    #[error("no handler functions found in source")]
    NoHandlers,
}

/// Deterministic, parsed-lite representation of a TS/Node source file
/// sufficient for the unverified-attestation detector.
///
/// **Limitations**: This is a structural pass that extracts function
/// definitions, their parameters, external-data reads, verification
/// calls, and privileged sinks. It does NOT perform full type inference,
/// control-flow analysis, or cross-module resolution. The detector
/// operates on the recovered structure and produces honest findings
/// scoped to what it can observe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpProgram {
    /// All handler/function definitions found in the source.
    pub handlers: Vec<Handler>,
    /// Raw source text for reference (deterministic, never used for substring matching in the detector).
    pub source_hash: String,
}

/// A handler function extracted from the source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Handler {
    pub name: String,
    /// Parameters the handler accepts (function signature).
    pub params: Vec<String>,
    /// External data reads: assignments from external sources (e.g. `const price = pyth.getPrice()`).
    pub external_reads: Vec<DataRead>,
    /// Verification/attestation checks present in the function body.
    pub verification_checks: Vec<VerificationCheck>,
    /// Allowlist/owner-check guards gating privileged sink targets.
    pub allowlist_checks: Vec<AllowlistCheck>,
    /// Safety-gate state reads (isReady, initialized, isHealthy, etc.).
    pub safety_gate_checks: Vec<SafetyGateCheck>,
    /// Permissive default returns (return true/false/0 in default branch).
    pub permissive_returns: Vec<PermissiveReturn>,
    /// Privileged sinks: state mutations, CPI calls, token transfers.
    pub privileged_sinks: Vec<PrivilegedSink>,
    /// Threshold adjustments / source-specific re-validation on fallback paths.
    pub threshold_adjustments: Vec<ThresholdAdjustment>,
    /// Dedicated init-guard checks for safety-gate state variables.
    pub init_guard_checks: Vec<InitGuardCheck>,
}

/// The semantic category of an external read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReadCategory {
    /// Oracle/price/attestation feeds (pyth, hermes, wormhole, etc.)
    ValueFeed,
    /// Config/routing/authority sources (fetchConfig, DB, env, request params)
    RoutingConfig,
    /// Safety-gate state reads (isReady, initialized, isHealthy, etc.)
    SafetyGateState,
    /// Fallback/failover source reads (catch, ??, dexscreener, backup, etc.)
    FailoverSource,
}

/// An external data read — a value sourced from outside the program boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataRead {
    /// Variable name the value is assigned to.
    pub variable: String,
    /// Source description (e.g. "pyth.get_price", "hermes_feed", "anchor_account").
    pub source: String,
    /// Semantic category: ValueFeed or RoutingConfig.
    pub category: ReadCategory,
    /// Line number in source (1-indexed, 0 if unknown).
    pub line: usize,
}

/// A verification/attestation check in the handler body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationCheck {
    /// What is being verified (e.g. "vaa_signature", "oracle_attestation", "signer").
    pub kind: String,
    /// The variable or value being verified.
    pub target: String,
    /// Line number.
    pub line: usize,
}

/// A privileged sink: a mutation or side-effect that should be gated by verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivilegedSink {
    /// Kind of sink (e.g. "token_transfer", "state_write", "cpi_call").
    pub kind: String,
    /// Line number.
    pub line: usize,
    /// If a sink argument traces to an external-read variable, record it here.
    pub target_variable: Option<String>,
}

/// An allowlist / owner-check guard in the handler body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowlistCheck {
    /// What kind of check (e.g. "includes_guard", "equality_guard").
    pub kind: String,
    /// The variable or value being guarded.
    pub target: String,
    /// Line number.
    pub line: usize,
}

/// A safety-gate state read — a boolean state check (isReady, initialized, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafetyGateCheck {
    /// Variable name or expression being checked.
    pub variable: String,
    /// What kind of gate (e.g. "readiness", "initialization", "health").
    pub kind: String,
    /// Line number.
    pub line: usize,
}

/// A permissive default return — a return statement with a permissive value
/// in the default/fallback branch of a safety gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissiveReturn {
    /// The permissive value returned (e.g. "true", "false", "0").
    pub value: String,
    /// Line number.
    pub line: usize,
}

/// A threshold adjustment or source-specific re-validation on a fallback path.
/// The dedicated suppressor for the silent-failover detector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThresholdAdjustment {
    /// What kind of adjustment (e.g. "tighten_threshold", "re_validate", "cross_check").
    pub kind: String,
    /// The variable or source being re-validated.
    pub target: String,
    /// Line number.
    pub line: usize,
}

/// A dedicated init-guard check — a pattern that explicitly checks/validates
/// a safety-gate state variable before the gate is used.
/// Examples: `require(initialized)`, `assert(isReady)`, `if (!x) throw`.
/// Used ONLY by the fail-open detector (NOT borrowed from verification_checks).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitGuardCheck {
    /// The variable being guarded (e.g. "isReady", "initialized").
    pub variable: String,
    /// What kind of guard (e.g. "require_guard", "assert_guard", "throw_guard").
    pub kind: String,
    /// Line number.
    pub line: usize,
}

/// A detection result from the op-layer detector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpViolation {
    /// Deterministic content-addressed id.
    pub id: String,
    /// The function containing the violation.
    pub function_id: String,
    /// Violation kind (e.g. "UnverifiedAttestation").
    pub violation_kind: String,
    /// Whether this violation was suppressed.
    pub suppressed: bool,
    /// Suppression reason if suppressed.
    pub suppression_reason: Option<String>,
    /// Provenance chain.
    pub provenance: String,
}

impl OpViolation {
    pub fn make_id(fn_id: &str, kind: &str, read_site: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        fn_id.hash(&mut h);
        kind.hash(&mut h);
        read_site.hash(&mut h);
        format!("op:{:016x}", h.finish())
    }
}
