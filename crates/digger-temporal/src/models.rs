/// Temporal Reasoning models — multi-transaction analysis.
///
/// All structures are deterministic and JSON serializable.
/// No AI, no inference, no heuristics, no scoring.
use serde::{Deserialize, Serialize};

/// A single function call in a transaction sequence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionStep {
    /// Function name.
    pub function: String,
    /// Step index in the sequence (0-based).
    pub index: usize,
    /// State variables this step reads.
    pub reads: Vec<String>,
    /// State variables this step writes.
    pub writes: Vec<String>,
    /// Whether this step has an external call.
    pub has_external_call: bool,
    /// Whether this step has authority enforcement.
    pub has_authority: bool,
}

/// State at a point in a transaction sequence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateSnapshot {
    /// Step index.
    pub step_index: usize,
    /// State variable names that are relevant.
    pub relevant_vars: Vec<String>,
    /// Variables written by this step.
    pub writes: Vec<String>,
}

/// An ordering constraint between two functions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemporalDependency {
    /// The function that must come first.
    pub predecessor: String,
    /// The function that must come second.
    pub successor: String,
    /// State variable involved in the dependency.
    pub state_var: String,
    /// Why this dependency exists.
    pub reason: DependencyReason,
    /// Whether the protocol enforces this ordering.
    pub is_enforced: bool,
}

/// Why a temporal dependency exists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DependencyReason {
    /// State must be updated before it is read by successor.
    StateUpdateBeforeRead,
    /// Authority must be checked before state mutation.
    AuthorityBeforeMutation,
    /// External call must follow state update (CEI pattern).
    StateUpdateBeforeExternal,
    /// Custom ordering constraint.
    Custom(String),
}

impl std::fmt::Display for DependencyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateUpdateBeforeRead => write!(f, "state_update_before_read"),
            Self::AuthorityBeforeMutation => write!(f, "authority_before_mutation"),
            Self::StateUpdateBeforeExternal => write!(f, "state_update_before_external"),
            Self::Custom(s) => write!(f, "custom({})", s),
        }
    }
}

/// An ordered sequence of function calls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionSequence {
    /// Sequence identifier (deterministic).
    pub sequence_id: String,
    /// Ordered steps.
    pub steps: Vec<TransactionStep>,
    /// Temporal dependencies between steps.
    pub dependencies: Vec<TemporalDependency>,
    /// Whether all dependencies are satisfied.
    pub is_valid: bool,
}

/// A violation of a temporal constraint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemporalAnomaly {
    /// The sequence that violates the constraint.
    pub sequence_id: String,
    /// The anomaly kind.
    pub kind: AnomalyKind,
    /// The predecessor function.
    pub predecessor: String,
    /// The successor function.
    pub successor: String,
    /// State variable involved.
    pub state_var: String,
    /// Severity.
    pub severity: digger_ir::Severity,
}

/// Kind of temporal anomaly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalyKind {
    /// Ordering constraint violated.
    OrderingViolation,
    /// State is inconsistent after sequence.
    StateInconsistency,
    /// Reordering would violate safety.
    ReorderingAttack,
}

impl std::fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OrderingViolation => write!(f, "ordering_violation"),
            Self::StateInconsistency => write!(f, "state_inconsistency"),
            Self::ReorderingAttack => write!(f, "reordering_attack"),
        }
    }
}

/// The complete temporal analysis report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemporalReport {
    /// Protocol identifier.
    pub protocol_id: String,
    /// All discovered temporal dependencies.
    pub dependencies: Vec<TemporalDependency>,
    /// All transaction sequences analyzed.
    pub sequences: Vec<TransactionSequence>,
    /// All anomalies detected.
    pub anomalies: Vec<TemporalAnomaly>,
    /// Summary statistics.
    pub summary: TemporalSummary,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemporalSummary {
    /// Total sequences analyzed.
    pub total_sequences: usize,
    /// Total dependencies discovered.
    pub total_dependencies: usize,
    /// Total anomalies detected.
    pub total_anomalies: usize,
    /// Functions with temporal dependencies.
    pub functions_with_dependencies: usize,
}
