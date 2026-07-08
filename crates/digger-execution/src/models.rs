/// Execution ordering models — checks-effects-interactions analysis.
///
/// All structures are deterministic and JSON serializable.
/// No AI, no inference, no heuristics, no scoring.
use serde::{Deserialize, Serialize};

/// Errors produced by the execution ordering engine.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExecutionError {
    /// The input JSON could not be deserialized into an execution report.
    #[error("Invalid report JSON: {0}")]
    InvalidReportJson(String),
}

/// Execution ordering report for a program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionReport {
    /// Protocol/program identifier.
    pub protocol_id: String,
    /// Per-function execution analysis.
    pub function_analyses: Vec<FunctionExecution>,
    /// Detected CEI violations.
    pub cei_violations: Vec<CEIViolation>,
    /// Summary statistics.
    pub summary: ExecutionSummary,
}

/// Execution analysis for a single function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FunctionExecution {
    /// Function name.
    pub function_name: String,
    /// Ordered operations in this function.
    pub ordered_operations: Vec<OperationEntry>,
    /// Whether this function has an external call.
    pub has_external_call: bool,
    /// Whether this function has a state write.
    pub has_state_write: bool,
    /// Whether this function has an authority check.
    pub has_authority_check: bool,
    /// Whether the external call occurs before a state write (CEI pattern).
    pub external_before_state_write: bool,
}

/// A single operation entry in execution order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OperationEntry {
    /// Sequence index (0-based).
    pub index: usize,
    /// Operation kind.
    pub kind: String,
    /// Target (state variable, call target, etc.).
    pub target: String,
}

/// A detected checks-effects-interactions violation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CEIViolation {
    /// Function name.
    pub function_name: String,
    /// Index of the external call that occurs before state write.
    pub external_call_index: usize,
    /// Index of the state write that occurs after the external call.
    pub state_write_index: usize,
    /// External call target.
    pub external_call_target: String,
    /// State variable being written.
    pub state_variable: String,
    /// Severity of the CEI violation.
    pub severity: digger_ir::Severity,
}

/// Summary statistics for execution analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionSummary {
    /// Total functions analyzed.
    pub total_functions: usize,
    /// Functions with external calls.
    pub functions_with_external_calls: usize,
    /// Functions with state writes.
    pub functions_with_state_writes: usize,
    /// Functions with CEI violations.
    pub functions_with_cei_violations: usize,
    /// Total CEI violations detected.
    pub total_cei_violations: usize,
}
