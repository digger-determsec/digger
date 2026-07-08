/// Cross-Function Expansion models.
///
/// All structures are deterministic and JSON serializable.
/// No AI, no inference, no heuristics, no scoring.
use serde::{Deserialize, Serialize};

/// Errors for expansion report serialization.
#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("Invalid report JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

/// Expanded operation — an operation that may have originated from a callee.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpandedOperation {
    /// Sequence index in the expanded stream (0-based).
    pub index: usize,
    /// Operation kind.
    pub kind: String,
    /// Target (state variable, call target, etc.).
    pub target: String,
    /// Function where this operation was originally defined.
    pub origin_function: String,
    /// Call chain from the root caller to this operation.
    pub call_chain: Vec<String>,
}

/// Expansion trace — explains how an expanded operation was produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpansionTrace {
    /// The caller function.
    pub caller_function: String,
    /// The callee function being expanded.
    pub callee_function: String,
    /// Depth of the expansion (0 = direct call from root).
    pub depth: usize,
    /// Indices of operations contributed by this expansion.
    pub operation_indices: Vec<usize>,
}

/// Expansion cycle — detected recursion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpansionCycle {
    /// The cycle path (A -> B -> A).
    pub cycle_path: Vec<String>,
}

/// Expanded CEI violation — detected after cross-function expansion.
///
/// Contains a base CEIViolation plus origin tracking for cross-function analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpandedCEIViolation {
    /// The base CEI violation (shared fields).
    #[serde(flatten)]
    pub base: digger_execution::CEIViolation,
    /// Function where the external call originates.
    pub external_call_origin: String,
    /// Function where the state write originates.
    pub state_write_origin: String,
}

/// Expansion report — top-level result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpansionReport {
    /// Protocol identifier.
    pub protocol_id: String,
    /// Per-function expanded operation streams.
    pub expanded_functions: Vec<ExpandedFunctionStream>,
    /// Detected expansion cycles.
    pub cycles: Vec<ExpansionCycle>,
    /// Expansion traces.
    pub traces: Vec<ExpansionTrace>,
    /// CEI violations detected after expansion.
    pub expanded_cei_violations: Vec<ExpandedCEIViolation>,
    /// Summary.
    pub summary: ExpansionSummary,
}

/// Expanded operation stream for a single function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpandedFunctionStream {
    /// Root function name.
    pub function_name: String,
    /// Expanded operations (inlined from callees).
    pub operations: Vec<ExpandedOperation>,
    /// Whether this function had any internal calls expanded.
    pub has_expansions: bool,
    /// Maximum expansion depth.
    pub max_depth: usize,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpansionSummary {
    /// Total functions analyzed.
    pub total_functions: usize,
    /// Functions with expansions.
    pub functions_with_expansions: usize,
    /// Total expansion traces.
    pub total_traces: usize,
    /// Total cycles detected.
    pub total_cycles: usize,
    /// Total expanded CEI violations.
    pub total_expanded_cei_violations: usize,
}
