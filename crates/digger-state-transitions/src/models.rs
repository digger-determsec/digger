/// State Transition models — behavioral analysis of how state changes.
///
/// All structures are deterministic and JSON serializable.
/// No AI, no inference, no heuristics, no scoring.
use serde::{Deserialize, Serialize};

/// A state transition — the canonical representation of how state changes.
///
/// This is the primary data model for Phase 7.4.
/// All downstream analysis derives from this structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateTransition {
    /// State variable identifier.
    pub state_var: String,
    /// Function performing the transition.
    pub function: String,
    /// The transition kind.
    pub kind: TransitionKind,
    /// Operation index in the execution stream.
    pub operation_index: usize,
    /// Whether a state read of this variable precedes the write.
    pub read_before_write: bool,
    /// Whether an external effect occurs between read and write.
    pub external_between_read_write: bool,
    /// Whether an authority check precedes the transition.
    pub authority_before_transition: bool,
    /// Whether this transition is inside a conditional branch.
    pub is_conditional: bool,
    /// The value expression (if extractable from AST).
    pub value_expression: Option<String>,
}

/// The kind of state transition — derived from AST, not from naming.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransitionKind {
    /// Simple assignment: x = value
    Assignment,
    /// Increment: x += value, x++
    Increment,
    /// Decrement: x -= value, x--
    Decrement,
    /// Toggle: x = !x
    Toggle,
    /// Initialization: first write to a variable
    Initialization,
    /// Deletion: delete x
    Deletion,
    /// Compound: other compound assignments
    Compound,
}

impl std::fmt::Display for TransitionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Assignment => write!(f, "assignment"),
            Self::Increment => write!(f, "increment"),
            Self::Decrement => write!(f, "decrement"),
            Self::Toggle => write!(f, "toggle"),
            Self::Initialization => write!(f, "initialization"),
            Self::Deletion => write!(f, "deletion"),
            Self::Compound => write!(f, "compound"),
        }
    }
}

/// A missing state transition — a function that should write but doesn't.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MissingTransition {
    /// Function name.
    pub function: String,
    /// State variable that should have been written.
    pub expected_state_var: String,
    /// Why the transition is expected.
    pub reason: MissingTransitionReason,
    /// Severity.
    pub severity: digger_ir::Severity,
}

/// Why a state transition is expected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MissingTransitionReason {
    /// Function has external effect but no state write.
    ExternalEffectWithoutWrite,
    /// Function reads state for computation but doesn't write back.
    ReadWithoutWrite,
}

impl std::fmt::Display for MissingTransitionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExternalEffectWithoutWrite => write!(f, "external_effect_without_write"),
            Self::ReadWithoutWrite => write!(f, "read_without_write"),
        }
    }
}

/// The canonical state transition report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateTransitionReport {
    /// Protocol identifier.
    pub protocol_id: String,
    /// All detected state transitions.
    pub transitions: Vec<StateTransition>,
    /// Missing transitions (expected but absent).
    pub missing_transitions: Vec<MissingTransition>,
    /// Summary statistics.
    pub summary: StateTransitionSummary,
}

/// Summary statistics for state transition analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateTransitionSummary {
    /// Total transitions detected.
    pub total_transitions: usize,
    /// Total missing transitions detected.
    pub total_missing: usize,
    /// Transitions with external effects between read and write.
    pub transitions_with_external_between: usize,
    /// Transitions without authority.
    pub transitions_without_authority: usize,
    /// Functions with missing transitions.
    pub functions_with_missing: usize,
}
