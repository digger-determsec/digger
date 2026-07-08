/// Verification IR — verifier-agnostic verification property models.
///
/// All structures are deterministic and JSON serializable.
/// No AI, no inference, no heuristics, no scoring.
/// No specific verification backend dependency.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A structured verification property derived from semantic analysis.
///
/// This is the canonical output of the verification boundary.
/// Any verification backend can consume this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationProperty {
    /// Unique property identifier (deterministic).
    pub property_id: String,
    /// Property kind.
    pub kind: PropertyKind,
    /// Which semantic subsystem generated this property.
    pub origin: PropertyOrigin,
    /// Human-readable description.
    pub description: String,
    /// The function(s) this property applies to.
    pub scope: Vec<String>,
    /// The state variable(s) involved.
    pub state_vars: Vec<String>,
    /// Structured predicate.
    pub predicate: Predicate,
    /// Evidence supporting this property.
    pub evidence: Vec<EvidenceRef>,
    /// Severity if violated.
    pub severity: digger_ir::Severity,
}

/// Kind of verification property.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PropertyKind {
    /// Authority must be enforced before action.
    AuthorityInvariant,
    /// State must be updated after external effect.
    AccountingInvariant,
    /// Operation ordering constraint.
    OrderingConstraint,
    /// Resource conservation law.
    ConservationLaw,
    /// Access control requirement.
    AccessControlRequirement,
    /// Custom property from user annotation.
    Custom,
}

impl std::fmt::Display for PropertyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthorityInvariant => write!(f, "authority_invariant"),
            Self::AccountingInvariant => write!(f, "accounting_invariant"),
            Self::OrderingConstraint => write!(f, "ordering_constraint"),
            Self::ConservationLaw => write!(f, "conservation_law"),
            Self::AccessControlRequirement => write!(f, "access_control_requirement"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// Which semantic subsystem generated a VerificationProperty.
///
/// Enables debugging, audit reporting, regression analysis,
/// and future AI-assisted reasoning without coupling to any backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PropertyOrigin {
    /// Generated from AuthorityGraph analysis.
    AuthorityGraph,
    /// Generated from StateTransition analysis.
    StateTransition,
    /// Generated from ResourceLifecycle analysis.
    ResourceLifecycle,
    /// Generated from CEI violation detection.
    ExecutionOrdering,
    /// Generated from cross-program analysis.
    CrossProgramAnalysis,
    /// Generated from multiple sources.
    Composite(Vec<PropertyOrigin>),
}

impl std::fmt::Display for PropertyOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthorityGraph => write!(f, "authority_graph"),
            Self::StateTransition => write!(f, "state_transition"),
            Self::ResourceLifecycle => write!(f, "resource_lifecycle"),
            Self::ExecutionOrdering => write!(f, "execution_ordering"),
            Self::CrossProgramAnalysis => write!(f, "cross_program_analysis"),
            Self::Composite(origins) => {
                let parts: Vec<String> = origins.iter().map(|o| o.to_string()).collect();
                write!(f, "composite({})", parts.join(", "))
            }
        }
    }
}

/// A structured predicate for formal verification.
///
/// Machine-parseable expression that a verifier can evaluate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Predicate {
    /// Always(condition) — must hold on every execution.
    Always(Box<Condition>),
    /// Eventually(condition) — must hold on some execution.
    Eventually(Box<Condition>),
    /// Before(op_a, op_b) — op_a must precede op_b.
    Before(String, String),
    /// After(op_a, op_b) — op_a must follow op_b.
    After(String, String),
    /// Implies(condition_a, condition_b) — if A then B.
    Implies(Box<Condition>, Box<Condition>),
    /// Not(condition) — must NOT hold.
    Not(Box<Condition>),
    /// And(conditions) — all must hold.
    And(Vec<Condition>),
    /// Or(conditions) — at least one must hold.
    Or(Vec<Condition>),
}

/// A condition within a predicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Condition {
    /// Function has authority check.
    HasAuthority { function: String },
    /// Function has state write to variable.
    HasStateWrite { function: String, state_var: String },
    /// Function has external call.
    HasExternalCall { function: String },
    /// Function has value transfer.
    HasValueTransfer { function: String },
    /// State variable is read before written.
    ReadBeforeWrite { function: String, state_var: String },
    /// External call occurs between read and write.
    ExternalBetweenReadWrite { function: String, state_var: String },
    /// Operation A precedes operation B.
    Precedes { op_a: String, op_b: String },
    /// State variable has been written.
    StateWritten { state_var: String },
    /// Custom condition with string expression.
    Custom(String),
}

/// Reference to evidence supporting a verification property.
///
/// Links back to specific semantic model objects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceRef {
    /// Reference to an AuthorityRelation.
    Authority { function: String, source: String },
    /// Reference to a StateTransition.
    StateTransition {
        function: String,
        state_var: String,
        kind: String,
    },
    /// Reference to a LifecyclePhase.
    LifecyclePhase {
        function: String,
        kind: String,
        index: usize,
    },
    /// Reference to an OperationEntry.
    Operation {
        function: String,
        index: usize,
        kind: String,
    },
    /// Custom evidence string.
    Custom(String),
}

/// The complete verification boundary output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationReport {
    /// Protocol identifier.
    pub protocol_id: String,
    /// All verification properties.
    pub properties: Vec<VerificationProperty>,
    /// Summary statistics.
    pub summary: VerificationSummary,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationSummary {
    /// Total properties generated.
    pub total_properties: usize,
    /// Properties by kind.
    pub by_kind: BTreeMap<String, usize>,
    /// Properties by origin.
    pub by_origin: BTreeMap<String, usize>,
    /// Properties by severity.
    pub by_severity: BTreeMap<String, usize>,
}

/// Result from an external verification backend.
///
/// Digger defines the interface; backends implement it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationResult {
    /// Property ID this result corresponds to.
    pub property_id: String,
    /// Verification status.
    pub status: VerificationStatus,
    /// Counter-example if status is Violated.
    pub counterexample: Option<Counterexample>,
    /// Proof artifact if status is Holds.
    pub proof_artifact: Option<String>,
    /// Backend identifier.
    pub backend: String,
    /// Deterministic result hash.
    pub result_hash: String,
}

/// Verification status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationStatus {
    /// Property holds for all executions.
    Holds,
    /// Property violated — counterexample provided.
    Violated,
    /// Engine could not determine (timeout, undecidable).
    Unknown,
}

/// Counter-example from a verification violation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Counterexample {
    /// Function where violation occurs.
    pub function: String,
    /// Operation index of the violation.
    pub operation_index: usize,
    /// Description of the violation.
    pub description: String,
    /// State variable values at violation point (if available).
    pub state_snapshot: BTreeMap<String, String>,
}
