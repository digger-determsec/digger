/// Economic Semantics models — behavioral economic constraint inference.
///
/// All structures are deterministic and JSON serializable.
/// No AI, no inference beyond structural patterns, no heuristics.
/// Economic meaning comes entirely from behavioral relationships.
use serde::{Deserialize, Serialize};

/// An economic relation — the canonical abstraction for economic constraints.
///
/// Every economic relationship is expressed as an EconomicRelation.
/// Specialized variants provide semantic precision without protocol-specific assumptions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EconomicRelation {
    /// Relation identifier (deterministic).
    pub relation_id: String,
    /// The relation variant.
    pub kind: EconomicRelationKind,
    /// State variables involved.
    pub state_vars: Vec<String>,
    /// Functions that participate in this relation.
    pub functions: Vec<String>,
    /// Evidence supporting this relation.
    pub evidence: Vec<String>,
    /// Whether the relation is currently satisfied.
    pub is_satisfied: bool,
}

/// Kind of economic relation.
///
/// Each variant represents a fundamental economic constraint pattern.
/// All inference is behavioral — no naming heuristics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EconomicRelationKind {
    /// Conservation: a quantity is preserved across operations.
    /// Inferred from: variable incremented by some functions, decremented by others.
    Conservation(ConservationRelation),

    /// Collateral: one variable constrains another.
    /// Inferred from: function reads both variables and enforces a relationship.
    Collateral(CollateralRelation),

    /// Debt: one variable represents an obligation.
    /// Inferred from: variable increased by some functions, decreased by others,
    /// with corresponding asset flows.
    Debt(DebtRelation),

    /// Dependency: one economic quantity constrains or influences another.
    /// Inferred from: function reads both variables without ownership/obligation.
    /// Examples: utilization → interest rate, reserve ratio → withdrawal limit.
    Dependency(DependencyRelation),
}

/// Conservation relation — a quantity is preserved.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConservationRelation {
    /// The conserved state variable.
    pub conserved_var: String,
    /// Functions that increase the quantity.
    pub inflow_functions: Vec<String>,
    /// Functions that decrease the quantity.
    pub outflow_functions: Vec<String>,
}

/// Collateral relation — one variable constrains another.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CollateralRelation {
    /// The collateral variable.
    pub collateral_var: String,
    /// The constrained variable.
    pub constrained_var: String,
    /// Functions that enforce this constraint.
    pub enforcing_functions: Vec<String>,
}

/// Debt relation — one variable represents an obligation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DebtRelation {
    /// The debt variable.
    pub debt_var: String,
    /// Functions that create debt.
    pub borrowing_functions: Vec<String>,
    /// Functions that reduce debt.
    pub repayment_functions: Vec<String>,
}

/// Dependency relation — one quantity constrains or influences another.
///
/// This is the most general relation type. It captures cases where
/// one economic quantity affects another without implying ownership or obligation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DependencyRelation {
    /// The influencing variable.
    pub influencer: String,
    /// The influenced variable.
    pub influenced: String,
    /// Functions where the dependency manifests.
    pub functions: Vec<String>,
    /// Whether the dependency is directional (influencer → influenced).
    pub is_directional: bool,
}

/// Economic invariant — a constraint that must hold for economic soundness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EconomicInvariant {
    /// Invariant identifier (deterministic).
    pub invariant_id: String,
    /// State variables involved.
    pub state_vars: Vec<String>,
    /// Functions that must preserve this invariant.
    pub functions: Vec<String>,
    /// Invariant kind.
    pub kind: InvariantKind,
    /// Whether the invariant is currently satisfied.
    pub is_satisfied: bool,
    /// Evidence supporting this invariant.
    pub evidence: Vec<String>,
}

/// Kind of economic invariant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InvariantKind {
    /// Conservation: total quantity is preserved.
    Conservation,
    /// Solvency: assets >= liabilities.
    Solvency,
    /// Collateralization: collateral >= debt * factor.
    Collateralization,
    /// Accounting: debits == credits.
    Accounting,
}

impl std::fmt::Display for InvariantKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conservation => write!(f, "conservation"),
            Self::Solvency => write!(f, "solvency"),
            Self::Collateralization => write!(f, "collateralization"),
            Self::Accounting => write!(f, "accounting"),
        }
    }
}

/// The complete economic analysis report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EconomicReport {
    /// Protocol identifier.
    pub protocol_id: String,
    /// All discovered economic relations.
    pub relations: Vec<EconomicRelation>,
    /// All discovered economic invariants.
    pub invariants: Vec<EconomicInvariant>,
    /// Summary statistics.
    pub summary: EconomicSummary,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EconomicSummary {
    /// Total relations discovered.
    pub total_relations: usize,
    /// Relations by kind.
    pub conservation_count: usize,
    pub collateral_count: usize,
    pub debt_count: usize,
    pub dependency_count: usize,
    /// Total invariants discovered.
    pub total_invariants: usize,
    /// Invariants currently satisfied.
    pub satisfied_invariants: usize,
    /// Invariants currently violated.
    pub violated_invariants: usize,
}
