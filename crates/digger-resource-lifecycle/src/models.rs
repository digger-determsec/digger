/// Resource Lifecycle models — behavioral analysis of economic resource movement.
///
/// All structures are deterministic and JSON serializable.
/// No AI, no inference, no heuristics, no scoring.
/// Language-agnostic, protocol-agnostic.
use serde::{Deserialize, Serialize};

/// The lifecycle of an economic resource through a protocol function.
///
/// This is the canonical representation of how a resource is
/// consumed, produced, or transformed by a function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceLifecycle {
    /// Function performing the lifecycle.
    pub function: String,
    /// State variable(s) that track this resource.
    pub tracking_vars: Vec<String>,
    /// Lifecycle phases observed in this function.
    pub phases: Vec<LifecyclePhase>,
    /// Whether the lifecycle is complete (all expected phases present).
    pub is_complete: bool,
    /// Anomalies detected in this lifecycle.
    pub anomalies: Vec<LifecycleAnomaly>,
}

/// A phase in the lifecycle of an economic resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecyclePhase {
    /// Phase kind.
    pub kind: PhaseKind,
    /// Operation index in the execution stream.
    pub operation_index: usize,
    /// State variable involved (if any).
    pub state_var: Option<String>,
    /// External target involved (if any).
    pub external_target: Option<String>,
    /// Whether authority is enforced before this phase.
    pub authority_enforced: bool,
}

/// Kind of lifecycle phase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PhaseKind {
    /// Authority check before resource movement.
    Authorization,
    /// Resource enters the protocol (deposit, receive, mint).
    Ingress,
    /// Internal accounting update (balance += amount).
    AccountingUpdate,
    /// State transition (non-accounting state change).
    StateTransition,
    /// Settlement (finalizing a resource movement).
    Settlement,
    /// Resource leaves the protocol (withdraw, transfer, burn).
    Egress,
}

impl std::fmt::Display for PhaseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authorization => write!(f, "authorization"),
            Self::Ingress => write!(f, "ingress"),
            Self::AccountingUpdate => write!(f, "accounting_update"),
            Self::StateTransition => write!(f, "state_transition"),
            Self::Settlement => write!(f, "settlement"),
            Self::Egress => write!(f, "egress"),
        }
    }
}

/// An anomaly in a resource lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecycleAnomaly {
    /// Anomaly kind.
    pub kind: AnomalyKind,
    /// Operation index where the anomaly occurs.
    pub operation_index: usize,
    /// Severity.
    pub severity: digger_ir::Severity,
    /// Description.
    pub description: String,
}

/// Kind of lifecycle anomaly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalyKind {
    /// Resource leaves without authorization.
    UnauthorizedEgress,
    /// Resource enters without accounting update.
    IngressWithoutAccounting,
    /// Resource leaves without accounting decrease.
    EgressWithoutAccountingDecrease,
    /// External effect between accounting read and write.
    AccountingIntegrityRisk,
    /// Resource movement without corresponding state change.
    UntrackedMovement,
}

impl std::fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnauthorizedEgress => write!(f, "unauthorized_egress"),
            Self::IngressWithoutAccounting => write!(f, "ingress_without_accounting"),
            Self::EgressWithoutAccountingDecrease => {
                write!(f, "egress_without_accounting_decrease")
            }
            Self::AccountingIntegrityRisk => write!(f, "accounting_integrity_risk"),
            Self::UntrackedMovement => write!(f, "untracked_movement"),
        }
    }
}

/// The canonical resource lifecycle report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceLifecycleReport {
    /// Protocol identifier.
    pub protocol_id: String,
    /// All detected resource lifecycles.
    pub lifecycles: Vec<ResourceLifecycle>,
    /// Summary statistics.
    pub summary: LifecycleSummary,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecycleSummary {
    /// Total lifecycles detected.
    pub total_lifecycles: usize,
    /// Total anomalies detected.
    pub total_anomalies: usize,
    /// Functions with anomalies.
    pub functions_with_anomalies: usize,
    /// Complete lifecycles (all phases present).
    pub complete_lifecycles: usize,
    /// Incomplete lifecycles (missing phases).
    pub incomplete_lifecycles: usize,
}
