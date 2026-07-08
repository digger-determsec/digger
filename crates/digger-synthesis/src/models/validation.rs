use serde::{Deserialize, Serialize};

// â”€â”€â”€ Preconditions Validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Result of preconditions validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreconditionsValidation {
    pub results: Vec<PreconditionCheck>,
    pub all_satisfied: bool,
    pub satisfied_count: usize,
    pub unsatisfied_count: usize,
    pub partial_count: usize,
    pub unknown_count: usize,
}

/// Status of a single precondition check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    Satisfied,
    Unsatisfied,
    PartiallySatisfied,
    Unknown,
}

/// A single precondition check result with evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreconditionCheck {
    pub kind: PreconditionType,
    pub description: String,
    pub status: ValidationStatus,
    pub evidence: Vec<String>,
    pub step_index: Option<usize>,
    pub confidence: f64,
}

/// Types of preconditions to validate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreconditionType {
    PrivilegeExists,
    AuthorityReachable,
    AccountOwnership,
    StateReachable,
    StorageInitialized,
    LiquidityAvailable,
    OracleManipulable,
    GovernanceDelaySatisfied,
    FlashLoanSourceAvailable,
    PdaDerivationPossible,
    SignerRequirementSatisfied,
}

// â”€â”€â”€ State Reachability â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// State reachability validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateReachabilityValidation {
    pub transitions: Vec<StateTransitionProof>,
    pub all_reachable: bool,
    pub reachable_count: usize,
    pub unreachable_count: usize,
}

/// Proof of a state transition's reachability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionProof {
    pub step_index: usize,
    pub from_state: String,
    pub to_state: String,
    pub reachable: bool,
    pub proof: String,
    pub unreachable_reason: Option<String>,
    pub missing_transition: Option<String>,
    pub conflicting_transition: Option<String>,
}

// â”€â”€â”€ Transaction Sequence Validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Transaction sequence validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSequenceValidation {
    pub valid: bool,
    pub issues: Vec<SequenceIssue>,
    pub ordering: Vec<OrderingConstraint>,
    pub explanation: String,
}

/// An issue with transaction ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceIssue {
    pub kind: SequenceIssueKind,
    pub step_a: usize,
    pub step_b: usize,
    pub description: String,
    pub evidence: Vec<String>,
}

/// Kind of sequence issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SequenceIssueKind {
    ImpossibleOrdering,
    DependencyViolation,
    CircularDependency,
    InvalidLifecycleOrdering,
    InvalidAuthorityOrdering,
}

/// An ordering constraint between two steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderingConstraint {
    pub from_step: usize,
    pub to_step: usize,
    pub kind: String,
    pub reason: String,
}

// â”€â”€â”€ Invariant Replay â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Result of replaying invariants through attack steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantReplayResult {
    pub replays: Vec<InvariantReplay>,
    pub violations_detected: usize,
    pub invariants_preserved: usize,
}

/// Replay of a single invariant through attack steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantReplay {
    pub invariant_id: String,
    pub invariant_description: String,
    pub initial_state: String,
    pub steps: Vec<InvariantStep>,
    pub violated: bool,
    pub violating_step: Option<usize>,
    pub evidence: Vec<String>,
    pub affected_assets: Vec<String>,
    pub propagation_chain: Vec<String>,
}

/// Invariant state at a specific step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantStep {
    pub step_index: usize,
    pub state: String,
    pub holds: bool,
    pub delta: String,
}

// â”€â”€â”€ Asset Flow Validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Asset flow validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetFlowValidation {
    pub flows: Vec<AssetFlow>,
    pub valid: bool,
    pub impossible_creations: Vec<String>,
    pub balance_violations: Vec<BalanceViolation>,
    pub explanation: String,
}

/// Flow of a specific asset through the exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetFlow {
    pub asset_id: String,
    pub asset_type: AssetType,
    pub steps: Vec<AssetFlowStep>,
    pub net_flow: f64,
    pub balance_before: f64,
    pub balance_after: f64,
    pub valid: bool,
}

/// Type of asset being tracked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetType {
    Token,
    VaultBalance,
    LpToken,
    DebtPosition,
    CollateralPosition,
    WrappedAsset,
    NativeCurrency,
}

/// Asset flow at a specific step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetFlowStep {
    pub step_index: usize,
    pub inflow: f64,
    pub outflow: f64,
    pub net: f64,
    pub cumulative: f64,
}

/// A balance violation detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceViolation {
    pub asset_id: String,
    pub step_index: usize,
    pub expected: f64,
    pub actual: f64,
    pub description: String,
}

// â”€â”€â”€ Capability Validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Capability validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityValidationResult {
    pub validations: Vec<CapabilityCheck>,
    pub all_proven: bool,
    pub proven_count: usize,
    pub unproven_count: usize,
}

/// Check for a single capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCheck {
    pub capability: String,
    pub description: String,
    pub proven: bool,
    pub evidence: Vec<String>,
    pub proof_type: ProofType,
}

/// How a capability was proven.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofType {
    /// Proven by IR analysis (function exists with right effects).
    IrAnalysis,
    /// Proven by graph analysis (edge exists in call graph).
    GraphAnalysis,
    /// Proven by knowledge graph (historical precedent).
    KnowledgeGraph,
    /// Proven by protocol pack (protocol-specific rule).
    ProtocolPack,
    /// Cannot be proven from available evidence.
    Unproven,
}

// â”€â”€â”€ Trust Boundary Validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Trust boundary validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundaryValidation {
    pub crossings: Vec<TrustBoundaryCrossing>,
    pub valid: bool,
    pub unauthorized_count: usize,
    pub explanation: String,
}

/// A single trust boundary crossing analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundaryCrossing {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub authorized: bool,
    pub validation_performed: bool,
    pub evidence: Vec<String>,
    pub step_index: usize,
}

// â”€â”€â”€ Economic Validation Report â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Economic validation report for an exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicValidationReport {
    pub capital_required: f64,
    pub borrowed_capital: f64,
    pub fees: f64,
    pub slippage_estimate: f64,
    pub gas_estimate: f64,
    pub expected_profit: f64,
    pub minimum_profitable_threshold: f64,
    pub profitable: bool,
    pub breakdown: Vec<EconomicLineItem>,
    pub explanation: String,
}

/// A single line item in the economic breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicLineItem {
    pub category: String,
    pub amount: f64,
    pub asset: String,
    pub description: String,
}
