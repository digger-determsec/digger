use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// â”€â”€â”€ Exploit Simulation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Logical simulation of an exploit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitSimulation {
    /// Chain being simulated.
    pub chain_id: String,
    /// Initial protocol state.
    pub initial_state: ProtocolState,
    /// State after each step.
    pub step_states: Vec<StepState>,
    /// Final protocol state.
    pub final_state: ProtocolState,
    /// Whether the simulation succeeded (all steps valid).
    pub success: bool,
    /// Why the simulation failed (if it did).
    pub failure_reason: Option<String>,
    /// Total economic impact.
    pub economic_impact: EconomicImpact,
    /// Simulation explanation.
    pub explanation: String,
}

/// State of the protocol at a point in the simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolState {
    /// Step index (-1 for initial).
    pub step_index: i32,
    /// State variable values (variable -> value description).
    pub state_vars: BTreeMap<String, String>,
    /// Balance changes (asset -> amount change).
    pub balances: BTreeMap<String, i64>,
    /// Ownership state (account -> owner).
    pub ownership: BTreeMap<String, String>,
    /// Authority state (function -> whether authority is enforced).
    pub authority: BTreeMap<String, bool>,
    /// Active invariant violations.
    pub violated_invariants: Vec<String>,
}

/// State after a single exploit step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepState {
    /// Step index.
    pub step: usize,
    /// State before this step.
    pub before: ProtocolState,
    /// What this step changed.
    pub changes: Vec<StateChange>,
    /// State after this step.
    pub after: ProtocolState,
    /// Why this step succeeded.
    pub success_reason: String,
}

/// A single state change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    /// What changed.
    pub kind: StateChangeKind,
    /// Variable/account affected.
    pub target: String,
    /// Old value.
    pub old_value: String,
    /// New value.
    pub new_value: String,
}

/// Kind of state change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateChangeKind {
    /// State variable modification.
    StateVariable,
    /// Balance change.
    Balance,
    /// Ownership change.
    Ownership,
    /// Authority change.
    Authority,
    /// Invariant violation.
    InvariantViolation,
}

/// Economic impact of an exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicImpact {
    /// Assets stolen or destroyed.
    pub assets_lost: BTreeMap<String, i64>,
    /// Assets gained by attacker.
    pub assets_gained: BTreeMap<String, i64>,
    /// Total USD value lost (estimated).
    pub total_usd_lost: f64,
    /// Invariant violations caused.
    pub invariant_violations: Vec<String>,
    /// Cascade effects on other protocols.
    pub cascade_effects: Vec<String>,
}

// â”€â”€â”€ Exploit Ranking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Deterministic scoring of an exploit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitRanking {
    /// Chain being ranked.
    pub chain_id: String,
    /// Overall score (0.0 - 1.0).
    pub score: f64,
    /// Individual ranking factors.
    pub factors: RankingFactors,
    /// Rank position (1 = highest).
    pub rank: usize,
}

/// Individual factors contributing to the ranking score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankingFactors {
    /// Quality and quantity of evidence (0.0 - 1.0).
    pub evidence_quality: f64,
    /// Fewer unsupported assumptions = higher score.
    pub assumption_support: f64,
    /// Contradictions reduce score.
    pub contradiction_score: f64,
    /// Similarity to known historical exploits.
    pub historical_similarity: f64,
    /// Depth of reasoning chain.
    pub reasoning_depth: f64,
    /// Protocol semantic confidence.
    pub protocol_semantics: f64,
    /// Number of trust boundary crossings.
    pub trust_boundary_score: f64,
    /// Estimated economic impact.
    pub economic_impact: f64,
}

// â”€â”€â”€ Exploit Explanation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Human-readable explanation of a synthesized exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitExplanation {
    /// Chain being explained.
    pub chain_id: String,
    /// High-level summary.
    pub summary: String,
    /// Step-by-step explanation.
    pub step_explanations: Vec<StepExplanation>,
    /// Why this exploit is feasible.
    pub feasibility_reasoning: String,
    /// Why this exploit is dangerous.
    pub danger_reasoning: String,
    /// How to mitigate this exploit.
    pub mitigation: String,
    /// Historical context.
    pub historical_context: String,
}

/// Explanation of a single exploit step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExplanation {
    /// Step index.
    pub step: usize,
    /// Plain English explanation.
    pub explanation: String,
    /// Evidence that supports this step.
    pub supporting_evidence: Vec<String>,
    /// Why this step succeeds.
    pub success_reason: String,
}

// â”€â”€â”€ Exploit Search Report â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Report from the exploit search process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitSearchReport {
    /// Protocol analyzed.
    pub protocol_id: String,
    /// Total chains synthesized.
    pub total_chains: usize,
    /// Chains that survived elimination.
    pub viable_chains: usize,
    /// Chains eliminated.
    pub eliminated_chains: usize,
    /// Ranked results.
    pub rankings: Vec<ExploitRanking>,
    /// Explanations for top chains.
    pub explanations: Vec<ExploitExplanation>,
    /// Simulations for top chains.
    pub simulations: Vec<ExploitSimulation>,
    /// Attack plans for top chains.
    pub attack_plans: Vec<AttackPlan>,
    /// Simulation specifications for top chains.
    pub simulation_specs: Vec<SimulationSpec>,
    /// Feasibility scores for top chains.
    pub feasibility_scores: Vec<FeasibilityScore>,
    /// Validation reports for top chains.
    pub validation_reports: Vec<ValidationReport>,
    /// Execution packages for top chains.
    pub execution_packages: Vec<ExecutionPackage>,
    /// Execution transcripts from running packages.
    pub execution_transcripts: Vec<ExecutionTranscript>,
    /// Differential analyses.
    pub differential_analyses: Vec<DifferentialAnalysis>,
    /// Confirmation results.
    pub confirmations: Vec<ExecutionConfirmation>,
    /// Search metadata.
    pub search_metadata: SearchMetadata,
}
/// Metadata about the search process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMetadata {
    /// Total search steps performed.
    pub search_steps: usize,
    /// Total pruning operations.
    pub pruning_ops: usize,
    /// Total elimination checks.
    pub elimination_checks: usize,
    /// Search duration estimate.
    pub search_explanation: String,
}

// â”€â”€â”€ Feasibility Types (defined here to avoid circular deps) â”€â”€â”€â”€â”€â”€

/// Comprehensive feasibility score for an exploit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeasibilityScore {
    /// Chain being scored.
    pub chain_id: String,
    /// Overall feasibility (0.0 - 1.0).
    pub overall: f64,
    /// Individual score components.
    pub components: FeasibilityComponents,
    /// Human-readable explanation.
    pub explanation: String,
    /// Feasibility verdict.
    pub verdict: FeasibilityVerdict,
}

/// Individual components of feasibility scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeasibilityComponents {
    /// Precondition satisfaction rate (0.0 - 1.0).
    pub precondition_score: f64,
    /// State transition reachability (0.0 - 1.0).
    pub state_reachability: f64,
    /// Number of invariant violations (higher = more exploitable).
    pub invariant_violations: f64,
    /// Trust boundary crossings (higher = more interesting).
    pub trust_boundary_score: f64,
    /// Economic viability (0.0 - 1.0).
    pub economic_viability: f64,
    /// Protocol assumption violations.
    pub assumption_violations: f64,
    /// Evidence quality (0.0 - 1.0).
    pub evidence_quality: f64,
    /// Step count efficiency (fewer steps = more practical).
    pub step_efficiency: f64,
}

/// Verdict on exploit feasibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeasibilityVerdict {
    HighlyFeasible,
    Feasible,
    PossiblyFeasible,
    Unlikely,
    Infeasible,
}

// â”€â”€â”€ Attack Plan Types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Complete attack plan derived from a validated exploit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPlan {
    pub plan_id: String,
    pub title: String,
    pub goal: String,
    pub steps: Vec<AttackPlanStep>,
    pub required_actors: Vec<AttackActor>,
    pub affected_targets: Vec<AffectedTarget>,
    pub broken_invariants: Vec<BrokenInvariant>,
    pub expected_outcomes: Vec<String>,
    pub preconditions: PreconditionSummary,
    pub feasibility: f64,
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPlanStep {
    pub step_number: usize,
    pub target_function: String,
    pub actor: String,
    pub action: String,
    pub parameters: Vec<String>,
    pub expected_state_changes: Vec<String>,
    pub expected_balance_changes: Vec<String>,
    pub preconditions: Vec<String>,
    pub evidence: Vec<String>,
    pub success_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackActor {
    pub actor_id: String,
    pub role: String,
    pub responsibilities: Vec<String>,
    pub required_permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedTarget {
    pub target_id: String,
    pub target_type: String,
    pub changes: Vec<String>,
    pub broken_invariants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokenInvariant {
    pub description: String,
    pub broken_by: String,
    pub impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreconditionSummary {
    pub total: usize,
    pub satisfied: usize,
    pub missing: usize,
    pub unknown: usize,
}

// â”€â”€â”€ Simulation Spec Types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationSpec {
    pub chain_id: String,
    pub targets: Vec<SimulationTarget>,
    pub fork_config: ForkConfig,
    pub required_balances: Vec<BalanceSpec>,
    pub required_accounts: Vec<AccountSpec>,
    pub transactions: Vec<TransactionSpec>,
    pub assertions: Vec<Assertion>,
    pub postconditions: Vec<String>,
    pub chain_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationTarget {
    pub id: String,
    pub source: String,
    pub chain: String,
    pub deploy_mode: DeployMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeployMode {
    Fork { block: u64 },
    Fresh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkConfig {
    pub chain: String,
    pub fork_block: Option<u64>,
    pub rpc_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceSpec {
    pub account: String,
    pub asset: String,
    pub amount: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSpec {
    pub address: String,
    pub account_type: String,
    pub permissions: Vec<String>,
    pub data_layout: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSpec {
    pub index: usize,
    pub from: String,
    pub to: String,
    pub function: String,
    pub parameters: Vec<String>,
    pub value: Option<String>,
    pub expect_success: bool,
    pub expected_revert: Option<String>,
    pub compute_budget: Option<u64>,
    pub signers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    pub kind: AssertionKind,
    pub target: String,
    pub expected: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssertionKind {
    BalanceCheck,
    StateCheck,
    RevertCheck,
    SuccessCheck,
    EventCheck,
    InvariantCheck,
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Gen 3.2 â€” Deterministic Exploit Validation Engine Types
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Complete validation report for a synthesized exploit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub chain_id: String,
    pub verdict: ValidationVerdict,
    pub validation_score: f64,
    pub confidence_interval: (f64, f64),
    pub preconditions: PreconditionsValidation,
    pub state_reachability: StateReachabilityValidation,
    pub transaction_sequence: TransactionSequenceValidation,
    pub invariant_replay: InvariantReplayResult,
    pub asset_flow: AssetFlowValidation,
    pub capability_validation: CapabilityValidationResult,
    pub trust_boundary: TrustBoundaryValidation,
    pub economic_validation: EconomicValidationReport,
    pub execution_blockers: Vec<ExecutionBlocker>,
    pub remaining_assumptions: Vec<String>,
    pub evidence_references: Vec<EvidenceReference>,
    pub validation_metadata: ValidationMetadata,
}

/// Overall validation verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationVerdict {
    /// All checks pass â€” exploit is executable as described.
    Valid,
    /// Most checks pass with minor issues.
    ValidWithCaveats,
    /// Some checks fail â€” exploit may need modification.
    PartiallyValid,
    /// Critical checks fail â€” exploit cannot execute as described.
    Invalid,
}

/// Metadata about the validation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationMetadata {
    pub total_checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub partial: usize,
    pub unknown: usize,
    pub validation_duration_hint: String,
}
