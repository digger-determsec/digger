use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// â”€â”€â”€ Execution Blocker â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A blocker preventing exploit execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionBlocker {
    pub step_index: Option<usize>,
    pub kind: BlockerKind,
    pub description: String,
    pub evidence: Vec<String>,
    pub severity: BlockerSeverity,
}

/// Kind of execution blocker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockerKind {
    MissingPrivilege,
    UnreachableState,
    ImpossibleOrdering,
    InvariantViolation,
    EconomicImpossibility,
    MissingCapability,
    TrustBoundaryViolation,
    InsufficientLiquidity,
    OracleUnavailable,
    GovernanceDelay,
}

/// Severity of an execution blocker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockerSeverity {
    Critical,
    High,
    Medium,
    Low,
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Gen 3.3 â€” Execution Preparation Types
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Complete execution package for a validated exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPackage {
    pub package_id: String,
    pub chain_id: String,
    pub protocol_id: String,
    pub chain_type: String,
    pub context: ExecutionContext,
    pub transactions: Vec<PreparedTransaction>,
    pub environment: EnvironmentRequirements,
    pub replay_bundle: ReplayBundle,
    pub validation: PackageValidation,
    pub readiness_score: f64,
    pub blockers: Vec<String>,
}

/// Execution context â€” everything needed to execute the exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub required_contracts: Vec<ContractRequirement>,
    pub required_accounts: Vec<AccountRequirement>,
    pub required_authorities: Vec<AuthorityRequirement>,
    pub required_assets: Vec<AssetRequirement>,
    pub required_balances: Vec<BalanceRequirement>,
    pub required_approvals: Vec<ApprovalRequirement>,
    pub required_signers: Vec<SignerRequirement>,
    pub required_pdas: Vec<PdaRequirement>,
    pub required_storage: Vec<StorageRequirement>,
    pub required_config: Vec<ConfigRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRequirement {
    pub id: String,
    pub address: Option<String>,
    pub program_id: Option<String>,
    pub source_required: bool,
    pub deployed: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRequirement {
    pub address: String,
    pub account_type: String,
    pub data_layout: Option<String>,
    pub must_exist: bool,
    pub must_be_empty: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityRequirement {
    pub account: String,
    pub authority_type: String,
    pub required_for: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRequirement {
    pub asset_id: String,
    pub asset_type: String,
    pub amount: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceRequirement {
    pub account: String,
    pub asset: String,
    pub minimum_balance: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    pub owner: String,
    pub spender: String,
    pub asset: String,
    pub amount: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerRequirement {
    pub signer_id: String,
    pub signer_type: String,
    pub key_type: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdaRequirement {
    pub pda_id: String,
    pub seeds: Vec<String>,
    pub bump: Option<u8>,
    pub owner_program: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRequirement {
    pub variable: String,
    pub expected_value: String,
    pub step_index: Option<usize>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigRequirement {
    pub parameter: String,
    pub expected_value: String,
    pub description: String,
}

/// A prepared transaction for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedTransaction {
    pub index: usize,
    pub step_index: usize,
    pub chain_type: String,
    pub from: String,
    pub to: String,
    pub function_selector: String,
    pub arguments: Vec<TransactionArgument>,
    pub calldata: Option<String>,
    pub value: Option<String>,
    pub gas_limit: Option<u64>,
    pub signers: Vec<String>,
    pub dependencies: Vec<usize>,
    pub expected_state_changes: Vec<String>,
    pub expected_events: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionArgument {
    pub name: String,
    pub arg_type: String,
    pub value: String,
    pub is_dynamic: bool,
}

/// Environment requirements for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentRequirements {
    pub fork_block: Option<u64>,
    pub chain_id: Option<u64>,
    pub rpc_url: Option<String>,
    pub deployed_contracts: Vec<ContractDeployment>,
    pub token_balances: Vec<BalanceSpec>,
    pub oracle_values: Vec<OracleValue>,
    pub governance_state: Vec<GovernanceState>,
    pub validator_config: Option<ValidatorConfig>,
    pub feature_gates: Vec<FeatureGate>,
    pub clock_requirements: Option<ClockRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDeployment {
    pub name: String,
    pub source: String,
    pub constructor_args: Vec<String>,
    pub salt: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleValue {
    pub oracle_id: String,
    pub asset: String,
    pub price: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceState {
    pub parameter: String,
    pub value: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub slots_per_epoch: u64,
    pub tick_duration_ms: u64,
    pub warp_slot: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureGate {
    pub name: String,
    pub enabled: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockRequirement {
    pub slot: Option<u64>,
    pub timestamp: Option<u64>,
    pub epoch: Option<u64>,
    pub description: String,
}

/// Replay bundle â€” portable execution package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBundle {
    pub bundle_id: String,
    pub version: String,
    pub chain_type: String,
    pub metadata: BundleMetadata,
    pub transaction_sequence: Vec<PreparedTransaction>,
    pub execution_dependencies: Vec<String>,
    pub required_artifacts: Vec<String>,
    pub expected_outputs: Vec<String>,
    pub cleanup_instructions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMetadata {
    pub created_at: String,
    pub chain_id: String,
    pub protocol_id: String,
    pub exploit_goal: String,
    pub total_steps: usize,
    pub total_transactions: usize,
    pub deterministic_hash: String,
}

/// Package validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageValidation {
    pub complete: bool,
    pub missing_prerequisites: Vec<String>,
    pub inconsistent_transactions: Vec<String>,
    pub reproducible: bool,
    pub explanation: String,
}

// â”€â”€â”€ EVM Transaction Types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmTransaction {
    pub step_index: usize,
    pub from: String,
    pub to: String,
    pub value: String,
    pub data: String,
    pub gas_limit: u64,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub chain_id: u64,
    pub nonce: u64,
    pub access_list: Vec<AccessListEntry>,
    pub function_signature: String,
    pub delegatecall: bool,
    pub create2: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListEntry {
    pub address: String,
    pub storage_keys: Vec<String>,
}

// â”€â”€â”€ Solana Transaction Types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaTransaction {
    pub step_index: usize,
    pub instructions: Vec<SolanaInstruction>,
    pub signers: Vec<SolanaSignerMeta>,
    pub compute_budget: u64,
    pub recent_blockhash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SolanaInstruction {
    ProgramInstruction(ProgramInstruction),
    ComputeBudgetInstruction(ComputeBudgetInstruction),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInstruction {
    pub program_id: String,
    pub accounts: Vec<SolanaAccountMeta>,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeBudgetInstruction {
    pub instruction_type: String,
    pub units: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaAccountMeta {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaSignerMeta {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Gen 4 â€” Deterministic Exploit Execution & Verification Types
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Complete execution transcript capturing everything that happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTranscript {
    pub transcript_id: String,
    pub chain_id: String,
    pub package_id: String,
    pub status: ExecutionStatus,
    pub entries: Vec<TranscriptEntry>,
    pub state_diff: StateDiff,
    pub economic_outcome: EconomicOutcome,
    pub gas_summary: GasSummary,
    pub total_duration_ms: u64,
    pub deterministic_hash: String,
}

/// Execution status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionStatus {
    Completed,
    Failed { step: usize, reason: String },
    Reverted { step: usize, reason: String },
    Timeout,
}

/// A single entry in the execution transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub step_index: usize,
    pub transaction_index: usize,
    pub timestamp_ms: u64,
    pub kind: TranscriptEntryKind,
    pub contract: String,
    pub function: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub input_data: String,
    pub output_data: String,
    pub gas_used: u64,
    pub success: bool,
    pub revert_reason: Option<String>,
    pub events: Vec<TranscriptEvent>,
    pub state_changes: Vec<ExecutionStateChange>,
    pub balance_changes: Vec<BalanceChange>,
}

/// Kind of transcript entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TranscriptEntryKind {
    Transaction,
    ContractCall,
    ExternalCall,
    CpiCall,
    StateRead,
    StateWrite,
    BalanceTransfer,
    Log,
    Error,
}

/// An event emitted during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptEvent {
    pub event_name: String,
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub decoded_fields: Vec<DecodedField>,
}

/// A decoded event field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedField {
    pub name: String,
    pub field_type: String,
    pub value: String,
}

/// A state change during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStateChange {
    pub address: String,
    pub slot: String,
    pub before: String,
    pub after: String,
    pub kind: ExecutionStateChangeKind,
}

/// Kind of execution state change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStateChangeKind {
    StorageWrite,
    BalanceChange,
    NonceChange,
    CodeChange,
    AccountCreate,
    AccountClose,
}

/// A balance change during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceChange {
    pub account: String,
    pub asset: String,
    pub before: f64,
    pub after: f64,
    pub delta: f64,
    pub reason: String,
}

/// Complete state diff (before vs after).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    pub storage_changes: Vec<ExecutionStateChange>,
    pub balance_changes: Vec<BalanceChange>,
    pub account_creations: Vec<String>,
    pub account_closures: Vec<String>,
    pub authority_changes: Vec<AuthorityChange>,
    pub total_storage_writes: usize,
    pub total_balance_transfers: usize,
}

/// An authority change during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityChange {
    pub account: String,
    pub old_authority: String,
    pub new_authority: String,
    pub step_index: usize,
}

/// Economic outcome of execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicOutcome {
    pub total_value_extracted: BTreeMap<String, f64>,
    pub total_value_deposited: BTreeMap<String, f64>,
    pub net_profit: BTreeMap<String, f64>,
    pub gas_cost: f64,
    pub protocol_losses: BTreeMap<String, f64>,
    pub attacker_gains: BTreeMap<String, f64>,
}

/// Gas/compute usage summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasSummary {
    pub total_gas: u64,
    pub per_step: Vec<GasPerStep>,
    pub average_gas_per_step: f64,
    pub gas_limit: u64,
    pub utilization: f64,
}

/// Gas usage for a single step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasPerStep {
    pub step_index: usize,
    pub gas_used: u64,
    pub breakdown: BTreeMap<String, u64>,
}

/// Differential state analysis â€” before vs after.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialAnalysis {
    pub storage_before: BTreeMap<String, String>,
    pub storage_after: BTreeMap<String, String>,
    pub balance_before: BTreeMap<String, f64>,
    pub balance_after: BTreeMap<String, f64>,
    pub ownership_before: BTreeMap<String, String>,
    pub ownership_after: BTreeMap<String, String>,
    pub authority_before: BTreeMap<String, bool>,
    pub authority_after: BTreeMap<String, bool>,
    pub invariant_status: Vec<InvariantStatus>,
    pub mutations: Vec<ProtocolMutation>,
    pub economic_impact: EconomicImpactAnalysis,
    pub verdict: DiffVerdict,
    pub explanation: String,
}

/// Status of an invariant after execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantStatus {
    pub invariant_id: String,
    pub description: String,
    pub held_before: bool,
    pub held_after: bool,
    pub violated_by_step: Option<usize>,
    pub evidence: Vec<String>,
}

/// A protocol mutation detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMutation {
    pub kind: MutationKind,
    pub target: String,
    pub before: String,
    pub after: String,
    pub step_index: usize,
    pub expected: bool,
}

/// Kind of mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MutationKind {
    StateWrite,
    BalanceTransfer,
    AuthorityChange,
    CodeUpgrade,
    AccountCreation,
    AccountClosure,
}

/// Economic impact analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicImpactAnalysis {
    pub total_extracted: BTreeMap<String, f64>,
    pub total_deposited: BTreeMap<String, f64>,
    pub protocol_impact: Vec<ProtocolImpact>,
    pub profit_margin: f64,
    pub roi: f64,
}

/// Impact on a specific protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolImpact {
    pub protocol: String,
    pub loss: BTreeMap<String, f64>,
    pub affected_functions: Vec<String>,
    pub affected_state: Vec<String>,
}

/// Diff verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiffVerdict {
    ExpectedVulnerability,
    PartiallyExpected,
    UnexpectedOutcome,
    NoChange,
}

/// Execution confirmation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfirmation {
    pub confirmation_id: String,
    pub chain_id: String,
    pub status: ConfirmationStatus,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub explanation: String,
    pub differential: DifferentialAnalysis,
    pub transcript: ExecutionTranscript,
    pub knowledge_feedback: Option<KnowledgeFeedback>,
}

/// Confirmation status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfirmationStatus {
    Verified,
    VerifiedWithCaveats,
    PartialSuccess,
    Failed,
    FailedWithExplanation,
}

/// Knowledge graph feedback from confirmed exploits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeFeedback {
    pub exploit_id: String,
    pub confidence_delta: f64,
    pub new_evidence: Vec<String>,
    pub updated_findings: Vec<String>,
    pub protocol_relationship_updates: Vec<ProtocolRelationshipUpdate>,
    pub benchmark_metadata_update: Option<BenchmarkMetadataUpdate>,
    pub lineage_update: ExploitLineage,
}

/// Update to a protocol relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolRelationshipUpdate {
    pub relationship_type: String,
    pub source: String,
    pub target: String,
    pub strength_delta: f64,
    pub evidence: String,
}

/// Update to benchmark metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetadataUpdate {
    pub exploit_id: String,
    pub previous_confidence: f64,
    pub new_confidence: f64,
    pub verification_status: String,
    pub execution_count: u64,
}

/// Exploit lineage tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitLineage {
    pub exploit_id: String,
    pub derived_from: Vec<String>,
    pub similar_to: Vec<String>,
    pub generation: u32,
    pub verification_history: Vec<VerificationEntry>,
}

/// A single verification entry in the lineage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationEntry {
    pub timestamp: String,
    pub status: ConfirmationStatus,
    pub confidence: f64,
    pub evidence: Vec<String>,
}
