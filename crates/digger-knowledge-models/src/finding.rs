/// Finding types — raw and normalized findings from audit reports.
use serde::{Deserialize, Serialize};

/// A raw finding extracted from a report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtractedFinding {
    /// Finding ID from report (e.g., "H-01").
    pub finding_id: String,
    /// Finding title.
    pub title: String,
    /// Severity.
    pub severity: FindingSeverity,
    /// Impact description.
    pub impact: String,
    /// Likelihood description (if available).
    pub likelihood: Option<String>,
    /// Full description.
    pub description: String,
    /// Root cause.
    pub root_cause: String,
    /// Exploit path (if described).
    pub exploit_path: Option<String>,
    /// Impacted contracts.
    pub impacted_contracts: Vec<String>,
    /// Impacted functions.
    pub impacted_functions: Vec<String>,
    /// Remediation advice.
    pub remediation: String,
    /// Finding status.
    pub status: FindingStatus,
    /// External references.
    pub references: Vec<String>,
    /// Code snippets from the finding.
    pub code_snippets: Vec<CodeSnippet>,
}

/// Finding severity from the report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Informational => write!(f, "informational"),
        }
    }
}

/// Finding status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingStatus {
    Resolved,
    Acknowledged,
    Fixed,
    Open,
    Unknown,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolved => write!(f, "resolved"),
            Self::Acknowledged => write!(f, "acknowledged"),
            Self::Fixed => write!(f, "fixed"),
            Self::Open => write!(f, "open"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A code snippet from a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CodeSnippet {
    pub language: String,
    pub code: String,
    pub context: Option<String>,
}

/// A normalized finding — mapped to Digger's canonical taxonomy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizedFinding {
    /// Deterministic finding identifier.
    pub finding_id: String,
    /// Original finding ID from report.
    pub original_finding_id: String,
    /// Report this finding came from.
    pub report_id: String,
    /// Protocol name.
    pub protocol_name: String,
    /// Protocol category.
    pub protocol_category: super::audit::ProtocolCategory,
    /// Protocol domain — canonical domain this finding applies to.
    pub protocol_domain: ProtocolDomain,
    /// Protocol pattern — specific mechanism within the domain.
    pub protocol_pattern: Option<String>,
    /// Vulnerability class (canonical).
    pub vulnerability_class: VulnerabilityClass,
    /// Attack goal this finding relates to.
    pub attack_goal: String,
    /// Required attacker capabilities (canonical).
    pub capability_pattern: Vec<String>,
    /// Violated invariant.
    pub violated_invariant: ViolatedInvariant,
    /// Attack technique used.
    pub attack_technique: AttackTechnique,
    /// Mitigation pattern (if standard).
    pub mitigation_pattern: Option<MitigationPattern>,
    /// Security assumptions that were violated.
    pub security_assumptions: Vec<SecurityAssumption>,
    /// Severity (mapped to digger_ir::Severity).
    pub severity: digger_ir::Severity,
    /// Structural root cause.
    pub root_cause: StructuralRootCause,
    /// Original impact text.
    pub impact_text: String,
    /// Original description text.
    pub description_text: String,
    /// Original remediation text.
    pub remediation_text: String,
    /// Impacted contracts.
    pub impacted_contracts: Vec<String>,
    /// Impacted functions.
    pub impacted_functions: Vec<String>,
    /// Confidence (1.0 for human-reported findings).
    pub confidence: f64,
}

/// Vulnerability class — canonical taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VulnerabilityClass {
    // Access control
    MissingAccessControl,
    PrivilegeEscalation,
    UnprotectedInitialization,

    // Reentrancy
    Reentrancy,
    CrossFunctionReentrancy,
    CrossContractReentrancy,

    // Economic
    PriceManipulation,
    FlashLoanAttack,
    OracleManipulation,
    SandwichAttack,
    MEVExtraction,
    LiquidationManipulation,

    // Accounting
    PrecisionLoss,
    RoundingError,
    IntegerOverflow,
    InvariantViolation,

    // State
    StateCorruption,
    FrontRunning,
    Griefing,
    DenialOfService,

    // Logic
    BusinessLogicFlaw,
    MissingValidation,
    IncorrectCalculation,
    UncheckedReturn,

    // Upgradeability
    StorageCollision,
    ProxyInitialization,
    UpgradeabilityRisk,

    // Composability
    ComposabilityRisk,
    CrossProtocolDependency,

    // Governance
    GovernanceAttack,
    TimelockBypass,
    VotingManipulation,

    // Other
    CentralizationRisk,
    Other(String),
}

impl std::fmt::Display for VulnerabilityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAccessControl => write!(f, "missing_access_control"),
            Self::PrivilegeEscalation => write!(f, "privilege_escalation"),
            Self::UnprotectedInitialization => write!(f, "unprotected_initialization"),
            Self::Reentrancy => write!(f, "reentrancy"),
            Self::CrossFunctionReentrancy => write!(f, "cross_function_reentrancy"),
            Self::CrossContractReentrancy => write!(f, "cross_contract_reentrancy"),
            Self::PriceManipulation => write!(f, "price_manipulation"),
            Self::FlashLoanAttack => write!(f, "flash_loan_attack"),
            Self::OracleManipulation => write!(f, "oracle_manipulation"),
            Self::SandwichAttack => write!(f, "sandwich_attack"),
            Self::MEVExtraction => write!(f, "mev_extraction"),
            Self::LiquidationManipulation => write!(f, "liquidation_manipulation"),
            Self::PrecisionLoss => write!(f, "precision_loss"),
            Self::RoundingError => write!(f, "rounding_error"),
            Self::IntegerOverflow => write!(f, "integer_overflow"),
            Self::InvariantViolation => write!(f, "invariant_violation"),
            Self::StateCorruption => write!(f, "state_corruption"),
            Self::FrontRunning => write!(f, "front_running"),
            Self::Griefing => write!(f, "griefing"),
            Self::DenialOfService => write!(f, "denial_of_service"),
            Self::BusinessLogicFlaw => write!(f, "business_logic_flaw"),
            Self::MissingValidation => write!(f, "missing_validation"),
            Self::IncorrectCalculation => write!(f, "incorrect_calculation"),
            Self::UncheckedReturn => write!(f, "unchecked_return"),
            Self::StorageCollision => write!(f, "storage_collision"),
            Self::ProxyInitialization => write!(f, "proxy_initialization"),
            Self::UpgradeabilityRisk => write!(f, "upgradeability_risk"),
            Self::ComposabilityRisk => write!(f, "composability_risk"),
            Self::CrossProtocolDependency => write!(f, "cross_protocol_dependency"),
            Self::GovernanceAttack => write!(f, "governance_attack"),
            Self::TimelockBypass => write!(f, "timelock_bypass"),
            Self::VotingManipulation => write!(f, "voting_manipulation"),
            Self::CentralizationRisk => write!(f, "centralization_risk"),
            Self::Other(s) => write!(f, "other({})", s),
        }
    }
}

/// Attack technique.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttackTechnique {
    ReentrancyExploit,
    FlashLoanBorrow,
    PriceOracleManipulation,
    FrontRunningTransaction,
    SandwichAttackVector,
    GovernanceProposalAttack,
    TimelockExploitation,
    StorageCollisionExploit,
    DelegatecallExploitation,
    UncheckedExternalCall,
    PrecisionLossExploitation,
    StateManipulationCrossFunction,
    AccessControlBypass,
    InitializationBypass,
    Other(String),
}

impl std::fmt::Display for AttackTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReentrancyExploit => write!(f, "reentrancy_exploit"),
            Self::FlashLoanBorrow => write!(f, "flash_loan_borrow"),
            Self::PriceOracleManipulation => write!(f, "price_oracle_manipulation"),
            Self::FrontRunningTransaction => write!(f, "front_running_transaction"),
            Self::SandwichAttackVector => write!(f, "sandwich_attack_vector"),
            Self::GovernanceProposalAttack => write!(f, "governance_proposal_attack"),
            Self::TimelockExploitation => write!(f, "timelock_exploitation"),
            Self::StorageCollisionExploit => write!(f, "storage_collision_exploit"),
            Self::DelegatecallExploitation => write!(f, "delegatecall_exploitation"),
            Self::UncheckedExternalCall => write!(f, "unchecked_external_call"),
            Self::PrecisionLossExploitation => write!(f, "precision_loss_exploitation"),
            Self::StateManipulationCrossFunction => write!(f, "state_manipulation_cross_function"),
            Self::AccessControlBypass => write!(f, "access_control_bypass"),
            Self::InitializationBypass => write!(f, "initialization_bypass"),
            Self::Other(s) => write!(f, "other({})", s),
        }
    }
}

/// Canonical protocol domain — the type of protocol this finding applies to.
///
/// Every finding should map to a protocol domain when applicable.
/// Domains are protocol-agnostic categories that group similar protocols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolDomain {
    /// ERC-4626 vaults and yield strategies.
    Vaults,
    /// Automated market makers and liquidity pools.
    AMMs,
    /// Lending and borrowing protocols.
    Lending,
    /// Liquid staking protocols (Lido, Rocket Pool, etc.).
    LiquidStaking,
    /// Restaking protocols (EigenLayer, Symbiotic, etc.).
    Restaking,
    /// Cross-chain bridges.
    Bridges,
    /// Governance and DAO systems.
    Governance,
    /// Cross-chain messaging (LayerZero, Wormhole, Axelar, etc.).
    CrossChainMessaging,
    /// Derivatives and options protocols.
    Derivatives,
    /// Stablecoins and pegged assets.
    Stablecoins,
    /// Yield aggregators and optimizer protocols.
    YieldAggregators,
    /// Options protocols.
    Options,
    /// Perpetual futures protocols.
    Perpetuals,
    /// Auction mechanisms (Dutch, English, etc.).
    Auctions,
    /// Account abstraction and smart wallets.
    AccountAbstraction,
    /// Token standards and implementations.
    TokenStandards,
    /// Oracle networks and price feeds.
    Oracles,
    /// MEV infrastructure.
    MEVInfrastructure,
    /// Generic or unknown domain.
    Generic,
}

impl std::fmt::Display for ProtocolDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vaults => write!(f, "vaults"),
            Self::AMMs => write!(f, "amms"),
            Self::Lending => write!(f, "lending"),
            Self::LiquidStaking => write!(f, "liquid_staking"),
            Self::Restaking => write!(f, "restaking"),
            Self::Bridges => write!(f, "bridges"),
            Self::Governance => write!(f, "governance"),
            Self::CrossChainMessaging => write!(f, "cross_chain_messaging"),
            Self::Derivatives => write!(f, "derivatives"),
            Self::Stablecoins => write!(f, "stablecoins"),
            Self::YieldAggregators => write!(f, "yield_aggregators"),
            Self::Options => write!(f, "options"),
            Self::Perpetuals => write!(f, "perpetuals"),
            Self::Auctions => write!(f, "auctions"),
            Self::AccountAbstraction => write!(f, "account_abstraction"),
            Self::TokenStandards => write!(f, "token_standards"),
            Self::Oracles => write!(f, "oracles"),
            Self::MEVInfrastructure => write!(f, "mev_infrastructure"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

/// Structural root cause.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StructuralRootCause {
    MissingAuthorityCheck,
    IncorrectOperationOrder,
    MissingStateUpdate,
    SharedMutableState,
    UnvalidatedExternalInput,
    IncorrectInvariantAssumption,
    MissingBoundaryCheck,
    UnsafeComposition,
    FeeOnTransferIncompatibility,
    StaleStateAssumption,
    UncheckedReturnValue,
    IncorrectRoundingDirection,
    MissingEventEmission,
    UnsafeExternalDependency,
    GasGriefing,
    SignatureMalleability,
    FrontRunningRisk,
    OracleStaleness,
    MissingSlippageProtection,
    MissingZeroAddressCheck,
    TimestampDependency,
    CrossFunctionStateInconsistency,
    Other(String),
}

impl std::fmt::Display for StructuralRootCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAuthorityCheck => write!(f, "missing_authority_check"),
            Self::IncorrectOperationOrder => write!(f, "incorrect_operation_order"),
            Self::MissingStateUpdate => write!(f, "missing_state_update"),
            Self::SharedMutableState => write!(f, "shared_mutable_state"),
            Self::UnvalidatedExternalInput => write!(f, "unvalidated_external_input"),
            Self::IncorrectInvariantAssumption => write!(f, "incorrect_invariant_assumption"),
            Self::MissingBoundaryCheck => write!(f, "missing_boundary_check"),
            Self::UnsafeComposition => write!(f, "unsafe_composition"),
            Self::FeeOnTransferIncompatibility => write!(f, "fee_on_transfer_incompatibility"),
            Self::StaleStateAssumption => write!(f, "stale_state_assumption"),
            Self::UncheckedReturnValue => write!(f, "unchecked_return_value"),
            Self::IncorrectRoundingDirection => write!(f, "incorrect_rounding_direction"),
            Self::MissingEventEmission => write!(f, "missing_event_emission"),
            Self::UnsafeExternalDependency => write!(f, "unsafe_external_dependency"),
            Self::GasGriefing => write!(f, "gas_griefing"),
            Self::SignatureMalleability => write!(f, "signature_malleability"),
            Self::FrontRunningRisk => write!(f, "front_running_risk"),
            Self::OracleStaleness => write!(f, "oracle_staleness"),
            Self::MissingSlippageProtection => write!(f, "missing_slippage_protection"),
            Self::MissingZeroAddressCheck => write!(f, "missing_zero_address_check"),
            Self::TimestampDependency => write!(f, "timestamp_dependency"),
            Self::CrossFunctionStateInconsistency => {
                write!(f, "cross_function_state_inconsistency")
            }
            Self::Other(s) => write!(f, "other({})", s),
        }
    }
}

/// Violated invariant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ViolatedInvariant {
    /// Invariant kind (maps to digger economics).
    pub kind: String,
    /// Description.
    pub description: String,
    /// Affected state variables.
    pub affected_state_vars: Vec<String>,
}

/// Security assumption that was violated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityAssumption {
    pub assumption: String,
    pub is_valid: bool,
    pub violated_by: Option<String>,
}

/// Mitigation pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MitigationPattern {
    pub technique: String,
    pub description: String,
    pub is_standard: bool,
}
