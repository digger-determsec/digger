/// Authority Model — deterministic authority analysis structures.
///
/// Represents authorization sources, checks, propagation, and boundaries.
/// No AI, no heuristics, no probabilistic reasoning.
use serde::{Deserialize, Serialize};

/// Authority source — what provides authorization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthoritySource {
    /// msg.sender comparison (Solidity).
    MsgSender,
    /// tx.origin comparison (Solidity, deprecated but still used).
    TxOrigin,
    /// Signer check (Solana/Anchor).
    Signer,
    /// PDA authority (Solana/Anchor has_one).
    PdaAuthority,
    /// Owner variable comparison.
    OwnerVariable,
    /// Role-based access (mapping[msg.sender] => role).
    RoleMapping,
    /// Multisig threshold check.
    Multisig,
    /// Governance proposal check.
    Governance,
    /// Unknown authority source.
    Unknown,
}

impl std::fmt::Display for AuthoritySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MsgSender => write!(f, "msg_sender"),
            Self::TxOrigin => write!(f, "tx_origin"),
            Self::Signer => write!(f, "signer"),
            Self::PdaAuthority => write!(f, "pda"),
            Self::OwnerVariable => write!(f, "owner"),
            Self::RoleMapping => write!(f, "role"),
            Self::Multisig => write!(f, "multisig"),
            Self::Governance => write!(f, "governance"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Authority check type — what kind of authorization check.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthorityCheckType {
    /// Ownership check (msg.sender == owner).
    Ownership,
    /// Role-based check (hasRole(msg.sender, ROLE)).
    Role,
    /// Signer validation (is_signer, Signer::from_account_info).
    SignerValidation,
    /// PDA validation (has_one = authority).
    PdaValidation,
    /// Multisig threshold check.
    MultisigValidation,
    /// Governance proposal check.
    GovernanceValidation,
    /// Generic require/assert — NOT an authority check.
    Invariant,
    /// No check present.
    Missing,
    /// Unknown check type.
    Unknown,
}

impl std::fmt::Display for AuthorityCheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ownership => write!(f, "ownership"),
            Self::Role => write!(f, "role"),
            Self::SignerValidation => write!(f, "signer"),
            Self::PdaValidation => write!(f, "pda"),
            Self::MultisigValidation => write!(f, "multisig"),
            Self::GovernanceValidation => write!(f, "governance"),
            Self::Invariant => write!(f, "invariant"),
            Self::Missing => write!(f, "missing"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Authority relationship for a single function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityRelation {
    /// Function name.
    pub function: String,
    /// Authority source (who provides authority).
    pub source: AuthoritySource,
    /// Check type (how authority is validated).
    pub check_type: AuthorityCheckType,
    /// Whether authority is enforced (genuine check) or absent.
    pub enforced: bool,
    /// Whether this is an invariant check (not authority).
    pub is_invariant: bool,
    /// Modifier names that apply to this function.
    pub modifiers: Vec<String>,
}

/// Authority graph — complete authority analysis result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityGraph {
    /// Per-function authority relations.
    pub relations: Vec<AuthorityRelation>,
    /// Functions with enforced authority.
    pub enforced_functions: Vec<String>,
    /// Functions missing authority.
    pub missing_authority: Vec<String>,
    /// Functions with invariant-only checks (not authority).
    pub invariant_only: Vec<String>,
    /// Authority propagation chains: (modifier → function).
    pub propagation_chains: Vec<(String, String)>,
    /// Summary statistics.
    pub summary: AuthoritySummary,
}

/// Authority summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthoritySummary {
    /// Total functions analyzed.
    pub total_functions: usize,
    /// Functions with enforced authority.
    pub enforced_count: usize,
    /// Functions missing authority.
    pub missing_count: usize,
    /// Functions with invariant-only checks.
    pub invariant_count: usize,
    /// Authority enforcement rate.
    pub enforcement_rate: f64,
}
