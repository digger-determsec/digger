/// Protocol Model — Semantic layer on top of deterministic outputs.
///
/// Models protocol intent from existing graph/hypothesis/session outputs.
/// Does NOT detect vulnerabilities. Only models structure and intent.
///
/// # Rules
///
/// 1. Purely interpretive mapping — no new analysis
/// 2. Deterministic: same input → same output
/// 3. No AI, no LLMs, no heuristics that change output
/// 4. Must NOT modify IR, graph engine, hypothesis engine, or session engine
/// 5. JSON serializable
use serde::{Deserialize, Serialize};

/// Protocol definition — the top-level model of a protocol's intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolDefinition {
    /// Protocol name (derived from program_id or module name).
    pub name: String,
    /// Protocol type: "vault", "token", "dex", "lending", "generic".
    pub protocol_type: String,
    /// Identified roles in the protocol.
    pub roles: Vec<ProtocolRole>,
    /// Identified assets managed by the protocol.
    pub assets: Vec<ProtocolAsset>,
    /// Inferred invariants.
    pub invariants: Vec<ProtocolInvariant>,
    /// Entry points (public functions).
    pub entry_points: Vec<ProtocolEntryPoint>,
    /// Summary.
    pub summary: ProtocolSummary,
}

/// A role in the protocol — who can do what.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolRole {
    /// Role name.
    pub name: String,
    /// Role type: "owner", "user", "admin", "external_actor".
    pub role_type: ProtocolRoleType,
    /// Functions this role can call.
    pub functions: Vec<String>,
    /// Description of this role's capabilities.
    pub description: String,
}

/// Role type classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolRoleType {
    /// Contract owner — typically has admin functions.
    Owner,
    /// Regular user — can deposit, withdraw, etc.
    User,
    /// Admin — elevated privileges beyond owner.
    Admin,
    /// External actor — other contracts or programs.
    ExternalActor,
}

impl std::fmt::Display for ProtocolRoleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Owner => write!(f, "Owner"),
            Self::User => write!(f, "User"),
            Self::Admin => write!(f, "Admin"),
            Self::ExternalActor => write!(f, "ExternalActor"),
        }
    }
}

/// An asset managed by the protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolAsset {
    /// Asset name (derived from state variable).
    pub name: String,
    /// Asset type: "token_balance", "native_balance", "internal_accounting".
    pub asset_type: ProtocolAssetType,
    /// Functions that read this asset.
    pub readers: Vec<String>,
    /// Functions that write this asset.
    pub writers: Vec<String>,
    /// Description.
    pub description: String,
}

/// Asset type classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolAssetType {
    /// Token balance (ERC20, SPL, etc.).
    TokenBalance,
    /// Native currency balance (ETH, SOL, etc.).
    NativeBalance,
    /// Internal accounting variable.
    InternalAccounting,
}

impl std::fmt::Display for ProtocolAssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenBalance => write!(f, "TokenBalance"),
            Self::NativeBalance => write!(f, "NativeBalance"),
            Self::InternalAccounting => write!(f, "InternalAccounting"),
        }
    }
}

/// An invariant — a property that should hold for the protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolInvariant {
    /// Invariant name.
    pub name: String,
    /// Invariant type.
    pub invariant_type: InvariantType,
    /// Human-readable description.
    pub description: String,
    /// Related state variables.
    pub related_state: Vec<String>,
    /// Related functions.
    pub related_functions: Vec<String>,
}

/// Invariant type classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InvariantType {
    /// Balance must not be negative.
    BalanceNonNegative,
    /// Total supply must remain constant (no mint/burn).
    SupplyConservation,
    /// Withdrawal must reduce balance before external call.
    WithdrawalOrdering,
    /// Only authorized callers can modify state.
    AccessControl,
    /// State variable is immutable after initialization.
    ImmutabilityGuard,
}

impl std::fmt::Display for InvariantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BalanceNonNegative => write!(f, "BalanceNonNegative"),
            Self::SupplyConservation => write!(f, "SupplyConservation"),
            Self::WithdrawalOrdering => write!(f, "WithdrawalOrdering"),
            Self::AccessControl => write!(f, "AccessControl"),
            Self::ImmutabilityGuard => write!(f, "ImmutabilityGuard"),
        }
    }
}

/// An entry point in the protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolEntryPoint {
    /// Function name.
    pub function: String,
    /// Role that typically calls this.
    pub primary_role: ProtocolRoleType,
    /// Whether this function modifies state.
    pub modifies_state: bool,
    /// Whether this function makes external calls.
    pub makes_external_calls: bool,
}

/// Summary of the protocol definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolSummary {
    /// Total roles identified.
    pub total_roles: usize,
    /// Total assets identified.
    pub total_assets: usize,
    /// Total invariants identified.
    pub total_invariants: usize,
    /// Total entry points.
    pub total_entry_points: usize,
    /// Protocol type.
    pub protocol_type: String,
}
