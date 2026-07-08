/// Hypothesis Engine v2 — Core Models
///
/// Hypotheses are NOT findings.
/// Hypotheses represent: "possible exploit explanations derived from structural evidence."
///
/// Every hypothesis is:
/// - Deterministic (same input → same output)
/// - Traceable (references graph facts)
/// - Evidence-backed (references path IDs, evidence chain IDs)
/// - Not scored (no confidence, no ranking)
use serde::{Deserialize, Serialize};

/// Unique hypothesis identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HypothesisId(pub String);

impl std::fmt::Display for HypothesisId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Hypothesis type — what kind of exploit pattern this represents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HypothesisType {
    /// External call before state update — potential reentrancy.
    ReentrancyCandidate,
    /// Public function mutates state without authority check.
    AuthorityBypassCandidate,
    /// CPI call without proper authority validation.
    CPITrustViolationCandidate,
    /// State written by multiple functions without coordination.
    StateCorruptionCandidate,
    /// Economic invariant violation (conservation, solvency, collateralization).
    EconomicInvariantViolationCandidate,
    /// Adversarial attack path confirmed as feasible.
    AdversarialPathCandidate,
    /// Storage-derived price/rate flows into value computation without
    /// external feed validation — potential oracle manipulation from
    /// internal mutable state.
    OracleManipulationCandidate,
    /// Public function makes value distribution/reward decision based on
    /// balance-like state with no temporal guard — potential flash-loan
    /// governance manipulation.
    FlashLoanGovernanceCandidate,
    /// Anchor instruction account lacks required constraints (signer, owner,
    /// has_one, seeds). Solana-specific: catches missing-mint-authority,
    /// missing-owner-check, and similar account-level authorization gaps.
    /// Structurally identical to AuthorityBypassCandidate but provides
    /// Solana-native naming and targets constraint-annotated accounts.
    MissingAccountConstraintCandidate,
    /// Arithmetic inside a Solidity unchecked{} block — overflow-prone math
    /// that the compiler will not check. Advisory: LOW/MEDIUM severity;
    /// flags potential precision-loss or overflow, not a confirmed exploit.
    UncheckedArithmeticCandidate,
    /// Division-before-multiplication ordering within a single expression —
    /// precision-loss pattern where truncated division feeds into multiplication.
    /// Advisory: MEDIUM severity; not a confirmed exploit, but flags a real
    /// structural pattern that commonly underlies rounding/oracle vulnerabilities.
    PrecisionLossCandidate,
}

impl std::fmt::Display for HypothesisType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReentrancyCandidate => write!(f, "ReentrancyCandidate"),
            Self::AuthorityBypassCandidate => write!(f, "AuthorityBypassCandidate"),
            Self::CPITrustViolationCandidate => write!(f, "CPITrustViolationCandidate"),
            Self::StateCorruptionCandidate => write!(f, "StateCorruptionCandidate"),
            Self::EconomicInvariantViolationCandidate => {
                write!(f, "EconomicInvariantViolationCandidate")
            }
            Self::AdversarialPathCandidate => write!(f, "AdversarialPathCandidate"),
            Self::OracleManipulationCandidate => write!(f, "OracleManipulationCandidate"),
            Self::FlashLoanGovernanceCandidate => write!(f, "FlashLoanGovernanceCandidate"),
            Self::MissingAccountConstraintCandidate => {
                write!(f, "MissingAccountConstraintCandidate")
            }
            Self::UncheckedArithmeticCandidate => {
                write!(f, "UncheckedArithmeticCandidate")
            }
            Self::PrecisionLossCandidate => {
                write!(f, "PrecisionLossCandidate")
            }
        }
    }
}

/// Hypothesis severity — re-exported from digger_ir for consistency.
pub use digger_ir::Severity as HypothesisSeverity;

/// Evidence supporting a hypothesis.
///
/// Every piece of evidence references specific graph facts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisEvidence {
    /// Vulnerability path ID (from StandardizedPaths).
    pub path_id: String,
    /// Evidence chain ID (from EvidenceChain).
    pub evidence_chain_id: String,
    /// Functions involved in this evidence.
    pub involved_functions: Vec<String>,
    /// Supporting graph facts — specific edge references.
    pub graph_facts: Vec<GraphFact>,
}

/// A specific graph fact that supports a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphFact {
    /// Type of fact: "external_call", "state_write", "authority_gap", "cpi_call".
    pub fact_type: String,
    /// Function this fact applies to.
    pub function: String,
    /// Detail (state variable name, target name, etc.).
    pub detail: String,
}

/// A hypothesis — a possible exploit explanation derived from structural evidence.
///
/// This is NOT a finding. It is a structural observation backed by evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    /// Unique identifier.
    pub id: HypothesisId,
    /// Type of hypothesis.
    pub hypothesis_type: HypothesisType,
    /// Structural severity classification.
    pub severity: HypothesisSeverity,
    /// Human-readable description.
    pub description: String,
    /// Primary function this hypothesis concerns.
    pub primary_function: String,
    /// Evidence supporting this hypothesis.
    pub evidence: Vec<HypothesisEvidence>,
    /// Structural explanation — why this pattern matters.
    pub structural_explanation: String,
}

/// Result of hypothesis derivation.
///
/// Contains all derived hypotheses plus metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisResult {
    /// Program identifier.
    pub program_id: String,
    /// All derived hypotheses.
    pub hypotheses: Vec<Hypothesis>,
    /// Summary statistics.
    pub summary: HypothesisSummary,
}

/// Summary statistics for hypothesis derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisSummary {
    /// Total hypotheses derived.
    pub total: usize,
    /// Count by type.
    pub reentrancy_count: usize,
    pub authority_bypass_count: usize,
    pub cpi_trust_count: usize,
    pub state_corruption_count: usize,
    pub economic_invariant_violation_count: usize,
    pub adversarial_path_count: usize,
    pub oracle_manipulation_count: usize,
    pub flash_loan_governance_count: usize,
    pub missing_account_constraint_count: usize,
    /// Count by severity.
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}
