use digger_ir;

/// Generation 3 â€” Core Data Models
///
/// Defines the complete type system for exploit synthesis:
/// - ExploitChain: ordered sequence of exploit steps
/// - ExploitStep: single action with prerequisites and evidence
/// - ExploitState: state machine transitions during exploit
/// - CapabilityGraph: extended attacker capability model
/// - ExploitSimulation: logical state evolution
/// - ExploitRanking: deterministic scoring
/// - ExploitExplanation: human-readable reasoning trace
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// â”€â”€â”€ Exploit State Machine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Exploit progression state.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExploitState {
    /// Preconditions identified.
    Preconditions,
    /// Attacker preparing resources/positions.
    Preparation,
    /// Attacker acquiring necessary capabilities.
    CapabilityAcquisition,
    /// Exploit execution begins.
    Execution,
    /// Protocol state is corrupted.
    StateCorruption,
    /// Value extraction from the protocol.
    ValueExtraction,
    /// Exit strategy.
    Exit,
    /// Cleanup or persistence mechanisms.
    Cleanup,
}

impl std::fmt::Display for ExploitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preconditions => write!(f, "Preconditions"),
            Self::Preparation => write!(f, "Preparation"),
            Self::CapabilityAcquisition => write!(f, "CapabilityAcquisition"),
            Self::Execution => write!(f, "Execution"),
            Self::StateCorruption => write!(f, "StateCorruption"),
            Self::ValueExtraction => write!(f, "ValueExtraction"),
            Self::Exit => write!(f, "Exit"),
            Self::Cleanup => write!(f, "Cleanup"),
        }
    }
}

impl ExploitState {
    /// All states in canonical order.
    pub fn all() -> &'static [ExploitState] {
        &[
            Self::Preconditions,
            Self::Preparation,
            Self::CapabilityAcquisition,
            Self::Execution,
            Self::StateCorruption,
            Self::ValueExtraction,
            Self::Exit,
            Self::Cleanup,
        ]
    }

    /// Valid transitions from this state.
    pub fn valid_transitions(&self) -> &'static [ExploitState] {
        match self {
            Self::Preconditions => &[Self::Preparation, Self::Cleanup],
            Self::Preparation => &[Self::CapabilityAcquisition, Self::Cleanup],
            Self::CapabilityAcquisition => &[Self::Execution, Self::Cleanup],
            Self::Execution => &[Self::StateCorruption, Self::Cleanup],
            Self::StateCorruption => &[Self::ValueExtraction, Self::Cleanup],
            Self::ValueExtraction => &[Self::Exit, Self::Cleanup],
            Self::Exit => &[Self::Cleanup],
            Self::Cleanup => &[],
        }
    }
}

// â”€â”€â”€ Capability Graph (Extended) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Attacker capability â€” what the attacker can do.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExploitCapability {
    /// Read state variables.
    ReadState,
    /// Write state variables.
    WriteState,
    /// Upgrade proxy implementation.
    UpgradeProxy,
    /// Mint new tokens.
    MintTokens,
    /// Burn existing tokens.
    BurnTokens,
    /// Transfer tokens/assets.
    TransferAssets,
    /// Delegate authority to another contract.
    DelegateAuthority,
    /// Borrow liquidity.
    BorrowLiquidity,
    /// Trigger liquidation.
    TriggerLiquidation,
    /// Obtain and repay flash loan.
    FlashLoan,
    /// Influence oracle price feeds.
    OracleInfluence,
    /// Influence governance proposals/voting.
    GovernanceInfluence,
    /// Escalate authority beyond intended scope.
    AuthorityEscalation,
    /// Execute cross-program invocation (Solana).
    CrossProgramInvocation,
    /// Execute cross-contract call (EVM).
    CrossContractCall,
    /// Control transaction ordering.
    TransactionOrdering,
    /// Observe private/mempool state.
    ObservePrivateState,
    /// Deploy auxiliary contracts.
    DeployContract,
    /// Split operations across transactions.
    MultiTransaction,
    /// Exploit storage collision.
    StorageCollision,
    /// Exploit delegatecall proxy.
    DelegatecallExploit,
}

impl std::fmt::Display for ExploitCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadState => write!(f, "ReadState"),
            Self::WriteState => write!(f, "WriteState"),
            Self::UpgradeProxy => write!(f, "UpgradeProxy"),
            Self::MintTokens => write!(f, "MintTokens"),
            Self::BurnTokens => write!(f, "BurnTokens"),
            Self::TransferAssets => write!(f, "TransferAssets"),
            Self::DelegateAuthority => write!(f, "DelegateAuthority"),
            Self::BorrowLiquidity => write!(f, "BorrowLiquidity"),
            Self::TriggerLiquidation => write!(f, "TriggerLiquidation"),
            Self::FlashLoan => write!(f, "FlashLoan"),
            Self::OracleInfluence => write!(f, "OracleInfluence"),
            Self::GovernanceInfluence => write!(f, "GovernanceInfluence"),
            Self::AuthorityEscalation => write!(f, "AuthorityEscalation"),
            Self::CrossProgramInvocation => write!(f, "CrossProgramInvocation"),
            Self::CrossContractCall => write!(f, "CrossContractCall"),
            Self::TransactionOrdering => write!(f, "TransactionOrdering"),
            Self::ObservePrivateState => write!(f, "ObservePrivateState"),
            Self::DeployContract => write!(f, "DeployContract"),
            Self::MultiTransaction => write!(f, "MultiTransaction"),
            Self::StorageCollision => write!(f, "StorageCollision"),
            Self::DelegatecallExploit => write!(f, "DelegatecallExploit"),
        }
    }
}

/// Capability edge â€” prerequisite or composition relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityLink {
    /// Source capability.
    pub from: ExploitCapability,
    /// Target capability.
    pub to: ExploitCapability,
    /// Relationship type.
    pub kind: CapabilityLinkKind,
}

/// Kind of capability relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapabilityLinkKind {
    /// `from` is required before `to` can be used.
    Prerequisite,
    /// `from` and `to` combine into a more powerful capability.
    Composes,
    /// `from` enables `to`.
    Enables,
}

/// Capability graph â€” the complete attacker capability model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesisCapabilityGraph {
    /// Detected capabilities.
    pub capabilities: Vec<ExploitCapability>,
    /// Capability relationships.
    pub links: Vec<CapabilityLink>,
    /// Source evidence for each capability.
    pub evidence: BTreeMap<ExploitCapability, Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prerequisites_of() {
        let mut graph = SynthesisCapabilityGraph::empty();
        graph.capabilities.push(ExploitCapability::BorrowLiquidity);
        graph.capabilities.push(ExploitCapability::FlashLoan);
        graph.capabilities.push(ExploitCapability::WriteState);
        graph.links.push(CapabilityLink {
            from: ExploitCapability::BorrowLiquidity,
            to: ExploitCapability::FlashLoan,
            kind: CapabilityLinkKind::Prerequisite,
        });
        graph.links.push(CapabilityLink {
            from: ExploitCapability::AuthorityEscalation,
            to: ExploitCapability::WriteState,
            kind: CapabilityLinkKind::Enables,
        });

        let prereqs = graph.prerequisites_of(&ExploitCapability::FlashLoan);
        assert_eq!(prereqs.len(), 1);
        assert_eq!(prereqs[0], ExploitCapability::BorrowLiquidity);

        let prereqs_write = graph.prerequisites_of(&ExploitCapability::WriteState);
        assert!(prereqs_write.is_empty());

        let prereqs_none = graph.prerequisites_of(&ExploitCapability::MintTokens);
        assert!(prereqs_none.is_empty());
    }
}

impl SynthesisCapabilityGraph {
    pub fn empty() -> Self {
        Self {
            capabilities: vec![],
            links: vec![],
            evidence: BTreeMap::new(),
        }
    }

    /// Check if a capability is available.
    pub fn has(&self, cap: &ExploitCapability) -> bool {
        self.capabilities.contains(cap)
    }

    /// Get prerequisites for a capability.
    pub fn prerequisites_of(&self, cap: &ExploitCapability) -> Vec<ExploitCapability> {
        self.links
            .iter()
            .filter(|l| l.to == *cap && matches!(l.kind, CapabilityLinkKind::Prerequisite))
            .map(|l| l.from.clone())
            .collect()
    }

    /// Check if all prerequisites for a capability are satisfied.
    pub fn prerequisites_satisfied(&self, cap: &ExploitCapability) -> bool {
        self.prerequisites_of(cap).iter().all(|p| self.has(p))
    }
}

// â”€â”€â”€ Exploit Step â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Single step in an exploit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitStep {
    /// Step index (0-based).
    pub index: usize,
    /// State transition this step represents.
    pub state_transition: ExploitState,
    /// Function/program invoked in this step.
    pub function: String,
    /// What this step does.
    pub action: String,
    /// Capability required for this step.
    pub required_capability: ExploitCapability,
    /// State variables affected.
    pub affected_state: Vec<String>,
    /// Assets transferred or affected.
    pub affected_assets: Vec<String>,
    /// Prerequisites that must hold before this step.
    pub prerequisites: Vec<String>,
    /// What this step changes (state mutations).
    pub mutations: Vec<String>,
    /// Evidence backing this step.
    pub evidence_refs: Vec<String>,
    /// Confidence in this step being correct.
    pub confidence: f64,
    /// Explanation of why this step works.
    pub explanation: String,
}

// â”€â”€â”€ Exploit Chain â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Complete exploit chain â€” ordered sequence of steps forming an attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitChain {
    /// Unique chain identifier.
    pub chain_id: String,
    /// Attack goal this chain achieves.
    pub goal: String,
    /// Ordered steps in the chain.
    pub steps: Vec<ExploitStep>,
    /// All capabilities required across all steps.
    pub required_capabilities: Vec<ExploitCapability>,
    /// Assumptions made by this chain.
    pub assumptions: Vec<String>,
    /// Violated invariants.
    pub violated_invariants: Vec<String>,
    /// Evidence provenance â€” references to Gen 1/2/knowledge artifacts.
    pub evidence_provenance: Vec<EvidenceReference>,
    /// Overall confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Overall severity.
    pub severity: digger_ir::Severity,
    /// Historical exploit similarity.
    pub historical_similarity: Vec<HistoricalSimilarity>,
    /// Ranking position (set after ranking).
    pub rank: Option<usize>,
    /// Explanation of why this chain is viable.
    pub explanation: String,
}

// â”€â”€â”€ Evidence Reference â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Reference to a piece of evidence from any layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReference {
    /// What kind of evidence this is.
    pub kind: EvidenceRefKind,
    /// Identifier of the evidence item.
    pub ref_id: String,
    /// Where this evidence came from.
    pub source: String,
    /// How this evidence was obtained.
    pub derivation: String,
}

/// Kind of evidence reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceRefKind {
    /// IR node (function, state variable, edge).
    IrNode,
    /// Graph analysis result.
    GraphAnalysis,
    /// Gen 2 hypothesis.
    Hypothesis,
    /// Knowledge graph node.
    KnowledgeGraph,
    /// Ingested audit finding.
    AuditFinding,
    /// Historical exploit.
    HistoricalExploit,
    /// Protocol pack rule.
    ProtocolPack,
    /// Semantic relationship.
    SemanticRelationship,
    /// Verification property.
    VerificationProperty,
    /// Economic invariant.
    EconomicInvariant,
}

// â”€â”€â”€ Historical Similarity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Similarity to a known historical exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalSimilarity {
    /// Historical exploit identifier.
    pub exploit_id: String,
    /// Protocol of the historical exploit.
    pub protocol: String,
    /// Similarity score (0.0 - 1.0).
    pub similarity: f64,
    /// Shared attack technique.
    pub shared_technique: String,
    /// Shared root cause.
    pub shared_root_cause: String,
    /// Shared invariant violation.
    pub shared_invariant: String,
    /// Differences from the historical exploit.
    pub differences: Vec<String>,
}
