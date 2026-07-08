/// Adversarial Modeling — Generation 2 baseline.
///
/// Pipeline:
///
///   SemanticModels → CapabilityGraph → GoalPreconditions
///       → AttackGoal → GoalSearch → EvidenceGraph → GoalHypothesis
///       → ReasoningSession → CapabilityReport
///
///   ReasoningRule → ReasoningTrace → FailureAnalysis
///       → CorpusFeedback → ProposedRule → RegressionFeedback
///
/// Every inference step is backed by a ReasoningRule with provenance.
/// Every piece of evidence is a node in a directed EvidenceGraph.
/// Every capability has explicit prerequisite edges in a CapabilityGraph.
/// Every analysis run produces a ReasoningSession as canonical record.
/// Confidence is computed from structural properties, not heuristics.
///
/// All structures are deterministic and JSON serializable.
/// No exploit signatures. No heuristics. No AI.
use serde::{Deserialize, Serialize};

/// Errors for adversarial report serialization.
#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("Invalid report JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

// ═══════════════════════════════════════════════════════════════
// Section 1: Reasoning Rule — first-class inference primitive
// ═══════════════════════════════════════════════════════════════

/// A reasoning rule — a single inference used by the engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningRule {
    pub rule_id: String,
    pub kind: RuleKind,
    pub description: String,
    pub inputs: Vec<String>,
    pub preconditions: Vec<String>,
    pub outputs: Vec<String>,
    pub confidence_weight: f64,
    pub provenance: RuleProvenance,
    pub validation_history: Vec<ValidationEntry>,
}

/// Kind of reasoning rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleKind {
    CapabilityDetection,
    GoalDerivation,
    PathSearch,
    EvidenceCollection,
    ConfidenceComputation,
    CapabilityComposition,
    GoalPreconditionCheck,
}

impl std::fmt::Display for RuleKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityDetection => write!(f, "capability_detection"),
            Self::GoalDerivation => write!(f, "goal_derivation"),
            Self::PathSearch => write!(f, "path_search"),
            Self::EvidenceCollection => write!(f, "evidence_collection"),
            Self::ConfidenceComputation => write!(f, "confidence_computation"),
            Self::CapabilityComposition => write!(f, "capability_composition"),
            Self::GoalPreconditionCheck => write!(f, "goal_precondition_check"),
        }
    }
}

/// Where a rule came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleProvenance {
    pub origin: String,
    pub phase: u32,
    pub last_validated: Option<String>,
}

/// A validation record for a rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationEntry {
    pub run_hash: String,
    pub corpus_id: String,
    pub result: ValidationResult,
}

/// Result of validating a rule against a corpus entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationResult {
    TruePositive,
    FalsePositive,
    NoOutput,
    Unknown,
}

// ═══════════════════════════════════════════════════════════════
// Section 2: CapabilityGraph — capabilities with prerequisite edges
// ═══════════════════════════════════════════════════════════════

/// A node in the capability graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityNode {
    pub capability_id: String,
    pub kind: CapabilityKind,
    pub functions: Vec<String>,
    pub state_vars: Vec<String>,
    pub detected_by: String,
}

/// An edge in the capability graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityEdge {
    pub from: String,
    pub to: String,
    pub kind: CapabilityEdgeKind,
}

/// Kind of capability edge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CapabilityEdgeKind {
    PrerequisiteOf,
    ComposesWith,
}

impl std::fmt::Display for CapabilityEdgeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrerequisiteOf => write!(f, "prerequisite_of"),
            Self::ComposesWith => write!(f, "composes_with"),
        }
    }
}

/// The capability graph — capabilities with prerequisite and composition edges.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityGraph {
    pub nodes: Vec<CapabilityNode>,
    pub edges: Vec<CapabilityEdge>,
    /// Capability compositions discovered during analysis.
    pub compositions: Vec<CapabilityComposition>,
}

impl CapabilityGraph {
    pub fn kinds(&self) -> std::collections::BTreeSet<&CapabilityKind> {
        self.nodes.iter().map(|n| &n.kind).collect()
    }

    pub fn has(&self, kind: &CapabilityKind) -> bool {
        self.nodes.iter().any(|n| n.kind == *kind)
    }

    pub fn transitive_prerequisites(&self, capability_id: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut visited = std::collections::BTreeSet::new();
        let mut stack = vec![capability_id.to_string()];

        while let Some(current) = stack.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            for edge in &self.edges {
                if edge.from == current && matches!(edge.kind, CapabilityEdgeKind::PrerequisiteOf) {
                    result.push(edge.to.clone());
                    stack.push(edge.to.clone());
                }
            }
        }

        result.sort();
        result.dedup();
        result
    }

    pub fn prerequisites_satisfied(&self, capability_id: &str) -> bool {
        let prereqs = self.transitive_prerequisites(capability_id);
        let present_ids: std::collections::BTreeSet<&String> =
            self.nodes.iter().map(|n| &n.capability_id).collect();
        prereqs.iter().all(|p| present_ids.contains(p))
    }

    pub fn composition_pairs(&self) -> Vec<(&CapabilityNode, &CapabilityNode)> {
        let mut result = Vec::new();
        for edge in &self.edges {
            if matches!(edge.kind, CapabilityEdgeKind::ComposesWith) {
                if let (Some(from), Some(to)) = (
                    self.nodes.iter().find(|n| n.capability_id == edge.from),
                    self.nodes.iter().find(|n| n.capability_id == edge.to),
                ) {
                    result.push((from, to));
                }
            }
        }
        result
    }

    pub fn flat_capabilities(&self) -> Vec<AttackerCapability> {
        self.nodes
            .iter()
            .map(|n| AttackerCapability {
                capability_id: n.capability_id.clone(),
                kind: n.kind.clone(),
                functions: n.functions.clone(),
                state_vars: n.state_vars.clone(),
                prerequisites: self
                    .edges
                    .iter()
                    .filter(|e| {
                        e.from == n.capability_id
                            && matches!(e.kind, CapabilityEdgeKind::PrerequisiteOf)
                    })
                    .map(|e| e.to.clone())
                    .collect(),
            })
            .collect()
    }
}

/// A capability composition — two or more capabilities that combine into a stronger capability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityComposition {
    /// Identifier (deterministic).
    pub composition_id: String,
    /// Capabilities that compose.
    pub capabilities: Vec<CapabilityKind>,
    /// The composite capability kind.
    pub composite: CompositeCapabilityKind,
    /// Why these capabilities compose.
    pub reason: String,
    /// The rule that discovered this composition.
    pub discovered_by: String,
}

/// Composite capability kinds — capabilities that emerge from composition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompositeCapabilityKind {
    /// Reentrancy across multiple transactions.
    MultiTransactionReentrancy,
    /// MEV extraction via observation + ordering control.
    MevExtraction,
    /// Flash loan price manipulation.
    FlashLoanPriceManipulation,
    /// Governance attack via liquidity + voting.
    GovernanceLiquidityAttack,
    /// Cross-function state corruption.
    CrossFunctionCorruption,
}

impl std::fmt::Display for CompositeCapabilityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MultiTransactionReentrancy => write!(f, "multi_transaction_reentrancy"),
            Self::MevExtraction => write!(f, "mev_extraction"),
            Self::FlashLoanPriceManipulation => write!(f, "flash_loan_price_manipulation"),
            Self::GovernanceLiquidityAttack => write!(f, "governance_liquidity_attack"),
            Self::CrossFunctionCorruption => write!(f, "cross_function_corruption"),
        }
    }
}

/// Flat attacker capability for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackerCapability {
    pub capability_id: String,
    pub kind: CapabilityKind,
    pub functions: Vec<String>,
    pub state_vars: Vec<String>,
    pub prerequisites: Vec<String>,
}

/// Kind of attacker capability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityKind {
    CanBorrowLiquidity,
    CanManipulatePrice,
    CanDelaySettlement,
    CanReenter,
    CanControlGovernance,
    CanTriggerCallback,
    CanDeployContract,
    CanSplitAcrossTransactions,
    CanControlTransactionOrdering,
    CanObserveState,
    CanCallPublicFunction,
    /// Attacker can exploit storage collision between proxy and implementation.
    CanExploitStorageCollision,
    /// Attacker can upgrade a proxy implementation.
    CanUpgradeProxy,
    /// Attacker can call across contracts within the protocol.
    CanCallCrossContract,
    /// Attacker can exploit delegatecall to modify proxy state.
    CanExploitDelegatecall,
}

impl std::fmt::Display for CapabilityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CanBorrowLiquidity => write!(f, "can_borrow_liquidity"),
            Self::CanManipulatePrice => write!(f, "can_manipulate_price"),
            Self::CanDelaySettlement => write!(f, "can_delay_settlement"),
            Self::CanReenter => write!(f, "can_reenter"),
            Self::CanControlGovernance => write!(f, "can_control_governance"),
            Self::CanTriggerCallback => write!(f, "can_trigger_callback"),
            Self::CanDeployContract => write!(f, "can_deploy_contract"),
            Self::CanSplitAcrossTransactions => write!(f, "can_split_across_transactions"),
            Self::CanControlTransactionOrdering => write!(f, "can_control_transaction_ordering"),
            Self::CanObserveState => write!(f, "can_observe_state"),
            Self::CanCallPublicFunction => write!(f, "can_call_public_function"),
            Self::CanExploitStorageCollision => write!(f, "can_exploit_storage_collision"),
            Self::CanUpgradeProxy => write!(f, "can_upgrade_proxy"),
            Self::CanCallCrossContract => write!(f, "can_call_cross_contract"),
            Self::CanExploitDelegatecall => write!(f, "can_exploit_delegatecall"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 3: AttackGoal
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttackGoal {
    DrainAssets,
    BreakEconomicInvariant,
    CorruptAccounting,
    CreateBadDebt,
    GainUnauthorizedControl,
    BypassAuthority,
    FreezeFunds,
    PreventSettlement,
    ManipulatePrice,
    ExhaustResources,
}

impl std::fmt::Display for AttackGoal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DrainAssets => write!(f, "drain_assets"),
            Self::BreakEconomicInvariant => write!(f, "break_economic_invariant"),
            Self::CorruptAccounting => write!(f, "corrupt_accounting"),
            Self::CreateBadDebt => write!(f, "create_bad_debt"),
            Self::GainUnauthorizedControl => write!(f, "gain_unauthorized_control"),
            Self::BypassAuthority => write!(f, "bypass_authority"),
            Self::FreezeFunds => write!(f, "freeze_funds"),
            Self::PreventSettlement => write!(f, "prevent_settlement"),
            Self::ManipulatePrice => write!(f, "manipulate_price"),
            Self::ExhaustResources => write!(f, "exhaust_resources"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 4: GoalCapabilityPattern — declarative search primitive
// ═══════════════════════════════════════════════════════════════

/// A declarative pattern linking a goal to the capabilities and constraints
/// that make it achievable. Replaces embedded procedural search logic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GoalCapabilityPattern {
    /// Pattern identifier.
    pub pattern_id: String,
    /// The attack goal this pattern serves.
    pub goal: AttackGoal,
    /// Required capability kinds.
    pub required_capabilities: Vec<CapabilityKind>,
    /// Which semantic model provides the constraint.
    pub constraint_source: EvidenceSource,
    /// The constraint type (e.g., "conservation", "collateralization").
    pub constraint_type: String,
    /// The semantic constraint violated.
    pub violated_constraint: String,
    /// The rule that implements this pattern.
    pub rule_id: String,
}

// ═══════════════════════════════════════════════════════════════
// Section 5: GoalPreconditions
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GoalPrecondition {
    pub goal: AttackGoal,
    pub required_capabilities: Vec<CapabilityKind>,
    pub required_relations: Vec<String>,
    pub required_anomalies: Vec<String>,
    pub derived_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GoalPreconditionResult {
    pub goal: AttackGoal,
    pub satisfied: bool,
    pub missing_capabilities: Vec<CapabilityKind>,
    pub missing_relations: Vec<String>,
    pub missing_anomalies: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Section 6: EvidenceGraph — directed evidence with causal edges
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceNode {
    pub node_id: String,
    pub source_model: EvidenceSource,
    pub model_id: String,
    pub description: String,
}

/// Which semantic model produced evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceSource {
    StateTransition,
    ResourceLifecycle,
    TemporalDependency,
    TemporalSequence,
    ActorInteraction,
    EconomicRelation,
    VerificationProperty,
    KnowledgeEvidence,
}

impl std::fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateTransition => write!(f, "state_transition"),
            Self::ResourceLifecycle => write!(f, "resource_lifecycle"),
            Self::TemporalDependency => write!(f, "temporal_dependency"),
            Self::TemporalSequence => write!(f, "temporal_sequence"),
            Self::ActorInteraction => write!(f, "actor_interaction"),
            Self::EconomicRelation => write!(f, "economic_relation"),
            Self::VerificationProperty => write!(f, "verification_property"),
            Self::KnowledgeEvidence => write!(f, "knowledge_evidence"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceEdge {
    pub from: String,
    pub to: String,
    pub kind: EvidenceEdgeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceEdgeKind {
    Enables,
    Violates,
    Requires,
    DerivesFrom,
}

impl std::fmt::Display for EvidenceEdgeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enables => write!(f, "enables"),
            Self::Violates => write!(f, "violates"),
            Self::Requires => write!(f, "requires"),
            Self::DerivesFrom => write!(f, "derives_from"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceGraph {
    pub nodes: Vec<EvidenceNode>,
    pub edges: Vec<EvidenceEdge>,
}

impl EvidenceGraph {
    pub fn empty() -> Self {
        Self {
            nodes: vec![],
            edges: vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn model_diversity(&self) -> usize {
        self.nodes
            .iter()
            .map(|n| &n.source_model)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    pub fn total_nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn nodes_from(&self, source: &EvidenceSource) -> Vec<&EvidenceNode> {
        self.nodes
            .iter()
            .filter(|n| n.source_model == *source)
            .collect()
    }

    pub fn merge(&mut self, other: &EvidenceGraph) {
        for node in &other.nodes {
            if !self.nodes.iter().any(|n| n.node_id == node.node_id) {
                self.nodes.push(node.clone());
            }
        }
        for edge in &other.edges {
            if !self
                .edges
                .iter()
                .any(|e| e.from == edge.from && e.to == edge.to && e.kind == edge.kind)
            {
                self.edges.push(edge.clone());
            }
        }
    }

    pub fn to_flat_evidence(&self) -> SemanticEvidence {
        let mut evidence = SemanticEvidence::empty();
        for node in &self.nodes {
            match node.source_model {
                EvidenceSource::EconomicRelation => {
                    evidence.violated_relations.push(node.model_id.clone())
                }
                EvidenceSource::VerificationProperty => {
                    evidence.violated_properties.push(node.model_id.clone())
                }
                EvidenceSource::ResourceLifecycle => {
                    evidence.violated_lifecycle.push(node.model_id.clone())
                }
                EvidenceSource::TemporalDependency | EvidenceSource::TemporalSequence => {
                    evidence.exploited_dependencies.push(node.model_id.clone())
                }
                EvidenceSource::ActorInteraction => {
                    evidence.actor_interactions.push(node.model_id.clone())
                }
                EvidenceSource::StateTransition => {
                    evidence.enabling_transitions.push(node.model_id.clone())
                }
                EvidenceSource::KnowledgeEvidence => {
                    evidence.enabling_transitions.push(node.model_id.clone())
                }
            }
        }
        evidence
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticEvidence {
    pub violated_relations: Vec<String>,
    pub violated_properties: Vec<String>,
    pub violated_lifecycle: Vec<String>,
    pub exploited_dependencies: Vec<String>,
    pub actor_interactions: Vec<String>,
    pub enabling_transitions: Vec<String>,
}

impl SemanticEvidence {
    pub fn empty() -> Self {
        Self {
            violated_relations: vec![],
            violated_properties: vec![],
            violated_lifecycle: vec![],
            exploited_dependencies: vec![],
            actor_interactions: vec![],
            enabling_transitions: vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.violated_relations.is_empty()
            && self.violated_properties.is_empty()
            && self.violated_lifecycle.is_empty()
            && self.exploited_dependencies.is_empty()
            && self.actor_interactions.is_empty()
            && self.enabling_transitions.is_empty()
    }

    pub fn total(&self) -> usize {
        self.violated_relations.len()
            + self.violated_properties.len()
            + self.violated_lifecycle.len()
            + self.exploited_dependencies.len()
            + self.actor_interactions.len()
            + self.enabling_transitions.len()
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 7: ConfidenceWeights — configurable confidence model
// ═══════════════════════════════════════════════════════════════

/// Weights for the structural confidence model.
/// Each weight corresponds to a factor in confidence computation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidenceWeights {
    /// Weight for semantic model diversity (how many models contribute evidence).
    pub model_diversity: f64,
    /// Weight for prerequisite satisfaction (are required capabilities' prereqs met).
    pub prerequisite_satisfaction: f64,
    /// Weight for path parsimony (shorter paths are more feasible).
    pub path_parsimony: f64,
    /// Weight for evidence edge density (more causal connections = stronger).
    pub evidence_edge_density: f64,
}

impl Default for ConfidenceWeights {
    fn default() -> Self {
        Self {
            model_diversity: 0.4,
            prerequisite_satisfaction: 0.3,
            path_parsimony: 0.2,
            evidence_edge_density: 0.1,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 8: AttackPath and GoalHypothesis
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackPrecondition {
    pub capability: CapabilityKind,
    pub state_var: String,
    pub is_satisfiable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackStep {
    pub index: usize,
    pub capability: CapabilityKind,
    pub function: String,
    pub state_var: String,
    pub violated_constraint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackPath {
    pub path_id: String,
    pub goal: AttackGoal,
    pub steps: Vec<AttackStep>,
    pub required_capabilities: Vec<CapabilityKind>,
    pub violated_constraint: String,
    pub violated_invariant: String,
    pub evidence_graph: EvidenceGraph,
    pub evidence: SemanticEvidence,
    pub confidence: f64,
    pub severity: digger_ir::Severity,
    pub rules_applied: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GoalHypothesis {
    pub goal: AttackGoal,
    pub paths: Vec<AttackPath>,
    pub evidence_graph: EvidenceGraph,
    pub evidence: SemanticEvidence,
    pub confidence: f64,
    pub is_feasible: bool,
    pub precondition_result: GoalPreconditionResult,
}

// ═══════════════════════════════════════════════════════════════
// Section 9: Introspection Layer
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningTrace {
    pub entries: Vec<TraceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceEntry {
    pub rule_id: String,
    pub rule_kind: RuleKind,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub fired: bool,
    pub entry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FailureAnalysis {
    pub failures: Vec<FailureReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FailureReason {
    pub goal: AttackGoal,
    pub reason: FailureKind,
    pub missing: Vec<String>,
    pub rule_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailureKind {
    MissingCapability,
    MissingRelation,
    NoSemanticSupport,
    CapabilityPrereqsUnmet,
}

impl std::fmt::Display for FailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCapability => write!(f, "missing_capability"),
            Self::MissingRelation => write!(f, "missing_relation"),
            Self::NoSemanticSupport => write!(f, "no_semantic_support"),
            Self::CapabilityPrereqsUnmet => write!(f, "capability_prereqs_unmet"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorpusFeedback {
    pub entries: Vec<FeedbackEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeedbackEntry {
    pub path_id: String,
    pub protocol_id: String,
    pub result: ValidationResult,
    pub explanation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProposedRule {
    pub rule_id: String,
    pub description: String,
    pub kind: RuleKind,
    pub condition: String,
    pub evidence_support: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegressionFeedback {
    pub entries: Vec<RegressionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegressionEntry {
    pub rule_id: String,
    pub path_id: String,
    pub was_true_positive: bool,
    pub now_detected: bool,
}

// ═══════════════════════════════════════════════════════════════
// Section 10: ReasoningSession — canonical execution record
// ═══════════════════════════════════════════════════════════════

/// Snapshot of the semantic model inputs at analysis time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputSnapshot {
    pub transition_count: usize,
    pub lifecycle_count: usize,
    pub dependency_count: usize,
    pub sequence_count: usize,
    pub actor_count: usize,
    pub interaction_count: usize,
    pub relation_count: usize,
    pub invariant_count: usize,
    pub property_count: usize,
    /// Deterministic hash of all inputs.
    pub input_hash: String,
}

/// Analysis assumptions and configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningContext {
    /// Analysis scope: "single_file", "multi_file", "protocol".
    pub scope: String,
    /// Target chain: "ethereum", "solana", "unknown".
    pub chain: String,
    /// Source language: "solidity", "anchor", "rust", "auto".
    pub language: String,
    /// Generation 2 baseline version.
    pub baseline_version: String,
    /// Enabled reasoning rule IDs.
    pub enabled_rules: Vec<String>,
    /// Confidence weights used.
    pub confidence_weights: ConfidenceWeights,
    /// Maximum capabilities per report.
    pub max_capabilities: usize,
    /// Maximum attack paths per report.
    pub max_attack_paths: usize,
    /// Maximum hypotheses per report.
    pub max_hypotheses: usize,
}

/// The canonical execution record for every analysis run.
/// CapabilityReport derives from this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningSession {
    /// Deterministic session identifier (hash of inputs + context).
    pub session_id: String,
    /// Protocol identifier.
    pub protocol_id: String,
    /// Input snapshot.
    pub input: InputSnapshot,
    /// Analysis context.
    pub context: ReasoningContext,
    /// Capability graph produced.
    pub capability_graph: CapabilityGraph,
    /// Goals derived.
    pub goals_derived: Vec<AttackGoal>,
    /// Precondition results.
    pub precondition_results: Vec<GoalPreconditionResult>,
    /// All attack paths found.
    pub paths_found: Vec<AttackPath>,
    /// Goal hypotheses.
    pub hypotheses: Vec<GoalHypothesis>,
    /// Failure analysis.
    pub failures: FailureAnalysis,
    /// Reasoning trace.
    pub trace: ReasoningTrace,
    /// All reasoning rules used.
    pub rules_used: Vec<ReasoningRule>,
    /// Summary.
    pub summary: AdversarialSummary,
}

// ═══════════════════════════════════════════════════════════════
// Section 11: Report — user-facing view derived from session
// ═══════════════════════════════════════════════════════════════

/// The complete adversarial analysis output — derived from ReasoningSession.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityReport {
    /// The canonical session this report derives from.
    pub session: ReasoningSession,
    /// Flat capabilities (backward compatibility).
    pub capabilities: Vec<AttackerCapability>,
    /// Goal hypotheses (convenience alias).
    pub hypotheses: Vec<GoalHypothesis>,
    /// All attack paths (convenience alias).
    pub attack_paths: Vec<AttackPath>,
    /// Summary (convenience alias).
    pub summary: AdversarialSummary,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdversarialSummary {
    pub total_capabilities: usize,
    pub total_attack_paths: usize,
    pub total_hypotheses: usize,
    pub feasible_goals: usize,
    pub violable_constraints: usize,
    pub total_rules_applied: usize,
    pub total_failures: usize,
    pub evidence_model_diversity: usize,
    pub total_compositions: usize,
}
