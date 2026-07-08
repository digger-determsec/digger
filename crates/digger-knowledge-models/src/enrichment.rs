/// Knowledge enrichment — deeper semantic relationships for existing artifacts.
///
/// Every enrichment is deterministic and traceable back to source data.
/// No concepts are invented without evidence.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Enriched exploit metadata — deeper semantic data extracted from exploit sources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExploitMetadata {
    /// Exploit timeline.
    pub timeline: ExploitTimeline,
    /// Attack prerequisites.
    pub prerequisites: Vec<AttackPrerequisite>,
    /// Attack path (ordered steps).
    pub attack_path: Vec<AttackStep>,
    /// State transitions caused by the exploit.
    pub state_transitions: Vec<ExploitStateTransition>,
    /// Affected protocol components.
    pub affected_components: Vec<AffectedComponent>,
    /// Trust boundary violations.
    pub trust_boundary_violations: Vec<TrustBoundaryViolation>,
    /// Broken invariants.
    pub broken_invariants: Vec<BrokenInvariant>,
    /// Economic assumptions violated.
    pub economic_assumptions_violated: Vec<String>,
    /// Privilege assumptions violated.
    pub privilege_assumptions_violated: Vec<String>,
    /// Attacker capabilities required.
    pub required_capabilities: Vec<String>,
    /// Affected assets.
    pub affected_assets: Vec<AffectedAsset>,
    /// Exploit outcome.
    pub outcome: ExploitOutcome,
    /// Mitigation strategy.
    pub mitigation: Option<MitigationStrategy>,
    /// Patched behavior (if known).
    pub patched_behavior: Option<String>,
    /// Version information.
    pub version_info: Option<VersionInfo>,
    /// Affected standards.
    pub affected_standards: Vec<String>,
    /// Protocol mechanisms involved.
    pub protocol_mechanisms: Vec<String>,
    /// Protocol lifecycle phase at time of exploit.
    pub lifecycle_phase: Option<String>,
    /// Exploit complexity.
    pub complexity: ExploitComplexity,
    /// Exploit repeatability.
    pub repeatability: ExploitRepeatability,
}

/// Exploit timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExploitTimeline {
    /// When the vulnerability was introduced (if known).
    pub introduced: Option<String>,
    /// When the exploit occurred.
    pub exploited: Option<String>,
    /// When the exploit was discovered.
    pub discovered: Option<String>,
    /// When the fix was deployed.
    pub patched: Option<String>,
    /// Duration the vulnerability was live (if known).
    pub live_duration: Option<String>,
}

/// Attack prerequisite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackPrerequisite {
    /// Prerequisite description.
    pub description: String,
    /// Prerequisite kind.
    pub kind: PrerequisiteKind,
    /// Whether the prerequisite is controllable by the attacker.
    pub attacker_controllable: bool,
}

/// Kind of attack prerequisite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrerequisiteKind {
    /// Requires specific contract state.
    ContractState,
    /// Requires specific market conditions.
    MarketCondition,
    /// Requires specific token properties.
    TokenProperty,
    /// Requires specific oracle behavior.
    OracleBehavior,
    /// Requires specific governance state.
    GovernanceState,
    /// Requires specific liquidity conditions.
    LiquidityCondition,
    /// Requires specific block conditions.
    BlockCondition,
    /// Requires specific external contract behavior.
    ExternalContract,
    /// Requires specific timing.
    Timing,
    /// Other prerequisite.
    Other,
}

impl std::fmt::Display for PrerequisiteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContractState => write!(f, "contract_state"),
            Self::MarketCondition => write!(f, "market_condition"),
            Self::TokenProperty => write!(f, "token_property"),
            Self::OracleBehavior => write!(f, "oracle_behavior"),
            Self::GovernanceState => write!(f, "governance_state"),
            Self::LiquidityCondition => write!(f, "liquidity_condition"),
            Self::BlockCondition => write!(f, "block_condition"),
            Self::ExternalContract => write!(f, "external_contract"),
            Self::Timing => write!(f, "timing"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Attack step in an exploit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackStep {
    /// Step index.
    pub index: usize,
    /// Step description.
    pub description: String,
    /// Action taken.
    pub action: String,
    /// Target component.
    pub target: String,
    /// State change caused.
    pub state_change: Option<String>,
}

/// State transition caused by an exploit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExploitStateTransition {
    /// Component affected.
    pub component: String,
    /// State variable affected.
    pub state_var: String,
    /// Previous value (if known).
    pub previous_value: Option<String>,
    /// New value (if known).
    pub new_value: Option<String>,
    /// Transition description.
    pub description: String,
}

/// Affected protocol component.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AffectedComponent {
    /// Component name (contract, module, function).
    pub name: String,
    /// Component kind.
    pub kind: ComponentKind,
    /// How it was affected.
    pub impact: String,
}

/// Kind of protocol component.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComponentKind {
    Contract,
    Function,
    StateVariable,
    Modifier,
    Library,
    Interface,
    Proxy,
    Oracle,
    Token,
}

impl std::fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Contract => write!(f, "contract"),
            Self::Function => write!(f, "function"),
            Self::StateVariable => write!(f, "state_variable"),
            Self::Modifier => write!(f, "modifier"),
            Self::Library => write!(f, "library"),
            Self::Interface => write!(f, "interface"),
            Self::Proxy => write!(f, "proxy"),
            Self::Oracle => write!(f, "oracle"),
            Self::Token => write!(f, "token"),
        }
    }
}

/// Trust boundary violation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustBoundaryViolation {
    /// Boundary description.
    pub boundary: String,
    /// How it was violated.
    pub violation: String,
    /// Consequence.
    pub consequence: String,
}

/// Broken invariant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrokenInvariant {
    /// Invariant description.
    pub invariant: String,
    /// Invariant kind.
    pub kind: String,
    /// How it was broken.
    pub violation: String,
    /// Consequence.
    pub consequence: String,
}

/// Affected asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AffectedAsset {
    /// Asset name or symbol.
    pub name: String,
    /// Asset type (token, NFT, LP, etc.).
    pub asset_type: String,
    /// Amount affected (if known).
    pub amount: Option<String>,
    /// Chain.
    pub chain: String,
}

/// Exploit outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExploitOutcome {
    /// Total loss amount.
    pub total_loss: Option<String>,
    /// Amount returned.
    pub returned: Option<String>,
    /// Net loss.
    pub net_loss: Option<String>,
    /// Whether the exploit was successful.
    pub successful: bool,
    /// Whether funds were recovered.
    pub recovered: bool,
    /// Outcome description.
    pub description: String,
}

/// Mitigation strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MitigationStrategy {
    /// Mitigation description.
    pub description: String,
    /// Mitigation kind.
    pub kind: MitigationKind,
    /// Whether the mitigation was implemented.
    pub implemented: bool,
    /// Implementation details.
    pub implementation: Option<String>,
}

/// Kind of mitigation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MitigationKind {
    /// Code fix.
    CodeFix,
    /// Configuration change.
    ConfigurationChange,
    /// Circuit breaker activation.
    CircuitBreaker,
    /// Governance action.
    GovernanceAction,
    /// Migration.
    Migration,
    /// Monitoring.
    Monitoring,
    /// Other.
    Other,
}

impl std::fmt::Display for MitigationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodeFix => write!(f, "code_fix"),
            Self::ConfigurationChange => write!(f, "configuration_change"),
            Self::CircuitBreaker => write!(f, "circuit_breaker"),
            Self::GovernanceAction => write!(f, "governance_action"),
            Self::Migration => write!(f, "migration"),
            Self::Monitoring => write!(f, "monitoring"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Version information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VersionInfo {
    /// Contract version (if known).
    pub contract_version: Option<String>,
    /// Compiler version.
    pub compiler_version: Option<String>,
    /// Framework version.
    pub framework_version: Option<String>,
}

/// Exploit complexity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExploitComplexity {
    /// Simple: single transaction, no special setup.
    Simple,
    /// Moderate: multiple transactions or specific conditions.
    Moderate,
    /// Complex: requires significant setup, timing, or resources.
    Complex,
}

impl std::fmt::Display for ExploitComplexity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Simple => write!(f, "simple"),
            Self::Moderate => write!(f, "moderate"),
            Self::Complex => write!(f, "complex"),
        }
    }
}

/// Exploit repeatability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExploitRepeatability {
    /// Repeatable: can be executed multiple times.
    Repeatable,
    /// One-shot: can only be executed once.
    OneShot,
    /// Conditional: repeatable under specific conditions.
    Conditional,
}

impl std::fmt::Display for ExploitRepeatability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repeatable => write!(f, "repeatable"),
            Self::OneShot => write!(f, "one_shot"),
            Self::Conditional => write!(f, "conditional"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Cross-Linking — semantic relationships between artifacts
// ═══════════════════════════════════════════════════════════════

/// A semantic link between two knowledge artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticLink {
    /// Source artifact ID.
    pub source_id: String,
    /// Target artifact ID.
    pub target_id: String,
    /// Link kind.
    pub kind: LinkKind,
    /// Link description.
    pub description: String,
    /// Structural relationship score.
    pub score: RelationshipScore,
    /// Confidence in this link (0.0–1.0).
    pub confidence: f64,
}

/// Structural relationship score — deterministic, evidence-backed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelationshipScore {
    /// Overall score (0.0–1.0).
    pub score: f64,
    /// Contributing evidence factors.
    pub factors: Vec<ScoreFactor>,
}

/// A contributing factor to a relationship score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreFactor {
    /// Factor name.
    pub name: String,
    /// Factor weight (0.0–1.0).
    pub weight: f64,
    /// Factor value (0.0–1.0).
    pub value: f64,
    /// Evidence supporting this factor.
    pub evidence: String,
}

/// Kind of semantic link — causal and semantic relationships.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LinkKind {
    /// A causes B (exploit causes loss, violation causes consequence).
    Causes,
    /// A enables B (capability enables exploit, precondition enables attack).
    Enables,
    /// A depends on B (protocol depends on oracle, exploit depends on liquidity).
    DependsOn,
    /// A requires B (exploit requires capability, invariant requires enforcement).
    Requires,
    /// A mitigates B (fix mitigates vulnerability, guard mitigates reentrancy).
    Mitigates,
    /// A protects against B (pattern protects against attack).
    ProtectsAgainst,
    /// A violates B (exploit violates invariant, finding violates property).
    Violates,
    /// A preserves B (check preserves invariant, guard preserves state).
    Preserves,
    /// A derives from B (finding derives from code, exploit derives from vulnerability).
    DerivesFrom,
    /// A specializes B (specific pattern specializes general class).
    Specializes,
    /// A generalizes B (general class encompasses specific pattern).
    Generalizes,
    /// A is equivalent to B (same underlying issue).
    EquivalentTo,
    /// A contradicts B (one finding contradicts another).
    Contradicts,
    /// A supersedes B (newer finding replaces older).
    Supersedes,
    /// A precedes B (temporal ordering in attack chain).
    Precedes,
    /// A follows B (temporal ordering in attack chain).
    Follows,
    /// A influences B (economic influence, price influence).
    Influences,
    /// A impacts B (exploit impacts protocol, change impacts behavior).
    Impacts,
    /// Exploit relates to audit finding (cross-source linkage).
    ExploitToAuditFinding,
    /// Exploit relates to root cause.
    ExploitToRootCause,
    /// Exploit relates to attack technique.
    ExploitToAttackTechnique,
    /// Exploit relates to another exploit.
    ExploitToExploit,
    /// Protocol relates to protocol.
    ProtocolToProtocol,
}

impl std::fmt::Display for LinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Causes => write!(f, "causes"),
            Self::Enables => write!(f, "enables"),
            Self::DependsOn => write!(f, "depends_on"),
            Self::Requires => write!(f, "requires"),
            Self::Mitigates => write!(f, "mitigates"),
            Self::ProtectsAgainst => write!(f, "protects_against"),
            Self::Violates => write!(f, "violates"),
            Self::Preserves => write!(f, "preserves"),
            Self::DerivesFrom => write!(f, "derives_from"),
            Self::Specializes => write!(f, "specializes"),
            Self::Generalizes => write!(f, "generalizes"),
            Self::EquivalentTo => write!(f, "equivalent_to"),
            Self::Contradicts => write!(f, "contradicts"),
            Self::Supersedes => write!(f, "supersedes"),
            Self::Precedes => write!(f, "precedes"),
            Self::Follows => write!(f, "follows"),
            Self::Influences => write!(f, "influences"),
            Self::Impacts => write!(f, "impacts"),
            Self::ExploitToAuditFinding => write!(f, "exploit_to_audit_finding"),
            Self::ExploitToRootCause => write!(f, "exploit_to_root_cause"),
            Self::ExploitToAttackTechnique => write!(f, "exploit_to_attack_technique"),
            Self::ExploitToExploit => write!(f, "exploit_to_exploit"),
            Self::ProtocolToProtocol => write!(f, "protocol_to_protocol"),
        }
    }
}

/// Enriched knowledge graph with cross-links.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnrichedKnowledgeGraph {
    /// Original knowledge graph nodes.
    pub nodes: Vec<super::graph::KnowledgeNode>,
    /// Original knowledge graph edges.
    pub edges: Vec<super::graph::KnowledgeEdge>,
    /// Semantic cross-links.
    pub links: Vec<SemanticLink>,
    /// Exploit metadata.
    pub exploit_metadata: BTreeMap<String, ExploitMetadata>,
}

/// Analytics for semantic relationship density.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelationshipAnalytics {
    /// Exploit-to-audit linkage rate.
    pub exploit_to_audit_rate: f64,
    /// Exploit-to-standard linkage rate.
    pub exploit_to_standard_rate: f64,
    /// Exploit-to-invariant linkage rate.
    pub exploit_to_invariant_rate: f64,
    /// Protocol component coverage (components with at least one exploit).
    pub protocol_component_coverage: usize,
    /// Total protocol components known.
    pub total_protocol_components: usize,
    /// Invariant coverage (invariants with at least one violation).
    pub invariant_coverage: usize,
    /// Total invariants known.
    pub total_invariants: usize,
    /// Trust boundary coverage.
    pub trust_boundary_coverage: usize,
    /// Total trust boundaries known.
    pub total_trust_boundaries: usize,
    /// Semantic relationship density (links per artifact).
    pub relationship_density: f64,
    /// Average relationships per artifact.
    pub avg_relationships_per_artifact: f64,
    /// Most common exploit chains.
    pub common_exploit_chains: Vec<ExploitChain>,
    /// Most common invariant violations.
    pub common_invariant_violations: Vec<InvariantViolationStat>,
    /// Ontology concepts with weakest evidence.
    pub weak_concepts: Vec<WeakConcept>,
    /// Relationship score distribution.
    pub score_distribution: ScoreDistribution,
    /// Strongest semantic relationships.
    pub strongest_relationships: Vec<SemanticLink>,
    /// Weakest semantic relationships.
    pub weakest_relationships: Vec<SemanticLink>,
    /// Most connected concepts.
    pub most_connected: Vec<ConnectedConcept>,
    /// Relationship type frequency.
    pub type_frequency: BTreeMap<String, usize>,
    /// Causal chain depth statistics.
    pub causal_chain_depth: ChainDepthStats,
    /// Relationship coverage by protocol.
    pub coverage_by_protocol: BTreeMap<String, usize>,
    /// Relationship coverage by vulnerability class.
    pub coverage_by_class: BTreeMap<String, usize>,
    /// Relationship coverage by root cause.
    pub coverage_by_root_cause: BTreeMap<String, usize>,
    /// Disconnected clusters requiring enrichment.
    pub disconnected_clusters: Vec<DisconnectedCluster>,
}

/// Score distribution statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreDistribution {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
    /// Buckets: 0.0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0
    pub buckets: Vec<usize>,
}

/// A connected concept with relationship count.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectedConcept {
    /// Concept ID.
    pub concept_id: String,
    /// Concept kind (finding, protocol, etc.).
    pub kind: String,
    /// Number of relationships.
    pub relationship_count: usize,
    /// Average relationship score.
    pub avg_score: f64,
}

/// Causal chain depth statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChainDepthStats {
    /// Maximum chain depth observed.
    pub max_depth: usize,
    /// Average chain depth.
    pub avg_depth: f64,
    /// Number of chains at each depth.
    pub depth_distribution: BTreeMap<usize, usize>,
}

/// A disconnected cluster requiring enrichment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisconnectedCluster {
    /// Cluster ID.
    pub cluster_id: String,
    /// Artifact IDs in this cluster.
    pub artifacts: Vec<String>,
    /// Suggested enrichment actions.
    pub suggestions: Vec<String>,
}

/// An exploit chain pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExploitChain {
    /// Chain description.
    pub description: String,
    /// Steps in the chain.
    pub steps: Vec<String>,
    /// Number of times observed.
    pub frequency: usize,
    /// Protocols affected.
    pub protocols: Vec<String>,
}

/// Invariant violation statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvariantViolationStat {
    /// Invariant kind.
    pub invariant: String,
    /// Number of violations.
    pub violation_count: usize,
    /// Protocols affected.
    pub protocols: Vec<String>,
}

/// Ontology concept with weak evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WeakConcept {
    /// Concept name.
    pub name: String,
    /// Concept kind.
    pub kind: String,
    /// Number of supporting findings.
    pub finding_count: usize,
    /// Number of supporting protocols.
    pub protocol_count: usize,
    /// Recommendation.
    pub recommendation: String,
}
