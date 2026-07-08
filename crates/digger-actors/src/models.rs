/// Multi-Actor Reasoning models — how participants interact.
///
/// All structures are deterministic and JSON serializable.
/// No AI, no inference, no heuristics, no scoring.
use serde::{Deserialize, Serialize};

/// An actor in the protocol — inferred from behavioral patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Actor {
    /// Actor identifier (deterministic).
    pub actor_id: String,
    /// Inferred role.
    pub role: ActorRole,
    /// Functions this actor can call.
    pub callable_functions: Vec<String>,
    /// State variables this actor's actions affect.
    pub affected_state: Vec<String>,
}

/// Inferred actor role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActorRole {
    /// Regular user (deposits, withdrawals, swaps).
    User,
    /// Protocol owner/admin (configuration, upgrades).
    Admin,
    /// Liquidator (liquidation functions).
    Liquidator,
    /// Governance (voting, proposals).
    Governance,
    /// Attacker (can call any public function).
    Attacker,
    /// Unknown role.
    Unknown,
}

impl std::fmt::Display for ActorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Admin => write!(f, "admin"),
            Self::Liquidator => write!(f, "liquidator"),
            Self::Governance => write!(f, "governance"),
            Self::Attacker => write!(f, "attacker"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// How one actor's action affects another actor's state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActorInteraction {
    /// The actor performing the action.
    pub actor: String,
    /// The function called.
    pub function: String,
    /// State variables affected.
    pub affected_state: Vec<String>,
    /// Other actors affected by this action.
    pub affected_actors: Vec<String>,
    /// Whether the interaction is adversarial.
    pub is_adversarial: bool,
    /// Interaction kind.
    pub kind: InteractionKind,
}

/// Kind of actor interaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InteractionKind {
    /// Actor modifies shared state.
    StateModification,
    /// Actor transfers assets affecting others.
    AssetTransfer,
    /// Actor changes protocol configuration.
    ConfigurationChange,
    /// Actor triggers liquidation affecting others.
    Liquidation,
    /// Actor manipulates price affecting others.
    PriceManipulation,
}

impl std::fmt::Display for InteractionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateModification => write!(f, "state_modification"),
            Self::AssetTransfer => write!(f, "asset_transfer"),
            Self::ConfigurationChange => write!(f, "configuration_change"),
            Self::Liquidation => write!(f, "liquidation"),
            Self::PriceManipulation => write!(f, "price_manipulation"),
        }
    }
}

/// A detected adversarial interaction pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdversarialPattern {
    /// Pattern kind.
    pub kind: AdversarialKind,
    /// The attacker actor.
    pub attacker: String,
    /// The victim actor.
    pub victim: String,
    /// The function exploited.
    pub function: String,
    /// State variable exploited.
    pub state_var: String,
    /// Severity.
    pub severity: digger_ir::Severity,
}

/// Kind of adversarial pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdversarialKind {
    /// Attacker front-runs victim's transaction.
    FrontRunning,
    /// Attacker sandwich-attacks victim's transaction.
    SandwichAttack,
    /// Attacker griefs victim (makes tx fail).
    Griefing,
    /// Attacker manipulates shared state.
    StateManipulation,
}

impl std::fmt::Display for AdversarialKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrontRunning => write!(f, "front_running"),
            Self::SandwichAttack => write!(f, "sandwich_attack"),
            Self::Griefing => write!(f, "griefing"),
            Self::StateManipulation => write!(f, "state_manipulation"),
        }
    }
}

/// The complete multi-actor analysis report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MultiActorReport {
    /// Protocol identifier.
    pub protocol_id: String,
    /// Inferred actors.
    pub actors: Vec<Actor>,
    /// Actor interactions.
    pub interactions: Vec<ActorInteraction>,
    /// Detected adversarial patterns.
    pub adversarial_patterns: Vec<AdversarialPattern>,
    /// Summary statistics.
    pub summary: MultiActorSummary,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MultiActorSummary {
    /// Total actors identified.
    pub total_actors: usize,
    /// Total interactions detected.
    pub total_interactions: usize,
    /// Total adversarial patterns detected.
    pub total_adversarial: usize,
    /// Actors with adversarial potential.
    pub actors_with_adversarial_potential: usize,
}
