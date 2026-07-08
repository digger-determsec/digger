/// Protocol Pack trait — interface for protocol-specific security knowledge.
use serde::{Deserialize, Serialize};

/// A protocol semantic pack — encodes protocol-specific security knowledge.
pub trait ProtocolPack: Send + Sync {
    /// Protocol name.
    fn name(&self) -> &str;

    /// Protocol version(s) this pack covers.
    fn versions(&self) -> &[&str];

    /// Chain(s) this protocol is deployed on.
    fn chains(&self) -> &[&str];

    /// Protocol invariants that must hold.
    fn invariants(&self) -> Vec<ProtocolInvariant>;

    /// Accounting rules for this protocol.
    fn accounting_rules(&self) -> Vec<AccountingRule>;

    /// Lifecycle phases.
    fn lifecycle_phases(&self) -> Vec<LifecyclePhase>;

    /// Trust boundaries.
    fn trust_boundaries(&self) -> Vec<TrustBoundary>;

    /// Privileged actors and their capabilities.
    fn privileged_actors(&self) -> Vec<PrivilegedActor>;

    /// Protocol-specific attack surfaces.
    fn attack_surfaces(&self) -> Vec<AttackSurface>;

    /// Common exploit patterns for this protocol.
    fn exploit_patterns(&self) -> Vec<ExploitPattern>;
}

/// A protocol invariant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolInvariant {
    /// Invariant description.
    pub description: String,
    /// State variables involved.
    pub state_vars: Vec<String>,
    /// Functions that must preserve this invariant.
    pub preserving_functions: Vec<String>,
    /// Consequence of violation.
    pub consequence: String,
}

/// An accounting rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountingRule {
    /// Rule description.
    pub description: String,
    /// Variables involved.
    pub variables: Vec<String>,
    /// Relationship (conservation, collateralization, etc.).
    pub relationship: String,
    /// Functions that enforce this rule.
    pub enforcing_functions: Vec<String>,
}

/// A lifecycle phase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecyclePhase {
    /// Phase name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Functions in this phase.
    pub functions: Vec<String>,
    /// Pre-conditions.
    pub preconditions: Vec<String>,
    /// Post-conditions.
    pub postconditions: Vec<String>,
}

/// A trust boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustBoundary {
    /// Boundary description.
    pub description: String,
    /// What crosses the boundary.
    pub crosses: String,
    /// What must be enforced.
    pub enforcement: String,
    /// Functions that cross this boundary.
    pub functions: Vec<String>,
}

/// A privileged actor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrivilegedActor {
    /// Actor name.
    pub name: String,
    /// Actor role.
    pub role: String,
    /// Capabilities.
    pub capabilities: Vec<String>,
    /// Trust level.
    pub trust_level: String,
}

/// An attack surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackSurface {
    /// Surface description.
    pub description: String,
    /// Attack vector.
    pub vector: String,
    /// Required capabilities.
    pub required_capabilities: Vec<String>,
    /// Impact.
    pub impact: String,
}

/// An exploit pattern specific to this protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExploitPattern {
    /// Pattern name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Conditions required.
    pub conditions: Vec<String>,
    /// Expected outcome.
    pub outcome: String,
    /// Historical examples.
    pub historical_examples: Vec<String>,
}
