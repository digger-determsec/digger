//! Deterministic priority engine.
//!
//! Priority is NOT a probabilistic score and NOT a weighted sum. It is a
//! deterministic TOTAL ORDER over integer fact counts. Each target carries a
//! [`PriorityKey`] -- a fixed-order tuple of integer concentrations/densities
//! recovered from the ProtocolModel. Targets are ordered by comparing those
//! tuples lexicographically (higher counts first), with stable tie-breaks on
//! target-kind order then content-addressed id. Because every input is an
//! integer derived from recovered facts, every ordering decision is fully
//! reproducible and explainable -- no AI, no ML, no weighting, no scoring.

use serde::{Deserialize, Serialize};

/// The deterministic inputs that drive priority. Each is an integer COUNT of
/// recovered facts -- never a probability and never a weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FactorKind {
    CapabilityConcentration,
    PermissionConcentration,
    AssetConcentration,
    TrustBoundaryDensity,
    ExternalDependencyCount,
    UpgradeComplexity,
    CrossContractInteractionDensity,
    StateMachineComplexity,
}

impl FactorKind {
    pub fn label(&self) -> &'static str {
        match self {
            FactorKind::CapabilityConcentration => "capability_concentration",
            FactorKind::PermissionConcentration => "permission_concentration",
            FactorKind::AssetConcentration => "asset_concentration",
            FactorKind::TrustBoundaryDensity => "trust_boundary_density",
            FactorKind::ExternalDependencyCount => "external_dependency_count",
            FactorKind::UpgradeComplexity => "upgrade_complexity",
            FactorKind::CrossContractInteractionDensity => "cross_contract_interaction_density",
            FactorKind::StateMachineComplexity => "state_machine_complexity",
        }
    }
}

/// One contributing factor: WHICH deterministic input, its integer COUNT, and
/// the exact recovered fact ids that produced it (explainability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorityFactor {
    pub kind: FactorKind,
    pub count: u32,
    pub contributing_fact_ids: Vec<String>,
}

/// The deterministic comparison key. Field DECLARATION ORDER is the
/// significance order: the derived `Ord` compares these integer counts
/// lexicographically, which is exactly the priority rule (capability
/// concentration is most significant, state-machine complexity least).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PriorityKey {
    pub capability_concentration: u32,
    pub permission_concentration: u32,
    pub asset_concentration: u32,
    pub trust_boundary_density: u32,
    pub external_dependency_count: u32,
    pub upgrade_complexity: u32,
    pub cross_contract_interaction_density: u32,
    pub state_machine_complexity: u32,
}

impl PriorityKey {
    /// True when no recovered facts contribute (an empty key never produces a
    /// target).
    pub fn is_empty(&self) -> bool {
        self.capability_concentration == 0
            && self.permission_concentration == 0
            && self.asset_concentration == 0
            && self.trust_boundary_density == 0
            && self.external_dependency_count == 0
            && self.upgrade_complexity == 0
            && self.cross_contract_interaction_density == 0
            && self.state_machine_complexity == 0
    }
}

/// The deterministic 1-based rank assigned after the total ordering. Rank 1 is
/// investigated first. `rank == 0` means "not yet ranked" (pre-assignment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PriorityRank {
    pub rank: u32,
}

impl PriorityRank {
    pub const UNRANKED: PriorityRank = PriorityRank { rank: 0 };
}
