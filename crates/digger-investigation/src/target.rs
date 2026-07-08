//! InvestigationTarget -- a deterministic SEMANTIC RESEARCH UNIT (never a
//! vulnerability). Each target names a protocol subsystem worth investigating,
//! carries the deterministic facts that prioritize it, and is fully explainable
//! through its contributing fact ids. Every target is a `RecoveredFact`.

use serde::{Deserialize, Serialize};

use crate::fact_impl::derive_provenance;
use crate::ids::{canon, join_ids, node_id, normalize_ids};
use crate::priority::{FactorKind, PriorityFactor, PriorityKey, PriorityRank};
use crate::scope::ScopeEstimate;
use crate::Provenance;

/// The deterministic subsystems the planner recognizes. Declaration order is
/// the stable tie-break order used by the priority engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TargetKind {
    UpgradeSubsystem,
    GovernanceSubsystem,
    TreasurySubsystem,
    VaultSubsystem,
    OracleSubsystem,
    BridgeSubsystem,
    PermissionSubsystem,
    ExternalDependencySubsystem,
    AssetMovementSubsystem,
    InitializationSubsystem,
    StateTransitionSubsystem,
}

impl TargetKind {
    pub fn label(&self) -> &'static str {
        match self {
            TargetKind::UpgradeSubsystem => "upgrade_subsystem",
            TargetKind::GovernanceSubsystem => "governance_subsystem",
            TargetKind::TreasurySubsystem => "treasury_subsystem",
            TargetKind::VaultSubsystem => "vault_subsystem",
            TargetKind::OracleSubsystem => "oracle_subsystem",
            TargetKind::BridgeSubsystem => "bridge_subsystem",
            TargetKind::PermissionSubsystem => "permission_subsystem",
            TargetKind::ExternalDependencySubsystem => "external_dependency_subsystem",
            TargetKind::AssetMovementSubsystem => "asset_movement_subsystem",
            TargetKind::InitializationSubsystem => "initialization_subsystem",
            TargetKind::StateTransitionSubsystem => "state_transition_subsystem",
        }
    }
}

/// The recovered ProtocolModel facts that support a target, partitioned so the
/// explainability questions are answerable directly:
/// - which capabilities are involved? -> `capability_fact_ids`
/// - which trust boundaries are involved? -> `trust_boundary_fact_ids`
/// - which assets are involved? -> `asset_fact_ids`
/// - which ProtocolModel objects support this target? -> `related_node_ids`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSupport {
    pub capability_fact_ids: Vec<String>,
    pub trust_boundary_fact_ids: Vec<String>,
    pub asset_fact_ids: Vec<String>,
    pub related_node_ids: Vec<String>,
}

/// Deterministic builder inputs for one target. The planner fills the recovered
/// fact id lists per factor; this type turns them into a [`PriorityKey`], the
/// explainable [`PriorityFactor`] list, the [`TargetSupport`], and the
/// [`ScopeEstimate`] with no further interpretation.
#[derive(Debug, Clone, Default)]
pub struct FactorInputs {
    pub capability: Vec<String>,
    pub permission: Vec<String>,
    pub asset: Vec<String>,
    pub trust_boundary: Vec<String>,
    pub external_dependency: Vec<String>,
    /// (count, contributing fact ids) -- count is upgrade-path step count, not id len.
    pub upgrade_complexity: (u32, Vec<String>),
    /// (count, contributing fact ids) -- cross-contract interaction count.
    pub cross_contract: (u32, Vec<String>),
    /// (count, contributing fact ids) -- state-machine transition count.
    pub state_machine: (u32, Vec<String>),
    /// Extra related ProtocolModel ids (e.g. attack surfaces, economic flows,
    /// invariants, actors) that support the target but do not drive a factor.
    pub related_extra: Vec<String>,
}

impl FactorInputs {
    pub fn key(&self) -> PriorityKey {
        PriorityKey {
            capability_concentration: self.capability.len() as u32,
            permission_concentration: self.permission.len() as u32,
            asset_concentration: self.asset.len() as u32,
            trust_boundary_density: self.trust_boundary.len() as u32,
            external_dependency_count: self.external_dependency.len() as u32,
            upgrade_complexity: self.upgrade_complexity.0,
            cross_contract_interaction_density: self.cross_contract.0,
            state_machine_complexity: self.state_machine.0,
        }
    }

    pub fn factors(&self) -> Vec<PriorityFactor> {
        let mut out: Vec<PriorityFactor> = Vec::new();
        let mut push = |kind: FactorKind, count: u32, ids: &[String]| {
            if count > 0 {
                let mut v = ids.to_vec();
                normalize_ids(&mut v);
                out.push(PriorityFactor {
                    kind,
                    count,
                    contributing_fact_ids: v,
                });
            }
        };
        push(
            FactorKind::CapabilityConcentration,
            self.capability.len() as u32,
            &self.capability,
        );
        push(
            FactorKind::PermissionConcentration,
            self.permission.len() as u32,
            &self.permission,
        );
        push(
            FactorKind::AssetConcentration,
            self.asset.len() as u32,
            &self.asset,
        );
        push(
            FactorKind::TrustBoundaryDensity,
            self.trust_boundary.len() as u32,
            &self.trust_boundary,
        );
        push(
            FactorKind::ExternalDependencyCount,
            self.external_dependency.len() as u32,
            &self.external_dependency,
        );
        push(
            FactorKind::UpgradeComplexity,
            self.upgrade_complexity.0,
            &self.upgrade_complexity.1,
        );
        push(
            FactorKind::CrossContractInteractionDensity,
            self.cross_contract.0,
            &self.cross_contract.1,
        );
        push(
            FactorKind::StateMachineComplexity,
            self.state_machine.0,
            &self.state_machine.1,
        );
        out
    }

    pub fn support(&self) -> TargetSupport {
        let mut cap = self.capability.clone();
        let mut tb = self.trust_boundary.clone();
        let mut asset = self.asset.clone();
        normalize_ids(&mut cap);
        normalize_ids(&mut tb);
        normalize_ids(&mut asset);

        let mut related: Vec<String> = Vec::new();
        related.extend(self.capability.iter().cloned());
        related.extend(self.permission.iter().cloned());
        related.extend(self.asset.iter().cloned());
        related.extend(self.trust_boundary.iter().cloned());
        related.extend(self.external_dependency.iter().cloned());
        related.extend(self.upgrade_complexity.1.iter().cloned());
        related.extend(self.cross_contract.1.iter().cloned());
        related.extend(self.state_machine.1.iter().cloned());
        related.extend(self.related_extra.iter().cloned());
        normalize_ids(&mut related);

        TargetSupport {
            capability_fact_ids: cap,
            trust_boundary_fact_ids: tb,
            asset_fact_ids: asset,
            related_node_ids: related,
        }
    }
}

/// A deterministic investigation target. Implements `RecoveredFact`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationTarget {
    /// Deterministic content-addressed id (`target:<digest>`).
    pub id: String,
    pub kind: TargetKind,
    /// 1-based priority rank, assigned by the planner after the total ordering.
    pub priority: PriorityRank,
    /// The deterministic comparison key that explains the ordering.
    pub priority_key: PriorityKey,
    /// WHY this was prioritized + WHICH deterministic facts contributed.
    pub factors: Vec<PriorityFactor>,
    /// WHICH ProtocolModel objects / capabilities / trust boundaries / assets
    /// support this target.
    pub support: TargetSupport,
    /// Deterministic estimated investigation scope.
    pub scope: ScopeEstimate,
    pub provenance: Provenance,
}

impl InvestigationTarget {
    /// Build a target from deterministic inputs. The id is content-addressed
    /// over the kind + sorted supporting fact ids, so it is stable regardless
    /// of the rank later assigned by the planner.
    pub fn from_inputs(kind: TargetKind, inputs: &FactorInputs) -> Self {
        let priority_key = inputs.key();
        let factors = inputs.factors();
        let support = inputs.support();
        let scope = ScopeEstimate::new(
            support.related_node_ids.len() as u32,
            support.capability_fact_ids.len() as u32,
            support.trust_boundary_fact_ids.len() as u32,
        );
        let related_join = join_ids(&support.related_node_ids);
        let id_canon = canon(&[kind.label(), &related_join]);
        let provenance = derive_provenance(&format!("target|{}", id_canon), &related_join);
        InvestigationTarget {
            id: node_id("target", &id_canon),
            kind,
            priority: PriorityRank::UNRANKED,
            priority_key,
            factors,
            support,
            scope,
            provenance,
        }
    }
}

impl_investigation_fact!(InvestigationTarget);
