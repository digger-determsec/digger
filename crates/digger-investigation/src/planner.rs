//! The deterministic Investigation Planner.
//!
//! `build_investigation_plan` consumes ONLY recovered `ProtocolModel` facts and
//! produces a canonical [`InvestigationPlan`]. Every subsystem is recovered by
//! gathering the ProtocolModel facts that belong to it (by fact id), deriving
//! integer factor counts, and emitting a target only when at least one
//! recovered fact supports it. Targets are then ordered by the deterministic
//! priority key (higher integer counts first), tie-broken by the stable
//! target-kind order then content-addressed id, and assigned 1-based ranks.
//!
//! No exploitability, no findings, no hypotheses, no AI, no probability.

use ::digger_protocol_model::actors::ActorKind;
use ::digger_protocol_model::assets::AssetKind;
use ::digger_protocol_model::attack_surface::SurfaceKind;
use ::digger_protocol_model::capability_graph::CapabilityKind;
use ::digger_protocol_model::economics::EconomicFlowKind;
use ::digger_protocol_model::model::ProtocolModel;
use ::digger_protocol_model::permissions::PermissionAction;
use ::digger_protocol_model::state_machine::StateMachineKind;
use ::digger_protocol_model::trust::TrustBoundaryKind;
use ::digger_protocol_model::DependencyKind;

use crate::fact_impl::derive_provenance;
use crate::ids::{canon, join_ids, node_id};
use crate::plan::InvestigationPlan;
use crate::priority::PriorityRank;
use crate::target::{FactorInputs, InvestigationTarget, TargetKind};

// ---- small deterministic collectors over the ProtocolModel ----------------

fn cap_ids(pm: &ProtocolModel, kinds: &[CapabilityKind]) -> Vec<String> {
    pm.capability_graph
        .capabilities
        .iter()
        .filter(|c| kinds.contains(&c.kind))
        .map(|c| c.id.clone())
        .collect()
}

fn perm_ids(pm: &ProtocolModel, actions: &[PermissionAction]) -> Vec<String> {
    pm.permissions
        .iter()
        .filter(|p| actions.contains(&p.action))
        .map(|p| p.id.clone())
        .collect()
}

fn asset_ids(pm: &ProtocolModel, kinds: &[AssetKind]) -> Vec<String> {
    pm.assets
        .iter()
        .filter(|a| kinds.contains(&a.kind))
        .map(|a| a.id.clone())
        .collect()
}

fn all_asset_ids(pm: &ProtocolModel) -> Vec<String> {
    pm.assets.iter().map(|a| a.id.clone()).collect()
}

fn boundary_ids(pm: &ProtocolModel, kinds: &[TrustBoundaryKind]) -> Vec<String> {
    pm.trust_boundaries
        .iter()
        .filter(|b| kinds.contains(&b.kind))
        .map(|b| b.id.clone())
        .collect()
}

fn dep_ids(pm: &ProtocolModel, kinds: &[DependencyKind]) -> Vec<String> {
    pm.dependencies
        .iter()
        .filter(|d| kinds.contains(&d.kind))
        .map(|d| d.id.clone())
        .collect()
}

fn surface_ids(pm: &ProtocolModel, kinds: &[SurfaceKind]) -> Vec<String> {
    pm.attack_surfaces
        .iter()
        .filter(|s| kinds.contains(&s.kind))
        .map(|s| s.id.clone())
        .collect()
}

fn flow_ids(pm: &ProtocolModel, kinds: &[EconomicFlowKind]) -> Vec<String> {
    pm.economic_flows
        .iter()
        .filter(|f| kinds.contains(&f.kind))
        .map(|f| f.id.clone())
        .collect()
}

fn all_flow_ids(pm: &ProtocolModel) -> Vec<String> {
    pm.economic_flows.iter().map(|f| f.id.clone()).collect()
}

fn actor_ids(pm: &ProtocolModel, kinds: &[ActorKind]) -> Vec<String> {
    pm.actors
        .iter()
        .filter(|a| kinds.contains(&a.kind))
        .map(|a| a.id.clone())
        .collect()
}

fn sm_ids(pm: &ProtocolModel, kinds: &[StateMachineKind]) -> Vec<String> {
    pm.state_machines
        .iter()
        .filter(|m| kinds.contains(&m.machine_kind))
        .map(|m| m.id.clone())
        .collect()
}

/// Total transitions across the given state machines (deterministic integer).
fn sm_transitions(pm: &ProtocolModel, kinds: &[StateMachineKind]) -> u32 {
    pm.state_machines
        .iter()
        .filter(|m| kinds.contains(&m.machine_kind))
        .map(|m| m.transitions.len() as u32)
        .sum()
}

/// All external dependency kinds (everything that is not a same-protocol token).
const EXTERNAL_DEPS: [DependencyKind; 6] = [
    DependencyKind::PriceOracle,
    DependencyKind::Bridge,
    DependencyKind::Router,
    DependencyKind::Governance,
    DependencyKind::ExternalProtocol,
    DependencyKind::SharedInfrastructure,
];

fn push_target(out: &mut Vec<InvestigationTarget>, kind: TargetKind, inputs: FactorInputs) {
    if inputs.key().is_empty() {
        return;
    }
    out.push(InvestigationTarget::from_inputs(kind, &inputs));
}

/// Build the deterministic investigation plan from a recovered ProtocolModel.
pub fn build_investigation_plan(pm: &ProtocolModel) -> InvestigationPlan {
    let mut targets: Vec<InvestigationTarget> = Vec::new();

    // -- Upgrade subsystem ---------------------------------------------------
    {
        let upgrade_step_count: u32 = pm.upgrade_paths.iter().map(|p| p.steps.len() as u32).sum();
        let upgrade_path_ids: Vec<String> = pm.upgrade_paths.iter().map(|p| p.id.clone()).collect();
        let sm = sm_ids(pm, &[StateMachineKind::Upgradeable]);
        push_target(
            &mut targets,
            TargetKind::UpgradeSubsystem,
            FactorInputs {
                capability: cap_ids(pm, &[CapabilityKind::Upgrade, CapabilityKind::Delegatecall]),
                permission: perm_ids(pm, &[PermissionAction::Upgrade]),
                trust_boundary: boundary_ids(pm, &[TrustBoundaryKind::UpgradeAuthority]),
                upgrade_complexity: (upgrade_step_count, upgrade_path_ids),
                state_machine: (sm_transitions(pm, &[StateMachineKind::Upgradeable]), sm),
                related_extra: surface_ids(pm, &[SurfaceKind::Upgrade, SurfaceKind::Proxy]),
                ..Default::default()
            },
        );
    }

    // -- Governance subsystem ------------------------------------------------
    push_target(
        &mut targets,
        TargetKind::GovernanceSubsystem,
        FactorInputs {
            capability: cap_ids(pm, &[CapabilityKind::Governance]),
            permission: perm_ids(pm, &[PermissionAction::Govern]),
            related_extra: {
                let mut v = actor_ids(pm, &[ActorKind::Governance]);
                v.extend(surface_ids(pm, &[SurfaceKind::Governance]));
                v
            },
            ..Default::default()
        },
    );

    // -- Treasury subsystem --------------------------------------------------
    push_target(
        &mut targets,
        TargetKind::TreasurySubsystem,
        FactorInputs {
            capability: cap_ids(pm, &[CapabilityKind::Treasury]),
            permission: perm_ids(pm, &[PermissionAction::Withdraw]),
            asset: asset_ids(pm, &[AssetKind::TreasuryAsset]),
            related_extra: flow_ids(pm, &[EconomicFlowKind::Withdraw]),
            ..Default::default()
        },
    );

    // -- Vault subsystem -----------------------------------------------------
    push_target(
        &mut targets,
        TargetKind::VaultSubsystem,
        FactorInputs {
            asset: asset_ids(pm, &[AssetKind::Vault]),
            related_extra: flow_ids(pm, &[EconomicFlowKind::Deposit, EconomicFlowKind::Withdraw]),
            ..Default::default()
        },
    );

    // -- Oracle subsystem ----------------------------------------------------
    {
        let deps = dep_ids(pm, &[DependencyKind::PriceOracle]);
        let cross = deps.len() as u32;
        push_target(
            &mut targets,
            TargetKind::OracleSubsystem,
            FactorInputs {
                capability: cap_ids(pm, &[CapabilityKind::OracleDependency]),
                external_dependency: deps.clone(),
                cross_contract: (cross, deps),
                related_extra: flow_ids(pm, &[EconomicFlowKind::OraclePriced]),
                ..Default::default()
            },
        );
    }

    // -- Bridge subsystem ----------------------------------------------------
    {
        let deps = dep_ids(pm, &[DependencyKind::Bridge]);
        let cross = deps.len() as u32;
        push_target(
            &mut targets,
            TargetKind::BridgeSubsystem,
            FactorInputs {
                capability: cap_ids(pm, &[CapabilityKind::BridgeDependency]),
                external_dependency: deps.clone(),
                cross_contract: (cross, deps),
                related_extra: flow_ids(pm, &[EconomicFlowKind::Bridge]),
                ..Default::default()
            },
        );
    }

    // -- Permission subsystem ------------------------------------------------
    {
        let all_perms: Vec<String> = pm.permissions.iter().map(|p| p.id.clone()).collect();
        push_target(
            &mut targets,
            TargetKind::PermissionSubsystem,
            FactorInputs {
                permission: all_perms,
                trust_boundary: boundary_ids(pm, &[TrustBoundaryKind::PrivilegedControl]),
                related_extra: surface_ids(pm, &[SurfaceKind::PrivilegedExecution]),
                ..Default::default()
            },
        );
    }

    // -- External dependency subsystem --------------------------------------
    {
        let deps = dep_ids(pm, &EXTERNAL_DEPS);
        let boundaries = boundary_ids(
            pm,
            &[
                TrustBoundaryKind::ExternalDependency,
                TrustBoundaryKind::SharedDependency,
            ],
        );
        let cross = deps.len() as u32 + boundaries.len() as u32;
        let mut cross_ids = deps.clone();
        cross_ids.extend(boundaries.iter().cloned());
        push_target(
            &mut targets,
            TargetKind::ExternalDependencySubsystem,
            FactorInputs {
                external_dependency: deps,
                trust_boundary: boundaries,
                cross_contract: (cross, cross_ids),
                related_extra: surface_ids(pm, &[SurfaceKind::ExternalCall]),
                ..Default::default()
            },
        );
    }

    // -- Asset movement subsystem -------------------------------------------
    push_target(
        &mut targets,
        TargetKind::AssetMovementSubsystem,
        FactorInputs {
            capability: cap_ids(pm, &[CapabilityKind::Mint, CapabilityKind::Burn]),
            asset: all_asset_ids(pm),
            related_extra: {
                let mut v = all_flow_ids(pm);
                v.extend(surface_ids(pm, &[SurfaceKind::AssetMovement]));
                v
            },
            ..Default::default()
        },
    );

    // -- Initialization subsystem -------------------------------------------
    {
        let sm = sm_ids(pm, &[StateMachineKind::Initializable]);
        push_target(
            &mut targets,
            TargetKind::InitializationSubsystem,
            FactorInputs {
                state_machine: (sm_transitions(pm, &[StateMachineKind::Initializable]), sm),
                related_extra: surface_ids(pm, &[SurfaceKind::Initialization]),
                ..Default::default()
            },
        );
    }

    // -- State transition subsystem -----------------------------------------
    {
        let all_machine_kinds = [
            StateMachineKind::Pausable,
            StateMachineKind::Upgradeable,
            StateMachineKind::Initializable,
        ];
        let sm = sm_ids(pm, &all_machine_kinds);
        push_target(
            &mut targets,
            TargetKind::StateTransitionSubsystem,
            FactorInputs {
                capability: cap_ids(pm, &[CapabilityKind::Pause]),
                trust_boundary: boundary_ids(pm, &[TrustBoundaryKind::EmergencyControl]),
                state_machine: (sm_transitions(pm, &all_machine_kinds), sm),
                ..Default::default()
            },
        );
    }

    // -- Deterministic total ordering + 1-based rank assignment --------------
    // Higher integer counts first (priority_key descending), then stable
    // target-kind order, then content-addressed id. Fully reproducible.
    targets.sort_by(|a, b| {
        b.priority_key
            .cmp(&a.priority_key)
            .then(a.kind.cmp(&b.kind))
            .then(a.id.cmp(&b.id))
    });
    for (i, t) in targets.iter_mut().enumerate() {
        t.priority = PriorityRank {
            rank: (i as u32) + 1,
        };
    }

    // -- Plan provenance + content-addressed id ------------------------------
    let target_ids: Vec<String> = targets.iter().map(|t| t.id.clone()).collect();
    let basis = join_ids(&target_ids);
    let id_canon = canon(&[&pm.id, &basis]);
    let provenance = derive_provenance(&format!("plan|{}", id_canon), &basis);

    InvestigationPlan {
        id: node_id("plan", &id_canon),
        protocol_model_id: pm.id.clone(),
        targets,
        provenance,
    }
}
