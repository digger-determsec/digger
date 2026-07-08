//! ProtocolModel -- the canonical, deterministic semantic representation of a
//! blockchain protocol. It is the highest-level recovered fact produced before
//! `SystemIR`, assembled ONLY from recovered facts. No SystemIR is built here
//! (that bridge is a later phase): A4 produces the model and stops.

use serde::{Deserialize, Serialize};

use crate::actors::{derive_actors, Actor, ActorKind};
use crate::assets::{derive_assets, Asset};
use crate::attack_surface::{derive_attack_surfaces, AttackSurface};
use crate::capability_graph::{derive_capability_graph, CapabilityGraph};
use crate::dependencies::normalize_dependencies;
use crate::economics::{derive_economic_flows, EconomicFlow};
use crate::ids::{join_ids, node_id};
use crate::invariants::{derive_invariant_candidates, InvariantCandidate};
use crate::permissions::{derive_permissions, Permission};
use crate::state_machine::{derive_state_machines, StateMachine};
use crate::trust::{derive_trust, TrustBoundary, TrustGraph};
use crate::upgrade::{derive_upgrade_paths, UpgradePath};
use crate::{
    derive_provenance, Provenance, RecoveredAddress, RecoveredDependency, RecoveredDeployment,
    RecoveredInterface,
};

/// The recovered facts that feed protocol-model construction. All optional /
/// chain-agnostic: missing inputs simply produce fewer model facts.
pub struct ProtocolModelInput<'a> {
    pub deployment: Option<&'a RecoveredDeployment>,
    pub dependencies: &'a [RecoveredDependency],
    pub interface: Option<&'a RecoveredInterface>,
}

/// The canonical semantic representation of a blockchain protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolModel {
    /// Deterministic content-addressed id (`protocol:<digest>`).
    pub id: String,
    pub actors: Vec<Actor>,
    pub assets: Vec<Asset>,
    pub permissions: Vec<Permission>,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub trust_graph: TrustGraph,
    /// Recovered dependencies referenced as-is (no duplicate IR).
    pub dependencies: Vec<RecoveredDependency>,
    pub upgrade_paths: Vec<UpgradePath>,
    pub state_machines: Vec<StateMachine>,
    pub economic_flows: Vec<EconomicFlow>,
    pub capability_graph: CapabilityGraph,
    pub attack_surfaces: Vec<AttackSurface>,
    pub invariant_candidates: Vec<InvariantCandidate>,
    pub provenance: Provenance,
}

impl_protocol_fact!(ProtocolModel);

impl ProtocolModel {
    /// Deterministically build the protocol model from recovered facts.
    pub fn build(input: &ProtocolModelInput<'_>) -> ProtocolModel {
        build_protocol_model(input.deployment, input.dependencies, input.interface)
    }
}

/// Deterministically assemble a [`ProtocolModel`] from recovered facts.
///
/// Order is fixed and acyclic: capabilities first (the semantic hub), then the
/// facts derived from them. Every output vector is sorted by fact id, so the
/// same recovered inputs always reproduce a byte-identical model.
pub fn build_protocol_model(
    deployment: Option<&RecoveredDeployment>,
    dependencies: &[RecoveredDependency],
    interface: Option<&RecoveredInterface>,
) -> ProtocolModel {
    let capability_graph = derive_capability_graph(deployment, dependencies, interface);
    let actors = derive_actors(deployment, dependencies);
    let assets = derive_assets(dependencies);

    // Upgrade permission holder = the recovered upgrade-authority actor address.
    let upgrade_holder: Option<RecoveredAddress> = actors
        .iter()
        .find(|a| a.kind == ActorKind::UpgradeAuthority)
        .map(|a| a.address.clone());
    let permissions = derive_permissions(&capability_graph, upgrade_holder.as_ref());

    let trust = derive_trust(deployment, dependencies, &actors, &capability_graph);
    let upgrade_paths = derive_upgrade_paths(deployment);
    let state_machines = derive_state_machines(&capability_graph, interface);
    let economic_flows = derive_economic_flows(&capability_graph, &assets, dependencies);
    let attack_surfaces = derive_attack_surfaces(
        &capability_graph,
        deployment,
        &permissions,
        &state_machines,
        dependencies,
    );
    let invariant_candidates =
        derive_invariant_candidates(&capability_graph, &actors, &assets, &permissions);
    let dependencies = normalize_dependencies(dependencies);

    // Content-address the model over the sorted ids of all child facts.
    let mut child_ids: Vec<String> = Vec::new();
    child_ids.extend(actors.iter().map(|x| x.id.clone()));
    child_ids.extend(assets.iter().map(|x| x.id.clone()));
    child_ids.extend(permissions.iter().map(|x| x.id.clone()));
    child_ids.extend(trust.boundaries.iter().map(|x| x.id.clone()));
    child_ids.push(trust.graph.id.clone());
    child_ids.extend(dependencies.iter().map(|x| x.id.clone()));
    child_ids.extend(upgrade_paths.iter().map(|x| x.id.clone()));
    child_ids.extend(state_machines.iter().map(|x| x.id.clone()));
    child_ids.extend(economic_flows.iter().map(|x| x.id.clone()));
    child_ids.push(capability_graph.id.clone());
    child_ids.extend(attack_surfaces.iter().map(|x| x.id.clone()));
    child_ids.extend(invariant_candidates.iter().map(|x| x.id.clone()));
    let canon = join_ids(&child_ids);
    let provenance = derive_provenance(&format!("protocol|{}", canon), &canon);

    ProtocolModel {
        id: node_id("protocol", &canon),
        actors,
        assets,
        permissions,
        trust_boundaries: trust.boundaries,
        trust_graph: trust.graph,
        dependencies,
        upgrade_paths,
        state_machines,
        economic_flows,
        capability_graph,
        attack_surfaces,
        invariant_candidates,
        provenance,
    }
}
