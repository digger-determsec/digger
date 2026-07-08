//! Reference resolution — resolves ResearchContext ids against ProtocolModel
//! into a deterministic intermediate `ResolvedContext`.
//!
//! B2 scope: equality-only id lookup. No SystemIR/Function/Edge construction.

use std::collections::{BTreeMap, BTreeSet};

use digger_protocol_model::actors::Actor;
use digger_protocol_model::assets::Asset;
use digger_protocol_model::attack_surface::AttackSurface;
use digger_protocol_model::capability_graph::Capability;
use digger_protocol_model::economics::EconomicFlow;
use digger_protocol_model::invariants::InvariantCandidate;
use digger_protocol_model::model::ProtocolModel;
use digger_protocol_model::permissions::Permission;
use digger_protocol_model::state_machine::StateMachine;
use digger_protocol_model::trust::TrustBoundary;
use digger_protocol_model::upgrade::UpgradePath;
use digger_reconstruct::dependency::RecoveredDependency;
use digger_research_context::ResearchContext;

/// A deterministic, per-protocol resolved view of ProtocolModel elements
/// selected by the ResearchContext. Stores references to concrete elements
/// (cloned for ownership; the bridge owns the resolved set).
///
/// All vectors are sorted by element id for deterministic ordering.
#[derive(Debug, Clone)]
pub struct ResolvedContext {
    /// The protocol model id this context resolves against.
    pub protocol_id: String,
    /// Resolved capabilities (sorted by id).
    pub capabilities: Vec<Capability>,
    /// Resolved trust boundaries (sorted by id).
    pub trust_boundaries: Vec<TrustBoundary>,
    /// Resolved permissions (sorted by id).
    pub permissions: Vec<Permission>,
    /// Resolved dependencies (sorted by id).
    pub dependencies: Vec<RecoveredDependency>,
    /// Resolved state machines (sorted by id).
    pub state_machines: Vec<StateMachine>,
    /// Resolved actors (sorted by id).
    pub actors: Vec<Actor>,
    /// Resolved assets (sorted by id).
    pub assets: Vec<Asset>,
    /// Resolved upgrade paths (sorted by id).
    pub upgrade_paths: Vec<UpgradePath>,
    /// Resolved attack surfaces (sorted by id).
    pub attack_surfaces: Vec<AttackSurface>,
    /// Resolved economic flows (sorted by id).
    pub economic_flows: Vec<EconomicFlow>,
    /// Resolved invariant candidates (sorted by id).
    pub invariant_candidates: Vec<InvariantCandidate>,
    /// Referenced node ids that could NOT be resolved against the provided
    /// ProtocolModel. Sorted deterministically.
    pub unresolved: Vec<String>,
}

/// Deterministically resolve a ResearchContext against a ProtocolModel.
///
/// Resolution is equality-only id lookup. The current protocol's elements are
/// always included. Referenced protocols not present in the provided model
/// contribute their ids to `unresolved`. Referenced node ids that don't match
/// any ProtocolModel element id are also unresolved.
///
/// This is a pure function of (ProtocolModel, ResearchContext) — reproducible,
/// no ordering dependence on input iteration.
pub fn resolve_context(model: &ProtocolModel, context: &ResearchContext) -> ResolvedContext {
    // Build index: element id -> cloned element for each collection.
    // Using BTreeMap for deterministic iteration order.
    let mut cap_index: BTreeMap<String, Capability> = BTreeMap::new();
    for c in &model.capability_graph.capabilities {
        cap_index.insert(c.id.clone(), c.clone());
    }
    let mut trust_index: BTreeMap<String, TrustBoundary> = BTreeMap::new();
    for t in &model.trust_boundaries {
        trust_index.insert(t.id.clone(), t.clone());
    }
    let mut perm_index: BTreeMap<String, Permission> = BTreeMap::new();
    for p in &model.permissions {
        perm_index.insert(p.id.clone(), p.clone());
    }
    let mut dep_index: BTreeMap<String, RecoveredDependency> = BTreeMap::new();
    for d in &model.dependencies {
        dep_index.insert(d.id.clone(), d.clone());
    }
    let mut sm_index: BTreeMap<String, StateMachine> = BTreeMap::new();
    for s in &model.state_machines {
        sm_index.insert(s.id.clone(), s.clone());
    }
    let mut actor_index: BTreeMap<String, Actor> = BTreeMap::new();
    for a in &model.actors {
        actor_index.insert(a.id.clone(), a.clone());
    }
    let mut asset_index: BTreeMap<String, Asset> = BTreeMap::new();
    for a in &model.assets {
        asset_index.insert(a.id.clone(), a.clone());
    }
    let mut upgrade_index: BTreeMap<String, UpgradePath> = BTreeMap::new();
    for u in &model.upgrade_paths {
        upgrade_index.insert(u.id.clone(), u.clone());
    }
    let mut surface_index: BTreeMap<String, AttackSurface> = BTreeMap::new();
    for s in &model.attack_surfaces {
        surface_index.insert(s.id.clone(), s.clone());
    }
    let mut flow_index: BTreeMap<String, EconomicFlow> = BTreeMap::new();
    for f in &model.economic_flows {
        flow_index.insert(f.id.clone(), f.clone());
    }
    let mut inv_index: BTreeMap<String, InvariantCandidate> = BTreeMap::new();
    for i in &model.invariant_candidates {
        inv_index.insert(i.id.clone(), i.clone());
    }

    // Resolution: try each referenced node id against every element index.
    let mut resolved_caps: BTreeMap<String, Capability> = BTreeMap::new();
    let mut resolved_trust: BTreeMap<String, TrustBoundary> = BTreeMap::new();
    let mut resolved_perms: BTreeMap<String, Permission> = BTreeMap::new();
    let mut resolved_deps: BTreeMap<String, RecoveredDependency> = BTreeMap::new();
    let mut resolved_sms: BTreeMap<String, StateMachine> = BTreeMap::new();
    let mut resolved_actors: BTreeMap<String, Actor> = BTreeMap::new();
    let mut resolved_assets: BTreeMap<String, Asset> = BTreeMap::new();
    let mut resolved_upgrades: BTreeMap<String, UpgradePath> = BTreeMap::new();
    let mut resolved_surfaces: BTreeMap<String, AttackSurface> = BTreeMap::new();
    let mut resolved_flows: BTreeMap<String, EconomicFlow> = BTreeMap::new();
    let mut resolved_invs: BTreeMap<String, InvariantCandidate> = BTreeMap::new();
    let mut unresolved: BTreeSet<String> = BTreeSet::new();

    for node_id in &context.referenced_node_ids {
        let mut found = false;

        if let Some(c) = cap_index.get(node_id) {
            resolved_caps.insert(node_id.clone(), c.clone());
            found = true;
        }
        if let Some(t) = trust_index.get(node_id) {
            resolved_trust.insert(node_id.clone(), t.clone());
            found = true;
        }
        if let Some(p) = perm_index.get(node_id) {
            resolved_perms.insert(node_id.clone(), p.clone());
            found = true;
        }
        if let Some(d) = dep_index.get(node_id) {
            resolved_deps.insert(node_id.clone(), d.clone());
            found = true;
        }
        if let Some(s) = sm_index.get(node_id) {
            resolved_sms.insert(node_id.clone(), s.clone());
            found = true;
        }
        if let Some(a) = actor_index.get(node_id) {
            resolved_actors.insert(node_id.clone(), a.clone());
            found = true;
        }
        if let Some(a) = asset_index.get(node_id) {
            resolved_assets.insert(node_id.clone(), a.clone());
            found = true;
        }
        if let Some(u) = upgrade_index.get(node_id) {
            resolved_upgrades.insert(node_id.clone(), u.clone());
            found = true;
        }
        if let Some(s) = surface_index.get(node_id) {
            resolved_surfaces.insert(node_id.clone(), s.clone());
            found = true;
        }
        if let Some(f) = flow_index.get(node_id) {
            resolved_flows.insert(node_id.clone(), f.clone());
            found = true;
        }
        if let Some(i) = inv_index.get(node_id) {
            resolved_invs.insert(node_id.clone(), i.clone());
            found = true;
        }

        if !found {
            unresolved.insert(node_id.clone());
        }
    }

    // Check referenced protocol ids — only the current protocol's model is
    // available; references to other protocols are unresolved.
    for pid in &context.referenced_protocol_ids {
        if pid != &model.id {
            unresolved.insert(pid.clone());
        }
    }

    // Convert BTreeMaps to sorted Vecs for deterministic output.
    ResolvedContext {
        protocol_id: model.id.clone(),
        capabilities: resolved_caps.into_values().collect(),
        trust_boundaries: resolved_trust.into_values().collect(),
        permissions: resolved_perms.into_values().collect(),
        dependencies: resolved_deps.into_values().collect(),
        state_machines: resolved_sms.into_values().collect(),
        actors: resolved_actors.into_values().collect(),
        assets: resolved_assets.into_values().collect(),
        upgrade_paths: resolved_upgrades.into_values().collect(),
        attack_surfaces: resolved_surfaces.into_values().collect(),
        economic_flows: resolved_flows.into_values().collect(),
        invariant_candidates: resolved_invs.into_values().collect(),
        unresolved: unresolved.into_iter().collect(),
    }
}
