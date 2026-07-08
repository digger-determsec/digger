//! Attack Surface Reconstruction -- deterministic recovery of WHERE a protocol
//! is reachable / exercisable. This phase ONLY recovers the surface; it never
//! determines exploitability, never scores, never ranks. Each surface is a fact
//! about structure, tied to the recovered facts that expose it.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::capability_graph::{CapabilityGraph, CapabilityKind};
use crate::ids::{join_ids, node_id};
use crate::permissions::Permission;
use crate::state_machine::{StateMachine, StateMachineKind};
use crate::{
    derive_provenance, DependencyKind, DeploymentDetail, Provenance, RecoveredDependency,
    RecoveredDeployment,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SurfaceKind {
    Upgrade,
    ExternalCall,
    PrivilegedExecution,
    AssetMovement,
    Initialization,
    Proxy,
    Governance,
}

impl SurfaceKind {
    pub fn label(&self) -> &'static str {
        match self {
            SurfaceKind::Upgrade => "upgrade",
            SurfaceKind::ExternalCall => "external_call",
            SurfaceKind::PrivilegedExecution => "privileged_execution",
            SurfaceKind::AssetMovement => "asset_movement",
            SurfaceKind::Initialization => "initialization",
            SurfaceKind::Proxy => "proxy",
            SurfaceKind::Governance => "governance",
        }
    }
}

/// A recovered attack surface. NO exploitability is expressed -- only that the
/// surface structurally exists, and which recovered facts expose it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackSurface {
    /// Deterministic content-addressed id (`surface:<digest>`).
    pub id: String,
    pub kind: SurfaceKind,
    pub exposed_by_fact_ids: Vec<String>,
    pub provenance: Provenance,
}

impl AttackSurface {
    fn new(kind: SurfaceKind, exposed_by_fact_ids: Vec<String>) -> Self {
        let mut basis = exposed_by_fact_ids;
        basis.sort();
        basis.dedup();
        let canon = format!("surface|{}|{}", kind.label(), basis.join(","));
        let provenance = derive_provenance(&canon, &basis.join(","));
        AttackSurface {
            id: node_id("surface", &canon),
            kind,
            exposed_by_fact_ids: basis,
            provenance,
        }
    }
}

impl_protocol_fact!(AttackSurface);

/// Deterministically recover attack surfaces from recovered facts. Each rule is
/// a fixed structural mapping; surfaces are deduped by kind.
pub fn derive_attack_surfaces(
    capabilities: &CapabilityGraph,
    deployment: Option<&RecoveredDeployment>,
    permissions: &[Permission],
    state_machines: &[StateMachine],
    dependencies: &[RecoveredDependency],
) -> Vec<AttackSurface> {
    let mut exposed: BTreeMap<SurfaceKind, BTreeSet<String>> = BTreeMap::new();
    let add = |k: SurfaceKind, id: String, m: &mut BTreeMap<SurfaceKind, BTreeSet<String>>| {
        m.entry(k).or_default().insert(id);
    };

    // Upgrade + proxy surfaces from deployment topology.
    if let Some(dep) = deployment {
        if let DeploymentDetail::Evm(e) = &dep.detail {
            if !e.proxies.is_empty() {
                add(SurfaceKind::Proxy, dep.id.clone(), &mut exposed);
                add(SurfaceKind::ExternalCall, dep.id.clone(), &mut exposed);
            }
        }
    }
    if let Some(id) = capabilities.fact_id_for(CapabilityKind::Upgrade) {
        add(SurfaceKind::Upgrade, id.to_string(), &mut exposed);
    }
    if let Some(id) = capabilities.fact_id_for(CapabilityKind::Delegatecall) {
        add(SurfaceKind::ExternalCall, id.to_string(), &mut exposed);
    }
    if let Some(id) = capabilities.fact_id_for(CapabilityKind::Governance) {
        add(SurfaceKind::Governance, id.to_string(), &mut exposed);
    }
    for cap in [
        CapabilityKind::Mint,
        CapabilityKind::Burn,
        CapabilityKind::Treasury,
    ] {
        if let Some(id) = capabilities.fact_id_for(cap) {
            add(SurfaceKind::AssetMovement, id.to_string(), &mut exposed);
        }
    }

    // External call surface from externally trusted dependencies.
    for d in dependencies {
        if matches!(
            d.kind,
            DependencyKind::PriceOracle
                | DependencyKind::Bridge
                | DependencyKind::ExternalProtocol
                | DependencyKind::Router
        ) {
            add(SurfaceKind::ExternalCall, d.id.clone(), &mut exposed);
        }
    }

    // Privileged execution surface from any recovered permission.
    for p in permissions {
        add(SurfaceKind::PrivilegedExecution, p.id.clone(), &mut exposed);
    }

    // Initialization surface from an initializable lifecycle.
    for sm in state_machines {
        if sm.machine_kind == StateMachineKind::Initializable {
            add(SurfaceKind::Initialization, sm.id.clone(), &mut exposed);
        }
    }

    let mut surfaces: Vec<AttackSurface> = exposed
        .into_iter()
        .map(|(kind, ids)| {
            let v: Vec<String> = ids.into_iter().collect();
            let _ = join_ids(&v); // normalization already applied in ctor
            AttackSurface::new(kind, v)
        })
        .collect();
    surfaces.sort_by(|a, b| a.id.cmp(&b.id));
    surfaces.dedup_by(|a, b| a.id == b.id);
    surfaces
}
