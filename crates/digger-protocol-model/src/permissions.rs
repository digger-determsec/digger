//! Permissions -- deterministic privileged actions a protocol exposes, derived
//! from recovered capabilities (and bound to an actor's address when the
//! deployment recovered one). Permissions are facts about WHAT privileged
//! actions exist, never judgments about whether they are safe.

use serde::{Deserialize, Serialize};

use crate::capability_graph::{CapabilityGraph, CapabilityKind};
use crate::ids::node_id;
use crate::{derive_provenance, Provenance, RecoveredAddress};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PermissionAction {
    Upgrade,
    Mint,
    Burn,
    Pause,
    Withdraw,
    Govern,
}

impl PermissionAction {
    pub fn label(&self) -> &'static str {
        match self {
            PermissionAction::Upgrade => "upgrade",
            PermissionAction::Mint => "mint",
            PermissionAction::Burn => "burn",
            PermissionAction::Pause => "pause",
            PermissionAction::Withdraw => "withdraw",
            PermissionAction::Govern => "govern",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permission {
    /// Deterministic content-addressed id (`perm:<digest>`).
    pub id: String,
    pub action: PermissionAction,
    /// The holder address when the deployment recovered one (e.g. upgrade
    /// authority); `None` when the action exists but no holder is recovered.
    pub holder: Option<RecoveredAddress>,
    /// The capability fact id this permission derives from.
    pub capability_fact_id: String,
    pub provenance: Provenance,
}

impl Permission {
    pub fn new(
        action: PermissionAction,
        holder: Option<RecoveredAddress>,
        capability_fact_id: String,
    ) -> Self {
        let canon = format!(
            "perm|{}|{:?}|{}",
            action.label(),
            holder,
            capability_fact_id
        );
        let provenance = derive_provenance(&canon, &capability_fact_id);
        Permission {
            id: node_id("perm", &canon),
            action,
            holder,
            capability_fact_id,
            provenance,
        }
    }
}

impl_protocol_fact!(Permission);

/// Deterministically derive permissions from the capability graph. Each
/// privileged capability maps to exactly one permission action.
pub fn derive_permissions(
    capabilities: &CapabilityGraph,
    upgrade_holder: Option<&RecoveredAddress>,
) -> Vec<Permission> {
    let mut permissions: Vec<Permission> = Vec::new();
    let mapping = [
        (CapabilityKind::Upgrade, PermissionAction::Upgrade),
        (CapabilityKind::Mint, PermissionAction::Mint),
        (CapabilityKind::Burn, PermissionAction::Burn),
        (CapabilityKind::Pause, PermissionAction::Pause),
        (CapabilityKind::Treasury, PermissionAction::Withdraw),
        (CapabilityKind::Governance, PermissionAction::Govern),
    ];
    for (cap_kind, action) in mapping {
        if let Some(cap_id) = capabilities.fact_id_for(cap_kind) {
            let holder = if action == PermissionAction::Upgrade {
                upgrade_holder.cloned()
            } else {
                None
            };
            permissions.push(Permission::new(action, holder, cap_id.to_string()));
        }
    }
    permissions.sort_by(|a, b| a.id.cmp(&b.id));
    permissions.dedup_by(|a, b| a.id == b.id);
    permissions
}
