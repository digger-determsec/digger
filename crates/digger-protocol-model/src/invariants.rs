//! Invariant Candidate Recovery -- deterministic invariant CANDIDATES generated
//! directly from recovered protocol structure. Every entry is explicitly marked
//! a candidate (`candidate == true`); the model NEVER claims correctness. Each
//! candidate must be validated by a later phase before any conclusion is drawn.

use serde::{Deserialize, Serialize};

use crate::actors::{Actor, ActorKind};
use crate::assets::{Asset, AssetKind};
use crate::capability_graph::{CapabilityGraph, CapabilityKind};
use crate::ids::node_id;
use crate::permissions::Permission;
use crate::{derive_provenance, Provenance};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InvariantKind {
    SupplyConservation,
    OwnershipPreservation,
    VaultAccountingConsistency,
    AuthorizationConsistency,
    UpgradeSafety,
}

impl InvariantKind {
    pub fn label(&self) -> &'static str {
        match self {
            InvariantKind::SupplyConservation => "supply_conservation",
            InvariantKind::OwnershipPreservation => "ownership_preservation",
            InvariantKind::VaultAccountingConsistency => "vault_accounting_consistency",
            InvariantKind::AuthorizationConsistency => "authorization_consistency",
            InvariantKind::UpgradeSafety => "upgrade_safety",
        }
    }
}

/// A deterministic invariant CANDIDATE. `candidate` is always true: this is a
/// hypothesis derived from structure, never a verified property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantCandidate {
    /// Deterministic content-addressed id (`invariant:<digest>`).
    pub id: String,
    pub kind: InvariantKind,
    /// Always `true` -- this is a candidate, not a proven property.
    pub candidate: bool,
    /// Deterministic structural rationale referencing the source fact ids.
    pub rationale: String,
    pub basis_fact_ids: Vec<String>,
    pub provenance: Provenance,
}

impl InvariantCandidate {
    fn new(kind: InvariantKind, rationale: String, basis_fact_ids: Vec<String>) -> Self {
        let mut basis = basis_fact_ids;
        basis.sort();
        basis.dedup();
        let canon = format!("invariant|{}|{}", kind.label(), basis.join(","));
        let provenance = derive_provenance(&canon, &basis.join(","));
        InvariantCandidate {
            id: node_id("invariant", &canon),
            kind,
            candidate: true,
            rationale,
            basis_fact_ids: basis,
            provenance,
        }
    }
}

impl_protocol_fact!(InvariantCandidate);

/// Deterministically recover invariant candidates from recovered structure.
pub fn derive_invariant_candidates(
    capabilities: &CapabilityGraph,
    actors: &[Actor],
    assets: &[Asset],
    permissions: &[Permission],
) -> Vec<InvariantCandidate> {
    let mut out: Vec<InvariantCandidate> = Vec::new();

    // Supply conservation when supply-changing capabilities exist.
    let mut supply_basis: Vec<String> = Vec::new();
    for cap in [CapabilityKind::Mint, CapabilityKind::Burn] {
        if let Some(id) = capabilities.fact_id_for(cap) {
            supply_basis.push(id.to_string());
        }
    }
    if !supply_basis.is_empty() {
        out.push(InvariantCandidate::new(
            InvariantKind::SupplyConservation,
            "Mint/burn capabilities change supply; total supply must be conserved by accounting."
                .to_string(),
            supply_basis,
        ));
    }

    // Ownership preservation when a privileged owner/admin/upgrade actor exists.
    let owner_basis: Vec<String> = actors
        .iter()
        .filter(|a| {
            matches!(
                a.kind,
                ActorKind::Owner | ActorKind::Admin | ActorKind::UpgradeAuthority
            )
        })
        .map(|a| a.id.clone())
        .collect();
    if !owner_basis.is_empty() {
        out.push(InvariantCandidate::new(
            InvariantKind::OwnershipPreservation,
            "Privileged ownership exists; ownership/authority assignment must be preserved across operations."
                .to_string(),
            owner_basis,
        ));
    }

    // Vault accounting consistency when a vault asset exists.
    let vault_basis: Vec<String> = assets
        .iter()
        .filter(|a| a.kind == AssetKind::Vault)
        .map(|a| a.id.clone())
        .collect();
    if !vault_basis.is_empty() {
        out.push(InvariantCandidate::new(
            InvariantKind::VaultAccountingConsistency,
            "Vault asset exists; deposited balances and accounting must remain consistent."
                .to_string(),
            vault_basis,
        ));
    }

    // Authorization consistency when any privileged permission exists.
    if !permissions.is_empty() {
        let basis: Vec<String> = permissions.iter().map(|p| p.id.clone()).collect();
        out.push(InvariantCandidate::new(
            InvariantKind::AuthorizationConsistency,
            "Privileged actions exist; authorization checks must gate them consistently."
                .to_string(),
            basis,
        ));
    }

    // Upgrade safety when an upgrade capability exists.
    if let Some(id) = capabilities.fact_id_for(CapabilityKind::Upgrade) {
        out.push(InvariantCandidate::new(
            InvariantKind::UpgradeSafety,
            "Upgrade capability exists; upgrades must preserve storage layout and authorization."
                .to_string(),
            vec![id.to_string()],
        ));
    }

    out.sort_by(|a, b| a.id.cmp(&b.id));
    out.dedup_by(|a, b| a.id == b.id);
    out
}
