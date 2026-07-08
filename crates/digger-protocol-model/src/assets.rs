//! Assets -- the deterministic value-bearing objects a protocol manages,
//! derived from recovered dependency facts (tokens, vaults). Assets are tied to
//! a recovered reference address; we never fabricate assets without evidence.

use serde::{Deserialize, Serialize};

use crate::ids::node_id;
use crate::{derive_provenance, DependencyKind, Provenance, RecoveredAddress, RecoveredDependency};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AssetKind {
    FungibleToken,
    NonFungibleToken,
    Vault,
    TreasuryAsset,
    NativeToken,
    Unknown,
}

impl AssetKind {
    pub fn label(&self) -> &'static str {
        match self {
            AssetKind::FungibleToken => "fungible_token",
            AssetKind::NonFungibleToken => "non_fungible_token",
            AssetKind::Vault => "vault",
            AssetKind::TreasuryAsset => "treasury_asset",
            AssetKind::NativeToken => "native_token",
            AssetKind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    /// Deterministic content-addressed id (`asset:<digest>`).
    pub id: String,
    pub kind: AssetKind,
    pub reference: RecoveredAddress,
    pub basis_fact_ids: Vec<String>,
    pub provenance: Provenance,
}

impl Asset {
    pub fn new(kind: AssetKind, reference: RecoveredAddress, basis_fact_ids: Vec<String>) -> Self {
        let mut basis = basis_fact_ids;
        basis.sort();
        basis.dedup();
        let canon = format!("asset|{}|{:?}|{}", kind.label(), reference, basis.join(","));
        let provenance = derive_provenance(&canon, &basis.join(","));
        Asset {
            id: node_id("asset", &canon),
            kind,
            reference,
            basis_fact_ids: basis,
            provenance,
        }
    }
}

impl_protocol_fact!(Asset);

/// Deterministically derive assets from recovered dependency facts.
pub fn derive_assets(dependencies: &[RecoveredDependency]) -> Vec<Asset> {
    let mut assets: Vec<Asset> = Vec::new();
    for d in dependencies {
        let kind = match d.kind {
            DependencyKind::Token => Some(AssetKind::FungibleToken),
            DependencyKind::Vault => Some(AssetKind::Vault),
            _ => None,
        };
        if let Some(k) = kind {
            assets.push(Asset::new(k, d.address.clone(), vec![d.id.clone()]));
        }
    }
    assets.sort_by(|a, b| a.id.cmp(&b.id));
    assets.dedup_by(|a, b| a.id == b.id);
    assets
}
