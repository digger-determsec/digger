//! Economic Flows -- deterministic value movements a protocol structurally
//! supports, derived from recovered capabilities, assets, and dependencies.
//! These are facts about WHAT value movements exist, not amounts, not rates,
//! not risk: no quantities, no scoring.

use serde::{Deserialize, Serialize};

use crate::assets::{Asset, AssetKind};
use crate::capability_graph::{CapabilityGraph, CapabilityKind};
use crate::ids::node_id;
use crate::{derive_provenance, DependencyKind, Provenance, RecoveredAddress, RecoveredDependency};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EconomicFlowKind {
    Mint,
    Burn,
    Deposit,
    Withdraw,
    Bridge,
    OraclePriced,
}

impl EconomicFlowKind {
    pub fn label(&self) -> &'static str {
        match self {
            EconomicFlowKind::Mint => "mint",
            EconomicFlowKind::Burn => "burn",
            EconomicFlowKind::Deposit => "deposit",
            EconomicFlowKind::Withdraw => "withdraw",
            EconomicFlowKind::Bridge => "bridge",
            EconomicFlowKind::OraclePriced => "oracle_priced",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicFlow {
    /// Deterministic content-addressed id (`flow:<digest>`).
    pub id: String,
    pub kind: EconomicFlowKind,
    #[serde(default)]
    pub asset_ref: Option<RecoveredAddress>,
    pub basis_fact_ids: Vec<String>,
    pub provenance: Provenance,
}

impl EconomicFlow {
    pub fn new(
        kind: EconomicFlowKind,
        asset_ref: Option<RecoveredAddress>,
        basis_fact_ids: Vec<String>,
    ) -> Self {
        let mut basis = basis_fact_ids;
        basis.sort();
        basis.dedup();
        let canon = format!("flow|{}|{:?}|{}", kind.label(), asset_ref, basis.join(","));
        let provenance = derive_provenance(&canon, &basis.join(","));
        EconomicFlow {
            id: node_id("flow", &canon),
            kind,
            asset_ref,
            basis_fact_ids: basis,
            provenance,
        }
    }
}

impl_protocol_fact!(EconomicFlow);

/// Deterministically derive economic flows from recovered facts.
pub fn derive_economic_flows(
    capabilities: &CapabilityGraph,
    assets: &[Asset],
    dependencies: &[RecoveredDependency],
) -> Vec<EconomicFlow> {
    let mut flows: Vec<EconomicFlow> = Vec::new();

    if let Some(id) = capabilities.fact_id_for(CapabilityKind::Mint) {
        flows.push(EconomicFlow::new(
            EconomicFlowKind::Mint,
            None,
            vec![id.to_string()],
        ));
    }
    if let Some(id) = capabilities.fact_id_for(CapabilityKind::Burn) {
        flows.push(EconomicFlow::new(
            EconomicFlowKind::Burn,
            None,
            vec![id.to_string()],
        ));
    }
    if let Some(id) = capabilities.fact_id_for(CapabilityKind::Treasury) {
        flows.push(EconomicFlow::new(
            EconomicFlowKind::Withdraw,
            None,
            vec![id.to_string()],
        ));
    }

    // Vault assets imply deposit + withdraw flows against that asset reference.
    for a in assets.iter().filter(|a| a.kind == AssetKind::Vault) {
        flows.push(EconomicFlow::new(
            EconomicFlowKind::Deposit,
            Some(a.reference.clone()),
            vec![a.id.clone()],
        ));
        flows.push(EconomicFlow::new(
            EconomicFlowKind::Withdraw,
            Some(a.reference.clone()),
            vec![a.id.clone()],
        ));
    }

    for d in dependencies {
        match d.kind {
            DependencyKind::Bridge => flows.push(EconomicFlow::new(
                EconomicFlowKind::Bridge,
                Some(d.address.clone()),
                vec![d.id.clone()],
            )),
            DependencyKind::PriceOracle => flows.push(EconomicFlow::new(
                EconomicFlowKind::OraclePriced,
                Some(d.address.clone()),
                vec![d.id.clone()],
            )),
            _ => {}
        }
    }

    flows.sort_by(|a, b| a.id.cmp(&b.id));
    flows.dedup_by(|a, b| a.id == b.id);
    flows
}
