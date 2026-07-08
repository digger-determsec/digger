//! Upgrade Paths -- deterministic, chain-agnostic upgrade routes derived from
//! recovered deployment facts. The public type never names a chain: each step
//! carries a stable mechanism TAG (already chain-neutral strings from the
//! deployment layer, e.g. `uups.upgradeTo`, `solana.bpf_upgradeable_loader`).

use serde::{Deserialize, Serialize};

use crate::ids::node_id;
use crate::{
    derive_provenance, DeploymentDetail, Provenance, RecoveredAddress, RecoveredDeployment,
    SolanaLoader,
};

/// One deterministic step on an upgrade path (chain-agnostic mechanism tag).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradePathStep {
    /// Stable, chain-neutral mechanism tag.
    pub mechanism: String,
}

/// A recovered upgrade path: ordered mechanism steps + the controlling
/// authority address when the deployment recovered one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradePath {
    /// Deterministic content-addressed id (`upgrade:<digest>`).
    pub id: String,
    pub steps: Vec<UpgradePathStep>,
    #[serde(default)]
    pub authority: Option<RecoveredAddress>,
    pub basis_fact_ids: Vec<String>,
    pub provenance: Provenance,
}

impl UpgradePath {
    fn new(
        steps: Vec<UpgradePathStep>,
        authority: Option<RecoveredAddress>,
        basis_fact_ids: Vec<String>,
    ) -> Self {
        let mut basis = basis_fact_ids;
        basis.sort();
        basis.dedup();
        let canon = format!(
            "upgrade|{}|{:?}|{}",
            steps
                .iter()
                .map(|s| s.mechanism.clone())
                .collect::<Vec<_>>()
                .join(">"),
            authority,
            basis.join(","),
        );
        let provenance = derive_provenance(&canon, &basis.join(","));
        UpgradePath {
            id: node_id("upgrade", &canon),
            steps,
            authority,
            basis_fact_ids: basis,
            provenance,
        }
    }
}

impl_protocol_fact!(UpgradePath);

/// Deterministically derive upgrade paths from a recovered deployment. Returns
/// at most one path (the deployment's upgrade route); empty when not upgradeable.
pub fn derive_upgrade_paths(deployment: Option<&RecoveredDeployment>) -> Vec<UpgradePath> {
    let Some(dep) = deployment else {
        return Vec::new();
    };
    match &dep.detail {
        DeploymentDetail::Evm(e) => {
            let mut steps: Vec<UpgradePathStep> = e
                .upgrade_path
                .iter()
                .map(|s| UpgradePathStep {
                    mechanism: s.mechanism.clone(),
                })
                .collect();
            // A proxy with no explicit upgrade-path step still delegates;
            // record the deterministic delegatecall mechanism.
            if steps.is_empty() && !e.proxies.is_empty() {
                steps.push(UpgradePathStep {
                    mechanism: "evm.proxy.delegatecall".to_string(),
                });
            }
            if steps.is_empty() && e.upgrade_authority.is_none() {
                return Vec::new();
            }
            let authority = e.upgrade_authority.as_ref().map(|a| a.address.clone());
            vec![UpgradePath::new(steps, authority, vec![dep.id.clone()])]
        }
        DeploymentDetail::Solana(s) => {
            if !matches!(s.loader, SolanaLoader::Upgradeable) {
                return Vec::new();
            }
            let steps = vec![UpgradePathStep {
                mechanism: "solana.bpf_upgradeable_loader".to_string(),
            }];
            let authority = s.upgrade_authority.as_ref().map(|a| a.address.clone());
            vec![UpgradePath::new(steps, authority, vec![dep.id.clone()])]
        }
    }
}
