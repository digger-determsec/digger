//! Capability Graph -- protocol CAPABILITIES recovered as FACTS (never findings,
//! never vulnerabilities). A capability is a deterministic structural fact:
//! "this protocol CAN upgrade / mint / pause / ...", derived only from recovered
//! deployment, dependency, and interface facts. No exploitability is implied.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::ids::{join_ids, node_id};
use crate::selectors as sel;
use crate::{
    derive_provenance, DependencyKind, DeploymentDetail, InterfaceDetail, Provenance,
    RecoveredDependency, RecoveredDeployment, RecoveredInterface, SolanaLoader,
};

/// A deterministic protocol capability. These are FACTS, not findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CapabilityKind {
    Upgrade,
    Mint,
    Burn,
    Pause,
    OracleDependency,
    BridgeDependency,
    FlashLoan,
    Delegatecall,
    Treasury,
    Governance,
}

impl CapabilityKind {
    pub fn label(&self) -> &'static str {
        match self {
            CapabilityKind::Upgrade => "upgrade",
            CapabilityKind::Mint => "mint",
            CapabilityKind::Burn => "burn",
            CapabilityKind::Pause => "pause",
            CapabilityKind::OracleDependency => "oracle_dependency",
            CapabilityKind::BridgeDependency => "bridge_dependency",
            CapabilityKind::FlashLoan => "flash_loan",
            CapabilityKind::Delegatecall => "delegatecall",
            CapabilityKind::Treasury => "treasury",
            CapabilityKind::Governance => "governance",
        }
    }
}

/// A single recovered capability fact with the source fact ids that evidence it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Deterministic content-addressed id (`cap:<digest>`).
    pub id: String,
    pub kind: CapabilityKind,
    /// Sorted, deduped source fact ids that deterministically evidence it.
    pub basis_fact_ids: Vec<String>,
    pub provenance: Provenance,
}

impl Capability {
    pub fn new(kind: CapabilityKind, basis_fact_ids: Vec<String>) -> Self {
        let mut basis = basis_fact_ids;
        basis.sort();
        basis.dedup();
        let canon = format!("cap|{}|{}", kind.label(), basis.join(","));
        let provenance = derive_provenance(&canon, &basis.join(","));
        Capability {
            id: node_id("cap", &canon),
            kind,
            basis_fact_ids: basis,
            provenance,
        }
    }
}

/// A deterministic relationship between two capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CapabilityEdgeKind {
    /// One capability governs/controls another (e.g. Governance -> Upgrade).
    Controls,
    /// One capability is mechanically realized via another (Upgrade -> Delegatecall).
    UsesMechanism,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEdge {
    pub from_id: String,
    pub to_id: String,
    pub kind: CapabilityEdgeKind,
}

/// The recovered capability graph: capabilities + their deterministic relations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGraph {
    /// Deterministic content-addressed id (`capgraph:<digest>`).
    pub id: String,
    pub capabilities: Vec<Capability>,
    pub edges: Vec<CapabilityEdge>,
    pub provenance: Provenance,
}

impl CapabilityGraph {
    /// True when a capability of `kind` was recovered.
    pub fn has(&self, kind: CapabilityKind) -> bool {
        self.capabilities.iter().any(|c| c.kind == kind)
    }
    /// The fact id of a recovered capability of `kind`, if present.
    pub fn fact_id_for(&self, kind: CapabilityKind) -> Option<&str> {
        self.capabilities
            .iter()
            .find(|c| c.kind == kind)
            .map(|c| c.id.as_str())
    }
}

impl_protocol_fact!(Capability, CapabilityGraph);

/// Deterministically derive the capability graph from recovered facts ONLY.
/// Every rule is a fixed structural mapping (no heuristics, no scoring):
/// - deployment upgrade topology      => Upgrade (+ Delegatecall for EVM proxies)
/// - Solana upgradeable loader        => Upgrade
/// - dependency classification        => Oracle/Bridge/Governance/Treasury
/// - standardized interface selectors => Mint/Burn/Pause/Upgrade/FlashLoan/...
pub fn derive_capability_graph(
    deployment: Option<&RecoveredDeployment>,
    dependencies: &[RecoveredDependency],
    interface: Option<&RecoveredInterface>,
) -> CapabilityGraph {
    // Collect basis fact ids per capability kind deterministically.
    let mut basis: BTreeMap<CapabilityKind, BTreeSet<String>> = BTreeMap::new();
    let add =
        |k: CapabilityKind, id: String, map: &mut BTreeMap<CapabilityKind, BTreeSet<String>>| {
            map.entry(k).or_default().insert(id);
        };

    if let Some(dep) = deployment {
        match &dep.detail {
            DeploymentDetail::Evm(e) => {
                let upgradeable = !e.proxies.is_empty()
                    || e.upgrade_authority.is_some()
                    || !e.upgrade_path.is_empty();
                if upgradeable {
                    add(CapabilityKind::Upgrade, dep.id.clone(), &mut basis);
                }
                // Every recovered proxy family delegates execution to an
                // implementation: a delegatecall capability fact.
                if !e.proxies.is_empty() {
                    add(CapabilityKind::Delegatecall, dep.id.clone(), &mut basis);
                }
            }
            DeploymentDetail::Solana(s) => {
                if matches!(s.loader, SolanaLoader::Upgradeable) {
                    add(CapabilityKind::Upgrade, dep.id.clone(), &mut basis);
                }
            }
        }
    }

    for d in dependencies {
        match d.kind {
            DependencyKind::PriceOracle => {
                add(CapabilityKind::OracleDependency, d.id.clone(), &mut basis)
            }
            DependencyKind::Bridge => {
                add(CapabilityKind::BridgeDependency, d.id.clone(), &mut basis)
            }
            DependencyKind::Governance => add(CapabilityKind::Governance, d.id.clone(), &mut basis),
            DependencyKind::Vault => add(CapabilityKind::Treasury, d.id.clone(), &mut basis),
            _ => {}
        }
    }

    if let Some(iface) = interface {
        if let InterfaceDetail::Evm(abi) = &iface.detail {
            for f in &abi.functions {
                let s = f.selector.selector.as_str();
                let fid = f.id.clone();
                match s {
                    x if x == sel::UPGRADE_TO || x == sel::UPGRADE_TO_AND_CALL => {
                        add(CapabilityKind::Upgrade, fid, &mut basis)
                    }
                    x if x == sel::MINT_ADDR_UINT || x == sel::MINT_UINT => {
                        add(CapabilityKind::Mint, fid, &mut basis)
                    }
                    x if x == sel::BURN_UINT || x == sel::BURN_ADDR_UINT => {
                        add(CapabilityKind::Burn, fid, &mut basis)
                    }
                    x if x == sel::PAUSE || x == sel::UNPAUSE => {
                        add(CapabilityKind::Pause, fid, &mut basis)
                    }
                    x if x == sel::FLASH_LOAN_3156 || x == sel::FLASH_LOAN_POOL => {
                        add(CapabilityKind::FlashLoan, fid, &mut basis)
                    }
                    x if x == sel::PROPOSE || x == sel::CAST_VOTE => {
                        add(CapabilityKind::Governance, fid, &mut basis)
                    }
                    x if x == sel::WITHDRAW_UINT || x == sel::WITHDRAW_ADDR => {
                        add(CapabilityKind::Treasury, fid, &mut basis)
                    }
                    _ => {}
                }
            }
        }
    }

    // Emit one capability per kind (sorted by kind via BTreeMap iteration).
    let mut capabilities: Vec<Capability> = basis
        .into_iter()
        .map(|(kind, ids)| Capability::new(kind, ids.into_iter().collect()))
        .collect();
    capabilities.sort_by(|a, b| a.id.cmp(&b.id));

    // Deterministic capability relations (fixed structural rules).
    let mut edges: Vec<CapabilityEdge> = Vec::new();
    let kind_id = |k: CapabilityKind, caps: &[Capability]| -> Option<String> {
        caps.iter().find(|c| c.kind == k).map(|c| c.id.clone())
    };
    if let (Some(gov), Some(up)) = (
        kind_id(CapabilityKind::Governance, &capabilities),
        kind_id(CapabilityKind::Upgrade, &capabilities),
    ) {
        edges.push(CapabilityEdge {
            from_id: gov,
            to_id: up,
            kind: CapabilityEdgeKind::Controls,
        });
    }
    if let (Some(up), Some(dc)) = (
        kind_id(CapabilityKind::Upgrade, &capabilities),
        kind_id(CapabilityKind::Delegatecall, &capabilities),
    ) {
        edges.push(CapabilityEdge {
            from_id: up,
            to_id: dc,
            kind: CapabilityEdgeKind::UsesMechanism,
        });
    }
    edges.sort_by(|a, b| {
        (a.from_id.as_str(), a.to_id.as_str()).cmp(&(b.from_id.as_str(), b.to_id.as_str()))
    });

    let canon = format!(
        "capgraph|{}|{}",
        capabilities
            .iter()
            .map(|c| c.id.clone())
            .collect::<Vec<_>>()
            .join(","),
        edges
            .iter()
            .map(|e| format!("{}>{}", e.from_id, e.to_id))
            .collect::<Vec<_>>()
            .join(","),
    );
    let basis_str = join_ids(
        &capabilities
            .iter()
            .map(|c| c.id.clone())
            .collect::<Vec<_>>(),
    );
    let provenance = derive_provenance(&canon, &basis_str);
    CapabilityGraph {
        id: node_id("capgraph", &canon),
        capabilities,
        edges,
        provenance,
    }
}
