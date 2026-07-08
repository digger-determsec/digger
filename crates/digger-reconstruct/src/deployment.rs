//! Chain-agnostic recovered deployment layer (Gen5 A3.2 / ADR-0016).
//!
//! Deployment mechanics live HERE, never inside architecture. A future
//! `RecoveredArchitecture` CONSUMES a [`RecoveredDeployment`] rather than
//! re-deriving deployment logic:
//!
//! ```text
//! RecoveredDeployment
//!   |- EvmDeployment    (proxy topology, implementation chain, upgrade authority)
//!   |- SolanaDeployment (upgradeable loader, program-data, CPI network)
//! ```
//!
//! Every deployment object is a [`crate::fact::RecoveredFact`]: deterministic id,
//! provenance, confidence, and reproducibility. Network access is NEVER required.
//! Offline reconstruction yields the SAME topology with implementation addresses
//! left [`RecoveredAddress::Unresolved`] (recording exactly what evidence would
//! resolve them) until an evidence provider supplies storage. RPC/storage are
//! evidence, never privileged truth.

use crate::evidence_requirement::EvidenceRequirement;
use crate::lifter::{node_id, TargetKind};
use crate::provenance::Provenance;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Chain-agnostic deployment fact. Exactly one `detail` variant is populated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredDeployment {
    /// Deterministic content-addressed id (`deploy:<digest>`).
    pub id: String,
    pub kind: DeploymentKind,
    pub detail: DeploymentDetail,
    pub provenance: Provenance,
}

impl RecoveredDeployment {
    pub fn make_id(canon: &str) -> String {
        node_id("deploy", canon)
    }
    /// All outstanding evidence requirements implied by unresolved addresses in
    /// this deployment (deterministic, sorted, de-duplicated). Drives the
    /// chain-agnostic completeness model -- no heuristics.
    pub fn outstanding_requirements(&self) -> Vec<EvidenceRequirement> {
        let mut out: Vec<EvidenceRequirement> = Vec::new();
        match &self.detail {
            DeploymentDetail::Evm(e) => {
                for p in &e.proxies {
                    out.extend(p.implementation.requirements().iter().cloned());
                }
                for h in &e.implementation_chain {
                    out.extend(h.address.requirements().iter().cloned());
                }
                if let Some(a) = &e.upgrade_authority {
                    out.extend(a.address.requirements().iter().cloned());
                }
            }
            DeploymentDetail::Solana(s) => {
                out.extend(s.program_data_account.requirements().iter().cloned());
                out.extend(s.program_owner.requirements().iter().cloned());
                if let Some(a) = &s.upgrade_authority {
                    out.extend(a.address.requirements().iter().cloned());
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeploymentKind {
    Evm,
    Solana,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentDetail {
    Evm(EvmDeployment),
    Solana(SolanaDeployment),
}

/// A deterministically-recovered address (EVM 20-byte / Solana key). When it
/// cannot be resolved from available evidence we record WHY rather than
/// fabricating a value -- preserving determinism and honesty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveredAddress {
    /// Lower-case `0x`-prefixed hex, deterministically recovered from evidence.
    Resolved(String),
    /// Not resolvable from available evidence. Records the deterministic,
    /// reproducible [`EvidenceRequirement`]s that would resolve it; future UI
    /// surfaces these directly to researchers.
    Unresolved {
        requirements: Vec<EvidenceRequirement>,
    },
}

impl RecoveredAddress {
    pub fn is_resolved(&self) -> bool {
        matches!(self, RecoveredAddress::Resolved(_))
    }
    /// Construct an unresolved address with sorted, de-duplicated requirements.
    pub fn unresolved(requirements: Vec<EvidenceRequirement>) -> Self {
        let mut requirements = requirements;
        requirements.sort();
        requirements.dedup();
        RecoveredAddress::Unresolved { requirements }
    }
    /// The evidence required to resolve this address (empty when resolved).
    pub fn requirements(&self) -> &[EvidenceRequirement] {
        match self {
            RecoveredAddress::Unresolved { requirements } => requirements,
            RecoveredAddress::Resolved(_) => &[],
        }
    }
}

// ============================ EVM ============================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProxyFamily {
    Eip1967,
    Transparent,
    Uups,
    Beacon,
    Diamond,
    MinimalProxy,
}

/// How a proxy family was deterministically detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionMethod {
    /// Matched a fixed runtime-bytecode pattern (e.g. EIP-1167 clone).
    BytecodePattern,
    /// A standard storage-slot constant appears as a PUSH32 immediate.
    StorageSlot,
    /// A standard selector appears as a PUSH4 immediate.
    SelectorPresence,
}

/// A single recovered proxy fact (one per detected family signal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredProxy {
    /// Deterministic content-addressed id (`proxy:<digest>`).
    pub id: String,
    pub family: ProxyFamily,
    pub detected_via: DetectionMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon_slot: Option<String>,
    /// Resolved implementation when deterministically available (Minimal Proxy
    /// embeds it in bytecode; slot-based families need storage evidence).
    pub implementation: RecoveredAddress,
    /// Diamond loupe selectors observed (sorted hex); empty for non-Diamond.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facet_selectors: Vec<String>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthorityKind {
    ProxyAdmin,
    UpgradeAuthority,
    BeaconOwner,
    DiamondOwner,
}

/// A recovered deployment authority (who can move an implementation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredAuthority {
    /// Deterministic content-addressed id (`auth:<digest>`).
    pub id: String,
    pub kind: AuthorityKind,
    pub address: RecoveredAddress,
    pub provenance: Provenance,
}

/// One hop in the deterministic implementation chain (bounded by MAX_PROXY_DEPTH).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImplementationHop {
    pub depth: u8,
    pub family: ProxyFamily,
    pub address: RecoveredAddress,
}

/// One deterministic step on the upgrade path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeStep {
    pub family: ProxyFamily,
    /// Stable mechanism tag, e.g. `eip1967.implementation_slot`, `uups.upgradeTo`.
    pub mechanism: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationshipKind {
    DelegatesTo,
    AdministeredBy,
    PointsToBeacon,
    HasFacet,
}

/// A deterministic deployment relationship between two fact ids / coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentRelationship {
    pub from: String,
    pub to: String,
    pub kind: RelationshipKind,
}

/// Deterministic, reproducible deployment metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentMetadata {
    pub runtime_code_len: usize,
    /// fnv1a digest of the analyzed runtime bytecode (reproducibility aid).
    pub runtime_code_digest: String,
}

/// EVM deployment topology: proxies, implementation chain, upgrade authority,
/// upgrade path, relationships, and metadata. An empty proxy list is itself a
/// deterministic fact (a direct, non-proxied deployment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmDeployment {
    /// Deterministic content-addressed id (`evmdeploy:<digest>`).
    pub id: String,
    pub proxies: Vec<RecoveredProxy>,
    pub implementation_chain: Vec<ImplementationHop>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_authority: Option<RecoveredAuthority>,
    pub upgrade_path: Vec<UpgradeStep>,
    pub relationships: Vec<DeploymentRelationship>,
    pub metadata: DeploymentMetadata,
    /// True when the implementation chain hit MAX_PROXY_DEPTH and was cut.
    pub truncated_at_max_depth: bool,
    pub provenance: Provenance,
}

// ============================ Solana ============================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SolanaLoader {
    /// BPF Upgradeable Loader.
    Upgradeable,
    /// Non-upgradeable BPF loader.
    NonUpgradeable,
}

/// Solana deployment topology + the deterministic CPI network. Shapes are
/// defined now; population arrives with the Solana lifter. Empty graphs are
/// valid (offline / no Solana evidence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaDeployment {
    /// Deterministic content-addressed id (`soldeploy:<digest>`).
    pub id: String,
    pub loader: SolanaLoader,
    pub program_data_account: RecoveredAddress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_authority: Option<RecoveredAuthority>,
    pub program_owner: RecoveredAddress,
    pub program_relationships: Vec<DeploymentRelationship>,
    pub cpi_graph: CpiGraph,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CpiNodeKind {
    Program,
    Account,
    Authority,
    Pda,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpiNode {
    /// Deterministic content-addressed id (`cpinode:<digest>`).
    pub id: String,
    pub kind: CpiNodeKind,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CpiEdgeKind {
    Owns,
    Authorizes,
    Derives,
    Invokes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpiEdge {
    pub from_id: String,
    pub to_id: String,
    pub kind: CpiEdgeKind,
}

/// The deterministic Cross-Program Invocation network: Solana's eventual
/// equivalent of the EVM call graph. Models Program -> Accounts -> Authorities
/// -> PDAs -> CPI edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpiGraph {
    /// Deterministic content-addressed id (`cpi:<digest>`).
    pub id: String,
    pub nodes: Vec<CpiNode>,
    pub edges: Vec<CpiEdge>,
    pub provenance: Provenance,
}

// ============================ Evidence + recoverer ============================

/// Deterministic storage evidence: standard slot (hex) -> 32-byte value (hex).
/// Supplied by an evidence provider (e.g. `RpcEvidenceProvider`). Offline this
/// is EMPTY and recovery still produces a topology with `Unresolved` addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageEvidence {
    pub slots: BTreeMap<String, String>,
}

impl StorageEvidence {
    pub fn empty() -> Self {
        StorageEvidence {
            slots: BTreeMap::new(),
        }
    }
    pub fn with_slot(mut self, slot: impl Into<String>, value: impl Into<String>) -> Self {
        self.slots.insert(slot.into(), value.into());
        self
    }
    pub fn get(&self, slot: &str) -> Option<&String> {
        self.slots.get(slot)
    }
}

/// Chain-agnostic deployment recovery. The engine depends ONLY on this trait;
/// concrete chains (EVM now, Solana later) provide a recoverer. `storage` is
/// evidence only -- passing an empty `StorageEvidence` keeps offline
/// reconstruction fully functional.
pub trait DeploymentRecoverer {
    fn target(&self) -> TargetKind;
    fn recover_deployment(
        &self,
        runtime_bytecode: &[u8],
        storage: &StorageEvidence,
    ) -> RecoveredDeployment;
}
