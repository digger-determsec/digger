//! Solana provider integration (Gen5 A3.3 / ADR-0018).
//!
//! Mirrors the EVM provider contract: a [`SolanaProvider`] is an EVIDENCE
//! provider ONLY. It NEVER builds `SystemIR` or a `RecoveredDeployment`. A
//! deterministic recoverer turns collected evidence into a chain-agnostic
//! [`RecoveredDeployment`] (Solana detail). Offline reconstruction stays
//! functional via the fixture provider. Providers are interchangeable and all
//! chain-specific logic is isolated behind this module.
//!
//! Pipeline (identical to EVM):
//!   Provider -> Evidence -> (EvidenceBundle) -> deterministic Reconstruction
//!   -> Recovered Facts -> RecoveredDeployment. Never provider -> SystemIR.

use crate::confidence::ConfidenceTier;
use crate::deployment::{
    AuthorityKind, CpiEdge, CpiEdgeKind, CpiGraph, CpiNode, CpiNodeKind, DeploymentDetail,
    DeploymentKind, DeploymentRelationship, RecoveredAddress, RecoveredAuthority,
    RecoveredDeployment, RelationshipKind, SolanaDeployment, SolanaLoader,
};
use crate::evidence::{EvidenceCategory, EvidenceItem};
use crate::evidence_requirement::EvidenceRequirement;
use crate::lifter::node_id;
use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};
use std::collections::BTreeMap;

/// The canonical BPF Upgradeable Loader program id.
pub const BPF_UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

/// A deterministic Solana account snapshot (evidence input). Pubkeys are
/// represented as lower-hex of the 32-byte key for sandbox determinism; a live
/// provider base58-decodes before populating this -- a transport detail that
/// does not affect reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaAccount {
    pub pubkey: String,
    pub owner: String,
    pub executable: bool,
    /// Account data as lower-hex.
    pub data_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SolanaRpcError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Same provider abstraction as EVM: emits deterministic account evidence only.
pub trait SolanaProvider {
    fn get_account(&self, pubkey: &str) -> Result<SolanaAccount, SolanaRpcError>;
}

/// Deterministic in-memory provider (offline / tests). Interchangeable with a
/// live JSON-RPC provider implementing the same trait.
#[derive(Debug, Default, Clone)]
pub struct FixtureSolanaProvider {
    accounts: BTreeMap<String, SolanaAccount>,
}

impl FixtureSolanaProvider {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_account(mut self, acct: SolanaAccount) -> Self {
        self.accounts.insert(acct.pubkey.clone(), acct);
        self
    }
}

impl SolanaProvider for FixtureSolanaProvider {
    fn get_account(&self, pubkey: &str) -> Result<SolanaAccount, SolanaRpcError> {
        self.accounts
            .get(pubkey)
            .cloned()
            .ok_or_else(|| SolanaRpcError::NotFound(pubkey.to_string()))
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0))
        .collect()
}

fn hx32(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

/// Collected Solana evidence. Providers fill this; reconstruction reads it.
#[derive(Debug, Clone, Default)]
pub struct SolanaResolutionEvidence {
    /// Every evidence item produced (all `RpcEvidence`).
    pub items: Vec<EvidenceItem>,
    pub program: Option<SolanaAccount>,
    pub program_data: Option<SolanaAccount>,
    /// Additional accounts (PDAs / owned accounts) collected as evidence.
    pub accounts: Vec<SolanaAccount>,
}

fn account_evidence(kind: &str, acct: &SolanaAccount) -> EvidenceItem {
    let payload = format!(
        "{}|owner={}|exec={}|data=0x{}",
        acct.pubkey,
        acct.owner,
        acct.executable,
        acct.data_hex.trim_start_matches("0x")
    );
    let prov = Provenance::new(
        EvidenceSource::ExternalIntegration,
        ReconstructionStage::Fetch,
        ConfidenceTier::Recovered,
        &payload,
    );
    EvidenceItem::categorized(
        EvidenceCategory::RpcEvidence,
        EvidenceSource::ExternalIntegration,
        kind,
        payload,
        prov,
    )
}

/// Provider -> Evidence. Collects program, ProgramData, and owned accounts.
/// NEVER constructs a `RecoveredDeployment` or `SystemIR`.
pub struct SolanaAccountResolver;

impl SolanaAccountResolver {
    /// Collect deterministic evidence for a program. For an Upgradeable program
    /// the program account data is `[u32 LE variant=2][32-byte programdata key]`.
    pub fn collect(
        provider: &dyn SolanaProvider,
        program_id: &str,
        owned_accounts: &[String],
    ) -> Result<SolanaResolutionEvidence, SolanaRpcError> {
        let mut ev = SolanaResolutionEvidence::default();
        let program = provider.get_account(program_id)?;
        ev.items
            .push(account_evidence("solana_get_program", &program));
        let data = hex_bytes(&program.data_hex);
        if program.owner == BPF_UPGRADEABLE_LOADER && data.len() >= 36 && data[0] == 2 {
            let pd = hx32(&data[4..36]);
            if let Ok(pd_acct) = provider.get_account(&pd) {
                ev.items
                    .push(account_evidence("solana_get_program_data", &pd_acct));
                ev.program_data = Some(pd_acct);
            }
        }
        for a in owned_accounts {
            if let Ok(acct) = provider.get_account(a) {
                ev.items.push(account_evidence("solana_get_account", &acct));
                ev.accounts.push(acct);
            }
        }
        ev.program = Some(program);
        Ok(ev)
    }
}

pub fn build_cpi_graph(ev: &SolanaResolutionEvidence, prov: &Provenance) -> CpiGraph {
    let mut nodes: Vec<CpiNode> = Vec::new();
    let mut edges: Vec<CpiEdge> = Vec::new();
    let mk = |kind: CpiNodeKind, canon: &str| CpiNode {
        id: node_id("cpinode", canon),
        kind,
        provenance: prov.clone(),
    };
    if let Some(p) = &ev.program {
        let prog = mk(CpiNodeKind::Program, &format!("program|{}", p.pubkey));
        if let Some(pd) = &ev.program_data {
            let pdn = mk(CpiNodeKind::Account, &format!("programdata|{}", pd.pubkey));
            edges.push(CpiEdge {
                from_id: prog.id.clone(),
                to_id: pdn.id.clone(),
                kind: CpiEdgeKind::Owns,
            });
            nodes.push(pdn);
        }
        for a in &ev.accounts {
            let is_pda = a.owner == p.pubkey;
            let an = mk(
                if is_pda {
                    CpiNodeKind::Pda
                } else {
                    CpiNodeKind::Account
                },
                &format!("account|{}", a.pubkey),
            );
            edges.push(CpiEdge {
                from_id: prog.id.clone(),
                to_id: an.id.clone(),
                kind: if is_pda {
                    CpiEdgeKind::Derives
                } else {
                    CpiEdgeKind::Invokes
                },
            });
            nodes.push(an);
        }
        nodes.insert(0, prog);
    }
    CpiGraph {
        id: node_id(
            "cpi",
            &format!("nodes={}|edges={}", nodes.len(), edges.len()),
        ),
        nodes,
        edges,
        provenance: prov.clone(),
    }
}

/// Deterministic Solana deployment recovery from collected evidence. This is
/// the reconstruction step (evidence -> RecoveredDeployment); the provider
/// never reaches this far.
pub struct SolanaDeploymentRecoverer;

impl SolanaDeploymentRecoverer {
    pub fn recover(&self, ev: &SolanaResolutionEvidence) -> RecoveredDeployment {
        let program = ev.program.as_ref();
        let canon = match program {
            Some(p) => p.pubkey.clone(),
            None => "no-program".to_string(),
        };
        let prov = Provenance::new(
            EvidenceSource::ExternalIntegration,
            ReconstructionStage::Recover,
            ConfidenceTier::Recovered,
            &canon,
        );

        let loader = match program {
            Some(p) if p.owner == BPF_UPGRADEABLE_LOADER => SolanaLoader::Upgradeable,
            _ => SolanaLoader::NonUpgradeable,
        };

        let program_data_account = match &ev.program_data {
            Some(pd) => RecoveredAddress::Resolved(pd.pubkey.clone()),
            None => RecoveredAddress::unresolved(vec![EvidenceRequirement::NeedsProgramData(
                canon.clone(),
            )]),
        };

        let program_owner = match program {
            Some(p) => RecoveredAddress::Resolved(p.owner.clone()),
            None => RecoveredAddress::unresolved(vec![EvidenceRequirement::NeedsImplementation(
                canon.clone(),
            )]),
        };

        let upgrade_authority = ev.program_data.as_ref().and_then(|pd| {
            let d = hex_bytes(&pd.data_hex);
            if d.len() >= 45 && d[12] == 1 {
                let auth = hx32(&d[13..45]);
                Some(RecoveredAuthority {
                    id: node_id("auth", &format!("solana-upgrade|{}", auth)),
                    kind: AuthorityKind::UpgradeAuthority,
                    address: RecoveredAddress::Resolved(auth),
                    provenance: Provenance::new(
                        EvidenceSource::StorageRecovery,
                        ReconstructionStage::Recover,
                        ConfidenceTier::Recovered,
                        &pd.pubkey,
                    ),
                })
            } else if d.len() >= 13 && d[12] == 0 {
                None
            } else {
                Some(RecoveredAuthority {
                    id: node_id("auth", &format!("solana-upgrade-unresolved|{}", canon)),
                    kind: AuthorityKind::UpgradeAuthority,
                    address: RecoveredAddress::unresolved(vec![
                        EvidenceRequirement::NeedsProgramData(canon.clone()),
                    ]),
                    provenance: Provenance::new(
                        EvidenceSource::StorageRecovery,
                        ReconstructionStage::Recover,
                        ConfidenceTier::Inferred,
                        &canon,
                    ),
                })
            }
        });

        let cpi_graph = build_cpi_graph(ev, &prov);

        let mut program_relationships = Vec::new();
        if let (Some(p), Some(pd)) = (program, ev.program_data.as_ref()) {
            program_relationships.push(DeploymentRelationship {
                from: p.pubkey.clone(),
                to: pd.pubkey.clone(),
                kind: RelationshipKind::AdministeredBy,
            });
        }

        let sol = SolanaDeployment {
            id: node_id("soldeploy", &canon),
            loader,
            program_data_account,
            upgrade_authority,
            program_owner,
            program_relationships,
            cpi_graph,
            provenance: prov.clone(),
        };

        RecoveredDeployment {
            id: RecoveredDeployment::make_id(&format!("solana|{}", canon)),
            kind: DeploymentKind::Solana,
            detail: DeploymentDetail::Solana(sol),
            provenance: prov,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact::RecoveredFact;

    fn pk(byte: u8) -> String {
        hx32(&[byte; 32])
    }

    #[test]
    fn upgradeable_program_recovers_authority_and_loader() {
        let pd_pubkey = pk(0xDD);
        let authority = pk(0xAA);
        let mut prog_data = vec![2u8, 0, 0, 0];
        prog_data.extend_from_slice(&[0xDDu8; 32]);
        let program = SolanaAccount {
            pubkey: pk(0x01),
            owner: BPF_UPGRADEABLE_LOADER.to_string(),
            executable: true,
            data_hex: hx32(&prog_data),
        };
        let mut pd_data = vec![3u8, 0, 0, 0];
        pd_data.extend_from_slice(&[0u8; 8]);
        pd_data.push(1u8);
        pd_data.extend_from_slice(&[0xAAu8; 32]);
        let pd = SolanaAccount {
            pubkey: pd_pubkey.clone(),
            owner: BPF_UPGRADEABLE_LOADER.to_string(),
            executable: false,
            data_hex: hx32(&pd_data),
        };
        let provider = FixtureSolanaProvider::new()
            .with_account(program.clone())
            .with_account(pd.clone());
        let ev = SolanaAccountResolver::collect(&provider, &program.pubkey, &[]).unwrap();
        // evidence only: all RpcEvidence, never SystemIR
        assert!(ev
            .items
            .iter()
            .all(|i| i.category == EvidenceCategory::RpcEvidence));
        let dep = SolanaDeploymentRecoverer.recover(&ev);
        assert!(dep.fact_id().starts_with("deploy:"));
        match &dep.detail {
            DeploymentDetail::Solana(s) => {
                assert_eq!(s.loader, SolanaLoader::Upgradeable);
                assert_eq!(
                    s.program_data_account,
                    RecoveredAddress::Resolved(pd_pubkey)
                );
                let auth = s.upgrade_authority.as_ref().expect("authority");
                assert_eq!(auth.address, RecoveredAddress::Resolved(authority));
                assert_eq!(auth.kind, AuthorityKind::UpgradeAuthority);
                assert!(!s.cpi_graph.nodes.is_empty());
            }
            _ => panic!("expected solana"),
        }
    }

    #[test]
    fn missing_program_data_is_unresolved_not_fabricated() {
        let mut prog_data = vec![2u8, 0, 0, 0];
        prog_data.extend_from_slice(&[0xDDu8; 32]);
        let program = SolanaAccount {
            pubkey: pk(0x01),
            owner: BPF_UPGRADEABLE_LOADER.to_string(),
            executable: true,
            data_hex: hx32(&prog_data),
        };
        let provider = FixtureSolanaProvider::new().with_account(program.clone());
        let ev = SolanaAccountResolver::collect(&provider, &program.pubkey, &[]).unwrap();
        let dep = SolanaDeploymentRecoverer.recover(&ev);
        match &dep.detail {
            DeploymentDetail::Solana(s) => {
                assert!(!s.program_data_account.is_resolved());
                assert!(!s.program_data_account.requirements().is_empty());
            }
            _ => panic!("expected solana"),
        }
    }
}
