//! Dependency recovery — chain-specific recoverers that produce
//! [`RecoveredDependency`] values from reconstruction evidence (C3.1).
//!
//! The trait is EVM-oriented (`LiftedProgram` input) because EVM dependencies
//! are derivable from the instruction stream. Solana gets its own recoverer in
//! C3.2 that takes `SolanaResolutionEvidence + CpiGraph`.

use crate::confidence::ConfidenceTier;
use crate::dependency::{
    DependencyDetail, DependencyKind, EvmDependency, RecoveredDependency, SolanaDependency,
};
use crate::deployment::{CpiEdgeKind, CpiGraph, RecoveredAddress};
use crate::known_programs::{classify_program, is_infrastructure};
use crate::known_selectors::classify_selector;
use crate::lifter::{node_id, LiftedProgram};
use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};
use crate::solana::SolanaResolutionEvidence;
use std::collections::BTreeSet;

/// Chain-agnostic dependency recovery trait.
pub trait DependencyRecoverer {
    fn recover_dependencies(&self, program: &LiftedProgram) -> Vec<RecoveredDependency>;
}

/// Free-function form of dependency recovery, mirroring
/// [`crate::lift_with`] / [`crate::recover_interface_with`].
pub fn recover_dependencies_with(
    recoverer: &dyn DependencyRecoverer,
    program: &LiftedProgram,
) -> Vec<RecoveredDependency> {
    recoverer.recover_dependencies(program)
}

/// EVM dependency recoverer: walks the instruction stream for PUSH20 addresses
/// followed (within a small forward window) by CALL/DELEGATECALL/STATICCALL.
#[derive(Default)]
pub struct EvmDependencyRecoverer;

impl EvmDependencyRecoverer {
    pub fn new() -> Self {
        Self
    }
}

const CALL_WINDOW: usize = 8;

fn is_call_mnemonic(m: &str) -> bool {
    m == "CALL" || m == "DELEGATECALL" || m == "STATICCALL"
}

fn is_precompile(addr_hex: &str) -> bool {
    if addr_hex.len() < 40 {
        return false;
    }
    let prefix = &addr_hex[..40 - 38]; // first 2 chars = high byte
    if prefix != "00" {
        return false;
    }
    let high38 = &addr_hex[2..40];
    // Check if the address is 0x0000..0001 through 0x0000..0009
    let stripped = high38.trim_start_matches('0');
    if stripped.is_empty() {
        return true; // 0x0000...0000 — zero addr
    }
    if stripped.len() <= 2 {
        if let Ok(n) = u8::from_str_radix(stripped, 16) {
            return (1..=9).contains(&n);
        }
    }
    false
}

impl DependencyRecoverer for EvmDependencyRecoverer {
    fn recover_dependencies(&self, program: &LiftedProgram) -> Vec<RecoveredDependency> {
        let insns = &program.instructions;
        let mut seen_addresses: BTreeSet<String> = BTreeSet::new();
        let mut results: Vec<RecoveredDependency> = Vec::new();

        for (i, insn) in insns.iter().enumerate() {
            // Look for PUSH20 with a 20-byte hex address operand
            if insn.mnemonic != "PUSH20" {
                continue;
            }
            let addr_hex = match &insn.operand {
                Some(op) => {
                    let h = op.strip_prefix("0x").unwrap_or(op);
                    if h.len() != 40 {
                        continue;
                    }
                    h.to_lowercase()
                }
                None => continue,
            };

            // Filter precompiles and zero address
            if is_precompile(&addr_hex) {
                continue;
            }

            // Check forward window for a CALL variant
            let window_end = (i + 1 + CALL_WINDOW).min(insns.len());
            let mut found_call = false;
            let mut observed_selectors: Vec<String> = Vec::new();
            let mut matched_kind: Option<DependencyKind> = None;

            for window_insn in insns.iter().take(window_end).skip(i + 1) {
                if is_call_mnemonic(&window_insn.mnemonic) {
                    found_call = true;
                }
                // Check for PUSH4 (selector) in the window
                if window_insn.mnemonic == "PUSH4" {
                    if let Some(sel_op) = &window_insn.operand {
                        let sel = sel_op.strip_prefix("0x").unwrap_or(sel_op).to_lowercase();
                        if sel.len() == 8 {
                            if let Some(kind) = classify_selector(&sel) {
                                matched_kind = Some(kind);
                            }
                            observed_selectors.push(format!("0x{}", sel));
                        }
                    }
                }
                if found_call && matched_kind.is_some() {
                    break;
                }
            }

            if !found_call {
                continue;
            }

            // Dedup by address
            if !seen_addresses.insert(addr_hex.clone()) {
                continue;
            }

            let kind = matched_kind.unwrap_or(DependencyKind::ExternalProtocol);
            let source = if matched_kind.is_some() {
                EvidenceSource::Selectors
            } else {
                EvidenceSource::RuntimeBytecode
            };
            let confidence = if matched_kind.is_some() {
                ConfidenceTier::Recovered
            } else {
                ConfidenceTier::Inferred
            };

            let canon = format!("dep|evm|{}|{}", addr_hex, kind_str(kind));
            let provenance =
                Provenance::new(source, ReconstructionStage::Recover, confidence, &canon);

            results.push(RecoveredDependency {
                id: RecoveredDependency::make_id(&canon),
                kind,
                address: RecoveredAddress::Resolved(format!("0x{}", addr_hex)),
                detail: DependencyDetail::Evm(EvmDependency { observed_selectors }),
                provenance,
            });
        }

        // Deterministic output: sort by id
        results.sort_by(|a, b| a.id.cmp(&b.id));
        results
    }
}

fn kind_str(k: DependencyKind) -> &'static str {
    match k {
        DependencyKind::Token => "token",
        DependencyKind::PriceOracle => "oracle",
        DependencyKind::Router => "router",
        DependencyKind::Bridge => "bridge",
        DependencyKind::Vault => "vault",
        DependencyKind::Governance => "governance",
        DependencyKind::ExternalProtocol => "external",
        DependencyKind::SharedInfrastructure => "shared",
    }
}

// ── Solana dependency recoverer (C3.2) ────────────────────────────────

/// Solana dependency recoverer: derives dependencies from CPI graph edges
/// and account ownership evidence. Input is `SolanaResolutionEvidence` +
/// `CpiGraph` (not `LiftedProgram`), so this does NOT implement the
/// `DependencyRecoverer` trait — it has its own method signature.
#[derive(Default)]
pub struct SolanaDependencyRecoverer;

impl SolanaDependencyRecoverer {
    pub fn new() -> Self {
        Self
    }

    pub fn recover_dependencies(
        &self,
        evidence: &SolanaResolutionEvidence,
        cpi: &CpiGraph,
        target_program_id: &str,
    ) -> Vec<RecoveredDependency> {
        use std::collections::HashMap;

        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut results: Vec<RecoveredDependency> = Vec::new();

        // Build reverse mapping: CPI node_id → owner program id
        // This lets us resolve Invokes edges back to their owner programs.
        let mut node_to_owner: HashMap<String, String> = HashMap::new();

        // Target program node
        if let Some(p) = &evidence.program {
            node_to_owner.insert(
                node_id("cpinode", &format!("program|{}", p.pubkey)),
                p.pubkey.clone(),
            );
        }
        // Program data node (owned by BPF loader)
        if let Some(pd) = &evidence.program_data {
            node_to_owner.insert(
                node_id("cpinode", &format!("programdata|{}", pd.pubkey)),
                pd.owner.clone(),
            );
        }
        // Account nodes — map as "account|{pubkey}" → owner,
        // and also as "program|{pubkey}" if the account IS a program (pubkey == owner)
        for acct in &evidence.accounts {
            node_to_owner.insert(
                node_id("cpinode", &format!("account|{}", acct.pubkey)),
                acct.owner.clone(),
            );
            if acct.executable || acct.pubkey == acct.owner {
                node_to_owner.insert(
                    node_id("cpinode", &format!("program|{}", acct.pubkey)),
                    acct.pubkey.clone(),
                );
            }
        }

        // PRIMARY — CPI Invokes edges: resolve target node → owner program
        for edge in &cpi.edges {
            if edge.kind != CpiEdgeKind::Invokes {
                continue;
            }
            let owner = match node_to_owner.get(&edge.to_id) {
                Some(o) => o.clone(),
                None => continue,
            };
            if owner == target_program_id || is_infrastructure(&owner) {
                continue;
            }
            if !seen.insert(owner.clone()) {
                continue;
            }
            let kind = classify_program(&owner).unwrap_or(DependencyKind::ExternalProtocol);
            let source = if classify_program(&owner).is_some() {
                EvidenceSource::ExternalIntegration
            } else {
                EvidenceSource::Inferred
            };
            let confidence = ConfidenceTier::Recovered;
            let canon = format!("dep|solana|{}|{}", owner, kind_str(kind));
            let provenance =
                Provenance::new(source, ReconstructionStage::Recover, confidence, &canon);
            results.push(RecoveredDependency {
                id: RecoveredDependency::make_id(&canon),
                kind,
                address: RecoveredAddress::Resolved(owner.clone()),
                detail: DependencyDetail::Solana(SolanaDependency {
                    observed_program_refs: vec![owner],
                }),
                provenance,
            });
        }

        // SECONDARY — account ownership: accounts whose owner is a
        // non-target, non-infrastructure program (not already found via CPI)
        for acct in &evidence.accounts {
            if acct.owner == target_program_id || is_infrastructure(&acct.owner) {
                continue;
            }
            if !seen.insert(acct.owner.clone()) {
                continue;
            }
            let kind = classify_program(&acct.owner).unwrap_or(DependencyKind::ExternalProtocol);
            let source = EvidenceSource::Inferred;
            let confidence = ConfidenceTier::Inferred;
            let canon = format!("dep|solana|{}|{}", acct.owner, kind_str(kind));
            let provenance =
                Provenance::new(source, ReconstructionStage::Recover, confidence, &canon);
            results.push(RecoveredDependency {
                id: RecoveredDependency::make_id(&canon),
                kind,
                address: RecoveredAddress::Resolved(acct.owner.clone()),
                detail: DependencyDetail::Solana(SolanaDependency {
                    observed_program_refs: vec![acct.owner.clone()],
                }),
                provenance,
            });
        }

        results.sort_by(|a, b| a.id.cmp(&b.id));
        results
    }
}

/// Free-function form of Solana dependency recovery.
pub fn recover_solana_dependencies_with(
    recoverer: &SolanaDependencyRecoverer,
    evidence: &SolanaResolutionEvidence,
    cpi: &CpiGraph,
    target_program_id: &str,
) -> Vec<RecoveredDependency> {
    recoverer.recover_dependencies(evidence, cpi, target_program_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifter::node_id;
    use crate::lifter::RecoveredInstruction;
    use crate::provenance::ReconstructionStage;

    fn test_prov(input: &str) -> Provenance {
        Provenance::new(
            EvidenceSource::RuntimeBytecode,
            ReconstructionStage::Lift,
            ConfidenceTier::Recovered,
            input,
        )
    }

    fn insn(mn: &str, op: Option<&str>) -> RecoveredInstruction {
        RecoveredInstruction {
            id: node_id("insn", &format!("{}|{:?}", mn, op)),
            offset: 0,
            mnemonic: mn.to_string(),
            operand: op.map(|s| s.to_string()),
            size: 1,
            provenance: test_prov(&format!("{}|{:?}", mn, op)),
        }
    }

    fn make_program(insns: Vec<RecoveredInstruction>) -> LiftedProgram {
        use crate::lifter::{
            RecoveredCFG, RecoveredDispatcher, RecoveredSelectorSet, RecoveryPattern,
        };
        LiftedProgram {
            id: node_id("program", "test"),
            target: crate::lifter::TargetKind::Evm,
            instructions: insns,
            cfg: RecoveredCFG {
                id: node_id("cfg", "test"),
                entry: 0,
                blocks: vec![],
                edges: vec![],
                provenance: test_prov("cfg"),
            },
            dispatcher: RecoveredDispatcher {
                id: node_id("dispatcher", "test"),
                entries: vec![],
                has_fallback: false,
                pattern: RecoveryPattern::new("test", &[]),
                provenance: test_prov("dispatch"),
            },
            selectors: RecoveredSelectorSet {
                id: node_id("sels", "test"),
                selectors: vec![],
                provenance: test_prov("sels"),
            },
            provenance: test_prov("program"),
        }
    }

    // Helper: make a 20-byte hex address from a single byte repeated
    fn addr(byte: u8) -> String {
        let hex = format!("{:02x}", byte);
        hex.repeat(20)
    }

    #[test]
    fn push20_call_known_selector_yields_token_dep() {
        let address = addr(0xab);
        let prog = make_program(vec![
            insn("PUSH20", Some(&format!("0x{}", address))),
            insn("PUSH4", Some("0xa9059cbb")),
            insn("CALL", None),
        ]);

        let deps = EvmDependencyRecoverer::new().recover_dependencies(&prog);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].kind, DependencyKind::Token);
        assert_eq!(
            deps[0].address,
            RecoveredAddress::Resolved(format!("0x{}", address))
        );
        assert_eq!(
            deps[0].detail,
            DependencyDetail::Evm(EvmDependency {
                observed_selectors: vec!["0xa9059cbb".into()],
            })
        );
        assert_eq!(deps[0].provenance.confidence, ConfidenceTier::Recovered);
    }

    #[test]
    fn push20_call_no_known_selector_yields_external_protocol() {
        let address = addr(0xcd);
        let prog = make_program(vec![
            insn("PUSH20", Some(&format!("0x{}", address))),
            insn("CALL", None),
        ]);

        let deps = EvmDependencyRecoverer::new().recover_dependencies(&prog);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].kind, DependencyKind::ExternalProtocol);
        assert_eq!(deps[0].provenance.confidence, ConfidenceTier::Inferred);
    }

    #[test]
    fn push20_precompile_filtered() {
        // 0x0000000000000000000000000000000000000004 = precompile ecRecover
        let prog = make_program(vec![
            insn("PUSH20", Some("0x0000000000000000000000000000000000000004")),
            insn("STATICCALL", None),
        ]);

        let deps = EvmDependencyRecoverer::new().recover_dependencies(&prog);
        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn determinism_same_input_same_output() {
        let address = addr(0xef);
        let make = || {
            let prog = make_program(vec![
                insn("PUSH20", Some(&format!("0x{}", address))),
                insn("PUSH4", Some("0x38ed1739")),
                insn("DELEGATECALL", None),
            ]);
            EvmDependencyRecoverer::new().recover_dependencies(&prog)
        };

        let a = make();
        let b = make();
        assert_eq!(format!("{:#?}", a), format!("{:#?}", b));
    }

    #[test]
    fn dedup_by_address() {
        let address = addr(0x11);
        let prog = make_program(vec![
            insn("PUSH20", Some(&format!("0x{}", address))),
            insn("CALL", None),
            insn("PUSH20", Some(&format!("0x{}", address))),
            insn("CALL", None),
        ]);

        let deps = EvmDependencyRecoverer::new().recover_dependencies(&prog);
        assert_eq!(deps.len(), 1);
    }

    #[test]
    fn no_call_after_push20_ignored() {
        let address = addr(0x22);
        let prog = make_program(vec![
            insn("PUSH20", Some(&format!("0x{}", address))),
            insn("STOP", None),
        ]);

        let deps = EvmDependencyRecoverer::new().recover_dependencies(&prog);
        assert_eq!(deps.len(), 0);
    }

    // ── Solana dependency recoverer tests ────────────────────────────

    use crate::deployment::{CpiEdge, CpiEdgeKind, CpiGraph, CpiNode, CpiNodeKind};
    use crate::solana::{SolanaAccount, SolanaResolutionEvidence};

    const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const SYS_PROG: &str = "11111111111111111111111111111111";
    const TARGET: &str = "MyTargetProgram11111111111111111111111111111111";

    fn solana_prov(input: &str) -> Provenance {
        Provenance::new(
            EvidenceSource::ExternalIntegration,
            ReconstructionStage::Lift,
            ConfidenceTier::Recovered,
            input,
        )
    }

    fn make_cpi_graph(
        edges: Vec<(CpiEdgeKind, &str, &str)>,
        nodes: Vec<(&str, CpiNodeKind)>,
    ) -> CpiGraph {
        let prov = solana_prov("cpi-test");
        let cpi_nodes: Vec<CpiNode> = nodes
            .into_iter()
            .map(|(canon, kind)| CpiNode {
                id: node_id("cpinode", canon),
                kind,
                provenance: prov.clone(),
            })
            .collect();
        let cpi_edges: Vec<CpiEdge> = edges
            .into_iter()
            .map(|(kind, from_canon, to_canon)| CpiEdge {
                from_id: node_id("cpinode", from_canon),
                to_id: node_id("cpinode", to_canon),
                kind,
            })
            .collect();
        CpiGraph {
            id: node_id("cpi", "test"),
            nodes: cpi_nodes,
            edges: cpi_edges,
            provenance: prov,
        }
    }

    /// Build evidence with a target program account and optional additional accounts.
    fn evidence_with(accounts: Vec<SolanaAccount>) -> SolanaResolutionEvidence {
        SolanaResolutionEvidence {
            items: vec![],
            program: Some(SolanaAccount {
                pubkey: TARGET.to_string(),
                owner: "BPFLoaderUpgradeab1e11111111111111111111111".to_string(),
                executable: true,
                data_hex: "00".repeat(8),
            }),
            program_data: None,
            accounts,
        }
    }

    #[test]
    fn invokes_spl_token_yields_token_dep() {
        let graph = make_cpi_graph(
            vec![(
                CpiEdgeKind::Invokes,
                &format!("program|{}", TARGET),
                &format!("program|{}", SPL_TOKEN),
            )],
            vec![
                (&format!("program|{}", TARGET), CpiNodeKind::Program),
                (&format!("program|{}", SPL_TOKEN), CpiNodeKind::Program),
            ],
        );
        // SPL_TOKEN must appear in evidence so the reverse mapping can find it
        let ev = evidence_with(vec![SolanaAccount {
            pubkey: SPL_TOKEN.to_string(),
            owner: SPL_TOKEN.to_string(),
            executable: true,
            data_hex: "00".repeat(8),
        }]);

        let deps = SolanaDependencyRecoverer::new().recover_dependencies(&ev, &graph, TARGET);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].kind, DependencyKind::Token);
        assert_eq!(
            deps[0].detail,
            DependencyDetail::Solana(SolanaDependency {
                observed_program_refs: vec![SPL_TOKEN.into()],
            })
        );
        assert_eq!(deps[0].provenance.confidence, ConfidenceTier::Recovered);
    }

    #[test]
    fn invokes_unknown_yields_external_protocol() {
        let unknown = "UnknownProgram1111111111111111111111111111111111";
        let graph = make_cpi_graph(
            vec![(
                CpiEdgeKind::Invokes,
                &format!("program|{}", TARGET),
                &format!("program|{}", unknown),
            )],
            vec![
                (&format!("program|{}", TARGET), CpiNodeKind::Program),
                (&format!("program|{}", unknown), CpiNodeKind::Program),
            ],
        );
        let ev = evidence_with(vec![SolanaAccount {
            pubkey: unknown.to_string(),
            owner: unknown.to_string(),
            executable: true,
            data_hex: "00".repeat(8),
        }]);

        let deps = SolanaDependencyRecoverer::new().recover_dependencies(&ev, &graph, TARGET);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].kind, DependencyKind::ExternalProtocol);
        assert_eq!(deps[0].provenance.confidence, ConfidenceTier::Recovered);
    }

    #[test]
    fn only_system_and_loader_refs_filtered() {
        let graph = make_cpi_graph(
            vec![(
                CpiEdgeKind::Invokes,
                &format!("program|{}", TARGET),
                &format!("program|{}", SYS_PROG),
            )],
            vec![
                (&format!("program|{}", TARGET), CpiNodeKind::Program),
                (&format!("program|{}", SYS_PROG), CpiNodeKind::Program),
            ],
        );
        let ev = evidence_with(vec![SolanaAccount {
            pubkey: SYS_PROG.to_string(),
            owner: SYS_PROG.to_string(),
            executable: true,
            data_hex: "00".repeat(8),
        }]);

        let deps = SolanaDependencyRecoverer::new().recover_dependencies(&ev, &graph, TARGET);
        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn solana_determinism() {
        let graph = make_cpi_graph(
            vec![(
                CpiEdgeKind::Invokes,
                &format!("program|{}", TARGET),
                &format!("program|{}", SPL_TOKEN),
            )],
            vec![
                (&format!("program|{}", TARGET), CpiNodeKind::Program),
                (&format!("program|{}", SPL_TOKEN), CpiNodeKind::Program),
            ],
        );
        let ev = evidence_with(vec![SolanaAccount {
            pubkey: SPL_TOKEN.to_string(),
            owner: SPL_TOKEN.to_string(),
            executable: true,
            data_hex: "00".repeat(8),
        }]);
        let r = || SolanaDependencyRecoverer::new().recover_dependencies(&ev, &graph, TARGET);

        let a = r();
        let b = r();
        assert_eq!(format!("{:#?}", a), format!("{:#?}", b));
    }
}
