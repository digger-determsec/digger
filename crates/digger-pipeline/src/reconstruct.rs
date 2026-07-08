//! Evidence collection + target-specific reconstruction (ADR-0025, C1.2).
//!
//! This module is the seam that selects a chain's provider/recoverer by
//! [`Target`] and immediately produces chain-agnostic [`RecoveredFacts`]. It is
//! the ONLY place above reconstruction where target-specific evidence shapes
//! appear; everything downstream (the Gen5 spine) is blockchain-agnostic. All
//! chain-specific logic lives inside `digger-reconstruct` — this module only
//! dispatches. Fully offline/deterministic: `StorageEvidence::empty()` and the
//! fixture Solana provider require no network.

use digger_reconstruct::{
    lift_with, recover_dependencies_with, recover_deployment_with, recover_interface_with,
    recover_solana_dependencies_with, EvmBytecodeLifter, EvmDependencyRecoverer,
    EvmDeploymentRecoverer, EvmInterfaceRecoverer, FixtureSolanaProvider, LiftError, SolanaAccount,
    SolanaAccountResolver, SolanaDependencyRecoverer, SolanaDeploymentRecoverer, SolanaRpcError,
    StorageEvidence,
};

use crate::spine::{run_gen5_spine, Gen5Spine, RecoveredFacts};
use crate::Target;

/// Chain-specific evidence inputs. Consumed immediately to produce
/// chain-agnostic `RecoveredFacts`; never propagated downstream.
#[derive(Debug, Clone)]
pub enum EvidenceInput {
    Evm {
        /// Deployed runtime bytecode.
        runtime_bytecode: Vec<u8>,
    },
    Solana {
        program_id: String,
        /// Account snapshots the provider can serve (program, program-data, PDAs).
        accounts: Vec<SolanaAccount>,
        /// Extra owned accounts to collect as evidence.
        owned_accounts: Vec<String>,
    },
}

/// Errors from the reconstruction front.
#[derive(Debug, thiserror::Error)]
pub enum ReconstructError {
    #[error("lift error: {0}")]
    Lift(LiftError),
    #[error("solana rpc error: {0}")]
    SolanaRpc(SolanaRpcError),
    /// The evidence variant did not match the requested target.
    #[error("target mismatch")]
    TargetMismatch,
}

/// Evidence → target-specific reconstruction → chain-agnostic `RecoveredFacts`.
/// Dispatches the provider/recoverer by `Target`. Dependency recovery is not
/// yet wired (no recoverer exists in digger-reconstruct), so `dependencies` is
/// empty for now — tracked as a C1 gap.
pub fn reconstruct(
    target: Target,
    evidence: &EvidenceInput,
) -> Result<RecoveredFacts, ReconstructError> {
    match (target, evidence) {
        (Target::Evm, EvidenceInput::Evm { runtime_bytecode }) => {
            let lifter = EvmBytecodeLifter::new();
            let program = lift_with(&lifter, runtime_bytecode).map_err(ReconstructError::Lift)?;
            let interface = recover_interface_with(&EvmInterfaceRecoverer::new(), &program);
            let deployment = recover_deployment_with(
                &EvmDeploymentRecoverer::new(),
                runtime_bytecode,
                &StorageEvidence::empty(),
            );
            let dependencies = recover_dependencies_with(&EvmDependencyRecoverer::new(), &program);
            // EXPERIMENTAL: bytecode-path body recovery (ADR-0029). Achieves 12.8% recall
            // on real compiled bytecode. Source-path recovery (100%) is the first-class path.
            let body = digger_reconstruct::recover_evm_body_graph(&program);
            Ok(RecoveredFacts {
                deployment: Some(deployment),
                dependencies,
                interface: Some(interface),
                body,
            })
        }
        (
            Target::Solana,
            EvidenceInput::Solana {
                program_id,
                accounts,
                owned_accounts,
            },
        ) => {
            let mut provider = FixtureSolanaProvider::new();
            for acct in accounts {
                provider = provider.with_account(acct.clone());
            }
            let ev = SolanaAccountResolver::collect(&provider, program_id, owned_accounts)
                .map_err(ReconstructError::SolanaRpc)?;
            let deployment = SolanaDeploymentRecoverer.recover(&ev);
            let cpi_graph = digger_reconstruct::build_cpi_graph(&ev, &deployment.provenance);
            let dependencies = recover_solana_dependencies_with(
                &SolanaDependencyRecoverer::new(),
                &ev,
                &cpi_graph,
                program_id,
            );
            Ok(RecoveredFacts {
                deployment: Some(deployment),
                dependencies,
                interface: None,
                body: None,
            })
        }
        _ => Err(ReconstructError::TargetMismatch),
    }
}

/// Evidence → reconstruction → full Gen5 spine, in one call. The canonical
/// single-target entry point for the live pipeline.
pub fn investigate(
    target: Target,
    evidence: &EvidenceInput,
) -> Result<Gen5Spine, ReconstructError> {
    let facts = reconstruct(target, evidence)?;
    Ok(run_gen5_spine(&facts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_reconstruct::SolanaAccount as Acct;

    const BPF_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

    // Minimal non-empty EVM runtime bytecode: PUSH1 0x00; PUSH1 0x00; STOP.
    // If lift_with rejects this, swap in the SAMPLE bytecode used by the
    // existing tests in crates/digger-reconstruct/src/evm.rs.
    fn evm_evidence() -> EvidenceInput {
        EvidenceInput::Evm {
            runtime_bytecode: vec![0x60, 0x00, 0x60, 0x00, 0x00],
        }
    }

    // Deterministic upgradeable-program fixture mirroring solana.rs tests:
    // program account data = [u32 LE variant=2][32-byte programdata key=0x11..].
    fn solana_evidence() -> EvidenceInput {
        let pd_key_hex = "11".repeat(32);
        let program = Acct {
            pubkey: "aa".repeat(32),
            owner: BPF_LOADER.to_string(),
            executable: true,
            data_hex: format!("02000000{}", pd_key_hex),
        };
        let program_data = Acct {
            pubkey: pd_key_hex.clone(),
            owner: BPF_LOADER.to_string(),
            executable: false,
            data_hex: "00".repeat(8),
        };
        EvidenceInput::Solana {
            program_id: "aa".repeat(32),
            accounts: vec![program, program_data],
            owned_accounts: vec![],
        }
    }

    #[test]
    fn evm_reconstruct_yields_facts() {
        let facts = reconstruct(Target::Evm, &evm_evidence()).expect("evm reconstruct");
        assert!(facts.deployment.is_some());
        assert!(facts.interface.is_some());
    }

    #[test]
    fn solana_reconstruct_yields_facts() {
        let facts = reconstruct(Target::Solana, &solana_evidence()).expect("solana reconstruct");
        assert!(facts.deployment.is_some());
    }

    #[test]
    fn target_mismatch_is_rejected() {
        assert!(matches!(
            reconstruct(Target::Solana, &evm_evidence()),
            Err(ReconstructError::TargetMismatch)
        ));
    }

    #[test]
    fn investigate_evm_end_to_end_one_system() {
        let spine = investigate(Target::Evm, &evm_evidence()).expect("evm investigate");
        assert_eq!(spine.bridged.systems.len(), 1);
    }

    #[test]
    fn investigate_solana_end_to_end_one_system() {
        let spine = investigate(Target::Solana, &solana_evidence()).expect("solana investigate");
        assert_eq!(spine.bridged.systems.len(), 1);
    }

    #[test]
    fn investigate_is_deterministic_per_target() {
        let e = evm_evidence();
        let a = investigate(Target::Evm, &e).unwrap();
        let b = investigate(Target::Evm, &e).unwrap();
        assert_eq!(format!("{:#?}", a.bridged), format!("{:#?}", b.bridged));
    }
}
