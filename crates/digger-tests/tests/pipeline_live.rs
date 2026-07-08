//! C1.4 — deterministic live-pipeline integration tests (evidence -> Gen3).
//! Drives the unified digger-pipeline (reconstruction -> Gen5 spine -> SystemIR
//! bridge -> Gen2 + Gen3) for both EVM and Solana evidence and asserts the run
//! is deterministic and reaches Gen3 for every recovered system.
//!
//! C3.3 — dependency propagation tests: proves RecoveredFacts.dependencies
//! (now non-empty via C3.1/C3.2 recoverers) flow through build_protocol_model
//! into ProtocolModel.dependencies.

use digger_pipeline::{investigate, investigate_and_analyze, EvidenceInput, Target};
use digger_reconstruct::SolanaAccount;

const BPF_UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
/// SPL Token Program (C3.2 known_programs classifies this as Token).
const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn evm_evidence() -> EvidenceInput {
    EvidenceInput::Evm {
        runtime_bytecode: vec![0x60, 0x00, 0x60, 0x00, 0x00],
    }
}

/// EVM bytecode that triggers the C3.1 dependency recoverer:
///   PUSH20 <0xAA..AA>   — embedded external address
///   PUSH4  0xa9059cbb    — ERC-20 transfer() selector
///   CALL                 — external call
///   STOP
/// The recoverer's 8-instruction forward window sees both PUSH4 and CALL after PUSH20,
/// yielding a Token dependency with observed_selectors=["0xa9059cbb"].
fn evm_dep_evidence() -> EvidenceInput {
    let mut bytecode = Vec::new();
    // PUSH20 (0x73) followed by 20 bytes of 0xAA
    bytecode.push(0x73);
    bytecode.extend(std::iter::repeat_n(0xAAu8, 20));
    // PUSH4 (0x63) followed by 0xa9059cbb
    bytecode.extend_from_slice(&[0x63, 0xa9, 0x05, 0x9c, 0xbb]);
    // CALL (0xf1)
    bytecode.push(0xf1);
    // STOP (0x00)
    bytecode.push(0x00);
    EvidenceInput::Evm {
        runtime_bytecode: bytecode,
    }
}

fn solana_evidence() -> EvidenceInput {
    let pd_key_bytes = [0xDDu8; 32];
    let pd_pubkey = hex(&pd_key_bytes);

    let mut prog_data = vec![2u8, 0, 0, 0];
    prog_data.extend_from_slice(&pd_key_bytes);
    let program = SolanaAccount {
        pubkey: hex(&[0x01u8; 32]),
        owner: BPF_UPGRADEABLE_LOADER.to_string(),
        executable: true,
        data_hex: hex(&prog_data),
    };

    let mut pd_data = vec![3u8, 0, 0, 0];
    pd_data.extend_from_slice(&[0u8; 8]);
    pd_data.push(1u8);
    pd_data.extend_from_slice(&[0xAAu8; 32]);
    let program_data = SolanaAccount {
        pubkey: pd_pubkey,
        owner: BPF_UPGRADEABLE_LOADER.to_string(),
        executable: false,
        data_hex: hex(&pd_data),
    };

    EvidenceInput::Solana {
        program_id: program.pubkey.clone(),
        accounts: vec![program, program_data],
        owned_accounts: vec![],
    }
}

/// Solana evidence with a token-account owned by SPL Token Program.
/// The C3.2 recoverer sees an Invokes edge to the SPL Token owner → Token dep.
fn solana_dep_evidence() -> EvidenceInput {
    let pd_key_bytes = [0xDDu8; 32];
    let pd_pubkey = hex(&pd_key_bytes);

    let mut prog_data = vec![2u8, 0, 0, 0];
    prog_data.extend_from_slice(&pd_key_bytes);
    let program = SolanaAccount {
        pubkey: hex(&[0x01u8; 32]),
        owner: BPF_UPGRADEABLE_LOADER.to_string(),
        executable: true,
        data_hex: hex(&prog_data),
    };

    let mut pd_data = vec![3u8, 0, 0, 0];
    pd_data.extend_from_slice(&[0u8; 8]);
    pd_data.push(1u8);
    pd_data.extend_from_slice(&[0xAAu8; 32]);
    let program_data = SolanaAccount {
        pubkey: pd_pubkey,
        owner: BPF_UPGRADEABLE_LOADER.to_string(),
        executable: false,
        data_hex: hex(&pd_data),
    };

    // An SPL Token token-account: owned by the Token program.
    // The C3.2 recoverer builds an Invokes edge from the target program
    // to this account, resolves owner=SPL_TOKEN → Token dependency.
    let token_account = SolanaAccount {
        pubkey: hex(&[0xBBu8; 32]),
        owner: SPL_TOKEN_PROGRAM.to_string(),
        executable: false,
        data_hex: "00".repeat(165), // Token account data is 165 bytes
    };

    EvidenceInput::Solana {
        program_id: program.pubkey.clone(),
        accounts: vec![program, program_data, token_account],
        owned_accounts: vec![hex(&[0xBBu8; 32])],
    }
}

// ── Existing C1.4 tests ─────────────────────────────────────────────

#[test]
fn evm_evidence_reaches_gen3() {
    let outcome =
        investigate_and_analyze(Target::Evm, &evm_evidence()).expect("EVM pipeline failed");
    assert!(
        !outcome.systems.is_empty(),
        "EVM evidence produced no systems"
    );
}

#[test]
fn solana_evidence_reaches_gen3() {
    let outcome = investigate_and_analyze(Target::Solana, &solana_evidence())
        .expect("Solana pipeline failed");
    assert!(
        !outcome.systems.is_empty(),
        "Solana evidence produced no systems"
    );
}

#[test]
fn evm_pipeline_is_deterministic() {
    let a = format!(
        "{:#?}",
        investigate_and_analyze(Target::Evm, &evm_evidence()).unwrap()
    );
    let b = format!(
        "{:#?}",
        investigate_and_analyze(Target::Evm, &evm_evidence()).unwrap()
    );
    assert_eq!(a, b, "EVM pipeline is not deterministic");
}

#[test]
fn solana_pipeline_is_deterministic() {
    let a = format!(
        "{:#?}",
        investigate_and_analyze(Target::Solana, &solana_evidence()).unwrap()
    );
    let b = format!(
        "{:#?}",
        investigate_and_analyze(Target::Solana, &solana_evidence()).unwrap()
    );
    assert_eq!(a, b, "Solana pipeline is not deterministic");
}

// ── C3.3 dependency propagation tests ───────────────────────────────

#[test]
fn evm_pipeline_recovers_and_propagates_dependency() {
    let spine = investigate(Target::Evm, &evm_dep_evidence()).expect("EVM pipeline failed");

    // 1. RecoveredFacts.dependencies was non-empty (verified transitively via spine.model)
    assert!(
        !spine.model.dependencies.is_empty(),
        "EVM dep fixture: ProtocolModel.dependencies is empty — dependency not propagated"
    );

    // 2. Exactly one dependency
    assert_eq!(
        spine.model.dependencies.len(),
        1,
        "EVM dep fixture: expected 1 dependency, got {}",
        spine.model.dependencies.len()
    );

    let dep = &spine.model.dependencies[0];

    // 3. It's a Token dependency at the expected address
    assert_eq!(
        dep.kind,
        digger_reconstruct::DependencyKind::Token,
        "EVM dep fixture: expected Token kind"
    );
    let addr = match &dep.address {
        digger_reconstruct::RecoveredAddress::Resolved(a) => a.clone(),
        other => panic!("EVM dep fixture: address not resolved: {:?}", other),
    };
    assert_eq!(
        addr, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "EVM dep fixture: wrong resolved address"
    );

    // 4. Observed selector matches the transfer() selector we embedded
    match &dep.detail {
        digger_reconstruct::DependencyDetail::Evm(evm_dep) => {
            assert!(
                evm_dep
                    .observed_selectors
                    .contains(&"0xa9059cbb".to_string()),
                "EVM dep fixture: expected 0xa9059cbb in observed_selectors, got {:?}",
                evm_dep.observed_selectors
            );
        }
        other => panic!("EVM dep fixture: expected Evm detail, got {:?}", other),
    }
}

#[test]
fn solana_pipeline_recovers_and_propagates_dependency() {
    let spine =
        investigate(Target::Solana, &solana_dep_evidence()).expect("Solana pipeline failed");

    // 1. Dependencies propagated into ProtocolModel
    assert!(
        !spine.model.dependencies.is_empty(),
        "Solana dep fixture: ProtocolModel.dependencies is empty — dependency not propagated"
    );

    // 2. Exactly one dependency (the SPL Token program)
    assert_eq!(
        spine.model.dependencies.len(),
        1,
        "Solana dep fixture: expected 1 dependency, got {}",
        spine.model.dependencies.len()
    );

    let dep = &spine.model.dependencies[0];

    // 3. It's a Token dependency referencing the SPL Token program
    assert_eq!(
        dep.kind,
        digger_reconstruct::DependencyKind::Token,
        "Solana dep fixture: expected Token kind"
    );
    let addr = match &dep.address {
        digger_reconstruct::RecoveredAddress::Resolved(a) => a.clone(),
        other => panic!("Solana dep fixture: address not resolved: {:?}", other),
    };
    assert_eq!(
        addr, SPL_TOKEN_PROGRAM,
        "Solana dep fixture: wrong resolved address"
    );

    // 4. SolanaDetail has the SPL Token program ref
    match &dep.detail {
        digger_reconstruct::DependencyDetail::Solana(sol_dep) => {
            assert!(
                sol_dep
                    .observed_program_refs
                    .contains(&SPL_TOKEN_PROGRAM.to_string()),
                "Solana dep fixture: expected SPL Token in observed_program_refs, got {:?}",
                sol_dep.observed_program_refs
            );
        }
        other => panic!(
            "Solana dep fixture: expected Solana detail, got {:?}",
            other
        ),
    }
}

#[test]
fn evm_dep_pipeline_is_deterministic() {
    let a = format!(
        "{:#?}",
        investigate(Target::Evm, &evm_dep_evidence()).unwrap()
    );
    let b = format!(
        "{:#?}",
        investigate(Target::Evm, &evm_dep_evidence()).unwrap()
    );
    assert_eq!(a, b, "EVM dep pipeline is not deterministic");
}

#[test]
fn solana_dep_pipeline_is_deterministic() {
    let a = format!(
        "{:#?}",
        investigate(Target::Solana, &solana_dep_evidence()).unwrap()
    );
    let b = format!(
        "{:#?}",
        investigate(Target::Solana, &solana_dep_evidence()).unwrap()
    );
    assert_eq!(a, b, "Solana dep pipeline is not deterministic");
}

#[test]
fn evm_dep_produces_derived_asset() {
    let spine = investigate(Target::Evm, &evm_dep_evidence()).expect("EVM pipeline failed");
    // A Token dependency should produce at least one Asset in the model
    assert!(
        !spine.model.assets.is_empty(),
        "EVM dep fixture: expected at least one derived asset from Token dependency"
    );
}

#[test]
fn solana_dep_produces_derived_asset() {
    let spine =
        investigate(Target::Solana, &solana_dep_evidence()).expect("Solana pipeline failed");
    // A Token dependency should produce at least one Asset in the model
    assert!(
        !spine.model.assets.is_empty(),
        "Solana dep fixture: expected at least one derived asset from Token dependency"
    );
}
