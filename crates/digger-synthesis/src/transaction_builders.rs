use crate::engine::SynthesisInputs;
/// Gen 3.3b — Transaction Builders: EVM and Solana.
use crate::models::*;

pub fn build_evm_transactions(
    chain: &ExploitChain,
    _inputs: &SynthesisInputs,
) -> Vec<EvmTransaction> {
    chain
        .steps
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let selector = compute_selector(&step.function);
            EvmTransaction {
                step_index: i,
                from: "0xATTACKER_ADDRESS".into(),
                to: resolve_target(&step.function),
                value: "0x0".into(),
                data: format!("{}{}", selector, encode_args(step)),
                gas_limit: estimate_evm_gas(step),
                max_fee_per_gas: Some("30000000000".into()),
                max_priority_fee_per_gas: Some("2000000000".into()),
                chain_id: 1,
                nonce: i as u64,
                access_list: vec![],
                function_signature: format!("{}()", step.function),
                delegatecall: step.required_capability == ExploitCapability::DelegatecallExploit,
                create2: false,
            }
        })
        .collect()
}

pub fn build_solana_transactions(
    chain: &ExploitChain,
    _inputs: &SynthesisInputs,
) -> Vec<SolanaTransaction> {
    chain
        .steps
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let mut accounts = vec![SolanaAccountMeta {
                pubkey: "ATTACKER_PUBKEY".into(),
                is_signer: true,
                is_writable: true,
            }];
            for var in &step.affected_state {
                accounts.push(SolanaAccountMeta {
                    pubkey: format!("ACCOUNT_{}", var.to_uppercase()),
                    is_signer: false,
                    is_writable: true,
                });
            }
            SolanaTransaction {
                step_index: i,
                instructions: vec![
                    SolanaInstruction::ComputeBudgetInstruction(ComputeBudgetInstruction {
                        instruction_type: "SetComputeUnitLimit".into(),
                        units: estimate_solana_compute(step),
                    }),
                    SolanaInstruction::ProgramInstruction(ProgramInstruction {
                        program_id: "11111111111111111111111111111111".into(),
                        accounts,
                        data: format!("instruction_data_{}", step.function),
                    }),
                ],
                signers: vec![SolanaSignerMeta {
                    pubkey: "ATTACKER_PUBKEY".into(),
                    is_signer: true,
                    is_writable: true,
                }],
                compute_budget: estimate_solana_compute(step),
                recent_blockhash: "DUMMY_BLOCKHASH_FOR_PLANNING".into(),
            }
        })
        .collect()
}

fn compute_selector(function: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{}()", function).as_bytes());
    format!("0x{}", &format!("{:x}", hasher.finalize())[..8])
}

fn encode_args(step: &ExploitStep) -> String {
    step.affected_state
        .iter()
        .map(|_| "0000000000000000000000000000000000000000000000000000000000000001".to_string())
        .collect()
}

fn estimate_evm_gas(step: &ExploitStep) -> u64 {
    let base = match step.state_transition {
        ExploitState::Execution => 100_000,
        ExploitState::ValueExtraction => 150_000,
        ExploitState::Preparation => 50_000,
        _ => 30_000,
    };
    base * if step.affected_state.len() > 3 { 2 } else { 1 }
}

fn resolve_target(function: &str) -> String {
    format!("0x{:040x}", {
        let mut h: u64 = 0;
        for b in function.bytes() {
            h = h.wrapping_mul(31).wrapping_add(b as u64);
        }
        h
    })
}

fn estimate_solana_compute(step: &ExploitStep) -> u64 {
    let base = match step.state_transition {
        ExploitState::Execution => 200_000,
        ExploitState::ValueExtraction => 300_000,
        ExploitState::Preparation => 100_000,
        _ => 50_000,
    };
    base * if step.affected_state.len() > 3 { 2 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_build() {
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "test".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::Execution,
                function: "withdraw".into(),
                action: "call".into(),
                required_capability: ExploitCapability::AuthorityEscalation,
                affected_state: vec!["balance".into()],
                affected_assets: vec![],
                prerequisites: vec![],
                mutations: vec![],
                evidence_refs: vec![],
                confidence: 0.7,
                explanation: "test".into(),
            }],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 0.7,
            severity: digger_ir::Severity::Medium,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        };
        let inputs = SynthesisInputs {
            ir: None,
            expansion: None,
            transitions: None,
            lifecycles: None,
            temporal: None,
            actors: None,
            economics: None,
            verification: None,
            adversarial: None,
            protocol: None,
            surface: None,
        };
        let txns = build_evm_transactions(&chain, &inputs);
        assert_eq!(txns.len(), 1);
        assert!(txns[0].data.starts_with("0x"));
    }

    #[test]
    fn test_solana_build() {
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "test".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::Execution,
                function: "process_payment".into(),
                action: "call".into(),
                required_capability: ExploitCapability::CrossProgramInvocation,
                affected_state: vec!["vault".into()],
                affected_assets: vec![],
                prerequisites: vec![],
                mutations: vec![],
                evidence_refs: vec![],
                confidence: 0.7,
                explanation: "test".into(),
            }],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 0.7,
            severity: digger_ir::Severity::Medium,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        };
        let inputs = SynthesisInputs {
            ir: None,
            expansion: None,
            transitions: None,
            lifecycles: None,
            temporal: None,
            actors: None,
            economics: None,
            verification: None,
            adversarial: None,
            protocol: None,
            surface: None,
        };
        let txns = build_solana_transactions(&chain, &inputs);
        assert_eq!(txns.len(), 1);
        assert!(txns[0].compute_budget > 0);
    }
}
