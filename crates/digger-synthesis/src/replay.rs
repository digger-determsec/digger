/// Gen 3.3c — Environment Requirements + Replay Packages.
use crate::models::*;

/// Generate replay package from execution package.
/// The `created_at` parameter must be provided explicitly — no wall-clock
/// access inside the deterministic build path.
pub fn build_replay_package(
    chain: &ExploitChain,
    evm_txns: &[EvmTransaction],
    solana_txns: &[SolanaTransaction],
    chain_type: &str,
    created_at: &str,
) -> ReplayBundle {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(chain.chain_id.as_bytes());
    for tx in evm_txns {
        hasher.update(tx.data.as_bytes());
    }
    for tx in solana_txns {
        hasher.update(tx.compute_budget.to_string().as_bytes());
    }
    let hash = format!("{:x}", hasher.finalize());

    let txns: Vec<PreparedTransaction> = chain
        .steps
        .iter()
        .enumerate()
        .map(|(i, step)| PreparedTransaction {
            index: i,
            step_index: step.index,
            chain_type: chain_type.into(),
            from: "attacker".into(),
            to: step.function.clone(),
            function_selector: format!(
                "0x{}",
                &format!("{:x}", {
                    let mut h: u64 = 0;
                    for b in step.function.bytes() {
                        h = h.wrapping_mul(31).wrapping_add(b as u64);
                    }
                    h
                })[..8]
            ),
            arguments: vec![],
            calldata: None,
            value: None,
            gas_limit: Some(100_000),
            signers: vec!["attacker".into()],
            dependencies: vec![],
            expected_state_changes: step.mutations.clone(),
            expected_events: vec![],
        })
        .collect();

    ReplayBundle {
        bundle_id: format!("replay-{}", chain.chain_id),
        version: "1.0.0".into(),
        chain_type: chain_type.into(),
        metadata: BundleMetadata {
            created_at: created_at.to_string(),
            chain_id: chain_type.into(),
            protocol_id: String::new(),
            exploit_goal: chain.goal.clone(),
            total_steps: chain.steps.len(),
            total_transactions: txns.len(),
            deterministic_hash: hash,
        },
        transaction_sequence: txns,
        execution_dependencies: vec!["compiled_contracts".into(), "forked_state".into()],
        required_artifacts: vec!["bytecode".into(), "abi".into()],
        expected_outputs: chain
            .steps
            .iter()
            .map(|s| format!("Step {}: {}", s.index, s.action))
            .collect(),
        cleanup_instructions: vec![
            "Reset chain state".into(),
            "Remove deployed contracts".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_replay_package() {
        let chain = ExploitChain {
            chain_id: "chain-replay-001".into(),
            goal: "DrainAssets".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::Execution,
                function: "withdraw".into(),
                action: "Drain via withdraw".into(),
                required_capability: ExploitCapability::TransferAssets,
                affected_state: vec!["balance".into()],
                affected_assets: vec![],
                prerequisites: vec![],
                mutations: vec!["decrease balance".into()],
                evidence_refs: vec![],
                confidence: 0.7,
                explanation: "Test".into(),
            }],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 0.7,
            severity: digger_ir::Severity::High,
            historical_similarity: vec![],
            rank: None,
            explanation: "Test".into(),
        };
        let evm_txns = vec![EvmTransaction {
            step_index: 0,
            from: "0xATTACKER".into(),
            to: "0xCONTRACT".into(),
            value: "0x0".into(),
            data: "0xdeadbeef".into(),
            gas_limit: 100_000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            chain_id: 1,
            nonce: 0,
            access_list: vec![],
            function_signature: "withdraw()".into(),
            delegatecall: false,
            create2: false,
        }];
        let bundle = build_replay_package(&chain, &evm_txns, &[], "evm", "2025-01-01T00:00:00Z");
        assert!(!bundle.bundle_id.is_empty());
        assert_eq!(bundle.chain_type, "evm");
        assert!(!bundle.transaction_sequence.is_empty());
        assert!(!bundle.expected_outputs.is_empty());
        assert!(!bundle.execution_dependencies.is_empty());
    }
}
