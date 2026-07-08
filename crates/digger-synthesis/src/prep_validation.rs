/// Gen 3.3e — Preparation Validation.
///
/// Validates that execution packages are complete, deterministic,
/// reproducible, and internally consistent.
use crate::models::*;

/// Validate an execution package for completeness and consistency.
pub fn validate_preparation(pkg: &ExecutionPackage) -> PackageValidation {
    let mut missing = Vec::new();
    let mut inconsistent = Vec::new();

    // Check completeness: required contexts are populated
    if pkg.context.required_contracts.is_empty() {
        missing.push("No required contracts identified".into());
    }
    if pkg.context.required_signers.is_empty() {
        missing.push("No required signers identified".into());
    }
    if pkg.transactions.is_empty() {
        missing.push("No transactions prepared".into());
    }

    // Check for missing prerequisites in transactions
    for tx in &pkg.transactions {
        for dep in &tx.dependencies {
            if !pkg.transactions.iter().any(|t| t.index == *dep) {
                missing.push(format!(
                    "Transaction {} depends on missing transaction {}",
                    tx.index, dep
                ));
            }
        }
    }

    // Check deterministic ordering (no circular dependencies)
    let mut visited = std::collections::HashSet::new();
    let mut in_stack = std::collections::HashSet::new();
    for tx in &pkg.transactions {
        if has_cycle_from(tx, &pkg.transactions, &mut visited, &mut in_stack) {
            inconsistent.push(format!(
                "Circular dependency detected involving transaction {}",
                tx.index
            ));
        }
    }

    // Check reproducibility: bundle has hash and version
    let reproducible = !pkg.replay_bundle.metadata.deterministic_hash.is_empty()
        && !pkg.replay_bundle.version.is_empty();

    if !reproducible {
        missing.push("Replay bundle missing deterministic hash or version".into());
    }

    // Check environment completeness
    if pkg.environment.fork_block.is_none() {
        missing.push("No fork block specified".into());
    }
    if pkg.environment.chain_id.is_none() {
        missing.push("No chain ID specified".into());
    }

    // Check transaction consistency
    for i in 0..pkg.transactions.len() {
        let tx = &pkg.transactions[i];
        if tx.to.is_empty() {
            inconsistent.push(format!("Transaction {} has empty target", i));
        }
        if tx.from.is_empty() {
            inconsistent.push(format!("Transaction {} has empty sender", i));
        }
    }

    let complete = missing.is_empty() && inconsistent.is_empty();

    let explanation = if complete {
        "Execution package is complete and consistent".into()
    } else {
        format!(
            "{} missing prerequisite(s), {} inconsistency(ies)",
            missing.len(),
            inconsistent.len()
        )
    };

    PackageValidation {
        complete,
        missing_prerequisites: missing,
        inconsistent_transactions: inconsistent,
        reproducible,
        explanation,
    }
}

fn has_cycle_from(
    tx: &PreparedTransaction,
    all: &[PreparedTransaction],
    visited: &mut std::collections::HashSet<usize>,
    in_stack: &mut std::collections::HashSet<usize>,
) -> bool {
    if in_stack.contains(&tx.index) {
        return true;
    }
    if visited.contains(&tx.index) {
        return false;
    }
    visited.insert(tx.index);
    in_stack.insert(tx.index);
    for dep in &tx.dependencies {
        if let Some(dep_tx) = all.iter().find(|t| t.index == *dep) {
            if has_cycle_from(dep_tx, all, visited, in_stack) {
                return true;
            }
        }
    }
    in_stack.remove(&tx.index);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_package() {
        let pkg = ExecutionPackage {
            package_id: "test".into(),
            chain_id: "test".into(),
            protocol_id: "test".into(),
            chain_type: "evm".into(),
            context: ExecutionContext {
                required_contracts: vec![ContractRequirement {
                    id: "c1".into(),
                    address: None,
                    program_id: None,
                    source_required: true,
                    deployed: false,
                    description: "test".into(),
                }],
                required_accounts: vec![],
                required_authorities: vec![],
                required_assets: vec![],
                required_balances: vec![],
                required_approvals: vec![],
                required_signers: vec![SignerRequirement {
                    signer_id: "attacker".into(),
                    signer_type: "eoa".into(),
                    key_type: "secp256k1".into(),
                    description: "test".into(),
                }],
                required_pdas: vec![],
                required_storage: vec![],
                required_config: vec![],
            },
            transactions: vec![PreparedTransaction {
                index: 0,
                step_index: 0,
                chain_type: "evm".into(),
                from: "0x1".into(),
                to: "0x2".into(),
                function_selector: "0x12345678".into(),
                arguments: vec![],
                calldata: None,
                value: None,
                gas_limit: Some(100000),
                signers: vec![],
                dependencies: vec![],
                expected_state_changes: vec![],
                expected_events: vec![],
            }],
            environment: EnvironmentRequirements {
                fork_block: Some(1),
                chain_id: Some(1),
                rpc_url: None,
                deployed_contracts: vec![],
                token_balances: vec![],
                oracle_values: vec![],
                governance_state: vec![],
                validator_config: None,
                feature_gates: vec![],
                clock_requirements: None,
            },
            replay_bundle: ReplayBundle {
                bundle_id: "test".into(),
                version: "1.0.0".into(),
                chain_type: "evm".into(),
                metadata: BundleMetadata {
                    created_at: "test".into(),
                    chain_id: "1".into(),
                    protocol_id: "test".into(),
                    exploit_goal: "test".into(),
                    total_steps: 1,
                    total_transactions: 1,
                    deterministic_hash: "abc123".into(),
                },
                transaction_sequence: vec![],
                execution_dependencies: vec![],
                required_artifacts: vec![],
                expected_outputs: vec![],
                cleanup_instructions: vec![],
            },
            validation: PackageValidation {
                complete: true,
                missing_prerequisites: vec![],
                inconsistent_transactions: vec![],
                reproducible: true,
                explanation: "test".into(),
            },
            readiness_score: 0.8,
            blockers: vec![],
        };
        let result = validate_preparation(&pkg);
        assert!(result.complete);
        assert!(result.reproducible);
    }

    #[test]
    fn test_incomplete_package() {
        let pkg = ExecutionPackage {
            package_id: "test".into(),
            chain_id: "test".into(),
            protocol_id: "test".into(),
            chain_type: "evm".into(),
            context: ExecutionContext {
                required_contracts: vec![],
                required_accounts: vec![],
                required_authorities: vec![],
                required_assets: vec![],
                required_balances: vec![],
                required_approvals: vec![],
                required_signers: vec![],
                required_pdas: vec![],
                required_storage: vec![],
                required_config: vec![],
            },
            transactions: vec![],
            environment: EnvironmentRequirements {
                fork_block: None,
                chain_id: None,
                rpc_url: None,
                deployed_contracts: vec![],
                token_balances: vec![],
                oracle_values: vec![],
                governance_state: vec![],
                validator_config: None,
                feature_gates: vec![],
                clock_requirements: None,
            },
            replay_bundle: ReplayBundle {
                bundle_id: "test".into(),
                version: "1.0.0".into(),
                chain_type: "evm".into(),
                metadata: BundleMetadata {
                    created_at: "test".into(),
                    chain_id: "1".into(),
                    protocol_id: "test".into(),
                    exploit_goal: "test".into(),
                    total_steps: 0,
                    total_transactions: 0,
                    deterministic_hash: "abc123".into(),
                },
                transaction_sequence: vec![],
                execution_dependencies: vec![],
                required_artifacts: vec![],
                expected_outputs: vec![],
                cleanup_instructions: vec![],
            },
            validation: PackageValidation {
                complete: false,
                missing_prerequisites: vec![],
                inconsistent_transactions: vec![],
                reproducible: true,
                explanation: "test".into(),
            },
            readiness_score: 0.0,
            blockers: vec![],
        };
        let result = validate_preparation(&pkg);
        assert!(!result.complete);
        assert!(!result.missing_prerequisites.is_empty());
    }
}
