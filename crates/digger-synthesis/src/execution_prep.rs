use crate::engine::SynthesisInputs;
/// Gen 3.3a — Execution Preparation: core context generation.
///
/// Transforms validated exploit chains into execution-ready preparation
/// contexts with all required resources enumerated.
use crate::models::*;

/// Generate execution package from validated chain.
pub fn prepare_execution(
    chain: &ExploitChain,
    validation: &ValidationReport,
    inputs: &crate::engine::SynthesisInputs<'_>,
) -> ExecutionPackage {
    let context = generate_execution_context(chain, inputs);
    let transactions = generate_transactions(chain, inputs);
    let environment = generate_environment(chain, inputs);
    let replay_bundle = generate_replay_bundle(chain, &transactions);

    let blockers: Vec<String> = validation
        .execution_blockers
        .iter()
        .filter(|b| b.severity == BlockerSeverity::Critical)
        .map(|b| b.description.clone())
        .collect();

    // Build the package first, then validate
    let mut pkg = ExecutionPackage {
        package_id: format!("pkg-{}", chain.chain_id),
        chain_id: chain.chain_id.clone(),
        protocol_id: inputs
            .ir
            .as_ref()
            .map(|ir| ir.program_id.clone())
            .unwrap_or_default(),
        chain_type: detect_chain_type(inputs),
        context,
        transactions,
        environment,
        replay_bundle,
        validation: PackageValidation {
            complete: false,
            missing_prerequisites: vec![],
            inconsistent_transactions: vec![],
            reproducible: false,
            explanation: "pending".into(),
        },
        readiness_score: 0.0,
        blockers,
    };

    // Now validate the package
    pkg.validation = crate::prep_validation::validate_preparation(&pkg);
    pkg.readiness_score = compute_readiness(&pkg.validation, validation);

    pkg
}

fn generate_execution_context(chain: &ExploitChain, inputs: &SynthesisInputs) -> ExecutionContext {
    let mut required_contracts: Vec<ContractRequirement> = Vec::new();
    let required_accounts: Vec<AccountRequirement> = Vec::new();
    let mut required_authorities: Vec<AuthorityRequirement> = Vec::new();
    let mut required_assets: Vec<AssetRequirement> = Vec::new();
    let mut required_balances: Vec<BalanceRequirement> = Vec::new();
    let mut required_signers: Vec<SignerRequirement> = Vec::new();
    let mut required_storage: Vec<StorageRequirement> = Vec::new();
    let required_config: Vec<ConfigRequirement> = Vec::new();

    for step in &chain.steps {
        // Contracts
        if !required_contracts.iter().any(|c| c.id == step.function) {
            required_contracts.push(ContractRequirement {
                id: step.function.clone(),
                address: None,
                program_id: None,
                source_required: true,
                deployed: false,
                description: format!("Contract/program containing function '{}'", step.function),
            });
        }

        // State variables
        for var in &step.affected_state {
            if !required_storage.iter().any(|s| s.variable == *var) {
                required_storage.push(StorageRequirement {
                    variable: var.clone(),
                    expected_value: "pre-exploit".into(),
                    step_index: Some(step.index),
                    description: format!("State variable '{}' must exist", var),
                });
            }
        }

        // Assets
        for asset in &step.affected_assets {
            if !required_assets.iter().any(|a| a.asset_id == *asset) {
                required_assets.push(AssetRequirement {
                    asset_id: asset.clone(),
                    asset_type: "token".into(),
                    amount: 0.0,
                    description: format!("Asset '{}' must be available", asset),
                });
            }
        }

        // Authority
        if step.required_capability == ExploitCapability::AuthorityEscalation {
            required_authorities.push(AuthorityRequirement {
                account: "attacker".into(),
                authority_type: "none_required".into(),
                required_for: vec![step.function.clone()],
                description: format!("Function '{}' must have no authority check", step.function),
            });
        }

        // Signer
        if !required_signers.iter().any(|s| s.signer_id == "attacker") {
            required_signers.push(SignerRequirement {
                signer_id: "attacker".into(),
                signer_type: "eoa".into(),
                key_type: "secp256k1".into(),
                description: "Attacker EOA key".into(),
            });
        }
    }

    // Balances from asset requirements
    for asset in &required_assets {
        required_balances.push(BalanceRequirement {
            account: "attacker".into(),
            asset: asset.asset_id.clone(),
            minimum_balance: 1.0,
            description: format!("Attacker needs {} of {}", 1.0, asset.asset_id),
        });
    }

    // Detect authority gaps from IR
    if let Some(ir) = inputs.ir {
        for edge in &ir.edges {
            if let digger_ir::Edge::Authority(a) = edge {
                if a.check_type == "missing" {
                    required_authorities.push(AuthorityRequirement {
                        account: a.function.clone(),
                        authority_type: "none_required".into(),
                        required_for: vec![a.function.clone()],
                        description: format!(
                            "Function '{}' has no authority enforcement",
                            a.function
                        ),
                    });
                }
            }
        }
    }

    ExecutionContext {
        required_contracts,
        required_accounts,
        required_authorities,
        required_assets,
        required_balances,
        required_approvals: vec![],
        required_signers,
        required_pdas: vec![],
        required_storage,
        required_config,
    }
}

fn generate_transactions(
    chain: &ExploitChain,
    inputs: &SynthesisInputs,
) -> Vec<PreparedTransaction> {
    chain
        .steps
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let selector = compute_function_selector(&step.function);
            let args = chain_step_to_args(step);
            let deps: Vec<usize> = step
                .prerequisites
                .iter()
                .filter_map(|p| {
                    if p.contains("Step") {
                        p.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<usize>().ok())
                    } else {
                        None
                    }
                })
                .collect();

            PreparedTransaction {
                index: i,
                step_index: step.index,
                chain_type: detect_chain_type(inputs),
                from: "attacker".into(),
                to: step.function.clone(),
                function_selector: selector,
                arguments: args,
                calldata: None,
                value: if step.required_capability == ExploitCapability::TransferAssets {
                    Some("0".into())
                } else {
                    None
                },
                gas_limit: Some(estimate_gas(step)),
                signers: vec!["attacker".into()],
                dependencies: deps,
                expected_state_changes: step.mutations.clone(),
                expected_events: vec![],
            }
        })
        .collect()
}

fn generate_environment(
    _chain: &ExploitChain,
    inputs: &SynthesisInputs,
) -> EnvironmentRequirements {
    let chain_type = detect_chain_type(inputs);
    let chain_id = if chain_type == "solana" {
        Some(101)
    } else {
        Some(1)
    };

    EnvironmentRequirements {
        fork_block: Some(0),
        chain_id,
        rpc_url: None,
        deployed_contracts: vec![],
        token_balances: vec![],
        oracle_values: vec![],
        governance_state: vec![],
        validator_config: if chain_type == "solana" {
            Some(ValidatorConfig {
                slots_per_epoch: 432000,
                tick_duration_ms: 400,
                warp_slot: None,
            })
        } else {
            None
        },
        feature_gates: vec![],
        clock_requirements: None,
    }
}

fn generate_replay_bundle(chain: &ExploitChain, txns: &[PreparedTransaction]) -> ReplayBundle {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for tx in txns {
        hasher.update(tx.function_selector.as_bytes());
    }
    let hash = format!("{:x}", hasher.finalize());

    ReplayBundle {
        bundle_id: format!("replay-{}", chain.chain_id),
        version: "1.0.0".into(),
        chain_type: txns
            .first()
            .map(|t| t.chain_type.clone())
            .unwrap_or_default(),
        metadata: BundleMetadata {
            created_at: now_iso(),
            chain_id: "1".into(),
            protocol_id: String::new(),
            exploit_goal: chain.goal.clone(),
            total_steps: chain.steps.len(),
            total_transactions: txns.len(),
            deterministic_hash: hash,
        },
        transaction_sequence: txns.to_vec(),
        execution_dependencies: vec!["contract_source_code".into()],
        required_artifacts: vec!["compiled_contracts".into()],
        expected_outputs: chain
            .steps
            .iter()
            .map(|s| format!("Step {}: {}", s.index, s.action))
            .collect(),
        cleanup_instructions: vec!["Remove test artifacts".into(), "Reset chain state".into()],
    }
}

fn compute_function_selector(function: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{}()", function).as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    format!("0x{}", &hash[..8])
}

fn chain_step_to_args(step: &ExploitStep) -> Vec<TransactionArgument> {
    step.affected_state
        .iter()
        .map(|var| TransactionArgument {
            name: var.clone(),
            arg_type: "uint256".into(),
            value: format!("state_{}", var),
            is_dynamic: false,
        })
        .collect()
}

fn estimate_gas(step: &ExploitStep) -> u64 {
    let base = match step.state_transition {
        ExploitState::Preparation => 21000,
        ExploitState::CapabilityAcquisition => 50000,
        ExploitState::Execution => 100000,
        ExploitState::StateCorruption => 80000,
        ExploitState::ValueExtraction => 150000,
        ExploitState::Exit => 30000,
        ExploitState::Cleanup => 25000,
        ExploitState::Preconditions => 10000,
    };
    let mult = match step.required_capability {
        ExploitCapability::FlashLoan => 3,
        ExploitCapability::CrossContractCall | ExploitCapability::CrossProgramInvocation => 2,
        ExploitCapability::GovernanceInfluence => 2,
        _ => 1,
    };
    base * mult
}

fn detect_chain_type(inputs: &SynthesisInputs) -> String {
    inputs
        .ir
        .as_ref()
        .map(|ir| match ir.language {
            digger_ir::Language::Solidity => "evm".into(),
            digger_ir::Language::Anchor | digger_ir::Language::Rust => "solana".into(),
            _ => "unknown".into(),
        })
        .unwrap_or_else(|| "evm".into())
}

fn compute_readiness(validation: &PackageValidation, vr: &ValidationReport) -> f64 {
    let completeness = if validation.complete { 1.0 } else { 0.5 };
    let reproducibility = if validation.reproducible { 1.0 } else { 0.3 };
    let validation_score = vr.validation_score;
    let blocker_penalty = vr
        .execution_blockers
        .iter()
        .filter(|b| b.severity == BlockerSeverity::Critical)
        .count() as f64
        * 0.15;
    ((completeness * 0.3 + reproducibility * 0.3 + validation_score * 0.4) - blocker_penalty)
        .clamp(0.0, 1.0)
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    let tod = secs % 86400;
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let mut y = 1970u64;
    let mut rem = days;
    loop {
        let diy = if (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400) {
            366
        } else {
            365
        };
        if rem < diy {
            break;
        }
        rem -= diy;
        y += 1;
    }
    format!("{:04}-01-{:02}T{:02}:{:02}:{:02}Z", y, 1 + rem, h, m, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_package_generation() {
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "DrainAssets".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::Execution,
                function: "withdraw".into(),
                action: "call".into(),
                required_capability: ExploitCapability::AuthorityEscalation,
                affected_state: vec!["balance".into()],
                affected_assets: vec!["USDC".into()],
                prerequisites: vec![],
                mutations: vec!["drain".into()],
                evidence_refs: vec![],
                confidence: 0.7,
                explanation: "no auth".into(),
            }],
            required_capabilities: vec![ExploitCapability::AuthorityEscalation],
            assumptions: vec![],
            violated_invariants: vec!["balance".into()],
            evidence_provenance: vec![EvidenceReference {
                kind: EvidenceRefKind::GraphAnalysis,
                ref_id: "g1".into(),
                source: "graph".into(),
                derivation: "test".into(),
            }],
            confidence: 0.7,
            severity: digger_ir::Severity::High,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        };
        let vr = ValidationReport {
            chain_id: "test".into(),
            verdict: ValidationVerdict::ValidWithCaveats,
            validation_score: 0.8,
            confidence_interval: (0.6, 1.0),
            preconditions: PreconditionsValidation {
                results: vec![],
                all_satisfied: true,
                satisfied_count: 1,
                unsatisfied_count: 0,
                partial_count: 0,
                unknown_count: 0,
            },
            state_reachability: StateReachabilityValidation {
                transitions: vec![],
                all_reachable: true,
                reachable_count: 1,
                unreachable_count: 0,
            },
            transaction_sequence: TransactionSequenceValidation {
                valid: true,
                issues: vec![],
                ordering: vec![],
                explanation: "valid".into(),
            },
            invariant_replay: InvariantReplayResult {
                replays: vec![],
                violations_detected: 1,
                invariants_preserved: 0,
            },
            asset_flow: AssetFlowValidation {
                flows: vec![],
                valid: true,
                impossible_creations: vec![],
                balance_violations: vec![],
                explanation: "ok".into(),
            },
            capability_validation: CapabilityValidationResult {
                validations: vec![],
                all_proven: true,
                proven_count: 1,
                unproven_count: 0,
            },
            trust_boundary: TrustBoundaryValidation {
                crossings: vec![],
                valid: true,
                unauthorized_count: 0,
                explanation: "ok".into(),
            },
            economic_validation: EconomicValidationReport {
                capital_required: 0.0,
                borrowed_capital: 0.0,
                fees: 0.0,
                slippage_estimate: 0.0,
                gas_estimate: 0.0,
                expected_profit: 1.0,
                minimum_profitable_threshold: 0.001,
                profitable: true,
                breakdown: vec![],
                explanation: "ok".into(),
            },
            execution_blockers: vec![],
            remaining_assumptions: vec![],
            evidence_references: vec![],
            validation_metadata: ValidationMetadata {
                total_checks: 3,
                passed: 3,
                failed: 0,
                partial: 0,
                unknown: 0,
                validation_duration_hint: "3 checks".into(),
            },
        };
        let inputs = crate::engine::SynthesisInputs {
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
        let pkg = prepare_execution(&chain, &vr, &inputs);
        assert_eq!(pkg.transactions.len(), 1);
        assert!(!pkg.context.required_signers.is_empty());
        assert!(pkg.replay_bundle.transaction_sequence.len() == 1);
    }
}
