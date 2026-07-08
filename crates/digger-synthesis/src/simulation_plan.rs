use crate::attack_plan::DetailedAttackPlan;
/// Generation 3.1f — Simulation Planning (Enhanced)
///
/// Generates deterministic simulation specifications for Foundry (EVM) and
/// Solana simulation engines. Includes preflight checks, detailed assertion
/// builders, and chain-specific configurations.
use crate::models::*;

/// Extended simulation spec with preflight checks.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtendedSimulationSpec {
    /// Base spec.
    pub base: SimulationSpec,
    /// Preflight checks before execution.
    pub preflight: Vec<PreflightCheck>,
    /// Chain-specific configuration.
    pub chain_config: ChainSpecificConfig,
    /// Expected failures (for negative testing).
    pub expected_failures: Vec<ExpectedFailure>,
    /// Cleanup instructions after simulation.
    pub cleanup: Vec<String>,
}

/// A preflight check to run before the simulation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreflightCheck {
    /// Check name.
    pub name: String,
    /// What to verify.
    pub description: String,
    /// Expected outcome.
    pub expected: String,
    /// Whether this check is required.
    pub required: bool,
}

/// Chain-specific configuration details.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ChainSpecificConfig {
    Evm(EvmConfig),
    Solana(SolanaConfig),
}

/// EVM-specific configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvmConfig {
    /// Fork block number.
    pub fork_block: u64,
    /// RPC URL.
    pub rpc_url: String,
    /// Gas limit per transaction.
    pub gas_limit: u64,
    /// Block gas limit.
    pub block_gas_limit: u64,
    /// Base fee.
    pub base_fee: u64,
    /// Chain ID.
    pub chain_id: u64,
    /// Contracts to deploy.
    pub deploy: Vec<EvmDeploy>,
}

/// EVM contract deployment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvmDeploy {
    /// Contract name.
    pub name: String,
    /// Constructor arguments.
    pub constructor_args: Vec<String>,
    /// Expected address (deterministic).
    pub expected_address: Option<String>,
}

/// Solana-specific configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SolanaConfig {
    /// RPC URL.
    pub rpc_url: String,
    /// Slot to fork from.
    pub fork_slot: u64,
    /// Programs to deploy.
    pub programs: Vec<SolanaProgram>,
    /// PDA accounts to create.
    pub pda_accounts: Vec<PdaAccount>,
    /// Total compute budget per transaction.
    pub compute_budget: u64,
    /// Rent-exempt minimum per account.
    pub rent_exempt_minimum: u64,
}

/// Solana program deployment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SolanaProgram {
    /// Program name.
    pub name: String,
    /// Program ID.
    pub program_id: String,
    /// Path to .so file.
    pub binary_path: String,
    /// Accounts that need to be initialized.
    pub init_accounts: Vec<String>,
}

/// PDA account to create.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PdaAccount {
    /// PDA name.
    pub name: String,
    /// Seeds for derivation.
    pub seeds: Vec<String>,
    /// Bump value.
    pub bump: u8,
    /// Program that owns this PDA.
    pub owner_program: String,
    /// Size in bytes.
    pub size: u64,
    /// Initial lamports.
    pub lamports: u64,
}

/// Expected failure during simulation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExpectedFailure {
    /// Step index that should fail.
    pub step_index: usize,
    /// Expected error message or pattern.
    pub error_pattern: String,
    /// Whether this failure is expected.
    pub expected: bool,
    /// Reason for expecting this failure.
    pub reason: String,
}

/// Generate Foundry simulation spec from a detailed attack plan.
pub fn generate_foundry_spec(plan: &DetailedAttackPlan) -> ExtendedSimulationSpec {
    let _base = generate_base_spec(plan, "evm");

    let preflight = vec![
        PreflightCheck {
            name: "fork_state".into(),
            description: "Fork chain state at specified block".into(),
            expected: "State matches forked block".into(),
            required: true,
        },
        PreflightCheck {
            name: "deployer_funded".into(),
            description: "Deployer account has sufficient ETH for gas".into(),
            expected: "Balance > 10 ETH".into(),
            required: true,
        },
        PreflightCheck {
            name: "contracts_verified".into(),
            description: "Target contracts are verified on block explorer".into(),
            expected: "All target contracts have source code".into(),
            required: false,
        },
        PreflightCheck {
            name: "block_gas_available".into(),
            description: "Block has enough gas for all transactions".into(),
            expected: "Block gas limit > sum of tx gas limits".into(),
            required: true,
        },
    ];

    let gas_estimates: u64 = plan
        .base
        .steps
        .iter()
        .zip(plan.resource_estimates.iter())
        .map(|(_, r)| r.compute_units)
        .sum();

    let chain_config = ChainSpecificConfig::Evm(EvmConfig {
        fork_block: 0,
        rpc_url: "https://eth.llamarpc.com".into(),
        gas_limit: gas_estimates.max(30_000_000),
        block_gas_limit: 30_000_000,
        base_fee: 10_000_000_000,
        chain_id: 1,
        deploy: vec![],
    });

    let assertions: Vec<Assertion> = plan
        .base
        .broken_invariants
        .iter()
        .enumerate()
        .map(|(i, inv)| Assertion {
            kind: AssertionKind::InvariantCheck,
            target: format!("post_state_invariant_{}", i),
            expected: "violated".into(),
            description: inv.description.clone(),
        })
        .chain(
            plan.base
                .steps
                .iter()
                .enumerate()
                .map(|(i, step)| Assertion {
                    kind: AssertionKind::BalanceCheck,
                    target: format!("step_{}_balance", i),
                    expected: "changed".into(),
                    description: format!(
                        "Balance changed after step {}: {}",
                        i, step.target_function
                    ),
                }),
        )
        .collect();

    ExtendedSimulationSpec {
        base: SimulationSpec {
            chain_id: plan.base.plan_id.clone(),
            targets: plan
                .base
                .affected_targets
                .iter()
                .map(|t| SimulationTarget {
                    id: t.target_id.clone(),
                    source: format!("src/{}.sol", t.target_id),
                    chain: "evm".into(),
                    deploy_mode: DeployMode::Fork { block: 0 },
                })
                .collect(),
            fork_config: ForkConfig {
                chain: "ethereum".into(),
                fork_block: Some(0),
                rpc_url: Some("https://eth.llamarpc.com".into()),
            },
            required_balances: plan
                .base
                .required_actors
                .iter()
                .flat_map(|a| {
                    a.required_permissions.iter().map(|_p| BalanceSpec {
                        account: a.actor_id.clone(),
                        asset: "ETH".into(),
                        amount: 10.0,
                    })
                })
                .collect(),
            required_accounts: plan
                .base
                .required_actors
                .iter()
                .map(|a| AccountSpec {
                    address: a.actor_id.clone(),
                    account_type: "attacker_eoa".into(),
                    permissions: a.required_permissions.clone(),
                    data_layout: None,
                })
                .collect(),
            transactions: plan
                .base
                .steps
                .iter()
                .enumerate()
                .map(|(i, step)| TransactionSpec {
                    index: i,
                    from: "attacker".into(),
                    to: step.target_function.clone(),
                    function: step.action.clone(),
                    parameters: step.preconditions.clone(),
                    value: None,
                    expect_success: true,
                    expected_revert: None,
                    compute_budget: None,
                    signers: vec![],
                })
                .collect(),
            assertions,
            postconditions: plan
                .base
                .expected_outcomes
                .iter()
                .map(|o| format!("POST: {}", o))
                .collect(),
            chain_type: "evm".into(),
        },
        preflight,
        chain_config,
        expected_failures: vec![],
        cleanup: vec![
            "Verify all invariant assertions pass".into(),
            "Record final state for comparison".into(),
            "Clean up test artifacts".into(),
        ],
    }
}

/// Generate Solana simulation spec from a detailed attack plan.
pub fn generate_solana_spec(plan: &DetailedAttackPlan) -> ExtendedSimulationSpec {
    let _base = generate_base_spec(plan, "solana");

    let preflight = vec![
        PreflightCheck {
            name: "fork_slot".into(),
            description: "Fork cluster state at specified slot".into(),
            expected: "State matches forked slot".into(),
            required: true,
        },
        PreflightCheck {
            name: "payer_funded".into(),
            description: "Payer account has sufficient SOL for rent and fees".into(),
            expected: "Balance > 2 SOL".into(),
            required: true,
        },
        PreflightCheck {
            name: "programs_deployed".into(),
            description: "All target programs are deployed at known addresses".into(),
            expected: "Program IDs match expected addresses".into(),
            required: true,
        },
        PreflightCheck {
            name: "pda_accounts_init".into(),
            description: "PDA accounts are initialized with correct seeds and bump".into(),
            expected: "All PDAs derivable from seeds".into(),
            required: true,
        },
    ];

    let total_compute: u64 = plan
        .resource_estimates
        .iter()
        .map(|r| r.compute_units)
        .sum();

    let chain_config = ChainSpecificConfig::Solana(SolanaConfig {
        rpc_url: "https://api.mainnet-beta.solana.com".into(),
        fork_slot: 0,
        programs: plan
            .base
            .affected_targets
            .iter()
            .map(|t| SolanaProgram {
                name: t.target_id.clone(),
                program_id: "11111111111111111111111111111111".to_string(),
                binary_path: format!("target/deploy/{}.so", t.target_id),
                init_accounts: vec![],
            })
            .collect(),
        pda_accounts: vec![],
        compute_budget: total_compute.max(400_000),
        rent_exempt_minimum: 890880,
    });

    let assertions: Vec<Assertion> = plan
        .base
        .broken_invariants
        .iter()
        .enumerate()
        .map(|(i, inv)| Assertion {
            kind: AssertionKind::InvariantCheck,
            target: format!("post_invariant_{}", i),
            expected: "violated".into(),
            description: inv.description.clone(),
        })
        .collect();

    ExtendedSimulationSpec {
        base: SimulationSpec {
            chain_id: plan.base.plan_id.clone(),
            targets: plan
                .base
                .affected_targets
                .iter()
                .map(|t| SimulationTarget {
                    id: t.target_id.clone(),
                    source: format!("target/deploy/{}.so", t.target_id),
                    chain: "solana".into(),
                    deploy_mode: DeployMode::Fork { block: 0 },
                })
                .collect(),
            fork_config: ForkConfig {
                chain: "solana".into(),
                fork_block: Some(0),
                rpc_url: Some("https://api.mainnet-beta.solana.com".into()),
            },
            required_balances: plan
                .base
                .required_actors
                .iter()
                .flat_map(|a| {
                    a.required_permissions.iter().map(|_p| BalanceSpec {
                        account: a.actor_id.clone(),
                        asset: "SOL".into(),
                        amount: 10.0,
                    })
                })
                .collect(),
            required_accounts: plan
                .base
                .required_actors
                .iter()
                .map(|a| AccountSpec {
                    address: a.actor_id.clone(),
                    account_type: "attacker_wallet".into(),
                    permissions: a.required_permissions.clone(),
                    data_layout: None,
                })
                .collect(),
            transactions: plan
                .base
                .steps
                .iter()
                .enumerate()
                .map(|(i, step)| TransactionSpec {
                    index: i,
                    from: "attacker".into(),
                    to: step.target_function.clone(),
                    function: step.action.clone(),
                    parameters: step.preconditions.clone(),
                    value: None,
                    expect_success: true,
                    expected_revert: None,
                    compute_budget: Some(400_000),
                    signers: vec!["attacker".into()],
                })
                .collect(),
            assertions,
            postconditions: plan
                .base
                .expected_outcomes
                .iter()
                .map(|o| format!("POST: {}", o))
                .collect(),
            chain_type: "solana".into(),
        },
        preflight,
        chain_config,
        expected_failures: vec![],
        cleanup: vec![
            "Verify all invariant assertions pass".into(),
            "Record final account state for comparison".into(),
            "Clean up test validator state".into(),
        ],
    }
}

fn generate_base_spec(plan: &DetailedAttackPlan, chain_type: &str) -> SimulationSpec {
    SimulationSpec {
        chain_id: plan.base.plan_id.clone(),
        targets: vec![],
        fork_config: ForkConfig {
            chain: chain_type.to_string(),
            fork_block: Some(0),
            rpc_url: None,
        },
        required_balances: vec![],
        required_accounts: vec![],
        transactions: vec![],
        assertions: vec![],
        postconditions: vec![],
        chain_type: chain_type.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack_plan;

    fn test_plan() -> DetailedAttackPlan {
        let chain = crate::models::ExploitChain {
            chain_id: "test".into(),
            goal: "DrainAssets".into(),
            steps: vec![crate::models::ExploitStep {
                index: 0,
                state_transition: crate::models::ExploitState::Execution,
                function: "withdraw".into(),
                action: "call withdraw".into(),
                required_capability: crate::models::ExploitCapability::AuthorityEscalation,
                affected_state: vec!["pool".into()],
                affected_assets: vec!["USDC".into()],
                prerequisites: vec![],
                mutations: vec!["drain".into()],
                evidence_refs: vec![],
                confidence: 0.7,
                explanation: "no auth".into(),
            }],
            required_capabilities: vec![crate::models::ExploitCapability::AuthorityEscalation],
            assumptions: vec![],
            violated_invariants: vec!["conservation".into()],
            evidence_provenance: vec![crate::models::EvidenceReference {
                kind: crate::models::EvidenceRefKind::GraphAnalysis,
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

        let preconditions = crate::preconditions::PreconditionResult {
            chain_id: "test".into(),
            preconditions: vec![],
            satisfied: 0,
            missing: 0,
            unknown: 0,
            all_satisfied: true,
        };

        let feasibility = crate::models::FeasibilityScore {
            chain_id: "test".into(),
            overall: 0.7,
            components: crate::models::FeasibilityComponents {
                precondition_score: 0.8,
                state_reachability: 0.9,
                invariant_violations: 0.3,
                trust_boundary_score: 0.1,
                economic_viability: 1.0,
                assumption_violations: 0.85,
                evidence_quality: 0.6,
                step_efficiency: 0.92,
            },
            explanation: "test".into(),
            verdict: crate::models::FeasibilityVerdict::Feasible,
        };

        attack_plan::generate_detailed_attack_plan(&chain, &preconditions, &feasibility)
    }

    #[test]
    fn test_foundry_spec() {
        let plan = test_plan();
        let spec = generate_foundry_spec(&plan);
        assert_eq!(spec.base.chain_type, "evm");
        assert!(!spec.preflight.is_empty());
        assert!(!spec.cleanup.is_empty());
        match &spec.chain_config {
            ChainSpecificConfig::Evm(cfg) => {
                assert!(cfg.gas_limit > 0);
                assert!(cfg.chain_id > 0);
            }
            _ => panic!("Expected EVM config"),
        }
    }

    #[test]
    fn test_solana_spec() {
        let plan = test_plan();
        let spec = generate_solana_spec(&plan);
        assert_eq!(spec.base.chain_type, "solana");
        assert!(!spec.preflight.is_empty());
        match &spec.chain_config {
            ChainSpecificConfig::Solana(cfg) => {
                assert!(cfg.compute_budget >= 400_000);
                assert!(cfg.rent_exempt_minimum > 0);
            }
            _ => panic!("Expected Solana config"),
        }
    }

    #[test]
    fn test_preflight_checks() {
        let plan = test_plan();
        let foundry = generate_foundry_spec(&plan);
        let required: Vec<&str> = foundry
            .preflight
            .iter()
            .filter(|p| p.required)
            .map(|p| p.name.as_str())
            .collect();
        assert!(required.contains(&"fork_state"));
        assert!(required.contains(&"deployer_funded"));
    }
}
