/// Uniswap V2/V3/V4 pack.
use super::pack::*;

pub struct UniswapPack;

impl ProtocolPack for UniswapPack {
    fn name(&self) -> &str {
        "Uniswap"
    }
    fn versions(&self) -> &[&str] {
        &["v2", "v3", "v4"]
    }
    fn chains(&self) -> &[&str] {
        &["ethereum", "polygon", "arbitrum", "optimism", "base", "bsc"]
    }

    fn invariants(&self) -> Vec<ProtocolInvariant> {
        vec![
            ProtocolInvariant {
                description: "Constant product: x * y = k".into(),
                state_vars: vec!["reserve0".into(), "reserve1".into()],
                preserving_functions: vec!["swap".into(), "mint".into(), "burn".into()],
                consequence: "Price manipulation, fund theft".into(),
            },
            ProtocolInvariant {
                description: "Total liquidity must equal sum of LP shares".into(),
                state_vars: vec!["totalSupply".into(), "reserve0".into(), "reserve1".into()],
                preserving_functions: vec!["mint".into(), "burn".into()],
                consequence: "LP share manipulation".into(),
            },
        ]
    }

    fn accounting_rules(&self) -> Vec<AccountingRule> {
        vec![
            AccountingRule {
                description: "Swap fee: 0.3% of input amount".into(),
                variables: vec!["amountIn".into(), "amountOut".into(), "fee".into()],
                relationship: "fee_deduction".into(),
                enforcing_functions: vec!["swap".into()],
            },
            AccountingRule {
                description: "LP share minting: proportional to liquidity added".into(),
                variables: vec!["amount0".into(), "amount1".into(), "totalSupply".into()],
                relationship: "proportional".into(),
                enforcing_functions: vec!["mint".into()],
            },
        ]
    }

    fn lifecycle_phases(&self) -> Vec<LifecyclePhase> {
        vec![
            LifecyclePhase {
                name: "Add Liquidity".into(),
                description: "User deposits token pair, receives LP shares".into(),
                functions: vec!["mint".into(), "addLiquidity".into()],
                preconditions: vec!["Pool exists".into(), "Tokens approved".into()],
                postconditions: vec!["LP shares minted".into(), "Reserves updated".into()],
            },
            LifecyclePhase {
                name: "Swap".into(),
                description: "User swaps one token for another".into(),
                functions: vec!["swap".into()],
                preconditions: vec!["Sufficient liquidity".into(), "Amount out > minimum".into()],
                postconditions: vec!["Reserves updated".into(), "Tokens transferred".into()],
            },
            LifecyclePhase {
                name: "Remove Liquidity".into(),
                description: "User burns LP shares, receives token pair".into(),
                functions: vec!["burn".into(), "removeLiquidity".into()],
                preconditions: vec!["User has LP shares".into()],
                postconditions: vec!["LP shares burned".into(), "Tokens returned".into()],
            },
        ]
    }

    fn trust_boundaries(&self) -> Vec<TrustBoundary> {
        vec![
            TrustBoundary {
                description: "Token transfers".into(),
                crosses: "ERC-20 token contracts".into(),
                enforcement: "SafeERC20".into(),
                functions: vec!["swap".into(), "mint".into(), "burn".into()],
            },
            TrustBoundary {
                description: "Price oracle dependency".into(),
                crosses: "External price feeds".into(),
                enforcement: "TWAP oracle, time-weighted average".into(),
                functions: vec!["swap".into()],
            },
        ]
    }

    fn privileged_actors(&self) -> Vec<PrivilegedActor> {
        vec![PrivilegedActor {
            name: "Factory Owner".into(),
            role: "protocol_admin".into(),
            capabilities: vec!["create_pool".into(), "set_fee".into()],
            trust_level: "high".into(),
        }]
    }

    fn attack_surfaces(&self) -> Vec<AttackSurface> {
        vec![
            AttackSurface {
                description: "Flash loan price manipulation".into(),
                vector: "Use flash loan to manipulate reserves, then swap at wrong price".into(),
                required_capabilities: vec!["flash_loan".into(), "large_capital".into()],
                impact: "Drain pool liquidity".into(),
            },
            AttackSurface {
                description: "Sandwich attack".into(),
                vector: "Frontrun victim's swap, backrun at inflated price".into(),
                required_capabilities: vec![
                    "mempool_observation".into(),
                    "transaction_ordering".into(),
                ],
                impact: "Victim receives less tokens".into(),
            },
        ]
    }

    fn exploit_patterns(&self) -> Vec<ExploitPattern> {
        vec![ExploitPattern {
            name: "Flash Loan Price Manipulation".into(),
            description: "Flash loan to manipulate reserves, exploit price-dependent protocol"
                .into(),
            conditions: vec![
                "Flash loan available".into(),
                "Price-dependent logic".into(),
            ],
            outcome: "Profit from manipulated price".into(),
            historical_examples: vec!["bZx".into(), "Pancake Bunny".into()],
        }]
    }
}
