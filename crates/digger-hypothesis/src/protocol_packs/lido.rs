/// Lido liquid staking protocol pack.
use super::pack::*;

pub struct LidoPack;

impl ProtocolPack for LidoPack {
    fn name(&self) -> &str {
        "Lido"
    }
    fn versions(&self) -> &[&str] {
        &["v1", "v2"]
    }
    fn chains(&self) -> &[&str] {
        &["ethereum"]
    }

    fn invariants(&self) -> Vec<ProtocolInvariant> {
        vec![
            ProtocolInvariant {
                description: "stETH total supply must equal total ETH staked + rewards".into(),
                state_vars: vec!["totalPooledEther".into(), "totalShares".into()],
                preserving_functions: vec![
                    "submit".into(),
                    "withdraw".into(),
                    "claimRewards".into(),
                ],
                consequence: "stETH depeg, fund theft".into(),
            },
            ProtocolInvariant {
                description: "Share price must be non-decreasing over time".into(),
                state_vars: vec!["totalPooledEther".into(), "totalShares".into()],
                preserving_functions: vec!["claimRewards".into()],
                consequence: "Share price manipulation".into(),
            },
        ]
    }

    fn accounting_rules(&self) -> Vec<AccountingRule> {
        vec![AccountingRule {
            description: "stETH = ETH deposited * (totalPooledEther / totalShares)".into(),
            variables: vec![
                "steth".into(),
                "eth".into(),
                "totalPooledEther".into(),
                "totalShares".into(),
            ],
            relationship: "share_price_formula".into(),
            enforcing_functions: vec!["submit".into(), "withdraw".into()],
        }]
    }

    fn lifecycle_phases(&self) -> Vec<LifecyclePhase> {
        vec![
            LifecyclePhase {
                name: "Deposit".into(),
                description: "User deposits ETH, receives stETH".into(),
                functions: vec!["submit".into()],
                preconditions: vec!["Beacon chain active".into()],
                postconditions: vec!["stETH minted".into(), "ETH pooled".into()],
            },
            LifecyclePhase {
                name: "Withdrawal".into(),
                description: "User burns stETH, receives ETH".into(),
                functions: vec!["withdraw".into()],
                preconditions: vec!["Sufficient pooled ETH".into()],
                postconditions: vec!["stETH burned".into(), "ETH released".into()],
            },
        ]
    }

    fn trust_boundaries(&self) -> Vec<TrustBoundary> {
        vec![
            TrustBoundary {
                description: "Beacon chain interaction".into(),
                crosses: "Ethereum 2.0 beacon chain".into(),
                enforcement: "Validator set management, withdrawal credentials".into(),
                functions: vec!["submit".into(), "withdraw".into()],
            },
            TrustBoundary {
                description: "Oracle price feed".into(),
                crosses: "stETH/ETH price oracle".into(),
                enforcement: "TWAP oracle, circuit breaker".into(),
                functions: vec!["submit".into(), "withdraw".into()],
            },
        ]
    }

    fn privileged_actors(&self) -> Vec<PrivilegedActor> {
        vec![
            PrivilegedActor {
                name: "DAO".into(),
                role: "governance".into(),
                capabilities: vec!["set_fee".into(), "add_validator".into(), "pause".into()],
                trust_level: "high".into(),
            },
            PrivilegedActor {
                name: "Oracle".into(),
                role: "price_feed".into(),
                capabilities: vec!["report_prices".into()],
                trust_level: "medium".into(),
            },
        ]
    }

    fn attack_surfaces(&self) -> Vec<AttackSurface> {
        vec![
            AttackSurface {
                description: "stETH depeg attack".into(),
                vector: "Manipulate stETH price via large withdrawals".into(),
                required_capabilities: vec!["large_capital".into(), "oracle_access".into()],
                impact: "stETH depeg, protocol insolvency".into(),
            },
            AttackSurface {
                description: "Validator slashing".into(),
                vector: "Compromise validator keys to cause slashing".into(),
                required_capabilities: vec!["validator_access".into()],
                impact: "Loss of staked ETH".into(),
            },
        ]
    }

    fn exploit_patterns(&self) -> Vec<ExploitPattern> {
        vec![ExploitPattern {
            name: "stETH Depeg".into(),
            description: "Large withdrawals cause stETH to depeg from ETH".into(),
            conditions: vec![
                "Large capital available".into(),
                "Oracle manipulation possible".into(),
            ],
            outcome: "stETH trades below peg".into(),
            historical_examples: vec!["Three Arrows Capital".into()],
        }]
    }
}
