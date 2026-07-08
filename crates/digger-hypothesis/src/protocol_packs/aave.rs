/// Aave lending protocol pack.
use super::pack::*;

pub struct AavePack;

impl ProtocolPack for AavePack {
    fn name(&self) -> &str {
        "Aave"
    }
    fn versions(&self) -> &[&str] {
        &["v2", "v3"]
    }
    fn chains(&self) -> &[&str] {
        &[
            "ethereum",
            "polygon",
            "arbitrum",
            "optimism",
            "base",
            "avalanche",
        ]
    }

    fn invariants(&self) -> Vec<ProtocolInvariant> {
        vec![
            ProtocolInvariant {
                description: "Total deposits must equal total borrows + reserves".into(),
                state_vars: vec![
                    "totalDeposits".into(),
                    "totalBorrows".into(),
                    "reserves".into(),
                ],
                preserving_functions: vec!["deposit".into(), "borrow".into(), "repay".into()],
                consequence: "Protocol insolvency".into(),
            },
            ProtocolInvariant {
                description: "Collateral ratio must remain above threshold".into(),
                state_vars: vec![
                    "collateral".into(),
                    "debt".into(),
                    "liquidationThreshold".into(),
                ],
                preserving_functions: vec!["borrow".into(), "repay".into(), "liquidate".into()],
                consequence: "Under-collateralized positions".into(),
            },
        ]
    }

    fn accounting_rules(&self) -> Vec<AccountingRule> {
        vec![AccountingRule {
            description: "Interest accrues linearly over time".into(),
            variables: vec!["principal".into(), "interestRate".into(), "time".into()],
            relationship: "compound_interest".into(),
            enforcing_functions: vec!["borrow".into(), "repay".into()],
        }]
    }

    fn lifecycle_phases(&self) -> Vec<LifecyclePhase> {
        vec![
            LifecyclePhase {
                name: "Supply".into(),
                description: "User deposits collateral".into(),
                functions: vec!["supply".into(), "deposit".into()],
                preconditions: vec!["Asset is supported".into()],
                postconditions: vec!["aTokens minted".into(), "Interest accrues".into()],
            },
            LifecyclePhase {
                name: "Borrow".into(),
                description: "User borrows against collateral".into(),
                functions: vec!["borrow".into()],
                preconditions: vec!["Sufficient collateral".into(), "Below borrow cap".into()],
                postconditions: vec!["Debt increases".into(), "Interest accrues".into()],
            },
            LifecyclePhase {
                name: "Liquidation".into(),
                description: "Under-collateralized position is liquidated".into(),
                functions: vec!["liquidationCall".into()],
                preconditions: vec!["Position below liquidation threshold".into()],
                postconditions: vec!["Debt repaid".into(), "Liquidation bonus awarded".into()],
            },
        ]
    }

    fn trust_boundaries(&self) -> Vec<TrustBoundary> {
        vec![TrustBoundary {
            description: "Oracle price feed".into(),
            crosses: "External oracle (Chainlink)".into(),
            enforcement: "Price feed validation, staleness checks".into(),
            functions: vec!["borrow".into(), "liquidationCall".into()],
        }]
    }

    fn privileged_actors(&self) -> Vec<PrivilegedActor> {
        vec![PrivilegedActor {
            name: "Pool Admin".into(),
            role: "governance".into(),
            capabilities: vec!["set_asset".into(), "pause".into(), "set_fee".into()],
            trust_level: "high".into(),
        }]
    }

    fn attack_surfaces(&self) -> Vec<AttackSurface> {
        vec![AttackSurface {
            description: "Oracle manipulation".into(),
            vector: "Manipulate oracle price to trigger unfair liquidation".into(),
            required_capabilities: vec!["oracle_access".into(), "capital".into()],
            impact: "Unfair liquidation, fund theft".into(),
        }]
    }

    fn exploit_patterns(&self) -> Vec<ExploitPattern> {
        vec![ExploitPattern {
            name: "Oracle Manipulation Liquidation".into(),
            description: "Manipulate oracle price to trigger liquidation at wrong price".into(),
            conditions: vec![
                "Oracle dependency".into(),
                "Price manipulation possible".into(),
            ],
            outcome: "Unfair liquidation profit".into(),
            historical_examples: vec!["Mango Markets".into()],
        }]
    }
}
