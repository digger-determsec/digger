/// Compound lending protocol pack.
use super::pack::*;

pub struct CompoundPack;

impl ProtocolPack for CompoundPack {
    fn name(&self) -> &str {
        "Compound"
    }
    fn versions(&self) -> &[&str] {
        &["v2", "v3"]
    }
    fn chains(&self) -> &[&str] {
        &["ethereum", "polygon", "arbitrum", "base"]
    }

    fn invariants(&self) -> Vec<ProtocolInvariant> {
        vec![ProtocolInvariant {
            description: "Total supply must equal total borrows + reserves".into(),
            state_vars: vec![
                "totalSupply".into(),
                "totalBorrows".into(),
                "reserves".into(),
            ],
            preserving_functions: vec!["mint".into(), "borrow".into(), "repayBorrow".into()],
            consequence: "Protocol insolvency".into(),
        }]
    }

    fn accounting_rules(&self) -> Vec<AccountingRule> {
        vec![AccountingRule {
            description: "cToken exchange rate increases with interest".into(),
            variables: vec![
                "exchangeRate".into(),
                "totalSupply".into(),
                "totalCash".into(),
                "totalBorrows".into(),
            ],
            relationship: "exchange_rate_formula".into(),
            enforcing_functions: vec!["mint".into(), "redeem".into()],
        }]
    }

    fn lifecycle_phases(&self) -> Vec<LifecyclePhase> {
        vec![
            LifecyclePhase {
                name: "Supply".into(),
                description: "User supplies assets, receives cTokens".into(),
                functions: vec!["mint".into()],
                preconditions: vec!["Market is listed".into()],
                postconditions: vec!["cTokens minted".into(), "Exchange rate updated".into()],
            },
            LifecyclePhase {
                name: "Borrow".into(),
                description: "User borrows against collateral".into(),
                functions: vec!["borrow".into()],
                preconditions: vec!["Sufficient collateral".into()],
                postconditions: vec!["Borrow balance increases".into()],
            },
        ]
    }

    fn trust_boundaries(&self) -> Vec<TrustBoundary> {
        vec![TrustBoundary {
            description: "Oracle price feed".into(),
            crosses: "External oracle".into(),
            enforcement: "Price feed validation".into(),
            functions: vec!["borrow".into(), "liquidateBorrow".into()],
        }]
    }

    fn privileged_actors(&self) -> Vec<PrivilegedActor> {
        vec![PrivilegedActor {
            name: "Comptroller Admin".into(),
            role: "governance".into(),
            capabilities: vec![
                "list_market".into(),
                "pause".into(),
                "set_collateral_factor".into(),
            ],
            trust_level: "high".into(),
        }]
    }

    fn attack_surfaces(&self) -> Vec<AttackSurface> {
        vec![AttackSurface {
            description: "Oracle manipulation".into(),
            vector: "Manipulate price feed to trigger unfair liquidation".into(),
            required_capabilities: vec!["oracle_access".into()],
            impact: "Unfair liquidation".into(),
        }]
    }

    fn exploit_patterns(&self) -> Vec<ExploitPattern> {
        vec![ExploitPattern {
            name: "Oracle Manipulation".into(),
            description: "Manipulate price to trigger liquidation".into(),
            conditions: vec!["Oracle dependency".into()],
            outcome: "Unfair liquidation profit".into(),
            historical_examples: vec!["Cream Finance".into()],
        }]
    }
}
