/// Morpho lending optimization protocol pack.
use super::pack::*;

pub struct MorphoPack;

impl ProtocolPack for MorphoPack {
    fn name(&self) -> &str {
        "Morpho"
    }
    fn versions(&self) -> &[&str] {
        &["v1", "v2", "blue"]
    }
    fn chains(&self) -> &[&str] {
        &["ethereum"]
    }

    fn invariants(&self) -> Vec<ProtocolInvariant> {
        vec![
            ProtocolInvariant {
                description: "Peer-to-peer matching must not create bad debt".into(),
                state_vars: vec!["peer_to_peer_supply".into(), "peer_to_peer_borrow".into()],
                preserving_functions: vec!["supply".into(), "borrow".into(), "withdraw".into()],
                consequence: "Bad debt, protocol insolvency".into(),
            },
            ProtocolInvariant {
                description: "Interest rate model must converge to market rate".into(),
                state_vars: vec!["utilization".into(), "interest_rate".into()],
                preserving_functions: vec!["supply".into(), "borrow".into()],
                consequence: "Incorrect interest accrual".into(),
            },
        ]
    }

    fn accounting_rules(&self) -> Vec<AccountingRule> {
        vec![AccountingRule {
            description: "P2P matching rate must be >= market rate for both parties".into(),
            variables: vec!["p2p_rate".into(), "market_rate".into()],
            relationship: "p2p_rate_geq_market".into(),
            enforcing_functions: vec!["supply".into(), "borrow".into()],
        }]
    }

    fn lifecycle_phases(&self) -> Vec<LifecyclePhase> {
        vec![LifecyclePhase {
            name: "P2P Matching".into(),
            description: "Match supply and borrow positions peer-to-peer".into(),
            functions: vec!["supply".into(), "borrow".into()],
            preconditions: vec![
                "Sufficient supply".into(),
                "Sufficient borrow demand".into(),
            ],
            postconditions: vec!["P2P position created".into(), "Interest rate set".into()],
        }]
    }

    fn trust_boundaries(&self) -> Vec<TrustBoundary> {
        vec![TrustBoundary {
            description: "Underlying protocol interaction".into(),
            crosses: "Aave/Compound lending pools".into(),
            enforcement: "Rate comparison, fallback to market".into(),
            functions: vec!["supply".into(), "borrow".into()],
        }]
    }

    fn privileged_actors(&self) -> Vec<PrivilegedActor> {
        vec![PrivilegedActor {
            name: "Governance".into(),
            role: "admin".into(),
            capabilities: vec!["set_interest_model".into(), "pause".into()],
            trust_level: "high".into(),
        }]
    }

    fn attack_surfaces(&self) -> Vec<AttackSurface> {
        vec![AttackSurface {
            description: "Interest rate manipulation".into(),
            vector: "Manipulate utilization to force unfavorable rates".into(),
            required_capabilities: vec!["large_capital".into()],
            impact: "Users receive suboptimal interest rates".into(),
        }]
    }

    fn exploit_patterns(&self) -> Vec<ExploitPattern> {
        vec![ExploitPattern {
            name: "Rate Manipulation".into(),
            description: "Manipulate utilization to force unfavorable P2P rates".into(),
            conditions: vec![
                "Large capital".into(),
                "Utilization manipulation possible".into(),
            ],
            outcome: "Suboptimal interest rates for users".into(),
            historical_examples: vec![],
        }]
    }
}
