/// ERC-4626 Tokenized Vault Standard pack.
use super::pack::*;

pub struct Erc4626Pack;

impl ProtocolPack for Erc4626Pack {
    fn name(&self) -> &str {
        "ERC-4626"
    }
    fn versions(&self) -> &[&str] {
        &["1.0"]
    }
    fn chains(&self) -> &[&str] {
        &["ethereum", "polygon", "arbitrum", "optimism", "base"]
    }

    fn invariants(&self) -> Vec<ProtocolInvariant> {
        vec![
            ProtocolInvariant {
                description: "Total assets must equal sum of all share balances * exchange rate"
                    .into(),
                state_vars: vec!["totalAssets".into(), "totalSupply".into()],
                preserving_functions: vec![
                    "deposit".into(),
                    "withdraw".into(),
                    "mint".into(),
                    "redeem".into(),
                ],
                consequence: "Share price manipulation, infinite minting".into(),
            },
            ProtocolInvariant {
                description: "Shares minted must be proportional to assets deposited".into(),
                state_vars: vec!["totalAssets".into(), "totalSupply".into()],
                preserving_functions: vec!["deposit".into(), "mint".into()],
                consequence: "Share dilution, unfair deposit/withdrawal".into(),
            },
        ]
    }

    fn accounting_rules(&self) -> Vec<AccountingRule> {
        vec![
            AccountingRule {
                description: "Deposit: shares = assets * totalSupply / totalAssets".into(),
                variables: vec![
                    "shares".into(),
                    "assets".into(),
                    "totalSupply".into(),
                    "totalAssets".into(),
                ],
                relationship: "proportional".into(),
                enforcing_functions: vec!["deposit".into(), "mint".into()],
            },
            AccountingRule {
                description: "Withdraw: assets = shares * totalAssets / totalSupply".into(),
                variables: vec![
                    "assets".into(),
                    "shares".into(),
                    "totalAssets".into(),
                    "totalSupply".into(),
                ],
                relationship: "proportional".into(),
                enforcing_functions: vec!["withdraw".into(), "redeem".into()],
            },
        ]
    }

    fn lifecycle_phases(&self) -> Vec<LifecyclePhase> {
        vec![
            LifecyclePhase {
                name: "Deposit".into(),
                description: "User deposits assets, receives shares".into(),
                functions: vec!["deposit".into(), "mint".into()],
                preconditions: vec![
                    "Vault is initialized".into(),
                    "Asset token is approved".into(),
                ],
                postconditions: vec!["Shares minted".into(), "Total assets increased".into()],
            },
            LifecyclePhase {
                name: "Withdrawal".into(),
                description: "User burns shares, receives assets".into(),
                functions: vec!["withdraw".into(), "redeem".into()],
                preconditions: vec![
                    "User has shares".into(),
                    "Vault has sufficient assets".into(),
                ],
                postconditions: vec!["Shares burned".into(), "Total assets decreased".into()],
            },
        ]
    }

    fn trust_boundaries(&self) -> Vec<TrustBoundary> {
        vec![
            TrustBoundary {
                description: "Asset token transfer".into(),
                crosses: "ERC-20 token contract".into(),
                enforcement: "SafeERC20 transferFrom/transfer".into(),
                functions: vec![
                    "deposit".into(),
                    "withdraw".into(),
                    "mint".into(),
                    "redeem".into(),
                ],
            },
            TrustBoundary {
                description: "Fee-on-transfer tokens".into(),
                crosses: "Non-standard ERC-20 behavior".into(),
                enforcement: "Account for transfer fees in deposit/withdraw calculations".into(),
                functions: vec!["deposit".into(), "withdraw".into()],
            },
        ]
    }

    fn privileged_actors(&self) -> Vec<PrivilegedActor> {
        vec![PrivilegedActor {
            name: "Vault Admin".into(),
            role: "administrator".into(),
            capabilities: vec![
                "pause".into(),
                "set_fee".into(),
                "set_withdrawal_queue".into(),
            ],
            trust_level: "high".into(),
        }]
    }

    fn attack_surfaces(&self) -> Vec<AttackSurface> {
        vec![
            AttackSurface {
                description: "First depositor inflation attack".into(),
                vector: "Donate assets to inflate share price".into(),
                required_capabilities: vec!["initial_deposit".into(), "asset_donation".into()],
                impact: "Subsequent depositors lose funds".into(),
            },
            AttackSurface {
                description: "Asset mismatch".into(),
                vector: "Vault reports different asset than actual token".into(),
                required_capabilities: vec!["asset_verification".into()],
                impact: "Deposits accepted for wrong token".into(),
            },
        ]
    }

    fn exploit_patterns(&self) -> Vec<ExploitPattern> {
        vec![
            ExploitPattern {
                name: "Inflation Attack".into(),
                description: "First depositor donates assets to inflate share price".into(),
                conditions: vec!["totalSupply == 0".into(), "asset donation possible".into()],
                outcome: "Subsequent depositors receive 0 shares".into(),
                historical_examples: vec!["Qubit Finance".into(), "Pancake Bunny".into()],
            },
            ExploitPattern {
                name: "Asset Swapping".into(),
                description: "Vault accepts different asset than expected".into(),
                conditions: vec!["asset parameter not validated".into()],
                outcome: "User deposits wrong token".into(),
                historical_examples: vec![],
            },
        ]
    }
}
