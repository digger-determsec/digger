/// Protocol Semantic Packs — canonical semantic models for protocol families.
///
/// Each pack describes how an entire protocol family behaves, providing
/// reusable semantic knowledge that the reasoning engine can combine
/// with economic relations, verification properties, state transitions,
/// temporal dependencies, capability graphs, evidence graphs, and
/// historical knowledge to reason about novel protocols.
///
/// Packs contain only semantic primitives — no exploit-specific detectors
/// or protocol-specific rules.
use digger_knowledge_models::*;
use serde::{Deserialize, Serialize};

/// A Protocol Semantic Pack — canonical semantic model for a protocol family.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolSemanticPack {
    /// Pack identifier.
    pub pack_id: String,
    /// Protocol domain this pack describes.
    pub domain: ProtocolDomain,
    /// Human-readable description.
    pub description: String,
    /// Canonical security invariants.
    pub security_invariants: Vec<CanonicalInvariant>,
    /// Economic invariants.
    pub economic_invariants: Vec<CanonicalInvariant>,
    /// State machine phases.
    pub state_phases: Vec<StatePhase>,
    /// Lifecycle transitions.
    pub lifecycle_transitions: Vec<LifecycleTransition>,
    /// Trusted actors and their roles.
    pub trusted_actors: Vec<TrustedActor>,
    /// Authority boundaries.
    pub authority_boundaries: Vec<AuthorityBoundary>,
    /// Protocol assumptions.
    pub protocol_assumptions: Vec<ProtocolAssumption>,
    /// Trust assumptions.
    pub trust_assumptions: Vec<TrustAssumption>,
    /// Economic relations.
    pub economic_relations: Vec<CanonicalEconomicRelation>,
    /// Resource lifecycles.
    pub resource_lifecycles: Vec<CanonicalResourceLifecycle>,
    /// Common architectural patterns.
    pub architectural_patterns: Vec<CanonicalArchitecturalPattern>,
}

/// A canonical invariant — a constraint that must hold for the protocol family.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalInvariant {
    /// Invariant identifier.
    pub invariant_id: String,
    /// Invariant description.
    pub description: String,
    /// Invariant kind.
    pub kind: String,
    /// State variables or properties involved.
    pub properties: Vec<String>,
    /// Consequence of violation.
    pub violation_consequence: String,
    /// How this invariant is typically enforced.
    pub enforcement_mechanism: String,
}

/// A state machine phase in a protocol's lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatePhase {
    /// Phase identifier.
    pub phase_id: String,
    /// Phase name.
    pub name: String,
    /// Phase description.
    pub description: String,
    /// Valid transitions from this phase.
    pub valid_transitions: Vec<String>,
    /// Invariants that must hold during this phase.
    pub phase_invariants: Vec<String>,
}

/// A lifecycle transition between phases.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecycleTransition {
    /// Transition identifier.
    pub transition_id: String,
    /// Source phase.
    pub from_phase: String,
    /// Target phase.
    pub to_phase: String,
    /// Trigger condition.
    pub trigger: String,
    /// Pre-conditions that must hold.
    pub preconditions: Vec<String>,
    /// Post-conditions that must hold.
    pub postconditions: Vec<String>,
    /// State changes that occur.
    pub state_changes: Vec<String>,
}

/// A trusted actor in the protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustedActor {
    /// Actor identifier.
    pub actor_id: String,
    /// Actor role.
    pub role: String,
    /// Actor description.
    pub description: String,
    /// Actions this actor can perform.
    pub actions: Vec<String>,
    /// Constraints on this actor.
    pub constraints: Vec<String>,
    /// Trust assumptions about this actor.
    pub trust_assumptions: Vec<String>,
}

/// An authority boundary — who can do what.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityBoundary {
    /// Boundary identifier.
    pub boundary_id: String,
    /// Description.
    pub description: String,
    /// Who has authority.
    pub authorized: Vec<String>,
    /// What they can do.
    pub actions: Vec<String>,
    /// What they cannot do.
    pub restrictions: Vec<String>,
    /// Consequence of boundary violation.
    pub violation_consequence: String,
}

/// A protocol assumption — something the protocol assumes to be true.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolAssumption {
    /// Assumption identifier.
    pub assumption_id: String,
    /// Assumption description.
    pub description: String,
    /// Assumption kind.
    pub kind: AssumptionKind,
    /// Consequence if assumption is violated.
    pub violation_consequence: String,
    /// How the assumption is typically validated.
    pub validation_mechanism: String,
}

/// Kind of protocol assumption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssumptionKind {
    /// Economic assumption (price, liquidity, incentive).
    Economic,
    /// Technical assumption (implementation, compiler, platform).
    Technical,
    /// Trust assumption (actor behavior, oracle reliability).
    Trust,
    /// Temporal assumption (timing, ordering, liveness).
    Temporal,
    /// Composability assumption (external contract behavior).
    Composability,
}

impl std::fmt::Display for AssumptionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Economic => write!(f, "economic"),
            Self::Technical => write!(f, "technical"),
            Self::Trust => write!(f, "trust"),
            Self::Temporal => write!(f, "temporal"),
            Self::Composability => write!(f, "composability"),
        }
    }
}

/// A trust assumption — what the protocol trusts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustAssumption {
    /// Assumption identifier.
    pub assumption_id: String,
    /// What is trusted.
    pub trusted_entity: String,
    /// What is assumed about the entity.
    pub assumption: String,
    /// Consequence if trust is violated.
    pub violation_consequence: String,
    /// How trust is typically verified.
    pub verification_mechanism: String,
}

/// A canonical economic relation for a protocol family.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalEconomicRelation {
    /// Relation identifier.
    pub relation_id: String,
    /// Relation kind.
    pub kind: String,
    /// Description.
    pub description: String,
    /// State variables involved.
    pub state_vars: Vec<String>,
    /// Functions that maintain this relation.
    pub maintaining_functions: Vec<String>,
    /// Consequence of violation.
    pub violation_consequence: String,
}

/// A canonical resource lifecycle for a protocol family.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalResourceLifecycle {
    /// Lifecycle identifier.
    pub lifecycle_id: String,
    /// Resource type.
    pub resource_type: String,
    /// Description.
    pub description: String,
    /// Lifecycle phases.
    pub phases: Vec<String>,
    /// Anomalies that can occur.
    pub anomalies: Vec<String>,
    /// Expected behavior.
    pub expected_behavior: String,
}

/// A canonical architectural pattern for a protocol family.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalArchitecturalPattern {
    /// Pattern identifier.
    pub pattern_id: String,
    /// Pattern name.
    pub name: String,
    /// Pattern description.
    pub description: String,
    /// Known security properties.
    pub security_properties: Vec<String>,
    /// Known risks.
    pub known_risks: Vec<String>,
    /// Best practices.
    pub best_practices: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Pack Registry
// ═══════════════════════════════════════════════════════════════

/// Get all available protocol semantic packs.
pub fn all_packs() -> Vec<ProtocolSemanticPack> {
    vec![
        vault_pack(),
        lending_pack(),
        amm_pack(),
        bridge_pack(),
        liquid_staking_pack(),
        restaking_pack(),
        governance_pack(),
        oracle_pack(),
        stablecoin_pack(),
        perpetuals_pack(),
    ]
}

/// Get a pack by domain.
pub fn pack_for_domain(domain: &ProtocolDomain) -> Option<ProtocolSemanticPack> {
    match domain {
        ProtocolDomain::Vaults => Some(vault_pack()),
        ProtocolDomain::Lending => Some(lending_pack()),
        ProtocolDomain::AMMs => Some(amm_pack()),
        ProtocolDomain::Bridges => Some(bridge_pack()),
        ProtocolDomain::LiquidStaking => Some(liquid_staking_pack()),
        ProtocolDomain::Restaking => Some(restaking_pack()),
        ProtocolDomain::Governance => Some(governance_pack()),
        ProtocolDomain::Oracles => Some(oracle_pack()),
        ProtocolDomain::Stablecoins => Some(stablecoin_pack()),
        ProtocolDomain::Perpetuals => Some(perpetuals_pack()),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════
// Vault Pack (ERC-4626)
// ═══════════════════════════════════════════════════════════════

fn vault_pack() -> ProtocolSemanticPack {
    ProtocolSemanticPack {
        pack_id: "pack:vaults".into(),
        domain: ProtocolDomain::Vaults,
        description: "ERC-4626 tokenized vaults and yield strategies".into(),
        security_invariants: vec![
            CanonicalInvariant {
                invariant_id: "inv:vault:share_asset_ratio".into(),
                description: "Share price must reflect actual asset backing".into(),
                kind: "accounting".into(),
                properties: vec!["totalAssets".into(), "totalSupply".into()],
                violation_consequence: "Share inflation attack, user fund loss".into(),
                enforcement_mechanism: "Virtual share offset, minimum deposit requirement".into(),
            },
            CanonicalInvariant {
                invariant_id: "inv:vault:deposit_mint_consistency".into(),
                description: "deposit() must mint shares proportional to assets deposited".into(),
                kind: "accounting".into(),
                properties: vec!["deposit".into(), "mint".into(), "convertToShares".into()],
                violation_consequence: "Incorrect share issuance, fund loss".into(),
                enforcement_mechanism: "convertToShares with proper rounding".into(),
            },
            CanonicalInvariant {
                invariant_id: "inv:vault:withdraw_redeem_consistency".into(),
                description: "withdraw() must burn proportional shares, redeem() must return proportional assets".into(),
                kind: "accounting".into(),
                properties: vec!["withdraw".into(), "redeem".into(), "convertToAssets".into()],
                violation_consequence: "Incorrect share redemption, fund loss".into(),
                enforcement_mechanism: "convertToAssets with proper rounding".into(),
            },
            CanonicalInvariant {
                invariant_id: "inv:vault:preview_accuracy".into(),
                description: "Preview functions must return values close to actual execution".into(),
                kind: "oracle".into(),
                properties: vec!["previewDeposit".into(), "previewMint".into(), "previewWithdraw".into(), "previewRedeem".into()],
                violation_consequence: "User receives fewer shares/assets than expected".into(),
                enforcement_mechanism: "Preview must be inclusive of fees, exclusive of slippage".into(),
            },
        ],
        economic_invariants: vec![
            CanonicalInvariant {
                invariant_id: "inv:vault:total_value".into(),
                description: "totalAssets() must equal sum of all underlying token balances".into(),
                kind: "conservation".into(),
                properties: vec!["totalAssets".into()],
                violation_consequence: "Vault insolvency".into(),
                enforcement_mechanism: "Accurate balance tracking, fee accounting".into(),
            },
        ],
        state_phases: vec![
            StatePhase {
                phase_id: "vault:active".into(),
                name: "Active".into(),
                description: "Vault accepts deposits and processes withdrawals".into(),
                valid_transitions: vec!["paused".into(), "shutdown".into()],
                phase_invariants: vec!["share_asset_ratio".into()],
            },
            StatePhase {
                phase_id: "vault:paused".into(),
                name: "Paused".into(),
                description: "Deposits blocked, withdrawals may still work".into(),
                valid_transitions: vec!["active".into(), "shutdown".into()],
                phase_invariants: vec![],
            },
            StatePhase {
                phase_id: "vault:shutdown".into(),
                name: "Shutdown".into(),
                description: "All operations blocked, emergency withdrawal only".into(),
                valid_transitions: vec![],
                phase_invariants: vec![],
            },
        ],
        lifecycle_transitions: vec![
            LifecycleTransition {
                transition_id: "vault:deposit_mint".into(),
                from_phase: "active".into(),
                to_phase: "active".into(),
                trigger: "User calls deposit() or mint()".into(),
                preconditions: vec!["User has approved token transfer".into(), "Deposit limit not exceeded".into()],
                postconditions: vec!["Shares minted to receiver".into(), "Assets transferred to vault".into()],
                state_changes: vec!["totalSupply += shares".into(), "asset balance += assets".into()],
            },
            LifecycleTransition {
                transition_id: "vault:withdraw_redeem".into(),
                from_phase: "active".into(),
                to_phase: "active".into(),
                trigger: "User calls withdraw() or redeem()".into(),
                preconditions: vec!["User has sufficient shares".into()],
                postconditions: vec!["Shares burned".into(), "Assets transferred to receiver".into()],
                state_changes: vec!["totalSupply -= shares".into(), "asset balance -= assets".into()],
            },
        ],
        trusted_actors: vec![
            TrustedActor {
                actor_id: "vault:owner".into(),
                role: "Owner".into(),
                description: "Can pause, unpause, and set strategy".into(),
                actions: vec!["pause".into(), "unpause".into(), "setStrategy".into()],
                constraints: vec!["Cannot steal user funds directly".into()],
                trust_assumptions: vec!["Owner acts in good faith".into()],
            },
            TrustedActor {
                actor_id: "vault:strategy".into(),
                role: "Strategy".into(),
                description: "Invests vault assets for yield".into(),
                actions: vec!["invest".into(), "harvest".into(), "withdraw".into()],
                constraints: vec!["Must return assets on demand".into()],
                trust_assumptions: vec!["Strategy is not malicious".into()],
            },
        ],
        authority_boundaries: vec![
            AuthorityBoundary {
                boundary_id: "vault:user_boundary".into(),
                description: "Users can only deposit/withdraw their own shares".into(),
                authorized: vec!["any user".into()],
                actions: vec!["deposit".into(), "mint".into(), "withdraw".into(), "redeem".into()],
                restrictions: vec!["Cannot modify vault parameters".into(), "Cannot access other users' shares".into()],
                violation_consequence: "Unauthorized fund access".into(),
            },
        ],
        protocol_assumptions: vec![
            ProtocolAssumption {
                assumption_id: "vault:underlying_token".into(),
                description: "Underlying token behaves as standard ERC-20".into(),
                kind: AssumptionKind::Composability,
                violation_consequence: "Fee-on-transfer or rebasing tokens break accounting".into(),
                validation_mechanism: "Check token transfer behavior before integration".into(),
            },
            ProtocolAssumption {
                assumption_id: "vault:asset_availability".into(),
                description: "Underlying assets are available for withdrawal".into(),
                kind: AssumptionKind::Economic,
                violation_consequence: "Withdrawal reverts, funds stuck".into(),
                validation_mechanism: "Strategy must maintain liquidity".into(),
            },
        ],
        trust_assumptions: vec![
            TrustAssumption {
                assumption_id: "vault:strategy_trust".into(),
                trusted_entity: "Strategy contract".into(),
                assumption: "Strategy returns assets when asked".into(),
                violation_consequence: "User funds locked in strategy".into(),
                verification_mechanism: "Strategy audit, withdrawal test".into(),
            },
        ],
        economic_relations: vec![
            CanonicalEconomicRelation {
                relation_id: "econ:vault:share_price".into(),
                kind: "dependency".into(),
                description: "Share price depends on totalAssets / totalSupply".into(),
                state_vars: vec!["totalAssets".into(), "totalSupply".into()],
                maintaining_functions: vec!["deposit".into(), "withdraw".into(), "harvest".into()],
                violation_consequence: "Incorrect share valuation".into(),
            },
        ],
        resource_lifecycles: vec![
            CanonicalResourceLifecycle {
                lifecycle_id: "lifecycle:vault:deposit".into(),
                resource_type: "underlying_token".into(),
                description: "Token deposit lifecycle".into(),
                phases: vec!["approval".into(), "transfer_in".into(), "share_mint".into()],
                anomalies: vec!["inflation_attack".into(), "fee_on_transfer".into()],
                expected_behavior: "Assets transfer in, shares minted proportionally".into(),
            },
            CanonicalResourceLifecycle {
                lifecycle_id: "lifecycle:vault:withdraw".into(),
                resource_type: "underlying_token".into(),
                description: "Token withdrawal lifecycle".into(),
                phases: vec!["share_burn".into(), "asset_withdrawal".into(), "transfer_out".into()],
                anomalies: vec!["insufficient_liquidity".into(), "strategy_withdrawal_failure".into()],
                expected_behavior: "Shares burned, assets transferred out proportionally".into(),
            },
        ],
        architectural_patterns: vec![
            CanonicalArchitecturalPattern {
                pattern_id: "arch:vault:erc4626".into(),
                name: "ERC-4626 Vault".into(),
                description: "Standard tokenized vault with share/asset conversion".into(),
                security_properties: vec!["share_asset_ratio".into(), "deposit_mint_consistency".into()],
                known_risks: vec!["inflation_attack".into(), "fee_on_transfer".into(), "preview_manipulation".into()],
                best_practices: vec![
                    "Use virtual share offset to prevent inflation attacks".into(),
                    "Round shares down on deposit, up on withdraw".into(),
                    "Validate underlying token behavior before integration".into(),
                ],
            },
        ],
    }
}

// ═══════════════════════════════════════════════════════════════
// Lending Pack
// ═══════════════════════════════════════════════════════════════

fn lending_pack() -> ProtocolSemanticPack {
    ProtocolSemanticPack {
        pack_id: "pack:lending".into(),
        domain: ProtocolDomain::Lending,
        description: "Lending and borrowing protocols with collateralization".into(),
        security_invariants: vec![
            CanonicalInvariant {
                invariant_id: "inv:lending:solvency".into(),
                description: "Total collateral value must exceed total debt".into(),
                kind: "solvency".into(),
                properties: vec!["totalCollateral".into(), "totalDebt".into()],
                violation_consequence: "Protocol insolvency, user fund loss".into(),
                enforcement_mechanism: "Liquidation mechanism, health factor checks".into(),
            },
            CanonicalInvariant {
                invariant_id: "inv:lending:health_factor".into(),
                description: "Health factor must remain above liquidation threshold".into(),
                kind: "collateralization".into(),
                properties: vec!["healthFactor".into(), "liquidationThreshold".into()],
                violation_consequence: "Position liquidatable, potential bad debt".into(),
                enforcement_mechanism: "Health factor calculation, liquidation triggers".into(),
            },
            CanonicalInvariant {
                invariant_id: "inv:lending:oracle_integrity".into(),
                description: "Price oracle must return accurate, non-manipulable prices".into(),
                kind: "oracle".into(),
                properties: vec!["oracle.price".into()],
                violation_consequence: "Incorrect collateral valuation, bad debt".into(),
                enforcement_mechanism: "TWAP, multiple oracle sources, staleness checks".into(),
            },
        ],
        economic_invariants: vec![CanonicalInvariant {
            invariant_id: "inv:lending:interest_accrual".into(),
            description: "Interest must accrue correctly over time".into(),
            kind: "accounting".into(),
            properties: vec![
                "borrowRate".into(),
                "supplyRate".into(),
                "utilization".into(),
            ],
            violation_consequence: "Incorrect interest, protocol insolvency".into(),
            enforcement_mechanism: "Interest rate model, utilization-based calculation".into(),
        }],
        state_phases: vec![
            StatePhase {
                phase_id: "lending:healthy".into(),
                name: "Healthy".into(),
                description: "Position is above liquidation threshold".into(),
                valid_transitions: vec!["warning".into(), "liquidatable".into()],
                phase_invariants: vec!["health_factor > 1".into()],
            },
            StatePhase {
                phase_id: "lending:liquidatable".into(),
                name: "Liquidatable".into(),
                description: "Position can be liquidated".into(),
                valid_transitions: vec!["healthy".into(), "liquidated".into()],
                phase_invariants: vec!["health_factor <= 1".into()],
            },
        ],
        lifecycle_transitions: vec![
            LifecycleTransition {
                transition_id: "lending:deposit_collateral".into(),
                from_phase: "healthy".into(),
                to_phase: "healthy".into(),
                trigger: "User deposits collateral".into(),
                preconditions: vec!["User has approved token transfer".into()],
                postconditions: vec![
                    "Collateral balance increased".into(),
                    "Health factor improved".into(),
                ],
                state_changes: vec!["collateral[user] += amount".into()],
            },
            LifecycleTransition {
                transition_id: "lending:borrow".into(),
                from_phase: "healthy".into(),
                to_phase: "healthy".into(),
                trigger: "User borrows against collateral".into(),
                preconditions: vec![
                    "Health factor > 1 after borrow".into(),
                    "Sufficient liquidity".into(),
                ],
                postconditions: vec![
                    "Debt balance increased".into(),
                    "Assets transferred to user".into(),
                ],
                state_changes: vec!["debt[user] += amount".into()],
            },
            LifecycleTransition {
                transition_id: "lending:liquidate".into(),
                from_phase: "liquidatable".into(),
                to_phase: "healthy".into(),
                trigger: "Liquidator repays debt for collateral".into(),
                preconditions: vec!["Health factor <= 1".into()],
                postconditions: vec![
                    "Debt reduced".into(),
                    "Collateral transferred to liquidator".into(),
                ],
                state_changes: vec![
                    "debt[user] -= repayAmount".into(),
                    "collateral[user] -= seizedAmount".into(),
                ],
            },
        ],
        trusted_actors: vec![
            TrustedActor {
                actor_id: "lending:oracle".into(),
                role: "Oracle".into(),
                description: "Provides price feeds for collateral valuation".into(),
                actions: vec!["provide_price".into()],
                constraints: vec!["Must be manipulation-resistant".into()],
                trust_assumptions: vec![
                    "Oracle returns accurate prices".into(),
                    "Oracle is not stale".into(),
                ],
            },
            TrustedActor {
                actor_id: "lending:liquidator".into(),
                role: "Liquidator".into(),
                description: "Repays unhealthy positions for collateral".into(),
                actions: vec!["liquidate".into()],
                constraints: vec!["Can only liquidate unhealthy positions".into()],
                trust_assumptions: vec!["Liquidators are economically rational".into()],
            },
        ],
        authority_boundaries: vec![AuthorityBoundary {
            boundary_id: "lending:user_boundary".into(),
            description: "Users can only manage their own positions".into(),
            authorized: vec!["position owner".into()],
            actions: vec![
                "deposit".into(),
                "withdraw".into(),
                "borrow".into(),
                "repay".into(),
            ],
            restrictions: vec!["Cannot modify other users' positions".into()],
            violation_consequence: "Unauthorized position modification".into(),
        }],
        protocol_assumptions: vec![
            ProtocolAssumption {
                assumption_id: "lending:oracle_reliability".into(),
                description: "Oracle prices are accurate and not manipulable".into(),
                kind: AssumptionKind::Trust,
                violation_consequence: "Incorrect collateral valuation, bad debt".into(),
                validation_mechanism: "TWAP, multiple sources, staleness checks".into(),
            },
            ProtocolAssumption {
                assumption_id: "lending:liquidation_incentive".into(),
                description: "Liquidators are incentivized to liquidate unhealthy positions".into(),
                kind: AssumptionKind::Economic,
                violation_consequence: "Bad debt accumulation".into(),
                validation_mechanism: "Liquidation bonus, gas cost analysis".into(),
            },
        ],
        trust_assumptions: vec![TrustAssumption {
            assumption_id: "lending:oracle_trust".into(),
            trusted_entity: "Price oracle".into(),
            assumption: "Returns accurate, timely prices".into(),
            violation_consequence: "Incorrect collateral valuation".into(),
            verification_mechanism: "Oracle audit, TWAP validation".into(),
        }],
        economic_relations: vec![CanonicalEconomicRelation {
            relation_id: "econ:lending:utilization".into(),
            kind: "dependency".into(),
            description: "Interest rate depends on utilization ratio".into(),
            state_vars: vec!["totalBorrow".into(), "totalSupply".into()],
            maintaining_functions: vec![
                "borrow".into(),
                "repay".into(),
                "deposit".into(),
                "withdraw".into(),
            ],
            violation_consequence: "Incorrect interest rate".into(),
        }],
        resource_lifecycles: vec![CanonicalResourceLifecycle {
            lifecycle_id: "lifecycle:lending:collateral".into(),
            resource_type: "collateral_token".into(),
            description: "Collateral deposit and withdrawal lifecycle".into(),
            phases: vec![
                "deposit".into(),
                "lock".into(),
                "liquidation_or_withdrawal".into(),
            ],
            anomalies: vec!["oracle_manipulation".into(), "liquidation_failure".into()],
            expected_behavior: "Collateral locked until debt repaid or liquidated".into(),
        }],
        architectural_patterns: vec![CanonicalArchitecturalPattern {
            pattern_id: "arch:lending:pool".into(),
            name: "Lending Pool".into(),
            description: "Pooled lending with collateralization and liquidation".into(),
            security_properties: vec!["solvency".into(), "health_factor".into()],
            known_risks: vec![
                "oracle_manipulation".into(),
                "bad_debt".into(),
                "liquidation_failure".into(),
            ],
            best_practices: vec![
                "Use TWAP oracles with staleness checks".into(),
                "Implement circuit breakers for extreme conditions".into(),
                "Maintain liquidation incentive".into(),
            ],
        }],
    }
}

// ═══════════════════════════════════════════════════════════════
// AMM Pack
// ═══════════════════════════════════════════════════════════════

fn amm_pack() -> ProtocolSemanticPack {
    ProtocolSemanticPack {
        pack_id: "pack:amms".into(),
        domain: ProtocolDomain::AMMs,
        description: "Automated market makers and liquidity pools".into(),
        security_invariants: vec![
            CanonicalInvariant {
                invariant_id: "inv:amm:constant_product".into(),
                description: "k = x * y must be maintained (for constant product AMMs)".into(),
                kind: "conservation".into(),
                properties: vec!["reserve0".into(), "reserve1".into()],
                violation_consequence: "Pool drained, liquidity loss".into(),
                enforcement_mechanism: "Swap calculation enforces k invariant".into(),
            },
            CanonicalInvariant {
                invariant_id: "inv:amm:fee_accounting".into(),
                description: "Fees must be correctly accounted for in reserves".into(),
                kind: "accounting".into(),
                properties: vec!["reserve0".into(), "reserve1".into(), "fee".into()],
                violation_consequence: "LP value loss, incorrect pricing".into(),
                enforcement_mechanism: "Fee-on-swap, fee accumulation".into(),
            },
        ],
        economic_invariants: vec![CanonicalInvariant {
            invariant_id: "inv:amm:lp_value".into(),
            description: "LP token value must reflect underlying reserves".into(),
            kind: "conservation".into(),
            properties: vec!["totalSupply".into(), "reserve0".into(), "reserve1".into()],
            violation_consequence: "LP token devaluation".into(),
            enforcement_mechanism: "Mint/burn proportional to reserves".into(),
        }],
        state_phases: vec![StatePhase {
            phase_id: "amm:active".into(),
            name: "Active".into(),
            description: "Pool accepts swaps and liquidity operations".into(),
            valid_transitions: vec!["paused".into()],
            phase_invariants: vec!["constant_product".into()],
        }],
        lifecycle_transitions: vec![
            LifecycleTransition {
                transition_id: "amm:swap".into(),
                from_phase: "active".into(),
                to_phase: "active".into(),
                trigger: "User swaps tokens".into(),
                preconditions: vec!["Sufficient liquidity".into()],
                postconditions: vec!["k maintained (after fees)".into()],
                state_changes: vec![
                    "reserve0 +=/-= amount".into(),
                    "reserve1 -=/+= amount".into(),
                ],
            },
            LifecycleTransition {
                transition_id: "amm:add_liquidity".into(),
                from_phase: "active".into(),
                to_phase: "active".into(),
                trigger: "User adds liquidity".into(),
                preconditions: vec!["Tokens approved".into()],
                postconditions: vec!["LP tokens minted".into(), "Reserves increased".into()],
                state_changes: vec![
                    "reserve0 += amount0".into(),
                    "reserve1 += amount1".into(),
                    "totalSupply += shares".into(),
                ],
            },
        ],
        trusted_actors: vec![],
        authority_boundaries: vec![],
        protocol_assumptions: vec![ProtocolAssumption {
            assumption_id: "amm:liquidity".into(),
            description: "Pool has sufficient liquidity for swaps".into(),
            kind: AssumptionKind::Economic,
            violation_consequence: "High slippage, swap failure".into(),
            validation_mechanism: "Check pool reserves before swap".into(),
        }],
        trust_assumptions: vec![],
        economic_relations: vec![CanonicalEconomicRelation {
            relation_id: "econ:amm:price".into(),
            kind: "dependency".into(),
            description: "Price is determined by reserve ratio".into(),
            state_vars: vec!["reserve0".into(), "reserve1".into()],
            maintaining_functions: vec!["swap".into()],
            violation_consequence: "Incorrect price, arbitrage loss".into(),
        }],
        resource_lifecycles: vec![CanonicalResourceLifecycle {
            lifecycle_id: "lifecycle:amm:swap".into(),
            resource_type: "token".into(),
            description: "Token swap lifecycle".into(),
            phases: vec![
                "transfer_in".into(),
                "swap_calculation".into(),
                "transfer_out".into(),
            ],
            anomalies: vec!["sandwich_attack".into(), "slippage_exceeded".into()],
            expected_behavior: "Token in, token out at market price".into(),
        }],
        architectural_patterns: vec![CanonicalArchitecturalPattern {
            pattern_id: "arch:amm:constant_product".into(),
            name: "Constant Product AMM".into(),
            description: "x * y = k pricing model".into(),
            security_properties: vec!["constant_product".into()],
            known_risks: vec![
                "sandwich_attack".into(),
                "impermanent_loss".into(),
                "price_manipulation".into(),
            ],
            best_practices: vec![
                "Implement slippage protection".into(),
                "Use TWAP for external price feeds".into(),
                "Add deadline parameter to swaps".into(),
            ],
        }],
    }
}

// ═══════════════════════════════════════════════════════════════
// Bridge Pack
// ═══════════════════════════════════════════════════════════════

fn bridge_pack() -> ProtocolSemanticPack {
    ProtocolSemanticPack {
        pack_id: "pack:bridges".into(),
        domain: ProtocolDomain::Bridges,
        description: "Cross-chain bridge protocols".into(),
        security_invariants: vec![
            CanonicalInvariant {
                invariant_id: "inv:bridge:lock_mint".into(),
                description:
                    "Tokens locked on source chain must equal tokens minted on destination".into(),
                kind: "conservation".into(),
                properties: vec!["locked_balance".into(), "minted_supply".into()],
                violation_consequence: "Unbacked tokens, bridge insolvency".into(),
                enforcement_mechanism: "Message validation, proof verification".into(),
            },
            CanonicalInvariant {
                invariant_id: "inv:bridge:message_validation".into(),
                description: "Cross-chain messages must be cryptographically validated".into(),
                kind: "authority".into(),
                properties: vec!["message_hash".into(), "signature".into()],
                violation_consequence: "Forged messages, unauthorized minting".into(),
                enforcement_mechanism: "Multi-sig validation, merkle proofs".into(),
            },
        ],
        economic_invariants: vec![],
        state_phases: vec![
            StatePhase {
                phase_id: "bridge:locked".into(),
                name: "Locked".into(),
                description: "Tokens locked on source chain".into(),
                valid_transitions: vec!["minted".into(), "unlocked".into()],
                phase_invariants: vec!["lock_mint".into()],
            },
            StatePhase {
                phase_id: "bridge:minted".into(),
                name: "Minted".into(),
                description: "Wrapped tokens minted on destination chain".into(),
                valid_transitions: vec!["burned".into()],
                phase_invariants: vec!["message_validation".into()],
            },
        ],
        lifecycle_transitions: vec![LifecycleTransition {
            transition_id: "bridge:lock_and_mint".into(),
            from_phase: "locked".into(),
            to_phase: "minted".into(),
            trigger: "User initiates cross-chain transfer".into(),
            preconditions: vec!["Tokens approved".into(), "Message validated".into()],
            postconditions: vec![
                "Tokens locked on source".into(),
                "Wrapped tokens minted on destination".into(),
            ],
            state_changes: vec![
                "locked_balance += amount".into(),
                "minted_supply += amount".into(),
            ],
        }],
        trusted_actors: vec![TrustedActor {
            actor_id: "bridge:validator".into(),
            role: "Validator".into(),
            description: "Validates cross-chain messages".into(),
            actions: vec!["validate_message".into(), "submit_proof".into()],
            constraints: vec!["Must verify message authenticity".into()],
            trust_assumptions: vec!["Validators are honest majority".into()],
        }],
        authority_boundaries: vec![],
        protocol_assumptions: vec![ProtocolAssumption {
            assumption_id: "bridge:validator_honesty".into(),
            description: "Bridge validators are honest majority".into(),
            kind: AssumptionKind::Trust,
            violation_consequence: "Forged messages, fund theft".into(),
            validation_mechanism: "Multi-sig threshold, validator set diversity".into(),
        }],
        trust_assumptions: vec![TrustAssumption {
            assumption_id: "bridge:message_reliability".into(),
            trusted_entity: "Cross-chain messaging layer".into(),
            assumption: "Messages are delivered reliably and in order".into(),
            violation_consequence: "Stuck funds, failed transfers".into(),
            verification_mechanism: "Message validation, timeout mechanisms".into(),
        }],
        economic_relations: vec![],
        resource_lifecycles: vec![CanonicalResourceLifecycle {
            lifecycle_id: "lifecycle:bridge:transfer".into(),
            resource_type: "token".into(),
            description: "Cross-chain token transfer lifecycle".into(),
            phases: vec![
                "lock".into(),
                "message_relay".into(),
                "validation".into(),
                "mint".into(),
            ],
            anomalies: vec![
                "message_forgery".into(),
                "stuck_transfer".into(),
                "double_spend".into(),
            ],
            expected_behavior: "Token locked, message relayed, wrapped token minted".into(),
        }],
        architectural_patterns: vec![CanonicalArchitecturalPattern {
            pattern_id: "arch:bridge:lock_mint".into(),
            name: "Lock and Mint Bridge".into(),
            description: "Lock tokens on source, mint wrapped tokens on destination".into(),
            security_properties: vec!["lock_mint".into(), "message_validation".into()],
            known_risks: vec!["message_forgery".into(), "validator_compromise".into()],
            best_practices: vec![
                "Multi-sig validation with diverse signers".into(),
                "Implement timeout and retry mechanisms".into(),
                "Add circuit breakers for anomalous transfers".into(),
            ],
        }],
    }
}

// ═══════════════════════════════════════════════════════════════
// Remaining packs (stubs — same structure, less detail)
// ═══════════════════════════════════════════════════════════════

fn liquid_staking_pack() -> ProtocolSemanticPack {
    ProtocolSemanticPack {
        pack_id: "pack:liquid_staking".into(),
        domain: ProtocolDomain::LiquidStaking,
        description: "Liquid staking protocols (Lido, Rocket Pool)".into(),
        security_invariants: vec![CanonicalInvariant {
            invariant_id: "inv:lst:share_ratio".into(),
            description: "Staked token value must reflect actual staked ETH".into(),
            kind: "conservation".into(),
            properties: vec!["totalPooledEther".into(), "totalShares".into()],
            violation_consequence: "Incorrect share valuation".into(),
            enforcement_mechanism: "Oracle report, rebase mechanism".into(),
        }],
        economic_invariants: vec![],
        state_phases: vec![],
        lifecycle_transitions: vec![],
        trusted_actors: vec![],
        authority_boundaries: vec![],
        protocol_assumptions: vec![],
        trust_assumptions: vec![],
        economic_relations: vec![],
        resource_lifecycles: vec![],
        architectural_patterns: vec![],
    }
}

fn restaking_pack() -> ProtocolSemanticPack {
    ProtocolSemanticPack {
        pack_id: "pack:restaking".into(),
        domain: ProtocolDomain::Restaking,
        description: "Restaking protocols (EigenLayer, Symbiotic)".into(),
        security_invariants: vec![CanonicalInvariant {
            invariant_id: "inv:restake:slashing".into(),
            description: "Slashing conditions must be verifiable and fair".into(),
            kind: "authority".into(),
            properties: vec!["slashingConditions".into()],
            violation_consequence: "Unjust slashing, fund loss".into(),
            enforcement_mechanism: "Slashing audit, dispute mechanism".into(),
        }],
        economic_invariants: vec![],
        state_phases: vec![],
        lifecycle_transitions: vec![],
        trusted_actors: vec![],
        authority_boundaries: vec![],
        protocol_assumptions: vec![],
        trust_assumptions: vec![],
        economic_relations: vec![],
        resource_lifecycles: vec![],
        architectural_patterns: vec![],
    }
}

fn governance_pack() -> ProtocolSemanticPack {
    ProtocolSemanticPack {
        pack_id: "pack:governance".into(),
        domain: ProtocolDomain::Governance,
        description: "Governance and DAO systems".into(),
        security_invariants: vec![CanonicalInvariant {
            invariant_id: "inv:gov:timelock".into(),
            description: "Governance actions must have timelock delay".into(),
            kind: "temporal".into(),
            properties: vec!["timelock".into()],
            violation_consequence: "Instant execution, no review window".into(),
            enforcement_mechanism: "Timelock contract".into(),
        }],
        economic_invariants: vec![],
        state_phases: vec![],
        lifecycle_transitions: vec![],
        trusted_actors: vec![],
        authority_boundaries: vec![],
        protocol_assumptions: vec![],
        trust_assumptions: vec![],
        economic_relations: vec![],
        resource_lifecycles: vec![],
        architectural_patterns: vec![],
    }
}

fn oracle_pack() -> ProtocolSemanticPack {
    ProtocolSemanticPack {
        pack_id: "pack:oracles".into(),
        domain: ProtocolDomain::Oracles,
        description: "Oracle networks and price feeds".into(),
        security_invariants: vec![CanonicalInvariant {
            invariant_id: "inv:oracle:freshness".into(),
            description: "Price data must be fresh (not stale)".into(),
            kind: "temporal".into(),
            properties: vec!["price".into(), "timestamp".into()],
            violation_consequence: "Stale prices used for critical calculations".into(),
            enforcement_mechanism: "Staleness threshold, heartbeat monitoring".into(),
        }],
        economic_invariants: vec![],
        state_phases: vec![],
        lifecycle_transitions: vec![],
        trusted_actors: vec![],
        authority_boundaries: vec![],
        protocol_assumptions: vec![],
        trust_assumptions: vec![],
        economic_relations: vec![],
        resource_lifecycles: vec![],
        architectural_patterns: vec![],
    }
}

fn stablecoin_pack() -> ProtocolSemanticPack {
    ProtocolSemanticPack {
        pack_id: "pack:stablecoins".into(),
        domain: ProtocolDomain::Stablecoins,
        description: "Stablecoins and pegged assets".into(),
        security_invariants: vec![CanonicalInvariant {
            invariant_id: "inv:stable:peg".into(),
            description: "Stablecoin must maintain peg to target asset".into(),
            kind: "economic".into(),
            properties: vec!["price".into(), "target_price".into()],
            violation_consequence: "Depeg, user fund loss".into(),
            enforcement_mechanism: "Peg stability mechanism, redemption right".into(),
        }],
        economic_invariants: vec![],
        state_phases: vec![],
        lifecycle_transitions: vec![],
        trusted_actors: vec![],
        authority_boundaries: vec![],
        protocol_assumptions: vec![],
        trust_assumptions: vec![],
        economic_relations: vec![],
        resource_lifecycles: vec![],
        architectural_patterns: vec![],
    }
}

fn perpetuals_pack() -> ProtocolSemanticPack {
    ProtocolSemanticPack {
        pack_id: "pack:perpetuals".into(),
        domain: ProtocolDomain::Perpetuals,
        description: "Perpetual futures protocols".into(),
        security_invariants: vec![CanonicalInvariant {
            invariant_id: "inv:perp:funding".into(),
            description: "Funding rate must converge price to index".into(),
            kind: "economic".into(),
            properties: vec![
                "fundingRate".into(),
                "indexPrice".into(),
                "markPrice".into(),
            ],
            violation_consequence: "Price divergence, unfair liquidation".into(),
            enforcement_mechanism: "Funding rate calculation, oracle integration".into(),
        }],
        economic_invariants: vec![],
        state_phases: vec![],
        lifecycle_transitions: vec![],
        trusted_actors: vec![],
        authority_boundaries: vec![],
        protocol_assumptions: vec![],
        trust_assumptions: vec![],
        economic_relations: vec![],
        resource_lifecycles: vec![],
        architectural_patterns: vec![],
    }
}

/// Serialize a pack to JSON.
pub fn pack_to_json(pack: &ProtocolSemanticPack) -> String {
    serde_json::to_string_pretty(pack).unwrap_or_else(|_| "{}".into())
}
