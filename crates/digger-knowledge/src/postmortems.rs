/// Exploit Postmortem parser — ingests real-world exploit writeups.
///
/// Parses structured exploit documents into NormalizedKnowledge.
/// Each postmortem represents a confirmed, real-world vulnerability
/// with verified impact and actual attack paths.
///
/// This is the highest-signal knowledge source because it contains
/// verified vulnerabilities with confirmed consequences.
use digger_knowledge_models::*;

/// Ingest a structured exploit postmortem.
#[allow(clippy::too_many_arguments)]
pub fn ingest_postmortem(
    title: &str,
    protocol: &str,
    vulnerability_type: &str,
    severity: &str,
    root_cause: &str,
    impact: &str,
    description: &str,
    fix: &str,
    source_url: &str,
) -> NormalizedKnowledge {
    let vuln_class = classify_vulnerability(vulnerability_type, description);
    let attack_goal = super::normalizer::map_to_attack_goal(&vuln_class);
    let root_cause_class = classify_root_cause(root_cause, description);
    let sev = parse_severity(severity);
    let sev_clone = sev.clone();
    let root_cause_clone = root_cause_class.to_string();

    let finding = NormalizedFinding {
        finding_id: compute_finding_id(protocol, title),
        original_finding_id: title.to_string(),
        report_id: format!("postmortem:{}", protocol.to_lowercase().replace(' ', "-")),
        protocol_name: protocol.to_string(),
        protocol_category: classify_protocol_category(description),
        protocol_domain: classify_postmortem_domain(description),
        protocol_pattern: None,
        vulnerability_class: vuln_class.clone(),
        attack_goal: attack_goal.clone(),
        capability_pattern: super::normalizer::infer_capabilities(&vuln_class),
        violated_invariant: super::normalizer::infer_violated_invariant(&vuln_class),
        attack_technique: infer_attack_technique(vulnerability_type, description),
        mitigation_pattern: super::normalizer::infer_mitigation_pattern(&vuln_class),
        security_assumptions: extract_assumptions(description),
        severity: sev,
        root_cause: root_cause_class,
        impact_text: impact.to_string(),
        description_text: description.to_string(),
        remediation_text: fix.to_string(),
        impacted_contracts: vec![],
        impacted_functions: vec![],
        confidence: 1.0,
    };

    let evidence = vec![KnowledgeEvidence {
        evidence_id: format!(
            "ev:postmortem:{}",
            protocol.to_lowercase().replace(' ', "-")
        ),
        kind: KnowledgeEvidenceKind::HistoricalFinding(HistoricalFindingEvidence {
            finding_id: finding.finding_id.clone(),
            protocol_name: protocol.to_string(),
            vulnerability_class: vuln_class.to_string(),
            attack_goal,
            root_cause: root_cause_clone,
            severity: sev_clone,
            impacted_functions: vec![],
        }),
        description: format!("Confirmed exploit: {} — {}", protocol, title),
        confidence: KnowledgeConfidence {
            support_count: 1,
            confidence_level: "verified".into(),
            first_seen: None,
            last_seen: None,
            contributing_sources: vec![source_url.to_string()],
        },
        source: source_url.to_string(),
        related_findings: vec![finding.finding_id.clone()],
    }];

    NormalizedKnowledge {
        knowledge_id: format!(
            "knowledge:postmortem:{}",
            protocol.to_lowercase().replace(' ', "-")
        ),
        source_id: "exploit_postmortem".into(),
        source_kind: KnowledgeSourceKind::ExploitPostmortem,
        source_identifier: source_url.to_string(),
        subject: protocol.to_string(),
        subject_category: classify_protocol_category(description).to_string(),
        findings: vec![finding],
        evidence,
        invariants: extract_invariants(description),
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![KnowledgeReference {
            reference_id: source_url.to_string(),
            kind: ReferenceKind::BlogPost,
            description: format!("Exploit postmortem: {}", title),
        }],
        claims: vec![SecurityClaim {
            claim_id: format!("claim:{}", protocol.to_lowercase().replace(' ', "-")),
            claim: format!("{} is vulnerable to {}", protocol, vulnerability_type),
            kind: ClaimKind::VulnerabilityExists,
            confidence: ClaimConfidence::Verified,
            evidence: vec![impact.to_string()],
            context: description.to_string(),
        }],
        raw_sections: std::collections::BTreeMap::new(),
    }
}

fn classify_vulnerability(vuln_type: &str, description: &str) -> VulnerabilityClass {
    let text = format!("{} {}", vuln_type, description).to_lowercase();

    if text.contains("signature verification")
        || text.contains("signature bypass")
        || text.contains("account validation")
    {
        return VulnerabilityClass::MissingAccessControl;
    }
    if text.contains("inflation")
        || text.contains("infinite spend")
        || text.contains("token duplication")
    {
        return VulnerabilityClass::IntegerOverflow;
    }
    if text.contains("proof verification")
        || text.contains("insufficient proof")
        || text.contains("unconstrained witness")
    {
        return VulnerabilityClass::InvariantViolation;
    }
    if text.contains("re-initialization")
        || text.contains("reinitialization")
        || text.contains("proxy") && text.contains("initialize")
    {
        return VulnerabilityClass::ProxyInitialization;
    }
    if text.contains("selfdestruct") || text.contains("self-destruct") || text.contains("suicide") {
        return VulnerabilityClass::Reentrancy;
    }
    if text.contains("delegatecall") || text.contains("delegate call") {
        return VulnerabilityClass::ComposabilityRisk;
    }
    if text.contains("front-run") || text.contains("frontrun") || text.contains("front run") {
        return VulnerabilityClass::FrontRunning;
    }
    if text.contains("code existence")
        || text.contains("code check")
        || text.contains("empty address")
    {
        return VulnerabilityClass::MissingValidation;
    }
    if text.contains("checkpoint")
        || text.contains("pn l")
        || text.contains("pnl")
        || text.contains("loss tracking")
    {
        return VulnerabilityClass::InvariantViolation;
    }
    if text.contains("social engineering")
        || text.contains("multisig")
        || text.contains("key compromise")
    {
        return VulnerabilityClass::MissingAccessControl;
    }
    if text.contains("cross-chain") || text.contains("bridge") || text.contains("cross chain") {
        return VulnerabilityClass::ComposabilityRisk;
    }
    if text.contains("storage") && text.contains("slot") {
        return VulnerabilityClass::StorageCollision;
    }
    if text.contains("timelock") {
        return VulnerabilityClass::TimelockBypass;
    }
    if text.contains("oracle") || text.contains("price manipulation") {
        return VulnerabilityClass::OracleManipulation;
    }
    if text.contains("gas optimization") || text.contains("removed check") {
        return VulnerabilityClass::MissingValidation;
    }

    VulnerabilityClass::Other(vuln_type.to_string())
}

fn classify_root_cause(root_cause: &str, description: &str) -> StructuralRootCause {
    let text = format!("{} {}", root_cause, description).to_lowercase();

    if text.contains("unconstrained witness")
        || text.contains("no constraint")
        || text.contains("without imposing")
    {
        return StructuralRootCause::UnvalidatedExternalInput;
    }
    if text.contains("bypass") || text.contains("not updated") || text.contains("missing redirect")
    {
        return StructuralRootCause::MissingAuthorityCheck;
    }
    if text.contains("storage slot") || text.contains("storage wiping") || text.contains("wiped") {
        return StructuralRootCause::UnsafeComposition;
    }
    if text.contains("gas optimization") || text.contains("removed") && text.contains("check") {
        return StructuralRootCause::MissingBoundaryCheck;
    }
    if text.contains("code existence")
        || text.contains("code check")
        || text.contains("empty address")
    {
        return StructuralRootCause::UnvalidatedExternalInput;
    }
    if text.contains("debt basis") || text.contains("pn l") || text.contains("loss tracking") {
        return StructuralRootCause::IncorrectInvariantAssumption;
    }
    if text.contains("social engineering") || text.contains("device compromise") {
        return StructuralRootCause::MissingAuthorityCheck;
    }
    if text.contains("timelock") && text.contains("removed") {
        return StructuralRootCause::MissingAuthorityCheck;
    }
    if text.contains("load_instruction_at") || text.contains("sysvar") {
        return StructuralRootCause::UnvalidatedExternalInput;
    }
    if text.contains("delegatecall") {
        return StructuralRootCause::UnsafeComposition;
    }

    StructuralRootCause::Other(root_cause.to_string())
}

fn infer_attack_technique(vuln_type: &str, description: &str) -> AttackTechnique {
    let text = format!("{} {}", vuln_type, description).to_lowercase();

    if text.contains("selfdestruct") || text.contains("self-destruct") {
        return AttackTechnique::ReentrancyExploit;
    }
    if text.contains("delegatecall") {
        return AttackTechnique::DelegatecallExploitation;
    }
    if text.contains("front-run") || text.contains("frontrun") {
        return AttackTechnique::FrontRunningTransaction;
    }
    if text.contains("signature") || text.contains("signature verification") {
        return AttackTechnique::AccessControlBypass;
    }
    if text.contains("proxy") || text.contains("re-initialization") {
        return AttackTechnique::StorageCollisionExploit;
    }
    if text.contains("inflation") || text.contains("infinite spend") {
        return AttackTechnique::PrecisionLossExploitation;
    }
    if text.contains("social engineering") || text.contains("multisig") {
        return AttackTechnique::AccessControlBypass;
    }
    if text.contains("oracle") || text.contains("price") {
        return AttackTechnique::PriceOracleManipulation;
    }

    AttackTechnique::Other(vuln_type.to_string())
}

fn extract_assumptions(description: &str) -> Vec<SecurityAssumption> {
    let mut assumptions = Vec::new();
    let lower = description.to_lowercase();

    if lower.contains("assumes") || lower.contains("assumption") {
        assumptions.push(SecurityAssumption {
            assumption: "Protocol assumes correct external behavior".into(),
            is_valid: false,
            violated_by: Some("exploit".into()),
        });
    }
    if lower.contains("trusted") || lower.contains("trust") {
        assumptions.push(SecurityAssumption {
            assumption: "Protocol trusts external actors".into(),
            is_valid: false,
            violated_by: Some("exploit".into()),
        });
    }
    if lower.contains("bypass") || lower.contains("without checking") {
        assumptions.push(SecurityAssumption {
            assumption: "Protocol assumes validation is sufficient".into(),
            is_valid: false,
            violated_by: Some("exploit".into()),
        });
    }

    assumptions
}

fn extract_invariants(description: &str) -> Vec<SecurityInvariant> {
    let mut invariants = Vec::new();
    let lower = description.to_lowercase();

    if lower.contains("balance") || lower.contains("token") {
        invariants.push(SecurityInvariant {
            invariant_id: "inv:balance_conservation".into(),
            description: "Token balances must be conserved".into(),
            kind: "conservation".into(),
            properties: vec![],
            is_violated: true,
            context: "exploit".into(),
        });
    }
    if lower.contains("signature") || lower.contains("verify") {
        invariants.push(SecurityInvariant {
            invariant_id: "inv:signature_validity".into(),
            description: "Signatures must be cryptographically valid".into(),
            kind: "authority".into(),
            properties: vec![],
            is_violated: true,
            context: "exploit".into(),
        });
    }
    if lower.contains("bridge") || lower.contains("cross-chain") {
        invariants.push(SecurityInvariant {
            invariant_id: "inv:bridge_integrity".into(),
            description: "Cross-chain messages must be authenticated".into(),
            kind: "authority".into(),
            properties: vec![],
            is_violated: true,
            context: "exploit".into(),
        });
    }

    invariants
}

fn classify_protocol_category(description: &str) -> ProtocolCategory {
    let lower = description.to_lowercase();
    if lower.contains("bridge")
        || lower.contains("cross-chain")
        || lower.contains("wormhole")
        || lower.contains("axelar")
    {
        return ProtocolCategory::Bridge;
    }
    if lower.contains("lending") || lower.contains("borrow") || lower.contains("collateral") {
        return ProtocolCategory::Lending;
    }
    if lower.contains("dex")
        || lower.contains("swap")
        || lower.contains("amm")
        || lower.contains("balancer")
    {
        return ProtocolCategory::DEX;
    }
    if lower.contains("rollup")
        || lower.contains("layer 2")
        || lower.contains("l2")
        || lower.contains("optimism")
        || lower.contains("arbitrum")
    {
        return ProtocolCategory::Infrastructure;
    }
    if lower.contains("perp")
        || lower.contains("perpetual")
        || lower.contains("futures")
        || lower.contains("drift")
    {
        return ProtocolCategory::Perps;
    }
    if lower.contains("yield") || lower.contains("staking") || lower.contains("tokemak") {
        return ProtocolCategory::Yield;
    }
    if lower.contains("vault") || lower.contains("strategy") || lower.contains("tranchess") {
        return ProtocolCategory::Vault;
    }
    if lower.contains("zk") || lower.contains("zero knowledge") || lower.contains("proof") {
        return ProtocolCategory::Infrastructure;
    }
    ProtocolCategory::Unknown
}

fn classify_postmortem_domain(description: &str) -> ProtocolDomain {
    let lower = description.to_lowercase();
    if lower.contains("bridge") || lower.contains("cross-chain") || lower.contains("wormhole") {
        return ProtocolDomain::Bridges;
    }
    if lower.contains("lending") || lower.contains("borrow") || lower.contains("collateral") {
        return ProtocolDomain::Lending;
    }
    if lower.contains("amm") || lower.contains("swap") || lower.contains("liquidity pool") {
        return ProtocolDomain::AMMs;
    }
    if lower.contains("vault") || lower.contains("share price") {
        return ProtocolDomain::Vaults;
    }
    if lower.contains("oracle") || lower.contains("price feed") {
        return ProtocolDomain::Oracles;
    }
    if lower.contains("governance") || lower.contains("voting") || lower.contains("timelock") {
        return ProtocolDomain::Governance;
    }
    if lower.contains("rollup") || lower.contains("layer 2") || lower.contains("l2") {
        return ProtocolDomain::Generic;
    }
    if lower.contains("perp") || lower.contains("perpetual") || lower.contains("futures") {
        return ProtocolDomain::Perpetuals;
    }
    if lower.contains("stablecoin") || lower.contains("peg") {
        return ProtocolDomain::Stablecoins;
    }
    if lower.contains("staking") || lower.contains("liquid staking") {
        return ProtocolDomain::LiquidStaking;
    }
    ProtocolDomain::Generic
}

fn parse_severity(severity: &str) -> digger_ir::Severity {
    let lower = severity.to_lowercase();
    if lower.contains("critical") {
        digger_ir::Severity::Critical
    } else if lower.contains("high") {
        digger_ir::Severity::High
    } else if lower.contains("medium") {
        digger_ir::Severity::Medium
    } else if lower.contains("low") {
        digger_ir::Severity::Low
    } else {
        digger_ir::Severity::Info
    }
}

fn compute_finding_id(protocol: &str, title: &str) -> String {
    let mut h: u64 = 0;
    for byte in protocol.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    for byte in title.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    format!("postmortem:{:x}", h)
}

/// Type alias for postmortem tuples: (title, protocol, vuln_type, severity, root_cause, impact, description, fix, url).
pub type PostmortemTuple = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

/// All known exploit postmortems ingested into the knowledge base.
pub fn all_postmortems() -> Vec<PostmortemTuple> {
    vec![
        // ── Original 9 ──
        ("zkSync Insufficient Proof Verification", "zkSync Lite", "Insufficient Proof Verification / Unconstrained Witness in ZK Circuit",
         "Critical", "Unconstrained witness in ZK circuit allows arbitrary mantissa values",
         "Unauthorized minting, freezing, transferring of tokens",
         "The parse_with_exponent_le function used AllocatedNum::alloc without constraining the witness value",
         "Replaced AllocatedNum::alloc with into_allocated_num that enforces constraints",
         "https://medium.com/immunefi/zksync-insufficient-proof-verification-bugfix-review-dcd57944d0e2"),
        ("Optimism SELFDESTRUCT Inflation Bug", "Optimism", "Inflation bug via improper balance handling during SELFDESTRUCT",
         "Critical", "SELFDESTRUCT opcode bypasses OVM balance redirection, duplicating tokens",
         "Unbounded token creation, economic disruption",
         "OVM stores ETH in OVM_ETH storage, but StateDB.Suicide directly clears stateObject.data.Balance without OVM redirect",
         "Added SubBalance call in opSuicide for OVM chains",
         "https://www.saurik.com/optimism.html"),
        ("Arbitrum DelayedInbox Re-initialization", "Arbitrum", "Re-initialization of upgradeable proxy due to storage slot wiping",
         "Critical", "postUpgradeInit wipes storage slots, removing initializer guard",
         "Loss of all bridged ETH deposits (up to 168,000 ETH per deposit)",
         "postUpgradeInit wiped slots 0,1,2 and set bridge/allowListEnabled to new values, but left boolean flags empty",
         "Ensured storage slots preserved during upgrade initialization",
         "https://medium.com/@0xriptide/hackers-in-arbitrums-inbox-ca23272641a2"),
        ("Aurora Infinite Spend", "Aurora", "Infinite Spend / Inflation Bug via DELEGATECALL",
         "Critical", "DELEGATECALL to ExitToNear triggers exit event without actual ETH transfer",
         "Direct loss of 70k ETH and $200M in other assets",
         "Exit logic only verified LOG event from ExitToNear address and assumed msg.value > 0 meant ETH was deposited",
         "Returned exit error if address does not match inputs, disabling DELEGATECALL",
         "https://medium.com/immunefi/aurora-infinite-spend-bugfix-review-6m-payout-e635d24273d"),
        ("Tranchess ShareStaking Checkpoint", "Tranchess", "Logic flaw / Accounting bypass in _checkpoint()",
         "Critical", "Checkpoint skip during rebalance causes mismatch between tracked and actual balances",
         "Up to 815.1 BTC and 1438.5 ETH on BSC",
         "_checkpoint() has early-return if already called in same block. Attacker calls claimableRewards() to invoke _checkpoint() early",
         "Persistent loss accumulator or reference price mechanism",
         "https://github.com/floranguyen0/tranchess-vulnerability-disclosure"),
        ("Balancer V2 Token Frontrun", "Balancer V2", "Front-running ERC20 deployments to create infinite balances",
         "Critical", "Removing code-existence check from SafeERC20 allows phantom deposits",
         "Up to $120M extraction from $800M TVL",
         "Balancer removed OpenZeppelins code-existence check as gas optimization. safeTransferFrom to non-existent contract returns success",
         "Restore code-existence check in safe transfer library",
         "https://paragraph.com/@kankodu/million-dollar-bugs-and-where-to-find-them"),
        ("Wormhole Signature Verification Bypass", "Wormhole", "Signature verification bypass / Account validation failure",
         "Critical", "load_instruction_at does not verify sysvar account address",
         "$324 million in stolen crypto-assets",
         "verify_signatures used load_instruction_at which does not check if input sysvar account is the real sysvar",
         "Validate instruction sysvar account address matches legitimate Solana sysvar",
         "https://kudelskisecurity.com/research/quick-analysis-of-the-wormhole-attack"),
        ("Tokemak DV PnL Tracking", "Tokemak", "Logic Flaw / Incorrect PnL Tracking in Destination Vault",
         "High", "Rebalancing resets debt basis, erasing accumulated losses",
         "DV incorrectly marked as not in loss, allowing users to extract full value",
         "Loss detection compares currentDvDebtValue against updatedDebtBasis. When rebalancing resets debt basis, system no longer recognizes prior loss",
         "Persistent loss accumulator that only clears when LP token price appreciates",
         "https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/589"),
        ("Drift Protocol Multisig Compromise", "Drift Protocol", "Operational security failure via social engineering and multisig compromise",
         "Critical", "Social engineering plus device compromise plus weak multisig plus removed timelock",
         "$285 million drained in 12 minutes, $22M+ downstream losses",
         "Attackers posed as quant firm, built trust over 6 months, compromised 2 contributor devices via malware, obtained pre-signed multisig approvals",
         "24-48 hour timelock, 3-of-5 multisig threshold, dedicated signing devices",
         "https://nexusmutual.io/blog/drift-protocol-incident-report"),
        // ── Second batch (rekt.news) ──
        ("Euler Finance Donation Attack", "Euler Finance", "Flawed donation mechanism lacking health check validation",
         "Critical", "donateToReserves does not check health of user position, allowing unbacked DToken debt",
         "$197M drained, cascading losses to Angle, Balancer, Temple DAO",
         "Attacker used flash loans to create underwater position via donateToReserves, then liquidated via second contract",
         "Add health check validation to donateToReserves function",
         "https://rekt.news/euler-rekt/"),
        ("Beanstalk Flash Loan Governance", "Beanstalk", "Flash loan-based governance attack",
         "Critical", "No delay between governance vote passage and proposal execution",
         "$181M drained, attacker retained ~$76M",
         "Attacker borrowed 350M DAI + 500M USDC + 150M USDT via flash loans, used for voting dominance, executed malicious proposal",
         "Implement timelock on proposal execution, use snapshot-based voting",
         "https://rekt.news/beanstalk-rekt/"),
        ("Cream Finance Oracle Manipulation", "Cream Finance", "Price oracle manipulation via yUSDVault",
         "Critical", "CREAM valued yUSDVault collateral using pricePerShare which could be manipulated",
         "$130M drained across ETH, BTC, stablecoins",
         "Attacker used flash loans to manipulate yUSDVault totalSupply, inflating pricePerShare, then borrowed against inflated collateral",
         "Use TWAP oracles, validate price feeds against manipulation",
         "https://rekt.news/cream-rekt-2/"),
        ("Mango Markets Oracle Manipulation", "Mango Markets", "Market/price manipulation via low-liquidity token",
         "Critical", "MNGO token had extremely low liquidity, making spot price trivially manipulable",
         "$115M in bad debt, ~$110M drained",
         "Attacker deposited funds, opened large MNGO-PERP long, counter-traded to spike spot price, borrowed against inflated collateral",
         "Do not use low-liquidity tokens for collateral valuation without manipulation safeguards",
         "https://rekt.news/mango-markets-rekt/"),
        ("BonqDAO Oracle Manipulation", "BonqDAO", "Oracle manipulation via instant price feeds",
         "Critical", "BonqDAO used instant Tellor oracle prices without validation",
         "$120M at token prices, attacker converted ~$1.7M due to low liquidity",
         "Attacker staked 10 TRB, submitted inflated WALBT price, minted 100M BEUR against 0.1 WALBT collateral",
         "Use TWAP oracles, validate oracle updates, add price bounds",
         "https://rekt.news/bonq-rekt/"),
        ("Curve Vyper Compiler Bug", "Curve Finance", "Compiler-level reentrancy via broken nonreentrant guard in Vyper",
         "Critical", "Storage slot misalignment in Vyper compiler caused reentrancy guard to malfunction",
         "$69M across Curve, Alchemix, JPEGd, Metronome",
         "Attacker exploited broken reentrancy guard to re-enter between add_liquidity and remove_liquidity, manipulating LP token prices",
         "Upgrade Vyper compiler to 0.3.1+, audit compiler-level code",
         "https://rekt.news/curve-vyper-rekt/"),
        ("Inverse Finance Oracle Manipulation", "Inverse Finance", "Oracle manipulation via spot price on low-liquidity DEX pair",
         "Critical", "Protocol relied on TWAP oracle from SushiSwap INV-WETH pair with very low liquidity",
         "$15.6M drained",
         "Attacker swapped 500 ETH for INV to inflate price 50x, spammed transactions to hold price across blocks, borrowed against inflated collateral",
         "Use Chainlink oracles with sufficient liquidity, validate TWAP against manipulation",
         "https://rekt.news/inverse-finance-rekt/"),
        ("Nomad Bridge Validation Bypass", "Nomad Bridge", "Improper initialization / validation bypass in bridge contract",
         "Critical", "Zero address set as trusted root after upgrade, making all messages read as valid",
         "$190M drained in ~2.5 hours",
         "Attacker called process() directly bypassing merkle root validation. Exploit was permissionless",
         "Properly initialize bridge contracts, validate merkle proofs before executing cross-chain messages",
         "https://rekt.news/nomad-rekt/"),
        ("Mirror Protocol Duplicate Withdrawal", "Mirror Protocol", "Logic bug / missing duplicate call check in withdrawal",
         "Critical", "Lock contract did not contain duplicate call check for withdrawals",
         "$90M drained, went unnoticed for 7 months",
         "Attacker repeatedly called unlock_position_funds for same position ID multiple times, draining collateral from other users",
         "Add duplicate call checks to withdrawal functions",
         "https://rekt.news/mirror-rekt/"),
        // ── Third batch (rekt.news) ──
        ("Hundred Finance Exchange Rate Manipulation", "Hundred Finance", "Exchange rate manipulation combined with rounding error in redeemUnderlying",
         "Critical", "Attacker donates large amount to inflate exchange rate, tiny collateral drains lending pools",
         "$7.4M stolen on Optimism",
         "Attacker flashloaned 500 WBTC, donated to hWBTC contract inflating exchange rate, used 2 wei of hWBTC as collateral to borrow 1021 ETH",
         "Ensure exchange rate integrity when empty or low-liquidity markets exist",
         "https://rekt.news/hundred-rekt2/"),
        ("Venus Protocol LUNA Oracle Failure", "Venus Protocol", "Oracle price feed circuit breaker failure during market crash",
         "Critical", "Chainlink oracle had hardcoded minimum price of $0.10 for LUNA, continued reporting inflated price during crash",
         "$13.5M loss on Venus, $8.3M on Blizz Finance",
         "Attacker bought cheap LUNA, deposited as collateral valued at $0.10 oracle price, borrowed real assets against inflated collateral",
         "Implement automated circuit-breakers to pause contracts during extreme market conditions",
         "https://rekt.news/venus-blizz-rekt/"),
        ("Harvest Finance Flash Loan Arbitrage", "Harvest Finance", "Price manipulation via flash loan arbitrage on vault share calculation",
         "Critical", "Vault price calculation used tokenIndex-based calculation vulnerable to stablecoin price distortion",
         "$33.8M extracted, attacker retained ~$24M",
         "Attacker flashloaned $50M USDT, swapped USDC to USDT via Curve to push price up, deposited at elevated price, withdrew at higher share value. Repeated 32 times.",
         "Use Curve get_virtual_price() for pricing, reduce slippage tolerance",
         "https://rekt.news/harvest-finance-rekt/"),
        ("PancakeBunny Flash Loan Price Manipulation", "PancakeBunny", "Flash loan price manipulation on PancakeSwap LP token valuation",
         "Critical", "Protocol used PancakeSwap pool prices for LP token valuation, susceptible to flash loan manipulation",
         "$45M drained, BUNNY crashed from $146 to $6",
         "Attacker flashloaned 2.32M WBNB, injected liquidity to inflate LP token price, called getReward() to claim inflated BUNNY rewards",
         "Do not use spot pool prices for LP token valuation",
         "https://rekt.news/pancakebunny-rekt/"),
        ("Spartan Protocol Liquidity Share Calculation", "Spartan Protocol", "Flash loan attack on flawed liquidity share calculation",
         "Critical", "calcLiquidityShare() queried current pool balance instead of cached values",
         "$30.5M drained",
         "Attacker flashloaned 10K WBNB, swapped for SPARTA, added liquidity, inflated pool balance via direct transfers, burned LP tokens at inflated rate",
         "Use cached/tokenAmountPooled values instead of live pool balances",
         "https://rekt.news/spartan-rekt/"),
        ("Visor Finance Access Control Flaw", "Visor Finance", "Smart contract access control flaw in deposit function",
         "Critical", "require() check only verified _from parameter had Owner() method returning msg.sender",
         "8.8M VISR tokens worth ~$8.2M",
         "Attacker deployed contract with Owner() method returning caller, passed as _from parameter to mint 195K vVISR tokens",
         "Implement proper authorization checks, validate contract identity",
         "https://rekt.news/visor-finance-rekt/"),
        ("Akropolis Reentrancy via Fake Token", "Akropolis", "Reentrancy combined with flash loans via attacker-created token",
         "Critical", "Protocol calculated deposit amount from balance difference, accepted any token including malicious ones",
         "$2M in DAI stolen",
         "Attacker created fake token, deposited into Akropolis, triggered reentrancy during deposit to get double-credited",
         "Validate deposit tokens, implement reentrancy guards, verify balance changes robustly",
         "https://rekt.news/akropolis-rekt/"),
        ("Furucombo Evil Contract Delegatecall", "Furucombo", "Evil contract exploit via nested delegatecall interactions",
         "Critical", "Furucombo proxy performed caller-specified delegatecalls to trusted handlers, letting storage be modified",
         "$14M stolen from user wallets",
         "Attacker used delegatecall to AAVE V2 proxy to set implementation address in Furucombo storage, then called Furucombo which executed malicious code",
         "Audit how delegatecall affects caller storage, avoid infinite approvals",
         "https://rekt.news/furucombo-rekt/"),
        ("Cashio Infinite Mint via Fake Root", "Cashio", "Infinite mint via incomplete collateral validation on Solana",
         "Critical", "LP tokens never had .mint field validated, allowing fake root contract creation",
         "$48M stolen",
         "Attacker created fake root contract and chain of fake accounts passing validation by referencing each other, minted 2B CASH against worthless tokens",
         "Validate .mint field on LP tokens, verify depositor_source against trusted references",
         "https://rekt.news/cashio-rekt/"),
    ]
}
