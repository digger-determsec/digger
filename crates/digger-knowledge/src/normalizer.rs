/// Normalizer — maps extracted findings to Digger's canonical taxonomy.
use digger_knowledge_models::*;

/// Normalize an extracted finding into Digger's canonical representation.
pub fn normalize_finding(finding: &ExtractedFinding, report: &AuditReport) -> NormalizedFinding {
    let vulnerability_class = classify_vulnerability(finding);
    let attack_goal = map_to_attack_goal(&vulnerability_class);
    let capability_pattern = infer_capabilities(&vulnerability_class);
    let violated_invariant = infer_violated_invariant(&vulnerability_class);
    let attack_technique = infer_attack_technique(finding, &vulnerability_class);
    let mitigation_pattern = infer_mitigation_pattern(&vulnerability_class);
    let security_assumptions = infer_security_assumptions(finding);
    let root_cause = infer_structural_root_cause(finding);
    let severity = map_severity(&finding.severity);
    let protocol_domain = classify_protocol_domain(finding, report);
    let protocol_pattern = infer_protocol_pattern(finding, &protocol_domain);

    let finding_hash = compute_finding_hash(&report.report_id, &finding.finding_id);

    NormalizedFinding {
        finding_id: finding_hash,
        original_finding_id: finding.finding_id.clone(),
        report_id: report.report_id.clone(),
        protocol_name: report.protocol_name.clone(),
        protocol_category: report.protocol_category.clone(),
        protocol_domain,
        protocol_pattern,
        vulnerability_class,
        attack_goal,
        capability_pattern,
        violated_invariant,
        attack_technique,
        mitigation_pattern,
        security_assumptions,
        severity,
        root_cause,
        impact_text: finding.impact.clone(),
        description_text: finding.description.clone(),
        remediation_text: finding.remediation.clone(),
        impacted_contracts: finding.impacted_contracts.clone(),
        impacted_functions: finding.impacted_functions.clone(),
        confidence: 1.0,
    }
}

/// Classify vulnerability class from finding content.
pub fn classify_vulnerability(finding: &ExtractedFinding) -> VulnerabilityClass {
    let text = format!(
        "{} {} {} {}",
        finding.title, finding.description, finding.root_cause, finding.impact
    )
    .to_lowercase();

    // Access control
    if text.contains("access control")
        || text.contains("unauthorized")
        || text.contains("missing modifier")
        || text.contains("missing access")
    {
        return VulnerabilityClass::MissingAccessControl;
    }
    if text.contains("privilege escalation") || text.contains("privilege") {
        return VulnerabilityClass::PrivilegeEscalation;
    }
    if text.contains("initialization")
        || text.contains("initialize")
        || text.contains("uninitialized")
    {
        return VulnerabilityClass::UnprotectedInitialization;
    }

    // Reentrancy
    if text.contains("cross-function reentrancy") || text.contains("cross function reentrancy") {
        return VulnerabilityClass::CrossFunctionReentrancy;
    }
    if text.contains("cross-contract reentrancy") || text.contains("cross contract reentrancy") {
        return VulnerabilityClass::CrossContractReentrancy;
    }
    if text.contains("reentrancy")
        || text.contains("reentrant")
        || text.contains("re-enter")
        || text.contains("reenter")
    {
        return VulnerabilityClass::Reentrancy;
    }

    // Economic
    if text.contains("flash loan") || text.contains("flashloan") {
        return VulnerabilityClass::FlashLoanAttack;
    }
    if text.contains("oracle manipulation") || text.contains("oracle") && text.contains("manipul") {
        return VulnerabilityClass::OracleManipulation;
    }
    if text.contains("price manipulation")
        || text.contains("price feed")
        || text.contains("price manipul")
    {
        return VulnerabilityClass::PriceManipulation;
    }
    if text.contains("sandwich") {
        return VulnerabilityClass::SandwichAttack;
    }
    if text.contains("mev")
        || text.contains("front-run")
        || text.contains("frontrun")
        || text.contains("front run")
    {
        return VulnerabilityClass::FrontRunning;
    }
    if text.contains("liquidation") && (text.contains("manipul") || text.contains("attack")) {
        return VulnerabilityClass::LiquidationManipulation;
    }

    // Accounting
    if text.contains("precision") || text.contains("rounding") || text.contains("decimal") {
        return VulnerabilityClass::PrecisionLoss;
    }
    if text.contains("overflow") || text.contains("underflow") {
        return VulnerabilityClass::IntegerOverflow;
    }
    if text.contains("invariant") && (text.contains("violat") || text.contains("break")) {
        return VulnerabilityClass::InvariantViolation;
    }

    // State
    if text.contains("state corruption") || text.contains("state manipul") {
        return VulnerabilityClass::StateCorruption;
    }
    if text.contains("denial of service") || text.contains("dos") || text.contains("grief") {
        return VulnerabilityClass::DenialOfService;
    }

    // Logic
    if text.contains("business logic") || text.contains("logic flaw") {
        return VulnerabilityClass::BusinessLogicFlaw;
    }
    if text.contains("missing validation")
        || text.contains("missing check")
        || text.contains("unchecked")
    {
        return VulnerabilityClass::MissingValidation;
    }
    if text.contains("incorrect calculation")
        || text.contains("wrong calculation")
        || text.contains("calculation error")
    {
        return VulnerabilityClass::IncorrectCalculation;
    }
    if text.contains("unchecked return") || text.contains("return value") {
        return VulnerabilityClass::UncheckedReturn;
    }

    // Upgradeability
    if text.contains("storage collision") || text.contains("storage clash") {
        return VulnerabilityClass::StorageCollision;
    }
    if text.contains("proxy") && text.contains("initializ") {
        return VulnerabilityClass::ProxyInitialization;
    }
    if text.contains("upgrade") {
        return VulnerabilityClass::UpgradeabilityRisk;
    }

    // Governance
    if text.contains("governance") || text.contains("voting") || text.contains("proposal") {
        return VulnerabilityClass::GovernanceAttack;
    }
    if text.contains("timelock") {
        return VulnerabilityClass::TimelockBypass;
    }

    // Composability
    if text.contains("composab")
        || text.contains("cross-protocol")
        || text.contains("cross chain")
        || text.contains("cross-chain")
    {
        return VulnerabilityClass::ComposabilityRisk;
    }

    // Centralization
    if text.contains("centralization")
        || text.contains("centralized")
        || text.contains("single point")
        || text.contains("single point of failure")
        || text.contains("trusted party")
        || text.contains("admin can")
        || text.contains("owner can")
        || text.contains("centralization attack")
        || text.contains("risks due to centralization")
    {
        return VulnerabilityClass::CentralizationRisk;
    }

    // Fee-on-transfer and token compatibility
    if text.contains("fee on transfer")
        || text.contains("fee-on-transfer")
        || text.contains("deflationary")
        || text.contains("rebasing")
        || text.contains("rebasing token")
        || text.contains("transfer fee")
        || text.contains("token with fee")
    {
        return VulnerabilityClass::ComposabilityRisk;
    }

    // Missing events and observability
    if text.contains("missing event")
        || text.contains("event emission")
        || text.contains("emit event")
        || text.contains("no event")
        || text.contains("event not emitted")
    {
        return VulnerabilityClass::MissingValidation;
    }

    // Slippage and sandwich protection
    if text.contains("slippage")
        || text.contains("sandwich protection")
        || text.contains("minimum output")
        || text.contains("min output")
        || text.contains("slippage tolerance")
    {
        return VulnerabilityClass::MissingValidation;
    }

    // Input validation
    if text.contains("input validation")
        || text.contains("insufficient validation")
        || text.contains("unvalidated input")
        || text.contains("missing parameter check")
        || text.contains("parameter validation")
    {
        return VulnerabilityClass::MissingValidation;
    }

    // Signature and cryptographic issues
    if text.contains("signature malleability")
        || text.contains("ecrecover")
        || text.contains("signature replay")
        || text.contains("nonce reuse")
    {
        return VulnerabilityClass::MissingValidation;
    }

    // Chain ID and replay
    if text.contains("chainid")
        || text.contains("chain id")
        || text.contains("replay")
        || text.contains("cross-chain replay")
    {
        return VulnerabilityClass::MissingValidation;
    }

    // Stale oracle and price
    if text.contains("stale price")
        || text.contains("price staleness")
        || text.contains("stale oracle")
        || text.contains("oracle staleness")
        || text.contains("stale data")
        || text.contains("stale value")
    {
        return VulnerabilityClass::OracleManipulation;
    }

    // Zero address checks
    if text.contains("zero address")
        || text.contains("address(0)")
        || text.contains("zero-address")
        || text.contains("address(0x0)")
        || text.contains("null address")
    {
        return VulnerabilityClass::MissingValidation;
    }

    // Race conditions and concurrency
    if text.contains("race condition") || text.contains("concurrent") {
        return VulnerabilityClass::FrontRunning;
    }

    // Insufficient checks
    if text.contains("insufficient") && text.contains("check") {
        return VulnerabilityClass::MissingValidation;
    }

    // Denial of service via revert
    if text.contains("unexpected") && text.contains("revert") {
        return VulnerabilityClass::DenialOfService;
    }

    // Stuck funds
    if text.contains("stuck")
        && (text.contains("fund")
            || text.contains("token")
            || text.contains("asset")
            || text.contains("ether")
            || text.contains("eth"))
    {
        return VulnerabilityClass::DenialOfService;
    }

    // Dust and small amounts
    if text.contains("dust")
        || text.contains("left behind")
        || text.contains("leftover")
        || text.contains("residual")
    {
        return VulnerabilityClass::BusinessLogicFlaw;
    }

    // Rescue and recovery
    if text.contains("rescue") || text.contains("recover") || text.contains("rescueTokens") {
        return VulnerabilityClass::BusinessLogicFlaw;
    }

    // Token approval issues
    if text.contains("approval")
        || text.contains("approve")
        || text.contains("allowance")
        || text.contains("infinite approval")
    {
        return VulnerabilityClass::MissingValidation;
    }

    // Module and registry issues
    if text.contains("module")
        && (text.contains("malicious") || text.contains("untrusted") || text.contains("registry"))
    {
        return VulnerabilityClass::MissingAccessControl;
    }

    // Delegatecall risks
    if text.contains("delegatecall")
        || text.contains("delegate call")
        || text.contains("delegate_call")
    {
        return VulnerabilityClass::ComposabilityRisk;
    }

    // Protocol-specific patterns — Uniswap, Aave, Compound, etc.
    if text.contains("uniswap")
        || text.contains("sushiswap")
        || text.contains("sushi swap")
        || text.contains("amm")
        || text.contains("liquidity pool")
        || text.contains("swap")
        || text.contains("swap rate")
    {
        // Check for specific vulnerability types within AMM context
        if text.contains("sandwich") || text.contains("front-run") || text.contains("frontrun") {
            return VulnerabilityClass::SandwichAttack;
        }
        if text.contains("slippage")
            || text.contains("minimum output")
            || text.contains("min output")
        {
            return VulnerabilityClass::MissingValidation;
        }
        if text.contains("oracle") || text.contains("price") {
            return VulnerabilityClass::OracleManipulation;
        }
        return VulnerabilityClass::BusinessLogicFlaw;
    }

    if text.contains("aave") || text.contains("compound") || text.contains("lending") {
        if text.contains("oracle") || text.contains("price") || text.contains("liquidat") {
            return VulnerabilityClass::OracleManipulation;
        }
        if text.contains("interest") || text.contains("rate") || text.contains("utilization") {
            return VulnerabilityClass::BusinessLogicFlaw;
        }
        return VulnerabilityClass::BusinessLogicFlaw;
    }

    if text.contains("vault") || text.contains("erc4626") || text.contains("erc-4626") {
        if text.contains("inflation") || text.contains("first depositor") {
            return VulnerabilityClass::BusinessLogicFlaw;
        }
        return VulnerabilityClass::BusinessLogicFlaw;
    }

    if text.contains("bridge") || text.contains("cross-chain") || text.contains("cross chain") {
        if text.contains("replay") || text.contains("signature") {
            return VulnerabilityClass::MissingValidation;
        }
        return VulnerabilityClass::ComposabilityRisk;
    }

    if text.contains("governance") || text.contains("dao") || text.contains("timelock") {
        if text.contains("flash loan") || text.contains("voting") || text.contains("proposal") {
            return VulnerabilityClass::GovernanceAttack;
        }
        return VulnerabilityClass::GovernanceAttack;
    }

    if text.contains("staking") || text.contains("validator") || text.contains("delegation") {
        return VulnerabilityClass::BusinessLogicFlaw;
    }

    if text.contains("nft") || text.contains("erc721") || text.contains("erc-721") {
        return VulnerabilityClass::BusinessLogicFlaw;
    }

    if text.contains("token")
        && (text.contains("mint") || text.contains("burn") || text.contains("transfer"))
    {
        if text.contains("approval") || text.contains("allowance") {
            return VulnerabilityClass::MissingValidation;
        }
        return VulnerabilityClass::BusinessLogicFlaw;
    }

    // Fallback: check for common vulnerability description patterns
    if text.contains("vulnerability")
        || text.contains("bug")
        || text.contains("issue")
        || text.contains("problem")
    {
        // Try to infer from surrounding context
        if text.contains("can be") || text.contains("allows") || text.contains("enables") {
            return VulnerabilityClass::BusinessLogicFlaw;
        }
    }

    // Access control bypass
    if text.contains("bypass")
        && (text.contains("check")
            || text.contains("validation")
            || text.contains("modifier")
            || text.contains("access"))
    {
        return VulnerabilityClass::MissingAccessControl;
    }

    // Oracle attacks
    if text.contains("oracle")
        && (text.contains("manipul")
            || text.contains("attack")
            || text.contains("exploit")
            || text.contains("twap"))
    {
        return VulnerabilityClass::OracleManipulation;
    }

    // Rounding errors
    if text.contains("rounding")
        && (text.contains("error")
            || text.contains("issue")
            || text.contains("attack")
            || text.contains("direction"))
    {
        return VulnerabilityClass::RoundingError;
    }

    // Precision issues
    if text.contains("precision")
        && (text.contains("loss")
            || text.contains("issue")
            || text.contains("error")
            || text.contains("decimal"))
    {
        return VulnerabilityClass::PrecisionLoss;
    }

    // Token approval issues
    if text.contains("approval")
        && (text.contains("unlimited") || text.contains("infinite") || text.contains("max"))
    {
        return VulnerabilityClass::MissingValidation;
    }

    // Reentrancy via gas
    if text.contains("gas")
        && (text.contains("grief") || text.contains("stipend") || text.contains("forward"))
    {
        return VulnerabilityClass::DenialOfService;
    }

    // Integer issues
    if text.contains("integer")
        && (text.contains("overflow") || text.contains("underflow") || text.contains("wrap"))
    {
        return VulnerabilityClass::IntegerOverflow;
    }

    // Arithmetic issues
    if text.contains("arithmetic")
        && (text.contains("overflow") || text.contains("underflow") || text.contains("error"))
    {
        return VulnerabilityClass::IntegerOverflow;
    }

    // Timestamp dependency
    if text.contains("timestamp")
        && (text.contains("dependence")
            || text.contains("manipulation")
            || text.contains("block.timestamp"))
    {
        return VulnerabilityClass::FrontRunning;
    }

    // Unchecked external calls
    if text.contains("unchecked")
        && (text.contains("call") || text.contains("return") || text.contains("success"))
    {
        return VulnerabilityClass::UncheckedReturn;
    }

    // Storage issues
    if text.contains("storage")
        && (text.contains("collision") || text.contains("overlap") || text.contains("layout"))
    {
        return VulnerabilityClass::StorageCollision;
    }

    // Proxy issues
    if text.contains("proxy")
        && (text.contains("initializ")
            || text.contains("upgrade")
            || text.contains("implementation"))
    {
        return VulnerabilityClass::ProxyInitialization;
    }

    // Griefing and DoS
    if text.contains("griefing") || text.contains("grief") {
        return VulnerabilityClass::DenialOfService;
    }
    if text.contains("stuck fund") || text.contains("stuck token") || text.contains("stuck asset") {
        return VulnerabilityClass::DenialOfService;
    }

    // Exchange rate and accounting
    if text.contains("exchange rate") || text.contains("exchange_rate") {
        return VulnerabilityClass::PrecisionLoss;
    }
    if text.contains("incorrect redeem") || text.contains("incorrect accounting") {
        return VulnerabilityClass::InvariantViolation;
    }
    if text.contains("boost buyback") || text.contains("incorrect amount") {
        return VulnerabilityClass::IncorrectCalculation;
    }

    // ERC compliance
    if text.contains("erc-1504")
        || text.contains("erc1504")
        || text.contains("not strictly compliant")
    {
        return VulnerabilityClass::ComposabilityRisk;
    }

    // Two-step patterns
    if text.contains("two-step") || text.contains("two step") {
        return VulnerabilityClass::MissingValidation;
    }

    // Sell under peg
    if text.contains("under peg") || text.contains("below peg") {
        return VulnerabilityClass::InvariantViolation;
    }

    // Redemption issues
    if text.contains("redemption") && text.contains("not being tracked") {
        return VulnerabilityClass::InvariantViolation;
    }
    if text.contains("redeem") && text.contains("without decreasing") {
        return VulnerabilityClass::InvariantViolation;
    }

    // Vault-specific
    if text.contains("vault") && text.contains("stuck") {
        return VulnerabilityClass::DenialOfService;
    }

    // Token compatibility
    if text.contains("does not work with") || text.contains("not supported") {
        return VulnerabilityClass::ComposabilityRisk;
    }

    // Fee issues
    if text.contains("fee")
        && (text.contains("incorrect") || text.contains("wrong") || text.contains("not tracked"))
    {
        return VulnerabilityClass::IncorrectCalculation;
    }

    // Interest rate
    if text.contains("interest rate") || text.contains("base rate") {
        return VulnerabilityClass::InvariantViolation;
    }

    // Reward issues
    if text.contains("reward")
        && (text.contains("steal") || text.contains("incorrect") || text.contains("stolen"))
    {
        return VulnerabilityClass::InvariantViolation;
    }

    // Coverage issues
    if text.contains("coverage") && (text.contains("zero") || text.contains("stolen")) {
        return VulnerabilityClass::InvariantViolation;
    }

    // Initialization ratio
    if text.contains("initialization ratio") || text.contains("decide the initialization") {
        return VulnerabilityClass::InvariantViolation;
    }

    VulnerabilityClass::Other(finding.title.clone())
}

/// Map vulnerability class to attack goal.
pub fn map_to_attack_goal(class: &VulnerabilityClass) -> String {
    match class {
        VulnerabilityClass::Reentrancy
        | VulnerabilityClass::CrossFunctionReentrancy
        | VulnerabilityClass::CrossContractReentrancy => "DrainAssets".into(),

        VulnerabilityClass::FlashLoanAttack
        | VulnerabilityClass::OracleManipulation
        | VulnerabilityClass::PriceManipulation
        | VulnerabilityClass::LiquidationManipulation => "ManipulatePrice".into(),

        VulnerabilityClass::MissingAccessControl
        | VulnerabilityClass::PrivilegeEscalation
        | VulnerabilityClass::UnprotectedInitialization => "GainUnauthorizedControl".into(),

        VulnerabilityClass::PrecisionLoss
        | VulnerabilityClass::RoundingError
        | VulnerabilityClass::IntegerOverflow
        | VulnerabilityClass::InvariantViolation => "CorruptAccounting".into(),

        VulnerabilityClass::FrontRunning
        | VulnerabilityClass::SandwichAttack
        | VulnerabilityClass::MEVExtraction => "ExhaustResources".into(),

        VulnerabilityClass::Griefing | VulnerabilityClass::DenialOfService => "FreezeFunds".into(),

        VulnerabilityClass::GovernanceAttack
        | VulnerabilityClass::TimelockBypass
        | VulnerabilityClass::VotingManipulation => "GainUnauthorizedControl".into(),

        VulnerabilityClass::StorageCollision
        | VulnerabilityClass::ProxyInitialization
        | VulnerabilityClass::UpgradeabilityRisk => "GainUnauthorizedControl".into(),

        _ => "BreakEconomicInvariant".into(),
    }
}

/// Infer required capabilities from vulnerability class.
pub fn infer_capabilities(class: &VulnerabilityClass) -> Vec<String> {
    match class {
        VulnerabilityClass::Reentrancy
        | VulnerabilityClass::CrossFunctionReentrancy
        | VulnerabilityClass::CrossContractReentrancy => vec!["CanReenter".into()],

        VulnerabilityClass::FlashLoanAttack => {
            vec!["CanBorrowLiquidity".into(), "CanManipulatePrice".into()]
        }
        VulnerabilityClass::OracleManipulation | VulnerabilityClass::PriceManipulation => {
            vec!["CanManipulatePrice".into()]
        }
        VulnerabilityClass::FrontRunning | VulnerabilityClass::SandwichAttack => vec![
            "CanObserveState".into(),
            "CanControlTransactionOrdering".into(),
        ],
        VulnerabilityClass::MEVExtraction => vec![
            "CanObserveState".into(),
            "CanControlTransactionOrdering".into(),
        ],
        VulnerabilityClass::GovernanceAttack => vec!["CanControlGovernance".into()],
        VulnerabilityClass::Griefing | VulnerabilityClass::DenialOfService => {
            vec!["CanCallPublicFunction".into()]
        }
        _ => vec!["CanCallPublicFunction".into()],
    }
}

/// Infer violated invariant from vulnerability class.
pub fn infer_violated_invariant(class: &VulnerabilityClass) -> ViolatedInvariant {
    match class {
        VulnerabilityClass::Reentrancy
        | VulnerabilityClass::CrossFunctionReentrancy
        | VulnerabilityClass::CrossContractReentrancy => ViolatedInvariant {
            kind: "conservation".into(),
            description: "Asset conservation violated by reentrant calls".into(),
            affected_state_vars: vec![],
        },
        VulnerabilityClass::FlashLoanAttack
        | VulnerabilityClass::OracleManipulation
        | VulnerabilityClass::PriceManipulation => ViolatedInvariant {
            kind: "collateralization".into(),
            description: "Collateralization invariant violated by price manipulation".into(),
            affected_state_vars: vec![],
        },
        VulnerabilityClass::MissingAccessControl | VulnerabilityClass::PrivilegeEscalation => {
            ViolatedInvariant {
                kind: "authority".into(),
                description: "Authority invariant violated by missing access control".into(),
                affected_state_vars: vec![],
            }
        }
        VulnerabilityClass::PrecisionLoss
        | VulnerabilityClass::RoundingError
        | VulnerabilityClass::IntegerOverflow => ViolatedInvariant {
            kind: "accounting".into(),
            description: "Accounting invariant violated by precision issues".into(),
            affected_state_vars: vec![],
        },
        _ => ViolatedInvariant {
            kind: "unknown".into(),
            description: "Security invariant violated".into(),
            affected_state_vars: vec![],
        },
    }
}

/// Infer attack technique.
pub fn infer_attack_technique(
    finding: &ExtractedFinding,
    class: &VulnerabilityClass,
) -> AttackTechnique {
    match class {
        VulnerabilityClass::Reentrancy
        | VulnerabilityClass::CrossFunctionReentrancy
        | VulnerabilityClass::CrossContractReentrancy => AttackTechnique::ReentrancyExploit,
        VulnerabilityClass::FlashLoanAttack => AttackTechnique::FlashLoanBorrow,
        VulnerabilityClass::OracleManipulation | VulnerabilityClass::PriceManipulation => {
            AttackTechnique::PriceOracleManipulation
        }
        VulnerabilityClass::FrontRunning => AttackTechnique::FrontRunningTransaction,
        VulnerabilityClass::SandwichAttack => AttackTechnique::SandwichAttackVector,
        VulnerabilityClass::GovernanceAttack => AttackTechnique::GovernanceProposalAttack,
        VulnerabilityClass::TimelockBypass => AttackTechnique::TimelockExploitation,
        VulnerabilityClass::StorageCollision => AttackTechnique::StorageCollisionExploit,
        VulnerabilityClass::MissingAccessControl | VulnerabilityClass::PrivilegeEscalation => {
            AttackTechnique::AccessControlBypass
        }
        VulnerabilityClass::UnprotectedInitialization => AttackTechnique::InitializationBypass,
        VulnerabilityClass::UncheckedReturn => AttackTechnique::UncheckedExternalCall,
        VulnerabilityClass::PrecisionLoss | VulnerabilityClass::RoundingError => {
            AttackTechnique::PrecisionLossExploitation
        }
        _ => AttackTechnique::Other(finding.title.clone()),
    }
}

/// Infer mitigation pattern.
pub fn infer_mitigation_pattern(class: &VulnerabilityClass) -> Option<MitigationPattern> {
    match class {
        VulnerabilityClass::Reentrancy
        | VulnerabilityClass::CrossFunctionReentrancy
        | VulnerabilityClass::CrossContractReentrancy => Some(MitigationPattern {
            technique: "checks-effects-interactions".into(),
            description: "Apply the checks-effects-interactions pattern: perform all checks first, then state changes, then external calls".into(),
            is_standard: true,
        }),
        VulnerabilityClass::MissingAccessControl => Some(MitigationPattern {
            technique: "access-control-modifier".into(),
            description: "Add require(msg.sender == owner) or onlyOwner modifier to sensitive functions".into(),
            is_standard: true,
        }),
        VulnerabilityClass::FlashLoanAttack => Some(MitigationPattern {
            technique: "flash-loan-protection".into(),
            description: "Use TWAP oracles or check that price changes are within bounds across blocks".into(),
            is_standard: true,
        }),
        VulnerabilityClass::OracleManipulation => Some(MitigationPattern {
            technique: "oracle-validation".into(),
            description: "Use multiple oracle sources and validate price staleness".into(),
            is_standard: true,
        }),
        _ => None,
    }
}

/// Infer security assumptions.
pub fn infer_security_assumptions(finding: &ExtractedFinding) -> Vec<SecurityAssumption> {
    let mut assumptions = Vec::new();

    let text = format!("{} {}", finding.description, finding.impact).to_lowercase();

    if text.contains("assumes") || text.contains("assumption") {
        assumptions.push(SecurityAssumption {
            assumption: "Protocol assumes correct external behavior".into(),
            is_valid: false,
            violated_by: Some(finding.title.clone()),
        });
    }

    if text.contains("trusted") || text.contains("trust") {
        assumptions.push(SecurityAssumption {
            assumption: "Protocol trusts external actors".into(),
            is_valid: false,
            violated_by: Some(finding.title.clone()),
        });
    }

    assumptions
}

/// Infer structural root cause.
pub fn infer_structural_root_cause(finding: &ExtractedFinding) -> StructuralRootCause {
    let text = format!(
        "{} {} {}",
        finding.title, finding.description, finding.root_cause
    )
    .to_lowercase();

    // ── Authority and access control ──
    if text.contains("missing check")
        || text.contains("missing require")
        || text.contains("no check")
        || text.contains("without check")
        || text.contains("no access control")
        || text.contains("missing access control")
        || text.contains("no authentication")
        || text.contains("missing authentication")
        || text.contains("unprotected function")
        || text.contains("public function that should be")
    {
        return StructuralRootCause::MissingAuthorityCheck;
    }

    // ── Operation ordering ──
    if (text.contains("order") || text.contains("ordering") || text.contains("sequence"))
        && (text.contains("incorrect")
            || text.contains("wrong")
            || text.contains("before")
            || text.contains("after")
            || text.contains("violation")
            || text.contains("violate"))
    {
        return StructuralRootCause::IncorrectOperationOrder;
    }
    if text.contains("state update") && text.contains("before") && text.contains("external") {
        return StructuralRootCause::IncorrectOperationOrder;
    }
    if text.contains("checks-effects-interactions")
        || text.contains("cei violation")
        || text.contains("cei pattern")
    {
        return StructuralRootCause::IncorrectOperationOrder;
    }

    // ── Missing state updates ──
    if text.contains("not updated")
        || text.contains("missing update")
        || text.contains("state not")
        || text.contains("not cleared")
        || text.contains("not reset")
        || text.contains("not decremented")
        || text.contains("not incremented")
    {
        return StructuralRootCause::MissingStateUpdate;
    }

    // ── Shared mutable state ──
    if text.contains("shared") && text.contains("mutable") {
        return StructuralRootCause::SharedMutableState;
    }
    if text.contains("shared state")
        || text.contains("shared variable")
        || text.contains("shared storage")
    {
        return StructuralRootCause::SharedMutableState;
    }

    // ── Input validation ──
    if text.contains("external input")
        || text.contains("user input")
        || text.contains("unvalidated")
        || text.contains("input validation")
        || text.contains("insufficient validation")
        || text.contains("missing validation")
        || text.contains("no validation")
        || text.contains("not validated")
        || text.contains("unverified input")
    {
        return StructuralRootCause::UnvalidatedExternalInput;
    }
    if text.contains("missing parameter") || text.contains("missing argument") {
        return StructuralRootCause::UnvalidatedExternalInput;
    }

    // ── Invariant assumptions ──
    if text.contains("invariant")
        && (text.contains("assumption") || text.contains("incorrect") || text.contains("violat"))
    {
        return StructuralRootCause::IncorrectInvariantAssumption;
    }
    if text.contains("assumption")
        && (text.contains("incorrect") || text.contains("wrong") || text.contains("invalid"))
    {
        return StructuralRootCause::IncorrectInvariantAssumption;
    }

    // ── Boundary checks ──
    if text.contains("boundary")
        || text.contains("bounds")
        || text.contains("limit")
        || text.contains("overflow")
        || text.contains("underflow")
    {
        return StructuralRootCause::MissingBoundaryCheck;
    }
    if text.contains("max value")
        || text.contains("min value")
        || text.contains("upper bound")
        || text.contains("lower bound")
    {
        return StructuralRootCause::MissingBoundaryCheck;
    }
    if text.contains("missing bounds")
        || text.contains("no bounds")
        || text.contains("without bounds")
    {
        return StructuralRootCause::MissingBoundaryCheck;
    }

    // ── Unsafe composition ──
    if text.contains("composab")
        || text.contains("interaction")
        || text.contains("cross-contract")
        || text.contains("cross contract")
    {
        return StructuralRootCause::UnsafeComposition;
    }
    if text.contains("external call") && text.contains("unsafe") {
        return StructuralRootCause::UnsafeComposition;
    }
    if text.contains("delegatecall") || text.contains("delegate call") {
        return StructuralRootCause::UnsafeComposition;
    }

    // ── Fee-on-transfer incompatibility ──
    if text.contains("fee on transfer")
        || text.contains("fee-on-transfer")
        || text.contains("deflationary")
        || text.contains("rebasing token")
        || text.contains("transfer fee")
    {
        return StructuralRootCause::FeeOnTransferIncompatibility;
    }

    // ── Stale state assumptions ──
    if text.contains("stale")
        && (text.contains("price")
            || text.contains("oracle")
            || text.contains("data")
            || text.contains("value"))
    {
        return StructuralRootCause::StaleStateAssumption;
    }
    if text.contains("cached")
        && (text.contains("stale") || text.contains("outdated") || text.contains("expired"))
    {
        return StructuralRootCause::StaleStateAssumption;
    }

    // ── Unchecked return values ──
    if text.contains("unchecked return")
        || text.contains("return value")
        || text.contains("unchecked call")
        || text.contains("return value not checked")
        || text.contains("return value not checked")
    {
        return StructuralRootCause::UncheckedReturnValue;
    }

    // ── Rounding and precision ──
    if text.contains("rounding")
        && (text.contains("error")
            || text.contains("direction")
            || text.contains("attack")
            || text.contains("issue"))
    {
        return StructuralRootCause::IncorrectRoundingDirection;
    }
    if text.contains("precision")
        && (text.contains("loss") || text.contains("error") || text.contains("issue"))
    {
        return StructuralRootCause::IncorrectRoundingDirection;
    }
    if text.contains("rounding") || text.contains("precision") || text.contains("decimal") {
        return StructuralRootCause::MissingBoundaryCheck;
    }

    // ── Reentrancy ──
    if text.contains("reentrancy")
        || text.contains("reentrant")
        || text.contains("re-enter")
        || text.contains("reenter")
    {
        return StructuralRootCause::CrossFunctionStateInconsistency;
    }

    // ── Front-running and MEV ──
    if text.contains("front-run")
        || text.contains("frontrun")
        || text.contains("front run")
        || text.contains("mev")
    {
        return StructuralRootCause::FrontRunningRisk;
    }

    // ── Oracle dependency ──
    if text.contains("oracle")
        && (text.contains("manipul") || text.contains("attack") || text.contains("dependency"))
    {
        return StructuralRootCause::OracleStaleness;
    }
    if text.contains("oracle staleness")
        || text.contains("stale oracle")
        || text.contains("oracle stale")
    {
        return StructuralRootCause::OracleStaleness;
    }

    // ── Governance and timelock ──
    if text.contains("governance") || text.contains("timelock") || text.contains("voting") {
        return StructuralRootCause::MissingAuthorityCheck;
    }

    // ── Upgrade and proxy ──
    if text.contains("upgrade") || text.contains("proxy") || text.contains("implementation") {
        return StructuralRootCause::UnsafeComposition;
    }

    // ── Missing event emission ──
    if text.contains("missing event")
        || text.contains("event emission")
        || text.contains("emit event")
    {
        return StructuralRootCause::MissingEventEmission;
    }

    // ── Slippage protection ──
    if text.contains("slippage")
        || text.contains("sandwich protection")
        || text.contains("minimum output")
        || text.contains("min output")
    {
        return StructuralRootCause::MissingSlippageProtection;
    }

    // ── Zero address checks ──
    if text.contains("zero address")
        || text.contains("address(0)")
        || text.contains("zero-address")
        || text.contains("null address")
    {
        return StructuralRootCause::MissingZeroAddressCheck;
    }

    // ── Signature malleability ──
    if text.contains("signature malleability")
        || text.contains("ecrecover")
        || text.contains("signature replay")
    {
        return StructuralRootCause::SignatureMalleability;
    }

    // ── Gas griefing ──
    if text.contains("gas")
        && (text.contains("grief")
            || text.contains("stipend")
            || text.contains("forward")
            || text.contains("exhaust"))
    {
        return StructuralRootCause::GasGriefing;
    }

    // ── Timestamp dependency ──
    if text.contains("timestamp")
        && (text.contains("dependence")
            || text.contains("manipulation")
            || text.contains("block.timestamp"))
    {
        return StructuralRootCause::TimestampDependency;
    }

    // ── Cross-function state inconsistency ──
    if text.contains("cross-function")
        || text.contains("cross function")
        || text.contains("state inconsistency")
    {
        return StructuralRootCause::CrossFunctionStateInconsistency;
    }

    // ── Centralization and trust ──
    if text.contains("centralization")
        || text.contains("centralized")
        || text.contains("trusted party")
        || text.contains("admin can")
        || text.contains("owner can")
    {
        return StructuralRootCause::MissingAuthorityCheck;
    }

    // ── Griefing and DoS ──
    if text.contains("griefing") || text.contains("grief") || text.contains("stuck fund") {
        return StructuralRootCause::GasGriefing;
    }

    // ── Exchange rate and accounting ──
    if text.contains("exchange rate") || text.contains("incorrect redeem") {
        return StructuralRootCause::IncorrectInvariantAssumption;
    }

    // ── Fee and token compatibility ──
    if text.contains("fee on transfer") || text.contains("fee-on-transfer") {
        return StructuralRootCause::FeeOnTransferIncompatibility;
    }

    // ── Two-step patterns ──
    if text.contains("two-step") || text.contains("two step") {
        return StructuralRootCause::MissingAuthorityCheck;
    }

    // ── Reward and coverage ──
    if text.contains("reward") && (text.contains("steal") || text.contains("stolen")) {
        return StructuralRootCause::IncorrectInvariantAssumption;
    }
    if text.contains("coverage") && text.contains("zero") {
        return StructuralRootCause::IncorrectInvariantAssumption;
    }

    StructuralRootCause::Other(finding.title.clone())
}

/// Classify the protocol domain for a finding.
pub fn classify_protocol_domain(
    finding: &ExtractedFinding,
    report: &AuditReport,
) -> ProtocolDomain {
    let text = format!(
        "{} {} {} {}",
        finding.title, finding.description, finding.impact, report.protocol_name
    )
    .to_lowercase();

    // Vaults / ERC-4626
    if text.contains("vault")
        || text.contains("erc-4626")
        || text.contains("erc4626")
        || text.contains("share price")
    {
        return ProtocolDomain::Vaults;
    }

    // AMMs
    if text.contains("amm")
        || text.contains("liquidity pool")
        || text.contains("swap pool")
        || text.contains("constant product")
        || text.contains("concentrated liquidity")
    {
        return ProtocolDomain::AMMs;
    }

    // Lending
    if text.contains("lending")
        || text.contains("borrow")
        || text.contains("collateral")
        || text.contains("liquidation")
        || text.contains("health factor")
    {
        return ProtocolDomain::Lending;
    }

    // Liquid staking
    if text.contains("liquid staking")
        || text.contains("steth")
        || text.contains("rebase")
        || (text.contains("staking") && text.contains("withdrawal"))
    {
        return ProtocolDomain::LiquidStaking;
    }

    // Restaking
    if text.contains("restaking")
        || text.contains("eigenlayer")
        || text.contains("symbiotic")
        || text.contains("slashing")
    {
        return ProtocolDomain::Restaking;
    }

    // Bridges
    if text.contains("bridge")
        || text.contains("cross-chain")
        || text.contains("cross chain")
        || text.contains("wrapped token")
        || text.contains("lock and mint")
    {
        return ProtocolDomain::Bridges;
    }

    // Governance
    if text.contains("governance")
        || text.contains("voting")
        || text.contains("proposal")
        || text.contains("timelock")
        || text.contains("dao")
    {
        return ProtocolDomain::Governance;
    }

    // Cross-chain messaging
    if text.contains("layerzero")
        || text.contains("wormhole")
        || text.contains("axelar")
        || text.contains("ccip")
        || text.contains("message passing")
    {
        return ProtocolDomain::CrossChainMessaging;
    }

    // Stablecoins
    if text.contains("stablecoin") || text.contains("peg") || text.contains("mint and burn") {
        return ProtocolDomain::Stablecoins;
    }

    // Perpetuals
    if text.contains("perpetual")
        || text.contains("perp")
        || text.contains("funding rate")
        || text.contains("position") && text.contains("leverage")
    {
        return ProtocolDomain::Perpetuals;
    }

    // Options
    if text.contains("option")
        || text.contains("call option")
        || text.contains("put option")
        || text.contains("strike price")
    {
        return ProtocolDomain::Options;
    }

    // Derivatives
    if text.contains("derivative") || text.contains("futures") || text.contains("synthetic") {
        return ProtocolDomain::Derivatives;
    }

    // Yield aggregators
    if text.contains("yield")
        || text.contains("strategy")
        || text.contains("auto-compound")
        || text.contains("optimizer")
    {
        return ProtocolDomain::YieldAggregators;
    }

    // Auctions
    if text.contains("auction")
        || text.contains("dutch auction")
        || text.contains("english auction")
    {
        return ProtocolDomain::Auctions;
    }

    // Account abstraction
    if text.contains("account abstraction")
        || text.contains("erc-4337")
        || text.contains("erc4337")
        || text.contains("smart wallet")
        || text.contains("bundler")
    {
        return ProtocolDomain::AccountAbstraction;
    }

    // Token standards
    if text.contains("erc-20")
        || text.contains("erc20")
        || text.contains("erc-721")
        || text.contains("erc721")
        || text.contains("erc-1155")
        || text.contains("erc1155")
        || text.contains("nft")
    {
        return ProtocolDomain::TokenStandards;
    }

    // Oracles
    if text.contains("oracle")
        || text.contains("price feed")
        || text.contains("chainlink")
        || text.contains("twap")
    {
        return ProtocolDomain::Oracles;
    }

    // MEV
    if text.contains("mev") || text.contains("flashbot") || text.contains("builder") {
        return ProtocolDomain::MEVInfrastructure;
    }

    ProtocolDomain::Generic
}

/// Infer the specific protocol pattern within a domain.
pub fn infer_protocol_pattern(
    finding: &ExtractedFinding,
    domain: &ProtocolDomain,
) -> Option<String> {
    let text = format!("{} {}", finding.title, finding.description).to_lowercase();

    match domain {
        ProtocolDomain::Vaults => {
            if text.contains("inflation attack") || text.contains("first depositor") {
                return Some("vault_inflation_attack".into());
            }
            if text.contains("share price") || text.contains("exchange rate") {
                return Some("share_price_manipulation".into());
            }
            if text.contains("deposit") && text.contains("mint") {
                return Some("deposit_mint_accounting".into());
            }
        }
        ProtocolDomain::AMMs => {
            if text.contains("sandwich") {
                return Some("sandwich_attack".into());
            }
            if text.contains("impermanent loss") {
                return Some("impermanent_loss".into());
            }
            if text.contains("fee") && text.contains("distribution") {
                return Some("fee_distribution".into());
            }
        }
        ProtocolDomain::Lending => {
            if text.contains("liquidation") {
                return Some("liquidation_mechanism".into());
            }
            if text.contains("interest rate") || text.contains("utilization") {
                return Some("interest_rate_model".into());
            }
            if text.contains("flash loan") {
                return Some("flash_loan_mechanism".into());
            }
            if text.contains("oracle") && text.contains("price") {
                return Some("oracle_price_feed".into());
            }
        }
        ProtocolDomain::Bridges => {
            if text.contains("message") && text.contains("validation") {
                return Some("message_validation".into());
            }
            if text.contains("lock") && text.contains("mint") {
                return Some("lock_and_mint".into());
            }
        }
        ProtocolDomain::Governance => {
            if text.contains("timelock") {
                return Some("timelock_mechanism".into());
            }
            if text.contains("voting") && text.contains("power") {
                return Some("voting_power".into());
            }
        }
        ProtocolDomain::Stablecoins => {
            if text.contains("peg") && text.contains("stability") {
                return Some("peg_stability".into());
            }
            if text.contains("mint") && text.contains("burn") {
                return Some("mint_burn_mechanism".into());
            }
        }
        _ => {}
    }

    None
}

/// Map FindingSeverity to digger_ir::Severity.
pub fn map_severity(severity: &FindingSeverity) -> digger_ir::Severity {
    match severity {
        FindingSeverity::Critical => digger_ir::Severity::Critical,
        FindingSeverity::High => digger_ir::Severity::High,
        FindingSeverity::Medium => digger_ir::Severity::Medium,
        FindingSeverity::Low => digger_ir::Severity::Low,
        FindingSeverity::Informational => digger_ir::Severity::Info,
    }
}

/// Compute deterministic finding hash.
fn compute_finding_hash(report_id: &str, finding_id: &str) -> String {
    let mut h: u64 = 0;
    for byte in report_id.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    for byte in finding_id.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    format!("{:x}", h)
}

/// Normalize an entire AuditReport into NormalizedKnowledge.
///
/// This is the primary entry point for converting source-specific
/// extracted data into the canonical representation consumed by
/// the reasoning engine.
pub fn normalize_report(report: &AuditReport) -> NormalizedKnowledge {
    // Normalize all findings
    let normalized_findings: Vec<NormalizedFinding> = report
        .findings
        .iter()
        .map(|f| normalize_finding(f, report))
        .collect();

    // Build knowledge evidence from findings
    let evidence = build_knowledge_evidence(&normalized_findings, report);

    // Extract invariants from privileged roles and centralization notes
    let invariants = extract_invariants_from_report(report);

    // Build knowledge ID
    let knowledge_id = format!("knowledge:{}", report.report_id);

    NormalizedKnowledge {
        knowledge_id,
        source_id: report.source_repo.clone(),
        source_kind: KnowledgeSourceKind::AuditRepository,
        source_identifier: report.source_path.clone(),
        subject: report.protocol_name.clone(),
        subject_category: report.protocol_category.to_string(),
        findings: normalized_findings,
        evidence,
        invariants,
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![],
        claims: vec![],
        raw_sections: report.raw_sections.clone(),
    }
}

/// Build knowledge evidence items from normalized findings.
fn build_knowledge_evidence(
    findings: &[NormalizedFinding],
    report: &AuditReport,
) -> Vec<KnowledgeEvidence> {
    let mut evidence = Vec::new();

    for finding in findings {
        evidence.push(KnowledgeEvidence {
            evidence_id: format!("ev:{}", finding.finding_id),
            kind: KnowledgeEvidenceKind::HistoricalFinding(HistoricalFindingEvidence {
                finding_id: finding.finding_id.clone(),
                protocol_name: finding.protocol_name.clone(),
                vulnerability_class: finding.vulnerability_class.to_string(),
                attack_goal: finding.attack_goal.clone(),
                root_cause: finding.root_cause.to_string(),
                severity: finding.severity.clone(),
                impacted_functions: finding.impacted_functions.clone(),
            }),
            description: format!(
                "Historical finding: [{}] {}",
                finding.original_finding_id, finding.description_text
            ),
            confidence: KnowledgeConfidence::single_finding(&report.source_repo),
            source: report.source_repo.clone(),
            related_findings: vec![finding.finding_id.clone()],
        });
    }

    evidence
}

/// Extract security invariants from report content.
fn extract_invariants_from_report(report: &AuditReport) -> Vec<SecurityInvariant> {
    let mut invariants = Vec::new();

    // Extract from privileged roles
    for role in &report.privileged_roles {
        invariants.push(SecurityInvariant {
            invariant_id: format!(
                "inv:role:{}",
                role.role_name.to_lowercase().replace(' ', "_")
            ),
            description: format!("Access control: {} must be restricted", role.role_name),
            kind: "authority".into(),
            properties: role.functions.clone(),
            is_violated: false,
            context: report.protocol_name.clone(),
        });
    }

    // Extract from centralization notes
    for (i, note) in report.centralization_notes.iter().enumerate() {
        let lower = note.to_lowercase();
        if lower.contains("trust") || lower.contains("centralized") || lower.contains("admin") {
            invariants.push(SecurityInvariant {
                invariant_id: format!("inv:centralization:{}:{}", report.protocol_name, i),
                description: note.clone(),
                kind: "centralization".into(),
                properties: vec![],
                is_violated: false,
                context: report.protocol_name.clone(),
            });
        }
    }

    invariants
}
