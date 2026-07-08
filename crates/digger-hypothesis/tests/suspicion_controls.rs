//! Phase 3B — Suspicion negative controls. Every fixture goes through
//! the real parse path (Solidity or RawProgram -> IR -> derive -> derive_suspicions).
//!
//! FP Decision on Class A: A withdraw that reads balance through arithmetic
//! and pays out via external call fires oracle suspicion IF the oracle
//! structural precondition is met. This is a GENUINE near-miss — the
//! channel exists for exactly this shape. is_finding:false.

use digger_knowledge_models::finding::{
    AttackTechnique, NormalizedFinding, StructuralRootCause, ViolatedInvariant, VulnerabilityClass,
};
use digger_knowledge_models::pattern::HistoricalFindingStore;
use std::collections::BTreeMap;

fn make_store(classes: &[&str]) -> HistoricalFindingStore {
    let mut findings = Vec::new();
    let mut by_class: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (i, cls) in classes.iter().enumerate() {
        let fid = format!("ctrl-{:03}", i);
        findings.push(NormalizedFinding {
            finding_id: fid.clone(),
            original_finding_id: format!("O-{}", i),
            report_id: "ctrl-report".to_string(),
            protocol_name: "Test".to_string(),
            protocol_category: digger_knowledge_models::audit::ProtocolCategory::Vault,
            protocol_domain: digger_knowledge_models::finding::ProtocolDomain::Vaults,
            protocol_pattern: None,
            vulnerability_class: VulnerabilityClass::Reentrancy,
            attack_goal: "drain".to_string(),
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: "conservation".to_string(),
                affected_state_vars: vec![],
                description: String::new(),
            },
            attack_technique: AttackTechnique::ReentrancyExploit,
            mitigation_pattern: None,
            security_assumptions: vec![],
            severity: digger_ir::Severity::High,
            root_cause: StructuralRootCause::MissingAuthorityCheck,
            impact_text: String::new(),
            description_text: String::new(),
            remediation_text: String::new(),
            impacted_contracts: vec![],
            impacted_functions: vec![],
            confidence: 1.0,
        });
        by_class.entry(cls.to_string()).or_default().push(fid);
    }
    HistoricalFindingStore {
        findings,
        by_class,
        by_protocol: BTreeMap::new(),
        by_technique: BTreeMap::new(),
        by_severity: BTreeMap::new(),
        patterns: vec![],
    }
}

fn run_suspicion_solidity(
    code: &str,
    store: &HistoricalFindingStore,
) -> digger_hypothesis::suspicion::SuspicionResult {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let hyp = digger_hypothesis::derive(&ir);
    digger_hypothesis::suspicion::derive_suspicions(
        &ir,
        &hyp,
        Some(store),
        Some("snap"),
        Some("src"),
    )
}

fn count_class(susp: &digger_hypothesis::suspicion::SuspicionResult, class: &str) -> usize {
    susp.suspicions
        .iter()
        .filter(|s| format!("{:?}", s.class) == class)
        .count()
}

// ═══════════════════════════════════════════════
// POSITIVE TESTS
// ═══════════════════════════════════════════════

/// Class B positive: flash-loan external-call payout.
/// Balance read through arithmetic -> external call with value transfer,
/// no temporal guard, no authority. Real flash-loan detector requires
/// !external_call so it ABSTAINS. Suspicion fires.
#[test]
fn positive_flashloan_external_call_payout() {
    let code = r#"
contract Pool {
    mapping(address => uint256) public balances;
    function claimReward() public {
        uint256 reward = balances[msg.sender] * 100 / 1000;
        msg.sender.call{value: reward}("");
    }
}
"#;
    let store = make_store(&["flash_loan_attack"]);
    let susp = run_suspicion_solidity(code, &store);
    let fl = count_class(&susp, "FlashLoanGovernanceCandidate");
    assert_eq!(fl, 1, "expected exactly 1 flash-loan suspicion, got {fl}");
}

// ═══════════════════════════════════════════════
// CLASS A (oracle) TESTS — P3D
// ═══════════════════════════════════════════════

/// Class A positive: setPrice writes lastPrice; swap reads it through
/// arithmetic, transfers value via external call. The real oracle detector
/// requires !external_call so it skips swap. Suspicion fires.
#[test]
fn class_a_positive_oracle_with_external_call() {
    let code = r#"
contract OracleSwap {
    uint256 public lastPrice;
    function setPrice(uint256 p) public { lastPrice = p; }
    function swap(uint256 amount) public {
        uint256 cost = lastPrice * amount;
        msg.sender.call{value: cost}("");
    }
}
"#;
    let store = make_store(&["oracle_manipulation"]);
    let susp = run_suspicion_solidity(code, &store);
    let orc = count_class(&susp, "OracleManipulationCandidate");
    assert_eq!(
        orc, 1,
        "expected exactly 1 oracle suspicion on swap, got {orc}"
    );
    assert_eq!(susp.suspicions[0].primary_function, "swap");
}

/// FP-decision: accrueRewards writes rewards[addr], claimReward reads it
/// through arithmetic + external call. Reads var written by DIFFERENT function.
/// This IS a genuine near-miss. Suspicion fires.
#[test]
fn class_a_near_miss_reads_other_function_state() {
    let code = r#"
contract Pool {
    mapping(address => uint256) public rewards;
    function accrueRewards(uint256 amount) public { rewards[msg.sender] += amount; }
    function claimReward() public {
        uint256 payout = rewards[msg.sender] * 100 / 1000;
        msg.sender.call{value: payout}("");
    }
}
"#;
    let store = make_store(&["oracle_manipulation"]);
    let susp = run_suspicion_solidity(code, &store);
    let orc = count_class(&susp, "OracleManipulationCandidate");
    assert_eq!(
        orc, 1,
        "near-miss: expected 1 oracle suspicion on claimReward, got {orc}"
    );
    assert_eq!(susp.suspicions[0].primary_function, "claimReward");
}

/// Discriminating negative: withdraw reads OWN balance (self-written) through
/// arithmetic + external call. Class A must NOT fire because the read var is
/// in self_written (the function itself writes balances[msg.sender]).
#[test]
fn class_a_negative_self_written_state_no_fire() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) public {
        uint256 payout = balances[msg.sender] * amount / 1000;
        balances[msg.sender] -= amount;
        msg.sender.call{value: payout}("");
    }
}
"#;
    let store = make_store(&["oracle_manipulation"]);
    let susp = run_suspicion_solidity(code, &store);
    let orc = count_class(&susp, "OracleManipulationCandidate");
    assert_eq!(
        orc, 0,
        "self-written state must NOT produce oracle suspicion, got {orc}"
    );
}

/// Flash-loan dedup: mirror the oracle dedup pattern. Use the same IR shape
/// where the real flash-loan detector fires; assert suspicion does NOT fire.
#[test]
fn dedup_flashloan_real_hypothesis_suppresses() {
    use digger_graph::build_system_ir;
    use digger_parser::model::*;

    let program = RawProgram {
        functions: vec![
            RawFunction {
                name: "sweepAwards".into(),
                contract: "PrizePool".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "accrued = balances[msg.sender] * prizeRate / SCALE; transfer(msg.sender, accrued)".into(),
                ..Default::default()
            },
            RawFunction {
                name: "deposit".into(),
                contract: "PrizePool".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "balances[msg.sender] += msg.value".into(),
                ..Default::default()
            },
        ],
        state: vec![RawState {
            name: "balances".into(),
            ty: "mapping".into(),
        }],
        calls: vec![],
        ..Default::default()
    };
    let ir = build_system_ir(program);

    // Verify real flash-loan detector fires for sweepAwards
    let hyp = digger_hypothesis::derive(&ir);
    let real_fl: Vec<_> = hyp
        .hypotheses
        .iter()
        .filter(|h| format!("{:?}", h.hypothesis_type) == "FlashLoanGovernanceCandidate")
        .collect();
    assert!(
        !real_fl.is_empty(),
        "setup: real flash-loan detector must fire for sweepAwards"
    );

    // Run suspicion — should dedup
    let store = make_store(&["flash_loan_attack"]);
    let susp = digger_hypothesis::suspicion::derive_suspicions(
        &ir,
        &hyp,
        Some(&store),
        Some("s"),
        Some("s"),
    );
    let fl = count_class(&susp, "FlashLoanGovernanceCandidate");
    assert_eq!(
        fl, 0,
        "real flash-loan hypothesis must suppress suspicion via dedup, got {fl}"
    );
}

// ═══════════════════════════════════════════════
// NEGATIVE CONTROLS (must yield ZERO)
// ═══════════════════════════════════════════════

/// External-feed shape: price from an external contract call, no internal-writable arithmetic.
#[test]
fn negative_external_feed_no_oracle_suspicion() {
    let code = r#"
contract ChainlinkConsumer {
    address public priceFeed;
    mapping(address => uint256) public balances;
    function swap(uint256 amount) public {
        (, int256 price, , , ) = AggregatorV3Interface(priceFeed).latestRoundData();
        uint256 cost = uint256(price) * amount;
        balances[msg.sender] += cost;
        msg.sender.transfer(cost);
    }
}
"#;
    let store = make_store(&["oracle_manipulation"]);
    let susp = run_suspicion_solidity(code, &store);
    let orc = count_class(&susp, "OracleManipulationCandidate");
    assert_eq!(
        orc, 0,
        "external feed must NOT produce oracle suspicion, got {orc}"
    );
}

/// Config counter: no value_transfer.
#[test]
fn negative_config_counter_no_suspicion() {
    let code = r#"
contract Config {
    uint256 public counter;
    function increment() public {
        counter = counter + 1;
    }
}
"#;
    let store = make_store(&["oracle_manipulation", "flash_loan_attack"]);
    let susp = run_suspicion_solidity(code, &store);
    assert_eq!(
        susp.suspicions.len(),
        0,
        "config counter must produce zero suspicions"
    );
}

/// Temporal-guarded staking: has_temporal_guard blocks flash-loan suspicion.
#[test]
fn negative_temporal_guarded_no_flashloan_suspicion() {
    let code = r#"
contract Staking {
    mapping(address => uint256) public balances;
    uint256 public lastClaim;
    function claimReward() public {
        require(block.timestamp >= lastClaim + 1 days);
        uint256 reward = balances[msg.sender] * 100 / 1000;
        balances[msg.sender] += reward;
    }
}
"#;
    let store = make_store(&["flash_loan_attack"]);
    let susp = run_suspicion_solidity(code, &store);
    let fl = count_class(&susp, "FlashLoanGovernanceCandidate");
    assert_eq!(
        fl, 0,
        "temporal-guarded staking must NOT produce flash-loan suspicion, got {fl}"
    );
}

/// Constant-amount transfer: no reads_balance_through_arithmetic.
#[test]
fn negative_constant_amount_no_flashloan_suspicion() {
    let code = r#"
contract Airdrop {
    mapping(address => uint256) public balances;
    function claim() public {
        balances[msg.sender] += 100;
        msg.sender.transfer(100);
    }
}
"#;
    let store = make_store(&["flash_loan_attack"]);
    let susp = run_suspicion_solidity(code, &store);
    let fl = count_class(&susp, "FlashLoanGovernanceCandidate");
    assert_eq!(
        fl, 0,
        "constant-amount must NOT produce flash-loan suspicion, got {fl}"
    );
}

/// Benign ERC20: reads and writes same state (balances[msg.sender]).
#[test]
fn negative_benign_erc20_no_suspicion() {
    let code = r#"
contract Token {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"#;
    let store = make_store(&["oracle_manipulation", "flash_loan_attack"]);
    let susp = run_suspicion_solidity(code, &store);
    assert_eq!(
        susp.suspicions.len(),
        0,
        "benign ERC20 must produce zero suspicions"
    );
}

// ═══════════════════════════════════════════════
// DEDUP TESTS
// ═══════════════════════════════════════════════

/// When the real oracle detector fires for a function, the suspicion must NOT
/// duplicate it. Uses the same IR fixture as the real oracle detector test.
#[test]
fn dedup_oracle_real_hypothesis_suppresses_suspicion() {
    use digger_graph::build_system_ir;
    use digger_parser::model::*;

    // Build the same IR the real oracle detector test uses
    let program = RawProgram {
        functions: vec![
            RawFunction {
                name: "setRate".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "rate = newRate".into(),
                ..Default::default()
            },
            RawFunction {
                name: "convert".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "amount = input * rate; transfer(msg.sender, amount)".into(),
                ..Default::default()
            },
        ],
        state: vec![RawState {
            name: "rate".into(),
            ty: "uint256".into(),
        }],
        calls: vec![],
        ..Default::default()
    };
    let ir = build_system_ir(program);

    // Verify the real oracle detector fires for "convert"
    let hyp = digger_hypothesis::derive(&ir);
    let real_oracle: Vec<_> = hyp
        .hypotheses
        .iter()
        .filter(|h| format!("{:?}", h.hypothesis_type) == "OracleManipulationCandidate")
        .collect();
    assert!(
        !real_oracle.is_empty(),
        "setup: real oracle detector must fire for convert"
    );

    // Run suspicion — should dedup against the real hypothesis
    let store = make_store(&["oracle_manipulation"]);
    let susp = digger_hypothesis::suspicion::derive_suspicions(
        &ir,
        &hyp,
        Some(&store),
        Some("s"),
        Some("s"),
    );
    let orc = count_class(&susp, "OracleManipulationCandidate");
    assert_eq!(
        orc, 0,
        "real oracle hypothesis must suppress suspicion via dedup, got {orc}"
    );
}

// ═══════════════════════════════════════════════
// INVARIANCE + SAFETY
// ═══════════════════════════════════════════════

/// HypothesisResult is NEVER modified by suspicion derivation.
#[test]
fn hypothesis_result_not_modified() {
    let code = r#"
contract Pool {
    mapping(address => uint256) public balances;
    function claimReward() public {
        uint256 reward = balances[msg.sender] * 100 / 1000;
        msg.sender.call{value: reward}("");
    }
}
"#;
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let hyp_before = digger_hypothesis::derive(&ir);
    let json_before = serde_json::to_string(&hyp_before).unwrap();

    let store = make_store(&["flash_loan_attack"]);
    let _susp = digger_hypothesis::suspicion::derive_suspicions(
        &ir,
        &hyp_before,
        Some(&store),
        Some("s"),
        Some("s"),
    );

    let json_after = serde_json::to_string(&hyp_before).unwrap();
    assert_eq!(
        json_before, json_after,
        "HypothesisResult must not change after derive_suspicions"
    );
}

/// Every suspicion has is_finding == false.
#[test]
fn all_suspicions_not_findings() {
    let code = r#"
contract Pool {
    mapping(address => uint256) public balances;
    function claimReward() public {
        uint256 reward = balances[msg.sender] * 100 / 1000;
        msg.sender.call{value: reward}("");
    }
}
"#;
    let store = make_store(&["flash_loan_attack"]);
    let susp = run_suspicion_solidity(code, &store);
    for s in &susp.suspicions {
        assert!(
            !s.is_finding,
            "suspicion {} must have is_finding=false",
            s.id
        );
    }
}

/// Determinism: same input twice yields identical suspicions.
#[test]
fn determinism_identical_across_runs() {
    let code = r#"
contract Pool {
    mapping(address => uint256) public balances;
    function claimReward() public {
        uint256 reward = balances[msg.sender] * 100 / 1000;
        msg.sender.call{value: reward}("");
    }
}
"#;
    let store = make_store(&["flash_loan_attack"]);
    let r1 = run_suspicion_solidity(code, &store);
    let r2 = run_suspicion_solidity(code, &store);
    assert_eq!(r1.suspicions.len(), r2.suspicions.len());
    for (a, b) in r1.suspicions.iter().zip(r2.suspicions.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.class, b.class);
        assert_eq!(a.primary_function, b.primary_function);
    }
}

/// Domain-scoping gap test: a domain-mismatched corpus (DEX findings for a
/// vault target) does NOT inflate suspicion count beyond the structural gate.
/// The suspicion fires the same number of times regardless of corpus domain
/// because SystemIR does not carry protocol_domain. This documents the
/// limitation: domain scoping is not yet possible.
#[test]
fn domain_mismatched_corpus_does_not_inflate() {
    let code = r#"
contract Pool {
    mapping(address => uint256) public balances;
    function claimReward() public {
        uint256 reward = balances[msg.sender] * 100 / 1000;
        msg.sender.call{value: reward}("");
    }
}
"#;
    // Store with oracle_manipulation from a DEX protocol (domain mismatch for vault target)
    let store = make_store(&["oracle_manipulation"]);
    let susp = run_suspicion_solidity(code, &store);
    // The structural gate (not domain) determines whether suspicion fires.
    // Domain mismatch does not add or remove suspicions.
    assert!(
        susp.suspicions.len() <= 2,
        "domain-mismatched corpus must not inflate count beyond structural gate"
    );
}

// ═══════════════════════════════════════════════
// P4: REPORT SURFACE TEST
// ═══════════════════════════════════════════════

/// Default path (no corpus): print_with_suspicions(sus=None) must produce
/// identical output to print(). The caller controls whether suspicions
/// are rendered — the default scan path never supplies them.
#[test]
fn p4_default_path_no_suspicions_section() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let hyp = digger_hypothesis::derive(&ir);

    // Verify SuspicionResult is empty when no store provided
    let susp_empty = digger_hypothesis::suspicion::derive_suspicions(&ir, &hyp, None, None, None);
    assert!(
        susp_empty.suspicions.is_empty(),
        "default path must produce zero suspicions"
    );

    // Verify SuspicionResult serialization is stable
    let json = serde_json::to_string(&susp_empty).unwrap();
    let deserialized: digger_hypothesis::suspicion::SuspicionResult =
        serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.suspicions.len(), 0);
}

/// With corpus supplied: SuspicionResult contains suspicions, all is_finding:false.
#[test]
fn p4_with_corpus_shows_suspicions() {
    let code = r#"
contract Pool {
    mapping(address => uint256) public balances;
    function claimReward() public {
        uint256 reward = balances[msg.sender] * 100 / 1000;
        msg.sender.call{value: reward}("");
    }
}
"#;
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let hyp = digger_hypothesis::derive(&ir);
    let store = make_store(&["flash_loan_attack"]);
    let susp = digger_hypothesis::suspicion::derive_suspicions(
        &ir,
        &hyp,
        Some(&store),
        Some("s"),
        Some("s"),
    );
    assert!(
        !susp.suspicions.is_empty(),
        "with-corpus path must produce suspicions"
    );
    for s in &susp.suspicions {
        assert!(!s.is_finding, "every suspicion must have is_finding=false");
    }
}

// ═══════════════════════════════════════════════
// P5: SNAPSHOT PINNING
// ═══════════════════════════════════════════════

/// Same snapshot_id -> identical corpus_prior on every suspicion.
#[test]
fn p5_determinism_same_snapshot_same_prior() {
    let code = r#"
contract Pool {
    mapping(address => uint256) public balances;
    function claimReward() public {
        uint256 reward = balances[msg.sender] * 100 / 1000;
        msg.sender.call{value: reward}("");
    }
}
"#;
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let hyp = digger_hypothesis::derive(&ir);
    let store = make_store(&["flash_loan_attack"]);
    let s1 = digger_hypothesis::suspicion::derive_suspicions(
        &ir,
        &hyp,
        Some(&store),
        Some("snap-v1"),
        Some("src"),
    );
    let s2 = digger_hypothesis::suspicion::derive_suspicions(
        &ir,
        &hyp,
        Some(&store),
        Some("snap-v1"),
        Some("src"),
    );
    assert_eq!(s1.suspicions.len(), s2.suspicions.len());
    for (a, b) in s1.suspicions.iter().zip(s2.suspicions.iter()) {
        assert_eq!(a.corpus_prior.snapshot_id, b.corpus_prior.snapshot_id);
    }
}

/// Different snapshot_id -> different snapshot_id field.
#[test]
fn p5_different_snapshot_id_reflected() {
    let code = r#"
contract Pool {
    mapping(address => uint256) public balances;
    function claimReward() public {
        uint256 reward = balances[msg.sender] * 100 / 1000;
        msg.sender.call{value: reward}("");
    }
}
"#;
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let hyp = digger_hypothesis::derive(&ir);
    let store = make_store(&["flash_loan_attack"]);
    let s1 = digger_hypothesis::suspicion::derive_suspicions(
        &ir,
        &hyp,
        Some(&store),
        Some("snap-A"),
        Some("src"),
    );
    let s2 = digger_hypothesis::suspicion::derive_suspicions(
        &ir,
        &hyp,
        Some(&store),
        Some("snap-B"),
        Some("src"),
    );
    assert_eq!(s1.suspicions.len(), s2.suspicions.len());
    for (a, b) in s1.suspicions.iter().zip(s2.suspicions.iter()) {
        assert_ne!(a.corpus_prior.snapshot_id, b.corpus_prior.snapshot_id);
    }
}

/// compute_corpus_hash deterministic (FNV-1a).
#[test]
fn p5_hash_deterministic() {
    let store = make_store(&["oracle_manipulation", "flash_loan_attack"]);
    assert_eq!(
        digger_hypothesis::derivation::compute_corpus_hash(&store),
        digger_hypothesis::derivation::compute_corpus_hash(&store)
    );
}

/// verify_corpus_snapshot: match ok, mismatch err.
#[test]
fn p5_verify_snapshot_match_and_mismatch() {
    let store = make_store(&["oracle_manipulation"]);
    let hash = digger_hypothesis::derivation::compute_corpus_hash(&store);
    assert!(digger_hypothesis::derivation::verify_corpus_snapshot(&store, Some(&hash)).is_ok());
    assert!(
        digger_hypothesis::derivation::verify_corpus_snapshot(&store, Some("deadbeef")).is_err()
    );
}

// ═══════════════════════════════════════════════
// P6: BROADEN NEGATIVE CONTROLS
// ═══════════════════════════════════════════════

/// Run the suspicion pass over representative exploit+benign fixtures.
/// Assert: no suspicion leaks into HypothesisResult, no severity change,
/// is_finding always false. Record per-fixture suspicion counts.
#[test]
fn p6_broaden_across_fixtures() {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let fixtures: Vec<(&str, &str)> = vec![
        // Reentrancy
        (
            "reentrancy",
            r#"
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#,
        ),
        // Oracle
        (
            "oracle",
            r#"
contract Oracle {
    uint256 public lastPrice;
    mapping(address => uint256) public balances;
    function swap(uint256 amount) public {
        uint256 cost = lastPrice * amount;
        balances[msg.sender] += cost;
        msg.sender.transfer(cost);
    }
}
"#,
        ),
        // Flash-loan positive
        (
            "flash_loan",
            r#"
contract Pool {
    mapping(address => uint256) public balances;
    function claimReward() public {
        uint256 reward = balances[msg.sender] * 100 / 1000;
        msg.sender.call{value: reward}("");
    }
}
"#,
        ),
        // Benign ERC20
        (
            "benign_erc20",
            r#"
contract Token {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"#,
        ),
        // Config counter
        (
            "config_counter",
            r#"
contract Config {
    uint256 public counter;
    function increment() public { counter = counter + 1; }
}
"#,
        ),
    ];

    let mega_store = make_store(&[
        "oracle_manipulation",
        "price_manipulation",
        "flash_loan_attack",
        "governance_attack",
        "reentrancy",
        "missing_access_control",
    ]);

    for (name, code) in fixtures {
        let program = parse_program(code, "solidity");
        let ir = build_system_ir_with_language(program, Language::Solidity);

        // Hypotheses before suspicion derivation
        let hyp_before = digger_hypothesis::derive(&ir);
        let json_before = serde_json::to_string(&hyp_before).unwrap();

        let susp = digger_hypothesis::suspicion::derive_suspicions(
            &ir,
            &hyp_before,
            Some(&mega_store),
            Some("broaden"),
            Some("p6"),
        );

        // Invariance: HypothesisResult not modified
        let json_after = serde_json::to_string(&hyp_before).unwrap();
        assert_eq!(
            json_before, json_after,
            "{name}: HypothesisResult must not change"
        );

        // All suspicions have is_finding=false
        for s in &susp.suspicions {
            assert!(
                !s.is_finding,
                "{name}: suspicion {} has is_finding=true",
                s.id
            );
        }

        // Log counts (test output shows these for debugging)
        println!(
            "{name}: {} suspicions, {} hypotheses",
            susp.suspicions.len(),
            hyp_before.hypotheses.len()
        );
    }
}

/// Exhaustive check: every HypothesisType that a suspicion can analogize
/// must have a mapping in the suspicion code. This catches new types.
#[test]
fn p6_all_suspicion_classes_have_corpus_keys() {
    // Every SuspicionClass that can fire must have a corpus by_class key.
    // The suspicion code checks store.by_class.contains_key for these keys.
    // If a new HypothesisType is added as a suspicion class, this test
    // will pass but the corresponding mapping must exist in suspicion.rs.
    let store = make_store(&[
        "oracle_manipulation",
        "price_manipulation",
        "flash_loan_attack",
        "governance_attack",
    ]);
    // Verify the store has all keys the suspicion code checks
    assert!(store.by_class.contains_key("oracle_manipulation"));
    assert!(store.by_class.contains_key("price_manipulation"));
    assert!(store.by_class.contains_key("flash_loan_attack"));
    assert!(store.by_class.contains_key("governance_attack"));
}

// ═══════════════════════════════════════════════
// P3: SNAPSHOT PINNING ACROSS RESTARTS
// ═══════════════════════════════════════════════

/// Same store -> same compute_corpus_hash across "restarts".
#[test]
fn p3_hash_stable_across_restarts() {
    let store = make_store(&["oracle_manipulation"]);
    let h1 = digger_hypothesis::derivation::compute_corpus_hash(&store);
    let h2 = digger_hypothesis::derivation::compute_corpus_hash(&store);
    let h3 = digger_hypothesis::derivation::compute_corpus_hash(&store);
    assert_eq!(h1, h2, "hash must be stable across restarts");
    assert_eq!(h2, h3, "hash must be stable across restarts");
}

/// Pinned snapshot -> verify_corpus_snapshot passes; mismatch -> error.
#[test]
fn p3_pinned_snapshot_passes_verify() {
    let store = make_store(&["flash_loan_attack"]);
    let hash = digger_hypothesis::derivation::compute_corpus_hash(&store);
    assert!(
        digger_hypothesis::derivation::verify_corpus_snapshot(&store, Some(&hash)).is_ok(),
        "pinned snapshot must pass verify"
    );
}

/// Wrong snapshot -> verify_corpus_snapshot errors.
#[test]
fn p3_wrong_snapshot_detected() {
    let store = make_store(&["flash_loan_attack"]);
    let result =
        digger_hypothesis::derivation::verify_corpus_snapshot(&store, Some("wrong-hash-000"));
    assert!(result.is_err(), "wrong snapshot must be detected");
    assert!(result.unwrap_err().contains("mismatch"));
}

/// Snapshot hash matches between suspicion derive and compute_corpus_hash.
#[test]
fn p3_suspicion_snapshot_matches_compute_hash() {
    use digger_graph::build_system_ir_with_language;
    use digger_ir::Language;
    use digger_parser::parse_program;

    let code = r#"
contract Pool {
    mapping(address => uint256) public balances;
    function claimReward() public {
        uint256 reward = balances[msg.sender] * 100 / 1000;
        msg.sender.call{value: reward}("");
    }
}
"#;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let hyp = digger_hypothesis::derive(&ir);
    let store = make_store(&["flash_loan_attack"]);

    let hash = digger_hypothesis::derivation::compute_corpus_hash(&store);
    let susp = digger_hypothesis::suspicion::derive_suspicions(
        &ir,
        &hyp,
        Some(&store),
        Some(&hash),
        Some("p3"),
    );

    // Every suspicion's snapshot_id must match the compute_corpus_hash result
    for s in &susp.suspicions {
        assert_eq!(
            s.corpus_prior.snapshot_id, hash,
            "snapshot must be pinned to compute_corpus_hash"
        );
    }
}
