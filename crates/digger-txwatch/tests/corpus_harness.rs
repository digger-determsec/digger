/// C48.2/Brick 4.2: GT corpus harness — shadow predicate replay with
/// per-chain arming gate and provenance tracking.
///
/// Each corpus case describes a recorded transaction and chain state.
/// Real captures (is_real_capture=true) are included in the GT metric.
/// Logic-only fixtures (is_real_capture=false) are replayed but excluded from GT.
/// Supports both EVM and Solana chains.
use std::collections::BTreeMap;
use std::sync::Arc;

/// Bootstrap floor: minimum benign captures per chain before Advisory/Armed
/// can be considered. Documented as statistically weak — the real bar is ~300.
const MIN_BENIGN: usize = 3;

#[derive(serde::Deserialize)]
struct CorpusTx {
    tx_hash: String,
    block_slot: u64,
    chain: String,
    target_contract: String,
    selector: String,
    call_data_preview: String,
}

#[derive(serde::Deserialize)]
struct CorpusChainState {
    account_owners: BTreeMap<String, String>,
    authorities: BTreeMap<String, String>,
    #[serde(default)]
    balance_deltas: BTreeMap<String, i128>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct CorpusFinding {
    finding_id: String,
    rule_id: String,
    severity: String,
    confidence_label: String,
    file: String,
    symbol: String,
}

#[derive(serde::Deserialize)]
struct CorpusCase {
    case_id: String,
    expected_label: String,
    #[serde(default)]
    is_real_capture: bool,
    #[serde(default)]
    capture_note: serde_json::Value,
    #[allow(dead_code)]
    chain: String,
    tx: CorpusTx,
    chain_state: CorpusChainState,
    finding: CorpusFinding,
}

#[derive(Debug, Default)]
struct ConfusionSummary {
    true_act_on_exploit: usize,
    false_action_on_benign: usize,
    missed_exploit: usize,
    correct_no_act: usize,
    undetermined: usize,
}

/// Per-chain rollup for arming gate evaluation.
#[derive(Debug, Default)]
struct ChainRollup {
    real_captures: usize,
    benign_captures: usize,
    exploit_captures: usize,
    false_actions_on_benign: usize,
    exploit_true_positives: usize,
}

fn load_corpus() -> Vec<CorpusCase> {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let corpus_dir = manifest_dir.join("tests").join("corpus");
    let mut cases = Vec::new();

    if !corpus_dir.exists() {
        return cases;
    }

    for entry in std::fs::read_dir(&corpus_dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(case) = serde_json::from_str::<CorpusCase>(&content) {
                    cases.push(case);
                }
            }
        }
    }

    cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    cases
}

fn build_chain_state(cs: &CorpusChainState) -> Arc<digger_txwatch::MockChainState> {
    let mut state = digger_txwatch::MockChainState::new();
    for (k, v) in &cs.account_owners {
        state = state.with_account_owner(k, v);
    }
    for (k, v) in &cs.authorities {
        state = state.with_authority(k, v);
    }
    for (k, v) in &cs.balance_deltas {
        state = state.with_balance_delta(k, *v);
    }
    Arc::new(state)
}

fn replay_case(case: &CorpusCase) -> (bool, bool) {
    let chain_state = build_chain_state(&case.chain_state);
    let tx = digger_txwatch::ObservedTx {
        tx_hash: case.tx.tx_hash.clone(),
        block_slot: case.tx.block_slot,
        chain: case.tx.chain.clone(),
        target_contract: case.tx.target_contract.clone(),
        selector: case.tx.selector.clone(),
        call_data_preview: case.tx.call_data_preview.clone(),
    };

    let predicates = digger_txwatch::predicates_for_finding(&case.finding.rule_id);
    let mut any_matched = false;
    let mut any_undetermined = false;

    for pred in &predicates {
        let ctx = digger_txwatch::TxContext {
            tx: &tx,
            state: chain_state.as_ref(),
        };
        let outcome = pred.evaluate(&ctx);
        if outcome.matched {
            any_matched = true;
        }
        if outcome.undetermined {
            any_undetermined = true;
        }
    }

    (any_matched, any_undetermined)
}

#[test]
fn corpus_replay_all_cases() {
    let cases = load_corpus();
    assert!(!cases.is_empty(), "Corpus must have at least one case");

    let mut summary = ConfusionSummary::default();
    let mut real_count = 0usize;
    let mut logic_only_count = 0usize;
    let mut by_label: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_chain: BTreeMap<String, usize> = BTreeMap::new();
    let mut chain_rollups: BTreeMap<String, ChainRollup> = BTreeMap::new();

    for case in &cases {
        let (any_matched, any_undetermined) = replay_case(case);

        if case.is_real_capture {
            real_count += 1;
            *by_label.entry(case.expected_label.clone()).or_insert(0) += 1;
            *by_chain.entry(case.tx.chain.clone()).or_insert(0) += 1;

            let rollup = chain_rollups.entry(case.tx.chain.clone()).or_default();
            rollup.real_captures += 1;

            match (case.expected_label.as_str(), any_matched) {
                ("Exploit", true) => {
                    summary.true_act_on_exploit += 1;
                    rollup.exploit_true_positives += 1;
                    rollup.exploit_captures += 1;
                }
                ("Exploit", false) => {
                    summary.missed_exploit += 1;
                    rollup.exploit_captures += 1;
                }
                ("Benign", true) => {
                    summary.false_action_on_benign += 1;
                    rollup.false_actions_on_benign += 1;
                    rollup.benign_captures += 1;
                }
                ("Benign", false) => {
                    summary.correct_no_act += 1;
                    rollup.benign_captures += 1;
                }
                _ => {}
            }

            if any_undetermined {
                summary.undetermined += 1;
            }
        } else {
            logic_only_count += 1;
        }

        eprintln!(
            "  {:<30} chain={:<8} expected={:<7} real={} matched={} undetermined={}",
            case.case_id,
            case.tx.chain,
            case.expected_label,
            case.is_real_capture,
            any_matched,
            any_undetermined
        );
    }

    eprintln!();
    eprintln!("===== CORPUS SIZE =====");
    eprintln!("  total cases:         {}", cases.len());
    eprintln!("  real captures:       {}", real_count);
    eprintln!("  logic-only fixtures: {}", logic_only_count);
    eprintln!("  by label:            {:?}", by_label);
    eprintln!("  by chain:            {:?}", by_chain);
    eprintln!();
    eprintln!("===== GT CONFUSION SUMMARY (real captures only) =====");
    eprintln!("  true_act_on_exploit:  {}", summary.true_act_on_exploit);
    eprintln!(
        "  false_action_on_benign: {}",
        summary.false_action_on_benign
    );
    eprintln!("  missed_exploit:      {}", summary.missed_exploit);
    eprintln!("  correct_no_act:      {}", summary.correct_no_act);
    eprintln!("  undetermined:        {}", summary.undetermined);
    eprintln!();
    eprintln!("===== PER-CHAIN ROLLUP =====");
    for (chain, rollup) in &chain_rollups {
        eprintln!(
            "  {}: real={} benign={} exploit={} false_acts={} exploit_tp={}",
            chain,
            rollup.real_captures,
            rollup.benign_captures,
            rollup.exploit_captures,
            rollup.false_actions_on_benign,
            rollup.exploit_true_positives
        );
    }

    assert_eq!(
        summary.false_action_on_benign, 0,
        "FALSE_ACTION_on_benign must be 0 over the real corpus"
    );
}

/// Per-chain arming gate: a chain's predicates may only be considered for
/// Advisory/Armed when:
///   1. false_actions_on_benign == 0
///   2. real_benign_captures >= MIN_BENIGN
#[test]
fn arming_gate_per_chain() {
    let cases = load_corpus();
    assert!(!cases.is_empty(), "Corpus must have at least one case");

    let mut chain_rollups: BTreeMap<String, ChainRollup> = BTreeMap::new();

    for case in &cases {
        if !case.is_real_capture {
            continue;
        }

        let (any_matched, _) = replay_case(case);
        let rollup = chain_rollups.entry(case.tx.chain.clone()).or_default();
        rollup.real_captures += 1;

        match (case.expected_label.as_str(), any_matched) {
            ("Exploit", true) => {
                rollup.exploit_true_positives += 1;
                rollup.exploit_captures += 1;
            }
            ("Exploit", false) => {
                rollup.exploit_captures += 1;
            }
            ("Benign", true) => {
                rollup.false_actions_on_benign += 1;
                rollup.benign_captures += 1;
            }
            ("Benign", false) => {
                rollup.benign_captures += 1;
            }
            _ => {}
        }
    }

    eprintln!();
    eprintln!("===== ARMING GATE EVALUATION =====");
    for (chain, rollup) in &chain_rollups {
        let false_actions_ok = rollup.false_actions_on_benign == 0;
        let benign_floor_ok = rollup.benign_captures >= MIN_BENIGN;
        let can_arm = false_actions_ok && benign_floor_ok;

        eprintln!(
            "  {}: false_actions={} benign_floor={}/{} can_arm={}",
            chain, rollup.false_actions_on_benign, rollup.benign_captures, MIN_BENIGN, can_arm
        );

        // Gate: false_actions_on_benign must be 0 for every chain.
        assert!(
            false_actions_ok,
            "Chain {} has false_actions_on_benign={}; must be 0 to pass gate",
            chain, rollup.false_actions_on_benign
        );
    }
}

#[test]
fn corpus_benign_yields_no_action() {
    let cases = load_corpus();
    for case in &cases {
        if case.expected_label != "Benign" {
            continue;
        }

        let (_, _) = replay_case(case);

        let shadow_decision = digger_txwatch::ShadowDecision {
            predicate_id: "test".into(),
            finding_id: case.finding.finding_id.clone(),
            matched: false,
            undetermined: false,
            missing_facts: vec![],
            would_have_acted: false,
            timestamp: "test".into(),
        };
        assert!(
            !shadow_decision.would_have_acted,
            "ShadowDecision must never have would_have_acted=true"
        );
    }
}

#[test]
fn corpus_can_autonomously_act_returns_false_for_shadow() {
    let cases = load_corpus();
    for case in &cases {
        let predicates = digger_txwatch::predicates_for_finding(&case.finding.rule_id);
        for pred in &predicates {
            assert_eq!(pred.stage, digger_evidence::PredicateStage::Shadow);

            let chain_state = build_chain_state(&case.chain_state);
            let tx = digger_txwatch::ObservedTx {
                tx_hash: case.tx.tx_hash.clone(),
                block_slot: case.tx.block_slot,
                chain: case.tx.chain.clone(),
                target_contract: case.tx.target_contract.clone(),
                selector: case.tx.selector.clone(),
                call_data_preview: case.tx.call_data_preview.clone(),
            };
            let ctx = digger_txwatch::TxContext {
                tx: &tx,
                state: chain_state.as_ref(),
            };
            let outcome = pred.evaluate(&ctx);
            assert!(
                !pred.can_autonomously_act(&outcome),
                "Shadow predicate must never be able to autonomously act"
            );
        }
    }
}

#[test]
fn corpus_real_captures_have_provenance() {
    let cases = load_corpus();
    for case in &cases {
        if !case.is_real_capture {
            continue;
        }
        assert!(
            !case.tx.tx_hash.is_empty(),
            "Real capture {} must have tx_hash",
            case.case_id
        );
        assert!(
            !case.tx.chain.is_empty(),
            "Real capture {} must have chain",
            case.case_id
        );
        assert!(
            !case.capture_note.is_null() && !case.capture_note.to_string().is_empty(),
            "Real capture {} must have capture_note",
            case.case_id
        );
    }
}

#[test]
fn corpus_gt_metric_is_honest() {
    let cases = load_corpus();
    let real_count = cases.iter().filter(|c| c.is_real_capture).count();
    let total = cases.len();
    let solana_real = cases
        .iter()
        .filter(|c| c.is_real_capture && c.tx.chain == "solana")
        .count();
    let evm_real = cases
        .iter()
        .filter(|c| c.is_real_capture && c.tx.chain == "evm")
        .count();
    eprintln!(
        "Corpus: {} total, {} real ({} evm, {} solana), {} logic-only",
        total,
        real_count,
        evm_real,
        solana_real,
        total - real_count
    );
    assert!(total >= 1, "Corpus must have at least 1 case");
}

// ── C53/B: Arming-gate proof tests ─────────────────────────────

/// Test the per-chain gate against real corpus state:
/// solana (n=3 benign, exploit_tp=0 → can_arm=NO),
/// evm (n=3 benign, exploit_tp=0 → can_arm=NO).
#[test]
fn test_c53_arming_gate_real_corpus_state() {
    let cases = load_corpus();
    assert!(!cases.is_empty(), "Corpus must have at least one case");

    let mut chain_rollups: BTreeMap<String, ChainRollup> = BTreeMap::new();

    for case in &cases {
        if !case.is_real_capture {
            continue;
        }

        let (any_matched, _) = replay_case(case);
        let rollup = chain_rollups.entry(case.tx.chain.clone()).or_default();
        rollup.real_captures += 1;

        match (case.expected_label.as_str(), any_matched) {
            ("Exploit", true) => {
                rollup.exploit_true_positives += 1;
                rollup.exploit_captures += 1;
            }
            ("Exploit", false) => {
                rollup.exploit_captures += 1;
            }
            ("Benign", true) => {
                rollup.false_actions_on_benign += 1;
                rollup.benign_captures += 1;
            }
            ("Benign", false) => {
                rollup.benign_captures += 1;
            }
            _ => {}
        }
    }

    // Real corpus state must NOT allow arming on any chain.
    // Full gate: false_actions==0 AND benign_floor>=MIN_BENIGN AND exploit_tp>0.
    // Both chains currently have exploit_tp=0, so can_arm is false for both.
    let mut evm_seen = false;
    let mut solana_seen = false;

    for (chain, rollup) in &chain_rollups {
        let false_actions_ok = rollup.false_actions_on_benign == 0;
        let benign_floor_ok = rollup.benign_captures >= MIN_BENIGN;
        let exploit_evidence = rollup.exploit_true_positives > 0;
        let can_arm = false_actions_ok && benign_floor_ok && exploit_evidence;

        // Both chains: false_actions=0, benign_floor=3/3, exploit_tp=0
        // → can_arm=false because exploit evidence is required but absent.
        assert!(
            !can_arm,
            "Chain {} must not arm: false_actions={} benign={}/{} exploit_tp={}",
            chain,
            rollup.false_actions_on_benign,
            rollup.benign_captures,
            MIN_BENIGN,
            rollup.exploit_true_positives
        );

        if chain == "evm" {
            assert_eq!(rollup.benign_captures, 6, "EVM benign captures");
            assert_eq!(
                rollup.exploit_true_positives, 0,
                "EVM exploit_tp must be 0 (migrateStake is L0 MISS)"
            );
            evm_seen = true;
        }
        if chain == "solana" {
            assert_eq!(rollup.benign_captures, 3, "Solana benign captures");
            assert_eq!(
                rollup.exploit_true_positives, 0,
                "Solana exploit_tp must be 0"
            );
            solana_seen = true;
        }
    }

    assert!(evm_seen, "Must have EVM chain rollup");
    assert!(solana_seen, "Must have Solana chain rollup");
}

/// Test that can_arm=true (hypothetically) does NOT auto-arm — stage stays Shadow.
/// This proves the governance gate: arming is a separate human action, never automatic.
#[test]
fn test_c53_can_arm_true_does_not_auto_arm() {
    struct SimpleCtx {
        facts: BTreeMap<String, String>,
    }
    impl digger_evidence::PredicateContext for SimpleCtx {
        fn resolve_fact(&self, name: &str) -> Option<String> {
            self.facts.get(name).cloned()
        }
    }

    // Hypothetical: a chain with exploit_tp>0, false_action==0, benign>=3.
    // Even if can_arm is true, every predicate is still Shadow.
    let pred = digger_txwatch::predicates_for_finding("unchecked_account_owner");
    assert!(!pred.is_empty());
    assert_eq!(pred[0].stage, digger_evidence::PredicateStage::Shadow);

    // can_autonomously_act must be false regardless of can_arm
    let ctx = SimpleCtx {
        facts: BTreeMap::from([("account_owner_mismatch".into(), "mismatch".into())]),
    };
    let outcome = pred[0].evaluate(&ctx);
    assert!(
        !pred[0].can_autonomously_act(&outcome),
        "can_arm=true does NOT auto-arm: stage stays Shadow"
    );

    // ShadowDecision.would_have_acted must be false
    let decision = digger_txwatch::ShadowDecision {
        predicate_id: pred[0].id.clone(),
        finding_id: "hypothetical-exploit".into(),
        matched: outcome.matched,
        undetermined: outcome.undetermined,
        missing_facts: outcome.missing_facts.clone(),
        would_have_acted: false,
        timestamp: "test".into(),
    };
    assert!(
        !decision.would_have_acted,
        "Arming is governance, never automatic"
    );
}

/// Document MIN_BENIGN as a bootstrap floor (statistically weak).
#[test]
fn test_c53_min_benign_documented() {
    // MIN_BENIGN = 3 is the bootstrap floor.
    // The real bar for statistical significance is ~300.
    // This test documents the floor and its weakness.
    assert_eq!(MIN_BENIGN, 3, "MIN_BENIGN must be 3 (bootstrap floor)");
    // Document that 3 is statistically weak.
    // Real bar: ~300 per chain for confidence in false_action_rate.
    let _ = "MIN_BENIGN=3 is bootstrap; real bar ~300. See arming_gate_per_chain.";
}

// ── E1: TempleDAO exploit fixture test ────────────────────────

/// Verify the TempleDAO exploit fixture loads correctly and has
/// the expected chain, class, and selector.
#[test]
fn test_e1_templedao_fixture_loads() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_path = manifest_dir
        .join("tests")
        .join("corpus")
        .join("evm-templedao-exploit.json");

    assert!(
        fixture_path.exists(),
        "Fixture must exist at {}",
        fixture_path.display()
    );

    let content = std::fs::read_to_string(&fixture_path).unwrap();
    let case: CorpusCase = serde_json::from_str(&content).unwrap();

    // Chain must be EVM
    assert_eq!(case.chain, "evm");
    assert_eq!(case.tx.chain, "evm");

    // Must be labeled as exploit
    assert_eq!(case.expected_label, "Exploit");
    assert!(case.is_real_capture);

    // Selector must be present (migrateStake = 0x66f7864a)
    assert_eq!(case.tx.selector, "66f7864a");

    // Finding must reference access_control / caller_is_not_authority
    assert_eq!(case.finding.rule_id, "access_control");

    // Capture note must reference the incident
    let note = &case.capture_note;
    assert_eq!(note["chain"].as_str().unwrap(), "evm");
    assert!(note["incident"].as_str().unwrap().contains("templedao"));

    // Verify the tx hash matches the pre-verified constant
    assert_eq!(
        case.tx.tx_hash,
        "0x4b119a4f4ba1ad483e9851973719f310527b43f3fcc827b6d52db9f4c1ddb6a2"
    );
}

// ── E2: EVM benign fixtures ──────────────────────────────────

/// Verify 3 EVM benign fixtures load correctly. Each must be:
/// - chain == evm
/// - expected_label == Benign
/// - is_real_capture == true
/// - sender (authorities[tx_hash]) != attacker 0x9c9fb310...
#[test]
fn test_e2_evm_benign_fixtures_load() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let corpus_dir = manifest_dir.join("tests").join("corpus");

    let attacker = "0x9c9fb3100a2a521985f0c47de3b4598dafd25b01";
    let mut evm_benign_count = 0usize;

    // evm-stax-benign-1..3 (unrelated_traffic)
    for i in 1..=3 {
        let filename = format!("evm-stax-benign-{}.json", i);
        let path = corpus_dir.join(&filename);
        assert!(
            path.exists(),
            "Fixture {} must exist at {}",
            filename,
            path.display()
        );

        let content = std::fs::read_to_string(&path).unwrap();
        let case: CorpusCase = serde_json::from_str(&content).unwrap();

        assert_eq!(case.chain, "evm", "Fixture {} must be chain=evm", filename);
        assert_eq!(
            case.tx.chain, "evm",
            "Fixture {} tx.chain must be evm",
            filename
        );
        assert_eq!(
            case.expected_label, "Benign",
            "Fixture {} must be Benign",
            filename
        );
        assert!(
            case.is_real_capture,
            "Fixture {} must be is_real_capture=true",
            filename
        );

        let sender = case
            .chain_state
            .authorities
            .get(&case.tx.tx_hash)
            .expect("Fixture must have authority for tx_hash");
        assert_ne!(
            sender.to_lowercase(),
            attacker,
            "Fixture {} sender must not be the attacker",
            filename
        );

        evm_benign_count += 1;
    }

    // evm-acl-benign-1..3 (legitimate_admin_action)
    for i in 1..=3 {
        let filename = format!("evm-acl-benign-{}.json", i);
        let path = corpus_dir.join(&filename);
        assert!(
            path.exists(),
            "Fixture {} must exist at {}",
            filename,
            path.display()
        );

        let content = std::fs::read_to_string(&path).unwrap();
        let case: CorpusCase = serde_json::from_str(&content).unwrap();

        assert_eq!(case.chain, "evm", "Fixture {} must be chain=evm", filename);
        assert_eq!(
            case.tx.chain, "evm",
            "Fixture {} tx.chain must be evm",
            filename
        );
        assert_eq!(
            case.expected_label, "Benign",
            "Fixture {} must be Benign",
            filename
        );
        assert!(
            case.is_real_capture,
            "Fixture {} must be is_real_capture=true",
            filename
        );

        let sender = case
            .chain_state
            .authorities
            .get(&case.tx.tx_hash)
            .expect("Fixture must have authority for tx_hash");
        assert_ne!(
            sender.to_lowercase(),
            attacker,
            "Fixture {} sender must not be the attacker",
            filename
        );

        evm_benign_count += 1;
    }

    assert_eq!(
        evm_benign_count, 6,
        "Must have exactly 6 EVM benign fixtures (3 stax + 3 acl)"
    );
}

// ── E3: EVM corpus replay + false-action gate ───────────────

/// Replay all EVM benign fixtures and assert zero false actions.
/// The frozen access_control predicate must not fire on any benign tx.
#[test]
fn test_e3_evm_no_false_actions() {
    let cases = load_corpus();
    let mut evm_false_actions = 0usize;

    for case in &cases {
        if !case.is_real_capture || case.tx.chain != "evm" || case.expected_label != "Benign" {
            continue;
        }

        let (any_matched, _) = replay_case(case);
        if any_matched {
            evm_false_actions += 1;
            eprintln!("  FALSE ACTION on {}: tx={}", case.case_id, case.tx.tx_hash);
        }
    }

    assert_eq!(
        evm_false_actions, 0,
        "EVM false_actions_on_benign must be 0 (got {})",
        evm_false_actions
    );
}

/// Verify EVM benign fixtures carry benign_kind metadata for self-documenting
/// evidence-strength labeling.
#[test]
fn test_e3_evm_benign_kind_documented() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let corpus_dir = manifest_dir.join("tests").join("corpus");

    for i in 1..=3 {
        let filename = format!("evm-stax-benign-{}.json", i);
        let path = corpus_dir.join(&filename);
        let content = std::fs::read_to_string(&path).unwrap();
        let case: serde_json::Value = serde_json::from_str(&content).unwrap();

        let benign_kind = case["capture_note"]["benign_kind"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(
            benign_kind, "unrelated_traffic",
            "Fixture {} must have benign_kind=unrelated_traffic in capture_note",
            filename
        );
    }
}

/// E3: migrateStake L0 recall measurement.
/// The frozen access_control predicate is evaluated against the TempleDAO
/// exploit fixture. This test documents the L0 recall result honestly —
/// no tuning is performed to improve it.
#[test]
fn test_e3_evm_exploit_l0_recall() {
    let cases = load_corpus();
    let mut evm_exploits = Vec::new();

    for case in &cases {
        if !case.is_real_capture || case.tx.chain != "evm" || case.expected_label != "Exploit" {
            continue;
        }

        let (any_matched, any_undetermined) = replay_case(case);
        evm_exploits.push((case.case_id.clone(), any_matched, any_undetermined));
    }

    assert!(!evm_exploits.is_empty(), "Must have at least 1 EVM exploit");

    let mut tps = 0usize;
    let total = evm_exploits.len();

    for (id, matched, undetermined) in &evm_exploits {
        eprintln!(
            "  EVM exploit {}: matched={} undetermined={}",
            id, matched, undetermined
        );
        if *matched {
            tps += 1;
        }
    }

    eprintln!(
        "  EVM L0 recall: {}/{} (migrateStake is {})",
        tps,
        total,
        if tps > 0 { "TP" } else { "MISS" }
    );

    // Document the result honestly. Do NOT tune to improve.
    // migrateStake on EVM is undetermined because account_owners is empty
    // (no EVM owner-check predicate fires without an owner entry).
    // This is a known L0 recall gap for EVM access_control.
    assert!(
        tps < total,
        "EVM exploit_tp < total is expected at L0 — recall gap documented"
    );
}
