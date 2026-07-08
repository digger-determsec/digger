/// Generalization Benchmark — Phase 7 validation
///
/// Tests Digger against exploits it has never been evaluated against.
/// Measures whether the existing architecture generalizes.
use digger_benchmark::*;
use digger_graph::build_system_ir;
use digger_hypothesis::analyze_compat as analyze;
use digger_parser::parse_program;

fn normalize(s: &str) -> String {
    s.trim().to_lowercase().replace('-', "_")
}

fn load_generalization_corpus() -> Vec<LoadedExploit> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let corpus_dir = workspace_root.join("corpus/generalization-benchmark");

    let mut exploits = vec![];

    for entry in std::fs::read_dir(&corpus_dir).unwrap().flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let meta_path = path.join("meta.json");
        let source_path = path.join("source.sol");

        if !meta_path.exists() || !source_path.exists() {
            continue;
        }

        let meta_str = std::fs::read_to_string(&meta_path).unwrap();
        let meta: ExploitMeta = serde_json::from_str(&meta_str).unwrap();
        let source = std::fs::read_to_string(&source_path).unwrap();

        exploits.push(LoadedExploit {
            meta,
            source_code: source,
            language: "solidity".into(),
            source_path: source_path.to_string_lossy().to_string(),
        });
    }

    exploits.sort_by(|a, b| a.meta.exploit_id.cmp(&b.meta.exploit_id));
    exploits
}

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data at corpus/generalization-benchmark/ (gitignored); run with --features corpus"
)]
#[test]
fn generalization_benchmark() {
    let corpus = load_generalization_corpus();
    assert!(
        corpus.len() >= 10,
        "Should load at least 10 generalization exploits, got {}",
        corpus.len()
    );

    let mut results = vec![];

    for exploit in &corpus {
        let program = parse_program(&exploit.source_code, &exploit.language);
        let ir = build_system_ir(program);
        let findings = analyze(&ir);

        let detected: Vec<String> = findings.iter().map(|f| f.kind.clone()).collect();
        let expected = &exploit.meta.expected_findings;

        let matched: Vec<String> = expected
            .iter()
            .filter(|e| detected.iter().any(|d| normalize(d) == normalize(e)))
            .cloned()
            .collect();

        let missed: Vec<String> = expected
            .iter()
            .filter(|e| !detected.iter().any(|d| normalize(d) == normalize(e)))
            .cloned()
            .collect();

        let signal = if missed.is_empty() {
            "FullyDetected"
        } else if matched.is_empty() {
            "StructurallyBlind"
        } else {
            "PartiallyDetected"
        };

        results.push((
            exploit.meta.exploit_id.clone(),
            exploit.meta.vulnerability_class.clone(),
            expected.clone(),
            detected.clone(),
            matched.clone(),
            missed.clone(),
            signal.to_string(),
        ));
    }

    results.sort_by(|a, b| a.0.cmp(&b.0));

    // Print report
    eprintln!("\n=== GENERALIZATION BENCHMARK ===\n");

    let fd = results.iter().filter(|r| r.6 == "FullyDetected").count();
    let pd = results
        .iter()
        .filter(|r| r.6 == "PartiallyDetected")
        .count();
    let sb = results
        .iter()
        .filter(|r| r.6 == "StructurallyBlind")
        .count();
    let total = results.len();

    eprintln!("Total: {}", total);
    eprintln!(
        "FullyDetected: {}/{} ({:.1}%)",
        fd,
        total,
        fd as f64 / total as f64 * 100.0
    );
    eprintln!("PartiallyDetected: {}", pd);
    eprintln!("StructurallyBlind: {}", sb);
    eprintln!();

    for (id, class, _expected, _detected, matched, missed, signal) in &results {
        eprintln!("[{}] {} ({})", signal, id, class);
        if !missed.is_empty() {
            eprintln!("  Missed: {:?}", missed);
        }
        if !matched.is_empty() {
            eprintln!("  Matched: {:?}", matched);
        }
    }

    // Assert minimum detection rate
    let detection_rate = fd as f64 / total as f64;
    assert!(
        detection_rate >= 0.5,
        "Generalization detection rate should be >= 50%, got {:.1}%",
        detection_rate * 100.0
    );
}

#[test]
fn debug_governance_exploit() {
    let source = r#"
contract Governor {
    mapping(uint256 => bool) public proposals;
    mapping(address => uint256) public votingPower;
    address public token;

    function propose(uint256 proposalId) external {
        proposals[proposalId] = true;
    }

    function vote(uint256 proposalId, bool support) external {
        require(proposals[proposalId]);
        uint256 power = votingPower[msg.sender];
        require(power > 0);
    }

    function execute(uint256 proposalId) external {
        require(proposals[proposalId]);
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ir = build_system_ir(program);

    eprintln!("=== GOVERNANCE DEBUG ===");
    eprintln!("Functions:");
    for f in &ir.functions {
        eprintln!(
            "  {}: visibility={:?}, effects={:?}",
            f.name, f.visibility, f.effects
        );
    }

    eprintln!("\nEdges:");
    for e in &ir.edges {
        eprintln!("  {:?}", e);
    }

    let hypotheses = analyze(&ir);
    eprintln!("\nHypotheses:");
    for h in &hypotheses {
        eprintln!("  [{}] {} - {}", h.kind, h.affected_function, h.reasoning);
    }

    // Check if MissingAuthorityCheck fires for vote
    let vote_hypotheses: Vec<_> = hypotheses
        .iter()
        .filter(|h| h.affected_function == "vote")
        .collect();
    eprintln!("\nVote hypotheses: {:?}", vote_hypotheses);
}
