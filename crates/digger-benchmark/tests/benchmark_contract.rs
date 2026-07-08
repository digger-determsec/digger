/// Benchmark Contract Tests — Phase 5.1
///
/// These tests enforce the benchmark contract.
use digger_benchmark::*;

fn test_corpus_dir() -> String {
    // Use relative path from workspace root
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    workspace_root
        .join("corpus")
        .join("known-exploits")
        .to_string_lossy()
        .to_string()
}

// ─────────────────────────────────────────────────────────────
// 1. Corpus loading
// ─────────────────────────────────────────────────────────────

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data at corpus/known-exploits/ (gitignored); run with --features corpus"
)]
#[test]
fn corpus_loads_successfully() {
    let corpus = load_corpus(&test_corpus_dir());
    assert!(
        corpus.len() >= 5,
        "Should load at least 5 exploits, got {}",
        corpus.len()
    );
}

#[test]
fn corpus_entries_have_source_code() {
    let corpus = load_corpus(&test_corpus_dir());
    for exploit in &corpus {
        assert!(
            !exploit.source_code.is_empty(),
            "Exploit {} must have source code",
            exploit.meta.exploit_id
        );
    }
}

#[test]
fn corpus_entries_have_metadata() {
    let corpus = load_corpus(&test_corpus_dir());
    for exploit in &corpus {
        assert!(!exploit.meta.exploit_id.is_empty(), "Must have exploit_id");
        assert!(
            !exploit.meta.vulnerability_class.is_empty(),
            "Must have vulnerability_class"
        );
        assert!(
            !exploit.meta.expected_findings.is_empty(),
            "Must have expected_findings"
        );
    }
}

#[test]
fn corpus_sorted_by_id() {
    let corpus = load_corpus(&test_corpus_dir());
    for i in 1..corpus.len() {
        assert!(
            corpus[i - 1].meta.exploit_id <= corpus[i].meta.exploit_id,
            "Corpus must be sorted by exploit_id"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 2. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn benchmark_deterministic() {
    let corpus = load_corpus(&test_corpus_dir());
    let r1 = run_benchmark(&corpus);
    let r2 = run_benchmark(&corpus);
    let r3 = run_benchmark(&corpus);

    assert_eq!(r1.total_exploits, r2.total_exploits);
    assert_eq!(r2.total_exploits, r3.total_exploits);
    assert_eq!(r1.passed, r2.passed);
    assert_eq!(r2.passed, r3.passed);
}

// ─────────────────────────────────────────────────────────────
// 3. Stable ordering
// ─────────────────────────────────────────────────────────────

#[test]
fn benchmark_results_sorted() {
    let corpus = load_corpus(&test_corpus_dir());
    let report = run_benchmark(&corpus);

    for i in 1..report.results.len() {
        assert!(
            report.results[i - 1].exploit_id <= report.results[i].exploit_id,
            "Results must be sorted by exploit_id"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 4. Serialization roundtrip
// ─────────────────────────────────────────────────────────────

#[test]
fn benchmark_serialization_roundtrip() {
    let corpus = load_corpus(&test_corpus_dir());
    let report = run_benchmark(&corpus);

    let json = serde_json::to_string_pretty(&report).unwrap();
    let deserialized: BenchmarkReport = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.total_exploits, report.total_exploits);
    assert_eq!(deserialized.passed, report.passed);
    assert_eq!(deserialized.results.len(), report.results.len());
}

#[test]
fn benchmark_serialization_stable() {
    let corpus = load_corpus(&test_corpus_dir());
    let report = run_benchmark(&corpus);

    let json1 = serde_json::to_string_pretty(&report).unwrap();
    let json2 = serde_json::to_string_pretty(&report).unwrap();
    assert_eq!(json1, json2);
}

// ─────────────────────────────────────────────────────────────
// 5. Exploit expectation matching
// ─────────────────────────────────────────────────────────────

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data at corpus/known-exploits/ (gitignored); run with --features corpus"
)]
#[test]
fn reentrancy_exploits_have_findings() {
    let corpus = load_corpus(&test_corpus_dir());
    let report = run_benchmark(&corpus);

    let reentrancy_results: Vec<_> = report
        .results
        .iter()
        .filter(|r| r.vulnerability_class == "reentrancy")
        .collect();

    assert!(
        !reentrancy_results.is_empty(),
        "Should have reentrancy exploits"
    );

    for result in &reentrancy_results {
        assert!(
            !result.findings_detected.is_empty(),
            "Reentrancy exploit {} should have at least one finding",
            result.exploit_id
        );
    }
}

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data at corpus/known-exploits/ (gitignored); run with --features corpus"
)]
#[test]
fn access_control_exploits_have_findings() {
    let corpus = load_corpus(&test_corpus_dir());
    let report = run_benchmark(&corpus);

    let ac_results: Vec<_> = report
        .results
        .iter()
        .filter(|r| r.vulnerability_class == "access-control")
        .collect();

    assert!(
        !ac_results.is_empty(),
        "Should have access-control exploits"
    );

    for result in &ac_results {
        assert!(
            !result.findings_detected.is_empty(),
            "Access-control exploit {} should have at least one finding",
            result.exploit_id
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 6. Aggregate statistics correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn aggregate_counts_correct() {
    let corpus = load_corpus(&test_corpus_dir());
    let report = run_benchmark(&corpus);

    assert_eq!(report.total_exploits, report.results.len());
    assert_eq!(report.passed + report.failed, report.total_exploits);
}

#[test]
fn class_reports_correct() {
    let corpus = load_corpus(&test_corpus_dir());
    let report = run_benchmark(&corpus);

    let total_from_classes: usize = report.by_class.iter().map(|c| c.total).sum();
    assert_eq!(total_from_classes, report.total_exploits);
}

#[test]
fn detection_rate_bounded() {
    let corpus = load_corpus(&test_corpus_dir());
    let report = run_benchmark(&corpus);

    assert!(report.finding_coverage_rate >= 0.0);
    assert!(report.finding_coverage_rate <= 1.0);

    for result in &report.results {
        assert!(result.detection_rate >= 0.0);
        assert!(result.detection_rate <= 1.0);
    }
}

// ─────────────────────────────────────────────────────────────
// 7. Empty corpus handling
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_corpus_produces_empty_report() {
    let corpus = vec![];
    let report = run_benchmark(&corpus);

    assert_eq!(report.total_exploits, 0);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 0);
    assert_eq!(report.results.len(), 0);
    assert_eq!(report.by_class.len(), 0);
}

// ─────────────────────────────────────────────────────────────
// 8. Missing findings explicitly reported
// ─────────────────────────────────────────────────────────────

#[test]
fn missing_findings_reported() {
    let corpus = load_corpus(&test_corpus_dir());
    let report = run_benchmark(&corpus);

    for result in &report.results {
        // If a result failed, it should have missed findings
        if !result.passed {
            assert!(
                !result.findings_missed.is_empty(),
                "Failed exploit {} should have missed findings",
                result.exploit_id
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────
// 9. Normalized exact matching (no substring)
// ─────────────────────────────────────────────────────────────

#[test]
fn normalize_finding_lowercase() {
    // CamelCase with separators → snake_case
    assert_eq!(
        digger_benchmark::loader::normalize_finding("ExternalCallRisk"),
        "external_call_risk"
    );
    // No separators → all lowercase
    assert_eq!(
        digger_benchmark::loader::normalize_finding("externalcallrisk"),
        "externalcallrisk"
    );
    // ALLCAPS with no separators → stays all lowercase
    assert_eq!(
        digger_benchmark::loader::normalize_finding("EXTERNALCALLRISK"),
        "externalcallrisk"
    );
    // Mixed case with separators → snake_case
    assert_eq!(
        digger_benchmark::loader::normalize_finding("MissingAuthorityCheck"),
        "missing_authority_check"
    );
}

#[test]
fn normalize_finding_hyphen_underscore() {
    assert_eq!(
        digger_benchmark::loader::normalize_finding("access-control"),
        "access_control"
    );
    assert_eq!(
        digger_benchmark::loader::normalize_finding("access_control"),
        "access_control"
    );
    assert_eq!(
        digger_benchmark::loader::normalize_finding("Access-Control"),
        "access_control"
    );
}

#[test]
fn normalize_finding_trim() {
    assert_eq!(
        digger_benchmark::loader::normalize_finding("  ExternalCallRisk  "),
        "external_call_risk"
    );
}

#[test]
fn findings_match_case_insensitive() {
    // CamelCase normalization means these match
    assert!(digger_benchmark::loader::findings_match(
        "ExternalCallRisk",
        "ExternalCallRisk"
    ));
    // Different findings should not match
    assert!(!digger_benchmark::loader::findings_match(
        "ExternalCallRisk",
        "MissingAuthorityCheck"
    ));
}

#[test]
fn findings_match_hyphen_underscore() {
    assert!(digger_benchmark::loader::findings_match(
        "Access-Control",
        "access_control"
    ));
    assert!(digger_benchmark::loader::findings_match(
        "Access-Control",
        "AccessControl"
    ));
}

#[test]
fn findings_no_substring_match() {
    // Critical: "State" must NOT match "StateMutationRisk"
    assert!(!digger_benchmark::loader::findings_match(
        "State",
        "StateMutationRisk"
    ));
    assert!(!digger_benchmark::loader::findings_match(
        "StateMutationRisk",
        "State"
    ));
    assert!(!digger_benchmark::loader::findings_match(
        "Authority",
        "MissingAuthorityCheck"
    ));
    assert!(!digger_benchmark::loader::findings_match(
        "Re",
        "ReentrancyRisk"
    ));
}

// ─────────────────────────────────────────────────────────────
// 10. Corpus count integrity
// ─────────────────────────────────────────────────────────────

#[test]
fn corpus_count_equals_loaded_count() {
    let corpus_dir = test_corpus_dir();
    let (corpus, errors) = digger_benchmark::loader::load_corpus_with_errors(&corpus_dir);

    // Every valid exploit must be loaded — no silent skips
    if let Some(error) = errors.first() {
        panic!("Corpus load error: {}", error);
    }

    // Count must be deterministic
    let (corpus2, errors2) = digger_benchmark::loader::load_corpus_with_errors(&corpus_dir);
    assert_eq!(corpus.len(), corpus2.len());
    assert_eq!(errors.len(), errors2.len());
}

// ─────────────────────────────────────────────────────────────
// 11. Finding coverage rate naming
// ─────────────────────────────────────────────────────────────

#[test]
fn finding_coverage_rate_field_name() {
    let corpus = load_corpus(&test_corpus_dir());
    let report = run_benchmark(&corpus);
    let json = serde_json::to_string(&report).unwrap();

    // New field name must be in JSON
    assert!(
        json.contains("finding_coverage_rate"),
        "JSON must use new field name"
    );
}

#[test]
fn finding_coverage_rate_deserialize_alias() {
    // Backward compatibility: old JSON with "overall_detection_rate" still parses
    let json = r#"{"total_exploits":1,"passed":1,"failed":0,"overall_detection_rate":0.5,"by_class":[],"results":[]}"#;
    let report: digger_benchmark::BenchmarkReport = serde_json::from_str(json).unwrap();
    assert_eq!(report.finding_coverage_rate, 0.5);
}
