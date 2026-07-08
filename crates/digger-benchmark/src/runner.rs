use crate::loader::findings_match;
use crate::models::*;
use digger_graph::build_system_ir;
use digger_hypothesis::analyze_compat as analyze;
/// Benchmark runner — validates Digger against known exploits.
use digger_parser::parse_program;

/// Run the benchmark against a loaded corpus.
///
/// This is the ONLY entry point. Deterministic: same input → same output.
pub fn run_benchmark(corpus: &[LoadedExploit]) -> BenchmarkReport {
    let results: Vec<BenchmarkResult> = corpus.iter().map(run_single).collect();

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;
    let overall_rate = if results.is_empty() {
        0.0
    } else {
        results.iter().map(|r| r.detection_rate).sum::<f64>() / results.len() as f64
    };

    // Aggregate by class
    let mut classes: std::collections::BTreeMap<String, Vec<&BenchmarkResult>> =
        std::collections::BTreeMap::new();
    for result in &results {
        classes
            .entry(result.vulnerability_class.clone())
            .or_default()
            .push(result);
    }

    let mut by_class: Vec<ClassReport> = classes
        .iter()
        .map(|(class, results)| {
            let class_passed = results.iter().filter(|r| r.passed).count();
            let class_rate =
                results.iter().map(|r| r.detection_rate).sum::<f64>() / results.len() as f64;
            ClassReport {
                vulnerability_class: class.clone(),
                total: results.len(),
                passed: class_passed,
                detection_rate: class_rate,
            }
        })
        .collect();
    by_class.sort_by(|a, b| a.vulnerability_class.cmp(&b.vulnerability_class));

    BenchmarkReport {
        total_exploits: corpus.len(),
        passed,
        failed,
        finding_coverage_rate: overall_rate,
        by_class,
        results,
        reasoning_quality: None,
    }
}

/// Run benchmark on a single exploit.
fn run_single(exploit: &LoadedExploit) -> BenchmarkResult {
    let raw = parse_program(&exploit.source_code, &exploit.language);
    let ir = build_system_ir(raw);
    let findings = analyze(&ir);

    let findings_detected: Vec<String> = findings.iter().map(|f| f.kind.clone()).collect();

    let findings_expected = exploit.meta.expected_findings.clone();

    // Match detected findings against expected — normalized exact only
    let findings_matched: Vec<String> = findings_expected
        .iter()
        .filter(|expected| {
            findings_detected
                .iter()
                .any(|detected| findings_match(detected, expected))
        })
        .cloned()
        .collect();

    let findings_missed: Vec<String> = findings_expected
        .iter()
        .filter(|expected| {
            !findings_detected
                .iter()
                .any(|detected| findings_match(detected, expected))
        })
        .cloned()
        .collect();

    let findings_unexpected: Vec<String> = findings_detected
        .iter()
        .filter(|detected| {
            !findings_expected
                .iter()
                .any(|expected| findings_match(detected, expected))
        })
        .cloned()
        .collect();

    let detection_rate = if findings_expected.is_empty() {
        1.0
    } else {
        findings_matched.len() as f64 / findings_expected.len() as f64
    };

    let passed = findings_missed.is_empty();

    // Detect hypothesis types
    let mut hypothesis_types_detected: Vec<String> = findings_detected
        .iter()
        .map(|f| {
            if f.contains("Reentrancy") {
                "ReentrancyCandidate".into()
            } else if f.contains("Authority") {
                "AuthorityBypassCandidate".into()
            } else if f.contains("CPI") || f.contains("CrossProgram") {
                "CPITrustViolationCandidate".into()
            } else if f.contains("State") || f.contains("Mutation") {
                "StateCorruptionCandidate".into()
            } else {
                f.clone()
            }
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    hypothesis_types_detected.sort();

    BenchmarkResult {
        exploit_id: exploit.meta.exploit_id.clone(),
        vulnerability_class: exploit.meta.vulnerability_class.clone(),
        protocol: exploit.meta.protocol.clone(),
        findings_detected,
        findings_expected,
        findings_matched,
        findings_missed,
        findings_unexpected,
        detection_rate,
        hypothesis_types_detected,
        passed,
        reasoning_quality: None,
    }
}
