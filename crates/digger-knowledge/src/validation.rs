/// Continuous Validation — measures reasoning performance against benchmarks.
///
/// Executes deterministic validation, preserves historical results,
/// detects regressions, and provides explainable evidence for human review.
///
/// Never modifies the reasoning engine automatically.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════
// Validation Suite
// ═══════════════════════════════════════════════════════════════

/// A validation suite — a collection of test cases.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationSuite {
    /// Suite identifier.
    pub suite_id: String,
    /// Suite name.
    pub name: String,
    /// Suite kind.
    pub kind: SuiteKind,
    /// Description.
    pub description: String,
    /// Test cases.
    pub cases: Vec<ValidationCase>,
    /// Version.
    pub version: String,
}

/// Kind of validation suite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SuiteKind {
    /// Historical exploit corpus.
    HistoricalExploits,
    /// Regression corpus.
    Regression,
    /// Generalization corpus.
    Generalization,
    /// Newly ingested knowledge source.
    NewSource,
    /// Protocol-specific benchmark.
    ProtocolSpecific,
}

impl std::fmt::Display for SuiteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HistoricalExploits => write!(f, "historical_exploits"),
            Self::Regression => write!(f, "regression"),
            Self::Generalization => write!(f, "generalization"),
            Self::NewSource => write!(f, "new_source"),
            Self::ProtocolSpecific => write!(f, "protocol_specific"),
        }
    }
}

/// A single validation case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationCase {
    /// Case identifier.
    pub case_id: String,
    /// Case name.
    pub name: String,
    /// Protocol this case tests.
    pub protocol: String,
    /// Source code or description.
    pub source: String,
    /// Expected findings.
    pub expected: Vec<ExpectedFinding>,
    /// Category.
    pub category: String,
    /// Description.
    pub description: String,
}

/// An expected finding in a validation case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpectedFinding {
    /// Expected vulnerability class.
    pub vulnerability_class: String,
    /// Expected attack goal.
    pub attack_goal: String,
    /// Expected severity.
    pub severity: String,
    /// Expected function (if known).
    pub function: Option<String>,
    /// Whether this finding is required for the case to pass.
    pub required: bool,
}

// ═══════════════════════════════════════════════════════════════
// Validation Run
// ═══════════════════════════════════════════════════════════════

/// A single execution of a validation suite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationRun {
    /// Run identifier (deterministic).
    pub run_id: String,
    /// Suite that was run.
    pub suite_id: String,
    /// Suite name.
    pub suite_name: String,
    /// Suite kind.
    pub suite_kind: SuiteKind,
    /// Benchmark version.
    pub benchmark_version: String,
    /// Ontology version.
    pub ontology_version: String,
    /// Reasoning engine version.
    pub engine_version: String,
    /// Knowledge snapshot version.
    pub knowledge_version: String,
    /// Corpus snapshot version.
    pub corpus_version: String,
    /// Results per case.
    pub results: Vec<ValidationResult>,
    /// Summary.
    pub summary: ValidationSummary,
    /// Regressions detected.
    pub regressions: Vec<DetectionRegression>,
    /// Improvements detected.
    pub improvements: Vec<DetectionImprovement>,
}

/// Result of a single validation case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationResult {
    /// Case identifier.
    pub case_id: String,
    /// Case name.
    pub case_name: String,
    /// Protocol.
    pub protocol: String,
    /// Whether the case passed.
    pub passed: bool,
    /// Expected findings.
    pub expected: Vec<ExpectedFinding>,
    /// Actual findings detected.
    pub actual: Vec<ActualFinding>,
    /// True positives.
    pub true_positives: usize,
    /// False positives.
    pub false_positives: usize,
    /// False negatives.
    pub false_negatives: usize,
    /// Detection rate (true positives / expected).
    pub detection_rate: f64,
    /// Structural confidence of detected findings.
    pub avg_confidence: f64,
    /// Evidence explaining the result.
    pub evidence: Vec<String>,
}

/// An actual finding detected by the engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActualFinding {
    /// Detected vulnerability class.
    pub vulnerability_class: String,
    /// Detected attack goal.
    pub attack_goal: String,
    /// Detected severity.
    pub severity: String,
    /// Detected function.
    pub function: Option<String>,
    /// Structural confidence.
    pub confidence: f64,
    /// Whether this matched an expected finding.
    pub matched_expected: bool,
}

/// Summary of a validation run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationSummary {
    /// Total cases.
    pub total_cases: usize,
    /// Passed cases.
    pub passed: usize,
    /// Failed cases.
    pub failed: usize,
    /// Overall detection rate.
    pub detection_rate: f64,
    /// Total true positives.
    pub total_true_positives: usize,
    /// Total false positives.
    pub total_false_positives: usize,
    /// Total false negatives.
    pub total_false_negatives: usize,
    /// Average confidence.
    pub avg_confidence: f64,
    /// Regressions from previous run.
    pub regression_count: usize,
    /// Improvements from previous run.
    pub improvement_count: usize,
}

// ═══════════════════════════════════════════════════════════════
// Regression and Improvement
// ═══════════════════════════════════════════════════════════════

/// A detection regression — a case that previously passed but now fails.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectionRegression {
    /// Case identifier.
    pub case_id: String,
    /// Case name.
    pub case_name: String,
    /// Protocol.
    pub protocol: String,
    /// Previous detection rate.
    pub previous_rate: f64,
    /// Current detection rate.
    pub current_rate: f64,
    /// What changed.
    pub change_description: String,
    /// Which semantic models contributed.
    pub affected_models: Vec<String>,
    /// Which reasoning rules changed.
    pub affected_rules: Vec<String>,
    /// Which knowledge artifacts influenced the result.
    pub affected_artifacts: Vec<String>,
    /// Evidence.
    pub evidence: Vec<String>,
}

/// A detection improvement — a case that previously failed but now passes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectionImprovement {
    /// Case identifier.
    pub case_id: String,
    /// Case name.
    pub case_name: String,
    /// Protocol.
    pub protocol: String,
    /// Previous detection rate.
    pub previous_rate: f64,
    /// Current detection rate.
    pub current_rate: f64,
    /// What changed.
    pub change_description: String,
    /// Evidence.
    pub evidence: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Benchmarks
// ═══════════════════════════════════════════════════════════════

/// A corpus benchmark — measures detection against the full corpus.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorpusBenchmark {
    /// Benchmark identifier.
    pub benchmark_id: String,
    /// Total cases.
    pub total_cases: usize,
    /// Detection rate.
    pub detection_rate: f64,
    /// Per-class detection rates.
    pub class_rates: BTreeMap<String, f64>,
    /// Per-goal detection rates.
    pub goal_rates: BTreeMap<String, f64>,
    /// Per-severity detection rates.
    pub severity_rates: BTreeMap<String, f64>,
}

/// A generalization benchmark — measures detection on unseen protocols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeneralizationBenchmark {
    /// Benchmark identifier.
    pub benchmark_id: String,
    /// Training protocols.
    pub training_protocols: usize,
    /// Testing protocols.
    pub testing_protocols: usize,
    /// Detection rate on training set.
    pub training_rate: f64,
    /// Detection rate on testing set.
    pub testing_rate: f64,
    /// Generalization gap (training - testing).
    pub generalization_gap: f64,
}

// ═══════════════════════════════════════════════════════════════
// Reasoning Coverage
// ─────────────────────────────────────────────────────────────

/// Reasoning coverage — what reasoning paths are exercised.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningCoverage {
    /// Total reasoning rules.
    pub total_rules: usize,
    /// Rules exercised by validation.
    pub exercised_rules: usize,
    /// Coverage percentage.
    pub coverage_pct: f64,
    /// Rules not exercised.
    pub unexercised_rules: Vec<String>,
    /// Per-category coverage.
    pub category_coverage: BTreeMap<String, f64>,
}

// ═══════════════════════════════════════════════════════════════
// Validation Trend
// ═══════════════════════════════════════════════════════════════

/// Validation trend over multiple runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationTrend {
    /// Run history.
    pub runs: Vec<ValidationRunSummary>,
    /// Detection rate trend.
    pub detection_trend: Vec<f64>,
    /// Regression count trend.
    pub regression_trend: Vec<usize>,
    /// Improvement count trend.
    pub improvement_trend: Vec<usize>,
}

/// Summary of a single run for trend tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationRunSummary {
    /// Run identifier.
    pub run_id: String,
    /// Suite name.
    pub suite_name: String,
    /// Detection rate.
    pub detection_rate: f64,
    /// Regression count.
    pub regression_count: usize,
    /// Improvement count.
    pub improvement_count: usize,
    /// Version identifiers.
    pub versions: VersionInfo,
}

/// Version information for a validation run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VersionInfo {
    pub benchmark: String,
    pub ontology: String,
    pub engine: String,
    pub knowledge: String,
    pub corpus: String,
}

// ═══════════════════════════════════════════════════════════════
// Validation Engine
// ═══════════════════════════════════════════════════════════════

/// Execute a validation suite against the current reasoning engine.
pub fn execute_validation(
    suite: &ValidationSuite,
    detected_findings: &[DetectedFinding],
    previous_run: Option<&ValidationRun>,
    versions: &VersionInfo,
) -> ValidationRun {
    let mut results = Vec::new();

    for case in &suite.cases {
        let result = validate_case(case, detected_findings);
        results.push(result);
    }

    let summary = compute_summary(&results);
    let regressions = detect_regressions(&results, previous_run);
    let improvements = detect_improvements(&results, previous_run);

    let run_id = compute_run_id(&suite.suite_id, versions);

    ValidationRun {
        run_id,
        suite_id: suite.suite_id.clone(),
        suite_name: suite.name.clone(),
        suite_kind: suite.kind.clone(),
        benchmark_version: versions.benchmark.clone(),
        ontology_version: versions.ontology.clone(),
        engine_version: versions.engine.clone(),
        knowledge_version: versions.knowledge.clone(),
        corpus_version: versions.corpus.clone(),
        results,
        summary,
        regressions,
        improvements,
    }
}

/// A finding detected by the engine (input to validation).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectedFinding {
    /// Protocol.
    pub protocol: String,
    /// Detected vulnerability class.
    pub vulnerability_class: String,
    /// Detected attack goal.
    pub attack_goal: String,
    /// Detected severity.
    pub severity: String,
    /// Detected function.
    pub function: Option<String>,
    /// Structural confidence.
    pub confidence: f64,
}

fn validate_case(case: &ValidationCase, detected: &[DetectedFinding]) -> ValidationResult {
    let case_detected: Vec<&DetectedFinding> = detected
        .iter()
        .filter(|d| d.protocol == case.protocol)
        .collect();

    let mut true_positives = 0;
    let mut false_negatives = 0;
    let mut actual_findings = Vec::new();
    let mut matched_expected = Vec::new();

    // Check each expected finding
    for expected in &case.expected {
        let found = case_detected.iter().any(|d| {
            d.vulnerability_class == expected.vulnerability_class
                && d.attack_goal == expected.attack_goal
        });
        if found {
            true_positives += 1;
            matched_expected.push(expected.vulnerability_class.clone());
        } else if expected.required {
            false_negatives += 1;
        }
    }

    // Count false positives (detected but not expected)
    let false_positives = case_detected
        .iter()
        .filter(|d| {
            !case.expected.iter().any(|e| {
                e.vulnerability_class == d.vulnerability_class && e.attack_goal == d.attack_goal
            })
        })
        .count();

    // Build actual findings
    for d in &case_detected {
        actual_findings.push(ActualFinding {
            vulnerability_class: d.vulnerability_class.clone(),
            attack_goal: d.attack_goal.clone(),
            severity: d.severity.clone(),
            function: d.function.clone(),
            confidence: d.confidence,
            matched_expected: matched_expected.contains(&d.vulnerability_class),
        });
    }

    let expected_required = case.expected.iter().filter(|e| e.required).count();
    let detection_rate = if expected_required > 0 {
        true_positives as f64 / expected_required as f64
    } else {
        1.0
    };

    let avg_confidence = if actual_findings.is_empty() {
        0.0
    } else {
        actual_findings.iter().map(|f| f.confidence).sum::<f64>() / actual_findings.len() as f64
    };

    let passed = false_negatives == 0 && false_positives == 0;

    let mut evidence = Vec::new();
    if !passed {
        if false_negatives > 0 {
            evidence.push(format!(
                "{} required findings not detected",
                false_negatives
            ));
        }
        if false_positives > 0 {
            evidence.push(format!("{} unexpected findings detected", false_positives));
        }
    }

    ValidationResult {
        case_id: case.case_id.clone(),
        case_name: case.name.clone(),
        protocol: case.protocol.clone(),
        passed,
        expected: case.expected.clone(),
        actual: actual_findings,
        true_positives,
        false_positives,
        false_negatives,
        detection_rate,
        avg_confidence,
        evidence,
    }
}

fn compute_summary(results: &[ValidationResult]) -> ValidationSummary {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    let total_tp: usize = results.iter().map(|r| r.true_positives).sum();
    let total_fp: usize = results.iter().map(|r| r.false_positives).sum();
    let total_fn: usize = results.iter().map(|r| r.false_negatives).sum();

    let total_expected: usize = results
        .iter()
        .map(|r| r.expected.iter().filter(|e| e.required).count())
        .sum();
    let detection_rate = if total_expected > 0 {
        total_tp as f64 / total_expected as f64
    } else {
        1.0
    };

    let avg_confidence = if results.is_empty() {
        0.0
    } else {
        results.iter().map(|r| r.avg_confidence).sum::<f64>() / results.len() as f64
    };

    ValidationSummary {
        total_cases: total,
        passed,
        failed,
        detection_rate,
        total_true_positives: total_tp,
        total_false_positives: total_fp,
        total_false_negatives: total_fn,
        avg_confidence,
        regression_count: 0, // filled by caller
        improvement_count: 0,
    }
}

fn detect_regressions(
    results: &[ValidationResult],
    previous: Option<&ValidationRun>,
) -> Vec<DetectionRegression> {
    let mut regressions = Vec::new();
    let prev = match previous {
        Some(p) => p,
        None => return regressions,
    };

    for result in results {
        if let Some(prev_result) = prev.results.iter().find(|r| r.case_id == result.case_id) {
            if prev_result.passed && !result.passed {
                regressions.push(DetectionRegression {
                    case_id: result.case_id.clone(),
                    case_name: result.case_name.clone(),
                    protocol: result.protocol.clone(),
                    previous_rate: prev_result.detection_rate,
                    current_rate: result.detection_rate,
                    change_description: format!(
                        "Detection rate decreased from {:.1}% to {:.1}%",
                        prev_result.detection_rate * 100.0,
                        result.detection_rate * 100.0
                    ),
                    affected_models: vec![],
                    affected_rules: vec![],
                    affected_artifacts: vec![],
                    evidence: result.evidence.clone(),
                });
            }
        }
    }

    regressions
}

fn detect_improvements(
    results: &[ValidationResult],
    previous: Option<&ValidationRun>,
) -> Vec<DetectionImprovement> {
    let mut improvements = Vec::new();
    let prev = match previous {
        Some(p) => p,
        None => return improvements,
    };

    for result in results {
        if let Some(prev_result) = prev.results.iter().find(|r| r.case_id == result.case_id) {
            if !prev_result.passed && result.passed {
                improvements.push(DetectionImprovement {
                    case_id: result.case_id.clone(),
                    case_name: result.case_name.clone(),
                    protocol: result.protocol.clone(),
                    previous_rate: prev_result.detection_rate,
                    current_rate: result.detection_rate,
                    change_description: format!(
                        "Detection rate improved from {:.1}% to {:.1}%",
                        prev_result.detection_rate * 100.0,
                        result.detection_rate * 100.0
                    ),
                    evidence: result.evidence.clone(),
                });
            }
        }
    }

    improvements
}

fn compute_run_id(suite_id: &str, versions: &VersionInfo) -> String {
    let mut h: u64 = 0;
    for byte in suite_id.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    for byte in versions.engine.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    for byte in versions.ontology.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    format!("{:x}", h)
}

/// Compute corpus benchmark from validation results.
pub fn compute_corpus_benchmark(
    results: &[ValidationResult],
    benchmark_id: &str,
) -> CorpusBenchmark {
    let total = results.len();

    let mut class_correct: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut goal_correct: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut sev_correct: BTreeMap<String, (usize, usize)> = BTreeMap::new();

    for result in results {
        for expected in &result.expected {
            if expected.required {
                let entry = class_correct
                    .entry(expected.vulnerability_class.clone())
                    .or_insert((0, 0));
                entry.1 += 1;
                if result.true_positives > 0 {
                    entry.0 += 1;
                }

                let entry = goal_correct
                    .entry(expected.attack_goal.clone())
                    .or_insert((0, 0));
                entry.1 += 1;
                if result.true_positives > 0 {
                    entry.0 += 1;
                }

                let entry = sev_correct
                    .entry(expected.severity.clone())
                    .or_insert((0, 0));
                entry.1 += 1;
                if result.true_positives > 0 {
                    entry.0 += 1;
                }
            }
        }
    }

    let rate = |v: &(usize, usize)| {
        if v.1 > 0 {
            v.0 as f64 / v.1 as f64
        } else {
            0.0
        }
    };

    let class_rates: BTreeMap<String, f64> = class_correct
        .iter()
        .map(|(k, v)| (k.clone(), rate(v)))
        .collect();
    let goal_rates: BTreeMap<String, f64> = goal_correct
        .iter()
        .map(|(k, v)| (k.clone(), rate(v)))
        .collect();
    let severity_rates: BTreeMap<String, f64> = sev_correct
        .iter()
        .map(|(k, v)| (k.clone(), rate(v)))
        .collect();

    let overall = results.iter().map(|r| r.detection_rate).sum::<f64>() / total.max(1) as f64;

    CorpusBenchmark {
        benchmark_id: benchmark_id.into(),
        total_cases: total,
        detection_rate: overall,
        class_rates,
        goal_rates,
        severity_rates,
    }
}

/// Compute reasoning coverage from validation results and rules.
pub fn compute_reasoning_coverage(
    exercised_rules: &[String],
    total_rules: &[String],
) -> ReasoningCoverage {
    let exercised: std::collections::BTreeSet<&String> = exercised_rules.iter().collect();
    let total_set: std::collections::BTreeSet<&String> = total_rules.iter().collect();

    let unexercised: Vec<String> = total_set
        .difference(&exercised)
        .map(|s| (*s).clone())
        .collect();

    let coverage_pct = if total_rules.is_empty() {
        0.0
    } else {
        exercised.len() as f64 / total_rules.len() as f64 * 100.0
    };

    ReasoningCoverage {
        total_rules: total_rules.len(),
        exercised_rules: exercised_rules.len(),
        coverage_pct,
        unexercised_rules: unexercised,
        category_coverage: BTreeMap::new(),
    }
}

/// Serialize run to JSON.
pub fn run_to_json(run: &ValidationRun) -> String {
    serde_json::to_string_pretty(run).unwrap_or_else(|_| "{}".into())
}

/// Serialize benchmark to JSON.
pub fn benchmark_to_json(benchmark: &CorpusBenchmark) -> String {
    serde_json::to_string_pretty(benchmark).unwrap_or_else(|_| "{}".into())
}
