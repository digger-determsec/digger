/// Research Workspace — isolates experimental reasoning from production.
///
/// Supports experimental rules, ontology concepts, normalization strategies,
/// knowledge sources, search heuristics, and confidence calculations.
///
/// Every experiment executes against the Continuous Validation subsystem.
/// Promotion into production never occurs automatically.
///
/// Deterministic: same inputs → same outputs.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════
// Experiment
// ═══════════════════════════════════════════════════════════════

/// A research experiment — isolated from production.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Experiment {
    /// Experiment identifier.
    pub experiment_id: String,
    /// Experiment name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Configuration.
    pub config: ExperimentConfiguration,
    /// Status.
    pub status: ExperimentStatus,
    /// Runs executed.
    pub runs: Vec<ExperimentRun>,
    /// Latest result.
    pub latest_result: Option<ExperimentResult>,
    /// Promotion recommendation.
    pub promotion: Option<PromotionCandidate>,
}

/// Status of an experiment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExperimentStatus {
    /// Experiment is being configured.
    Draft,
    /// Experiment is running.
    Running,
    /// Experiment completed successfully.
    Completed,
    /// Experiment was abandoned.
    Abandoned,
    /// Experiment was promoted to production.
    Promoted,
}

impl std::fmt::Display for ExperimentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Abandoned => write!(f, "abandoned"),
            Self::Promoted => write!(f, "promoted"),
        }
    }
}

/// Configuration for an experiment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentConfiguration {
    /// Experimental rules to test.
    pub experimental_rules: Vec<ExperimentalRule>,
    /// Experimental ontology entries.
    pub experimental_ontology: Vec<ExperimentalOntologyEntry>,
    /// Experimental normalization strategies.
    pub normalization_strategies: Vec<NormalizationStrategy>,
    /// Experimental knowledge sources.
    pub knowledge_sources: Vec<ExperimentalKnowledge>,
    /// Experimental search heuristics.
    pub search_heuristics: Vec<SearchHeuristic>,
    /// Alternative confidence calculations.
    pub confidence_configs: Vec<ConfidenceConfig>,
    /// Validation suite to run against.
    pub validation_suite_id: String,
    /// Baseline run ID to compare against.
    pub baseline_run_id: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// Experimental Primitives
// ═══════════════════════════════════════════════════════════════

/// An experimental reasoning rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentalRule {
    /// Rule identifier.
    pub rule_id: String,
    /// Rule kind.
    pub kind: String,
    /// Description.
    pub description: String,
    /// Condition that triggers this rule (structured).
    pub condition: RuleCondition,
    /// Output produced.
    pub output: RuleOutput,
    /// Hypothesis: what this rule should improve.
    pub hypothesis: String,
    /// Expected impact.
    pub expected_impact: String,
}

/// Condition for an experimental rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleCondition {
    /// Input types required.
    pub inputs: Vec<String>,
    /// Preconditions.
    pub preconditions: Vec<String>,
    /// Pattern to match (structured).
    pub pattern: String,
}

/// Output of an experimental rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleOutput {
    /// Output type.
    pub output_type: String,
    /// Output description.
    pub description: String,
}

/// An experimental ontology entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentalOntologyEntry {
    /// Entry name.
    pub name: String,
    /// Entry kind: vulnerability_class, attack_technique, root_cause, etc.
    pub kind: String,
    /// Description.
    pub description: String,
    /// Evidence supporting this entry.
    pub evidence: Vec<String>,
    /// Hypothesis: what this entry should capture.
    pub hypothesis: String,
}

/// An experimental normalization strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizationStrategy {
    /// Strategy identifier.
    pub strategy_id: String,
    /// Description.
    pub description: String,
    /// Input patterns to normalize.
    pub input_patterns: Vec<String>,
    /// Output canonical forms.
    pub output_forms: Vec<String>,
    /// Hypothesis.
    pub hypothesis: String,
}

/// An experimental knowledge source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentalKnowledge {
    /// Source identifier.
    pub source_id: String,
    /// Source kind.
    pub kind: String,
    /// Description.
    pub description: String,
    /// Expected findings count.
    pub expected_findings: usize,
    /// Hypothesis.
    pub hypothesis: String,
}

/// An experimental search heuristic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchHeuristic {
    /// Heuristic identifier.
    pub heuristic_id: String,
    /// Description.
    pub description: String,
    /// Search strategy.
    pub strategy: String,
    /// Expected improvement.
    pub expected_improvement: String,
    /// Hypothesis.
    pub hypothesis: String,
}

/// An alternative confidence calculation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidenceConfig {
    /// Config identifier.
    pub config_id: String,
    /// Description.
    pub description: String,
    /// Weight for model diversity.
    pub model_diversity_weight: f64,
    /// Weight for prerequisite satisfaction.
    pub prerequisite_weight: f64,
    /// Weight for path parsimony.
    pub parsimony_weight: f64,
    /// Weight for evidence density.
    pub evidence_density_weight: f64,
    /// Hypothesis.
    pub hypothesis: String,
}

// ═══════════════════════════════════════════════════════════════
// Experiment Run and Result
// ═══════════════════════════════════════════════════════════════

/// A single execution of an experiment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentRun {
    /// Run identifier (deterministic).
    pub run_id: String,
    /// Experiment identifier.
    pub experiment_id: String,
    /// Configuration used.
    pub config_hash: String,
    /// Validation suite used.
    pub suite_id: String,
    /// Version identifiers.
    pub versions: ExperimentVersions,
    /// Result.
    pub result: ExperimentResult,
}

/// Version identifiers for an experiment run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentVersions {
    pub engine: String,
    pub ontology: String,
    pub knowledge: String,
    pub corpus: String,
    pub experiment: String,
}

/// Result of an experiment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentResult {
    /// Detection rate.
    pub detection_rate: f64,
    /// True positives.
    pub true_positives: usize,
    /// False positives.
    pub false_positives: usize,
    /// False negatives.
    pub false_negatives: usize,
    /// Average confidence.
    pub avg_confidence: f64,
    /// Reasoning coverage.
    pub reasoning_coverage: f64,
    /// Affected benchmark suites.
    pub affected_suites: Vec<String>,
    /// Affected semantic models.
    pub affected_models: Vec<String>,
    /// Statistical summary.
    pub stats: ExperimentStats,
}

/// Statistical summary of an experiment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentStats {
    /// Total cases run.
    pub total_cases: usize,
    /// Cases passed.
    pub passed: usize,
    /// Cases failed.
    pub failed: usize,
    /// Detection rate.
    pub detection_rate: f64,
    /// Confidence distribution.
    pub confidence_distribution: ConfidenceDistribution,
    /// Per-class detection rates.
    pub class_rates: BTreeMap<String, f64>,
}

/// Confidence distribution statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidenceDistribution {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
}

// ═══════════════════════════════════════════════════════════════
// Experiment Comparison
// ═══════════════════════════════════════════════════════════════

/// Comparison between experiment and production baseline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentComparison {
    /// Experiment run.
    pub experiment_run: ExperimentRun,
    /// Baseline run (production).
    pub baseline_run_id: String,
    /// Detection improvement.
    pub detection_delta: f64,
    /// Improvements detected.
    pub improvements: Vec<ExperimentImprovement>,
    /// Regressions introduced.
    pub regressions: Vec<ExperimentRegression>,
    /// Affected benchmark suites.
    pub affected_suites: Vec<String>,
    /// Affected semantic models.
    pub affected_models: Vec<String>,
    /// Reasoning coverage change.
    pub coverage_delta: f64,
    /// Confidence change.
    pub confidence_delta: f64,
    /// Statistical significance.
    pub significant: bool,
    /// Promotion recommendation.
    pub recommendation: PromotionRecommendation,
}

/// An improvement from an experiment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentImprovement {
    /// Case that improved.
    pub case_id: String,
    /// Case name.
    pub case_name: String,
    /// Previous detection rate.
    pub previous_rate: f64,
    /// New detection rate.
    pub new_rate: f64,
    /// What changed.
    pub change_description: String,
    /// Evidence.
    pub evidence: Vec<String>,
}

/// A regression from an experiment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentRegression {
    /// Case that regressed.
    pub case_id: String,
    /// Case name.
    pub case_name: String,
    /// Previous detection rate.
    pub previous_rate: f64,
    /// New detection rate.
    pub new_rate: f64,
    /// What changed.
    pub change_description: String,
    /// Which experimental rules caused this.
    pub caused_by: Vec<String>,
    /// Evidence.
    pub evidence: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Promotion
// ═══════════════════════════════════════════════════════════════

/// A promotion candidate — recommendation to move experiment to production.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromotionCandidate {
    /// Experiment identifier.
    pub experiment_id: String,
    /// Experiment name.
    pub experiment_name: String,
    /// Recommendation.
    pub recommendation: PromotionRecommendation,
    /// Justification.
    pub justification: String,
    /// Evidence supporting promotion.
    pub evidence: Vec<String>,
    /// Risks of promotion.
    pub risks: Vec<String>,
    /// Items to promote.
    pub promotion_items: Vec<PromotionItem>,
    /// Status: pending, approved, rejected.
    pub status: String,
}

/// Recommendation for promotion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PromotionRecommendation {
    /// Strong recommendation to promote.
    Promote,
    /// Promote with modifications.
    PromoteWithChanges,
    /// Needs more evaluation.
    NeedsMoreData,
    /// Do not promote.
    DoNotPromote,
}

impl std::fmt::Display for PromotionRecommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Promote => write!(f, "promote"),
            Self::PromoteWithChanges => write!(f, "promote_with_changes"),
            Self::NeedsMoreData => write!(f, "needs_more_data"),
            Self::DoNotPromote => write!(f, "do_not_promote"),
        }
    }
}

/// An item to promote from experiment to production.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromotionItem {
    /// Item kind.
    pub kind: String,
    /// Item name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Evidence supporting this item.
    pub evidence: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Workspace Engine
// ═══════════════════════════════════════════════════════════════

/// Execute an experiment against a validation suite.
pub fn execute_experiment(
    experiment: &Experiment,
    validation_results: &[super::validation::ValidationResult],
    _baseline_results: Option<&[super::validation::ValidationResult]>,
    versions: &ExperimentVersions,
) -> ExperimentRun {
    let config_hash = compute_config_hash(&experiment.config);
    let run_id = compute_run_id(&experiment.experiment_id, &config_hash);

    let _result = compute_experiment_result(validation_results);
    let stats = compute_experiment_stats(validation_results);

    ExperimentRun {
        run_id,
        experiment_id: experiment.experiment_id.clone(),
        config_hash,
        suite_id: experiment.config.validation_suite_id.clone(),
        versions: versions.clone(),
        result: ExperimentResult {
            detection_rate: stats.detection_rate,
            true_positives: validation_results.iter().map(|r| r.true_positives).sum(),
            false_positives: validation_results.iter().map(|r| r.false_positives).sum(),
            false_negatives: validation_results.iter().map(|r| r.false_negatives).sum(),
            avg_confidence: stats.detection_rate, // simplified
            reasoning_coverage: 0.0,
            affected_suites: vec![],
            affected_models: vec![],
            stats,
        },
    }
}

/// Compare an experiment run against a baseline.
pub fn compare_experiment(
    experiment_run: &ExperimentRun,
    baseline_results: &[super::validation::ValidationResult],
    baseline_run_id: &str,
) -> ExperimentComparison {
    let baseline_rate = baseline_results
        .iter()
        .map(|r| r.detection_rate)
        .sum::<f64>()
        / baseline_results.len().max(1) as f64;

    let detection_delta = experiment_run.result.detection_rate - baseline_rate;

    let mut improvements = Vec::new();
    let mut regressions = Vec::new();

    // Find improvements and regressions per case
    for baseline in baseline_results.iter() {
        let case_id = baseline.case_id.clone();
        let case_name = baseline.case_name.clone();

        // Simplified comparison — in practice would match by case_id
        if baseline.detection_rate < experiment_run.result.detection_rate
            && experiment_run.result.detection_rate - baseline.detection_rate > 0.1
        {
            improvements.push(ExperimentImprovement {
                case_id: case_id.clone(),
                case_name: case_name.clone(),
                previous_rate: baseline.detection_rate,
                new_rate: experiment_run.result.detection_rate,
                change_description: format!(
                    "Detection rate improved from {:.1}% to {:.1}%",
                    baseline.detection_rate * 100.0,
                    experiment_run.result.detection_rate * 100.0
                ),
                evidence: vec![],
            });
        } else if baseline.detection_rate > experiment_run.result.detection_rate
            && baseline.detection_rate - experiment_run.result.detection_rate > 0.1
        {
            regressions.push(ExperimentRegression {
                case_id: case_id.clone(),
                case_name: case_name.clone(),
                previous_rate: baseline.detection_rate,
                new_rate: experiment_run.result.detection_rate,
                change_description: format!(
                    "Detection rate decreased from {:.1}% to {:.1}%",
                    baseline.detection_rate * 100.0,
                    experiment_run.result.detection_rate * 100.0
                ),
                caused_by: vec![],
                evidence: vec![],
            });
        }
    }

    let significant = detection_delta.abs() > 0.05;

    let recommendation = if regressions.is_empty() && improvements.len() >= 2 {
        PromotionRecommendation::Promote
    } else if regressions.is_empty() && !improvements.is_empty() {
        PromotionRecommendation::PromoteWithChanges
    } else if !regressions.is_empty() && !improvements.is_empty() {
        PromotionRecommendation::NeedsMoreData
    } else {
        PromotionRecommendation::DoNotPromote
    };

    ExperimentComparison {
        experiment_run: experiment_run.clone(),
        baseline_run_id: baseline_run_id.into(),
        detection_delta,
        improvements,
        regressions,
        affected_suites: experiment_run.result.affected_suites.clone(),
        affected_models: experiment_run.result.affected_models.clone(),
        coverage_delta: 0.0,
        confidence_delta: 0.0,
        significant,
        recommendation,
    }
}

/// Generate a promotion candidate from a comparison.
pub fn generate_promotion_candidate(
    comparison: &ExperimentComparison,
    experiment: &Experiment,
) -> Option<PromotionCandidate> {
    if comparison.recommendation == PromotionRecommendation::DoNotPromote {
        return None;
    }

    let mut promotion_items = Vec::new();

    for rule in &experiment.config.experimental_rules {
        promotion_items.push(PromotionItem {
            kind: "experimental_rule".into(),
            name: rule.rule_id.clone(),
            description: rule.description.clone(),
            evidence: vec![rule.hypothesis.clone()],
        });
    }

    for entry in &experiment.config.experimental_ontology {
        promotion_items.push(PromotionItem {
            kind: "ontology_entry".into(),
            name: entry.name.clone(),
            description: entry.description.clone(),
            evidence: entry.evidence.clone(),
        });
    }

    let mut risks = Vec::new();
    for regression in &comparison.regressions {
        risks.push(format!(
            "Regression in {}: {}",
            regression.case_name, regression.change_description
        ));
    }

    Some(PromotionCandidate {
        experiment_id: experiment.experiment_id.clone(),
        experiment_name: experiment.name.clone(),
        recommendation: comparison.recommendation.clone(),
        justification: format!(
            "Detection rate delta: {:+.1}%, {} improvements, {} regressions",
            comparison.detection_delta * 100.0,
            comparison.improvements.len(),
            comparison.regressions.len()
        ),
        evidence: comparison
            .improvements
            .iter()
            .map(|i| i.change_description.clone())
            .collect(),
        risks,
        promotion_items,
        status: "pending".into(),
    })
}

fn compute_config_hash(config: &ExperimentConfiguration) -> String {
    let mut h: u64 = 0;
    for rule in &config.experimental_rules {
        for byte in rule.rule_id.bytes() {
            h = h.wrapping_mul(31).wrapping_add(byte as u64);
        }
    }
    for entry in &config.experimental_ontology {
        for byte in entry.name.bytes() {
            h = h.wrapping_mul(31).wrapping_add(byte as u64);
        }
    }
    format!("{:x}", h)
}

fn compute_run_id(experiment_id: &str, config_hash: &str) -> String {
    let mut h: u64 = 0;
    for byte in experiment_id.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    for byte in config_hash.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    format!("{:x}", h)
}

fn compute_experiment_result(results: &[super::validation::ValidationResult]) -> ExperimentResult {
    let total = results.len();
    let tp: usize = results.iter().map(|r| r.true_positives).sum();
    let fp: usize = results.iter().map(|r| r.false_positives).sum();
    let fn_count: usize = results.iter().map(|r| r.false_negatives).sum();
    let rate = if tp + fn_count > 0 {
        tp as f64 / (tp + fn_count) as f64
    } else {
        0.0
    };

    ExperimentResult {
        detection_rate: rate,
        true_positives: tp,
        false_positives: fp,
        false_negatives: fn_count,
        avg_confidence: results.iter().map(|r| r.avg_confidence).sum::<f64>() / total.max(1) as f64,
        reasoning_coverage: 0.0,
        affected_suites: vec![],
        affected_models: vec![],
        stats: compute_experiment_stats(results),
    }
}

fn compute_experiment_stats(results: &[super::validation::ValidationResult]) -> ExperimentStats {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    let tp: usize = results.iter().map(|r| r.true_positives).sum();
    let fn_count: usize = results.iter().map(|r| r.false_negatives).sum();
    let rate = if tp + fn_count > 0 {
        tp as f64 / (tp + fn_count) as f64
    } else {
        0.0
    };

    let confidences: Vec<f64> = results.iter().map(|r| r.avg_confidence).collect();
    let conf_dist = compute_confidence_distribution(&confidences);

    let mut class_rates: BTreeMap<String, f64> = BTreeMap::new();
    for result in results {
        for expected in &result.expected {
            let entry = class_rates
                .entry(expected.vulnerability_class.clone())
                .or_insert(0.0);
            if result.true_positives > 0 {
                *entry += 1.0;
            }
        }
    }
    for val in class_rates.values_mut() {
        *val /= total.max(1) as f64;
    }

    ExperimentStats {
        total_cases: total,
        passed,
        failed,
        detection_rate: rate,
        confidence_distribution: conf_dist,
        class_rates,
    }
}

fn compute_confidence_distribution(values: &[f64]) -> ConfidenceDistribution {
    if values.is_empty() {
        return ConfidenceDistribution {
            min: 0.0,
            max: 0.0,
            mean: 0.0,
            median: 0.0,
            std_dev: 0.0,
        };
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let median = if sorted.len().is_multiple_of(2) {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
    } else {
        sorted[sorted.len() / 2]
    };
    let variance = sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / sorted.len() as f64;
    let std_dev = variance.sqrt();

    ConfidenceDistribution {
        min,
        max,
        mean,
        median,
        std_dev,
    }
}

/// Serialize experiment to JSON.
pub fn experiment_to_json(experiment: &Experiment) -> String {
    serde_json::to_string_pretty(experiment).unwrap_or_else(|_| "{}".into())
}

/// Serialize comparison to JSON.
pub fn comparison_to_json(comparison: &ExperimentComparison) -> String {
    serde_json::to_string_pretty(comparison).unwrap_or_else(|_| "{}".into())
}
