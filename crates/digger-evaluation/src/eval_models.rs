/// Evaluation framework models — shared types for all evaluation modules.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ─── Live Contest Evaluation ──────────────────────────────────────

/// Result of evaluating against a single contest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContestEvaluation {
    pub contest_id: String,
    pub source: String,
    pub contest_date: String,
    pub protocol: String,
    pub digger_findings: Vec<FindingComparison>,
    pub official_findings: Vec<String>,
    pub true_positives: usize,
    pub partial_matches: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub unique_findings: Vec<String>,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub comparison_report: String,
}

/// Comparison of a single finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingComparison {
    pub digger_finding: String,
    pub matched_official: Option<String>,
    pub match_type: MatchType,
    pub confidence: f64,
    pub explanation: String,
}

/// Type of match between Digger and official findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MatchType {
    ExactMatch,
    PartialMatch,
    SemanticMatch,
    NoMatch,
    FalsePositive,
}

// ─── Historical Exploit Replay ────────────────────────────────────

/// Result of replaying a historical exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    pub exploit_id: String,
    pub exploit_name: String,
    pub protocol: String,
    pub chain: String,
    pub expected_outcome: String,
    pub digger_outcome: String,
    pub synthesis_accuracy: f64,
    pub validation_accuracy: f64,
    pub execution_accuracy: f64,
    pub root_cause_match: bool,
    pub affected_components_match: bool,
    pub mitigation_match: bool,
    pub overall_accuracy: f64,
    pub differences: Vec<String>,
    pub explanation: String,
}

// ─── False Positive Analysis ──────────────────────────────────────

/// Analysis of rejected hypotheses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveAnalysis {
    pub total_rejected: usize,
    pub rejection_reasons: BTreeMap<String, usize>,
    pub by_protocol: BTreeMap<String, ProtocolFPStats>,
    pub by_vuln_class: BTreeMap<String, VulnClassFPStats>,
    pub recommendations: Vec<String>,
}

/// False positive stats for a protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolFPStats {
    pub protocol: String,
    pub total_rejected: usize,
    pub top_reasons: Vec<(String, usize)>,
}

/// False positive stats for a vulnerability class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnClassFPStats {
    pub vuln_class: String,
    pub total_rejected: usize,
    pub top_reasons: Vec<(String, usize)>,
}

// ─── Miss Analysis ────────────────────────────────────────────────

/// Detailed miss analysis for missed findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedMissAnalysis {
    pub total_missed: usize,
    pub misses: Vec<SingleMiss>,
    pub by_category: BTreeMap<String, usize>,
    pub improvement_recommendations: Vec<ImprovementRecommendation>,
}

/// A single missed finding analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleMiss {
    pub finding_id: String,
    pub expected_finding: String,
    pub miss_reason: MissReason,
    pub explanation: String,
    pub severity: String,
    pub category: String,
}

/// Reason for missing a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MissReason {
    MissingKnowledge,
    MissingProtocolSemantics,
    MissingReasoningRule,
    MissingValidationLogic,
    ParserLimitation,
    BenchmarkGap,
    ConfidenceTooLow,
    EliminatedByValidation,
    InsufficientEvidence,
}

/// Recommendation for improving detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImprovementRecommendation {
    pub priority: usize,
    pub target: String,
    pub action: String,
    pub expected_impact: String,
    pub effort: String,
}

// ─── Comparative Evaluation ───────────────────────────────────────

/// Comparison between two Digger versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionComparison {
    pub baseline_version: String,
    pub current_version: String,
    pub timestamp: String,
    pub metrics: ComparisonMetrics,
    pub regressions: Vec<RegressionItem>,
    pub improvements: Vec<ImprovementItem>,
    pub verdict: RegressionVerdict,
}

/// Metrics for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonMetrics {
    pub baseline_precision: f64,
    pub current_precision: f64,
    pub baseline_recall: f64,
    pub current_recall: f64,
    pub baseline_f1: f64,
    pub current_f1: f64,
    pub baseline_reasoning_quality: f64,
    pub current_reasoning_quality: f64,
    pub baseline_validation_accuracy: f64,
    pub current_validation_accuracy: f64,
    pub baseline_execution_accuracy: f64,
    pub current_execution_accuracy: f64,
    pub baseline_runtime_ms: u64,
    pub current_runtime_ms: u64,
    pub baseline_memory_bytes: u64,
    pub current_memory_bytes: u64,
}

/// A detected regression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionItem {
    pub metric: String,
    pub baseline_value: f64,
    pub current_value: f64,
    pub delta: f64,
    pub severity: String,
}

/// A detected improvement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImprovementItem {
    pub metric: String,
    pub baseline_value: f64,
    pub current_value: f64,
    pub delta: f64,
}

/// Regression verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RegressionVerdict {
    Pass,
    Warning,
    Fail,
}

// ─── Coverage Dashboard ───────────────────────────────────────────

/// Comprehensive coverage dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDashboard {
    pub generated_at: String,
    pub protocol_coverage: CoverageDimension,
    pub exploit_category_coverage: CoverageDimension,
    pub benchmark_coverage: CoverageDimension,
    pub reasoning_coverage: CoverageDimension,
    pub validation_coverage: CoverageDimension,
    pub execution_coverage: CoverageDimension,
    pub knowledge_coverage: CoverageDimension,
    pub overall_score: f64,
    pub highest_roi_areas: Vec<ROIRecommendation>,
}

/// A single coverage dimension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDimension {
    pub name: String,
    pub covered: usize,
    pub total: usize,
    pub score: f64,
    pub gaps: Vec<String>,
}

/// ROI recommendation for improvement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ROIRecommendation {
    pub area: String,
    pub current_coverage: f64,
    pub potential_coverage: f64,
    pub effort: String,
    pub expected_impact: String,
    pub priority: usize,
}

// ─── Research Report ──────────────────────────────────────────────

/// Comprehensive research report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchReport {
    pub report_id: String,
    pub generated_at: String,
    pub executive_summary: String,
    pub benchmark_metrics: ResearchBenchmarkMetrics,
    pub unique_findings: Vec<String>,
    pub missed_findings: Vec<String>,
    pub exploit_quality: QualityMetrics,
    pub reasoning_quality: QualityMetrics,
    pub validation_quality: QualityMetrics,
    pub execution_quality: QualityMetrics,
    pub improvements: Vec<ImprovementRecommendation>,
}

/// Benchmark metrics for research report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchBenchmarkMetrics {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub detection_rate: f64,
    pub avg_runtime_ms: f64,
    pub coverage_by_class: BTreeMap<String, f64>,
}

/// Quality metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    pub score: f64,
    pub strengths: Vec<String>,
    pub weaknesses: Vec<String>,
    pub test_count: usize,
}

// ─── Continuous Validation ────────────────────────────────────────

/// Result of a continuous validation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuousValidationResult {
    pub run_id: String,
    pub timestamp: String,
    pub benchmark_result: bool,
    pub regression_result: RegressionVerdict,
    pub reasoning_comparison: ReasoningComparison,
    pub validation_comparison: ValidationComparison,
    pub execution_comparison: ExecutionComparison,
    pub overall_verdict: RegressionVerdict,
    pub details: String,
}

/// Reasoning comparison between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningComparison {
    pub hypotheses_before: usize,
    pub hypotheses_after: usize,
    pub consistency_score: f64,
    pub regressions: Vec<String>,
}

/// Validation comparison between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationComparison {
    pub validated_before: usize,
    pub validated_after: usize,
    pub consistency_score: f64,
    pub regressions: Vec<String>,
}

/// Execution comparison between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionComparison {
    pub executed_before: usize,
    pub executed_after: usize,
    pub consistency_score: f64,
    pub regressions: Vec<String>,
}
