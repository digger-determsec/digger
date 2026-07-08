/// Benchmark models — deterministic validation structures.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DetectorStatus {
    Frozen,
    Experimental,
    Graduated,
}

/// Exploit metadata from meta.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitMeta {
    pub exploit_id: String,
    pub vulnerability_class: String,
    pub protocol: String,
    pub chain: String,
    pub year: u32,
    pub loss_usd: u64,
    pub expected_findings: Vec<String>,
    pub expected_path_types: Vec<String>,
    pub expected_hypotheses: Vec<String>,
    pub known_limitations: Vec<String>,
}

/// A loaded exploit with source code and metadata.
#[derive(Debug, Clone)]
pub struct LoadedExploit {
    pub meta: ExploitMeta,
    pub source_code: String,
    pub language: String,
    pub source_path: String,
}

/// Result of benchmarking a single exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub exploit_id: String,
    pub vulnerability_class: String,
    pub protocol: String,
    pub findings_detected: Vec<String>,
    pub findings_expected: Vec<String>,
    pub findings_matched: Vec<String>,
    pub findings_missed: Vec<String>,
    pub findings_unexpected: Vec<String>,
    pub detection_rate: f64,
    pub hypothesis_types_detected: Vec<String>,
    pub passed: bool,
    /// Reasoning quality metrics for this exploit.
    pub reasoning_quality: Option<ReasoningQualityResult>,
}

/// Reasoning quality result for a single exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningQualityResult {
    /// Average evidence depth (evidence items per hypothesis).
    pub avg_evidence_depth: f64,
    /// Average reasoning depth (reasoning text length).
    pub avg_reasoning_depth: f64,
    /// Number of hypotheses generated.
    pub total_hypotheses: usize,
    /// Number of hypotheses with explanations.
    pub hypotheses_with_explanations: usize,
    /// Explanation completeness score (0.0–1.0).
    pub explanation_completeness: f64,
    /// Number of contradictions detected.
    pub contradictions_detected: usize,
    /// Number of assumptions validated.
    pub assumptions_validated: usize,
    /// Ranking determinism verified.
    pub ranking_deterministic: bool,
    /// Root cause accuracy (hypotheses matching expected root cause).
    pub root_cause_accuracy: f64,
    /// False positive count.
    pub false_positives: usize,
}

/// Aggregate benchmark report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub total_exploits: usize,
    pub passed: usize,
    pub failed: usize,
    /// Finding-level coverage rate = total_matched / total_expected.
    #[serde(alias = "overall_detection_rate")]
    pub finding_coverage_rate: f64,
    pub by_class: Vec<ClassReport>,
    pub results: Vec<BenchmarkResult>,
    /// Aggregate reasoning quality metrics.
    pub reasoning_quality: Option<AggregateReasoningQuality>,
}

/// Aggregate reasoning quality across all exploits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateReasoningQuality {
    /// Average evidence depth across all exploits.
    pub avg_evidence_depth: f64,
    /// Average reasoning depth.
    pub avg_reasoning_depth: f64,
    /// Average explanation completeness.
    pub avg_explanation_completeness: f64,
    /// Total contradictions across all exploits.
    pub total_contradictions: usize,
    /// Total assumptions validated.
    pub total_assumptions_validated: usize,
    /// Ranking determinism rate (deterministic / total).
    pub ranking_determinism_rate: f64,
    /// Average root cause accuracy.
    pub avg_root_cause_accuracy: f64,
    /// Total false positives.
    pub total_false_positives: usize,
    /// False positive rate (false_positives / total_hypotheses).
    pub false_positive_rate: f64,
    /// Regression stability (unchanged results across runs).
    pub regression_stability: f64,
}

/// Per-vulnerability-class report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassReport {
    pub vulnerability_class: String,
    pub total: usize,
    pub passed: usize,
    pub detection_rate: f64,
}
