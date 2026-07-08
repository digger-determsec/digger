/// Evaluation models — deterministic measurement structures.
use serde::{Deserialize, Serialize};

/// Ground truth for a single exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    /// Exploit identifier.
    pub exploit_id: String,
    /// Expected hypotheses (vulnerability types).
    pub expected_hypotheses: Vec<String>,
    /// Expected evidence types.
    pub expected_evidence_types: Vec<String>,
    /// Expected root cause.
    pub expected_root_cause: String,
    /// Expected violated invariants.
    pub expected_invariants: Vec<String>,
    /// Expected trust boundaries crossed.
    pub expected_trust_boundaries: Vec<String>,
    /// Severity level.
    pub severity: String,
    /// Chain.
    pub chain: String,
    /// Protocol.
    pub protocol: String,
}

/// Evaluation result for a single exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// Exploit identifier.
    pub exploit_id: String,
    /// Precision metrics.
    pub precision: PrecisionMetrics,
    /// Recall metrics.
    pub recall: RecallMetrics,
    /// Root-cause accuracy.
    pub root_cause_accuracy: f64,
    /// Explanation completeness.
    pub explanation_completeness: ExplanationMetrics,
    /// Evidence quality.
    pub evidence_quality: EvidenceMetrics,
    /// Determinism verification.
    pub determinism: DeterminismMetrics,
    /// Runtime metrics.
    pub runtime: RuntimeMetrics,
    /// Whether this exploit passed evaluation.
    pub passed: bool,
}

/// Precision metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecisionMetrics {
    /// True positives.
    pub true_positives: usize,
    /// False positives.
    pub false_positives: usize,
    /// Precision = TP / (TP + FP).
    pub precision: f64,
}

/// Recall metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallMetrics {
    /// True positives.
    pub true_positives: usize,
    /// False negatives (missed detections).
    pub false_negatives: usize,
    /// Recall = TP / (TP + FN).
    pub recall: f64,
}

/// Explanation metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationMetrics {
    /// Has reasoning trace.
    pub has_reasoning_trace: bool,
    /// Has evidence chain.
    pub has_evidence_chain: bool,
    /// Has violated invariants.
    pub has_violated_invariants: bool,
    /// Has trust boundaries.
    pub has_trust_boundaries: bool,
    /// Has mitigation rationale.
    pub has_mitigation: bool,
    /// Completeness score (0.0–1.0).
    pub completeness_score: f64,
}

/// Evidence metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceMetrics {
    /// Total evidence items.
    pub total_evidence: usize,
    /// Unique evidence items.
    pub unique_evidence: usize,
    /// Evidence depth (items per hypothesis).
    pub depth: f64,
    /// Evidence diversity (distinct types).
    pub diversity: usize,
}

/// Determinism metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterminismMetrics {
    /// Whether output is deterministic across runs.
    pub is_deterministic: bool,
    /// Number of runs performed.
    pub runs: usize,
    /// Hash of output (for comparison).
    pub output_hash: String,
}

/// Runtime metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeMetrics {
    /// Parse time (ms).
    pub parse_ms: f64,
    /// Graph build time (ms).
    pub graph_build_ms: f64,
    /// Hypothesis generation time (ms).
    pub hypothesis_ms: f64,
    /// Pipeline processing time (ms).
    pub pipeline_ms: f64,
    /// Total time (ms).
    pub total_ms: f64,
    /// Peak memory usage (bytes).
    pub peak_memory_bytes: usize,
}

/// Aggregate evaluation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationReport {
    /// Total exploits evaluated.
    pub total_exploits: usize,
    /// Individual results.
    pub results: Vec<EvaluationResult>,
    /// Aggregate precision.
    pub aggregate_precision: f64,
    /// Aggregate recall.
    pub aggregate_recall: f64,
    /// Aggregate F1 score.
    pub aggregate_f1: f64,
    /// Average root-cause accuracy.
    pub avg_root_cause_accuracy: f64,
    /// Average explanation completeness.
    pub avg_explanation_completeness: f64,
    /// Average evidence depth.
    pub avg_evidence_depth: f64,
    /// Determinism rate (deterministic / total).
    pub determinism_rate: f64,
    /// Average runtime (ms).
    pub avg_runtime_ms: f64,
    /// Total runtime (ms).
    pub total_runtime_ms: f64,
    /// Average peak memory (bytes).
    pub avg_peak_memory: usize,
    /// Pass rate.
    pub pass_rate: f64,
}
