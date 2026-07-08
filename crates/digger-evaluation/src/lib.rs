#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

//! Digger Evaluation Framework — comprehensive real-world validation.
//!
//! Four names (FindingComparison, EvaluationResult, Regression, report_to_json) are
//! intentionally defined in distinct modules with different semantics. They are NOT
//! re-exported from the crate root — access them via their module path.

pub mod blind;
pub mod case_study;
pub mod contest_eval;
pub mod continuous;
pub mod continuous_regression;
pub mod coverage_dashboard;
pub mod differential;
pub mod eval_models;
pub mod false_positive;
pub mod harness;
pub mod improvement;
pub mod integration;
pub mod live_eval;
pub mod live_protocol_eval;
pub mod market_dashboard;
pub mod metrics;
pub mod miss_analysis;
pub mod models;
pub mod perf_profile;
pub mod regression;
pub mod replay_eval;
pub mod research_dataset;
pub mod research_dataset_v2;
pub mod research_report;

pub use blind::*;
pub use case_study::*;
pub use contest_eval::*;
pub use continuous::*;
pub use continuous_regression::*;
pub use coverage_dashboard::*;
pub use false_positive::*;
pub use improvement::*;
pub use integration::*;
pub use market_dashboard::*;
pub use metrics::*;
pub use miss_analysis::*;
pub use perf_profile::*;
pub use replay_eval::*;
pub use research_dataset::*;
pub use research_dataset_v2::*;
pub use research_report::*;

pub use differential::{
    compare_snapshots, AggregateChanges, AggregateSnapshot, ConfidenceDrift, DifferentialReport,
    EvaluationSnapshot, ExplanationChange, NewDetection, RankingDrift,
};
pub use eval_models::{
    ComparisonMetrics, ContestEvaluation, ContinuousValidationResult, CoverageDashboard,
    CoverageDimension, DetailedMissAnalysis, ExecutionComparison, FalsePositiveAnalysis,
    ImprovementItem, ImprovementRecommendation, MatchType, ProtocolFPStats, QualityMetrics,
    ReasoningComparison, RegressionItem, RegressionVerdict, ReplayResult, ResearchBenchmarkMetrics,
    ResearchReport, SingleMiss, ValidationComparison, VersionComparison, VulnClassFPStats,
};
pub use harness::{report_from_json, run_evaluation, EvalError};
pub use live_eval::{
    aggregate_results, evaluate_target, evaluate_targets, DiggerFinding, EvaluationSummary,
    EvaluationTarget, OfficialFinding, PerformanceMetrics,
};
pub use live_protocol_eval::{
    compute_similarity, evaluate_protocol, EvalPerformanceMetrics, EvaluationMetrics,
    EvidenceChainLink, FindingValidationReport, MatchClassification, ProtocolEvaluation,
};
pub use models::{
    DeterminismMetrics, EvidenceMetrics, ExplanationMetrics, GroundTruth, PrecisionMetrics,
    RecallMetrics, RuntimeMetrics,
};
pub use regression::{
    analyze_coverage, compare_reports, CoverageAnalysisReport, Improvement, IntegrityReport,
    MissingCategory, ModifiedCase, RegressionReport, WeakCoverage,
};
