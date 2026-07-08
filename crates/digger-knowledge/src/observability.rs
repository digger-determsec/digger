/// Knowledge Observability — tracks how the knowledge base evolves over time.
///
/// Compares successive corpus snapshots and reports changes.
/// Never modifies the ontology or reasoning engine.
///
/// Provides historical observability for measuring how Digger's
/// security knowledge evolves across releases and corpus expansions.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════
// Snapshot
// ═══════════════════════════════════════════════════════════════

/// A point-in-time capture of the knowledge base state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeSnapshot {
    /// Snapshot identifier (deterministic hash of state).
    pub snapshot_id: String,
    /// Snapshot label (e.g., "v1.0.0", "2026-06-14", "post-c4-ingestion").
    pub label: String,
    /// Total reports ingested.
    pub total_reports: usize,
    /// Total findings.
    pub total_findings: usize,
    /// Total protocols.
    pub total_protocols: usize,
    /// Total distinct functions.
    pub total_functions: usize,
    /// Source distribution.
    pub sources: BTreeMap<String, usize>,
    /// Category distribution.
    pub categories: BTreeMap<String, usize>,
    /// Severity distribution.
    pub severity: BTreeMap<String, usize>,
    /// Vulnerability class coverage percentage.
    pub class_coverage_pct: f64,
    /// Attack technique coverage percentage.
    pub technique_coverage_pct: f64,
    /// Root cause coverage percentage.
    pub root_cause_coverage_pct: f64,
    /// Total knowledge graph nodes.
    pub graph_nodes: usize,
    /// Total knowledge graph edges.
    pub graph_edges: usize,
    /// Average graph degree.
    pub graph_avg_degree: f64,
    /// Total reasoning patterns.
    pub total_patterns: usize,
    /// Well-supported patterns (5+ protocols).
    pub well_supported_patterns: usize,
    /// Total semantic equivalence pairs.
    pub equivalence_pairs: usize,
    /// Cross-protocol equivalence pairs.
    pub cross_protocol_pairs: usize,
    /// Total distinct canonical classes.
    pub distinct_classes: usize,
    /// Total distinct canonical techniques.
    pub distinct_techniques: usize,
    /// Total distinct canonical root causes.
    pub distinct_root_causes: usize,
    /// Overall health score.
    pub health_score: f64,
}

// ═══════════════════════════════════════════════════════════════
// Trends and Deltas
// ═══════════════════════════════════════════════════════════════

/// A trend analysis comparing two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeTrend {
    /// Baseline snapshot.
    pub baseline: KnowledgeSnapshot,
    /// Current snapshot.
    pub current: KnowledgeSnapshot,
    /// Metric deltas.
    pub deltas: Vec<MetricDelta>,
    /// Coverage trends.
    pub coverage_trend: CoverageTrend,
    /// Pattern trends.
    pub pattern_trend: PatternTrend,
    /// Graph trends.
    pub graph_trend: GraphTrend,
    /// Ontology trends.
    pub ontology_trend: OntologyTrend,
    /// Quality regressions detected.
    pub regressions: Vec<QualityRegression>,
    /// Milestones reached.
    pub milestones: Vec<KnowledgeMilestone>,
}

/// Change in a metric between snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricDelta {
    /// Metric name.
    pub name: String,
    /// Previous value.
    pub previous: f64,
    /// Current value.
    pub current: f64,
    /// Absolute change.
    pub delta: f64,
    /// Percentage change.
    pub pct_change: f64,
    /// Direction: "up", "down", "stable".
    pub direction: String,
}

/// Coverage evolution between snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoverageTrend {
    /// Class coverage delta.
    pub class_coverage: MetricDelta,
    /// Technique coverage delta.
    pub technique_coverage: MetricDelta,
    /// Root cause coverage delta.
    pub root_cause_coverage: MetricDelta,
    /// Newly classified findings.
    pub newly_classified: usize,
    /// Newly unclassified findings.
    pub newly_unclassified: usize,
}

/// Reasoning pattern evolution between snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatternTrend {
    /// Total patterns delta.
    pub total_patterns: MetricDelta,
    /// Well-supported patterns delta.
    pub well_supported: MetricDelta,
    /// Newly emerged patterns.
    pub new_patterns: Vec<String>,
    /// Patterns that lost support.
    pub weakened_patterns: Vec<String>,
}

/// Knowledge graph evolution between snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphTrend {
    /// Nodes delta.
    pub nodes: MetricDelta,
    /// Edges delta.
    pub edges: MetricDelta,
    /// Average degree delta.
    pub avg_degree: MetricDelta,
    /// Equivalence pairs delta.
    pub equivalence_pairs: MetricDelta,
}

/// Ontology evolution between snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OntologyTrend {
    /// Distinct classes delta.
    pub distinct_classes: MetricDelta,
    /// Distinct techniques delta.
    pub distinct_techniques: MetricDelta,
    /// Distinct root causes delta.
    pub distinct_root_causes: MetricDelta,
    /// Newly introduced concepts.
    pub new_concepts: Vec<String>,
    /// Deprecated concepts.
    pub deprecated_concepts: Vec<String>,
}

/// A quality regression detected between snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QualityRegression {
    /// Regression kind.
    pub kind: RegressionKind,
    /// Description.
    pub description: String,
    /// Previous value.
    pub previous: f64,
    /// Current value.
    pub current: f64,
    /// Severity: "critical", "warning", "info".
    pub severity: String,
    /// Recommendation.
    pub recommendation: String,
}

/// Kind of quality regression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegressionKind {
    /// Coverage decreased.
    CoverageDecrease,
    /// Quality score decreased.
    QualityDecrease,
    /// Graph connectivity decreased.
    ConnectivityDecrease,
    /// Pattern support decreased.
    PatternSupportDecrease,
    /// New orphan concepts appeared.
    NewOrphanConcepts,
    /// Duplicate rate increased.
    DuplicateIncrease,
}

impl std::fmt::Display for RegressionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CoverageDecrease => write!(f, "coverage_decrease"),
            Self::QualityDecrease => write!(f, "quality_decrease"),
            Self::ConnectivityDecrease => write!(f, "connectivity_decrease"),
            Self::PatternSupportDecrease => write!(f, "pattern_support_decrease"),
            Self::NewOrphanConcepts => write!(f, "new_orphan_concepts"),
            Self::DuplicateIncrease => write!(f, "duplicate_increase"),
        }
    }
}

/// A milestone in knowledge evolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeMilestone {
    /// Milestone kind.
    pub kind: MilestoneKind,
    /// Description.
    pub description: String,
    /// Value achieved.
    pub value: f64,
    /// Threshold crossed.
    pub threshold: f64,
}

/// Kind of milestone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MilestoneKind {
    /// Coverage exceeded a threshold.
    CoverageThreshold,
    /// Pattern count exceeded a threshold.
    PatternThreshold,
    /// Protocol count exceeded a threshold.
    ProtocolThreshold,
    /// Finding count exceeded a threshold.
    FindingThreshold,
    /// Graph density exceeded a threshold.
    GraphDensityThreshold,
    /// Health score exceeded a threshold.
    HealthScoreThreshold,
}

impl std::fmt::Display for MilestoneKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CoverageThreshold => write!(f, "coverage_threshold"),
            Self::PatternThreshold => write!(f, "pattern_threshold"),
            Self::ProtocolThreshold => write!(f, "protocol_threshold"),
            Self::FindingThreshold => write!(f, "finding_threshold"),
            Self::GraphDensityThreshold => write!(f, "graph_density_threshold"),
            Self::HealthScoreThreshold => write!(f, "health_score_threshold"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Observability Engine
// ═══════════════════════════════════════════════════════════════

/// Create a snapshot from current knowledge state.
pub fn create_snapshot(
    knowledge_items: &[digger_knowledge_models::NormalizedKnowledge],
    analytics: &super::analytics::CorpusAnalyticsReport,
    label: &str,
) -> KnowledgeSnapshot {
    let snapshot_id = compute_snapshot_id(knowledge_items, label);

    KnowledgeSnapshot {
        snapshot_id,
        label: label.into(),
        total_reports: analytics.overview.total_reports,
        total_findings: analytics.overview.total_findings,
        total_protocols: analytics.overview.total_protocols,
        total_functions: analytics.overview.total_functions,
        sources: analytics.overview.sources.clone(),
        categories: analytics.overview.categories.clone(),
        severity: analytics.overview.severity_distribution.clone(),
        class_coverage_pct: analytics.coverage.vulnerability_classes.coverage_pct,
        technique_coverage_pct: analytics.coverage.attack_techniques.coverage_pct,
        root_cause_coverage_pct: analytics.coverage.root_causes.coverage_pct,
        graph_nodes: analytics.graph_stats.total_nodes,
        graph_edges: analytics.graph_stats.total_edges,
        graph_avg_degree: analytics.graph_stats.avg_degree,
        total_patterns: analytics.pattern_stats.total_patterns,
        well_supported_patterns: analytics.pattern_stats.well_supported_patterns,
        equivalence_pairs: analytics.equivalence_stats.total_pairs,
        cross_protocol_pairs: analytics.equivalence_stats.cross_protocol_pairs,
        distinct_classes: analytics.coverage.vulnerability_classes.distinct_categories,
        distinct_techniques: analytics.coverage.attack_techniques.distinct_categories,
        distinct_root_causes: analytics.coverage.root_causes.distinct_categories,
        health_score: 0.0, // computed separately
    }
}

fn compute_snapshot_id(
    items: &[digger_knowledge_models::NormalizedKnowledge],
    label: &str,
) -> String {
    let mut h: u64 = 0;
    for byte in label.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    for item in items {
        for byte in item.knowledge_id.bytes() {
            h = h.wrapping_mul(31).wrapping_add(byte as u64);
        }
    }
    format!("{:x}", h)
}

/// Compare two snapshots and produce a trend analysis.
pub fn compare_snapshots(
    baseline: &KnowledgeSnapshot,
    current: &KnowledgeSnapshot,
) -> KnowledgeTrend {
    let deltas = compute_deltas(baseline, current);
    let coverage_trend = compute_coverage_trend(baseline, current);
    let pattern_trend = compute_pattern_trend(baseline, current);
    let graph_trend = compute_graph_trend(baseline, current);
    let ontology_trend = compute_ontology_trend(baseline, current);
    let regressions = detect_regressions(baseline, current);
    let milestones = detect_milestones(baseline, current);

    KnowledgeTrend {
        baseline: baseline.clone(),
        current: current.clone(),
        deltas,
        coverage_trend,
        pattern_trend,
        graph_trend,
        ontology_trend,
        regressions,
        milestones,
    }
}

fn compute_deltas(baseline: &KnowledgeSnapshot, current: &KnowledgeSnapshot) -> Vec<MetricDelta> {
    vec![
        delta(
            "total_reports",
            baseline.total_reports as f64,
            current.total_reports as f64,
        ),
        delta(
            "total_findings",
            baseline.total_findings as f64,
            current.total_findings as f64,
        ),
        delta(
            "total_protocols",
            baseline.total_protocols as f64,
            current.total_protocols as f64,
        ),
        delta(
            "total_functions",
            baseline.total_functions as f64,
            current.total_functions as f64,
        ),
        delta(
            "class_coverage",
            baseline.class_coverage_pct,
            current.class_coverage_pct,
        ),
        delta(
            "technique_coverage",
            baseline.technique_coverage_pct,
            current.technique_coverage_pct,
        ),
        delta(
            "root_cause_coverage",
            baseline.root_cause_coverage_pct,
            current.root_cause_coverage_pct,
        ),
        delta(
            "graph_nodes",
            baseline.graph_nodes as f64,
            current.graph_nodes as f64,
        ),
        delta(
            "graph_edges",
            baseline.graph_edges as f64,
            current.graph_edges as f64,
        ),
        delta(
            "graph_avg_degree",
            baseline.graph_avg_degree,
            current.graph_avg_degree,
        ),
        delta(
            "total_patterns",
            baseline.total_patterns as f64,
            current.total_patterns as f64,
        ),
        delta(
            "equivalence_pairs",
            baseline.equivalence_pairs as f64,
            current.equivalence_pairs as f64,
        ),
        delta("health_score", baseline.health_score, current.health_score),
    ]
}

fn delta(name: &str, prev: f64, curr: f64) -> MetricDelta {
    let d = curr - prev;
    let pct = if prev > 0.0 { d / prev * 100.0 } else { 0.0 };
    let direction = if d > 0.01 {
        "up".into()
    } else if d < -0.01 {
        "down".into()
    } else {
        "stable".into()
    };
    MetricDelta {
        name: name.into(),
        previous: prev,
        current: curr,
        delta: d,
        pct_change: pct,
        direction,
    }
}

fn compute_coverage_trend(
    baseline: &KnowledgeSnapshot,
    current: &KnowledgeSnapshot,
) -> CoverageTrend {
    CoverageTrend {
        class_coverage: delta(
            "class_coverage",
            baseline.class_coverage_pct,
            current.class_coverage_pct,
        ),
        technique_coverage: delta(
            "technique_coverage",
            baseline.technique_coverage_pct,
            current.technique_coverage_pct,
        ),
        root_cause_coverage: delta(
            "root_cause_coverage",
            baseline.root_cause_coverage_pct,
            current.root_cause_coverage_pct,
        ),
        newly_classified: (current.total_findings as f64 * current.class_coverage_pct / 100.0
            - baseline.total_findings as f64 * baseline.class_coverage_pct / 100.0)
            .max(0.0) as usize,
        newly_unclassified: 0,
    }
}

fn compute_pattern_trend(
    baseline: &KnowledgeSnapshot,
    current: &KnowledgeSnapshot,
) -> PatternTrend {
    PatternTrend {
        total_patterns: delta(
            "total_patterns",
            baseline.total_patterns as f64,
            current.total_patterns as f64,
        ),
        well_supported: delta(
            "well_supported",
            baseline.well_supported_patterns as f64,
            current.well_supported_patterns as f64,
        ),
        new_patterns: vec![],
        weakened_patterns: vec![],
    }
}

fn compute_graph_trend(baseline: &KnowledgeSnapshot, current: &KnowledgeSnapshot) -> GraphTrend {
    GraphTrend {
        nodes: delta(
            "graph_nodes",
            baseline.graph_nodes as f64,
            current.graph_nodes as f64,
        ),
        edges: delta(
            "graph_edges",
            baseline.graph_edges as f64,
            current.graph_edges as f64,
        ),
        avg_degree: delta(
            "graph_avg_degree",
            baseline.graph_avg_degree,
            current.graph_avg_degree,
        ),
        equivalence_pairs: delta(
            "equivalence_pairs",
            baseline.equivalence_pairs as f64,
            current.equivalence_pairs as f64,
        ),
    }
}

fn compute_ontology_trend(
    baseline: &KnowledgeSnapshot,
    current: &KnowledgeSnapshot,
) -> OntologyTrend {
    OntologyTrend {
        distinct_classes: delta(
            "distinct_classes",
            baseline.distinct_classes as f64,
            current.distinct_classes as f64,
        ),
        distinct_techniques: delta(
            "distinct_techniques",
            baseline.distinct_techniques as f64,
            current.distinct_techniques as f64,
        ),
        distinct_root_causes: delta(
            "distinct_root_causes",
            baseline.distinct_root_causes as f64,
            current.distinct_root_causes as f64,
        ),
        new_concepts: vec![],
        deprecated_concepts: vec![],
    }
}

fn detect_regressions(
    baseline: &KnowledgeSnapshot,
    current: &KnowledgeSnapshot,
) -> Vec<QualityRegression> {
    let mut regressions = Vec::new();

    // Coverage regression
    if current.class_coverage_pct < baseline.class_coverage_pct - 1.0 {
        regressions.push(QualityRegression {
            kind: RegressionKind::CoverageDecrease,
            description: format!(
                "Class coverage decreased from {:.1}% to {:.1}%",
                baseline.class_coverage_pct, current.class_coverage_pct
            ),
            previous: baseline.class_coverage_pct,
            current: current.class_coverage_pct,
            severity: "warning".into(),
            recommendation: "Review recent corpus additions for classification gaps".into(),
        });
    }

    // Pattern support regression
    if current.well_supported_patterns < baseline.well_supported_patterns {
        regressions.push(QualityRegression {
            kind: RegressionKind::PatternSupportDecrease,
            description: format!(
                "Well-supported patterns decreased from {} to {}",
                baseline.well_supported_patterns, current.well_supported_patterns
            ),
            previous: baseline.well_supported_patterns as f64,
            current: current.well_supported_patterns as f64,
            severity: "warning".into(),
            recommendation: "Review pattern support — corpus changes may have weakened patterns"
                .into(),
        });
    }

    // Graph connectivity regression
    if current.graph_avg_degree < baseline.graph_avg_degree - 0.5 {
        regressions.push(QualityRegression {
            kind: RegressionKind::ConnectivityDecrease,
            description: format!(
                "Graph average degree decreased from {:.2} to {:.2}",
                baseline.graph_avg_degree, current.graph_avg_degree
            ),
            previous: baseline.graph_avg_degree,
            current: current.graph_avg_degree,
            severity: "info".into(),
            recommendation: "Review graph connectivity — new nodes may be isolated".into(),
        });
    }

    // Health score regression
    if current.health_score < baseline.health_score - 0.05 {
        regressions.push(QualityRegression {
            kind: RegressionKind::QualityDecrease,
            description: format!(
                "Health score decreased from {:.2} to {:.2}",
                baseline.health_score, current.health_score
            ),
            previous: baseline.health_score,
            current: current.health_score,
            severity: "critical".into(),
            recommendation: "Review all quality dimensions for degradation".into(),
        });
    }

    regressions
}

fn detect_milestones(
    baseline: &KnowledgeSnapshot,
    current: &KnowledgeSnapshot,
) -> Vec<KnowledgeMilestone> {
    let mut milestones = Vec::new();

    // Coverage milestones
    for threshold in &[25.0, 50.0, 75.0, 90.0] {
        if baseline.class_coverage_pct < *threshold && current.class_coverage_pct >= *threshold {
            milestones.push(KnowledgeMilestone {
                kind: MilestoneKind::CoverageThreshold,
                description: format!("Class coverage exceeded {:.0}%", threshold),
                value: current.class_coverage_pct,
                threshold: *threshold,
            });
        }
    }

    // Pattern milestones
    for threshold in &[10, 25, 50, 100] {
        if baseline.total_patterns < *threshold && current.total_patterns >= *threshold {
            milestones.push(KnowledgeMilestone {
                kind: MilestoneKind::PatternThreshold,
                description: format!("Reasoning patterns exceeded {}", threshold),
                value: current.total_patterns as f64,
                threshold: *threshold as f64,
            });
        }
    }

    // Protocol milestones
    for threshold in &[50, 100, 200, 500] {
        if baseline.total_protocols < *threshold && current.total_protocols >= *threshold {
            milestones.push(KnowledgeMilestone {
                kind: MilestoneKind::ProtocolThreshold,
                description: format!("Protocols exceeded {}", threshold),
                value: current.total_protocols as f64,
                threshold: *threshold as f64,
            });
        }
    }

    // Finding milestones
    for threshold in &[1000, 5000, 10000, 50000] {
        if baseline.total_findings < *threshold && current.total_findings >= *threshold {
            milestones.push(KnowledgeMilestone {
                kind: MilestoneKind::FindingThreshold,
                description: format!("Findings exceeded {}", threshold),
                value: current.total_findings as f64,
                threshold: *threshold as f64,
            });
        }
    }

    // Health score milestones
    for threshold in &[0.5, 0.7, 0.8, 0.9] {
        if baseline.health_score < *threshold && current.health_score >= *threshold {
            milestones.push(KnowledgeMilestone {
                kind: MilestoneKind::HealthScoreThreshold,
                description: format!("Health score exceeded {:.1}", threshold),
                value: current.health_score,
                threshold: *threshold,
            });
        }
    }

    milestones
}

/// Serialize trend to JSON.
pub fn trend_to_json(trend: &KnowledgeTrend) -> String {
    serde_json::to_string_pretty(trend).unwrap_or_else(|_| "{}".into())
}

/// Serialize snapshot to JSON.
pub fn snapshot_to_json(snapshot: &KnowledgeSnapshot) -> String {
    serde_json::to_string_pretty(snapshot).unwrap_or_else(|_| "{}".into())
}
