/// Knowledge Quality Assurance — deterministic validation of the knowledge corpus.
///
/// Measures, explains, and reports the quality of the knowledge layer.
/// Never modifies knowledge automatically.
///
/// Evaluates:
/// - Ontology coverage over time
/// - Parser extraction quality
/// - Normalization quality
/// - Semantic equivalence quality
/// - Reasoning pattern stability
/// - Duplicate detection quality
/// - Graph connectivity
/// - Orphaned concepts
/// - Unsupported ontology entries
/// - Low-confidence reasoning artifacts
use digger_knowledge_models::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════
// Quality Report Types
// ═══════════════════════════════════════════════════════════════

/// The complete knowledge quality report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeQualityReport {
    /// Report identifier (deterministic).
    pub report_id: String,
    /// Overall health score (0.0–1.0).
    pub health_score: f64,
    /// Ontology health metrics.
    pub ontology_health: OntologyHealth,
    /// Extraction quality metrics.
    pub extraction_quality: ExtractionQuality,
    /// Normalization quality metrics.
    pub normalization_quality: NormalizationQuality,
    /// Graph quality metrics.
    pub graph_quality: GraphQuality,
    /// Pattern quality metrics.
    pub pattern_quality: PatternQuality,
    /// Coverage gaps.
    pub coverage_gaps: Vec<CoverageGap>,
    /// Consistency issues.
    pub consistency_issues: Vec<ConsistencyIssue>,
    /// Orphan concepts.
    pub orphan_concepts: Vec<OrphanConcept>,
    /// Duplicate clusters.
    pub duplicate_clusters: Vec<DuplicateCluster>,
    /// Quality metrics over time.
    pub metrics: Vec<QualityMetric>,
    /// Recommendations for human review.
    pub recommendations: Vec<QualityRecommendation>,
}

/// Ontology health — how well the canonical taxonomy covers the corpus.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OntologyHealth {
    /// Vulnerability class coverage percentage.
    pub class_coverage_pct: f64,
    /// Attack technique coverage percentage.
    pub technique_coverage_pct: f64,
    /// Root cause coverage percentage.
    pub root_cause_coverage_pct: f64,
    /// Invariant type coverage percentage.
    pub invariant_coverage_pct: f64,
    /// Unsupported ontology entries (entries with zero corpus support).
    pub unsupported_entries: Vec<String>,
    /// Overall ontology health score.
    pub health_score: f64,
}

/// Extraction quality — how well the parser extracts structured data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtractionQuality {
    /// Total reports parsed.
    pub total_reports: usize,
    /// Reports with zero findings (potential parse failure).
    pub empty_reports: usize,
    /// Findings with blank descriptions.
    pub blank_descriptions: usize,
    /// Findings with blank root causes.
    pub blank_root_causes: usize,
    /// Findings with blank remediation.
    pub blank_remediation: usize,
    /// Findings with extracted functions.
    pub findings_with_functions: usize,
    /// Findings with extracted code snippets.
    pub findings_with_snippets: usize,
    /// Extraction quality score (0.0–1.0).
    pub quality_score: f64,
}

/// Normalization quality — how well findings map to canonical taxonomy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizationQuality {
    /// Total findings.
    pub total_findings: usize,
    /// Findings classified into canonical classes.
    pub classified_findings: usize,
    /// Findings with canonical attack techniques.
    pub classified_techniques: usize,
    /// Findings with canonical root causes.
    pub classified_root_causes: usize,
    /// Findings with canonical attack goals.
    pub classified_goals: usize,
    /// Normalization quality score (0.0–1.0).
    pub quality_score: f64,
}

/// Graph quality — knowledge graph health metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphQuality {
    /// Total nodes.
    pub total_nodes: usize,
    /// Total edges.
    pub total_edges: usize,
    /// Isolated nodes (no edges).
    pub isolated_nodes: usize,
    /// Connected components.
    pub connected_components: usize,
    /// Average degree.
    pub avg_degree: f64,
    /// Graph density (edges / max possible edges).
    pub density: f64,
    /// Graph quality score (0.0–1.0).
    pub quality_score: f64,
}

/// Pattern quality — reasoning pattern health metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatternQuality {
    /// Total patterns.
    pub total_patterns: usize,
    /// Well-supported patterns (5+ protocols).
    pub well_supported: usize,
    /// Weakly supported patterns (1–2 protocols).
    pub weakly_supported: usize,
    /// Average findings per pattern.
    pub avg_findings: f64,
    /// Average protocols per pattern.
    pub avg_protocols: f64,
    /// Pattern quality score (0.0–1.0).
    pub quality_score: f64,
}

/// A coverage gap — where the ontology doesn't cover the corpus.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoverageGap {
    /// Gap kind.
    pub kind: CoverageGapKind,
    /// Description.
    pub description: String,
    /// Number of affected findings.
    pub affected_findings: usize,
    /// Affected protocols.
    pub affected_protocols: Vec<String>,
    /// Recommendation for addressing this gap.
    pub recommendation: String,
}

/// Kind of coverage gap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CoverageGapKind {
    /// Missing vulnerability class.
    MissingClass,
    /// Missing attack technique.
    MissingTechnique,
    /// Missing root cause.
    MissingRootCause,
    /// Missing invariant type.
    MissingInvariant,
    /// Missing mitigation pattern.
    MissingMitigation,
}

impl std::fmt::Display for CoverageGapKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingClass => write!(f, "missing_class"),
            Self::MissingTechnique => write!(f, "missing_technique"),
            Self::MissingRootCause => write!(f, "missing_root_cause"),
            Self::MissingInvariant => write!(f, "missing_invariant"),
            Self::MissingMitigation => write!(f, "missing_mitigation"),
        }
    }
}

/// A consistency issue — where the knowledge layer has contradictions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsistencyIssue {
    /// Issue kind.
    pub kind: ConsistencyKind,
    /// Description.
    pub description: String,
    /// Affected finding IDs.
    pub affected_findings: Vec<String>,
    /// Recommendation.
    pub recommendation: String,
}

/// Kind of consistency issue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsistencyKind {
    /// Same finding classified differently across sources.
    InconsistentClassification,
    /// Same protocol classified differently.
    InconsistentCategory,
    /// Finding severity contradicts classification.
    SeverityMismatch,
    /// Duplicate findings with different IDs.
    DuplicateFinding,
    /// Orphaned reference (references non-existent finding).
    OrphanedReference,
}

impl std::fmt::Display for ConsistencyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InconsistentClassification => write!(f, "inconsistent_classification"),
            Self::InconsistentCategory => write!(f, "inconsistent_category"),
            Self::SeverityMismatch => write!(f, "severity_mismatch"),
            Self::DuplicateFinding => write!(f, "duplicate_finding"),
            Self::OrphanedReference => write!(f, "orphaned_reference"),
        }
    }
}

/// An orphan concept — an ontology entry with no corpus support.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrphanConcept {
    /// Concept name.
    pub name: String,
    /// Concept kind.
    pub kind: String,
    /// Recommendation: deprecate, promote, or wait.
    pub recommendation: String,
}

/// A duplicate cluster — findings that may be duplicates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DuplicateCluster {
    /// Cluster identifier.
    pub cluster_id: String,
    /// Finding IDs in this cluster.
    pub finding_ids: Vec<String>,
    /// Similarity evidence.
    pub similarity: String,
    /// Recommendation: merge, keep separate, or review.
    pub recommendation: String,
}

/// A quality metric — a single measurement over time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QualityMetric {
    /// Metric name.
    pub name: String,
    /// Metric value.
    pub value: f64,
    /// Metric unit.
    pub unit: String,
    /// Description.
    pub description: String,
}

/// A quality recommendation for human review.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QualityRecommendation {
    /// Recommendation identifier.
    pub recommendation_id: String,
    /// Recommendation kind.
    pub kind: String,
    /// Description.
    pub description: String,
    /// Priority: high, medium, low.
    pub priority: String,
    /// Affected components.
    pub affected: Vec<String>,
    /// Evidence supporting this recommendation.
    pub evidence: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Quality Assurance Engine
// ═══════════════════════════════════════════════════════════════

/// Compute knowledge quality report from corpus and analytics.
pub fn compute_quality_report(
    knowledge_items: &[NormalizedKnowledge],
    analytics: &super::analytics::CorpusAnalyticsReport,
) -> KnowledgeQualityReport {
    let all_findings: Vec<&NormalizedFinding> = knowledge_items
        .iter()
        .flat_map(|k| k.findings.iter())
        .collect();

    let ontology_health = compute_ontology_health(&all_findings, analytics);
    let extraction_quality = compute_extraction_quality(&all_findings, knowledge_items);
    let normalization_quality = compute_normalization_quality(&all_findings);
    let graph_quality = compute_graph_quality(analytics);
    let pattern_quality = compute_pattern_quality(analytics);
    let coverage_gaps = compute_coverage_gaps(&all_findings, analytics);
    let consistency_issues = compute_consistency_issues(&all_findings, knowledge_items);
    let orphan_concepts = compute_orphan_concepts(analytics);
    let duplicate_clusters = compute_duplicate_clusters(&all_findings);
    let metrics = compute_metrics(&all_findings, analytics);
    let recommendations = compute_recommendations(
        &coverage_gaps,
        &consistency_issues,
        &orphan_concepts,
        &duplicate_clusters,
        &ontology_health,
    );

    let health_score = compute_health_score(
        &ontology_health,
        &extraction_quality,
        &normalization_quality,
        &graph_quality,
        &pattern_quality,
    );

    let report_id = compute_report_id(knowledge_items);

    KnowledgeQualityReport {
        report_id,
        health_score,
        ontology_health,
        extraction_quality,
        normalization_quality,
        graph_quality,
        pattern_quality,
        coverage_gaps,
        consistency_issues,
        orphan_concepts,
        duplicate_clusters,
        metrics,
        recommendations,
    }
}

fn compute_report_id(items: &[NormalizedKnowledge]) -> String {
    let mut h: u64 = 0;
    for item in items {
        for byte in item.knowledge_id.bytes() {
            h = h.wrapping_mul(31).wrapping_add(byte as u64);
        }
    }
    format!("{:x}", h)
}

// ── Ontology Health ──

fn compute_ontology_health(
    findings: &[&NormalizedFinding],
    analytics: &super::analytics::CorpusAnalyticsReport,
) -> OntologyHealth {
    let total = findings.len() as f64;
    if total == 0.0 {
        return OntologyHealth {
            class_coverage_pct: 0.0,
            technique_coverage_pct: 0.0,
            root_cause_coverage_pct: 0.0,
            invariant_coverage_pct: 0.0,
            unsupported_entries: vec![],
            health_score: 0.0,
        };
    }

    let class_pct = analytics.coverage.vulnerability_classes.coverage_pct;
    let tech_pct = analytics.coverage.attack_techniques.coverage_pct;
    let rc_pct = analytics.coverage.root_causes.coverage_pct;
    let inv_pct = 100.0; // invariant types are not per-finding

    // Find unsupported ontology entries
    let mut unsupported = Vec::new();
    for (class, count) in &analytics.coverage.class_distribution {
        if *count == 0 {
            unsupported.push(class.clone());
        }
    }

    let health_score = (class_pct * 0.4 + tech_pct * 0.3 + rc_pct * 0.2 + inv_pct * 0.1) / 100.0;

    OntologyHealth {
        class_coverage_pct: class_pct,
        technique_coverage_pct: tech_pct,
        root_cause_coverage_pct: rc_pct,
        invariant_coverage_pct: inv_pct,
        unsupported_entries: unsupported,
        health_score,
    }
}

// ── Extraction Quality ──

fn compute_extraction_quality(
    findings: &[&NormalizedFinding],
    knowledge_items: &[NormalizedKnowledge],
) -> ExtractionQuality {
    let total = findings.len();
    let empty_reports = knowledge_items
        .iter()
        .filter(|k| k.findings.is_empty())
        .count();

    let blank_desc = findings
        .iter()
        .filter(|f| f.description_text.is_empty())
        .count();
    let blank_rc = findings
        .iter()
        .filter(|f| {
            f.root_cause.to_string().starts_with("other(") || f.root_cause.to_string().is_empty()
        })
        .count();
    let blank_remediation = findings
        .iter()
        .filter(|f| f.remediation_text.is_empty())
        .count();
    let with_fns = findings
        .iter()
        .filter(|f| !f.impacted_functions.is_empty())
        .count();

    let total_f = total as f64;
    let desc_score = if total_f > 0.0 {
        1.0 - blank_desc as f64 / total_f
    } else {
        1.0
    };
    let rc_score = if total_f > 0.0 {
        1.0 - blank_rc as f64 / total_f
    } else {
        1.0
    };
    let fn_score = if total_f > 0.0 {
        with_fns as f64 / total_f
    } else {
        0.0
    };
    let quality_score = (desc_score * 0.4 + rc_score * 0.3 + fn_score * 0.3).min(1.0);

    ExtractionQuality {
        total_reports: knowledge_items.len(),
        empty_reports,
        blank_descriptions: blank_desc,
        blank_root_causes: blank_rc,
        blank_remediation,
        findings_with_functions: with_fns,
        findings_with_snippets: 0, // not tracked yet
        quality_score,
    }
}

// ── Normalization Quality ──

fn compute_normalization_quality(findings: &[&NormalizedFinding]) -> NormalizationQuality {
    let total = findings.len();
    let total_f = total as f64;

    let classified = findings
        .iter()
        .filter(|f| !f.vulnerability_class.to_string().starts_with("other("))
        .count();
    let classified_tech = findings
        .iter()
        .filter(|f| !f.attack_technique.to_string().starts_with("other("))
        .count();
    let classified_rc = findings
        .iter()
        .filter(|f| !f.root_cause.to_string().starts_with("other("))
        .count();
    let classified_goals = findings
        .iter()
        .filter(|f| !f.attack_goal.is_empty())
        .count();

    let class_score = if total_f > 0.0 {
        classified as f64 / total_f
    } else {
        0.0
    };
    let tech_score = if total_f > 0.0 {
        classified_tech as f64 / total_f
    } else {
        0.0
    };
    let rc_score = if total_f > 0.0 {
        classified_rc as f64 / total_f
    } else {
        0.0
    };
    let goal_score = if total_f > 0.0 {
        classified_goals as f64 / total_f
    } else {
        0.0
    };

    let quality_score =
        (class_score * 0.4 + tech_score * 0.25 + rc_score * 0.2 + goal_score * 0.15).min(1.0);

    NormalizationQuality {
        total_findings: total,
        classified_findings: classified,
        classified_techniques: classified_tech,
        classified_root_causes: classified_rc,
        classified_goals,
        quality_score,
    }
}

// ── Graph Quality ──

fn compute_graph_quality(analytics: &super::analytics::CorpusAnalyticsReport) -> GraphQuality {
    let total_nodes = analytics.graph_stats.total_nodes;
    let total_edges = analytics.graph_stats.total_edges;
    let avg_degree = analytics.graph_stats.avg_degree;
    let max_edges = if total_nodes > 1 {
        total_nodes * (total_nodes - 1) / 2
    } else {
        1
    };
    let density = total_edges as f64 / max_edges as f64;

    // Quality: higher density and degree = better connected graph
    let density_score = (density * 100.0).min(1.0);
    let degree_score = (avg_degree / 10.0).min(1.0);
    let quality_score = (density_score * 0.5 + degree_score * 0.5).min(1.0);

    GraphQuality {
        total_nodes,
        total_edges,
        isolated_nodes: analytics.graph_stats.isolated_nodes,
        connected_components: analytics.graph_stats.connected_components,
        avg_degree,
        density,
        quality_score,
    }
}

// ── Pattern Quality ──

fn compute_pattern_quality(analytics: &super::analytics::CorpusAnalyticsReport) -> PatternQuality {
    let total = analytics.pattern_stats.total_patterns;
    let well = analytics.pattern_stats.well_supported_patterns;
    let weak = analytics.pattern_stats.weakly_supported_patterns;
    let avg_findings = analytics.pattern_stats.avg_findings_per_pattern;
    let avg_protocols = analytics.pattern_stats.avg_protocols_per_pattern;

    let support_ratio = if total > 0 {
        well as f64 / total as f64
    } else {
        0.0
    };
    let quality_score = (support_ratio * 0.6 + (avg_protocols / 50.0).min(1.0) * 0.4).min(1.0);

    PatternQuality {
        total_patterns: total,
        well_supported: well,
        weakly_supported: weak,
        avg_findings,
        avg_protocols,
        quality_score,
    }
}

// ── Coverage Gaps ──

fn compute_coverage_gaps(
    _findings: &[&NormalizedFinding],
    analytics: &super::analytics::CorpusAnalyticsReport,
) -> Vec<CoverageGap> {
    let mut gaps = Vec::new();

    // Class gaps: unclassified clusters with 3+ findings
    for cluster in &analytics.gaps.unclassified_clusters {
        if cluster.count >= 3 {
            gaps.push(CoverageGap {
                kind: CoverageGapKind::MissingClass,
                description: format!(
                    "Missing class for '{}' ({} findings, {} protocols)",
                    cluster.pattern,
                    cluster.count,
                    cluster.protocols.len()
                ),
                affected_findings: cluster.count,
                affected_protocols: cluster.protocols.clone(),
                recommendation: format!(
                    "Consider adding '{}' to canonical vulnerability classes",
                    cluster.pattern
                ),
            });
        }
    }

    // Technique gaps
    for tech in &analytics.gaps.unknown_techniques {
        if tech.frequency >= 3 {
            gaps.push(CoverageGap {
                kind: CoverageGapKind::MissingTechnique,
                description: format!(
                    "Missing technique for '{}' ({} protocols)",
                    tech.description, tech.frequency
                ),
                affected_findings: tech.frequency,
                affected_protocols: tech.protocols.clone(),
                recommendation: format!(
                    "Consider adding '{}' to canonical attack techniques",
                    tech.description
                ),
            });
        }
    }

    // Root cause gaps
    for rc in &analytics.gaps.unknown_root_causes {
        if rc.frequency >= 3 {
            gaps.push(CoverageGap {
                kind: CoverageGapKind::MissingRootCause,
                description: format!(
                    "Missing root cause for '{}' ({} protocols)",
                    rc.description, rc.frequency
                ),
                affected_findings: rc.frequency,
                affected_protocols: rc.protocols.clone(),
                recommendation: format!(
                    "Consider adding '{}' to canonical root causes",
                    rc.description
                ),
            });
        }
    }

    gaps.sort_by_key(|b| std::cmp::Reverse(b.affected_findings));
    gaps
}

// ── Consistency Issues ──

fn compute_consistency_issues(
    findings: &[&NormalizedFinding],
    knowledge_items: &[NormalizedKnowledge],
) -> Vec<ConsistencyIssue> {
    let mut issues = Vec::new();

    // Check for duplicate findings (same title, same protocol)
    let mut title_protocol: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in findings {
        let key = format!("{}:{}", f.description_text, f.protocol_name);
        title_protocol
            .entry(key)
            .or_default()
            .push(f.finding_id.clone());
    }
    for (key, ids) in &title_protocol {
        if ids.len() > 1 {
            issues.push(ConsistencyIssue {
                kind: ConsistencyKind::DuplicateFinding,
                description: format!(
                    "Potential duplicate: '{}' has {} findings",
                    key.split(':').next().unwrap_or("?"),
                    ids.len()
                ),
                affected_findings: ids.clone(),
                recommendation: "Review and merge if duplicates confirmed".into(),
            });
        }
    }

    // Check for inconsistent categories (same protocol, different categories)
    let mut protocol_categories: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for item in knowledge_items {
        protocol_categories
            .entry(item.subject.clone())
            .or_default()
            .push(item.subject_category.clone());
    }
    for (protocol, categories) in &protocol_categories {
        let unique: std::collections::BTreeSet<&String> = categories.iter().collect();
        if unique.len() > 1 {
            issues.push(ConsistencyIssue {
                kind: ConsistencyKind::InconsistentCategory,
                description: format!(
                    "Protocol '{}' classified as multiple categories: {:?}",
                    protocol, categories
                ),
                affected_findings: vec![],
                recommendation: "Standardize protocol category classification".into(),
            });
        }
    }

    issues.sort_by_key(|a| a.kind.to_string());
    issues
}

// ── Orphan Concepts ──

fn compute_orphan_concepts(
    analytics: &super::analytics::CorpusAnalyticsReport,
) -> Vec<OrphanConcept> {
    let mut orphans = Vec::new();

    // Classes with zero findings
    for (class, count) in &analytics.coverage.class_distribution {
        if *count == 0 {
            orphans.push(OrphanConcept {
                name: class.clone(),
                kind: "vulnerability_class".into(),
                recommendation: "Consider deprecation if no future support expected".into(),
            });
        }
    }

    // Techniques with zero findings
    for (tech, count) in &analytics.coverage.technique_distribution {
        if *count == 0 {
            orphans.push(OrphanConcept {
                name: tech.clone(),
                kind: "attack_technique".into(),
                recommendation: "Consider deprecation if no future support expected".into(),
            });
        }
    }

    // Root causes with zero findings
    for (rc, count) in &analytics.coverage.root_cause_distribution {
        if *count == 0 {
            orphans.push(OrphanConcept {
                name: rc.clone(),
                kind: "root_cause".into(),
                recommendation: "Consider deprecation if no future support expected".into(),
            });
        }
    }

    orphans
}

// ── Duplicate Clusters ──

fn compute_duplicate_clusters(findings: &[&NormalizedFinding]) -> Vec<DuplicateCluster> {
    let mut clusters = Vec::new();
    let _equivalents = digger_knowledge_models::KnowledgeGraph {
        nodes: vec![],
        edges: vec![],
    }; // placeholder — use classifier directly

    // Group by same title + same protocol
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in findings {
        let key = format!("{}|{}", f.description_text, f.protocol_name);
        groups.entry(key).or_default().push(f.finding_id.clone());
    }

    let mut cluster_id = 0;
    for (key, ids) in &groups {
        if ids.len() > 1 {
            clusters.push(DuplicateCluster {
                cluster_id: format!("dup:{}", cluster_id),
                finding_ids: ids.clone(),
                similarity: format!(
                    "Same title and protocol: {}",
                    key.split('|').next().unwrap_or("?")
                ),
                recommendation: "Review for potential merge".into(),
            });
            cluster_id += 1;
        }
    }

    clusters
}

// ── Quality Metrics ──

fn compute_metrics(
    findings: &[&NormalizedFinding],
    analytics: &super::analytics::CorpusAnalyticsReport,
) -> Vec<QualityMetric> {
    let total = findings.len() as f64;
    vec![
        QualityMetric {
            name: "total_findings".into(),
            value: total,
            unit: "findings".into(),
            description: "Total findings in corpus".into(),
        },
        QualityMetric {
            name: "class_coverage".into(),
            value: analytics.coverage.vulnerability_classes.coverage_pct,
            unit: "percent".into(),
            description: "Vulnerability class coverage percentage".into(),
        },
        QualityMetric {
            name: "technique_coverage".into(),
            value: analytics.coverage.attack_techniques.coverage_pct,
            unit: "percent".into(),
            description: "Attack technique coverage percentage".into(),
        },
        QualityMetric {
            name: "root_cause_coverage".into(),
            value: analytics.coverage.root_causes.coverage_pct,
            unit: "percent".into(),
            description: "Root cause coverage percentage".into(),
        },
        QualityMetric {
            name: "graph_density".into(),
            value: analytics.graph_stats.avg_degree,
            unit: "edges/node".into(),
            description: "Average graph degree".into(),
        },
        QualityMetric {
            name: "pattern_count".into(),
            value: analytics.pattern_stats.total_patterns as f64,
            unit: "patterns".into(),
            description: "Total reasoning patterns".into(),
        },
        QualityMetric {
            name: "equivalence_pairs".into(),
            value: analytics.equivalence_stats.total_pairs as f64,
            unit: "pairs".into(),
            description: "Semantic equivalence pairs".into(),
        },
    ]
}

// ── Recommendations ──

fn compute_recommendations(
    gaps: &[CoverageGap],
    issues: &[ConsistencyIssue],
    orphans: &[OrphanConcept],
    duplicates: &[DuplicateCluster],
    _health: &OntologyHealth,
) -> Vec<QualityRecommendation> {
    let mut recs = Vec::new();

    // High-priority: large coverage gaps
    for gap in gaps.iter().filter(|g| g.affected_findings >= 10) {
        recs.push(QualityRecommendation {
            recommendation_id: String::new(),
            kind: "coverage_gap".into(),
            description: format!(
                "Address {} gap: {} ({} findings)",
                gap.kind, gap.description, gap.affected_findings
            ),
            priority: "high".into(),
            affected: vec![gap.kind.to_string()],
            evidence: vec![format!(
                "{} findings across {} protocols",
                gap.affected_findings,
                gap.affected_protocols.len()
            )],
        });
    }

    // Medium-priority: consistency issues
    for issue in issues.iter().take(10) {
        recs.push(QualityRecommendation {
            recommendation_id: String::new(),
            kind: "consistency".into(),
            description: issue.description.clone(),
            priority: "medium".into(),
            affected: vec![issue.kind.to_string()],
            evidence: issue.affected_findings.clone(),
        });
    }

    // Low-priority: orphan concepts
    if !orphans.is_empty() {
        recs.push(QualityRecommendation {
            recommendation_id: String::new(),
            kind: "orphan_concepts".into(),
            description: format!(
                "{} orphan ontology entries with zero corpus support",
                orphans.len()
            ),
            priority: "low".into(),
            affected: orphans.iter().map(|o| o.name.clone()).collect(),
            evidence: vec![],
        });
    }

    // Low-priority: duplicate clusters
    if !duplicates.is_empty() {
        recs.push(QualityRecommendation {
            recommendation_id: String::new(),
            kind: "duplicates".into(),
            description: format!("{} potential duplicate clusters detected", duplicates.len()),
            priority: "low".into(),
            affected: vec![],
            evidence: vec![],
        });
    }

    // Assign IDs
    for (i, rec) in recs.iter_mut().enumerate() {
        rec.recommendation_id = format!("qr:{:04}", i);
    }

    recs
}

// ── Health Score ──

fn compute_health_score(
    ontology: &OntologyHealth,
    extraction: &ExtractionQuality,
    normalization: &NormalizationQuality,
    graph: &GraphQuality,
    pattern: &PatternQuality,
) -> f64 {
    (ontology.health_score * 0.3
        + extraction.quality_score * 0.2
        + normalization.quality_score * 0.25
        + graph.quality_score * 0.1
        + pattern.quality_score * 0.15)
        .min(1.0)
}

/// Serialize report to JSON.
pub fn report_to_json(report: &KnowledgeQualityReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}
