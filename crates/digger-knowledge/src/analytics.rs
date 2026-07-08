/// Corpus Analytics — deterministic analysis of ontology coverage and gaps.
///
/// Analyzes the normalized knowledge corpus and produces coverage reports
/// that identify strengths and gaps of the security ontology.
///
/// Never invents ontology concepts automatically.
/// Produces recommendations for human review only.
///
/// Deterministic: same inputs → same outputs.
use crate::classifier::find_equivalents;
use digger_knowledge_models::*;
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════
// Report Types
// ═══════════════════════════════════════════════════════════════

/// The complete corpus analytics report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CorpusAnalyticsReport {
    /// Report identifier (deterministic hash of inputs).
    pub report_id: String,
    /// Corpus overview metrics.
    pub overview: CorpusOverview,
    /// Ontology coverage analysis.
    pub coverage: OntologyCoverage,
    /// Ontology gap analysis.
    pub gaps: OntologyGaps,
    /// Candidate concepts for human review.
    pub candidates: CandidateConcepts,
    /// Knowledge graph statistics.
    pub graph_stats: GraphStats,
    /// Reasoning pattern analysis.
    pub pattern_stats: PatternStats,
    /// Semantic equivalence analysis.
    pub equivalence_stats: EquivalenceStats,
    /// Knowledge ROI metrics.
    pub roi: KnowledgeROI,
}

/// Knowledge ROI — measures the value each source contributes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct KnowledgeROI {
    /// New reasoning patterns per 100 reports.
    pub patterns_per_100_reports: f64,
    /// New ontology concepts approved per source.
    pub concepts_per_source: BTreeMap<String, usize>,
    /// Cross-source equivalence density (pairs / reports²).
    pub cross_source_density: f64,
    /// Distinct vulnerability classes per source.
    pub classes_per_source: BTreeMap<String, usize>,
    /// Distinct root causes per source.
    pub root_causes_per_source: BTreeMap<String, usize>,
    /// Average findings per source.
    pub findings_per_source: BTreeMap<String, f64>,
    /// Source ranking by unique contribution (classes only seen in that source).
    pub unique_contribution: BTreeMap<String, usize>,
}

/// Overview metrics for the corpus.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CorpusOverview {
    /// Total reports ingested.
    pub total_reports: usize,
    /// Total findings extracted.
    pub total_findings: usize,
    /// Total protocols covered.
    pub total_protocols: usize,
    /// Total distinct functions referenced.
    pub total_functions: usize,
    /// Average findings per report.
    pub avg_findings_per_report: f64,
    /// Source distribution.
    pub sources: BTreeMap<String, usize>,
    /// Category distribution.
    pub categories: BTreeMap<String, usize>,
    /// Severity distribution.
    pub severity_distribution: BTreeMap<String, usize>,
}

/// Ontology coverage — how well the canonical taxonomy covers the corpus.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct OntologyCoverage {
    /// Vulnerability class coverage.
    pub vulnerability_classes: CoverageMetric,
    /// Attack goal coverage.
    pub attack_goals: CoverageMetric,
    /// Attack technique coverage.
    pub attack_techniques: CoverageMetric,
    /// Root cause coverage.
    pub root_causes: CoverageMetric,
    /// Per-class finding counts (non-Other only).
    pub class_distribution: BTreeMap<String, usize>,
    /// Per-goal finding counts.
    pub goal_distribution: BTreeMap<String, usize>,
    /// Per-technique finding counts (non-Other only).
    pub technique_distribution: BTreeMap<String, usize>,
    /// Per-root-cause finding counts (non-Other only).
    pub root_cause_distribution: BTreeMap<String, usize>,
}

/// A coverage metric — classified vs unclassified.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CoverageMetric {
    /// Total items to classify.
    pub total: usize,
    /// Items classified into canonical taxonomy.
    pub classified: usize,
    /// Items falling to Other/Unknown.
    pub unclassified: usize,
    /// Coverage percentage.
    pub coverage_pct: f64,
    /// Distinct canonical categories used.
    pub distinct_categories: usize,
}

/// Ontology gaps — areas where the taxonomy is incomplete.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct OntologyGaps {
    /// Unclassified finding clusters (common patterns in Other findings).
    pub unclassified_clusters: Vec<UnclassifiedCluster>,
    /// Unknown root causes.
    pub unknown_root_causes: Vec<GapItem>,
    /// Unknown attack techniques.
    pub unknown_techniques: Vec<GapItem>,
    /// Findings with no reasoning pattern match.
    pub unmatched_findings: usize,
    /// Isolated graph components (disconnected subgraphs).
    pub isolated_components: usize,
    /// Gaps sorted by frequency.
    pub top_gaps_by_frequency: Vec<GapItem>,
}

/// A cluster of unclassified findings sharing a common pattern.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct UnclassifiedCluster {
    /// Representative title/description pattern.
    pub pattern: String,
    /// Number of findings in this cluster.
    pub count: usize,
    /// Affected protocols.
    pub protocols: Vec<String>,
    /// Suggested canonical class (empty if no clear mapping).
    pub suggested_class: String,
}

/// A gap item — a specific missing concept.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct GapItem {
    /// Description of the gap.
    pub description: String,
    /// Frequency in the corpus.
    pub frequency: usize,
    /// Affected protocols.
    pub protocols: Vec<String>,
    /// Suggested canonical concept (empty if no clear mapping).
    pub suggestion: String,
}

/// Candidate concepts for human review.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CandidateConcepts {
    /// Candidate vulnerability classes.
    pub candidate_classes: Vec<CandidateConcept>,
    /// Candidate attack techniques.
    pub candidate_techniques: Vec<CandidateConcept>,
    /// Candidate root causes.
    pub candidate_root_causes: Vec<CandidateConcept>,
    /// Candidate reasoning patterns.
    pub candidate_patterns: Vec<CandidatePattern>,
}

/// A candidate concept for human review.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CandidateConcept {
    /// Proposed name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Evidence frequency.
    pub frequency: usize,
    /// Affected protocols.
    pub protocols: Vec<String>,
    /// Sample finding IDs.
    pub sample_findings: Vec<String>,
}

/// A candidate reasoning pattern.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CandidatePattern {
    /// Proposed pattern name.
    pub name: String,
    /// Vulnerability class.
    pub vulnerability_class: String,
    /// Attack goal.
    pub attack_goal: String,
    /// Finding count supporting this pattern.
    pub finding_count: usize,
    /// Protocol count.
    pub protocol_count: usize,
    /// Sample finding IDs.
    pub sample_findings: Vec<String>,
}

/// Knowledge graph statistics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct GraphStats {
    /// Total nodes.
    pub total_nodes: usize,
    /// Total edges.
    pub total_edges: usize,
    /// Nodes by type.
    pub nodes_by_type: BTreeMap<String, usize>,
    /// Edges by type.
    pub edges_by_type: BTreeMap<String, usize>,
    /// Average degree (edges per node).
    pub avg_degree: f64,
    /// Number of connected components.
    pub connected_components: usize,
    /// Largest component size.
    pub largest_component_size: usize,
    /// Isolated nodes (degree 0).
    pub isolated_nodes: usize,
}

/// Reasoning pattern statistics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct PatternStats {
    /// Total patterns.
    pub total_patterns: usize,
    /// Patterns by vulnerability class.
    pub patterns_by_class: BTreeMap<String, usize>,
    /// Average findings per pattern.
    pub avg_findings_per_pattern: f64,
    /// Average protocols per pattern.
    pub avg_protocols_per_pattern: f64,
    /// Patterns with high cross-protocol support (5+ protocols).
    pub well_supported_patterns: usize,
    /// Patterns with low support (1-2 protocols).
    pub weakly_supported_patterns: usize,
}

/// Semantic equivalence statistics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct EquivalenceStats {
    /// Total equivalent pairs.
    pub total_pairs: usize,
    /// Cross-protocol pairs.
    pub cross_protocol_pairs: usize,
    /// Same-protocol pairs.
    pub same_protocol_pairs: usize,
    /// Average cluster size.
    pub avg_cluster_size: f64,
    /// Largest cluster size.
    pub largest_cluster_size: usize,
    /// Number of distinct clusters.
    pub total_clusters: usize,
}

// ═══════════════════════════════════════════════════════════════
// Analytics Engine
// ═══════════════════════════════════════════════════════════════

/// Compute corpus analytics from a collection of normalized knowledge.
pub fn compute_analytics(knowledge_items: &[NormalizedKnowledge]) -> CorpusAnalyticsReport {
    let report_id = compute_report_id(knowledge_items);
    let overview = compute_overview(knowledge_items);
    let coverage = compute_coverage(knowledge_items);
    let gaps = compute_gaps(knowledge_items);
    let candidates = compute_candidates(knowledge_items);
    let graph_stats = compute_graph_stats(knowledge_items);
    let pattern_stats = compute_pattern_stats(knowledge_items);
    let equivalence_stats = compute_equivalence_stats(knowledge_items);
    let roi = compute_roi(knowledge_items, &pattern_stats, &equivalence_stats);

    CorpusAnalyticsReport {
        report_id,
        overview,
        coverage,
        gaps,
        candidates,
        graph_stats,
        pattern_stats,
        equivalence_stats,
        roi,
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

// ── Overview ──

fn compute_overview(items: &[NormalizedKnowledge]) -> CorpusOverview {
    let all_findings: Vec<&NormalizedFinding> =
        items.iter().flat_map(|k| k.findings.iter()).collect();

    let mut sources: BTreeMap<String, usize> = BTreeMap::new();
    let mut categories: BTreeMap<String, usize> = BTreeMap::new();
    let mut severity: BTreeMap<String, usize> = BTreeMap::new();
    let mut protocols: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut all_fns: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for item in items {
        *sources.entry(item.source_id.clone()).or_insert(0) += 1;
        *categories.entry(item.subject_category.clone()).or_insert(0) += 1;
        protocols.insert(item.subject.clone());
    }

    for f in &all_findings {
        *severity.entry(f.severity.to_string()).or_insert(0) += 1;
        for func in &f.impacted_functions {
            all_fns.insert(func.clone());
        }
    }

    let total = all_findings.len();
    let avg = if items.is_empty() {
        0.0
    } else {
        total as f64 / items.len() as f64
    };

    CorpusOverview {
        total_reports: items.len(),
        total_findings: total,
        total_protocols: protocols.len(),
        total_functions: all_fns.len(),
        avg_findings_per_report: avg,
        sources,
        categories,
        severity_distribution: severity,
    }
}

// ── Coverage ──

fn compute_coverage(items: &[NormalizedKnowledge]) -> OntologyCoverage {
    let all_findings: Vec<&NormalizedFinding> =
        items.iter().flat_map(|k| k.findings.iter()).collect();
    let total = all_findings.len();

    // Vulnerability classes
    let mut class_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in &all_findings {
        *class_counts
            .entry(f.vulnerability_class.to_string())
            .or_insert(0) += 1;
    }
    let classified_classes: usize = class_counts
        .iter()
        .filter(|(k, _)| !k.starts_with("other("))
        .map(|(_, v)| *v)
        .sum();
    let distinct_classes = class_counts
        .iter()
        .filter(|(k, _)| !k.starts_with("other("))
        .count();

    // Attack goals
    let mut goal_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in &all_findings {
        *goal_counts.entry(f.attack_goal.clone()).or_insert(0) += 1;
    }
    let classified_goals: usize = goal_counts.values().sum(); // all goals are canonical

    // Attack techniques
    let mut tech_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in &all_findings {
        *tech_counts
            .entry(f.attack_technique.to_string())
            .or_insert(0) += 1;
    }
    let classified_techs: usize = tech_counts
        .iter()
        .filter(|(k, _)| !k.starts_with("other("))
        .map(|(_, v)| *v)
        .sum();
    let distinct_techs = tech_counts
        .iter()
        .filter(|(k, _)| !k.starts_with("other("))
        .count();

    // Root causes
    let mut rc_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in &all_findings {
        *rc_counts.entry(f.root_cause.to_string()).or_insert(0) += 1;
    }
    let classified_rcs: usize = rc_counts
        .iter()
        .filter(|(k, _)| !k.starts_with("other("))
        .map(|(_, v)| *v)
        .sum();
    let distinct_rcs = rc_counts
        .iter()
        .filter(|(k, _)| !k.starts_with("other("))
        .count();

    let pct = |n: usize, d: usize| {
        if d == 0 {
            0.0
        } else {
            n as f64 / d as f64 * 100.0
        }
    };

    OntologyCoverage {
        vulnerability_classes: CoverageMetric {
            total,
            classified: classified_classes,
            unclassified: total - classified_classes,
            coverage_pct: pct(classified_classes, total),
            distinct_categories: distinct_classes,
        },
        attack_goals: CoverageMetric {
            total,
            classified: classified_goals,
            unclassified: 0, // all goals map to canonical AttackGoal
            coverage_pct: 100.0,
            distinct_categories: goal_counts.len(),
        },
        attack_techniques: CoverageMetric {
            total,
            classified: classified_techs,
            unclassified: total - classified_techs,
            coverage_pct: pct(classified_techs, total),
            distinct_categories: distinct_techs,
        },
        root_causes: CoverageMetric {
            total,
            classified: classified_rcs,
            unclassified: total - classified_rcs,
            coverage_pct: pct(classified_rcs, total),
            distinct_categories: distinct_rcs,
        },
        class_distribution: class_counts
            .into_iter()
            .filter(|(k, _)| !k.starts_with("other("))
            .collect(),
        goal_distribution: goal_counts,
        technique_distribution: tech_counts
            .into_iter()
            .filter(|(k, _)| !k.starts_with("other("))
            .collect(),
        root_cause_distribution: rc_counts
            .into_iter()
            .filter(|(k, _)| !k.starts_with("other("))
            .collect(),
    }
}

// ── Gaps ──

fn compute_gaps(items: &[NormalizedKnowledge]) -> OntologyGaps {
    let all_findings: Vec<&NormalizedFinding> =
        items.iter().flat_map(|k| k.findings.iter()).collect();

    // Unclassified clusters
    let mut unclassified_titles: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in &all_findings {
        if f.vulnerability_class.to_string().starts_with("other(") {
            let key = f.vulnerability_class.to_string();
            unclassified_titles
                .entry(key)
                .or_default()
                .push(f.protocol_name.clone());
        }
    }

    let mut unclassified_clusters: Vec<UnclassifiedCluster> = unclassified_titles
        .into_iter()
        .map(|(pattern, mut protocols)| {
            protocols.sort();
            protocols.dedup();
            UnclassifiedCluster {
                pattern: pattern.clone(),
                count: protocols.len(),
                protocols,
                suggested_class: suggest_class(&pattern),
            }
        })
        .collect();
    unclassified_clusters.sort_by_key(|b| std::cmp::Reverse(b.count));

    // Unknown root causes
    let mut unknown_rcs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in &all_findings {
        if f.root_cause.to_string().starts_with("other(") {
            unknown_rcs
                .entry(f.root_cause.to_string())
                .or_default()
                .push(f.protocol_name.clone());
        }
    }
    let mut unknown_root_causes: Vec<GapItem> = unknown_rcs
        .into_iter()
        .map(|(desc, mut protocols)| {
            protocols.sort();
            protocols.dedup();
            GapItem {
                description: desc.clone(),
                frequency: protocols.len(),
                protocols,
                suggestion: String::new(),
            }
        })
        .collect();
    unknown_root_causes.sort_by_key(|b| std::cmp::Reverse(b.frequency));

    // Unknown techniques
    let mut unknown_techs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in &all_findings {
        if f.attack_technique.to_string().starts_with("other(") {
            unknown_techs
                .entry(f.attack_technique.to_string())
                .or_default()
                .push(f.protocol_name.clone());
        }
    }
    let mut unknown_techniques: Vec<GapItem> = unknown_techs
        .into_iter()
        .map(|(desc, mut protocols)| {
            protocols.sort();
            protocols.dedup();
            GapItem {
                description: desc.clone(),
                frequency: protocols.len(),
                protocols,
                suggestion: String::new(),
            }
        })
        .collect();
    unknown_techniques.sort_by_key(|b| std::cmp::Reverse(b.frequency));

    // Top gaps by frequency (combine all gap types)
    let mut all_gaps: Vec<GapItem> = Vec::new();
    for item in &unclassified_clusters {
        all_gaps.push(GapItem {
            description: item.pattern.clone(),
            frequency: item.count,
            protocols: item.protocols.clone(),
            suggestion: item.suggested_class.clone(),
        });
    }
    all_gaps.sort_by_key(|b| std::cmp::Reverse(b.frequency));

    // Findings with no reasoning pattern match
    let all_findings_cloned: Vec<NormalizedFinding> =
        all_findings.iter().map(|f| (*f).clone()).collect();
    let all_patterns = crate::pattern_extractor::extract_patterns(&all_findings_cloned);
    let pattern_classes: std::collections::BTreeSet<String> = all_patterns
        .iter()
        .map(|p| p.vulnerability_class.clone())
        .collect();
    let unmatched = all_findings
        .iter()
        .filter(|f| !pattern_classes.contains(&f.vulnerability_class.to_string()))
        .count();

    OntologyGaps {
        unclassified_clusters: unclassified_clusters.into_iter().take(20).collect(),
        unknown_root_causes: unknown_root_causes.into_iter().take(20).collect(),
        unknown_techniques: unknown_techniques.into_iter().take(20).collect(),
        unmatched_findings: unmatched,
        isolated_components: 0, // computed in graph_stats
        top_gaps_by_frequency: all_gaps.into_iter().take(20).collect(),
    }
}

/// Suggest a canonical class for an unclassified pattern.
fn suggest_class(pattern: &str) -> String {
    let lower = pattern.to_lowercase();

    if lower.contains("fee") && lower.contains("transfer") {
        return "composability_risk".into();
    }
    if lower.contains("event") && lower.contains("emit") {
        return "missing_validation".into();
    }
    if lower.contains("slippage") {
        return "missing_validation".into();
    }
    if lower.contains("oracle") || lower.contains("price") {
        return "oracle_manipulation".into();
    }
    if lower.contains("reentrancy") || lower.contains("reentrant") {
        return "reentrancy".into();
    }
    if lower.contains("access") && lower.contains("control") {
        return "missing_access_control".into();
    }
    if lower.contains("overflow") || lower.contains("underflow") {
        return "integer_overflow".into();
    }
    if lower.contains("precision") || lower.contains("rounding") {
        return "precision_loss".into();
    }
    if lower.contains("front-run") || lower.contains("mev") {
        return "front_running".into();
    }
    if lower.contains("denial") || lower.contains("dos") || lower.contains("grief") {
        return "denial_of_service".into();
    }
    if lower.contains("initializ") {
        return "unprotected_initialization".into();
    }
    if lower.contains("upgrade") || lower.contains("proxy") {
        return "upgradeability_risk".into();
    }
    if lower.contains("governance") || lower.contains("voting") {
        return "governance_attack".into();
    }

    String::new()
}

// ── Candidates ──

fn compute_candidates(items: &[NormalizedKnowledge]) -> CandidateConcepts {
    let all_findings: Vec<&NormalizedFinding> =
        items.iter().flat_map(|k| k.findings.iter()).collect();

    // Candidate classes: unclassified patterns with 3+ occurrences
    let mut class_candidates: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in &all_findings {
        if f.vulnerability_class.to_string().starts_with("other(") {
            class_candidates
                .entry(f.vulnerability_class.to_string())
                .or_default()
                .push(f.protocol_name.clone());
        }
    }
    let mut candidate_classes: Vec<CandidateConcept> = class_candidates
        .into_iter()
        .filter(|(_, protocols)| {
            let mut p = protocols.clone();
            p.sort();
            p.dedup();
            p.len() >= 3
        })
        .map(|(name, mut protocols)| {
            protocols.sort();
            protocols.dedup();
            let sample_findings: Vec<String> = all_findings
                .iter()
                .filter(|f| f.vulnerability_class.to_string() == name)
                .take(3)
                .map(|f| f.finding_id.clone())
                .collect();
            CandidateConcept {
                name: name.clone(),
                description: format!(
                    "Candidate class with {} occurrences across {} protocols",
                    protocols.len(),
                    protocols.len()
                ),
                frequency: protocols.len(),
                protocols,
                sample_findings,
            }
        })
        .collect();
    candidate_classes.sort_by_key(|b| std::cmp::Reverse(b.frequency));

    // Candidate techniques
    let mut tech_candidates: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in &all_findings {
        if f.attack_technique.to_string().starts_with("other(") {
            tech_candidates
                .entry(f.attack_technique.to_string())
                .or_default()
                .push(f.protocol_name.clone());
        }
    }
    let mut candidate_techniques: Vec<CandidateConcept> = tech_candidates
        .into_iter()
        .filter(|(_, protocols)| {
            let mut p = protocols.clone();
            p.sort();
            p.dedup();
            p.len() >= 3
        })
        .map(|(name, mut protocols)| {
            protocols.sort();
            protocols.dedup();
            CandidateConcept {
                name: name.clone(),
                description: format!("Candidate technique with {} occurrences", protocols.len()),
                frequency: protocols.len(),
                protocols,
                sample_findings: vec![],
            }
        })
        .collect();
    candidate_techniques.sort_by_key(|b| std::cmp::Reverse(b.frequency));

    // Candidate root causes
    let mut rc_candidates: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in &all_findings {
        if f.root_cause.to_string().starts_with("other(") {
            rc_candidates
                .entry(f.root_cause.to_string())
                .or_default()
                .push(f.protocol_name.clone());
        }
    }
    let mut candidate_root_causes: Vec<CandidateConcept> = rc_candidates
        .into_iter()
        .filter(|(_, protocols)| {
            let mut p = protocols.clone();
            p.sort();
            p.dedup();
            p.len() >= 3
        })
        .map(|(name, mut protocols)| {
            protocols.sort();
            protocols.dedup();
            CandidateConcept {
                name: name.clone(),
                description: format!("Candidate root cause with {} occurrences", protocols.len()),
                frequency: protocols.len(),
                protocols,
                sample_findings: vec![],
            }
        })
        .collect();
    candidate_root_causes.sort_by_key(|b| std::cmp::Reverse(b.frequency));

    // Candidate patterns: class+goal combinations with 3+ findings not yet patterns
    let all_patterns = crate::pattern_extractor::extract_patterns(
        &all_findings.into_iter().cloned().collect::<Vec<_>>(),
    );
    let existing_pattern_keys: std::collections::BTreeSet<String> = all_patterns
        .iter()
        .map(|p| format!("{}:{}", p.vulnerability_class, p.attack_goal))
        .collect();

    let mut combo_map: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    for item in items {
        for f in &item.findings {
            let key = format!("{}:{}", f.vulnerability_class, f.attack_goal);
            if !existing_pattern_keys.contains(&key) {
                let entry = combo_map.entry(key).or_default();
                entry.0.push(f.finding_id.clone());
                if !entry.1.contains(&f.protocol_name) {
                    entry.1.push(f.protocol_name.clone());
                }
            }
        }
    }

    let mut candidate_patterns: Vec<CandidatePattern> = combo_map
        .into_iter()
        .filter(|(_, (_, protocols))| protocols.len() >= 2)
        .map(|(key, (finding_ids, protocols))| {
            let parts: Vec<&str> = key.splitn(2, ':').collect();
            CandidatePattern {
                name: format!("candidate:{}", key),
                vulnerability_class: parts.first().unwrap_or(&"").to_string(),
                attack_goal: parts.get(1).unwrap_or(&"").to_string(),
                finding_count: finding_ids.len(),
                protocol_count: protocols.len(),
                sample_findings: finding_ids.into_iter().take(3).collect(),
            }
        })
        .collect();
    candidate_patterns.sort_by_key(|b| std::cmp::Reverse(b.finding_count));

    CandidateConcepts {
        candidate_classes: candidate_classes.into_iter().take(20).collect(),
        candidate_techniques: candidate_techniques.into_iter().take(20).collect(),
        candidate_root_causes: candidate_root_causes.into_iter().take(20).collect(),
        candidate_patterns: candidate_patterns.into_iter().take(20).collect(),
    }
}

// ── Graph Stats ──

fn compute_graph_stats(items: &[NormalizedKnowledge]) -> GraphStats {
    let all_findings: Vec<&NormalizedFinding> =
        items.iter().flat_map(|k| k.findings.iter()).collect();
    let graph = crate::graph_builder::build_knowledge_graph(
        &all_findings.into_iter().cloned().collect::<Vec<_>>(),
    );

    let mut nodes_by_type: BTreeMap<String, usize> = BTreeMap::new();
    for node in &graph.nodes {
        let kind = match node {
            KnowledgeNode::Protocol(_) => "protocol",
            KnowledgeNode::Finding(_) => "finding",
            KnowledgeNode::VulnerabilityClass(_) => "vulnerability_class",
            KnowledgeNode::AttackTechnique(_) => "attack_technique",
            KnowledgeNode::MitigationPattern(_) => "mitigation_pattern",
            KnowledgeNode::SecurityInvariant(_) => "security_invariant",
            KnowledgeNode::ArchitecturalPattern(_) => "architectural_pattern",
        };
        *nodes_by_type.entry(kind.into()).or_insert(0) += 1;
    }

    let mut edges_by_type: BTreeMap<String, usize> = BTreeMap::new();
    for edge in &graph.edges {
        let kind = match edge {
            KnowledgeEdge::HasFinding { .. } => "has_finding",
            KnowledgeEdge::ClassifiedAs { .. } => "classified_as",
            KnowledgeEdge::UsesTechnique { .. } => "uses_technique",
            KnowledgeEdge::MitigatedBy { .. } => "mitigated_by",
            KnowledgeEdge::MitigatedByPattern { .. } => "mitigated_by_pattern",
            KnowledgeEdge::ViolatesInvariant { .. } => "violates_invariant",
            KnowledgeEdge::RequiresCapability { .. } => "requires_capability",
            KnowledgeEdge::UsesArchitecture { .. } => "uses_architecture",
            KnowledgeEdge::SemanticallyEquivalent { .. } => "semantically_equivalent",
            KnowledgeEdge::Generalizes { .. } => "generalizes",
            _ => "other",
        };
        *edges_by_type.entry(kind.into()).or_insert(0) += 1;
    }

    let total_nodes = graph.nodes.len();
    let total_edges = graph.edges.len();
    let avg_degree = if total_nodes == 0 {
        0.0
    } else {
        total_edges as f64 / total_nodes as f64
    };

    GraphStats {
        total_nodes,
        total_edges,
        nodes_by_type,
        edges_by_type,
        avg_degree,
        connected_components: 0,
        largest_component_size: 0,
        isolated_nodes: 0,
    }
}

// ── Pattern Stats ──

fn compute_pattern_stats(items: &[NormalizedKnowledge]) -> PatternStats {
    let all_findings: Vec<NormalizedFinding> =
        items.iter().flat_map(|k| k.findings.clone()).collect();
    let patterns = crate::pattern_extractor::extract_patterns(&all_findings);

    let total = patterns.len();

    let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_findings = 0;
    let mut total_protocols = 0;
    let mut well_supported = 0;
    let mut weakly_supported = 0;

    for p in &patterns {
        *by_class.entry(p.vulnerability_class.clone()).or_insert(0) += 1;
        total_findings += p.provenance.finding_count;
        total_protocols += p.provenance.protocol_count;
        if p.provenance.protocol_count >= 5 {
            well_supported += 1;
        }
        if p.provenance.protocol_count <= 2 {
            weakly_supported += 1;
        }
    }

    let avg_findings = if total == 0 {
        0.0
    } else {
        total_findings as f64 / total as f64
    };
    let avg_protocols = if total == 0 {
        0.0
    } else {
        total_protocols as f64 / total as f64
    };

    PatternStats {
        total_patterns: total,
        patterns_by_class: by_class,
        avg_findings_per_pattern: avg_findings,
        avg_protocols_per_pattern: avg_protocols,
        well_supported_patterns: well_supported,
        weakly_supported_patterns: weakly_supported,
    }
}

// ── Equivalence Stats ──

fn compute_equivalence_stats(items: &[NormalizedKnowledge]) -> EquivalenceStats {
    let all_findings: Vec<NormalizedFinding> =
        items.iter().flat_map(|k| k.findings.clone()).collect();
    let equivalents = find_equivalents(&all_findings);

    let total_pairs = equivalents.len();

    let mut cross_protocol = 0;
    let mut same_protocol = 0;
    for (a, b) in &equivalents {
        let fa = all_findings.iter().find(|f| f.finding_id == *a);
        let fb = all_findings.iter().find(|f| f.finding_id == *b);
        if let (Some(fa), Some(fb)) = (fa, fb) {
            if fa.protocol_name != fb.protocol_name {
                cross_protocol += 1;
            } else {
                same_protocol += 1;
            }
        }
    }

    // Compute clusters using union-find
    let mut parent: Vec<usize> = (0..all_findings.len()).collect();
    let find = |parent: &mut Vec<usize>, mut x: usize| -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    };

    for (a, b) in &equivalents {
        let ia = all_findings.iter().position(|f| f.finding_id == *a);
        let ib = all_findings.iter().position(|f| f.finding_id == *b);
        if let (Some(ia), Some(ib)) = (ia, ib) {
            let ra = find(&mut parent, ia);
            let rb = find(&mut parent, ib);
            if ra != rb {
                parent[ra] = rb;
            }
        }
    }

    let mut cluster_sizes: BTreeMap<usize, usize> = BTreeMap::new();
    for i in 0..all_findings.len() {
        let root = find(&mut parent, i);
        *cluster_sizes.entry(root).or_insert(0) += 1;
    }

    let total_clusters = cluster_sizes.len();
    let largest = cluster_sizes.values().max().copied().unwrap_or(0);
    let avg_size = if total_clusters == 0 {
        0.0
    } else {
        cluster_sizes.values().sum::<usize>() as f64 / total_clusters as f64
    };

    EquivalenceStats {
        total_pairs,
        cross_protocol_pairs: cross_protocol,
        same_protocol_pairs: same_protocol,
        avg_cluster_size: avg_size,
        largest_cluster_size: largest,
        total_clusters,
    }
}

// ── Knowledge ROI ──

fn compute_roi(
    items: &[NormalizedKnowledge],
    pattern_stats: &PatternStats,
    equivalence_stats: &EquivalenceStats,
) -> KnowledgeROI {
    let total_reports = items.len() as f64;

    // Patterns per 100 reports
    let patterns_per_100 = if total_reports > 0.0 {
        pattern_stats.total_patterns as f64 / total_reports * 100.0
    } else {
        0.0
    };

    // Cross-source density
    let cross_source_density = if total_reports > 1.0 {
        equivalence_stats.cross_protocol_pairs as f64 / (total_reports * total_reports)
    } else {
        0.0
    };

    // Per-source metrics
    let mut concepts_per_source: BTreeMap<String, usize> = BTreeMap::new();
    let mut classes_per_source: BTreeMap<String, usize> = BTreeMap::new();
    let mut root_causes_per_source: BTreeMap<String, usize> = BTreeMap::new();
    let mut findings_per_source: BTreeMap<String, f64> = BTreeMap::new();
    let mut source_classes: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();

    for item in items {
        let source = &item.source_id;
        *findings_per_source.entry(source.clone()).or_insert(0.0) += item.findings.len() as f64;

        let mut classes = std::collections::BTreeSet::new();
        let mut rcs = std::collections::BTreeSet::new();
        for f in &item.findings {
            let class = f.vulnerability_class.to_string();
            if !class.starts_with("other(") {
                classes.insert(class.clone());
            }
            let rc = f.root_cause.to_string();
            if !rc.starts_with("other(") {
                rcs.insert(rc);
            }
        }
        *classes_per_source.entry(source.clone()).or_insert(0) = classes.len();
        *root_causes_per_source.entry(source.clone()).or_insert(0) = rcs.len();
        *concepts_per_source.entry(source.clone()).or_insert(0) = classes.len() + rcs.len();
        source_classes
            .entry(source.clone())
            .or_default()
            .extend(classes);
    }

    // Average findings per source
    for (source, count) in &findings_per_source.clone() {
        let reports_in_source = items.iter().filter(|i| &i.source_id == source).count() as f64;
        if reports_in_source > 0.0 {
            findings_per_source.insert(source.clone(), count / reports_in_source);
        }
    }

    // Unique contribution: classes only seen in one source
    let all_classes: std::collections::BTreeSet<String> = source_classes
        .values()
        .flat_map(|s| s.iter().cloned())
        .collect();

    let mut unique_contribution: BTreeMap<String, usize> = BTreeMap::new();
    for class in &all_classes {
        let sources_with_class: Vec<&String> = source_classes
            .iter()
            .filter(|(_, classes)| classes.contains(class))
            .map(|(source, _)| source)
            .collect();
        if sources_with_class.len() == 1 {
            *unique_contribution
                .entry(sources_with_class[0].clone())
                .or_insert(0) += 1;
        }
    }

    KnowledgeROI {
        patterns_per_100_reports: patterns_per_100,
        concepts_per_source,
        cross_source_density,
        classes_per_source,
        root_causes_per_source,
        findings_per_source,
        unique_contribution,
    }
}

/// Serialize report to JSON.
pub fn report_to_json(report: &CorpusAnalyticsReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}
