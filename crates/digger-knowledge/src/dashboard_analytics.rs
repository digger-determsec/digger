/// Dashboard Analytics — Evidence Density, Coverage Velocity, Saturation, ROI, Next Best Action.
///
/// All computations are deterministic. No ML, no embeddings, no probabilistic estimation.
/// Same inputs → same outputs, always.
use digger_knowledge_models::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════
// Section 1: Evidence Density
// ═══════════════════════════════════════════════════════════════

/// Evidence density report — per-category evidence strength.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceDensityReport {
    /// Per-category density metrics.
    pub categories: Vec<EvidenceDensity>,
    /// Concepts flagged as weakly supported.
    pub weak_concepts: Vec<WeakConceptEntry>,
    /// Categories ranked by evidence strength (strongest first).
    pub ranking: Vec<String>,
}

/// Evidence density for a single canonical category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceDensity {
    /// Category name (e.g., "reentrancy", "missing_access_control").
    pub category: String,
    /// Category kind (e.g., "vulnerability_class", "root_cause", "attack_technique").
    pub kind: String,
    /// Total supporting findings.
    pub total_findings: usize,
    /// Total supporting exploits (from exploit postmortems).
    pub total_exploits: usize,
    /// Total supporting audit reports.
    pub total_audit_reports: usize,
    /// Total supporting protocols.
    pub total_protocols: usize,
    /// Total supporting sources (distinct source providers).
    pub total_sources: usize,
    /// Cross-protocol diversity (protocols / total_protocols_in_corpus).
    pub cross_protocol_diversity: f64,
    /// Cross-source diversity (sources / total_sources_in_corpus).
    pub cross_source_diversity: f64,
    /// Evidence strength score (composite).
    pub evidence_strength: f64,
}

/// A concept flagged as weakly supported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WeakConceptEntry {
    /// Concept name.
    pub name: String,
    /// Concept kind.
    pub kind: String,
    /// Total independent supporting artifacts.
    pub artifact_count: usize,
    /// Why it's weak.
    pub reason: String,
}

/// Compute evidence density for all canonical categories.
pub fn compute_evidence_density(items: &[NormalizedKnowledge]) -> EvidenceDensityReport {
    let all_findings: Vec<&NormalizedFinding> =
        items.iter().flat_map(|k| k.findings.iter()).collect();

    let total_protocols_in_corpus: usize = items
        .iter()
        .map(|k| k.subject.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let total_sources_in_corpus: usize = items
        .iter()
        .map(|k| k.source_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    // Collect all unique categories across dimensions
    let mut category_map: BTreeMap<String, Vec<&NormalizedFinding>> = BTreeMap::new();

    // Vulnerability classes
    for f in &all_findings {
        let key = f.vulnerability_class.to_string();
        if !key.starts_with("other(") {
            category_map.entry(key).or_default().push(f);
        }
    }
    // Root causes
    for f in &all_findings {
        let key = f.root_cause.to_string();
        if !key.starts_with("other(") {
            category_map.entry(key).or_default().push(f);
        }
    }
    // Attack techniques
    for f in &all_findings {
        let key = f.attack_technique.to_string();
        if !key.starts_with("other(") {
            category_map.entry(key).or_default().push(f);
        }
    }

    let mut densities: Vec<EvidenceDensity> = Vec::new();

    for (category, findings) in &category_map {
        let total_findings = findings.len();
        let protocols: std::collections::BTreeSet<&str> =
            findings.iter().map(|f| f.protocol_name.as_str()).collect();
        let sources: std::collections::BTreeSet<&str> = findings
            .iter()
            .map(|f| {
                items
                    .iter()
                    .find(|k| k.findings.iter().any(|kf| kf.finding_id == f.finding_id))
                    .map(|k| k.source_id.as_str())
                    .unwrap_or("unknown")
            })
            .collect();

        let total_exploits = findings
            .iter()
            .filter(|f| {
                items.iter().any(|k| {
                    k.source_kind == KnowledgeSourceKind::ExploitPostmortem
                        && k.findings.iter().any(|kf| kf.finding_id == f.finding_id)
                })
            })
            .count();

        let total_audit_reports: std::collections::BTreeSet<&str> = findings
            .iter()
            .filter(|f| {
                items.iter().any(|k| {
                    k.source_kind == KnowledgeSourceKind::AuditRepository
                        && k.findings.iter().any(|kf| kf.finding_id == f.finding_id)
                })
            })
            .filter_map(|f| {
                items
                    .iter()
                    .find(|k| k.findings.iter().any(|kf| kf.finding_id == f.finding_id))
            })
            .map(|k| k.source_id.as_str())
            .collect();

        let cross_protocol_diversity = if total_protocols_in_corpus > 0 {
            protocols.len() as f64 / total_protocols_in_corpus as f64
        } else {
            0.0
        };
        let cross_source_diversity = if total_sources_in_corpus > 0 {
            sources.len() as f64 / total_sources_in_corpus as f64
        } else {
            0.0
        };

        // Evidence strength: weighted composite
        let evidence_strength = compute_evidence_strength(
            total_findings,
            total_exploits,
            total_audit_reports.len(),
            protocols.len(),
            sources.len(),
            cross_protocol_diversity,
            cross_source_diversity,
        );

        let kind = categorize_kind(category);

        densities.push(EvidenceDensity {
            category: category.clone(),
            kind,
            total_findings,
            total_exploits,
            total_audit_reports: total_audit_reports.len(),
            total_protocols: protocols.len(),
            total_sources: sources.len(),
            cross_protocol_diversity,
            cross_source_diversity,
            evidence_strength,
        });
    }

    // Rank by evidence strength (strongest first)
    densities.sort_by(|a, b| {
        b.evidence_strength
            .partial_cmp(&a.evidence_strength)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let ranking: Vec<String> = densities.iter().map(|d| d.category.clone()).collect();

    // Flag weak concepts (< 5 independent supporting artifacts)
    let weak_concepts: Vec<WeakConceptEntry> = densities
        .iter()
        .filter(|d| {
            let independent_artifacts = d.total_findings + d.total_exploits + d.total_audit_reports;
            independent_artifacts < 5
        })
        .map(|d| WeakConceptEntry {
            name: d.category.clone(),
            kind: d.kind.clone(),
            artifact_count: d.total_findings + d.total_exploits + d.total_audit_reports,
            reason: format!(
                "Only {} independent supporting artifacts (findings: {}, exploits: {}, reports: {})",
                d.total_findings + d.total_exploits + d.total_audit_reports,
                d.total_findings,
                d.total_exploits,
                d.total_audit_reports
            ),
        })
        .collect();

    EvidenceDensityReport {
        categories: densities,
        weak_concepts,
        ranking,
    }
}

fn compute_evidence_strength(
    findings: usize,
    exploits: usize,
    audit_reports: usize,
    _protocols: usize,
    _sources: usize,
    cross_protocol_diversity: f64,
    cross_source_diversity: f64,
) -> f64 {
    // Weighted composite score
    let finding_score = (findings as f64).ln_1p() / 10.0; // diminishing returns
    let exploit_score = exploits as f64 * 0.3; // exploits are strong evidence
    let report_score = audit_reports as f64 * 0.2;
    let protocol_score = cross_protocol_diversity * 0.25;
    let source_score = cross_source_diversity * 0.15;

    (finding_score + exploit_score + report_score + protocol_score + source_score).min(1.0)
}

fn categorize_kind(name: &str) -> String {
    // Check if it matches a known root cause
    let root_causes = [
        "missing_authority_check",
        "incorrect_operation_order",
        "missing_state_update",
        "shared_mutable_state",
        "unvalidated_external_input",
        "incorrect_invariant_assumption",
        "missing_boundary_check",
        "unsafe_composition",
        "fee_on_transfer_incompatibility",
        "stale_state_assumption",
        "unchecked_return_value",
        "incorrect_rounding_direction",
        "missing_event_emission",
        "unsafe_external_dependency",
        "gas_griefing",
        "signature_malleability",
        "front_running_risk",
        "oracle_staleness",
        "missing_slippage_protection",
        "missing_zero_address_check",
        "timestamp_dependency",
        "cross_function_state_inconsistency",
    ];
    if root_causes.contains(&name) {
        return "root_cause".into();
    }

    let techniques = [
        "reentrancy_exploit",
        "flash_loan_borrow",
        "price_oracle_manipulation",
        "front_running_transaction",
        "sandwich_attack_vector",
        "governance_proposal_attack",
        "timelock_exploitation",
        "storage_collision_exploit",
        "delegatecall_exploitation",
        "unchecked_external_call",
        "precision_loss_exploitation",
        "state_manipulation_cross_function",
        "access_control_bypass",
        "initialization_bypass",
    ];
    if techniques.contains(&name) {
        return "attack_technique".into();
    }

    "vulnerability_class".into()
}

// ═══════════════════════════════════════════════════════════════
// Section 2: Coverage Velocity
// ═══════════════════════════════════════════════════════════════

/// A historical dashboard snapshot for velocity tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DashboardSnapshot {
    /// Snapshot timestamp (deterministic: hash of corpus state).
    pub snapshot_id: String,
    /// Total reports at this point.
    pub total_reports: usize,
    /// Total findings at this point.
    pub total_findings: usize,
    /// Total protocols at this point.
    pub total_protocols: usize,
    /// Coverage percentages by dimension.
    pub coverage_dimensions: BTreeMap<String, f64>,
    /// Distinct categories discovered.
    pub distinct_categories: usize,
}

/// Coverage velocity report — how coverage changes over time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoverageVelocityReport {
    /// Snapshots in chronological order.
    pub snapshots: Vec<DashboardSnapshot>,
    /// Per-dimension velocity metrics.
    pub dimensions: Vec<DimensionVelocity>,
    /// Dimensions improving rapidly.
    pub rapidly_improving: Vec<String>,
    /// Dimensions that have plateaued.
    pub plateaued: Vec<String>,
}

/// Velocity metrics for a single coverage dimension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DimensionVelocity {
    /// Dimension name.
    pub dimension: String,
    /// Absolute change from previous snapshot.
    pub absolute_change: f64,
    /// Percentage change from previous snapshot.
    pub percentage_change: f64,
    /// Growth rate (change per snapshot).
    pub growth_rate: f64,
    /// Moving average of last N snapshots (N=3 or fewer).
    pub moving_average: f64,
    /// Coverage acceleration (second derivative).
    pub acceleration: f64,
    /// Whether coverage is slowing down.
    pub is_slowing: bool,
    /// Current coverage value.
    pub current_value: f64,
}

/// Persist a snapshot. In production this writes to disk;
/// here we return the snapshot for the caller to persist.
pub fn create_snapshot(items: &[NormalizedKnowledge]) -> DashboardSnapshot {
    let all_findings: Vec<&NormalizedFinding> =
        items.iter().flat_map(|k| k.findings.iter()).collect();

    let total_reports = items.len();
    let total_findings = all_findings.len();
    let total_protocols: usize = items
        .iter()
        .map(|k| k.subject.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    let mut coverage_dimensions: BTreeMap<String, f64> = BTreeMap::new();

    // Vulnerability class coverage
    let class_total = 33usize;
    let class_covered: usize = all_findings
        .iter()
        .map(|f| f.vulnerability_class.to_string())
        .filter(|c| !c.starts_with("other("))
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    coverage_dimensions.insert(
        "vulnerability_class".into(),
        class_covered as f64 / class_total as f64 * 100.0,
    );

    // Root cause coverage
    let rc_total = 22usize;
    let rc_covered: usize = all_findings
        .iter()
        .map(|f| f.root_cause.to_string())
        .filter(|c| !c.starts_with("other("))
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    coverage_dimensions.insert(
        "root_cause".into(),
        rc_covered as f64 / rc_total as f64 * 100.0,
    );

    // Attack technique coverage
    let tech_total = 14usize;
    let tech_covered: usize = all_findings
        .iter()
        .map(|f| f.attack_technique.to_string())
        .filter(|c| !c.starts_with("other("))
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    coverage_dimensions.insert(
        "attack_technique".into(),
        tech_covered as f64 / tech_total as f64 * 100.0,
    );

    // Protocol domain coverage
    let domain_total = 19usize;
    let domain_covered: usize = all_findings
        .iter()
        .map(|f| f.protocol_domain.to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    coverage_dimensions.insert(
        "protocol_domain".into(),
        domain_covered as f64 / domain_total as f64 * 100.0,
    );

    let distinct_categories = all_findings
        .iter()
        .map(|f| f.vulnerability_class.to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    // Deterministic snapshot ID
    let mut h: u64 = 0;
    for item in items {
        for byte in item.knowledge_id.bytes() {
            h = h.wrapping_mul(31).wrapping_add(byte as u64);
        }
    }

    DashboardSnapshot {
        snapshot_id: format!("snap:{:016x}", h),
        total_reports,
        total_findings,
        total_protocols,
        coverage_dimensions,
        distinct_categories,
    }
}

/// Compute coverage velocity from a sequence of snapshots.
pub fn compute_velocity(snapshots: &[DashboardSnapshot]) -> CoverageVelocityReport {
    if snapshots.is_empty() {
        return CoverageVelocityReport {
            snapshots: vec![],
            dimensions: vec![],
            rapidly_improving: vec![],
            plateaued: vec![],
        };
    }

    // Collect all dimension names
    let all_dims: std::collections::BTreeSet<String> = snapshots
        .iter()
        .flat_map(|s| s.coverage_dimensions.keys().cloned())
        .collect();

    let mut dimensions = Vec::new();
    let mut rapidly_improving = Vec::new();
    let mut plateaued = Vec::new();

    for dim in &all_dims {
        let values: Vec<f64> = snapshots
            .iter()
            .map(|s| s.coverage_dimensions.get(dim).copied().unwrap_or(0.0))
            .collect();

        let current = *values.last().unwrap_or(&0.0);
        let prev = if values.len() >= 2 {
            values[values.len() - 2]
        } else {
            current
        };

        let absolute_change = current - prev;
        let percentage_change = if prev > 0.0 {
            (current - prev) / prev * 100.0
        } else {
            0.0
        };

        // Growth rate: average change per snapshot
        let growth_rate = if values.len() >= 2 {
            let total_change = values.last().unwrap_or(&0.0) - values.first().unwrap_or(&0.0);
            total_change / (values.len() - 1) as f64
        } else {
            0.0
        };

        // Moving average (last 3 or fewer)
        let window = values.len().min(3);
        let moving_average = if window > 0 {
            values[values.len() - window..].iter().sum::<f64>() / window as f64
        } else {
            0.0
        };

        // Acceleration: second derivative
        let acceleration = if values.len() >= 3 {
            let v1 = values[values.len() - 1] - values[values.len() - 2];
            let v0 = values[values.len() - 2] - values[values.len() - 3];
            v1 - v0
        } else {
            0.0
        };

        let is_slowing = acceleration < -0.01;

        if absolute_change > 1.0 {
            rapidly_improving.push(dim.clone());
        }
        if is_slowing && growth_rate < 0.1 {
            plateaued.push(dim.clone());
        }

        dimensions.push(DimensionVelocity {
            dimension: dim.clone(),
            absolute_change,
            percentage_change,
            growth_rate,
            moving_average,
            acceleration,
            is_slowing,
            current_value: current,
        });
    }

    CoverageVelocityReport {
        snapshots: snapshots.to_vec(),
        dimensions,
        rapidly_improving,
        plateaued,
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 3: Saturation Analysis
// ═══════════════════════════════════════════════════════════════

/// Saturation analysis report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SaturationReport {
    /// Per-dimension saturation metrics.
    pub dimensions: Vec<SaturationDimension>,
    /// Dimensions approaching saturation.
    pub approaching_saturation: Vec<String>,
    /// Dimensions with room for growth.
    pub room_for_growth: Vec<String>,
}

/// Saturation metrics for a single dimension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SaturationDimension {
    /// Dimension name.
    pub dimension: String,
    /// Current coverage percentage.
    pub current_coverage: f64,
    /// Average growth rate over last N snapshots.
    pub avg_growth_rate: f64,
    /// Number of new concepts discovered in last N snapshots.
    pub new_concepts_recent: usize,
    /// Percentage of new artifacts mapping to existing concepts.
    pub existing_concept_mapping_rate: f64,
    /// Saturation score (0.0 = no saturation, 1.0 = fully saturated).
    pub saturation_score: f64,
    /// Classification.
    pub classification: String,
}

/// Compute saturation analysis from snapshots and current items.
pub fn compute_saturation(
    snapshots: &[DashboardSnapshot],
    _items: &[NormalizedKnowledge],
) -> SaturationReport {
    if snapshots.len() < 2 {
        return SaturationReport {
            dimensions: vec![],
            approaching_saturation: vec![],
            room_for_growth: vec![],
        };
    }

    // Get recent snapshots (last 3 or all)
    let recent_count = snapshots.len().min(3);
    let recent = &snapshots[snapshots.len() - recent_count..];

    let all_dims: std::collections::BTreeSet<String> = snapshots
        .iter()
        .flat_map(|s| s.coverage_dimensions.keys().cloned())
        .collect();

    let mut dimensions = Vec::new();
    let mut approaching_saturation = Vec::new();
    let mut room_for_growth = Vec::new();

    for dim in &all_dims {
        let current = recent
            .last()
            .and_then(|s| s.coverage_dimensions.get(dim))
            .copied()
            .unwrap_or(0.0);

        // Average growth rate over recent snapshots
        let mut growth_rates = Vec::new();
        for w in 1..recent.len() {
            let prev = recent[recent.len() - w - 1]
                .coverage_dimensions
                .get(dim)
                .copied()
                .unwrap_or(0.0);
            let curr = recent[recent.len() - w]
                .coverage_dimensions
                .get(dim)
                .copied()
                .unwrap_or(0.0);
            growth_rates.push(curr - prev);
        }
        let avg_growth_rate = if growth_rates.is_empty() {
            0.0
        } else {
            growth_rates.iter().sum::<f64>() / growth_rates.len() as f64
        };

        // New concepts: distinct categories in recent vs earlier
        let earlier = &snapshots[..snapshots.len() - recent_count.max(1)];
        let recent_categories: usize = recent
            .iter()
            .map(|s| s.distinct_categories)
            .max()
            .unwrap_or(0);
        let earlier_categories: usize = earlier
            .iter()
            .map(|s| s.distinct_categories)
            .max()
            .unwrap_or(0);
        let new_concepts_recent = recent_categories.saturating_sub(earlier_categories);

        // Existing concept mapping rate: if few new concepts but many new artifacts,
        // most artifacts map to existing concepts
        let recent_findings: usize = recent.iter().map(|s| s.total_findings).sum();
        let earlier_findings: usize = earlier.iter().map(|s| s.total_findings).sum();
        let new_findings = recent_findings.saturating_sub(earlier_findings);
        let existing_concept_mapping_rate = if new_findings > 0 && new_concepts_recent > 0 {
            1.0 - (new_concepts_recent as f64 / new_findings as f64).min(1.0)
        } else if new_findings > 0 {
            1.0
        } else {
            0.0
        };

        // Saturation score
        let saturation_score = compute_saturation_score(
            current,
            avg_growth_rate,
            new_concepts_recent,
            existing_concept_mapping_rate,
        );

        let classification = if saturation_score >= 0.8 {
            "saturated"
        } else if saturation_score >= 0.5 {
            "approaching_saturation"
        } else if saturation_score >= 0.2 {
            "moderate_growth"
        } else {
            "high_growth"
        };

        if saturation_score >= 0.5 {
            approaching_saturation.push(dim.clone());
        } else {
            room_for_growth.push(dim.clone());
        }

        dimensions.push(SaturationDimension {
            dimension: dim.clone(),
            current_coverage: current,
            avg_growth_rate,
            new_concepts_recent,
            existing_concept_mapping_rate,
            saturation_score,
            classification: classification.into(),
        });
    }

    dimensions.sort_by(|a, b| {
        b.saturation_score
            .partial_cmp(&a.saturation_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    SaturationReport {
        dimensions,
        approaching_saturation,
        room_for_growth,
    }
}

fn compute_saturation_score(
    current_coverage: f64,
    avg_growth_rate: f64,
    new_concepts_recent: usize,
    existing_concept_mapping_rate: f64,
) -> f64 {
    // High coverage + low growth + few new concepts + high existing mapping = saturated
    let coverage_score = current_coverage / 100.0;
    let growth_score = if avg_growth_rate < 0.1 {
        1.0
    } else if avg_growth_rate < 0.5 {
        0.5
    } else {
        0.0
    };
    let concept_score = if new_concepts_recent == 0 {
        1.0
    } else if new_concepts_recent <= 1 {
        0.7
    } else if new_concepts_recent <= 3 {
        0.3
    } else {
        0.0
    };
    let mapping_score = existing_concept_mapping_rate;

    // Weighted composite
    coverage_score * 0.3 + growth_score * 0.3 + concept_score * 0.2 + mapping_score * 0.2
}

// ═══════════════════════════════════════════════════════════════
// Section 4: Knowledge ROI (Enhanced)
// ═══════════════════════════════════════════════════════════════

/// Enhanced Knowledge ROI — per-source return on investment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeROIReport {
    /// Per-source ROI metrics.
    pub sources: Vec<SourceROI>,
    /// Sources ranked by ROI (best first).
    pub ranking: Vec<String>,
}

/// ROI metrics for a single ingestion source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceROI {
    /// Source identifier.
    pub source_id: String,
    /// Source kind.
    pub source_kind: String,
    /// Total reports ingested.
    pub total_reports: usize,
    /// Total findings extracted.
    pub total_findings: usize,
    /// New canonical concepts introduced (classes not seen in other sources).
    pub new_concepts_introduced: usize,
    /// Existing concepts reinforced (classes already seen in other sources).
    pub existing_concepts_reinforced: usize,
    /// New protocol domains added.
    pub new_protocol_domains_added: usize,
    /// New standards added.
    pub new_standards_added: usize,
    /// New reasoning patterns added.
    pub new_reasoning_patterns_added: usize,
    /// Evidence density increase (how much this source strengthens existing categories).
    pub evidence_density_increase: f64,
    /// Coverage increase per ingested artifact.
    pub coverage_increase_per_artifact: f64,
    /// Composite ROI score.
    pub roi_score: f64,
}

/// Compute enhanced knowledge ROI.
pub fn compute_knowledge_roi(items: &[NormalizedKnowledge]) -> KnowledgeROIReport {
    // Group findings by source
    let mut source_findings: BTreeMap<String, Vec<&NormalizedFinding>> = BTreeMap::new();
    let mut _source_kind_map: BTreeMap<String, String> = BTreeMap::new();

    for item in items {
        let source = &item.source_id;
        _source_kind_map.insert(source.clone(), format!("{:?}", item.source_kind));
        for f in &item.findings {
            source_findings.entry(source.clone()).or_default().push(f);
        }
    }

    // For each source, compute what it uniquely contributes
    let first_source = items
        .first()
        .map(|i| i.source_id.clone())
        .unwrap_or_default();
    let _all_other_classes: std::collections::BTreeSet<String> = items
        .iter()
        .flat_map(|k| {
            if k.source_id != first_source {
                k.findings
                    .iter()
                    .map(|f| f.vulnerability_class.to_string())
                    .filter(|c| !c.starts_with("other("))
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        })
        .collect();

    let mut sources = Vec::new();
    let all_sources: Vec<String> = source_findings.keys().cloned().collect();

    for source_id in &all_sources {
        let findings = &source_findings[source_id];
        let source_kind = _source_kind_map.get(source_id).cloned().unwrap_or_default();

        let total_reports = items.iter().filter(|k| &k.source_id == source_id).count();
        let total_findings = findings.len();

        // Classes introduced by this source
        let source_classes: std::collections::BTreeSet<String> = findings
            .iter()
            .map(|f| f.vulnerability_class.to_string())
            .filter(|c| !c.starts_with("other("))
            .collect();

        let other_classes: std::collections::BTreeSet<String> = items
            .iter()
            .filter(|k| &k.source_id != source_id)
            .flat_map(|k| {
                k.findings
                    .iter()
                    .map(|f| f.vulnerability_class.to_string())
                    .filter(|c| !c.starts_with("other("))
            })
            .collect();

        let new_concepts_introduced: usize = source_classes.difference(&other_classes).count();
        let existing_concepts_reinforced: usize =
            source_classes.intersection(&other_classes).count();

        // New protocol domains
        let source_domains: std::collections::BTreeSet<String> = findings
            .iter()
            .map(|f| f.protocol_domain.to_string())
            .collect();
        let other_domains: std::collections::BTreeSet<String> = items
            .iter()
            .filter(|k| &k.source_id != source_id)
            .flat_map(|k| k.findings.iter().map(|f| f.protocol_domain.to_string()))
            .collect();
        let new_protocol_domains_added = source_domains.difference(&other_domains).count();

        // New standards
        let source_standards: std::collections::BTreeSet<String> = items
            .iter()
            .filter(|k| &k.source_id == source_id)
            .filter(|k| k.source_kind == KnowledgeSourceKind::Standard)
            .map(|k| k.subject.clone())
            .collect();
        let other_standards: std::collections::BTreeSet<String> = items
            .iter()
            .filter(|k| &k.source_id != source_id)
            .filter(|k| k.source_kind == KnowledgeSourceKind::Standard)
            .map(|k| k.subject.clone())
            .collect();
        let new_standards_added = source_standards.difference(&other_standards).count();

        // New reasoning patterns (class+goal combos unique to this source)
        let source_combos: std::collections::BTreeSet<String> = findings
            .iter()
            .map(|f| format!("{}:{}", f.vulnerability_class, f.attack_goal))
            .collect();
        let other_combos: std::collections::BTreeSet<String> = items
            .iter()
            .filter(|k| &k.source_id != source_id)
            .flat_map(|k| {
                k.findings
                    .iter()
                    .map(|f| format!("{}:{}", f.vulnerability_class, f.attack_goal))
            })
            .collect();
        let new_reasoning_patterns_added = source_combos.difference(&other_combos).count();

        // Evidence density increase: how much this source strengthens existing categories
        let evidence_density_increase = if total_findings > 0 {
            (existing_concepts_reinforced as f64 / source_classes.len().max(1) as f64) * 0.5
                + (new_concepts_introduced as f64 / 10.0).min(0.5)
        } else {
            0.0
        };

        // Coverage increase per artifact
        let coverage_increase_per_artifact = if total_findings > 0 {
            (new_concepts_introduced + new_protocol_domains_added) as f64 / total_findings as f64
        } else {
            0.0
        };

        // Composite ROI score
        let roi_score = compute_roi_score(
            new_concepts_introduced,
            existing_concepts_reinforced,
            new_protocol_domains_added,
            new_standards_added,
            new_reasoning_patterns_added,
            evidence_density_increase,
            coverage_increase_per_artifact,
        );

        sources.push(SourceROI {
            source_id: source_id.clone(),
            source_kind,
            total_reports,
            total_findings,
            new_concepts_introduced,
            existing_concepts_reinforced,
            new_protocol_domains_added,
            new_standards_added,
            new_reasoning_patterns_added,
            evidence_density_increase,
            coverage_increase_per_artifact,
            roi_score,
        });
    }

    sources.sort_by(|a, b| {
        b.roi_score
            .partial_cmp(&a.roi_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let ranking = sources.iter().map(|s| s.source_id.clone()).collect();

    KnowledgeROIReport { sources, ranking }
}

fn compute_roi_score(
    new_concepts: usize,
    reinforced: usize,
    new_domains: usize,
    new_standards: usize,
    new_patterns: usize,
    density_increase: f64,
    coverage_per_artifact: f64,
) -> f64 {
    let concept_score = new_concepts as f64 * 0.25;
    let reinforce_score = reinforced as f64 * 0.05;
    let domain_score = new_domains as f64 * 0.20;
    let standard_score = new_standards as f64 * 0.15;
    let pattern_score = new_patterns as f64 * 0.15;
    let density_score = density_increase * 0.10;
    let coverage_score = coverage_per_artifact * 0.10;

    concept_score
        + reinforce_score
        + domain_score
        + standard_score
        + pattern_score
        + density_score
        + coverage_score
}

// ═══════════════════════════════════════════════════════════════
// Section 5: Next Best Action
// ═══════════════════════════════════════════════════════════════

/// Next Best Action report — deterministic recommendations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NextBestActionReport {
    /// Ranked recommendations.
    pub actions: Vec<RecommendedAction>,
    /// Summary of expected improvement.
    pub expected_improvement: ExpectedImprovement,
}

/// A single recommended action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecommendedAction {
    /// Action rank (1 = highest priority).
    pub rank: usize,
    /// Action kind.
    pub kind: String,
    /// Description.
    pub description: String,
    /// Target dimension(s) this action improves.
    pub target_dimensions: Vec<String>,
    /// Expected coverage improvement (percentage points).
    pub expected_coverage_improvement: f64,
    /// Expected new concepts.
    pub expected_new_concepts: usize,
    /// Expected new protocols.
    pub expected_new_protocols: usize,
    /// Evidence supporting this recommendation.
    pub evidence: Vec<String>,
    /// Why this action is prioritized.
    pub rationale: String,
}

/// Expected total improvement from all recommended actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpectedImprovement {
    /// Total expected coverage improvement.
    pub total_coverage_improvement: f64,
    /// Total expected new concepts.
    pub total_new_concepts: usize,
    /// Total expected new protocols.
    pub total_new_protocols: usize,
    /// Dimensions most impacted.
    pub most_impacted_dimensions: Vec<String>,
}

/// Compute next best actions.
pub fn compute_next_best_actions(
    items: &[NormalizedKnowledge],
    density: &EvidenceDensityReport,
    saturation: &SaturationReport,
    _roi: &KnowledgeROIReport,
) -> NextBestActionReport {
    let mut actions = Vec::new();
    let mut rank = 1;

    // 1. Address weak concepts — categories with < 5 artifacts
    for weak in &density.weak_concepts {
        actions.push(RecommendedAction {
            rank,
            kind: "strengthen_weak_concept".into(),
            description: format!(
                "Ingest more evidence for '{}' — currently only {} supporting artifacts",
                weak.name, weak.artifact_count
            ),
            target_dimensions: vec![weak.kind.clone()],
            expected_coverage_improvement: 0.5,
            expected_new_concepts: 0,
            expected_new_protocols: 1,
            evidence: vec![weak.reason.clone()],
            rationale: "Weak concepts risk false confidence in classification".into(),
        });
        rank += 1;
    }

    // 2. Expand dimensions with room for growth (not saturated)
    for dim in &saturation.room_for_growth {
        if dim == "vulnerability_class" || dim == "root_cause" || dim == "attack_technique" {
            let current = saturation
                .dimensions
                .iter()
                .find(|d| d.dimension == *dim)
                .map(|d| d.current_coverage)
                .unwrap_or(0.0);

            let expected_improvement = (100.0 - current) * 0.1; // 10% of remaining gap

            actions.push(RecommendedAction {
                rank,
                kind: "expand_dimension".into(),
                description: format!(
                    "Expand '{}' coverage — currently at {:.1}%, room for {:.1}pp improvement",
                    dim, current, expected_improvement
                ),
                target_dimensions: vec![dim.clone()],
                expected_coverage_improvement: expected_improvement,
                expected_new_concepts: 2,
                expected_new_protocols: 3,
                evidence: vec![
                    format!("Current coverage: {:.1}%", current),
                    "Dimension not yet saturated".into(),
                ],
                rationale: "Maximize ontology completeness in under-covered dimensions".into(),
            });
            rank += 1;
        }
    }

    // 3. Ingest highest ROI sources not yet present
    let existing_sources: std::collections::BTreeSet<String> =
        items.iter().map(|k| k.source_id.clone()).collect();

    let missing_high_value_sources = [
        (
            "sherlock",
            "audit_repository",
            "Sherlock judging contests — high finding density",
        ),
        (
            "cantina",
            "audit_repository",
            "Cantina audits — deep protocol analysis",
        ),
        (
            "pashov",
            "audit_repository",
            "Pashov audit reports — systematic coverage",
        ),
        (
            "trailofbits",
            "audit_repository",
            "Trail of Bits — industry-standard methodology",
        ),
    ];

    for (source, kind, reason) in &missing_high_value_sources {
        if !existing_sources.contains(*source) {
            actions.push(RecommendedAction {
                rank,
                kind: "ingest_source".into(),
                description: format!("Ingest {} ({})", source, kind),
                target_dimensions: vec!["vulnerability_class".into(), "root_cause".into()],
                expected_coverage_improvement: 2.0,
                expected_new_concepts: 3,
                expected_new_protocols: 5,
                evidence: vec![reason.to_string()],
                rationale: "High-ROI source not yet ingested".into(),
            });
            rank += 1;
        }
    }

    // 4. Add missing protocol domains
    let all_findings: Vec<&NormalizedFinding> =
        items.iter().flat_map(|k| k.findings.iter()).collect();
    let covered_domains: std::collections::BTreeSet<String> = all_findings
        .iter()
        .map(|f| f.protocol_domain.to_string())
        .collect();

    let all_domains = [
        ("bridges", "Cross-chain bridges — high-value attack surface"),
        (
            "governance",
            "Governance systems — flash loan voting attacks",
        ),
        ("stablecoins", "Stablecoins — peg mechanism failures"),
        ("derivatives", "Derivatives — oracle manipulation vectors"),
        ("oracles", "Oracles — price feed manipulation"),
    ];

    for (domain, reason) in &all_domains {
        if !covered_domains.contains(*domain) {
            actions.push(RecommendedAction {
                rank,
                kind: "add_protocol_domain".into(),
                description: format!("Add protocol domain: {}", domain),
                target_dimensions: vec!["protocol_domain".into()],
                expected_coverage_improvement: 5.3, // 1/19 of domain coverage
                expected_new_concepts: 1,
                expected_new_protocols: 2,
                evidence: vec![reason.to_string()],
                rationale: "Uncovered protocol domain represents blind spot".into(),
            });
            rank += 1;
        }
    }

    // Sort by expected coverage improvement (descending)
    actions.sort_by(|a, b| {
        b.expected_coverage_improvement
            .partial_cmp(&a.expected_coverage_improvement)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    // Re-rank
    for (i, action) in actions.iter_mut().enumerate() {
        action.rank = i + 1;
    }

    let total_coverage_improvement: f64 = actions
        .iter()
        .map(|a| a.expected_coverage_improvement)
        .sum();
    let total_new_concepts: usize = actions.iter().map(|a| a.expected_new_concepts).sum();
    let total_new_protocols: usize = actions.iter().map(|a| a.expected_new_protocols).sum();

    let most_impacted_dimensions: Vec<String> = actions
        .iter()
        .flat_map(|a| a.target_dimensions.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    NextBestActionReport {
        actions,
        expected_improvement: ExpectedImprovement {
            total_coverage_improvement,
            total_new_concepts,
            total_new_protocols,
            most_impacted_dimensions,
        },
    }
}
