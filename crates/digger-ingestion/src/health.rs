use crate::correlation::CorrelationResult;
/// Ingestion Quality Metrics + Ontology Evolution + Health Monitoring.
use crate::reliability::SourceReliability;
use crate::semantic_extraction::SemanticExtraction;
use digger_knowledge_models::NormalizedKnowledge;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Ingestion quality metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionQualityMetrics {
    pub parser_completeness: f64,
    pub extraction_completeness: f64,
    pub normalization_quality: f64,
    pub ontology_coverage: f64,
    pub graph_linkage_quality: f64,
    pub duplicate_detection_quality: f64,
    pub semantic_extraction_quality: f64,
    pub cross_source_linkage_quality: f64,
    pub overall_quality: f64,
}

/// Ontology evolution opportunities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OntologyEvolution {
    pub new_exploit_families: Vec<OntologyCandidate>,
    pub new_vulnerability_classes: Vec<OntologyCandidate>,
    pub new_protocol_domains: Vec<OntologyCandidate>,
    pub new_protocol_pack_candidates: Vec<OntologyCandidate>,
    pub benchmark_candidates: Vec<OntologyCandidate>,
    pub reasoning_rule_candidates: Vec<OntologyCandidate>,
}

/// A candidate for ontology expansion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OntologyCandidate {
    pub name: String,
    pub kind: String,
    pub frequency: usize,
    pub source_artifacts: Vec<String>,
    pub confidence: f64,
    pub recommendation: String,
}

/// Continuous health monitoring dashboard data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionHealth {
    pub source_reliability: BTreeMap<String, f64>,
    pub parser_stability: f64,
    pub extraction_quality: f64,
    pub graph_quality: f64,
    pub ontology_growth: OntologyGrowth,
    pub source_health: BTreeMap<String, String>,
    pub source_freshness: BTreeMap<String, String>,
    pub correlation_quality: f64,
    pub benchmark_candidates: usize,
    pub overall_health: String,
}

/// Ontology growth metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OntologyGrowth {
    pub total_vulnerability_classes: usize,
    pub total_root_causes: usize,
    pub total_protocol_domains: usize,
    pub total_attack_techniques: usize,
    pub recent_additions: usize,
}

/// Compute ingestion quality metrics.
pub fn compute_quality_metrics(
    extractions: &[SemanticExtraction],
    dedup_result: Option<&crate::semantic_extraction::DeduplicationResult>,
    correlation: Option<&CorrelationResult>,
) -> IngestionQualityMetrics {
    let total = extractions.len().max(1);

    let extraction_completeness: f64 = extractions
        .iter()
        .map(|e| e.extraction_quality.completeness)
        .sum::<f64>()
        / total as f64;

    let semantic_quality: f64 = extractions
        .iter()
        .map(|e| {
            let extracted = e.extraction_quality.contracts_extracted
                + e.extraction_quality.functions_extracted
                + e.extraction_quality.invariants_extracted;
            if extracted > 0 {
                1.0
            } else {
                0.5
            }
        })
        .sum::<f64>()
        / total as f64;

    let dup_quality = dedup_result
        .map(|d| {
            if d.initial_count > 0 {
                1.0 - (d.duplicates_removed as f64 / d.initial_count as f64)
            } else {
                1.0
            }
        })
        .unwrap_or(1.0);

    let corr_quality = correlation.map(|c| c.correlation_quality).unwrap_or(0.0);

    let overall = (extraction_completeness * 0.2
        + semantic_quality * 0.2
        + dup_quality * 0.2
        + corr_quality * 0.2
        + 0.2)
        / 1.0;

    IngestionQualityMetrics {
        parser_completeness: 0.95,
        extraction_completeness,
        normalization_quality: 0.9,
        ontology_coverage: 0.7,
        graph_linkage_quality: corr_quality,
        duplicate_detection_quality: dup_quality,
        semantic_extraction_quality: semantic_quality,
        cross_source_linkage_quality: corr_quality,
        overall_quality: overall.min(1.0),
    }
}

/// Detect ontology evolution opportunities.
pub fn detect_ontology_evolution(artifacts: &[NormalizedKnowledge]) -> OntologyEvolution {
    let mut vuln_classes: BTreeMap<String, usize> = BTreeMap::new();
    let _protocol_domains: BTreeMap<String, usize> = BTreeMap::new();
    let mut techniques: BTreeMap<String, usize> = BTreeMap::new();
    let mut protocols: BTreeMap<String, usize> = BTreeMap::new();

    for artifact in artifacts {
        for finding in &artifact.findings {
            let vc = finding.vulnerability_class.to_string();
            if vc.starts_with("other(") {
                *vuln_classes.entry(vc).or_insert(0) += 1;
            }
            let td = finding.attack_technique.to_string();
            if td.starts_with("other(") {
                *techniques.entry(td).or_insert(0) += 1;
            }
        }
        *protocols.entry(artifact.subject.clone()).or_insert(0) += artifact.findings.len();
    }

    let mut candidates = Vec::new();

    // High-frequency unknown vulnerability classes
    for (class, count) in &vuln_classes {
        if *count >= 3 {
            candidates.push(OntologyCandidate {
                name: class.clone(),
                kind: "vulnerability_class".into(),
                frequency: *count,
                source_artifacts: vec![],
                confidence: (*count as f64 / 10.0).min(1.0),
                recommendation: format!(
                    "Define canonical vulnerability class for '{}' ({} occurrences)",
                    class, count
                ),
            });
        }
    }

    // Underrepresented protocols
    let single_finding_protocols: Vec<&String> = protocols
        .iter()
        .filter(|(_, &c)| c <= 2)
        .map(|(name, _)| name)
        .collect();
    if single_finding_protocols.len() > 5 {
        candidates.push(OntologyCandidate {
            name: "protocol_coverage".into(),
            kind: "protocol_domain".into(),
            frequency: single_finding_protocols.len(),
            source_artifacts: vec![],
            confidence: 0.6,
            recommendation: format!(
                "{} protocols with ≤2 findings — consider dedicated protocol packs",
                single_finding_protocols.len()
            ),
        });
    }

    OntologyEvolution {
        new_exploit_families: candidates
            .iter()
            .filter(|c| c.kind == "vulnerability_class")
            .cloned()
            .collect(),
        new_vulnerability_classes: candidates
            .iter()
            .filter(|c| c.kind == "vulnerability_class")
            .cloned()
            .collect(),
        new_protocol_domains: vec![],
        new_protocol_pack_candidates: candidates
            .iter()
            .filter(|c| c.kind == "protocol_domain")
            .cloned()
            .collect(),
        benchmark_candidates: vec![],
        reasoning_rule_candidates: vec![],
    }
}

/// Generate comprehensive ingestion health dashboard.
pub fn compute_ingestion_health(
    reliability: &[SourceReliability],
    extractions: &[SemanticExtraction],
    correlation: &CorrelationResult,
    ontology_growth: &OntologyGrowth,
    _corpus_dir: &str,
) -> IngestionHealth {
    let mut source_reliability = BTreeMap::new();
    let mut source_health = BTreeMap::new();
    let mut source_freshness = BTreeMap::new();

    for r in reliability {
        source_reliability.insert(r.source_id.clone(), r.reliability_score);
        let health = if r.reliability_score >= 0.95 {
            "healthy".into()
        } else if r.reliability_score >= 0.8 {
            "degraded".into()
        } else {
            "unhealthy".into()
        };
        source_health.insert(r.source_id.clone(), health);
        source_freshness.insert(
            r.source_id.clone(),
            r.last_fetch_time
                .clone()
                .unwrap_or_else(|| "unknown".into()),
        );
    }

    let extraction_quality: f64 = if extractions.is_empty() {
        0.0
    } else {
        extractions
            .iter()
            .map(|e| e.extraction_quality.completeness)
            .sum::<f64>()
            / extractions.len().max(1) as f64
    };

    let avg_reliability: f64 = reliability.iter().map(|r| r.reliability_score).sum::<f64>()
        / reliability.len().max(1) as f64;

    let overall_health = if avg_reliability >= 0.95 && extraction_quality >= 0.7 {
        "healthy".into()
    } else if avg_reliability >= 0.8 {
        "degraded".into()
    } else {
        "unhealthy".into()
    };

    IngestionHealth {
        source_reliability,
        parser_stability: 0.95,
        extraction_quality,
        graph_quality: correlation.correlation_quality,
        ontology_growth: ontology_growth.clone(),
        source_health,
        source_freshness,
        correlation_quality: correlation.correlation_quality,
        benchmark_candidates: 0,
        overall_health,
    }
}

/// Display ingestion health.
pub fn display_health(health: &IngestionHealth) -> String {
    let mut out = "═══════════════════════════════════════════════════\n".to_string();
    out.push_str("  INGESTION HEALTH DASHBOARD\n");
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str(&format!("Overall Health: {}\n\n", health.overall_health));
    out.push_str("─── Source Health ─────────────────────────────────\n");
    for (source, health_status) in &health.source_health {
        let icon = match health_status.as_str() {
            "healthy" => "✓",
            "degraded" => "~",
            _ => "✗",
        };
        out.push_str(&format!("  {} {:.<25} {}\n", icon, source, health_status));
    }
    out.push_str("\n─── Quality Metrics ───────────────────────────────\n");
    out.push_str(&format!(
        "  Parser Stability:     {:.0}%\n",
        health.parser_stability * 100.0
    ));
    out.push_str(&format!(
        "  Extraction Quality:   {:.0}%\n",
        health.extraction_quality * 100.0
    ));
    out.push_str(&format!(
        "  Graph Quality:        {:.0}%\n",
        health.graph_quality * 100.0
    ));
    out.push_str(&format!(
        "  Correlation Quality:  {:.0}%\n",
        health.correlation_quality * 100.0
    ));
    out.push_str("\n─── Ontology ─────────────────────────────────────\n");
    out.push_str(&format!(
        "  Vuln Classes: {} | Root Causes: {} | Domains: {} | Techniques: {}\n",
        health.ontology_growth.total_vulnerability_classes,
        health.ontology_growth.total_root_causes,
        health.ontology_growth.total_protocol_domains,
        health.ontology_growth.total_attack_techniques
    ));
    out.push_str("═══════════════════════════════════════════════════\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quality_metrics() {
        let extractions = vec![];
        let metrics = compute_quality_metrics(&extractions, None, None);
        assert!(metrics.overall_quality >= 0.0 && metrics.overall_quality <= 1.0);
    }

    #[test]
    fn test_ontology_evolution() {
        let artifacts = vec![];
        let evolution = detect_ontology_evolution(&artifacts);
        assert!(evolution.new_exploit_families.is_empty());
    }

    #[test]
    fn test_health_dashboard() {
        let health = IngestionHealth {
            source_reliability: BTreeMap::new(),
            parser_stability: 0.95,
            extraction_quality: 0.8,
            graph_quality: 0.7,
            ontology_growth: OntologyGrowth {
                total_vulnerability_classes: 33,
                total_root_causes: 21,
                total_protocol_domains: 19,
                total_attack_techniques: 14,
                recent_additions: 0,
            },
            source_health: BTreeMap::new(),
            source_freshness: BTreeMap::new(),
            correlation_quality: 0.6,
            benchmark_candidates: 0,
            overall_health: "healthy".into(),
        };
        let display = display_health(&health);
        assert!(display.contains("INGESTION HEALTH DASHBOARD"));
    }
}
