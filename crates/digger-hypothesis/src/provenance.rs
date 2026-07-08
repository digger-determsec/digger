/// Evidence Provenance — track which source contributed to each conclusion.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Provenance record for a single piece of evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProvenanceRecord {
    /// Evidence identifier.
    pub evidence_id: String,
    /// Source type.
    pub source_type: SourceType,
    /// Source identifier (e.g., audit name, exploit ID).
    pub source_id: String,
    /// Source URL or path.
    pub source_location: String,
    /// Confidence in this source (1.0 = verified, 0.5 = inferred).
    pub source_confidence: f64,
    /// Timestamp (deterministic hash).
    pub provenance_hash: String,
}

/// Type of evidence source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceType {
    /// Audit report.
    AuditReport,
    /// Exploit postmortem.
    ExploitPostmortem,
    /// Protocol documentation.
    ProtocolDocumentation,
    /// Standard (ERC, EIP, etc.).
    Standard,
    /// Reasoning rule.
    ReasoningRule,
    /// Graph analysis.
    GraphAnalysis,
    /// Benchmark corpus.
    BenchmarkCorpus,
}

/// Provenance graph — tracks how sources contribute to conclusions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProvenanceGraph {
    /// All provenance records.
    pub records: Vec<ProvenanceRecord>,
    /// Source → evidence mapping.
    pub source_evidence_map: BTreeMap<String, Vec<String>>,
    /// Evidence → conclusion mapping.
    pub evidence_conclusion_map: BTreeMap<String, Vec<String>>,
    /// Total sources.
    pub total_sources: usize,
    /// Source diversity (unique source types).
    pub source_diversity: usize,
}

/// Build provenance graph from evidence and conclusions.
pub fn build_provenance(
    evidence: &[ProvenanceRecord],
    conclusions: &[(String, Vec<String>)], // (conclusion_id, evidence_ids)
) -> ProvenanceGraph {
    let mut source_evidence_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut evidence_conclusion_map: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // Build source → evidence mapping
    for record in evidence {
        source_evidence_map
            .entry(record.source_id.clone())
            .or_default()
            .push(record.evidence_id.clone());
    }

    // Build evidence → conclusion mapping
    for (conclusion_id, evidence_ids) in conclusions {
        for eid in evidence_ids {
            evidence_conclusion_map
                .entry(eid.clone())
                .or_default()
                .push(conclusion_id.clone());
        }
    }

    let source_types: std::collections::BTreeSet<String> = evidence
        .iter()
        .map(|r| format!("{:?}", r.source_type))
        .collect();

    ProvenanceGraph {
        records: evidence.to_vec(),
        source_evidence_map,
        evidence_conclusion_map,
        total_sources: source_types.len(),
        source_diversity: source_types.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provenance_deterministic() {
        let records = vec![ProvenanceRecord {
            evidence_id: "E1".into(),
            source_type: SourceType::AuditReport,
            source_id: "audit-1".into(),
            source_location: "https://example.com".into(),
            source_confidence: 1.0,
            provenance_hash: "abc123".into(),
        }];
        let conclusions = vec![("C1".into(), vec!["E1".into()])];

        let g1 = build_provenance(&records, &conclusions);
        let g2 = build_provenance(&records, &conclusions);
        assert_eq!(g1.total_sources, g2.total_sources);
    }
}
