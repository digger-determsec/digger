/// Reasoning patterns — reusable security knowledge derived from historical findings.
use serde::{Deserialize, Serialize};

/// A reusable reasoning pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningPattern {
    /// Deterministic pattern identifier.
    pub pattern_id: String,
    /// Pattern name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Vulnerability class this pattern addresses.
    pub vulnerability_class: String,
    /// Attack goal.
    pub attack_goal: String,
    /// Required attacker capabilities.
    pub required_capabilities: Vec<String>,
    /// Structural indicators that suggest this pattern.
    pub structural_indicators: Vec<StructuralIndicator>,
    /// Invariants violated by this pattern.
    pub violated_invariants: Vec<String>,
    /// Evidence sources relevant to this pattern.
    pub evidence_sources: Vec<String>,
    /// Historical finding IDs supporting this pattern.
    pub historical_findings: Vec<String>,
    /// Baseline confidence from historical data.
    pub confidence_baseline: f64,
    /// Provenance.
    pub provenance: PatternProvenance,
}

/// A structural indicator for a reasoning pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StructuralIndicator {
    /// Indicator description.
    pub indicator: String,
    /// Which semantic model provides this indicator.
    pub source_model: String,
    /// Weight (0.0–1.0).
    pub weight: f64,
}

/// Provenance for a reasoning pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatternProvenance {
    /// Source repository.
    pub source: String,
    /// Number of findings supporting this pattern.
    pub finding_count: usize,
    /// Number of protocols with this pattern.
    pub protocol_count: usize,
    /// First seen date.
    pub first_seen: Option<String>,
    /// Last seen date.
    pub last_seen: Option<String>,
}

/// The historical finding store — queryable archive of normalized findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalFindingStore {
    /// All normalized findings.
    pub findings: Vec<super::finding::NormalizedFinding>,
    /// Index by vulnerability class.
    pub by_class: std::collections::BTreeMap<String, Vec<String>>,
    /// Index by protocol name.
    pub by_protocol: std::collections::BTreeMap<String, Vec<String>>,
    /// Index by attack technique.
    pub by_technique: std::collections::BTreeMap<String, Vec<String>>,
    /// Index by severity.
    pub by_severity: std::collections::BTreeMap<String, Vec<String>>,
    /// All reasoning patterns.
    pub patterns: Vec<ReasoningPattern>,
}

impl HistoricalFindingStore {
    pub fn empty() -> Self {
        Self {
            findings: vec![],
            by_class: std::collections::BTreeMap::new(),
            by_protocol: std::collections::BTreeMap::new(),
            by_technique: std::collections::BTreeMap::new(),
            by_severity: std::collections::BTreeMap::new(),
            patterns: vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }

    pub fn total_patterns(&self) -> usize {
        self.patterns.len()
    }
}
