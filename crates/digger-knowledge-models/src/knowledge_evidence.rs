/// KnowledgeEvidence — the bridge between the knowledge pipeline and the reasoning engine.
///
/// KnowledgeEvidence is a first-class semantic primitive that represents
/// any piece of external security knowledge that can serve as supporting
/// evidence for the reasoning engine.
///
/// The reasoning engine consumes KnowledgeEvidence through its EvidenceGraph.
/// Structural reasoning remains the primary source of truth.
/// Knowledge evidence provides supporting context, explanation, prioritization,
/// and retrieval only.
use serde::{Deserialize, Serialize};

/// A piece of knowledge evidence — consumed by the reasoning engine's EvidenceGraph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeEvidence {
    /// Evidence identifier (deterministic).
    pub evidence_id: String,
    /// The kind of knowledge evidence.
    pub kind: KnowledgeEvidenceKind,
    /// Human-readable description.
    pub description: String,
    /// Confidence metadata (informational only — never overrides structural confidence).
    pub confidence: KnowledgeConfidence,
    /// Source repository.
    pub source: String,
    /// Related finding IDs.
    pub related_findings: Vec<String>,
}

/// Kind of knowledge evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KnowledgeEvidenceKind {
    HistoricalFinding(HistoricalFindingEvidence),
    ReasoningPattern(ReasoningPatternEvidence),
    SimilarProtocol(SimilarProtocolEvidence),
    ArchitecturePattern(ArchitecturePatternEvidence),
    MitigationPattern(MitigationPatternEvidence),
    FormalProof(FormalProofEvidence),
    AcademicReference(AcademicReferenceEvidence),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalFindingEvidence {
    pub finding_id: String,
    pub protocol_name: String,
    pub vulnerability_class: String,
    pub attack_goal: String,
    pub root_cause: String,
    pub severity: digger_ir::Severity,
    pub impacted_functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReasoningPatternEvidence {
    pub pattern_id: String,
    pub name: String,
    pub vulnerability_class: String,
    pub required_capabilities: Vec<String>,
    pub structural_indicators: Vec<String>,
    pub support_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimilarProtocolEvidence {
    pub protocol_name: String,
    pub category: String,
    pub finding_count: usize,
    pub shared_vulnerability_classes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchitecturePatternEvidence {
    pub pattern: String,
    pub category: String,
    pub common_vulnerabilities: Vec<String>,
    pub protocol_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MitigationPatternEvidence {
    pub technique: String,
    pub effective_against: Vec<String>,
    pub is_standard: bool,
    pub adoption_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormalProofEvidence {
    pub property: String,
    pub status: String,
    pub backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcademicReferenceEvidence {
    pub title: String,
    pub authors: Vec<String>,
    pub relevance: String,
}

/// Confidence metadata for knowledge evidence.
///
/// This is informational only. It must never modify or override
/// structural confidence produced by the reasoning engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeConfidence {
    /// Number of historical findings supporting this evidence.
    pub support_count: usize,
    /// Confidence level: "established", "observed", "speculative".
    pub confidence_level: String,
    /// First seen date (ISO format).
    pub first_seen: Option<String>,
    /// Last seen date (ISO format).
    pub last_seen: Option<String>,
    /// Contributing source repositories.
    pub contributing_sources: Vec<String>,
}

impl KnowledgeConfidence {
    pub fn single_finding(source: &str) -> Self {
        Self {
            support_count: 1,
            confidence_level: "observed".into(),
            first_seen: None,
            last_seen: None,
            contributing_sources: vec![source.into()],
        }
    }

    pub fn established(count: usize, sources: Vec<String>) -> Self {
        Self {
            support_count: count,
            confidence_level: if count >= 5 {
                "established"
            } else {
                "observed"
            }
            .into(),
            first_seen: None,
            last_seen: None,
            contributing_sources: sources,
        }
    }
}
