/// Knowledge graph — connects protocols, findings, patterns, and invariants.
use serde::{Deserialize, Serialize};

/// The knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeGraph {
    pub nodes: Vec<KnowledgeNode>,
    pub edges: Vec<KnowledgeEdge>,
}

impl KnowledgeGraph {
    pub fn empty() -> Self {
        Self {
            nodes: vec![],
            edges: vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// A node in the knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KnowledgeNode {
    Protocol(ProtocolNode),
    Finding(FindingNode),
    VulnerabilityClass(VulnerabilityClassNode),
    AttackTechnique(AttackTechniqueNode),
    MitigationPattern(MitigationPatternNode),
    SecurityInvariant(SecurityInvariantNode),
    ArchitecturalPattern(ArchitecturalPatternNode),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolNode {
    pub protocol_id: String,
    pub name: String,
    pub category: String,
    pub audit_count: usize,
    pub total_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingNode {
    pub finding_id: String,
    pub report_id: String,
    pub protocol_id: String,
    pub vulnerability_class: String,
    pub severity: digger_ir::Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilityClassNode {
    pub class: String,
    pub occurrence_count: usize,
    pub affected_protocols: Vec<String>,
    pub typical_severity: digger_ir::Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackTechniqueNode {
    pub technique: String,
    pub used_in_findings: Vec<String>,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MitigationPatternNode {
    pub technique: String,
    pub effective_against: Vec<String>,
    pub adoption_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityInvariantNode {
    pub invariant: String,
    pub kind: String,
    pub violated_by: Vec<String>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArchitecturalPatternNode {
    pub pattern: String,
    pub category: String,
    pub common_vulnerabilities: Vec<String>,
    pub protocols: Vec<String>,
}

/// An edge in the knowledge graph.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KnowledgeEdge {
    HasFinding {
        protocol_id: String,
        finding_id: String,
    },
    ClassifiedAs {
        finding_id: String,
        class: String,
    },
    UsesTechnique {
        finding_id: String,
        technique: String,
    },
    MitigatedBy {
        finding_id: String,
        pattern: String,
    },
    MitigatedByPattern {
        class: String,
        pattern: String,
    },
    ViolatesInvariant {
        class: String,
        invariant: String,
    },
    RequiresCapability {
        technique: String,
        capability: String,
    },
    UsesArchitecture {
        protocol_id: String,
        pattern: String,
    },
    SemanticallyEquivalent {
        finding_a: String,
        finding_b: String,
    },
    Generalizes {
        specific: String,
        general: String,
    },
}
