use serde::{Deserialize, Serialize};

/// Agent-facing hypothesis — a testable claim about a potential issue.
///
/// Hypotheses are NOT findings. They are structured speculation that
/// requires evidence before any evaluation. Every hypothesis carries
/// `is_finding: false` as an invariant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hypothesis {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub hypothesis_id: String,
    pub source_surfaces: Vec<String>,
    pub claim: String,
    pub evidence_required: Vec<String>,
    pub disproof_conditions: Vec<String>,
    pub status: HypothesisStatus,
    pub confidence: Confidence,
    pub evidence_collected: Vec<EvidenceRef>,
    pub is_finding: bool,
}

impl Hypothesis {
    /// Create a new hypothesis with default metadata.
    pub fn new(
        hypothesis_id: String,
        claim: String,
        source_surfaces: Vec<String>,
        evidence_required: Vec<String>,
        disproof_conditions: Vec<String>,
    ) -> Self {
        Self {
            schema_version: "digger.hypothesis.v1".into(),
            digger_version: env!("CARGO_PKG_VERSION").into(),
            report_kind: "hypothesis".into(),
            hypothesis_id,
            source_surfaces,
            claim,
            evidence_required,
            disproof_conditions,
            status: HypothesisStatus::Proposed,
            confidence: Confidence {
                level: ConfidenceLevel::Low,
                reason: "hypothesis only; no proof task executed".into(),
            },
            evidence_collected: Vec::new(),
            is_finding: false,
        }
    }
}

/// Lifecycle status of a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    /// Initial state; claim formulated, no evidence gathered.
    Proposed,
    /// Evidence gathering in progress.
    NeedsEvidence,
    /// Cannot proceed (missing data, external dependency).
    Blocked,
    /// Disproof condition met; hypothesis invalidated.
    Rejected,
    /// Validated and ready for MY.3 proof task generation.
    ReadyForProofTask,
}

/// Confidence assessment for a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Confidence {
    pub level: ConfidenceLevel,
    pub reason: String,
}

/// Confidence levels for hypotheses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    /// Default for new hypotheses.
    Low,
    /// After evidence gathered, not yet validated.
    Medium,
    /// Strong evidence, awaiting proof task execution.
    High,
}

/// A reference to evidence that has been collected for a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRef {
    pub source: String,
    pub description: String,
    pub timestamp: Option<String>,
}
