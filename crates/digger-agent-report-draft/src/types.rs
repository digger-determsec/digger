use serde::{Deserialize, Serialize};

/// An assistant report draft — an evidence-bound summary, NOT a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistantReportDraft {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub draft_id: String,
    pub source_evidence_runs: Vec<String>,
    pub source_proof_tasks: Vec<String>,
    pub summary: String,
    pub evidence_citations: Vec<EvidenceCitation>,
    pub limitations: Vec<String>,
    pub validation_failures: Vec<String>,
    pub unresolved_questions: Vec<String>,
    pub is_finding: bool,
}

impl AssistantReportDraft {
    pub fn new(
        draft_id: String,
        summary: String,
        evidence_citations: Vec<EvidenceCitation>,
    ) -> Self {
        Self {
            schema_version: "digger.report_draft.v1".into(),
            digger_version: env!("CARGO_PKG_VERSION").into(),
            report_kind: "report_draft".into(),
            draft_id,
            source_evidence_runs: Vec::new(),
            source_proof_tasks: Vec::new(),
            summary,
            evidence_citations,
            limitations: Vec::new(),
            validation_failures: Vec::new(),
            unresolved_questions: Vec::new(),
            is_finding: false,
        }
    }
}

/// A citation linking a claim to specific evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceCitation {
    pub evidence_run_id: String,
    pub command_id: Option<String>,
    pub artifact_id: Option<String>,
    pub output_id: Option<String>,
    pub quote_or_summary: String,
    pub supports_claim: bool,
}
