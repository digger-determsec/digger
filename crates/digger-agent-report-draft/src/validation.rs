use crate::types::AssistantReportDraft;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportDraftValidationError {
    EmptyDraftId,
    EmptySummary,
    MissingEvidenceCitations,
    IsFindingTrue,
}

impl std::fmt::Display for ReportDraftValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyDraftId => write!(f, "draft_id must be non-empty"),
            Self::EmptySummary => write!(f, "summary must be non-empty"),
            Self::MissingEvidenceCitations => {
                write!(f, "evidence_citations must have at least one entry")
            }
            Self::IsFindingTrue => write!(f, "is_finding must be false"),
        }
    }
}

impl std::error::Error for ReportDraftValidationError {}

pub fn validate_report_draft(draft: &AssistantReportDraft) -> Vec<ReportDraftValidationError> {
    let mut errors = Vec::new();
    if draft.draft_id.trim().is_empty() {
        errors.push(ReportDraftValidationError::EmptyDraftId);
    }
    if draft.summary.trim().is_empty() {
        errors.push(ReportDraftValidationError::EmptySummary);
    }
    if draft.evidence_citations.is_empty() {
        errors.push(ReportDraftValidationError::MissingEvidenceCitations);
    }
    if draft.is_finding {
        errors.push(ReportDraftValidationError::IsFindingTrue);
    }
    errors
}
