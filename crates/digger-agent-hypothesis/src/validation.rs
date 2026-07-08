use crate::types::Hypothesis;

/// Validation error for hypothesis contract violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    EmptyClaim,
    MissingEvidenceRequirements,
    MissingDisproofConditions,
    InvalidStatus { status: String },
    EmptyConfidenceReason,
    IsFindingTrue,
    MissingSchemaVersion,
    MissingReportKind,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyClaim => write!(f, "claim must be non-empty"),
            Self::MissingEvidenceRequirements => {
                write!(f, "evidence_required must have at least one entry")
            }
            Self::MissingDisproofConditions => {
                write!(f, "disproof_conditions must have at least one entry")
            }
            Self::InvalidStatus { status } => {
                write!(f, "invalid status: '{}'", status)
            }
            Self::EmptyConfidenceReason => write!(f, "confidence.reason must be non-empty"),
            Self::IsFindingTrue => write!(f, "is_finding must be false"),
            Self::MissingSchemaVersion => write!(f, "schema_version must be present"),
            Self::MissingReportKind => write!(f, "report_kind must be present"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate a hypothesis against the contract rules.
pub fn validate(h: &Hypothesis) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if h.schema_version.is_empty() {
        errors.push(ValidationError::MissingSchemaVersion);
    }

    if h.report_kind.is_empty() {
        errors.push(ValidationError::MissingReportKind);
    }

    if h.claim.trim().is_empty() {
        errors.push(ValidationError::EmptyClaim);
    }

    if h.evidence_required.is_empty() {
        errors.push(ValidationError::MissingEvidenceRequirements);
    }

    if h.disproof_conditions.is_empty() {
        errors.push(ValidationError::MissingDisproofConditions);
    }

    if h.confidence.reason.trim().is_empty() {
        errors.push(ValidationError::EmptyConfidenceReason);
    }

    if h.is_finding {
        errors.push(ValidationError::IsFindingTrue);
    }

    errors
}
