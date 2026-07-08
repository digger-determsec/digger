use crate::types::ProofTask;

/// Validation error for proof task contract violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofTaskValidationError {
    EmptyTaskId,
    EmptyHypothesisId,
    EmptyClaim,
    MissingTargetSurfaces,
    MissingRequiredEvidence,
    MissingAllowedTools,
    MissingForbiddenActions,
    MissingExpectedOutputs,
    MissingValidationGates,
    MissingStopConditions,
    IsFindingTrue,
    EmptySchemaVersion,
    EmptyReportKind,
    EmptyDiggerVersion,
}

impl std::fmt::Display for ProofTaskValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTaskId => write!(f, "task_id must be non-empty"),
            Self::EmptyHypothesisId => write!(f, "hypothesis_id must be non-empty"),
            Self::EmptyClaim => write!(f, "claim must be non-empty"),
            Self::MissingTargetSurfaces => {
                write!(f, "target_surfaces must have at least one entry")
            }
            Self::MissingRequiredEvidence => {
                write!(f, "required_evidence must have at least one entry")
            }
            Self::MissingAllowedTools => write!(f, "allowed_tools must have at least one entry"),
            Self::MissingForbiddenActions => {
                write!(f, "forbidden_actions must have at least one entry")
            }
            Self::MissingExpectedOutputs => {
                write!(f, "expected_outputs must have at least one entry")
            }
            Self::MissingValidationGates => {
                write!(f, "validation_gates must have at least one entry")
            }
            Self::MissingStopConditions => {
                write!(f, "stop_conditions must have at least one entry")
            }
            Self::IsFindingTrue => write!(f, "is_finding must be false"),
            Self::EmptySchemaVersion => write!(f, "schema_version must be present"),
            Self::EmptyReportKind => write!(f, "report_kind must be present"),
            Self::EmptyDiggerVersion => write!(f, "digger_version must be present"),
        }
    }
}

impl std::error::Error for ProofTaskValidationError {}

/// Validate a proof task against the contract rules.
pub fn validate_proof_task(task: &ProofTask) -> Vec<ProofTaskValidationError> {
    let mut errors = Vec::new();

    if task.schema_version.is_empty() {
        errors.push(ProofTaskValidationError::EmptySchemaVersion);
    }

    if task.report_kind.is_empty() {
        errors.push(ProofTaskValidationError::EmptyReportKind);
    }

    if task.digger_version.is_empty() {
        errors.push(ProofTaskValidationError::EmptyDiggerVersion);
    }

    if task.task_id.trim().is_empty() {
        errors.push(ProofTaskValidationError::EmptyTaskId);
    }

    if task.hypothesis_id.trim().is_empty() {
        errors.push(ProofTaskValidationError::EmptyHypothesisId);
    }

    if task.claim.trim().is_empty() {
        errors.push(ProofTaskValidationError::EmptyClaim);
    }

    if task.target_surfaces.is_empty() {
        errors.push(ProofTaskValidationError::MissingTargetSurfaces);
    }

    if task.required_evidence.is_empty() {
        errors.push(ProofTaskValidationError::MissingRequiredEvidence);
    }

    if task.allowed_tools.is_empty() {
        errors.push(ProofTaskValidationError::MissingAllowedTools);
    }

    if task.forbidden_actions.is_empty() {
        errors.push(ProofTaskValidationError::MissingForbiddenActions);
    }

    if task.expected_outputs.is_empty() {
        errors.push(ProofTaskValidationError::MissingExpectedOutputs);
    }

    if task.validation_gates.is_empty() {
        errors.push(ProofTaskValidationError::MissingValidationGates);
    }

    if task.stop_conditions.is_empty() {
        errors.push(ProofTaskValidationError::MissingStopConditions);
    }

    if task.is_finding {
        errors.push(ProofTaskValidationError::IsFindingTrue);
    }

    errors
}
