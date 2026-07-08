use crate::types::EvidenceRun;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceRunValidationError {
    EmptySchemaVersion,
    EmptyReportKind,
    EmptyDiggerVersion,
    EmptyEvidenceRunId,
    EmptyProofTaskId,
    EmptyHypothesisId,
    IsFindingTrue,
    MissingValidationResults,
    EmptyValidationGate { index: usize },
    EmptyValidationStatus { index: usize },
    EmptyValidationMessage { index: usize },
    EmptyCommandId { index: usize },
    EmptyCommandTool { index: usize },
    EmptyCommandPolicyLevel { index: usize },
    InvalidOutputStream { index: usize, value: String },
    EmptyOutputRef { index: usize },
    EmptyArtifactId { index: usize },
    EmptyArtifactPath { index: usize },
    EmptyArtifactKind { index: usize },
    EmptyStopCondition { field: String },
}

impl std::fmt::Display for EvidenceRunValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySchemaVersion => write!(f, "schema_version must be present"),
            Self::EmptyReportKind => write!(f, "report_kind must be present"),
            Self::EmptyDiggerVersion => write!(f, "digger_version must be present"),
            Self::EmptyEvidenceRunId => write!(f, "evidence_run_id must be non-empty"),
            Self::EmptyProofTaskId => write!(f, "proof_task_id must be non-empty"),
            Self::EmptyHypothesisId => write!(f, "hypothesis_id must be non-empty"),
            Self::IsFindingTrue => write!(f, "is_finding must be false"),
            Self::MissingValidationResults => {
                write!(f, "validation_results must have at least one entry")
            }
            Self::EmptyValidationGate { index } => {
                write!(f, "validation_results[{}].gate must be non-empty", index)
            }
            Self::EmptyValidationStatus { index } => {
                write!(f, "validation_results[{}].status must be non-empty", index)
            }
            Self::EmptyValidationMessage { index } => {
                write!(f, "validation_results[{}].message must be non-empty", index)
            }
            Self::EmptyCommandId { index } => {
                write!(f, "command_log[{}].command_id must be non-empty", index)
            }
            Self::EmptyCommandTool { index } => {
                write!(f, "command_log[{}].tool must be non-empty", index)
            }
            Self::EmptyCommandPolicyLevel { index } => {
                write!(f, "command_log[{}].policy_level must be non-empty", index)
            }
            Self::InvalidOutputStream { index, value } => {
                write!(
                    f,
                    "raw_outputs[{}].stream must be stdout, stderr, or artifact; got '{}'",
                    index, value
                )
            }
            Self::EmptyOutputRef { index } => {
                write!(
                    f,
                    "raw_outputs[{}].path_or_inline_ref must be non-empty",
                    index
                )
            }
            Self::EmptyArtifactId { index } => {
                write!(f, "artifacts[{}].artifact_id must be non-empty", index)
            }
            Self::EmptyArtifactPath { index } => {
                write!(f, "artifacts[{}].path must be non-empty", index)
            }
            Self::EmptyArtifactKind { index } => {
                write!(f, "artifacts[{}].kind must be non-empty", index)
            }
            Self::EmptyStopCondition { field } => {
                write!(f, "stop_condition_triggered.{} must be non-empty", field)
            }
        }
    }
}

impl std::error::Error for EvidenceRunValidationError {}

pub fn validate_evidence_run(run: &EvidenceRun) -> Vec<EvidenceRunValidationError> {
    let mut errors = Vec::new();

    if run.schema_version.is_empty() {
        errors.push(EvidenceRunValidationError::EmptySchemaVersion);
    }
    if run.report_kind.is_empty() {
        errors.push(EvidenceRunValidationError::EmptyReportKind);
    }
    if run.digger_version.is_empty() {
        errors.push(EvidenceRunValidationError::EmptyDiggerVersion);
    }
    if run.evidence_run_id.trim().is_empty() {
        errors.push(EvidenceRunValidationError::EmptyEvidenceRunId);
    }
    if run.proof_task_id.trim().is_empty() {
        errors.push(EvidenceRunValidationError::EmptyProofTaskId);
    }
    if run.hypothesis_id.trim().is_empty() {
        errors.push(EvidenceRunValidationError::EmptyHypothesisId);
    }
    if run.is_finding {
        errors.push(EvidenceRunValidationError::IsFindingTrue);
    }
    if run.validation_results.is_empty() {
        errors.push(EvidenceRunValidationError::MissingValidationResults);
    }

    for (i, vr) in run.validation_results.iter().enumerate() {
        if vr.gate.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyValidationGate { index: i });
        }
        if vr.status.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyValidationStatus { index: i });
        }
        if vr.message.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyValidationMessage { index: i });
        }
    }

    for (i, cmd) in run.command_log.iter().enumerate() {
        if cmd.command_id.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyCommandId { index: i });
        }
        if cmd.tool.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyCommandTool { index: i });
        }
        if cmd.policy_level.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyCommandPolicyLevel { index: i });
        }
    }

    for (i, out) in run.raw_outputs.iter().enumerate() {
        let stream = out.stream.as_str();
        if stream != "stdout" && stream != "stderr" && stream != "artifact" {
            errors.push(EvidenceRunValidationError::InvalidOutputStream {
                index: i,
                value: stream.to_string(),
            });
        }
        if out.path_or_inline_ref.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyOutputRef { index: i });
        }
    }

    for (i, art) in run.artifacts.iter().enumerate() {
        if art.artifact_id.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyArtifactId { index: i });
        }
        if art.path.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyArtifactPath { index: i });
        }
        if art.kind.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyArtifactKind { index: i });
        }
    }

    if let Some(ref sc) = run.stop_condition_triggered {
        if sc.condition.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyStopCondition {
                field: "condition".into(),
            });
        }
        if sc.reason.trim().is_empty() {
            errors.push(EvidenceRunValidationError::EmptyStopCondition {
                field: "reason".into(),
            });
        }
    }

    errors
}
