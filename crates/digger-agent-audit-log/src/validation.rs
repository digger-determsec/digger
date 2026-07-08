use crate::types::AuditEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventValidationError {
    EmptyEventId,
    EmptyEventType,
    EmptyActor,
    EmptyActionSummary,
    IsFindingTrue,
}

impl std::fmt::Display for AuditEventValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyEventId => write!(f, "event_id must be non-empty"),
            Self::EmptyEventType => write!(f, "event_type must be non-empty"),
            Self::EmptyActor => write!(f, "actor must be non-empty"),
            Self::EmptyActionSummary => write!(f, "action_summary must be non-empty"),
            Self::IsFindingTrue => write!(f, "is_finding must be false"),
        }
    }
}

impl std::error::Error for AuditEventValidationError {}

pub fn validate_audit_event(event: &AuditEvent) -> Vec<AuditEventValidationError> {
    let mut errors = Vec::new();
    if event.event_id.trim().is_empty() {
        errors.push(AuditEventValidationError::EmptyEventId);
    }
    if event.event_type.trim().is_empty() {
        errors.push(AuditEventValidationError::EmptyEventType);
    }
    if event.actor.trim().is_empty() {
        errors.push(AuditEventValidationError::EmptyActor);
    }
    if event.action_summary.trim().is_empty() {
        errors.push(AuditEventValidationError::EmptyActionSummary);
    }
    if event.is_finding {
        errors.push(AuditEventValidationError::IsFindingTrue);
    }
    errors
}
