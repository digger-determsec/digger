use serde::{Deserialize, Serialize};

/// An audit event — a record of agent activity in the MY-Digger flow.
///
/// AuditEvents are NOT findings. They are activity records for reviewability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub event_id: String,
    pub event_type: String,
    pub actor: String,
    pub input_refs: Vec<String>,
    pub output_refs: Vec<String>,
    pub action_summary: String,
    pub approval_required: bool,
    pub approval_status: String,
    pub policy_decision: String,
    pub is_mutating: bool,
    pub is_finding: bool,
}

impl AuditEvent {
    pub fn new(
        event_id: String,
        event_type: String,
        actor: String,
        action_summary: String,
    ) -> Self {
        Self {
            schema_version: "digger.agent_audit_log.v1".into(),
            digger_version: env!("CARGO_PKG_VERSION").into(),
            report_kind: "agent_audit_event".into(),
            event_id,
            event_type,
            actor,
            input_refs: Vec::new(),
            output_refs: Vec::new(),
            action_summary,
            approval_required: false,
            approval_status: "not_required".into(),
            policy_decision: "allowed".into(),
            is_mutating: false,
            is_finding: false,
        }
    }
}
