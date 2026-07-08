use digger_agent_audit_log::*;

fn valid_event() -> AuditEvent {
    AuditEvent::new(
        "ae-001".into(),
        "hypothesis_created".into(),
        "agent".into(),
        "Formed hypothesis".into(),
    )
}

#[test]
fn test_metadata_contract() {
    let e = valid_event();
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["schema_version"], "digger.agent_audit_log.v1");
    assert_eq!(json["report_kind"], "agent_audit_event");
    assert!(json["digger_version"].as_str().is_some());
}

#[test]
fn test_is_finding_false_invariant() {
    let e = valid_event();
    assert!(!e.is_finding);
    assert_eq!(serde_json::to_value(&e).unwrap()["is_finding"], false);
}

#[test]
fn test_rejects_is_finding_true() {
    let mut e = valid_event();
    e.is_finding = true;
    let errors = validate_audit_event(&e);
    assert!(errors.contains(&AuditEventValidationError::IsFindingTrue));
}

#[test]
fn test_rejects_empty_event_id() {
    let mut e = valid_event();
    e.event_id = "".into();
    assert!(validate_audit_event(&e).contains(&AuditEventValidationError::EmptyEventId));
}

#[test]
fn test_rejects_empty_actor() {
    let mut e = valid_event();
    e.actor = "".into();
    assert!(validate_audit_event(&e).contains(&AuditEventValidationError::EmptyActor));
}

#[test]
fn test_rejects_empty_action_summary() {
    let mut e = valid_event();
    e.action_summary = "".into();
    assert!(validate_audit_event(&e).contains(&AuditEventValidationError::EmptyActionSummary));
}

#[test]
fn test_valid_event_passes() {
    let e = valid_event();
    let errors = validate_audit_event(&e);
    assert!(errors.is_empty(), "valid event should pass: {:?}", errors);
}

#[test]
fn test_no_forbidden_fields() {
    let e = valid_event();
    let json = serde_json::to_value(&e).unwrap();
    assert!(json.get("generated_at").is_none());
    assert!(json.get("severity").is_none());
    assert!(json.get("risk_score").is_none());
    assert!(json.get("vulnerability").is_none());
}

#[test]
fn test_deterministic_serialization() {
    let e1 = valid_event();
    let e2 = valid_event();
    assert_eq!(
        serde_json::to_string(&e1).unwrap(),
        serde_json::to_string(&e2).unwrap()
    );
}
