use digger_agent_proof_task::*;

fn valid_proof_task() -> ProofTask {
    ProofTask::new(
        "pt-001".into(),
        "hyp-001".into(),
        "The withdraw function may lack authority verification".into(),
        vec!["s-001".into()],
        vec!["Digger scan of withdraw function".into()],
        vec!["digger scan".into()],
        vec!["No exploit execution".into()],
        vec!["Authority check presence/absence".into()],
        vec!["validate_assistant_output must pass".into()],
        vec!["Validation failure on any derived claim".into()],
    )
}

#[test]
fn test_metadata_contract() {
    let t = valid_proof_task();
    let json = serde_json::to_value(&t).unwrap();

    assert_eq!(json["schema_version"], "digger.proof_task.v1");
    assert_eq!(json["report_kind"], "proof_task");
    assert!(json["digger_version"].as_str().is_some());
    assert_eq!(json["task_id"], "pt-001");
    assert_eq!(json["hypothesis_id"], "hyp-001");
    assert_eq!(json["status"], "proposed");
}

#[test]
fn test_is_finding_false_invariant() {
    let t = valid_proof_task();
    assert!(!t.is_finding, "is_finding must always be false");

    let json = serde_json::to_value(&t).unwrap();
    assert_eq!(json["is_finding"], false);
}

#[test]
fn test_rejects_is_finding_true() {
    let mut t = valid_proof_task();
    t.is_finding = true;
    let errors = validate_proof_task(&t);
    assert!(errors.contains(&ProofTaskValidationError::IsFindingTrue));
}

#[test]
fn test_rejects_empty_task_id() {
    let mut t = valid_proof_task();
    t.task_id = "".into();
    let errors = validate_proof_task(&t);
    assert!(errors.contains(&ProofTaskValidationError::EmptyTaskId));
}

#[test]
fn test_rejects_empty_hypothesis_id() {
    let mut t = valid_proof_task();
    t.hypothesis_id = "".into();
    let errors = validate_proof_task(&t);
    assert!(errors.contains(&ProofTaskValidationError::EmptyHypothesisId));
}

#[test]
fn test_rejects_missing_target_surfaces() {
    let mut t = valid_proof_task();
    t.target_surfaces = vec![];
    let errors = validate_proof_task(&t);
    assert!(errors.contains(&ProofTaskValidationError::MissingTargetSurfaces));
}

#[test]
fn test_rejects_missing_required_evidence() {
    let mut t = valid_proof_task();
    t.required_evidence = vec![];
    let errors = validate_proof_task(&t);
    assert!(errors.contains(&ProofTaskValidationError::MissingRequiredEvidence));
}

#[test]
fn test_rejects_missing_validation_gates() {
    let mut t = valid_proof_task();
    t.validation_gates = vec![];
    let errors = validate_proof_task(&t);
    assert!(errors.contains(&ProofTaskValidationError::MissingValidationGates));
}

#[test]
fn test_rejects_missing_stop_conditions() {
    let mut t = valid_proof_task();
    t.stop_conditions = vec![];
    let errors = validate_proof_task(&t);
    assert!(errors.contains(&ProofTaskValidationError::MissingStopConditions));
}

#[test]
fn test_ready_task_is_not_finding() {
    let mut t = valid_proof_task();
    t.status = ProofTaskStatus::Ready;
    assert!(!t.is_finding, "ready task must not be a finding");

    let json = serde_json::to_value(&t).unwrap();
    assert_eq!(json["status"], "ready");
    assert_eq!(json["is_finding"], false);
}

#[test]
fn test_json_no_severity_risk_finding_fields() {
    let t = valid_proof_task();
    let json = serde_json::to_value(&t).unwrap();

    assert!(json.get("severity").is_none());
    assert!(json.get("risk_score").is_none());
    assert!(json.get("vulnerability").is_none());
    assert!(json.get("finding").is_none());
    assert!(json.get("exploit").is_none());
    assert!(json.get("confidence_ceiling").is_none());
    assert!(json.get("generated_at").is_none());
}

#[test]
fn test_deterministic_serialization() {
    let t1 = valid_proof_task();
    let t2 = valid_proof_task();
    let json1 = serde_json::to_string(&t1).unwrap();
    let json2 = serde_json::to_string(&t2).unwrap();
    assert_eq!(json1, json2, "serialization must be deterministic");
}
