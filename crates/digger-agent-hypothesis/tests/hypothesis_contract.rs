use digger_agent_hypothesis::*;

fn valid_hypothesis() -> Hypothesis {
    Hypothesis::new(
        "hyp-001".into(),
        "The withdraw function may lack authority verification".into(),
        vec!["s-001".into()],
        vec!["Source code review of withdraw function".into()],
        vec!["Authority check found in withdraw or callers".into()],
    )
}

#[test]
fn test_schema_metadata_contract() {
    let h = valid_hypothesis();
    let json = serde_json::to_value(&h).unwrap();

    assert_eq!(json["schema_version"], "digger.hypothesis.v1");
    assert_eq!(json["report_kind"], "hypothesis");
    assert!(json["digger_version"].as_str().is_some());
    assert_eq!(json["hypothesis_id"], "hyp-001");
    assert_eq!(json["status"], "proposed");
    assert!(json["confidence"].is_object());
    assert_eq!(json["confidence"]["level"], "low");
}

#[test]
fn test_is_finding_false_invariant() {
    let h = valid_hypothesis();
    assert!(!h.is_finding, "is_finding must always be false");

    let json = serde_json::to_value(&h).unwrap();
    assert_eq!(json["is_finding"], false);
}

#[test]
fn test_validation_rejects_empty_claim() {
    let mut h = valid_hypothesis();
    h.claim = "".into();
    let errors = validate(&h);
    assert!(errors.contains(&ValidationError::EmptyClaim));
}

#[test]
fn test_validation_rejects_missing_evidence_requirements() {
    let mut h = valid_hypothesis();
    h.evidence_required = vec![];
    let errors = validate(&h);
    assert!(errors.contains(&ValidationError::MissingEvidenceRequirements));
}

#[test]
fn test_validation_rejects_missing_disproof_conditions() {
    let mut h = valid_hypothesis();
    h.disproof_conditions = vec![];
    let errors = validate(&h);
    assert!(errors.contains(&ValidationError::MissingDisproofConditions));
}

#[test]
fn test_validation_rejects_empty_confidence_reason() {
    let mut h = valid_hypothesis();
    h.confidence.reason = "".into();
    let errors = validate(&h);
    assert!(errors.contains(&ValidationError::EmptyConfidenceReason));
}

#[test]
fn test_validation_rejects_is_finding_true() {
    let mut h = valid_hypothesis();
    h.is_finding = true;
    let errors = validate(&h);
    assert!(errors.contains(&ValidationError::IsFindingTrue));
}

#[test]
fn test_valid_hypothesis_passes_validation() {
    let h = valid_hypothesis();
    let errors = validate(&h);
    assert!(
        errors.is_empty(),
        "valid hypothesis should pass: {:?}",
        errors
    );
}

#[test]
fn test_json_contains_no_severity_risk_finding_fields() {
    let h = valid_hypothesis();
    let json = serde_json::to_value(&h).unwrap();

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
    let h1 = valid_hypothesis();
    let h2 = valid_hypothesis();
    let json1 = serde_json::to_string(&h1).unwrap();
    let json2 = serde_json::to_string(&h2).unwrap();
    assert_eq!(json1, json2, "serialization must be deterministic");
}

#[test]
fn test_status_lifecycle() {
    let mut h = valid_hypothesis();
    assert_eq!(h.status, HypothesisStatus::Proposed);

    h.status = HypothesisStatus::NeedsEvidence;
    assert_eq!(h.status, HypothesisStatus::NeedsEvidence);

    h.status = HypothesisStatus::ReadyForProofTask;
    assert_eq!(h.status, HypothesisStatus::ReadyForProofTask);
    assert!(!h.is_finding, "ready_for_proof_task must not be a finding");
}
