use digger_agent_evidence_run::*;

fn valid_level0() -> EvidenceRun {
    let mut run = EvidenceRun::new("er-001".into(), "pt-001".into(), "hyp-001".into());
    run.validation_results = vec![ValidationResult {
        gate: "schema_check".into(),
        status: "passed".into(),
        message: "schema valid".into(),
        blocks_promotion: false,
    }];
    run
}

#[test]
fn test_metadata_contract() {
    let r = valid_level0();
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["schema_version"], "digger.evidence_run.v1");
    assert_eq!(json["report_kind"], "evidence_run");
    assert!(json["digger_version"].as_str().is_some());
    assert_eq!(json["evidence_run_id"], "er-001");
    assert_eq!(json["proof_task_id"], "pt-001");
    assert_eq!(json["hypothesis_id"], "hyp-001");
}

#[test]
fn test_is_finding_false_invariant() {
    let r = valid_level0();
    assert!(!r.is_finding);
    assert_eq!(serde_json::to_value(&r).unwrap()["is_finding"], false);
}

#[test]
fn test_rejects_is_finding_true() {
    let mut r = valid_level0();
    r.is_finding = true;
    let errors = validate_evidence_run(&r);
    assert!(errors.contains(&EvidenceRunValidationError::IsFindingTrue));
}

#[test]
fn test_level0_validates_with_empty_collections() {
    let r = valid_level0();
    let errors = validate_evidence_run(&r);
    assert!(errors.is_empty(), "Level 0 should validate: {:?}", errors);
}

#[test]
fn test_rejects_empty_evidence_run_id() {
    let mut r = valid_level0();
    r.evidence_run_id = "".into();
    assert!(validate_evidence_run(&r).contains(&EvidenceRunValidationError::EmptyEvidenceRunId));
}

#[test]
fn test_rejects_empty_proof_task_id() {
    let mut r = valid_level0();
    r.proof_task_id = "".into();
    assert!(validate_evidence_run(&r).contains(&EvidenceRunValidationError::EmptyProofTaskId));
}

#[test]
fn test_rejects_empty_hypothesis_id() {
    let mut r = valid_level0();
    r.hypothesis_id = "".into();
    assert!(validate_evidence_run(&r).contains(&EvidenceRunValidationError::EmptyHypothesisId));
}

#[test]
fn test_rejects_missing_validation_results() {
    let mut r = valid_level0();
    r.validation_results = vec![];
    assert!(
        validate_evidence_run(&r).contains(&EvidenceRunValidationError::MissingValidationResults)
    );
}

#[test]
fn test_command_record_validation() {
    let mut r = valid_level0();
    r.command_log = vec![CommandRecord {
        command_id: "".into(),
        tool: "digger scan".into(),
        args_redacted: vec![],
        exit_code: Some(0),
        stdout_ref: None,
        stderr_ref: None,
        policy_level: "read_only".into(),
    }];
    let errors = validate_evidence_run(&r);
    assert!(errors.contains(&EvidenceRunValidationError::EmptyCommandId { index: 0 }));
}

#[test]
fn test_raw_output_validation() {
    let mut r = valid_level0();
    r.raw_outputs = vec![RawOutputRef {
        output_id: "out-001".into(),
        stream: "invalid_stream".into(),
        path_or_inline_ref: "/tmp/output".into(),
        truncated: false,
    }];
    let errors = validate_evidence_run(&r);
    assert!(errors
        .iter()
        .any(|e| matches!(e, EvidenceRunValidationError::InvalidOutputStream { .. })));
}

#[test]
fn test_stop_condition_validation() {
    let mut r = valid_level0();
    r.stop_condition_triggered = Some(StopConditionRecord {
        condition: "".into(),
        triggered: true,
        reason: "validation failed".into(),
    });
    let errors = validate_evidence_run(&r);
    assert!(errors
        .iter()
        .any(|e| matches!(e, EvidenceRunValidationError::EmptyStopCondition { .. })));
}

#[test]
fn test_validation_failure_blocks_promotion() {
    let mut r = valid_level0();
    r.validation_results = vec![ValidationResult {
        gate: "evidence_check".into(),
        status: "failed".into(),
        message: "missing evidence".into(),
        blocks_promotion: true,
    }];
    let errors = validate_evidence_run(&r);
    assert!(
        errors.is_empty(),
        "failed validation with blocks_promotion is valid: {:?}",
        errors
    );
    assert!(!r.is_finding, "failed validation must not become a finding");
}

#[test]
fn test_json_no_forbidden_fields() {
    let r = valid_level0();
    let json = serde_json::to_value(&r).unwrap();
    assert!(json.get("generated_at").is_none());
    assert!(json.get("severity").is_none());
    assert!(json.get("risk_score").is_none());
    assert!(json.get("vulnerability").is_none());
    assert!(json.get("exploit").is_none());
}

#[test]
fn test_deterministic_serialization() {
    let r1 = valid_level0();
    let r2 = valid_level0();
    assert_eq!(
        serde_json::to_string(&r1).unwrap(),
        serde_json::to_string(&r2).unwrap()
    );
}

#[test]
fn test_level0_from_proof_task() {
    use digger_agent_proof_task::types::ProofTask;

    let pt = ProofTask::new(
        "pt-001".into(),
        "hyp-001".into(),
        "withdraw lacks authority".into(),
        vec!["s-001".into()],
        vec!["scan result".into()],
        vec!["digger scan".into()],
        vec!["no exploit execution".into()],
        vec!["authority check".into()],
        vec!["validate passes".into()],
        vec!["validation failure stops".into()],
    );

    let run = plan_level0_evidence_run("er-001".into(), &pt);

    assert_eq!(run.schema_version, "digger.evidence_run.v1");
    assert_eq!(run.proof_task_id, "pt-001");
    assert_eq!(run.hypothesis_id, "hyp-001");
    assert!(run.command_log.is_empty());
    assert!(run.raw_outputs.is_empty());
    assert!(run.artifacts.is_empty());
    assert_eq!(run.validation_results.len(), 1);
    assert_eq!(run.validation_results[0].gate, "level_0_planning_only");
    assert!(!run.is_finding);
    assert!(run.stop_condition_triggered.is_none());
}

#[test]
fn test_level0_validates() {
    use digger_agent_proof_task::types::ProofTask;

    let pt = ProofTask::new(
        "pt-002".into(),
        "hyp-002".into(),
        "test claim".into(),
        vec!["s-002".into()],
        vec!["review".into()],
        vec!["digger scan".into()],
        vec!["no exploit".into()],
        vec!["check".into()],
        vec!["validate".into()],
        vec!["stop on failure".into()],
    );

    let run = plan_level0_evidence_run("er-002".into(), &pt);
    let errors = validate_evidence_run(&run);
    assert!(errors.is_empty(), "Level 0 should validate: {:?}", errors);
}

#[test]
fn test_level0_ids_match_proof_task() {
    use digger_agent_proof_task::types::ProofTask;

    let pt = ProofTask::new(
        "pt-999".into(),
        "hyp-999".into(),
        "test".into(),
        vec!["s-999".into()],
        vec!["review".into()],
        vec!["digger scan".into()],
        vec!["no exploit".into()],
        vec!["check".into()],
        vec!["validate".into()],
        vec!["stop".into()],
    );

    let run = plan_level0_evidence_run("er-999".into(), &pt);
    assert_eq!(run.evidence_run_id, "er-999");
    assert_eq!(run.proof_task_id, "pt-999");
    assert_eq!(run.hypothesis_id, "hyp-999");
}

#[test]
fn test_level0_no_forbidden_fields() {
    use digger_agent_proof_task::types::ProofTask;

    let pt = ProofTask::new(
        "pt-100".into(),
        "hyp-100".into(),
        "test".into(),
        vec!["s-100".into()],
        vec!["r".into()],
        vec!["digger scan".into()],
        vec!["no exploit".into()],
        vec!["c".into()],
        vec!["v".into()],
        vec!["s".into()],
    );

    let run = plan_level0_evidence_run("er-100".into(), &pt);
    let json = serde_json::to_value(&run).unwrap();
    assert!(json.get("generated_at").is_none());
    assert!(json.get("severity").is_none());
    assert!(json.get("risk_score").is_none());
    assert!(json.get("vulnerability").is_none());
    assert!(json.get("exploit").is_none());
    assert_eq!(json["is_finding"], false);
}
