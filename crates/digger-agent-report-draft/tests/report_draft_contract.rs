use digger_agent_report_draft::*;

fn valid_draft() -> AssistantReportDraft {
    AssistantReportDraft::new(
        "ard-001".into(),
        "Summary of findings with evidence".into(),
        vec![EvidenceCitation {
            evidence_run_id: "er-001".into(),
            command_id: None,
            artifact_id: None,
            output_id: None,
            quote_or_summary: "authority check absent".into(),
            supports_claim: true,
        }],
    )
}

#[test]
fn test_metadata_contract() {
    let d = valid_draft();
    let json = serde_json::to_value(&d).unwrap();
    assert_eq!(json["schema_version"], "digger.report_draft.v1");
    assert_eq!(json["report_kind"], "report_draft");
    assert!(json["digger_version"].as_str().is_some());
}

#[test]
fn test_is_finding_false_invariant() {
    let d = valid_draft();
    assert!(!d.is_finding);
    assert_eq!(serde_json::to_value(&d).unwrap()["is_finding"], false);
}

#[test]
fn test_rejects_is_finding_true() {
    let mut d = valid_draft();
    d.is_finding = true;
    let errors = validate_report_draft(&d);
    assert!(errors.contains(&ReportDraftValidationError::IsFindingTrue));
}

#[test]
fn test_rejects_empty_draft_id() {
    let mut d = valid_draft();
    d.draft_id = "".into();
    assert!(validate_report_draft(&d).contains(&ReportDraftValidationError::EmptyDraftId));
}

#[test]
fn test_rejects_empty_summary() {
    let mut d = valid_draft();
    d.summary = "".into();
    assert!(validate_report_draft(&d).contains(&ReportDraftValidationError::EmptySummary));
}

#[test]
fn test_rejects_missing_citations() {
    let mut d = valid_draft();
    d.evidence_citations = vec![];
    assert!(
        validate_report_draft(&d).contains(&ReportDraftValidationError::MissingEvidenceCitations)
    );
}

#[test]
fn test_valid_draft_passes() {
    let d = valid_draft();
    let errors = validate_report_draft(&d);
    assert!(errors.is_empty(), "valid draft should pass: {:?}", errors);
}

#[test]
fn test_no_forbidden_fields() {
    let d = valid_draft();
    let json = serde_json::to_value(&d).unwrap();
    assert!(json.get("generated_at").is_none());
    assert!(json.get("severity").is_none());
    assert!(json.get("risk_score").is_none());
    assert!(json.get("vulnerability").is_none());
}

#[test]
fn test_deterministic_serialization() {
    let d1 = valid_draft();
    let d2 = valid_draft();
    assert_eq!(
        serde_json::to_string(&d1).unwrap(),
        serde_json::to_string(&d2).unwrap()
    );
}
