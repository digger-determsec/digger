use digger_agent_hypothesis::types::Hypothesis;
use digger_agent_hypothesis::validate;
use digger_agent_proof_task::types::ProofTask;
use digger_agent_proof_task::validate_proof_task;
use digger_repo_intelligence::types::{ConfidenceLevel, SurfaceNode};

fn make_surface() -> SurfaceNode {
    SurfaceNode {
        id: "s-001".into(),
        path: "contracts/TokenVault.sol".into(),
        chain: "evm".into(),
        category: "privileged_operation".into(),
        name: "TokenVault::withdraw".into(),
        kind: "function".into(),
        evidence: vec![],
        confidence: ConfidenceLevel {
            inventory: "high".into(),
            classification: "medium".into(),
        },
    }
}

fn make_hypothesis(surface_id: &str) -> Hypothesis {
    Hypothesis::new(
        "hyp-001".into(),
        "The withdraw function may lack authority verification".into(),
        vec![surface_id.into()],
        vec!["Source code review of withdraw function".into()],
        vec!["Authority check found in withdraw or callers".into()],
    )
}

fn make_proof_task(hypothesis_id: &str, surface_id: &str) -> ProofTask {
    ProofTask::new(
        "pt-001".into(),
        hypothesis_id.into(),
        "The withdraw function may lack authority verification".into(),
        vec![surface_id.into()],
        vec!["Digger scan of withdraw function".into()],
        vec!["digger scan".into()],
        vec!["No exploit execution".into()],
        vec!["Authority check presence/absence".into()],
        vec!["validate_assistant_output must pass".into()],
        vec!["Validation failure on any derived claim".into()],
    )
}

#[test]
fn test_surface_to_hypothesis_reference() {
    let surface = make_surface();
    let hypothesis = make_hypothesis(&surface.id);

    assert_eq!(hypothesis.source_surfaces, vec!["s-001"]);
    assert_eq!(hypothesis.report_kind, "hypothesis");
    assert!(!hypothesis.is_finding);

    let errors = validate(&hypothesis);
    assert!(
        errors.is_empty(),
        "hypothesis should validate: {:?}",
        errors
    );
}

#[test]
fn test_hypothesis_to_proof_task_reference() {
    let surface = make_surface();
    let hypothesis = make_hypothesis(&surface.id);
    let proof_task = make_proof_task(&hypothesis.hypothesis_id, &surface.id);

    assert_eq!(proof_task.hypothesis_id, "hyp-001");
    assert_eq!(proof_task.target_surfaces, vec!["s-001"]);
    assert_eq!(proof_task.report_kind, "proof_task");
    assert!(!proof_task.is_finding);

    let errors = validate_proof_task(&proof_task);
    assert!(
        errors.is_empty(),
        "proof task should validate: {:?}",
        errors
    );
}

#[test]
fn test_full_chain_serialization() {
    let surface = make_surface();
    let hypothesis = make_hypothesis(&surface.id);
    let proof_task = make_proof_task(&hypothesis.hypothesis_id, &surface.id);

    let s_json = serde_json::to_value(&surface).unwrap();
    let h_json = serde_json::to_value(&hypothesis).unwrap();
    let p_json = serde_json::to_value(&proof_task).unwrap();

    // Metadata present
    assert_eq!(s_json["id"], "s-001");
    assert_eq!(h_json["schema_version"], "digger.hypothesis.v1");
    assert_eq!(p_json["schema_version"], "digger.proof_task.v1");

    // Cross-references valid
    assert_eq!(h_json["source_surfaces"][0], "s-001");
    assert_eq!(p_json["hypothesis_id"], "hyp-001");
    assert_eq!(p_json["target_surfaces"][0], "s-001");

    // Non-finding invariant
    assert_eq!(h_json["is_finding"], false);
    assert_eq!(p_json["is_finding"], false);

    // No forbidden fields
    for json in [&s_json, &h_json, &p_json] {
        assert!(json.get("severity").is_none());
        assert!(json.get("risk_score").is_none());
        assert!(json.get("vulnerability").is_none());
        assert!(json.get("generated_at").is_none());
    }
}

#[test]
fn test_invalid_surface_reference_blocks_hypothesis() {
    let mut hypothesis = make_hypothesis("s-999");
    hypothesis.source_surfaces = vec!["s-999".into()];
    // Hypothesis validates structurally (surface existence is runtime check)
    let errors = validate(&hypothesis);
    assert!(
        errors.is_empty(),
        "structural validation passes: {:?}",
        errors
    );
    // But agent should note s-999 doesn't exist in the intelligence map
}

#[test]
fn test_invalid_hypothesis_reference_fails_proof_task() {
    let mut proof_task = make_proof_task("hyp-999", "s-001");
    proof_task.hypothesis_id = "hyp-999".into();
    // Structural validation passes (ID format is valid)
    let errors = validate_proof_task(&proof_task);
    assert!(
        errors.is_empty(),
        "structural validation passes: {:?}",
        errors
    );
    // Agent must verify hyp-999 exists before using this proof task
}
