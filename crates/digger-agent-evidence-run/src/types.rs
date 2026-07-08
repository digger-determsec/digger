use serde::{Deserialize, Serialize};

/// An evidence run — a record of evidence gathered about a hypothesis.
///
/// EvidenceRuns are NOT findings. They are evidence records.
/// MY.4 produces EvidenceRuns. MY.5 may draft reports from them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRun {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub evidence_run_id: String,
    pub proof_task_id: String,
    pub hypothesis_id: String,
    pub command_log: Vec<CommandRecord>,
    pub raw_outputs: Vec<RawOutputRef>,
    pub artifacts: Vec<ArtifactRef>,
    pub validation_results: Vec<ValidationResult>,
    pub stop_condition_triggered: Option<StopConditionRecord>,
    pub is_finding: bool,
}

impl EvidenceRun {
    /// Create a new evidence run with default metadata and empty collections.
    pub fn new(evidence_run_id: String, proof_task_id: String, hypothesis_id: String) -> Self {
        Self {
            schema_version: "digger.evidence_run.v1".into(),
            digger_version: env!("CARGO_PKG_VERSION").into(),
            report_kind: "evidence_run".into(),
            evidence_run_id,
            proof_task_id,
            hypothesis_id,
            command_log: Vec::new(),
            raw_outputs: Vec::new(),
            artifacts: Vec::new(),
            validation_results: Vec::new(),
            stop_condition_triggered: None,
            is_finding: false,
        }
    }
}

/// A record of a command that was executed (Level 2+).
///
/// This is a record type only. It must not run commands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandRecord {
    pub command_id: String,
    pub tool: String,
    pub args_redacted: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout_ref: Option<String>,
    pub stderr_ref: Option<String>,
    pub policy_level: String,
}

/// A reference to raw output from a command or inspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawOutputRef {
    pub output_id: String,
    pub stream: String,
    pub path_or_inline_ref: String,
    pub truncated: bool,
}

/// A reference to a file artifact produced during evidence gathering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub path: String,
    pub kind: String,
    pub sha256: Option<String>,
}

/// Result of validating an evidence run against a gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationResult {
    pub gate: String,
    pub status: String,
    pub message: String,
    pub blocks_promotion: bool,
}

/// Record of a stop condition that was triggered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StopConditionRecord {
    pub condition: String,
    pub triggered: bool,
    pub reason: String,
}

/// Create a Level 0 planning record from a ProofTask.
///
/// This is the first safe bridge between MY.3 and MY.4.
/// It does NOT execute anything. It produces a planning-only EvidenceRun.
pub fn plan_level0_evidence_run(
    evidence_run_id: String,
    proof_task: &digger_agent_proof_task::types::ProofTask,
) -> EvidenceRun {
    let mut run = EvidenceRun::new(
        evidence_run_id,
        proof_task.task_id.clone(),
        proof_task.hypothesis_id.clone(),
    );
    run.validation_results = vec![ValidationResult {
        gate: "level_0_planning_only".into(),
        status: "passed".into(),
        message: "Proof task accepted for Level 0 planning record; no execution performed.".into(),
        blocks_promotion: false,
    }];
    run
}
