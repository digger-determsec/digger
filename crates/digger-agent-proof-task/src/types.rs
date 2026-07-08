use serde::{Deserialize, Serialize};

/// A proof task — a plan for gathering evidence about a hypothesis.
///
/// Proof tasks are NOT findings. They are NOT execution instructions.
/// They describe what evidence must be gathered, what tools are permitted,
/// and what conditions would confirm or refute the originating hypothesis.
///
/// MY.3 defines proof tasks. MY.4 (future) executes them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofTask {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub task_id: String,
    pub hypothesis_id: String,
    pub claim: String,
    pub target_surfaces: Vec<String>,
    pub required_evidence: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub forbidden_actions: Vec<String>,
    pub expected_outputs: Vec<String>,
    pub validation_gates: Vec<String>,
    pub stop_conditions: Vec<String>,
    pub status: ProofTaskStatus,
    pub is_finding: bool,
}

impl ProofTask {
    /// Create a new proof task with default metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: String,
        hypothesis_id: String,
        claim: String,
        target_surfaces: Vec<String>,
        required_evidence: Vec<String>,
        allowed_tools: Vec<String>,
        forbidden_actions: Vec<String>,
        expected_outputs: Vec<String>,
        validation_gates: Vec<String>,
        stop_conditions: Vec<String>,
    ) -> Self {
        Self {
            schema_version: "digger.proof_task.v1".into(),
            digger_version: env!("CARGO_PKG_VERSION").into(),
            report_kind: "proof_task".into(),
            task_id,
            hypothesis_id,
            claim,
            target_surfaces,
            required_evidence,
            allowed_tools,
            forbidden_actions,
            expected_outputs,
            validation_gates,
            stop_conditions,
            status: ProofTaskStatus::Proposed,
            is_finding: false,
        }
    }
}

/// Lifecycle status of a proof task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofTaskStatus {
    /// Task defined, not yet ready for execution.
    Proposed,
    /// Task validated and ready for MY.4 execution.
    Ready,
    /// Cannot proceed (blocked by missing data or external dependency).
    Blocked,
    /// Task rejected or cancelled.
    Rejected,
}
