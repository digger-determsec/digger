use crate::assumptions::*;
use crate::compound::CompoundHypothesisResult;
use crate::models::*;
/// Verification Task Engine — Deterministic Task Derivation
///
/// Converts assumptions into actionable researcher verification tasks.
///
/// # Rules
///
/// 1. Consumes only AssumptionResult, HypothesisResult, CompoundHypothesisResult
/// 2. Does NOT modify any existing outputs
/// 3. Deterministic: same input → same output
/// 4. No AI, no probabilities, no ranking
/// 5. Every task has expected validation and failure implication
use serde::{Deserialize, Serialize};

/// Unique verification task identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerificationTaskId(pub String);

impl std::fmt::Display for VerificationTaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Verification task type — what a researcher should verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationTaskType {
    /// Verify that the external call target is controlled or trusted.
    VerifyExternalTargetControl,
    /// Verify that reentrancy protection exists.
    VerifyReentrancyProtection,
    /// Verify that authority enforcement exists.
    VerifyAuthorityEnforcement,
    /// Verify state mutation ordering (checks-effects-interactions).
    VerifyStateMutationOrdering,
    /// Verify shared state coordination (mutex, single-writer).
    VerifySharedStateCoordination,
    /// Verify CPI trust boundary is enforced.
    VerifyCPITrustBoundary,
    /// Verify caller restrictions exist.
    VerifyCallerRestrictions,
    /// Verify single-writer guarantee for state.
    VerifySingleWriterGuarantee,
}

impl std::fmt::Display for VerificationTaskType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerifyExternalTargetControl => write!(f, "VerifyExternalTargetControl"),
            Self::VerifyReentrancyProtection => write!(f, "VerifyReentrancyProtection"),
            Self::VerifyAuthorityEnforcement => write!(f, "VerifyAuthorityEnforcement"),
            Self::VerifyStateMutationOrdering => write!(f, "VerifyStateMutationOrdering"),
            Self::VerifySharedStateCoordination => write!(f, "VerifySharedStateCoordination"),
            Self::VerifyCPITrustBoundary => write!(f, "VerifyCPITrustBoundary"),
            Self::VerifyCallerRestrictions => write!(f, "VerifyCallerRestrictions"),
            Self::VerifySingleWriterGuarantee => write!(f, "VerifySingleWriterGuarantee"),
        }
    }
}

/// A verification task — actionable item for a researcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationTask {
    /// Unique identifier.
    pub task_id: VerificationTaskId,
    /// Type of verification.
    pub task_type: VerificationTaskType,
    /// Source assumption ID.
    pub source_assumption_id: AssumptionId,
    /// Source hypothesis ID.
    pub source_hypothesis_id: HypothesisId,
    /// Evidence IDs supporting this task.
    pub evidence_ids: Vec<String>,
    /// Short title.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// What the researcher should validate.
    pub expected_validation: String,
    /// What happens if validation fails.
    pub failure_implication: String,
}

/// Result of verification task derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationTaskResult {
    /// Program identifier.
    pub program_id: String,
    /// All verification tasks.
    pub tasks: Vec<VerificationTask>,
    /// Summary statistics.
    pub summary: VerificationSummary,
}

/// Summary statistics for verification tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSummary {
    /// Total tasks derived.
    pub total: usize,
    /// Count by type.
    pub verify_external_target_control: usize,
    pub verify_reentrancy_protection: usize,
    pub verify_authority_enforcement: usize,
    pub verify_state_mutation_ordering: usize,
    pub verify_shared_state_coordination: usize,
    pub verify_cpi_trust_boundary: usize,
    pub verify_caller_restrictions: usize,
    pub verify_single_writer_guarantee: usize,
}

/// Derive verification tasks from assumptions and hypotheses.
///
/// This is the ONLY entry point. Consumes existing outputs only.
pub fn derive_verification_tasks(
    assumptions: &AssumptionResult,
    _hypotheses: &HypothesisResult,
    _compounds: &CompoundHypothesisResult,
) -> VerificationTaskResult {
    let mut tasks = vec![];

    for assumption in &assumptions.all_assumptions {
        let task = assumption_to_task(assumption);
        tasks.push(task);
    }

    let summary = build_summary(&tasks);

    VerificationTaskResult {
        program_id: assumptions.program_id.clone(),
        tasks,
        summary,
    }
}

/// Convert an assumption into a verification task.
fn assumption_to_task(assumption: &Assumption) -> VerificationTask {
    match assumption.assumption_type {
        AssumptionType::ExternalTargetControlled => VerificationTask {
            task_id: VerificationTaskId(format!("VT-EXT-{}", assumption.id.0)),
            task_type: VerificationTaskType::VerifyExternalTargetControl,
            source_assumption_id: assumption.id.clone(),
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
            title: "Verify External Target Control".into(),
            description: format!(
                "The hypothesis '{}' depends on the external call target being attacker-controlled. \
                 Verify whether the target contract address is immutable, set by trusted governance, \
                 or otherwise protected from attacker manipulation.",
                assumption.source_hypothesis_id
            ),
            expected_validation: "Target contract address is immutable or controlled by trusted governance.".into(),
            failure_implication: "Attacker-controlled target may enable exploit chain.".into(),
        },

        AssumptionType::ReentrantExecutionPossible => VerificationTask {
            task_id: VerificationTaskId(format!("VT-REENT-{}", assumption.id.0)),
            task_type: VerificationTaskType::VerifyReentrancyProtection,
            source_assumption_id: assumption.id.clone(),
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
            title: "Verify Reentrancy Protection".into(),
            description: format!(
                "The hypothesis '{}' depends on re-entrant execution being possible. \
                 Verify whether a reentrancy guard (mutex, nonReentrant modifier) is in place, \
                 or whether the checks-effects-interactions pattern is followed.",
                assumption.source_hypothesis_id
            ),
            expected_validation: "Reentrancy guard exists or state is updated before external calls.".into(),
            failure_implication: "Re-entrant execution may allow attacker to drain funds or corrupt state.".into(),
        },

        AssumptionType::AuthorityCheckAbsent => VerificationTask {
            task_id: VerificationTaskId(format!("VT-AUTH-{}", assumption.id.0)),
            task_type: VerificationTaskType::VerifyAuthorityEnforcement,
            source_assumption_id: assumption.id.clone(),
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
            title: "Verify Authority Enforcement".into(),
            description: format!(
                "The hypothesis '{}' depends on the absence of authority checks. \
                 Verify whether require(msg.sender == owner), onlyOwner modifier, \
                 or Signer checks are present in the function or inherited.",
                assumption.source_hypothesis_id
            ),
            expected_validation: "Authority check (require, modifier, Signer) is present in the code path.".into(),
            failure_implication: "Unauthorized callers may execute privileged operations.".into(),
        },

        AssumptionType::SharedStateMutable => VerificationTask {
            task_id: VerificationTaskId(format!("VT-MUTABLE-{}", assumption.id.0)),
            task_type: VerificationTaskType::VerifySharedStateCoordination,
            source_assumption_id: assumption.id.clone(),
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
            title: "Verify Shared State Mutability".into(),
            description: format!(
                "The hypothesis '{}' depends on shared state being mutable. \
                 Verify whether the state variable is declared as constant or immutable, \
                 or whether mutation is protected by access control.",
                assumption.source_hypothesis_id
            ),
            expected_validation: "State variable is constant, immutable, or mutation is access-controlled.".into(),
            failure_implication: "Mutable shared state may be corrupted by concurrent or unauthorized writes.".into(),
        },

        AssumptionType::CPITrustRequired => VerificationTask {
            task_id: VerificationTaskId(format!("VT-CPI-{}", assumption.id.0)),
            task_type: VerificationTaskType::VerifyCPITrustBoundary,
            source_assumption_id: assumption.id.clone(),
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
            title: "Verify CPI Trust Boundary".into(),
            description: format!(
                "The hypothesis '{}' depends on a CPI trust boundary being crossed. \
                 Verify whether the CPI target program is trusted, whether the CPI call \
                 is validated before execution, or whether the target is immutable.",
                assumption.source_hypothesis_id
            ),
            expected_validation: "CPI target is trusted, or CPI call is validated before execution.".into(),
            failure_implication: "Untrusted CPI target may execute arbitrary code on behalf of the program.".into(),
        },

        AssumptionType::StateMutationAfterCall => VerificationTask {
            task_id: VerificationTaskId(format!("VT-ORDER-{}", assumption.id.0)),
            task_type: VerificationTaskType::VerifyStateMutationOrdering,
            source_assumption_id: assumption.id.clone(),
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
            title: "Verify State Mutation Ordering".into(),
            description: format!(
                "The hypothesis '{}' depends on state mutation occurring after an external call. \
                 Verify whether the checks-effects-interactions pattern is followed, \
                 or whether state is updated before external interactions.",
                assumption.source_hypothesis_id
            ),
            expected_validation: "State variables are updated before external calls (checks-effects-interactions).".into(),
            failure_implication: "State mutation after external call enables reentrancy-style attacks.".into(),
        },

        AssumptionType::MultipleWritersExist => VerificationTask {
            task_id: VerificationTaskId(format!("VT-WRITERS-{}", assumption.id.0)),
            task_type: VerificationTaskType::VerifySingleWriterGuarantee,
            source_assumption_id: assumption.id.clone(),
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
            title: "Verify Single Writer Guarantee".into(),
            description: format!(
                "The hypothesis '{}' depends on multiple functions writing to the same state. \
                 Verify whether only one function writes to the state variable, \
                 or whether all writers are coordinated through a single entry point.",
                assumption.source_hypothesis_id
            ),
            expected_validation: "Only one function writes to the state variable, or all writers are coordinated.".into(),
            failure_implication: "Uncoordinated writes may lead to inconsistent or corrupted state.".into(),
        },

        AssumptionType::CoordinationMissing => VerificationTask {
            task_id: VerificationTaskId(format!("VT-COORD-{}", assumption.id.0)),
            task_type: VerificationTaskType::VerifySharedStateCoordination,
            source_assumption_id: assumption.id.clone(),
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
            title: "Verify Writer Coordination".into(),
            description: format!(
                "The hypothesis '{}' depends on the absence of coordination between writers. \
                 Verify whether a mutex, lock, or single-writer pattern ensures \
                 only one writer can modify state at a time.",
                assumption.source_hypothesis_id
            ),
            expected_validation: "Mutex, lock, or single-writer pattern prevents concurrent writes.".into(),
            failure_implication: "Concurrent writes without coordination may corrupt state.".into(),
        },

        AssumptionType::CallerInfluencePossible => VerificationTask {
            task_id: VerificationTaskId(format!("VT-CALLER-{}", assumption.id.0)),
            task_type: VerificationTaskType::VerifyCallerRestrictions,
            source_assumption_id: assumption.id.clone(),
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
            title: "Verify Caller Restrictions".into(),
            description: format!(
                "The hypothesis '{}' depends on the caller being able to influence execution. \
                 Verify whether access control restricts who can call the function, \
                 or whether the function is only callable by trusted contracts.",
                assumption.source_hypothesis_id
            ),
            expected_validation: "Access control restricts function callers to trusted addresses.".into(),
            failure_implication: "Unrestricted callers may trigger unintended execution paths.".into(),
        },
    }
}

/// Build summary statistics.
fn build_summary(tasks: &[VerificationTask]) -> VerificationSummary {
    VerificationSummary {
        total: tasks.len(),
        verify_external_target_control: tasks
            .iter()
            .filter(|t| t.task_type == VerificationTaskType::VerifyExternalTargetControl)
            .count(),
        verify_reentrancy_protection: tasks
            .iter()
            .filter(|t| t.task_type == VerificationTaskType::VerifyReentrancyProtection)
            .count(),
        verify_authority_enforcement: tasks
            .iter()
            .filter(|t| t.task_type == VerificationTaskType::VerifyAuthorityEnforcement)
            .count(),
        verify_state_mutation_ordering: tasks
            .iter()
            .filter(|t| t.task_type == VerificationTaskType::VerifyStateMutationOrdering)
            .count(),
        verify_shared_state_coordination: tasks
            .iter()
            .filter(|t| t.task_type == VerificationTaskType::VerifySharedStateCoordination)
            .count(),
        verify_cpi_trust_boundary: tasks
            .iter()
            .filter(|t| t.task_type == VerificationTaskType::VerifyCPITrustBoundary)
            .count(),
        verify_caller_restrictions: tasks
            .iter()
            .filter(|t| t.task_type == VerificationTaskType::VerifyCallerRestrictions)
            .count(),
        verify_single_writer_guarantee: tasks
            .iter()
            .filter(|t| t.task_type == VerificationTaskType::VerifySingleWriterGuarantee)
            .count(),
    }
}
