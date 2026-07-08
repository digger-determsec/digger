use crate::assumptions::*;
use crate::models::*;
use crate::verification::*;
/// Inversion Engine — Deterministic Hypothesis Invalidation Derivation
///
/// Derives what conditions would invalidate a hypothesis.
/// Does NOT evaluate whether those conditions hold.
///
/// # Rules
///
/// 1. Consumes only AssumptionResult and VerificationTaskResult
/// 2. Does NOT modify any existing outputs
/// 3. Deterministic: same input → same output
/// 4. No AI, no probabilities, no ranking
/// 5. Every inversion has an invalidating condition and explanation
use serde::{Deserialize, Serialize};

/// Unique inversion identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InversionId(pub String);

impl std::fmt::Display for InversionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Inversion type — what kind of invalidation this represents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InversionType {
    /// Reentrancy hypothesis would be invalidated.
    InvalidateReentrancy,
    /// Authority bypass hypothesis would be invalidated.
    InvalidateAuthorityBypass,
    /// CPI trust violation hypothesis would be invalidated.
    InvalidateCPITrustViolation,
    /// State corruption hypothesis would be invalidated.
    InvalidateStateCorruption,
    /// Caller influence hypothesis would be invalidated.
    InvalidateCallerInfluence,
}

impl std::fmt::Display for InversionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidateReentrancy => write!(f, "InvalidateReentrancy"),
            Self::InvalidateAuthorityBypass => write!(f, "InvalidateAuthorityBypass"),
            Self::InvalidateCPITrustViolation => write!(f, "InvalidateCPITrustViolation"),
            Self::InvalidateStateCorruption => write!(f, "InvalidateStateCorruption"),
            Self::InvalidateCallerInfluence => write!(f, "InvalidateCallerInfluence"),
        }
    }
}

/// An inversion condition — what would invalidate a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inversion {
    /// Unique identifier.
    pub id: InversionId,
    /// Type of inversion.
    pub inversion_type: InversionType,
    /// Source hypothesis ID.
    pub source_hypothesis_id: HypothesisId,
    /// Source assumption IDs.
    pub source_assumption_ids: Vec<AssumptionId>,
    /// Source verification task IDs.
    pub source_verification_task_ids: Vec<VerificationTaskId>,
    /// The condition that would invalidate the hypothesis.
    pub invalidating_condition: String,
    /// Explanation of why this condition invalidates the hypothesis.
    pub explanation: String,
    /// Evidence references.
    pub evidence_ids: Vec<String>,
}

/// Result of inversion derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InversionResult {
    /// Program identifier.
    pub program_id: String,
    /// All inversions.
    pub inversions: Vec<Inversion>,
    /// Summary statistics.
    pub summary: InversionSummary,
}

/// Summary statistics for inversions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InversionSummary {
    /// Total inversions derived.
    pub total: usize,
    /// Count by type.
    pub invalidate_reentrancy: usize,
    pub invalidate_authority_bypass: usize,
    pub invalidate_cpi_trust_violation: usize,
    pub invalidate_state_corruption: usize,
    pub invalidate_caller_influence: usize,
}

/// Derive inversions from assumptions and verification tasks.
///
/// This is the ONLY entry point. Consumes existing outputs only.
pub fn derive_inversions(
    assumptions: &AssumptionResult,
    verification: &VerificationTaskResult,
    _hypotheses: &HypothesisResult,
) -> InversionResult {
    let mut inversions = vec![];

    // Map assumptions to inversions by type
    for assumption in &assumptions.all_assumptions {
        let inversion = assumption_to_inversion(assumption, verification);
        inversions.push(inversion);
    }

    let summary = build_summary(&inversions);

    InversionResult {
        program_id: assumptions.program_id.clone(),
        inversions,
        summary,
    }
}

/// Convert an assumption into an inversion.
fn assumption_to_inversion(
    assumption: &Assumption,
    verification: &VerificationTaskResult,
) -> Inversion {
    // Find related verification tasks
    let related_tasks: Vec<&VerificationTask> = verification
        .tasks
        .iter()
        .filter(|t| t.source_assumption_id == assumption.id)
        .collect();

    let task_ids: Vec<VerificationTaskId> =
        related_tasks.iter().map(|t| t.task_id.clone()).collect();

    match assumption.assumption_type {
        AssumptionType::ReentrantExecutionPossible => Inversion {
            id: InversionId(format!("INV-REENT-{}", assumption.id.0)),
            inversion_type: InversionType::InvalidateReentrancy,
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            source_assumption_ids: vec![assumption.id.clone()],
            source_verification_task_ids: task_ids,
            invalidating_condition: "Reentrancy guard is present (nonReentrant modifier, mutex lock), \
                OR state is updated before external call (checks-effects-interactions pattern), \
                OR pull-payment pattern is used instead of push transfers.".into(),
            explanation: format!(
                "The reentrancy hypothesis '{}' depends on re-entrant execution being possible. \
                 If any of the following conditions hold, the hypothesis is invalidated:\n\
                 1. A reentrancy guard (nonReentrant, mutex) prevents re-entry\n\
                 2. State is updated before the external call (CEI pattern)\n\
                 3. A pull-payment pattern is used instead of direct transfers",
                assumption.source_hypothesis_id
            ),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
        },

        AssumptionType::AuthorityCheckAbsent => Inversion {
            id: InversionId(format!("INV-AUTH-{}", assumption.id.0)),
            inversion_type: InversionType::InvalidateAuthorityBypass,
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            source_assumption_ids: vec![assumption.id.clone()],
            source_verification_task_ids: task_ids,
            invalidating_condition: "Authority validation exists in the code path: \
                require(msg.sender == owner), onlyOwner modifier, Signer check, \
                has_one constraint, or other access control mechanism.".into(),
            explanation: format!(
                "The authority bypass hypothesis '{}' depends on the absence of authority checks. \
                 If authority validation exists (require, modifier, Signer, has_one), \
                 the hypothesis is invalidated because unauthorized callers cannot execute the function.",
                assumption.source_hypothesis_id
            ),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
        },

        AssumptionType::CallerInfluencePossible => Inversion {
            id: InversionId(format!("INV-CALLER-{}", assumption.id.0)),
            inversion_type: InversionType::InvalidateCallerInfluence,
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            source_assumption_ids: vec![assumption.id.clone()],
            source_verification_task_ids: task_ids,
            invalidating_condition: "Access control restricts callers to trusted addresses: \
                whitelist, role-based access, Signer verification, \
                or the function is only callable by a trusted program.".into(),
            explanation: format!(
                "The caller influence hypothesis '{}' depends on the caller being able to influence execution. \
                 If access control restricts who can call the function, \
                 the hypothesis is invalidated because untrusted callers cannot trigger the execution path.",
                assumption.source_hypothesis_id
            ),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
        },

        AssumptionType::MultipleWritersExist => Inversion {
            id: InversionId(format!("INV-WRITERS-{}", assumption.id.0)),
            inversion_type: InversionType::InvalidateStateCorruption,
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            source_assumption_ids: vec![assumption.id.clone()],
            source_verification_task_ids: task_ids,
            invalidating_condition: "Single-writer guarantee exists: \
                only one function writes to the state variable, \
                OR all writers are coordinated through a single entry point, \
                OR the state variable is constant/immutable.".into(),
            explanation: format!(
                "The state corruption hypothesis '{}' depends on multiple writers existing. \
                 If a single-writer guarantee exists (only one writer, or coordinated writes), \
                 the hypothesis is invalidated because uncoordinated corruption is not possible.",
                assumption.source_hypothesis_id
            ),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
        },

        AssumptionType::CoordinationMissing => Inversion {
            id: InversionId(format!("INV-COORD-{}", assumption.id.0)),
            inversion_type: InversionType::InvalidateStateCorruption,
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            source_assumption_ids: vec![assumption.id.clone()],
            source_verification_task_ids: task_ids,
            invalidating_condition: "Coordination primitive exists: \
                mutex lock, reentrancy guard, single-writer pattern, \
                or state is only modified through a single coordinated entry point.".into(),
            explanation: format!(
                "The state corruption hypothesis '{}' depends on coordination being missing. \
                 If a coordination primitive exists (mutex, lock, single-writer), \
                 the hypothesis is invalidated because concurrent writes are prevented.",
                assumption.source_hypothesis_id
            ),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
        },

        AssumptionType::SharedStateMutable => Inversion {
            id: InversionId(format!("INV-MUTABLE-{}", assumption.id.0)),
            inversion_type: InversionType::InvalidateStateCorruption,
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            source_assumption_ids: vec![assumption.id.clone()],
            source_verification_task_ids: task_ids,
            invalidating_condition: "State variable is declared as constant or immutable, \
                OR mutation is protected by access control.".into(),
            explanation: format!(
                "The state corruption hypothesis '{}' depends on shared state being mutable. \
                 If the state is immutable or mutation is access-controlled, \
                 the hypothesis is invalidated because state cannot be corrupted.",
                assumption.source_hypothesis_id
            ),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
        },

        AssumptionType::CPITrustRequired => Inversion {
            id: InversionId(format!("INV-CPI-{}", assumption.id.0)),
            inversion_type: InversionType::InvalidateCPITrustViolation,
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            source_assumption_ids: vec![assumption.id.clone()],
            source_verification_task_ids: task_ids,
            invalidating_condition: "CPI target is a trusted program (immutable, audited, governance-controlled), \
                OR CPI call is validated before execution, \
                OR the CPI target cannot be changed by an attacker.".into(),
            explanation: format!(
                "The CPI trust violation hypothesis '{}' depends on a CPI trust boundary being crossed. \
                 If the CPI target is trusted or validated, \
                 the hypothesis is invalidated because the trust boundary is not actually violated.",
                assumption.source_hypothesis_id
            ),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
        },

        AssumptionType::ExternalTargetControlled => Inversion {
            id: InversionId(format!("INV-EXT-{}", assumption.id.0)),
            inversion_type: InversionType::InvalidateReentrancy,
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            source_assumption_ids: vec![assumption.id.clone()],
            source_verification_task_ids: task_ids,
            invalidating_condition: "External call target is immutable or controlled by trusted governance, \
                OR the target cannot trigger callbacks to the original contract.".into(),
            explanation: format!(
                "The reentrancy hypothesis '{}' depends on the external target being attacker-controlled. \
                 If the target is trusted or cannot trigger callbacks, \
                 the hypothesis is invalidated because re-entrant execution is not possible.",
                assumption.source_hypothesis_id
            ),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
        },

        AssumptionType::StateMutationAfterCall => Inversion {
            id: InversionId(format!("INV-ORDER-{}", assumption.id.0)),
            inversion_type: InversionType::InvalidateReentrancy,
            source_hypothesis_id: assumption.source_hypothesis_id.clone(),
            source_assumption_ids: vec![assumption.id.clone()],
            source_verification_task_ids: task_ids,
            invalidating_condition: "State variables are updated before external calls, \
                following the checks-effects-interactions pattern.".into(),
            explanation: format!(
                "The reentrancy hypothesis '{}' depends on state mutation occurring after an external call. \
                 If state is updated before the call (CEI pattern), \
                 the hypothesis is invalidated because re-entrant execution sees updated state.",
                assumption.source_hypothesis_id
            ),
            evidence_ids: assumption.supporting_evidence_ids.clone(),
        },
    }
}

/// Build summary statistics.
fn build_summary(inversions: &[Inversion]) -> InversionSummary {
    InversionSummary {
        total: inversions.len(),
        invalidate_reentrancy: inversions
            .iter()
            .filter(|i| i.inversion_type == InversionType::InvalidateReentrancy)
            .count(),
        invalidate_authority_bypass: inversions
            .iter()
            .filter(|i| i.inversion_type == InversionType::InvalidateAuthorityBypass)
            .count(),
        invalidate_cpi_trust_violation: inversions
            .iter()
            .filter(|i| i.inversion_type == InversionType::InvalidateCPITrustViolation)
            .count(),
        invalidate_state_corruption: inversions
            .iter()
            .filter(|i| i.inversion_type == InversionType::InvalidateStateCorruption)
            .count(),
        invalidate_caller_influence: inversions
            .iter()
            .filter(|i| i.inversion_type == InversionType::InvalidateCallerInfluence)
            .count(),
    }
}
