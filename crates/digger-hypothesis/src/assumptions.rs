use crate::compound::CompoundHypothesisResult;
use crate::models::*;
/// Assumption Engine — Deterministic Assumption Derivation
///
/// Explains why a hypothesis or compound hypothesis exists and what
/// conditions must hold for it to be valid.
///
/// # Rules
///
/// 1. Consumes only HypothesisResult and CompoundHypothesisResult
/// 2. Does NOT modify any existing outputs
/// 3. Deterministic: same input → same output
/// 4. No AI, no probabilities, no ranking
/// 5. Every assumption has an invalidation condition
use serde::{Deserialize, Serialize};

/// Unique assumption identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssumptionId(pub String);

impl std::fmt::Display for AssumptionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Assumption type — what condition must hold for the hypothesis to be valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssumptionType {
    /// The external call target is controlled by an attacker.
    ExternalTargetControlled,
    /// Re-entrant execution is possible (callback before state update).
    ReentrantExecutionPossible,
    /// An authority check is absent from the code path.
    AuthorityCheckAbsent,
    /// Shared state is mutable by multiple callers.
    SharedStateMutable,
    /// CPI trust boundary must be crossed for the exploit.
    CPITrustRequired,
    /// State mutation occurs after an external call.
    StateMutationAfterCall,
    /// Multiple writers exist for the same state variable.
    MultipleWritersExist,
    /// Coordination between writers is missing.
    CoordinationMissing,
    /// The caller can influence the execution path.
    CallerInfluencePossible,
}

impl std::fmt::Display for AssumptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExternalTargetControlled => write!(f, "ExternalTargetControlled"),
            Self::ReentrantExecutionPossible => write!(f, "ReentrantExecutionPossible"),
            Self::AuthorityCheckAbsent => write!(f, "AuthorityCheckAbsent"),
            Self::SharedStateMutable => write!(f, "SharedStateMutable"),
            Self::CPITrustRequired => write!(f, "CPITrustRequired"),
            Self::StateMutationAfterCall => write!(f, "StateMutationAfterCall"),
            Self::MultipleWritersExist => write!(f, "MultipleWritersExist"),
            Self::CoordinationMissing => write!(f, "CoordinationMissing"),
            Self::CallerInfluencePossible => write!(f, "CallerInfluencePossible"),
        }
    }
}

/// A single assumption — a condition that must hold for a hypothesis to be valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assumption {
    /// Unique identifier.
    pub id: AssumptionId,
    /// Type of assumption.
    pub assumption_type: AssumptionType,
    /// Source hypothesis ID this assumption belongs to.
    pub source_hypothesis_id: HypothesisId,
    /// Source compound hypothesis ID (if derived from compound).
    pub source_compound_hypothesis_id: Option<String>,
    /// Evidence IDs supporting this assumption.
    pub supporting_evidence_ids: Vec<String>,
    /// Explanation of why this assumption exists.
    pub explanation: String,
    /// Condition that would invalidate this assumption.
    pub invalidation_condition: String,
}

/// A set of assumptions for a single hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssumptionSet {
    /// The hypothesis these assumptions apply to.
    pub hypothesis_id: HypothesisId,
    /// The assumptions.
    pub assumptions: Vec<Assumption>,
}

/// Result of assumption derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssumptionResult {
    /// Program identifier.
    pub program_id: String,
    /// All assumption sets (one per hypothesis).
    pub assumption_sets: Vec<AssumptionSet>,
    /// Flat list of all assumptions.
    pub all_assumptions: Vec<Assumption>,
    /// Summary statistics.
    pub summary: AssumptionSummary,
}

/// Summary statistics for assumption derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssumptionSummary {
    /// Total assumptions derived.
    pub total: usize,
    /// Count by type.
    pub external_target_controlled: usize,
    pub reentrant_execution_possible: usize,
    pub authority_check_absent: usize,
    pub shared_state_mutable: usize,
    pub cpi_trust_required: usize,
    pub state_mutation_after_call: usize,
    pub multiple_writers_exist: usize,
    pub coordination_missing: usize,
    pub caller_influence_possible: usize,
}

/// Derive assumptions from HypothesisResult and CompoundHypothesisResult.
///
/// This is the ONLY entry point. Consumes existing outputs only.
pub fn derive_assumptions(
    hypotheses: &HypothesisResult,
    _compounds: &CompoundHypothesisResult,
) -> AssumptionResult {
    let mut assumption_sets = vec![];
    let mut all_assumptions = vec![];

    // Derive assumptions for each atomic hypothesis
    for hyp in &hypotheses.hypotheses {
        let assumptions = derive_for_hypothesis(hyp, &hypotheses.program_id);
        all_assumptions.extend(assumptions.clone());
        assumption_sets.push(AssumptionSet {
            hypothesis_id: hyp.id.clone(),
            assumptions,
        });
    }

    let summary = build_summary(&all_assumptions);

    AssumptionResult {
        program_id: hypotheses.program_id.clone(),
        assumption_sets,
        all_assumptions,
        summary,
    }
}

/// Derive assumptions for a single atomic hypothesis.
fn derive_for_hypothesis(hyp: &Hypothesis, _program_id: &str) -> Vec<Assumption> {
    let mut assumptions = vec![];

    match hyp.hypothesis_type {
        HypothesisType::ReentrancyCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-REENT-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::ExternalTargetControlled,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp.evidence.iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on the external call target being attacker-controlled. \
                     The function '{}' makes an external call that could be used for re-entrant execution.",
                    hyp.id, hyp.primary_function
                ),
                invalidation_condition: "Target contract is trusted and immutable, or external call \
                    cannot trigger callbacks to the original contract.".into(),
            });

            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-REENT-{}-2", hyp.id.0)),
                assumption_type: AssumptionType::ReentrantExecutionPossible,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp.evidence.iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on re-entrant execution being possible. \
                     The external call in '{}' occurs before state update, allowing callback re-entry.",
                    hyp.id, hyp.primary_function
                ),
                invalidation_condition: "Reentrancy guard (mutex) is in place, or state is updated \
                    before the external call.".into(),
            });

            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-REENT-{}-3", hyp.id.0)),
                assumption_type: AssumptionType::StateMutationAfterCall,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on state mutation occurring after the external call. \
                     If state were updated before the call, re-entrancy would be prevented.",
                    hyp.id
                ),
                invalidation_condition: "State variables are updated before the external call, \
                    following the checks-effects-interactions pattern."
                    .into(),
            });
        }

        HypothesisType::AuthorityBypassCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-AUTH-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::AuthorityCheckAbsent,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp.evidence.iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on the absence of authority checks. \
                     The function '{}' is publicly callable and mutates state without access control.",
                    hyp.id, hyp.primary_function
                ),
                invalidation_condition: "An authority check (require, modifier, Signer) is present \
                    in the function or inherited from a modifier.".into(),
            });

            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-AUTH-{}-2", hyp.id.0)),
                assumption_type: AssumptionType::CallerInfluencePossible,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on the caller being able to influence execution. \
                     Without authority checks, any caller can trigger the state mutation.",
                    hyp.id
                ),
                invalidation_condition: "Access control restricts who can call the function, \
                    or the function is only callable by trusted contracts."
                    .into(),
            });
        }

        HypothesisType::CPITrustViolationCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-CPI-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::CPITrustRequired,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp.evidence.iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on a CPI trust boundary being crossed. \
                     The function '{}' makes a cross-program invocation without authority enforcement.",
                    hyp.id, hyp.primary_function
                ),
                invalidation_condition: "CPI target is a trusted program, or authority check \
                    validates the CPI call before execution.".into(),
            });

            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-CPI-{}-2", hyp.id.0)),
                assumption_type: AssumptionType::AuthorityCheckAbsent,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on the absence of authority checks before CPI. \
                     Without authority, any caller can trigger the cross-program invocation.",
                    hyp.id
                ),
                invalidation_condition: "Authority check (Signer, has_one) validates the caller \
                    before the CPI call is made."
                    .into(),
            });
        }

        HypothesisType::StateCorruptionCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-STATE-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::MultipleWritersExist,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on multiple functions writing to the same state. \
                     Uncoordinated writes can lead to inconsistent state.",
                    hyp.id
                ),
                invalidation_condition: "Only one function writes to the state variable, \
                    or all writers are coordinated through a single entry point."
                    .into(),
            });

            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-STATE-{}-2", hyp.id.0)),
                assumption_type: AssumptionType::CoordinationMissing,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on the absence of coordination between writers. \
                     Without synchronization, concurrent writes can corrupt state.",
                    hyp.id
                ),
                invalidation_condition: "A mutex, lock, or single-writer pattern ensures \
                    only one writer can modify state at a time."
                    .into(),
            });

            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-STATE-{}-3", hyp.id.0)),
                assumption_type: AssumptionType::SharedStateMutable,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on the shared state being mutable. \
                     If the state were immutable, corruption would not be possible.",
                    hyp.id
                ),
                invalidation_condition: "The state variable is declared as constant or immutable."
                    .into(),
            });
        }

        HypothesisType::EconomicInvariantViolationCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-ECON-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::SharedStateMutable,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on the economic invariant being violated. \
                     The invariant must hold for protocol solvency.",
                    hyp.id
                ),
                invalidation_condition:
                    "Economic invariant is properly enforced by all code paths.".into(),
            });
        }

        HypothesisType::AdversarialPathCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-ADV-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::ExternalTargetControlled,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on the adversarial path being feasible. \
                     The attacker must have the required capabilities.",
                    hyp.id
                ),
                invalidation_condition:
                    "Attacker lacks required capabilities or prerequisites are not met.".into(),
            });
        }

        HypothesisType::OracleManipulationCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-ORACLE-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::SharedStateMutable,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on writable state variables being used \
                     for value computation without external feed validation. \
                     The state variables must be mutable for manipulation to occur.",
                    hyp.id
                ),
                invalidation_condition:
                    "State variables are immutable, or an external oracle feed is used \
                     for price/rate computation."
                        .into(),
            });

            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-ORACLE-{}-2", hyp.id.0)),
                assumption_type: AssumptionType::ExternalTargetControlled,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on the absence of external oracle validation. \
                     If an external feed were used, internal state manipulation would not affect output.",
                    hyp.id
                ),
                invalidation_condition:
                    "An external oracle or TWAP feed is integrated for price/rate input.".into(),
            });
        }

        HypothesisType::FlashLoanGovernanceCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-FLGOV-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::SharedStateMutable,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on shared mutable balance/deposit state \
                     being read by a value-distributing function without temporal guard. \
                     An attacker can inflate the balance via flash loan before the read.",
                    hyp.id
                ),
                invalidation_condition:
                    "A temporal guard (block.number/timestamp check, timelock, cooldown) \
                     prevents same-block balance manipulation, or the function does not \
                     read shared mutable state."
                        .into(),
            });

            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-FLGOV-{}-2", hyp.id.0)),
                assumption_type: AssumptionType::CallerInfluencePossible,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on the caller being able to influence the \
                     value distribution decision through flash-loan balance inflation. \
                     Without authority checks, any caller can exploit this pattern.",
                    hyp.id
                ),
                invalidation_condition:
                    "Authority check restricts who can trigger the function, or the \
                     distribution amount is not derived from the inflated balance."
                        .into(),
            });
        }

        HypothesisType::MissingAccountConstraintCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-ACCT-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::SharedStateMutable,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on an Anchor instruction account \
                     lacking a required constraint (signer, has_one, owner, or PDA seeds). \
                     Without this constraint, any caller can pass an arbitrary account.",
                    hyp.id
                ),
                invalidation_condition:
                    "The account has a proper constraint annotation (#[account(constraint = ...)] \
                     or #[account(has_one = ...)] or Signer<'info> type)."
                        .into(),
            });
        }
        HypothesisType::UncheckedArithmeticCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-UNCHECK-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::ExternalTargetControlled,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on arithmetic inside an unchecked block \
                     where overflow is not checked. If the result feeds a value transfer, \
                     precision loss or overflow may alter the intended amount.",
                    hyp.id
                ),
                invalidation_condition:
                    "The unchecked block is removed and replaced with checked arithmetic, \
                     or the arithmetic result is bounded/validated before use."
                        .into(),
            });
        }
        HypothesisType::PrecisionLossCandidate => {
            assumptions.push(Assumption {
                id: AssumptionId(format!("ASM-PC-{}-1", hyp.id.0)),
                assumption_type: AssumptionType::ExternalTargetControlled,
                source_hypothesis_id: hyp.id.clone(),
                source_compound_hypothesis_id: None,
                supporting_evidence_ids: hyp
                    .evidence
                    .iter()
                    .map(|e| e.evidence_chain_id.clone())
                    .collect(),
                explanation: format!(
                    "Hypothesis '{}' depends on a division-before-multiplication \
                     pattern where truncated division feeds into a multiplication \
                     that flows into a value transfer. This precision-loss ordering \
                     may silently reduce the computed amount.",
                    hyp.id
                ),
                invalidation_condition:
                    "The expression ordering is changed to multiply-then-divide, \
                     or a bounded-division pattern (mulDiv/mulDivDown) is used."
                        .into(),
            });
        }
    }

    assumptions
}

/// Build summary statistics.
fn build_summary(assumptions: &[Assumption]) -> AssumptionSummary {
    AssumptionSummary {
        total: assumptions.len(),
        external_target_controlled: assumptions
            .iter()
            .filter(|a| a.assumption_type == AssumptionType::ExternalTargetControlled)
            .count(),
        reentrant_execution_possible: assumptions
            .iter()
            .filter(|a| a.assumption_type == AssumptionType::ReentrantExecutionPossible)
            .count(),
        authority_check_absent: assumptions
            .iter()
            .filter(|a| a.assumption_type == AssumptionType::AuthorityCheckAbsent)
            .count(),
        shared_state_mutable: assumptions
            .iter()
            .filter(|a| a.assumption_type == AssumptionType::SharedStateMutable)
            .count(),
        cpi_trust_required: assumptions
            .iter()
            .filter(|a| a.assumption_type == AssumptionType::CPITrustRequired)
            .count(),
        state_mutation_after_call: assumptions
            .iter()
            .filter(|a| a.assumption_type == AssumptionType::StateMutationAfterCall)
            .count(),
        multiple_writers_exist: assumptions
            .iter()
            .filter(|a| a.assumption_type == AssumptionType::MultipleWritersExist)
            .count(),
        coordination_missing: assumptions
            .iter()
            .filter(|a| a.assumption_type == AssumptionType::CoordinationMissing)
            .count(),
        caller_influence_possible: assumptions
            .iter()
            .filter(|a| a.assumption_type == AssumptionType::CallerInfluencePossible)
            .count(),
    }
}
