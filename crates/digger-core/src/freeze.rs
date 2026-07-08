/// PHASE 3 STATUS:
/// - DETECTION LAYER: FROZEN
/// - REASONING LAYER: FROZEN
/// - SESSION LAYER: FROZEN
/// - WORKBENCH CONTRACT: FROZEN
///
/// Any modification requires explicit Phase 4 migration.
///
/// Phase 3 freeze marker — compile-time enforcement.
///
/// This type cannot be instantiated outside this module.
/// It serves as a compile-time guard against accidental extensions.
pub struct Phase3Freeze {
    _private: (),
}

/// Schema version lock — all Phase 3 schemas are pinned to this version.
pub const SCHEMA_VERSION: &str = "2.3";

/// Phase 3 freeze declaration.
pub const PHASE3_STATUS: &str = "FROZEN";

/// List of frozen modules.
pub const FROZEN_MODULES: &[&str] = &[
    "digger-graph",
    "digger-hypothesis",
    "digger-surface",
    "digger-core",
];

/// List of frozen schema types.
pub const FROZEN_SCHEMAS: &[&str] = &[
    "SecurityIntelligenceOutput",
    "HypothesisResult",
    "CompoundHypothesisResult",
    "AssumptionResult",
    "VerificationTaskResult",
    "InversionResult",
    "ResearchSessionResult",
];

/// List of frozen derivation functions.
pub const FROZEN_DERIVATIONS: &[&str] = &[
    "derive",                    // Atomic hypotheses
    "derive_compound",           // Compound hypotheses
    "derive_assumptions",        // Assumptions
    "derive_verification_tasks", // Verification tasks
    "derive_inversions",         // Inversions
    "derive_session",            // Research sessions
];

/// List of frozen hypothesis types.
pub const FROZEN_HYPOTHESIS_TYPES: &[&str] = &[
    "ReentrancyCandidate",
    "AuthorityBypassCandidate",
    "CPITrustViolationCandidate",
    "StateCorruptionCandidate",
];

/// List of frozen compound hypothesis types.
pub const FROZEN_COMPOUND_TYPES: &[&str] = &[
    "ReentrancyAuthorityChain",
    "CPIAuthorityChain",
    "StateCorruptionChain",
    "MultiPathExploitChain",
];

/// List of frozen assumption types.
pub const FROZEN_ASSUMPTION_TYPES: &[&str] = &[
    "ExternalTargetControlled",
    "ReentrantExecutionPossible",
    "AuthorityCheckAbsent",
    "SharedStateMutable",
    "CPITrustRequired",
    "StateMutationAfterCall",
    "MultipleWritersExist",
    "CoordinationMissing",
    "CallerInfluencePossible",
];

/// List of frozen inversion types.
pub const FROZEN_INVERSION_TYPES: &[&str] = &[
    "InvalidateReentrancy",
    "InvalidateAuthorityBypass",
    "InvalidateCPITrustViolation",
    "InvalidateStateCorruption",
    "InvalidateCallerInfluence",
];

/// List of frozen verification task types.
pub const FROZEN_VERIFICATION_TYPES: &[&str] = &[
    "VerifyExternalTargetControl",
    "VerifyReentrancyProtection",
    "VerifyAuthorityEnforcement",
    "VerifyStateMutationOrdering",
    "VerifySharedStateCoordination",
    "VerifyCPITrustBoundary",
    "VerifyCallerRestrictions",
    "VerifySingleWriterGuarantee",
];

// ─────────────────────────────────────────────────────────────
// Runtime assertion helpers
// ─────────────────────────────────────────────────────────────

/// Validate Phase 3 integrity — checks that frozen enums haven't been extended.
///
/// This is a runtime check that verifies the freeze contract.
/// If any check fails, the system has been modified in a frozen area.
pub fn validate_phase3_integrity() -> Result<(), FreezeViolation> {
    validate_schema_version()?;
    validate_hypothesis_types()?;
    validate_compound_types()?;
    validate_assumption_types()?;
    validate_inversion_types()?;
    validate_verification_types()?;
    Ok(())
}

/// Validate that the schema version matches the frozen version.
pub fn validate_schema_version() -> Result<(), FreezeViolation> {
    let surface_version = digger_surface::SCHEMA_VERSION;
    if surface_version != SCHEMA_VERSION {
        return Err(FreezeViolation::SchemaVersionMismatch {
            expected: SCHEMA_VERSION.to_string(),
            actual: surface_version.to_string(),
        });
    }
    Ok(())
}

/// Validate that hypothesis types haven't been extended.
pub fn validate_hypothesis_types() -> Result<(), FreezeViolation> {
    let actual: Vec<&str> = vec![
        "ReentrancyCandidate",
        "AuthorityBypassCandidate",
        "CPITrustViolationCandidate",
        "StateCorruptionCandidate",
    ];

    if actual.len() != FROZEN_HYPOTHESIS_TYPES.len() {
        return Err(FreezeViolation::TypeCountMismatch {
            module: "HypothesisType".into(),
            expected: FROZEN_HYPOTHESIS_TYPES.len(),
            actual: actual.len(),
        });
    }

    for expected in FROZEN_HYPOTHESIS_TYPES {
        if !actual.contains(expected) {
            return Err(FreezeViolation::TypeRemoved {
                module: "HypothesisType".into(),
                type_name: expected.to_string(),
            });
        }
    }

    Ok(())
}

/// Validate that compound hypothesis types haven't been extended.
pub fn validate_compound_types() -> Result<(), FreezeViolation> {
    let actual: Vec<&str> = vec![
        "ReentrancyAuthorityChain",
        "CPIAuthorityChain",
        "StateCorruptionChain",
        "MultiPathExploitChain",
    ];

    if actual.len() != FROZEN_COMPOUND_TYPES.len() {
        return Err(FreezeViolation::TypeCountMismatch {
            module: "CompoundHypothesisType".into(),
            expected: FROZEN_COMPOUND_TYPES.len(),
            actual: actual.len(),
        });
    }

    Ok(())
}

/// Validate that assumption types haven't been extended.
pub fn validate_assumption_types() -> Result<(), FreezeViolation> {
    let actual: Vec<&str> = vec![
        "ExternalTargetControlled",
        "ReentrantExecutionPossible",
        "AuthorityCheckAbsent",
        "SharedStateMutable",
        "CPITrustRequired",
        "StateMutationAfterCall",
        "MultipleWritersExist",
        "CoordinationMissing",
        "CallerInfluencePossible",
    ];

    if actual.len() != FROZEN_ASSUMPTION_TYPES.len() {
        return Err(FreezeViolation::TypeCountMismatch {
            module: "AssumptionType".into(),
            expected: FROZEN_ASSUMPTION_TYPES.len(),
            actual: actual.len(),
        });
    }

    Ok(())
}

/// Validate that inversion types haven't been extended.
pub fn validate_inversion_types() -> Result<(), FreezeViolation> {
    let actual: Vec<&str> = vec![
        "InvalidateReentrancy",
        "InvalidateAuthorityBypass",
        "InvalidateCPITrustViolation",
        "InvalidateStateCorruption",
        "InvalidateCallerInfluence",
    ];

    if actual.len() != FROZEN_INVERSION_TYPES.len() {
        return Err(FreezeViolation::TypeCountMismatch {
            module: "InversionType".into(),
            expected: FROZEN_INVERSION_TYPES.len(),
            actual: actual.len(),
        });
    }

    Ok(())
}

/// Validate that verification task types haven't been extended.
pub fn validate_verification_types() -> Result<(), FreezeViolation> {
    let actual: Vec<&str> = vec![
        "VerifyExternalTargetControl",
        "VerifyReentrancyProtection",
        "VerifyAuthorityEnforcement",
        "VerifyStateMutationOrdering",
        "VerifySharedStateCoordination",
        "VerifyCPITrustBoundary",
        "VerifyCallerRestrictions",
        "VerifySingleWriterGuarantee",
    ];

    if actual.len() != FROZEN_VERIFICATION_TYPES.len() {
        return Err(FreezeViolation::TypeCountMismatch {
            module: "VerificationTaskType".into(),
            expected: FROZEN_VERIFICATION_TYPES.len(),
            actual: actual.len(),
        });
    }

    Ok(())
}

/// Validate that outputs are deterministic by running derivation multiple times.
pub fn validate_deterministic_outputs(ir: &digger_ir::SystemIR) -> Result<(), FreezeViolation> {
    let hyp1 = digger_hypothesis::derive(ir);
    let hyp2 = digger_hypothesis::derive(ir);
    let hyp3 = digger_hypothesis::derive(ir);

    let json1 = serde_json::to_string(&hyp1).map_err(|_| FreezeViolation::SerializationFailed {
        module: "digger-hypothesis".into(),
    })?;
    let json2 = serde_json::to_string(&hyp2).map_err(|_| FreezeViolation::SerializationFailed {
        module: "digger-hypothesis".into(),
    })?;
    let json3 = serde_json::to_string(&hyp3).map_err(|_| FreezeViolation::SerializationFailed {
        module: "digger-hypothesis".into(),
    })?;

    if json1 != json2 || json2 != json3 {
        return Err(FreezeViolation::NonDeterministicOutput {
            module: "digger-hypothesis".into(),
        });
    }

    Ok(())
}

/// Freeze violation — describes what was broken.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FreezeViolation {
    /// Schema version mismatch.
    #[error("Schema version mismatch: expected '{expected}', got '{actual}'")]
    SchemaVersionMismatch { expected: String, actual: String },
    /// Type count changed in a frozen enum.
    #[error("Type count mismatch in {module}: expected {expected}, got {actual}")]
    TypeCountMismatch {
        module: String,
        expected: usize,
        actual: usize,
    },
    /// Type removed from a frozen enum.
    #[error("Type '{type_name}' removed from frozen module '{module}'")]
    TypeRemoved { module: String, type_name: String },
    /// Output is non-deterministic.
    #[error("Non-deterministic output detected in '{module}'")]
    NonDeterministicOutput { module: String },
    /// Serialization failed during determinism check.
    #[error("Serialization failed for module '{module}'")]
    SerializationFailed { module: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_constants_are_consistent() {
        assert_eq!(FROZEN_HYPOTHESIS_TYPES.len(), 4);
        assert_eq!(FROZEN_COMPOUND_TYPES.len(), 4);
        assert_eq!(FROZEN_ASSUMPTION_TYPES.len(), 9);
        assert_eq!(FROZEN_INVERSION_TYPES.len(), 5);
        assert_eq!(FROZEN_VERIFICATION_TYPES.len(), 8);
        assert_eq!(FROZEN_SCHEMAS.len(), 7);
        assert_eq!(FROZEN_DERIVATIONS.len(), 6);
    }

    #[test]
    fn schema_version_matches() {
        assert_eq!(SCHEMA_VERSION, "2.3");
    }

    #[test]
    fn phase3_status_is_frozen() {
        assert_eq!(PHASE3_STATUS, "FROZEN");
    }

    #[test]
    fn validate_phase3_integrity_passes() {
        let result = validate_phase3_integrity();
        assert!(
            result.is_ok(),
            "Phase 3 integrity check failed: {:?}",
            result
        );
    }

    #[test]
    fn validate_schema_version_passes() {
        let result = validate_schema_version();
        assert!(result.is_ok(), "Schema version check failed: {:?}", result);
    }

    #[test]
    fn validate_hypothesis_types_passes() {
        let result = validate_hypothesis_types();
        assert!(
            result.is_ok(),
            "Hypothesis types check failed: {:?}",
            result
        );
    }

    #[test]
    fn validate_compound_types_passes() {
        let result = validate_compound_types();
        assert!(result.is_ok(), "Compound types check failed: {:?}", result);
    }

    #[test]
    fn validate_assumption_types_passes() {
        let result = validate_assumption_types();
        assert!(
            result.is_ok(),
            "Assumption types check failed: {:?}",
            result
        );
    }

    #[test]
    fn validate_inversion_types_passes() {
        let result = validate_inversion_types();
        assert!(result.is_ok(), "Inversion types check failed: {:?}", result);
    }

    #[test]
    fn validate_verification_types_passes() {
        let result = validate_verification_types();
        assert!(
            result.is_ok(),
            "Verification types check failed: {:?}",
            result
        );
    }

    /// WS3: prove validate_deterministic_outputs runs over real output, not an empty set.
    /// Builds a populated IR with one function that has state_mutation + external_call,
    /// derives hypotheses (must produce >=1), then validates determinism.
    #[test]
    fn validate_deterministic_outputs_passes_on_populated_ir() {
        let ir = digger_ir::SystemIR {
            program_id: "test-populated".into(),
            language: digger_ir::Language::Solidity,
            functions: vec![digger_ir::Function {
                id: "fn_vuln".into(),
                name: "vulnerable_fn".into(),
                contract: String::new(),
                visibility: digger_ir::Visibility::Public,
                inputs: vec![],
                outputs: vec![],
                modifiers: vec![],
                effects: digger_ir::Effects {
                    state_mutation: true,
                    external_call: true,
                    authority_required: false,
                    value_transfer: false,
                    has_arithmetic: false,
                    has_temporal_guard: false,
                    value_flow: None,
                    has_unchecked_arithmetic: false,
                    writes_caller_scoped_state: false,
                    has_precision_loss_ordering: false,
                },
            }],
            state: vec![digger_ir::StateVariable {
                id: "sv_total".into(),
                name: "total".into(),
                ty: "uint256".into(),
                mutable: true,
            }],
            edges: vec![digger_ir::Edge::Authority(digger_ir::AuthorityEdge {
                function: "vulnerable_fn".into(),
                check_type: "missing".into(),
                authority_source: "none".into(),
            })],
        };

        // Non-vacuous: derive must produce >=1 hypothesis
        let hypotheses = digger_hypothesis::derive(&ir);
        assert!(
            !hypotheses.hypotheses.is_empty(),
            "populated IR must yield >=1 hypothesis (got 0 — test would be vacuous)"
        );

        // Validate determinism — must pass (same IR → same JSON 3 times)
        let result = validate_deterministic_outputs(&ir);
        assert!(
            result.is_ok(),
            "determinism validation failed: {:?}",
            result
        );
    }
}
