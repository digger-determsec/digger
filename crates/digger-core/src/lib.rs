#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

/// PHASE 3 STATUS:
/// - DETECTION LAYER: FROZEN
/// - REASONING LAYER: FROZEN
/// - SESSION LAYER: FROZEN
/// - WORKBENCH CONTRACT: FROZEN
///
/// Any modification requires explicit Phase 4 migration.
pub mod freeze;

pub use freeze::{
    validate_assumption_types, validate_compound_types, validate_deterministic_outputs,
    validate_hypothesis_types, validate_inversion_types, validate_phase3_integrity,
    validate_schema_version, validate_verification_types, FreezeViolation, Phase3Freeze,
    FROZEN_ASSUMPTION_TYPES, FROZEN_COMPOUND_TYPES, FROZEN_DERIVATIONS, FROZEN_HYPOTHESIS_TYPES,
    FROZEN_INVERSION_TYPES, FROZEN_MODULES, FROZEN_SCHEMAS, FROZEN_VERIFICATION_TYPES,
    PHASE3_STATUS, SCHEMA_VERSION,
};
