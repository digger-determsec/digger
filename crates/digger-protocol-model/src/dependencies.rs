//! External Dependencies (model view).
//!
//! Dependencies are already first-class recovered facts
//! ([`RecoveredDependency`]) produced by A3.3. To honor "no duplicate IR", the
//! protocol model REFERENCES those facts directly rather than redefining them:
//! the model stores the recovered dependencies as-is (each already implements
//! `RecoveredFact`, with provenance / confidence / reproducibility / id).
//!
//! This module provides a deterministic normalization helper so the model holds
//! a stable, sorted, de-duplicated dependency set.

use crate::RecoveredDependency;

/// Deterministically normalize the dependency set: sorted by fact id, deduped.
pub fn normalize_dependencies(dependencies: &[RecoveredDependency]) -> Vec<RecoveredDependency> {
    let mut out: Vec<RecoveredDependency> = dependencies.to_vec();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out.dedup_by(|a, b| a.id == b.id);
    out
}
