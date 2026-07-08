#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

//! Shared deterministic helpers for Generation 5 crates.
//!
//! This crate centralizes the id/addressing helpers and provenance derivation
//! that every Gen 5 crate (protocol-model, investigation, research-graph,
//! research-context) needs. It depends only on `digger-reconstruct` (for
//! `node_id`, `digest_str`, and the `RecoveredFact` trait + provenance types).

// Re-export the reconstruction identity primitives so all Gen 5 crates use
// the same `node_id` and `digest_str` without each crate depending on
// digger-reconstruct's internal module layout.
pub use ::digger_reconstruct::digest::digest_str;
pub use ::digger_reconstruct::lifter::node_id;

/// Canonical join of parts with `|` (stable, order-sensitive by caller).
pub fn canon(parts: &[&str]) -> String {
    parts.join("|")
}

/// Deterministically normalize a set of fact ids: sort + dedup + join with `,`.
pub fn join_ids(ids: &[String]) -> String {
    let mut v: Vec<String> = ids.to_vec();
    v.sort();
    v.dedup();
    v.join(",")
}

/// Sort + dedup a vector of fact ids in place (deterministic order).
pub fn normalize_ids(ids: &mut Vec<String>) {
    ids.sort();
    ids.dedup();
}

/// Sort + dedup a vector of strings, returning a new owned vec.
pub fn sorted_unique(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

/// Deterministic provenance for a DERIVED Gen 5 fact.
///
/// All Gen 5 derived facts share the same provenance construction:
/// - originating evidence = [`EvidenceSource::Inferred`] (deduced, never observed),
/// - stage = [`ReconstructionStage::Enrich`] (higher-level facts derived from
///   recovered facts -- precedes `Normalize`/SystemIR emission),
/// - confidence = [`ConfidenceTier::Inferred`] (deterministic deduction),
/// - `basis` records the exact supporting fact ids.
///
/// The reproducibility key is content-addressed over `input`, so identical
/// inputs always reproduce an identical provenance. No scoring, no heuristics.
pub fn derive_provenance(input: &str, basis: &str) -> ::digger_reconstruct::provenance::Provenance {
    use ::digger_reconstruct::confidence::ConfidenceTier;
    use ::digger_reconstruct::provenance::{EvidenceSource, Provenance, ReconstructionStage};

    Provenance::new(
        EvidenceSource::Inferred,
        ReconstructionStage::Enrich,
        ConfidenceTier::Inferred,
        input,
    )
    .with_basis(basis)
}

/// Implements the reconstruction `RecoveredFact` trait for local Gen 5 facts.
/// Each fact must expose `id` and `provenance` fields; confidence and
/// reproducibility default to the provenance values.
#[macro_export]
macro_rules! impl_gen5_fact {
    ($($t:ty),+ $(,)?) => {
        $(impl ::digger_reconstruct::fact::RecoveredFact for $t {
            fn fact_id(&self) -> &str { &self.id }
            fn provenance(&self) -> &::digger_reconstruct::provenance::Provenance {
                &self.provenance
            }
        })+
    };
}

#[cfg(test)]
mod tests;
