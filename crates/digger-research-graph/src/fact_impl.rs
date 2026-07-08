//! Shared deterministic provenance + `RecoveredFact` impl macro for
//! research-graph facts. Provenance is shared via `digger-gen5-common`.

/// Deterministic provenance for a DERIVED research-graph fact.
/// Re-exported from `digger-gen5-common`.
pub use ::digger_gen5_common::derive_provenance;

/// Implements the reconstruction `RecoveredFact` trait for local graph facts.
macro_rules! impl_graph_fact {
    ($($t:ty),+ $(,)?) => {
        $(impl ::digger_reconstruct::fact::RecoveredFact for $t {
            fn fact_id(&self) -> &str { &self.id }
            fn provenance(&self) -> &::digger_reconstruct::provenance::Provenance {
                &self.provenance
            }
        })+
    };
}
