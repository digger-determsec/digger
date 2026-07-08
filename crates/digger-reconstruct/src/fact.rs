//! Canonical reconstruction object model (ADR-0015).
//!
//! EVERY reconstructed object in Generation 5 is a [`RecoveredFact`]: it exposes
//! a deterministic identifier, its provenance, a confidence tier, and a
//! reproducibility key. New recovered objects (selectors, proxies, storage
//! slots, accounts, permissions, authorities, trust boundaries, ...) implement
//! this trait so the Research Graph can treat every fact uniformly. Confidence
//! and reproducibility default to the values carried by the fact's provenance,
//! so a fact can never disagree with its own provenance.

use crate::confidence::ConfidenceTier;
use crate::provenance::{Provenance, ReproducibilityKey};

/// The common deterministic fact model shared by every reconstructed object.
pub trait RecoveredFact {
    /// Deterministic, content-addressed identifier (stable across runs).
    fn fact_id(&self) -> &str;
    /// Provenance describing why this fact exists.
    fn provenance(&self) -> &Provenance;
    /// Confidence tier (defaults to the provenance tier).
    fn confidence(&self) -> ConfidenceTier {
        self.provenance().confidence
    }
    /// Reproducibility key (defaults to the provenance key).
    fn reproducibility(&self) -> &ReproducibilityKey {
        &self.provenance().reproducibility
    }
}

macro_rules! impl_recovered_fact {
    ($($t:ty),+ $(,)?) => {
        $(impl RecoveredFact for $t {
            fn fact_id(&self) -> &str { &self.id }
            fn provenance(&self) -> &Provenance { &self.provenance }
        })+
    };
}

use crate::dependency::RecoveredDependency;
use crate::deployment::{
    CpiGraph, CpiNode, EvmDeployment, RecoveredAuthority, RecoveredDeployment, RecoveredProxy,
    SolanaDeployment,
};
use crate::interface::{
    RecoveredAbi, RecoveredAccount, RecoveredFunction, RecoveredInstructionLayout,
    RecoveredInterface, RecoveredSolanaInstruction,
};
use crate::lifter::RecoveredSelector;

impl_recovered_fact!(
    RecoveredSelector,
    RecoveredFunction,
    RecoveredAbi,
    RecoveredInterface,
    RecoveredSolanaInstruction,
    RecoveredInstructionLayout,
    RecoveredAccount,
    RecoveredDeployment,
    EvmDeployment,
    SolanaDeployment,
    RecoveredProxy,
    RecoveredAuthority,
    CpiGraph,
    CpiNode,
    RecoveredDependency,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::ConfidenceTier;
    use crate::lifter::node_id;
    use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};

    #[test]
    fn selector_is_a_fact_backed_by_its_provenance() {
        let prov = Provenance::new(
            EvidenceSource::Selectors,
            ReconstructionStage::Recover,
            ConfidenceTier::Recovered,
            "0xa9059cbb",
        );
        let sel = RecoveredSelector {
            id: node_id("sel", "0xa9059cbb"),
            selector: "0xa9059cbb".to_string(),
            bytes: vec![0xa9, 0x05, 0x9c, 0xbb],
            provenance: prov.clone(),
        };
        assert_eq!(sel.fact_id(), sel.id);
        assert_eq!(sel.confidence(), ConfidenceTier::Recovered);
        assert_eq!(sel.reproducibility(), &prov.reproducibility);
    }
}
