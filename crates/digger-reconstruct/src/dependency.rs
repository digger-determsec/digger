//! Recovered protocol dependencies (Gen5 A3.3 / ADR-0017).
//!
//! A [`RecoveredDependency`] is a deterministic PROTOCOL dependency -- tokens,
//! price oracles, routers, bridges, vaults, governance, external protocols,
//! shared infrastructure -- distinct from deployment and architecture. It is
//! blockchain-agnostic (`Evm`/`Solana`/`Move`/`Wasm` details) and is a
//! [`crate::fact::RecoveredFact`].
//!
//! A future `RecoveredArchitecture` CONSUMES dependencies; it never OWNS or
//! re-derives them. Dependency recovery is never merged into architecture.

use crate::deployment::RecoveredAddress;
use crate::lifter::node_id;
use crate::provenance::Provenance;
use serde::{Deserialize, Serialize};

/// Deterministic protocol-dependency classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DependencyKind {
    Token,
    PriceOracle,
    Router,
    Bridge,
    Vault,
    Governance,
    ExternalProtocol,
    SharedInfrastructure,
}

/// Chain-specific dependency detail. Exactly one variant is populated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyDetail {
    Evm(EvmDependency),
    Solana(SolanaDependency),
    Move(MoveDependency),
    Wasm(WasmDependency),
}

/// A deterministically recovered protocol dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredDependency {
    /// Deterministic content-addressed id (`dep:<digest>`).
    pub id: String,
    pub kind: DependencyKind,
    /// Where the dependency lives: resolved or honestly unresolved.
    pub address: RecoveredAddress,
    pub detail: DependencyDetail,
    pub provenance: Provenance,
}

impl RecoveredDependency {
    pub fn make_id(canon: &str) -> String {
        node_id("dep", canon)
    }
}

/// EVM dependency evidence (e.g. observed interface selectors that classify it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmDependency {
    pub observed_selectors: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaDependency {
    pub observed_program_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveDependency {
    pub observed_module_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmDependency {
    pub observed_import_refs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::ConfidenceTier;
    use crate::fact::RecoveredFact;
    use crate::provenance::{EvidenceSource, ReconstructionStage};
    #[test]
    fn dependency_is_a_recovered_fact() {
        let prov = Provenance::new(
            EvidenceSource::Selectors,
            ReconstructionStage::Recover,
            ConfidenceTier::Inferred,
            "dep|token|0xabc",
        );
        let d = RecoveredDependency {
            id: RecoveredDependency::make_id("token|0xabc"),
            kind: DependencyKind::Token,
            address: RecoveredAddress::Resolved("0xabc".into()),
            detail: DependencyDetail::Evm(EvmDependency {
                observed_selectors: vec!["0xa9059cbb".into()],
            }),
            provenance: prov,
        };
        assert!(d.fact_id().starts_with("dep:"));
        assert_eq!(d.confidence(), ConfidenceTier::Inferred);
    }
}
