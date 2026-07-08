//! Fact-level provenance (ADR-0009). Every reconstructed fact that enters
//! SystemIR carries one of these so a future workspace can explain exactly
//! why the fact exists.
//!
//! ## Refinement: deterministic Provenance IDs
//! Every `Provenance` has a deterministic `id` derived ONLY from deterministic
//! inputs. Research Graph nodes reference provenance by `id` instead of
//! duplicating provenance data.

use crate::confidence::ConfidenceTier;
use crate::digest::{digest_str, fnv1a_64};
use crate::{RECONSTRUCTOR_CRATE, RECONSTRUCTOR_VERSION};
use serde::{Deserialize, Serialize};

/// Originating evidence for a reconstructed fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceSource {
    SourceCode,
    RuntimeBytecode,
    DeploymentBytecode,
    Metadata,
    StorageRecovery,
    Selectors,
    Events,
    ProxyInfo,
    ExternalIntegration,
    /// Deduced rather than directly observed (always < Authoritative).
    Inferred,
}

/// The reconstruction stage that produced a fact.
///
/// ## FROZEN lifecycle (Generation 5)
/// The complete, ordered stage lifecycle is:
/// 1. `Fetch`       — retrieve raw evidence (RPC / raw bytecode / source / metadata).
/// 2. `Disassemble` — decode opcodes into instructions (no semantics yet).
/// 3. `Lift`        — build basic blocks + control-flow graph from instructions.
/// 4. `Recover`     — recover dispatcher, jump targets, selectors, functions.
/// 5. `Fuse`        — Evidence Fusion seam (deterministic; ratified by ADR-0012).
/// 6. `Enrich`      — attach corroborating evidence (metadata/ABI) to recovered facts.
/// 7. `Normalize`   — emit canonical `digger_ir::SystemIR`.
///
/// This enum is FROZEN. Do NOT extend it casually now that Generation 5 has
/// begun — any new stage requires an ADR (see
/// `docs/generation-5/04-reconstruction-data-flow.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReconstructionStage {
    Fetch,
    Disassemble,
    Lift,
    Recover,
    Fuse,
    Enrich,
    Normalize,
}

/// Deterministic reproducibility key: same `input_digest` + same reconstructor
/// version reproduces an identical fact (Principle 1, ADR-0009).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReproducibilityKey {
    pub input_digest: String,
    pub reconstructor_crate: String,
    pub reconstructor_version: String,
}

impl ReproducibilityKey {
    pub fn from_input(input: &str) -> Self {
        ReproducibilityKey {
            input_digest: digest_str(input),
            reconstructor_crate: RECONSTRUCTOR_CRATE.to_string(),
            reconstructor_version: RECONSTRUCTOR_VERSION.to_string(),
        }
    }
}

/// Provenance attached to a single reconstructed fact. The `id` is deterministic
/// and content-addressed; equal provenance inputs always yield the same `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub id: String,
    pub originating_evidence: EvidenceSource,
    pub stage: ReconstructionStage,
    pub confidence: ConfidenceTier,
    pub reproducibility: ReproducibilityKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
}

impl Provenance {
    /// Compute the deterministic id from deterministic inputs ONLY.
    fn compute_id(
        ev: &EvidenceSource,
        stage: &ReconstructionStage,
        conf: &ConfidenceTier,
        repro: &ReproducibilityKey,
        basis: &Option<String>,
    ) -> String {
        let canon = format!(
            "{:?}|{:?}|{:?}|{}|{}|{}|{}",
            ev,
            stage,
            conf,
            repro.input_digest,
            repro.reconstructor_crate,
            repro.reconstructor_version,
            basis.as_deref().unwrap_or("")
        );
        format!("prov:{}", fnv1a_64(canon.as_bytes()))
    }

    pub fn new(
        originating_evidence: EvidenceSource,
        stage: ReconstructionStage,
        confidence: ConfidenceTier,
        input: &str,
    ) -> Self {
        let reproducibility = ReproducibilityKey::from_input(input);
        let basis = None;
        let id = Self::compute_id(
            &originating_evidence,
            &stage,
            &confidence,
            &reproducibility,
            &basis,
        );
        Provenance {
            id,
            originating_evidence,
            stage,
            confidence,
            reproducibility,
            basis,
        }
    }

    /// Returns a NEW provenance with the basis set; `id` is recomputed so it
    /// stays a deterministic function of all inputs.
    pub fn with_basis(self, basis: impl Into<String>) -> Self {
        let basis = Some(basis.into());
        let id = Self::compute_id(
            &self.originating_evidence,
            &self.stage,
            &self.confidence,
            &self.reproducibility,
            &basis,
        );
        Provenance { id, basis, ..self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_is_deterministic() {
        assert_eq!(
            ReproducibilityKey::from_input("0x6080"),
            ReproducibilityKey::from_input("0x6080")
        );
    }
    #[test]
    fn id_is_deterministic_and_basis_sensitive() {
        let a = Provenance::new(
            EvidenceSource::RuntimeBytecode,
            ReconstructionStage::Recover,
            ConfidenceTier::Recovered,
            "0x6080",
        );
        let b = Provenance::new(
            EvidenceSource::RuntimeBytecode,
            ReconstructionStage::Recover,
            ConfidenceTier::Recovered,
            "0x6080",
        );
        assert_eq!(a.id, b.id);
        let c = a.clone().with_basis("selector 0xa9059cbb");
        assert_ne!(a.id, c.id);
        assert!(c.id.starts_with("prov:"));
    }
}
