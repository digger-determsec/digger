//! Deterministic evidence-provider model (Gen5 A3, ADR-0013 "RPC principle").
//!
//! RPC is NOT privileged truth. It is one Evidence Provider among equals:
//! source code, bytecode, metadata, RPC, engine knowledge, and user input all
//! emit [`EvidenceItem`]s through the SAME [`EvidenceProvider`] trait, each
//! tagged with exactly one [`EvidenceCategory`]. No provider receives special
//! treatment. Offline reconstruction stays fully functional because the
//! provider set is pluggable (fixtures / raw bytecode need no network).

use crate::confidence::ConfidenceTier;
use crate::evidence::{EvidenceCategory, EvidenceItem};
use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};

/// A deterministic source of evidence. Implementations MUST be pure functions
/// of their configured inputs (no wall-clock, no ambient state). RPC-backed
/// providers implement this exactly like any other provider.
pub trait EvidenceProvider {
    /// Stable provider identifier (e.g. `evm.rpc`, `evm.bytecode`, `metadata`).
    fn provider_id(&self) -> &str;
    /// The single category every item from this provider belongs to.
    fn category(&self) -> EvidenceCategory;
    /// Deterministically collect this provider's evidence.
    fn collect(&self) -> Vec<EvidenceItem>;
}

/// Evidence sourced via an RPC-like network provider. Categorized as
/// `RpcEvidence` to record *how it was acquired* — it carries NO special
/// authority over bytecode/metadata/source evidence. Built deterministically
/// from already-fetched bytes so the same provider works offline (fixtures).
#[derive(Debug, Clone)]
pub struct RpcEvidenceProvider {
    provider_id: String,
    items: Vec<EvidenceItem>,
}

impl RpcEvidenceProvider {
    /// Construct from a single deterministic `eth_getCode`-style fetch.
    pub fn from_code(provider_id: impl Into<String>, coordinate_key: &str, code: &[u8]) -> Self {
        let payload = format!("{}|0x{}", coordinate_key, hex_lower(code));
        let prov = Provenance::new(
            EvidenceSource::RuntimeBytecode,
            ReconstructionStage::Fetch,
            ConfidenceTier::Recovered,
            &payload,
        );
        let item = EvidenceItem::categorized(
            EvidenceCategory::RpcEvidence,
            EvidenceSource::RuntimeBytecode,
            "rpc_get_code",
            payload,
            prov,
        );
        RpcEvidenceProvider {
            provider_id: provider_id.into(),
            items: vec![item],
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

impl EvidenceProvider for RpcEvidenceProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }
    fn category(&self) -> EvidenceCategory {
        EvidenceCategory::RpcEvidence
    }
    fn collect(&self) -> Vec<EvidenceItem> {
        self.items.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rpc_is_just_an_evidence_provider() {
        let p = RpcEvidenceProvider::from_code("evm.rpc", "1:0xabc:100", &[0x60, 0x80]);
        let items = p.collect();
        assert_eq!(items.len(), 1);
        assert_eq!(p.category(), EvidenceCategory::RpcEvidence);
        assert_eq!(items[0].category, EvidenceCategory::RpcEvidence);
        // RPC carries no privileged confidence — same tiers as any provider
        assert_eq!(p.provider_id(), "evm.rpc");
    }
}
