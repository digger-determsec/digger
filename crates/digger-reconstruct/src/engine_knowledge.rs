//! Engine Knowledge types (ADR-0010): globally reusable, content-addressed
//! reference data — NOT owned by any scan/project/org.
//!
//! ## Namespaced identifiers (refinement)
//! Knowledge categories use namespaced identifiers (e.g. `evm.selector`,
//! `protocol.fingerprint`) to scale across targets and avoid naming collisions.

use crate::digest::digest_str;
use crate::provenance::Provenance;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KnowledgeKind {
    EvmSelector,
    EvmProxy,
    EvmEvent,
    EvmAbi,
    ProtocolArchitecture,
    ProtocolFingerprint,
}

impl KnowledgeKind {
    /// Namespaced identifier (namespace.category).
    pub fn namespace_id(&self) -> &'static str {
        match self {
            KnowledgeKind::EvmSelector => "evm.selector",
            KnowledgeKind::EvmProxy => "evm.proxy",
            KnowledgeKind::EvmEvent => "evm.event",
            KnowledgeKind::EvmAbi => "evm.abi",
            KnowledgeKind::ProtocolArchitecture => "protocol.architecture",
            KnowledgeKind::ProtocolFingerprint => "protocol.fingerprint",
        }
    }
    /// Leading namespace segment (e.g. "evm", "protocol").
    pub fn namespace(&self) -> &'static str {
        self.namespace_id().split('.').next().unwrap_or("")
    }
}

/// A globally reusable knowledge entry. `key` is content-addressed and prefixed
/// by the namespaced identifier so the same fact deduplicates across all
/// sessions. Carries provenance (by value here; graph nodes reference
/// `provenance.id`) but NO owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineKnowledgeEntry {
    pub kind: KnowledgeKind,
    pub key: String,
    pub value: String,
    pub provenance: Provenance,
}

impl EngineKnowledgeEntry {
    pub fn new(kind: KnowledgeKind, value: impl Into<String>, provenance: Provenance) -> Self {
        let value = value.into();
        let key = format!("{}:{}", kind.namespace_id(), digest_str(&value));
        EngineKnowledgeEntry {
            kind,
            key,
            value,
            provenance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::ConfidenceTier;
    use crate::provenance::{EvidenceSource, ReconstructionStage};
    #[test]
    fn namespaced_content_addressed_key() {
        let p = Provenance::new(
            EvidenceSource::Selectors,
            ReconstructionStage::Recover,
            ConfidenceTier::Recovered,
            "0xa9059cbb",
        );
        let e =
            EngineKnowledgeEntry::new(KnowledgeKind::EvmSelector, "transfer(address,uint256)", p);
        assert!(e.key.starts_with("evm.selector:"));
        assert_eq!(KnowledgeKind::ProtocolFingerprint.namespace(), "protocol");
    }
}
