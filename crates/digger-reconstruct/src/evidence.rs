//! Evidence items and the IMMUTABLE, VERSIONED EvidenceBundle fusion SEAM
//! (ADR-0012 reserved). A1 provides deterministic assembly only.
//!
//! ## Evidence Categories (A3 / ADR-0013)
//! Every [`EvidenceItem`] belongs to EXACTLY ONE [`EvidenceCategory`]. The
//! category is the deterministic *provenance class* of the evidence and is
//! independent of how it was transported. [`EvidenceCategory::for_source`] is a
//! TOTAL, deterministic mapping from [`EvidenceSource`] to a default category;
//! providers that need a transport-specific class (e.g. RPC-fetched bytecode)
//! construct items with [`EvidenceItem::categorized`].

use crate::digest::{digest_str, fnv1a_64};
use crate::provenance::{EvidenceSource, Provenance};
use serde::{Deserialize, Serialize};

/// Current EvidenceBundle schema/semantics version.
pub const EVIDENCE_BUNDLE_VERSION: u32 = 1;

/// Deterministic provenance class. Every EvidenceItem has exactly one. These
/// categories drive explainability and future Research Graph queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceCategory {
    CodeEvidence,
    BytecodeEvidence,
    MetadataEvidence,
    RpcEvidence,
    KnowledgeEvidence,
    UserEvidence,
}

impl EvidenceCategory {
    /// TOTAL deterministic default mapping. Every `EvidenceSource` variant maps
    /// to exactly one category. RPC-transported evidence overrides this via
    /// [`EvidenceItem::categorized`] (RPC is never privileged truth).
    pub fn for_source(source: EvidenceSource) -> Self {
        match source {
            EvidenceSource::SourceCode => EvidenceCategory::CodeEvidence,
            EvidenceSource::RuntimeBytecode
            | EvidenceSource::DeploymentBytecode
            | EvidenceSource::Selectors
            | EvidenceSource::Events
            | EvidenceSource::StorageRecovery => EvidenceCategory::BytecodeEvidence,
            EvidenceSource::Metadata => EvidenceCategory::MetadataEvidence,
            EvidenceSource::ProxyInfo | EvidenceSource::ExternalIntegration => {
                EvidenceCategory::RpcEvidence
            }
            EvidenceSource::Inferred => EvidenceCategory::KnowledgeEvidence,
        }
    }
}

/// A single piece of evidence collected before reconstruction. Belongs to
/// exactly one [`EvidenceCategory`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub category: EvidenceCategory,
    pub source: EvidenceSource,
    pub kind: String,
    pub payload: String,
    pub provenance: Provenance,
}

impl EvidenceItem {
    /// Category defaults deterministically from the source.
    pub fn new(
        source: EvidenceSource,
        kind: impl Into<String>,
        payload: impl Into<String>,
        provenance: Provenance,
    ) -> Self {
        EvidenceItem {
            category: EvidenceCategory::for_source(source),
            source,
            kind: kind.into(),
            payload: payload.into(),
            provenance,
        }
    }
    /// Explicit category (e.g. RPC transport, engine knowledge, user input).
    pub fn categorized(
        category: EvidenceCategory,
        source: EvidenceSource,
        kind: impl Into<String>,
        payload: impl Into<String>,
        provenance: Provenance,
    ) -> Self {
        EvidenceItem {
            category,
            source,
            kind: kind.into(),
            payload: payload.into(),
            provenance,
        }
    }
    pub fn digest(&self) -> String {
        digest_str(&format!(
            "{:?}|{:?}|{}|{}",
            self.category, self.source, self.kind, self.payload
        ))
    }
}

/// The single deterministic reconstruction input. IMMUTABLE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    bundle_version: u32,
    items: Vec<EvidenceItem>,
    bundle_digest: String,
}

impl EvidenceBundle {
    fn assemble(mut items: Vec<EvidenceItem>) -> Self {
        items.sort_by(|a, b| {
            let ka = (
                format!("{:?}", a.category),
                format!("{:?}", a.source),
                a.kind.clone(),
                a.digest(),
            );
            let kb = (
                format!("{:?}", b.category),
                format!("{:?}", b.source),
                b.kind.clone(),
                b.digest(),
            );
            ka.cmp(&kb)
        });
        let concat: String = items
            .iter()
            .map(|i| i.digest())
            .collect::<Vec<_>>()
            .join("|");
        let bundle_digest = fnv1a_64(concat.as_bytes());
        EvidenceBundle {
            bundle_version: EVIDENCE_BUNDLE_VERSION,
            items,
            bundle_digest,
        }
    }
    pub fn new(items: Vec<EvidenceItem>) -> Self {
        Self::assemble(items)
    }
    pub fn with_added(&self, more: Vec<EvidenceItem>) -> Self {
        let mut combined = self.items.clone();
        combined.extend(more);
        Self::assemble(combined)
    }
    pub fn bundle_version(&self) -> u32 {
        self.bundle_version
    }
    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }
    pub fn items(&self) -> &[EvidenceItem] {
        &self.items
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn has_multiple_sources(&self) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        for i in &self.items {
            seen.insert(format!("{:?}", i.source));
        }
        seen.len() > 1
    }
    /// Distinct evidence categories present (deterministic order).
    pub fn categories(&self) -> Vec<EvidenceCategory> {
        let mut seen = std::collections::BTreeSet::new();
        for i in &self.items {
            seen.insert(i.category);
        }
        seen.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::ConfidenceTier;
    use crate::provenance::ReconstructionStage;
    fn item(src: EvidenceSource, kind: &str, payload: &str, tier: ConfidenceTier) -> EvidenceItem {
        EvidenceItem::new(
            src,
            kind,
            payload,
            Provenance::new(src, ReconstructionStage::Fetch, tier, payload),
        )
    }
    #[test]
    fn every_source_maps_to_exactly_one_category() {
        // total mapping: never panics, always one category
        for s in [
            EvidenceSource::SourceCode,
            EvidenceSource::RuntimeBytecode,
            EvidenceSource::DeploymentBytecode,
            EvidenceSource::Metadata,
            EvidenceSource::StorageRecovery,
            EvidenceSource::Selectors,
            EvidenceSource::Events,
            EvidenceSource::ProxyInfo,
            EvidenceSource::ExternalIntegration,
            EvidenceSource::Inferred,
        ] {
            let _ = EvidenceCategory::for_source(s);
        }
        assert_eq!(
            EvidenceCategory::for_source(EvidenceSource::SourceCode),
            EvidenceCategory::CodeEvidence
        );
        assert_eq!(
            EvidenceCategory::for_source(EvidenceSource::RuntimeBytecode),
            EvidenceCategory::BytecodeEvidence
        );
        assert_eq!(
            EvidenceCategory::for_source(EvidenceSource::Metadata),
            EvidenceCategory::MetadataEvidence
        );
    }
    #[test]
    fn bundle_digest_order_independent_and_versioned() {
        let a = EvidenceBundle::new(vec![
            item(
                EvidenceSource::RuntimeBytecode,
                "runtime_bytecode",
                "0x6080",
                ConfidenceTier::Recovered,
            ),
            item(
                EvidenceSource::Metadata,
                "abi_fragment",
                "transfer(address,uint256)",
                ConfidenceTier::Inferred,
            ),
        ]);
        let b = EvidenceBundle::new(vec![
            item(
                EvidenceSource::Metadata,
                "abi_fragment",
                "transfer(address,uint256)",
                ConfidenceTier::Inferred,
            ),
            item(
                EvidenceSource::RuntimeBytecode,
                "runtime_bytecode",
                "0x6080",
                ConfidenceTier::Recovered,
            ),
        ]);
        assert_eq!(a.bundle_digest(), b.bundle_digest());
        assert_eq!(a.bundle_version(), 1);
        assert!(a.has_multiple_sources());
        assert!(a.categories().contains(&EvidenceCategory::BytecodeEvidence));
        assert!(a.categories().contains(&EvidenceCategory::MetadataEvidence));
    }
    #[test]
    fn user_and_knowledge_categories_are_explicit() {
        let u = EvidenceItem::categorized(
            EvidenceCategory::UserEvidence,
            EvidenceSource::Metadata,
            "user_hint",
            "is a vault",
            Provenance::new(
                EvidenceSource::Metadata,
                ReconstructionStage::Fetch,
                ConfidenceTier::Hypothesized,
                "user",
            ),
        );
        assert_eq!(u.category, EvidenceCategory::UserEvidence);
    }
}
