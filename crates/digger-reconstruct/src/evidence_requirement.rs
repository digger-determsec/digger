//! Deterministic, reproducible evidence requirements (Gen5 A3.3 / ADR-0017).
//!
//! Generalizes "unresolved" reconstruction. Instead of an ad-hoc `needs: String`,
//! every unresolved recovered object exposes a deterministic, reproducible list
//! of [`EvidenceRequirement`]s describing EXACTLY what evidence would complete
//! deterministic reconstruction. Future UI surfaces these to researchers.

use serde::{Deserialize, Serialize};

/// A single deterministic piece of evidence needed to finish reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceRequirement {
    /// A specific storage slot value is required (hex slot key).
    NeedsStorage(String),
    /// The implementation/code at a specific address is required.
    NeedsImplementation(String),
    /// A Solana ProgramData account is required (account key).
    NeedsProgramData(String),
    /// Contract/program metadata is required.
    NeedsMetadata,
    /// Verified source is required.
    NeedsSource,
    /// A live RPC read against an address is required.
    NeedsRpc(String),
    /// An explorer artifact (e.g. verified ABI / facet map) is required.
    NeedsExplorerArtifact,
    /// Raw bytecode is required.
    NeedsBytecode,
}

impl EvidenceRequirement {
    /// Stable kind tag (no payload), for grouping / UI filtering.
    pub fn kind(&self) -> &'static str {
        match self {
            EvidenceRequirement::NeedsStorage(_) => "NeedsStorage",
            EvidenceRequirement::NeedsImplementation(_) => "NeedsImplementation",
            EvidenceRequirement::NeedsProgramData(_) => "NeedsProgramData",
            EvidenceRequirement::NeedsMetadata => "NeedsMetadata",
            EvidenceRequirement::NeedsSource => "NeedsSource",
            EvidenceRequirement::NeedsRpc(_) => "NeedsRpc",
            EvidenceRequirement::NeedsExplorerArtifact => "NeedsExplorerArtifact",
            EvidenceRequirement::NeedsBytecode => "NeedsBytecode",
        }
    }
    /// Deterministic, human-surfaceable label (future UI).
    pub fn label(&self) -> String {
        match self {
            EvidenceRequirement::NeedsStorage(s) => format!("storage slot {}", s),
            EvidenceRequirement::NeedsImplementation(a) => format!("implementation code at {}", a),
            EvidenceRequirement::NeedsProgramData(a) => format!("program-data account {}", a),
            EvidenceRequirement::NeedsMetadata => "contract metadata".to_string(),
            EvidenceRequirement::NeedsSource => "verified source".to_string(),
            EvidenceRequirement::NeedsRpc(a) => format!("RPC read of {}", a),
            EvidenceRequirement::NeedsExplorerArtifact => "explorer artifact".to_string(),
            EvidenceRequirement::NeedsBytecode => "runtime bytecode".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_kind_and_label() {
        let r = EvidenceRequirement::NeedsStorage("0xabc".into());
        assert_eq!(r.kind(), "NeedsStorage");
        assert_eq!(r.label(), "storage slot 0xabc");
    }
    #[test]
    fn requirements_sort_deterministically() {
        let mut v = vec![
            EvidenceRequirement::NeedsSource,
            EvidenceRequirement::NeedsBytecode,
            EvidenceRequirement::NeedsMetadata,
        ];
        let mut w = v.clone();
        w.reverse();
        v.sort();
        w.sort();
        assert_eq!(v, w);
    }
}
