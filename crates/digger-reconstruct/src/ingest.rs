//! On-demand ingestion adapter (C5.4, Stage 1).
//!
//! Fetches bytecode/account artifacts for a target and records provenance.
//! Deterministic + cached: same target → same artifact. No network in tests.
//! Never fabricates bytecode.
//!
//! ## Design
//!
//! ```text
//! IngestionTarget → IngestionAdapter::fetch → IngestionArtifact
//!                                                  ↓
//!                                        EvidenceInput (for reconstruct())
//! ```
//!
//! The adapter produces artifacts that include full provenance metadata
//! (address, chain, block, fetched_at). The pipeline uses the artifact
//! to build `EvidenceInput` and feed the reconstruction engine.

use crate::confidence::ConfidenceTier;
use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};
use serde::{Deserialize, Serialize};

/// What to fetch — the target specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngestionTarget {
    /// EVM contract: address + chain.
    Evm { address: String, chain: String },
    /// Solana program: program id.
    Solana { program_id: String },
}

/// Fetched artifact with full provenance metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionArtifact {
    /// The target this artifact was fetched for.
    pub target: IngestionTarget,
    /// Runtime bytecode (EVM) or program bytes (Solana).
    pub bytecode: Vec<u8>,
    /// Additional metadata (ABI, IDL, source verification, etc.).
    pub metadata: ArtifactMetadata,
    /// Provenance recording how/when this artifact was obtained.
    pub provenance: Provenance,
}

/// Metadata about the fetched artifact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    /// Block number or slot at which the artifact was fetched.
    pub block_number: Option<u64>,
    /// Whether the bytecode was verified on-chain.
    pub verified: bool,
    /// Additional chain-specific metadata.
    pub extra: std::collections::BTreeMap<String, String>,
}

/// Trait for fetching artifacts from a target. Implementors must be deterministic:
/// same inputs → same outputs.
pub trait IngestionAdapter {
    fn fetch(&self, target: &IngestionTarget) -> Result<IngestionArtifact, IngestionError>;
}

/// Errors during ingestion.
#[derive(Debug, Clone, thiserror::Error)]
pub enum IngestionError {
    /// Target not found or invalid.
    #[error("target not found: {0}")]
    NotFound(String),
    /// Network or provider error (should not happen in fixture mode).
    #[error("provider error: {0}")]
    ProviderError(String),
    /// Bytecode was fabricated or invalid.
    #[error("invalid bytecode: {0}")]
    InvalidBytecode(String),
}

/// Fixture-based adapter for tests. Loads pre-fetched bytecode from files.
/// No network access. Deterministic by construction.
pub struct FixtureAdapter {
    /// Root directory containing fixture artifacts.
    /// Expected layout: <root>/<chain>/<address>/bytecode.hex
    root: std::path::PathBuf,
}

impl FixtureAdapter {
    pub fn new(root: std::path::PathBuf) -> Self {
        Self { root }
    }
}

impl IngestionAdapter for FixtureAdapter {
    fn fetch(&self, target: &IngestionTarget) -> Result<IngestionArtifact, IngestionError> {
        match target {
            IngestionTarget::Evm { address, chain } => {
                let path = self.root.join(chain).join(format!("{}.hex", address));
                let hex_str = std::fs::read_to_string(&path)
                    .map_err(|e| IngestionError::NotFound(format!("{}: {}", path.display(), e)))?;
                let bytecode =
                    hex_decode(hex_str.trim()).map_err(IngestionError::InvalidBytecode)?;

                let provenance = Provenance::new(
                    EvidenceSource::DeploymentBytecode,
                    ReconstructionStage::Fetch,
                    ConfidenceTier::Recovered,
                    &format!("ingest|evm|{}|{}", chain, address),
                );

                Ok(IngestionArtifact {
                    target: target.clone(),
                    bytecode,
                    metadata: ArtifactMetadata {
                        block_number: None,
                        verified: true, // fixture = verified
                        extra: std::collections::BTreeMap::new(),
                    },
                    provenance,
                })
            }
            IngestionTarget::Solana { program_id } => {
                let path = self.root.join("solana").join(format!("{}.hex", program_id));
                let hex_str = std::fs::read_to_string(&path)
                    .map_err(|e| IngestionError::NotFound(format!("{}: {}", path.display(), e)))?;
                let bytecode =
                    hex_decode(hex_str.trim()).map_err(IngestionError::InvalidBytecode)?;

                let provenance = Provenance::new(
                    EvidenceSource::DeploymentBytecode,
                    ReconstructionStage::Fetch,
                    ConfidenceTier::Recovered,
                    &format!("ingest|solana|{}", program_id),
                );

                Ok(IngestionArtifact {
                    target: target.clone(),
                    bytecode,
                    metadata: ArtifactMetadata {
                        block_number: None,
                        verified: true,
                        extra: std::collections::BTreeMap::new(),
                    },
                    provenance,
                })
            }
        }
    }
}

/// Decode a hex string to bytes. Handles optional "0x" prefix.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| format!("hex decode error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_basic() {
        assert_eq!(hex_decode("ff00ab").unwrap(), vec![0xff, 0x00, 0xab]);
        assert_eq!(hex_decode("0xff00ab").unwrap(), vec![0xff, 0x00, 0xab]);
        assert!(hex_decode("f").is_err()); // odd length
    }

    #[test]
    fn fixture_adapter_missing_file() {
        let adapter = FixtureAdapter::new(std::path::PathBuf::from("/nonexistent"));
        let target = IngestionTarget::Evm {
            address: "0x1234".into(),
            chain: "mainnet".into(),
        };
        assert!(adapter.fetch(&target).is_err());
    }
}
