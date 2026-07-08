use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Input for repo intelligence scan.
pub struct RepoIntelligenceInput {
    pub root: PathBuf,
    pub chain: Chain,
}

/// Chain target.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Chain {
    #[serde(rename = "evm")]
    Evm,
    #[serde(rename = "solana")]
    Solana,
}

impl Chain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Chain::Evm => "evm",
            Chain::Solana => "solana",
        }
    }
}

/// Top-level repository intelligence map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoIntelligenceMap {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub chain: String,
    pub generated_from: GeneratedFrom,
    pub surfaces: Vec<SurfaceNode>,
    pub unknowns: Vec<UnknownItem>,
    pub summary: RepoIntelligenceSummary,
}

/// Generation metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneratedFrom {
    pub mode: String,
}

/// A classified surface in the repository.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurfaceNode {
    pub id: String,
    pub path: String,
    pub chain: String,
    pub category: String,
    pub name: String,
    pub kind: String,
    pub evidence: Vec<EvidencePointer>,
    pub confidence: ConfidenceLevel,
}

/// A reference to where evidence about a surface can be found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidencePointer {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_start: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_end: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    pub reason: String,
}

/// Inventory and classification confidence levels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidenceLevel {
    pub inventory: String,
    pub classification: String,
}

/// A surface that could not be classified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnknownItem {
    pub path: String,
    pub reason: String,
}

/// Summary of the intelligence map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoIntelligenceSummary {
    pub surface_count: usize,
    pub unknown_count: usize,
}
