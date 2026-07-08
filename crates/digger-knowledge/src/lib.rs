#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

/// Errors for the digger-knowledge crate.
#[derive(Debug, thiserror::Error)]
pub enum KnowledgeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

/// Digger Knowledge — extraction pipeline for security knowledge sources.
///
/// Pipeline:
///
///   Source Content -> KnowledgeSource.extract() -> NormalizedKnowledge
///       -> KnowledgeGraph -> Evidence -> HistoricalFindingStore
///       -> Digger Reasoning Engine
///
/// All sources produce the same NormalizedKnowledge output.
/// The reasoning engine never knows where knowledge originated.
///
/// Deterministic: same inputs -> same outputs.
/// No ML. No LLM. Rule-based extraction and classification.
pub mod analytics;
pub mod cantina;
pub mod classifier;
pub mod code4rena;
pub mod corpus;
pub mod cyfrin;
pub mod dashboard;
pub mod dashboard_analytics;
pub mod defihacklabs;
pub mod defillama;
pub mod enrichment;
pub mod graph_builder;
pub mod graph_traversal;
pub mod normalizer;
pub mod observability;
pub mod ontology;
pub mod openzeppelin;
pub mod pashov;
pub mod pattern_extractor;
pub mod pdf_extractor;
pub mod postmortems;
pub mod protocol_docs;
pub mod protocol_packs;
pub mod quality;
pub mod sherlock;
pub mod store_builder;
pub mod trailofbits;
pub mod validation;
pub mod workspace;

pub use classifier::*;
pub use graph_builder::*;
pub use normalizer::*;
pub use pashov::*;
pub use pattern_extractor::*;
pub use store_builder::*;

#[cfg(test)]
mod tests;
