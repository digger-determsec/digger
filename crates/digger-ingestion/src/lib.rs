#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Digger Ingestion — automatic knowledge ingestion pipeline.
///
/// Deterministic ingestion from security sources into the Digger corpus.
/// Same input → same output, always.
pub mod cli;
pub mod corpus_intelligence;
pub mod correlation;
pub mod dedup;
pub mod fetcher;
pub mod file_class;
pub mod health;
pub mod manifest;
pub mod observability;
pub mod pipeline;
pub mod regression;
pub mod reliability;
pub mod scheduler;
pub mod semantic_extraction;
pub mod sources;
pub mod store;

pub use pipeline::run_ingestion;
pub use scheduler::Scheduler;
pub use store::IngestionBatch;

#[derive(Debug, thiserror::Error)]
pub enum IngestionError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("process error: {0}")]
    Process(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error(transparent)]
    Schema(#[from] crate::reliability::SchemaError),
    #[error("{0}")]
    Other(String),
}

impl From<String> for IngestionError {
    fn from(s: String) -> Self {
        IngestionError::Other(s)
    }
}

impl From<&str> for IngestionError {
    fn from(s: &str) -> Self {
        IngestionError::Other(s.to_string())
    }
}
