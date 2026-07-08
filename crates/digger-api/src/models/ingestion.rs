/// Ingestion endpoint request/response types.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct IngestionRunRequest {
    pub source: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IngestionRunResponse {
    pub status: String,
    pub details: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IngestionStatusResponse {
    pub total_findings: usize,
    pub sources: Vec<SourceStatus>,
}

#[derive(Debug, Serialize)]
pub struct SourceStatus {
    pub source_id: String,
    pub finding_count: usize,
    pub last_sync: String,
    pub health: String,
}
