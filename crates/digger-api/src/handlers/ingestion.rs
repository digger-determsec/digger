use crate::app::AppState;
use crate::error::ApiError;
use crate::models::ingestion::*;
/// Ingestion handlers — status, run.
use axum::extract::State;
use axum::Json;

pub async fn status() -> Json<IngestionStatusResponse> {
    // Read actual corpus state from disk
    let corpus_dir = std::path::Path::new("corpus");
    let hashes = digger_ingestion::store::load_existing_hashes(corpus_dir);
    let manifest_dir = corpus_dir.join(".digger/manifests");

    let source_ids = [
        "code4rena",
        "sherlock",
        "defillama",
        "slowmist",
        "defihacklabs",
        "github-advisories",
    ];
    let mut sources = Vec::new();

    for &source_id in &source_ids {
        let manifest = digger_ingestion::manifest::SourceManifest::load(&manifest_dir, source_id);
        let health = if manifest.artifacts.is_empty() {
            "unknown".into()
        } else {
            "healthy".into()
        };
        sources.push(SourceStatus {
            source_id: source_id.to_string(),
            finding_count: manifest.active_count,
            last_sync: manifest.last_sync,
            health,
        });
    }

    Json(IngestionStatusResponse {
        total_findings: hashes.len(),
        sources,
    })
}

pub async fn run(
    State(_state): State<AppState>,
    Json(req): Json<IngestionRunRequest>,
) -> Result<Json<IngestionRunResponse>, ApiError> {
    let source_filter = req.source.as_deref();
    let corpus_dir = "corpus";

    match digger_ingestion::pipeline::run_ingestion(corpus_dir, source_filter) {
        Ok(batches) => {
            let summary: Vec<String> = batches
                .iter()
                .map(|b| {
                    format!(
                        "{}: fetched={}, stored={}",
                        b.source_id, b.fetched_count, b.stored_count
                    )
                })
                .collect();
            Ok(Json(IngestionRunResponse {
                status: "completed".into(),
                details: summary,
            }))
        }
        Err(e) => Err(ApiError::InternalError(format!("Ingestion failed: {}", e))),
    }
}
