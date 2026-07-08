use crate::app::AppState;
use crate::error::ApiError;
use crate::models::analysis::*;
/// Scan handler — wraps existing analysis pipeline.
use axum::extract::{Path, State};
use axum::Json;

/// Synchronous scan — runs the pipeline with a timeout.
pub async fn scan(
    State(_state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, ApiError> {
    let code = req.code.clone();
    let lang = req.lang.clone();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            let raw = digger_parser::parse_program(&code, &lang);
            let language = match lang.as_str() {
                "solidity" | "sol" => digger_ir::Language::Solidity,
                "anchor" => digger_ir::Language::Anchor,
                "rust" | "rs" => digger_ir::Language::Rust,
                _ => digger_ir::Language::Unknown,
            };
            let ir = digger_graph::build_system_ir_with_language(raw, language);
            digger_hypothesis::derive(&ir)
        }),
    )
    .await
    .map_err(|_| ApiError::InternalError("Scan timed out after 60 seconds".into()))?
    .map_err(|e| ApiError::InternalError(format!("Scan failed: {}", e)))?;

    let findings: Vec<serde_json::Value> = result
        .hypotheses
        .iter()
        .map(|h| {
            serde_json::json!({
                "id": h.id.0,
                "type": h.hypothesis_type.to_string(),
                "severity": format!("{:?}", h.severity),
                "description": h.description,
                "function": h.primary_function,
                "evidence_count": h.evidence.len(),
            })
        })
        .collect();

    let summary = serde_json::json!({
        "total_hypotheses": result.hypotheses.len(),
        "summary": result.summary,
    });

    Ok(Json(ScanResponse {
        findings,
        summary,
        program_id: result.program_id,
    }))
}

pub async fn get_job(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.job_store.read().await;
    match store.get(&id) {
        Some(job) => Ok(Json(serde_json::json!({
            "id": job.id,
            "status": format!("{:?}", job.status),
            "progress": job.progress,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
        }))),
        None => Err(ApiError::NotFound(format!("Job '{}' not found", id))),
    }
}

pub async fn cancel_job(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut store = state.job_store.write().await;
    match store.get_mut(&id) {
        Some(job) => {
            job.status = crate::jobs::JobStatus::Cancelled;
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            job.completed_at = Some(format!("{}s", secs));
            Ok(Json(serde_json::json!({
                "id": job.id,
                "status": "Cancelled",
                "message": "Job cancelled successfully",
            })))
        }
        None => Err(ApiError::NotFound(format!("Job '{}' not found", id))),
    }
}
