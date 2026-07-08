use crate::app::AppState;
use crate::error::ApiError;
/// Resource detail handlers — finding/{id}, hypothesis/{id}, report/{id}.
use axum::extract::{Path, State};
use axum::Json;

pub async fn get_finding(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let corpus_dir = std::path::Path::new("corpus");
    let source_ids = [
        "code4rena",
        "sherlock",
        "defillama",
        "slowmist",
        "defihacklabs",
        "github-advisories",
        "solana-docs",
    ];
    for source_id in &source_ids {
        let items = digger_ingestion::store::load_corpus(corpus_dir, source_id);
        for item in items {
            for finding in &item.findings {
                if finding.finding_id == id {
                    return Ok(Json(serde_json::json!({
                        "id": finding.finding_id,
                        "original_id": finding.original_finding_id,
                        "description": finding.description_text,
                        "vulnerability_class": format!("{}", finding.vulnerability_class),
                        "root_cause": format!("{}", finding.root_cause),
                        "attack_goal": finding.attack_goal,
                        "severity": format!("{:?}", finding.severity),
                        "impacted_functions": finding.impacted_functions,
                        "impacted_contracts": finding.impacted_contracts,
                        "source": {
                            "id": item.source_id,
                            "identifier": item.source_identifier,
                            "kind": format!("{:?}", item.source_kind),
                        },
                        "evidence_count": item.evidence.len(),
                        "invariant_count": item.invariants.len(),
                    })));
                }
            }
        }
    }
    Err(ApiError::NotFound(format!("Finding '{}' not found", id)))
}

pub async fn get_hypothesis(Path(id): Path<String>) -> Result<Json<serde_json::Value>, ApiError> {
    // M2 FIX: Return proper 404 with clear guidance, not fake 200 data
    Err(ApiError::NotFound(format!(
        "Hypothesis '{}' not found. Hypotheses are generated on-demand via POST /api/v1/scan.",
        id
    )))
}

pub async fn get_report(Path(id): Path<String>) -> Result<Json<serde_json::Value>, ApiError> {
    // M2 FIX: Return proper 404 with clear guidance, not fake 200 data
    Err(ApiError::NotFound(format!(
        "Report '{}' not found. Reports are generated via POST /api/v1/scan, /api/v1/synthesize, /api/v1/validate, or /api/v1/execute.", id
    )))
}
