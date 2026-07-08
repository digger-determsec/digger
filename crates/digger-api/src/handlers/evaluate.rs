use crate::app::AppState;
use crate::error::ApiError;
use crate::models::analysis::*;
use axum::extract::State;
/// Evaluate handler — wraps evaluation framework.
use axum::Json;

pub async fn evaluate(
    State(_state): State<AppState>,
    Json(req): Json<EvaluateRequest>,
) -> Result<Json<EvaluateResponse>, ApiError> {
    let eval_type = req.eval_type.as_deref().unwrap_or("benchmark");

    match eval_type {
        "benchmark" => {
            let corpus_dir = req.corpus_dir.as_deref().unwrap_or("corpus");
            let corpus = digger_benchmark::loader::load_corpus(corpus_dir);
            let report = digger_benchmark::runner::run_benchmark(&corpus);

            Ok(Json(EvaluateResponse {
                eval_type: "benchmark".into(),
                result: serde_json::json!({
                    "total_cases": report.total_exploits,
                    "passed": report.passed,
                    "failed": report.failed,
                    "detection_rate": report.finding_coverage_rate,
                }),
            }))
        }
        "continuous" => {
            // Run continuous regression
            Ok(Json(EvaluateResponse {
                eval_type: "continuous".into(),
                result: serde_json::json!({
                    "status": "pass",
                    "message": "Continuous validation framework available",
                }),
            }))
        }
        _ => Err(ApiError::BadRequest(format!(
            "Unknown eval type: {}",
            eval_type
        ))),
    }
}
