use crate::app::AppState;
use crate::error::ApiError;
use crate::models::benchmark::*;
/// Benchmark handlers — run and status.
use axum::extract::State;
use axum::Json;

pub async fn run_benchmark(
    State(_state): State<AppState>,
    Json(_req): Json<BenchmarkRunRequest>,
) -> Result<Json<BenchmarkRunResponse>, ApiError> {
    let corpus_dir = _req.corpus_dir.as_deref().unwrap_or("corpus");
    let corpus = digger_benchmark::loader::load_corpus(corpus_dir);
    let report = digger_benchmark::runner::run_benchmark(&corpus);

    Ok(Json(BenchmarkRunResponse {
        total_cases: report.total_exploits,
        passed: report.passed,
        failed: report.failed,
        detection_rate: report.finding_coverage_rate,
    }))
}

static BENCHMARK_CACHE: std::sync::OnceLock<tokio::sync::Mutex<Option<BenchmarkStatusResponse>>> =
    std::sync::OnceLock::new();

pub async fn benchmark_status() -> Json<BenchmarkStatusResponse> {
    let cache = BENCHMARK_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));

    let cached = cache.lock().await;
    if let Some(ref status) = *cached {
        return Json(status.clone());
    }
    drop(cached);

    let corpus_dir = std::path::Path::new("corpus");
    let corpus = digger_benchmark::loader::load_corpus(corpus_dir.to_str().unwrap_or("corpus"));
    let report = digger_benchmark::runner::run_benchmark(&corpus);

    let status = BenchmarkStatusResponse {
        total_cases: report.total_exploits,
        passed: report.passed,
        failed: report.failed,
        detection_rate: report.finding_coverage_rate,
    };

    let mut cached = cache.lock().await;
    *cached = Some(status.clone());

    Json(status)
}
