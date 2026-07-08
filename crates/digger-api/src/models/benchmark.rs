/// Benchmark endpoint request/response types.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct BenchmarkRunRequest {
    pub corpus_dir: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BenchmarkRunResponse {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub detection_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkStatusResponse {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub detection_rate: f64,
}
