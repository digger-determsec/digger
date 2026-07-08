/// System endpoint request/response types.
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
    pub checks: Vec<HealthCheck>,
}

#[derive(Debug, Serialize)]
pub struct VersionResponse {
    pub version: String,
    pub schema_version: String,
    pub phase_status: String,
    pub capabilities: Vec<String>,
    pub supported_languages: Vec<String>,
    pub pipeline_stages: Vec<String>,
}
