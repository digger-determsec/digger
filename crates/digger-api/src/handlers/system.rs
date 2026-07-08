use crate::app::AppState;
use crate::models::system::*;
/// System handlers — health, version, metrics with real operational data.
use axum::extract::State;
use axum::Json;

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let mut checks = Vec::new();
    let mut overall_status = "healthy".to_string();

    // Check disk space
    let disk_check = check_disk_space();
    if disk_check.status != "healthy" {
        overall_status = "degraded".to_string();
    }
    checks.push(disk_check);

    // Check git command availability
    let git_check = check_git_availability();
    if git_check.status != "healthy" {
        overall_status = "degraded".to_string();
    }
    checks.push(git_check);

    Json(HealthResponse {
        status: overall_status,
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_secs: state.start_time.elapsed().as_secs(),
        checks,
    })
}

fn check_disk_space() -> HealthCheck {
    match std::fs::metadata("/") {
        Ok(_) => HealthCheck {
            name: "disk_space".into(),
            status: "healthy".into(),
            message: "Root filesystem accessible".into(),
        },
        Err(_) => HealthCheck {
            name: "disk_space".into(),
            status: "unhealthy".into(),
            message: "Cannot access filesystem".into(),
        },
    }
}

fn check_git_availability() -> HealthCheck {
    match std::process::Command::new("git").arg("--version").output() {
        Ok(output) => {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                HealthCheck {
                    name: "git".into(),
                    status: "healthy".into(),
                    message: format!("Git available: {}", version.trim()),
                }
            } else {
                HealthCheck {
                    name: "git".into(),
                    status: "unhealthy".into(),
                    message: "Git command failed".into(),
                }
            }
        }
        Err(_) => HealthCheck {
            name: "git".into(),
            status: "unhealthy".into(),
            message: "Git is not installed or not in PATH".into(),
        },
    }
}

pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").into(),
        schema_version: "2.3".into(),
        phase_status: "FROZEN".into(),
        capabilities: vec![
            "scan".into(),
            "hypothesis".into(),
            "synthesize".into(),
            "validate".into(),
            "verify".into(),
            "benchmark".into(),
            "ingestion".into(),
            "knowledge_graph".into(),
            "protocol_packs".into(),
            "explanation".into(),
            "platform".into(),
        ],
        supported_languages: vec!["solidity".into(), "anchor".into(), "rust".into()],
        pipeline_stages: vec![
            "parser".into(),
            "systemir".into(),
            "graph".into(),
            "reasoning".into(),
            "synthesis".into(),
            "validation".into(),
            "execution".into(),
            "verification".into(),
            "explanation".into(),
        ],
    })
}

pub async fn metrics() -> Json<crate::metrics::MetricsSnapshot> {
    Json(crate::metrics::GLOBAL_METRICS.snapshot())
}
