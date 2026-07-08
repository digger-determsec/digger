use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::org_guard::verify_org;
/// Platform handlers — organizations, projects, scans, reports, artifacts, webhooks.
use axum::extract::{Extension, Path, State};
use axum::Json;
use serde::Deserialize;

const MAX_STRING_LEN: usize = 4096;

/// L3 FIX: Validate string input length.
fn validate_str(name: &str, field: &str) -> Result<(), ApiError> {
    if name.len() > MAX_STRING_LEN {
        Err(ApiError::BadRequest(format!(
            "{} too long (max {} characters)",
            field, MAX_STRING_LEN
        )))
    } else {
        Ok(())
    }
}
use crate::app::AppState;

// ─── Organizations ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: String,
    pub role: String,
}

pub async fn create_org(
    State(state): State<AppState>,
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_str(&req.name, "name")?;
    let mgr = digger_platform::org::OrgManager::new(&*state.platform_store);
    let org = mgr
        .create(&req.name, &req.user_id)
        .map_err(|e| ApiError::InternalError(e.message))?;
    Ok(Json(
        serde_json::to_value(&org).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn list_orgs(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let mgr = digger_platform::org::OrgManager::new(&*state.platform_store);
    let orgs = mgr.list();
    Ok(Json(
        serde_json::to_value(&orgs).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn get_org(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    verify_org(&auth, &id).map_err(|_| ApiError::NotFound("not found".into()))?;
    let mgr = digger_platform::org::OrgManager::new(&*state.platform_store);
    let org = mgr.get(&id).map_err(|e| ApiError::NotFound(e.message))?;
    Ok(Json(
        serde_json::to_value(&org).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn add_member(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    verify_org(&auth, &id).map_err(|_| ApiError::NotFound("not found".into()))?;
    let mgr = digger_platform::org::OrgManager::new(&*state.platform_store);
    let role = match req.role.as_str() {
        "admin" => digger_platform::models::Role::Admin,
        "member" => digger_platform::models::Role::Member,
        "viewer" => digger_platform::models::Role::Viewer,
        _ => return Err(ApiError::BadRequest(format!("Invalid role: {}", req.role))),
    };
    let org = mgr
        .add_member(&id, &req.user_id, role)
        .map_err(|e| ApiError::InternalError(e.message))?;
    Ok(Json(
        serde_json::to_value(&org).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn delete_org(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    verify_org(&auth, &id).map_err(|_| ApiError::NotFound("not found".into()))?;
    let mgr = digger_platform::org::OrgManager::new(&*state.platform_store);
    mgr.delete(&id)
        .map_err(|e| ApiError::InternalError(e.message))?;
    Ok(Json(serde_json::json!({"deleted": true})))
}

// ─── Projects ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub description: Option<String>,
}

pub async fn create_project(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(org_id): Path<String>,
    Json(req): Json<CreateProjectRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    verify_org(&auth, &org_id).map_err(|_| ApiError::NotFound("not found".into()))?;
    validate_str(&req.name, "name")?;
    let mgr = digger_platform::project::ProjectManager::new(&*state.platform_store);
    let project = mgr
        .create(&org_id, &req.name, req.description.as_deref().unwrap_or(""))
        .map_err(|e| ApiError::InternalError(e.message))?;
    Ok(Json(
        serde_json::to_value(&project).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn list_projects(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(org_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    verify_org(&auth, &org_id).map_err(|_| ApiError::NotFound("not found".into()))?;
    let mgr = digger_platform::project::ProjectManager::new(&*state.platform_store);
    let projects = mgr.list_for_org(&org_id);
    Ok(Json(
        serde_json::to_value(&projects).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn get_project(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mgr = digger_platform::project::ProjectManager::new(&*state.platform_store);
    let project = mgr.get(&id).map_err(|e| ApiError::NotFound(e.message))?;
    verify_org(&auth, &project.org_id).map_err(|_| ApiError::NotFound("not found".into()))?;
    Ok(Json(
        serde_json::to_value(&project).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

// ─── Scan History ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateScanRequest {
    pub project_id: String,
    pub language: String,
    pub code: String,
}

pub async fn create_scan(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(org_id): Path<String>,
    Json(req): Json<CreateScanRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    verify_org(&auth, &org_id).map_err(|_| ApiError::NotFound("not found".into()))?;
    validate_str(&req.project_id, "project_id")?;
    let mgr = digger_platform::scan_history::ScanHistoryManager::new(&*state.platform_store);
    let scan = mgr
        .create(&req.project_id, &org_id, &req.language, &req.code)
        .map_err(|e| ApiError::InternalError(e.message))?;
    Ok(Json(
        serde_json::to_value(&scan).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn list_scans(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(project_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Resolve project -> owning org for cross-tenant check
    let pmgr = digger_platform::project::ProjectManager::new(&*state.platform_store);
    let project = pmgr
        .get(&project_id)
        .map_err(|e| ApiError::NotFound(e.message))?;
    verify_org(&auth, &project.org_id).map_err(|_| ApiError::NotFound("not found".into()))?;

    let mgr = digger_platform::scan_history::ScanHistoryManager::new(&*state.platform_store);
    let scans = mgr.list_for_project(&project_id, 50);
    Ok(Json(
        serde_json::to_value(&scans).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn get_scan(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mgr = digger_platform::scan_history::ScanHistoryManager::new(&*state.platform_store);
    let scan = mgr.get(&id).map_err(|e| ApiError::NotFound(e.message))?;
    verify_org(&auth, &scan.org_id).map_err(|_| ApiError::NotFound("not found".into()))?;
    Ok(Json(
        serde_json::to_value(&scan).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

#[derive(Debug, Deserialize)]
pub struct CompareRequest {
    pub scan_b: String,
}

pub async fn compare_scans(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CompareRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mgr = digger_platform::scan_history::ScanHistoryManager::new(&*state.platform_store);
    let comparison = mgr
        .compare(&id, &req.scan_b)
        .map_err(|e| ApiError::InternalError(e.message))?;
    Ok(Json(
        serde_json::to_value(&comparison).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

// ─── Reports ───────────────────────────────────────────────────────

pub async fn get_report_detail(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mgr = digger_platform::reports::ReportManager::new(&*state.platform_store);
    let report = mgr.get(&id).map_err(|e| ApiError::NotFound(e.message))?;
    verify_org(&auth, &report.org_id).map_err(|_| ApiError::NotFound("not found".into()))?;
    Ok(Json(
        serde_json::to_value(&report).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn report_lineage(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mgr = digger_platform::reports::ReportManager::new(&*state.platform_store);
    let lineage = mgr
        .trace_lineage(&id)
        .map_err(|e| ApiError::InternalError(e.message))?;
    Ok(Json(
        serde_json::to_value(&lineage).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

#[derive(Debug, Deserialize)]
pub struct DiffRequest {
    pub report_b: String,
}

pub async fn diff_reports(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<DiffRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mgr = digger_platform::reports::ReportManager::new(&*state.platform_store);
    let diff = mgr
        .diff(&id, &req.report_b)
        .map_err(|e| ApiError::InternalError(e.message))?;
    Ok(Json(
        serde_json::to_value(&diff).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

// ─── Artifacts ─────────────────────────────────────────────────────

pub async fn get_artifact(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mgr = digger_platform::artifacts::ArtifactManager::new(&*state.platform_store);
    let artifact = mgr.get(&id).map_err(|e| ApiError::NotFound(e.message))?;
    // 2-step lookup: artifact -> project -> org
    let pmgr = digger_platform::project::ProjectManager::new(&*state.platform_store);
    let project = pmgr
        .get(&artifact.project_id)
        .map_err(|e| ApiError::NotFound(e.message))?;
    verify_org(&auth, &project.org_id).map_err(|_| ApiError::NotFound("not found".into()))?;
    Ok(Json(
        serde_json::to_value(&artifact).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn list_artifacts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(scan_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Resolve scan -> project -> org for cross-tenant check
    let smgr = digger_platform::scan_history::ScanHistoryManager::new(&*state.platform_store);
    let scan = smgr
        .get(&scan_id)
        .map_err(|e| ApiError::NotFound(e.message))?;
    let pmgr = digger_platform::project::ProjectManager::new(&*state.platform_store);
    let project = pmgr
        .get(&scan.project_id)
        .map_err(|e| ApiError::NotFound(e.message))?;
    verify_org(&auth, &project.org_id).map_err(|_| ApiError::NotFound("not found".into()))?;

    let mgr = digger_platform::artifacts::ArtifactManager::new(&*state.platform_store);
    let artifacts = mgr.list_for_scan(&scan_id);
    Ok(Json(
        serde_json::to_value(&artifacts).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

// ─── Webhooks ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterWebhookRequest {
    pub url: String,
    pub events: Vec<String>,
}

pub async fn register_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(org_id): Path<String>,
    Json(req): Json<RegisterWebhookRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    verify_org(&auth, &org_id).map_err(|_| ApiError::NotFound("not found".into()))?;
    // SSRF protection: validate webhook URL before registering
    crate::net_guard::validate_external_url(&req.url)?;

    let mut events = Vec::new();
    for e in &req.events {
        let event = match e.as_str() {
            "scan.completed" => digger_platform::models::WebhookEvent::ScanCompleted,
            "scan.failed" => digger_platform::models::WebhookEvent::ScanFailed,
            "job.completed" => digger_platform::models::WebhookEvent::JobCompleted,
            "report.generated" => digger_platform::models::WebhookEvent::ReportGenerated,
            "ingestion.completed" => digger_platform::models::WebhookEvent::IngestionCompleted,
            "benchmark.completed" => digger_platform::models::WebhookEvent::BenchmarkCompleted,
            "evaluation.completed" => digger_platform::models::WebhookEvent::EvaluationCompleted,
            _ => return Err(ApiError::BadRequest(format!("Unrecognized webhook event: '{}'. Valid events: scan.completed, scan.failed, job.completed, report.generated, ingestion.completed, benchmark.completed, evaluation.completed", e))),
        };
        events.push(event);
    }
    let mgr = digger_platform::webhooks::WebhookManager::new(&*state.platform_store);
    let webhook = mgr
        .register(&org_id, &req.url, events)
        .map_err(|e| ApiError::InternalError(e.message))?;
    Ok(Json(
        serde_json::to_value(&webhook).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn list_webhooks(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(org_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    verify_org(&auth, &org_id).map_err(|_| ApiError::NotFound("not found".into()))?;
    let mgr = digger_platform::webhooks::WebhookManager::new(&*state.platform_store);
    let webhooks = mgr.list_for_org(&org_id);
    Ok(Json(
        serde_json::to_value(&webhooks).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ))
}

pub async fn delete_webhook(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mgr = digger_platform::webhooks::WebhookManager::new(&*state.platform_store);
    mgr.delete(&id)
        .map_err(|e| ApiError::InternalError(e.message))?;
    Ok(Json(serde_json::json!({"deleted": true})))
}
