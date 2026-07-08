use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::AuthenticatedKey;
use crate::org_guard::verify_org;
use digger_platform::api_keys;

#[derive(Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub org_id: String,
    pub project_id: Option<String>,
    /// Optional expiry timestamp (ISO 8601). None = never expires.
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
pub struct CreateKeyResponse {
    pub key: String,
    pub id: String,
    pub prefix: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct KeyMetadata {
    pub id: String,
    pub prefix: String,
    pub name: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub created_at: String,
    pub last_used: Option<String>,
    pub revoked: bool,
    pub expires_at: Option<String>,
}

pub async fn create_key(
    State(state): State<AppState>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), StatusCode> {
    let secret = api_keys::create_key_with_expiry(
        &*state.platform_store,
        &req.name,
        &req.org_id,
        req.project_id.as_deref(),
        req.expires_at,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            key: secret.key,
            id: secret.id,
            prefix: secret.prefix,
            message: "Store this key securely. It will not be shown again.".into(),
        }),
    ))
}

pub async fn list_keys_default(
    State(state): State<AppState>,
) -> Result<Json<Vec<KeyMetadata>>, StatusCode> {
    let keys = api_keys::list_keys(&*state.platform_store, "default");
    let metadata: Vec<KeyMetadata> = keys
        .into_iter()
        .map(|k| KeyMetadata {
            id: k.id,
            prefix: k.prefix,
            name: k.name,
            org_id: k.org_id,
            project_id: k.project_id,
            created_at: k.created_at,
            last_used: k.last_used,
            revoked: k.revoked,
            expires_at: k.expires_at,
        })
        .collect();
    Ok(Json(metadata))
}

pub async fn list_keys(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<KeyMetadata>>, StatusCode> {
    verify_org(&auth, &org_id)?;
    let keys = api_keys::list_keys(&*state.platform_store, &org_id);
    let metadata: Vec<KeyMetadata> = keys
        .into_iter()
        .map(|k| KeyMetadata {
            id: k.id,
            prefix: k.prefix,
            name: k.name,
            org_id: k.org_id,
            project_id: k.project_id,
            created_at: k.created_at,
            last_used: k.last_used,
            revoked: k.revoked,
            expires_at: k.expires_at,
        })
        .collect();
    Ok(Json(metadata))
}

pub async fn revoke_key(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path((org_id, key_id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    verify_org(&auth, &org_id)?;
    api_keys::revoke_key(&*state.platform_store, &org_id, &key_id)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(StatusCode::NO_CONTENT)
}
