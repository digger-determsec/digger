use axum::extract::State;
use axum::http::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

use crate::app::AppState;

/// Extension injected into the request after successful auth.
/// Carries the key's org_id for cross-tenant enforcement.
#[derive(Debug, Clone)]
pub struct AuthenticatedKey {
    pub key_id: String,
    pub org_id: String,
    /// If true, this is a bootstrap/admin key (org scoping skipped).
    pub is_admin: bool,
}

/// Validate API key from `X-API-Key` header.
///
/// Two-tier validation:
/// 1. Bootstrap key: DIGGER_API_KEY env var (constant-time compare, for admin/legacy)
/// 2. Stored keys: sha256-validated via digger-platform api_keys module
///
/// FAIL-CLOSED: if neither method accepts the key, deny the request.
/// On success, injects `AuthenticatedKey` into request extensions.
pub async fn auth_layer(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let path = req.uri().path();

    // Health/readiness/version probes are exempt from auth (ops can probe keyless).
    if path == "/api/v1/health" || path == "/api/v1/version" {
        req.extensions_mut().insert(AuthenticatedKey {
            key_id: "anonymous".into(),
            org_id: "anonymous".into(),
            is_admin: false,
        });
        return Ok(next.run(req).await);
    }

    if provided.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Tier 1: Bootstrap/admin key (env var, constant-time comparison)
    if let Ok(expected) = std::env::var("DIGGER_API_KEY") {
        if !expected.is_empty() && digger_platform::timing::timing_safe_eq(provided, &expected) {
            req.extensions_mut().insert(AuthenticatedKey {
                key_id: "bootstrap".into(),
                org_id: "admin".into(),
                is_admin: true,
            });
            return Ok(next.run(req).await);
        }
    }

    // Tier 2: Stored hashed keys via digger-platform
    match digger_platform::api_keys::validate_key(&*state.platform_store, provided) {
        Ok(record) => {
            let mut updated = record.clone();
            let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            if updated.last_used.as_deref() != Some(&now) {
                updated.last_used = Some(now);
                if let Ok(val) = serde_json::to_value(&updated) {
                    let _ = state
                        .platform_store
                        .write_json("api_keys", &record.id, &val);
                }
            }
            req.extensions_mut().insert(AuthenticatedKey {
                key_id: record.id,
                org_id: record.org_id,
                is_admin: false,
            });
            Ok(next.run(req).await)
        }
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}
