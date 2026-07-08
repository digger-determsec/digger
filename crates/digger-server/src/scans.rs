use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::extract_session_token;
use crate::{AppState, ErrorResponse};

#[derive(Deserialize)]
pub struct SaveScanRequest {
    pub language: String,
    pub source: String,
    pub findings: Vec<serde_json::Value>,
    pub provenance: String,
}

#[derive(Serialize)]
pub struct ScanSummary {
    pub id: String,
    pub language: String,
    pub finding_count: i64,
    pub source_sha256: String,
    pub shared: bool,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ScanDetail {
    pub id: String,
    pub language: String,
    pub findings: Vec<serde_json::Value>,
    pub provenance: String,
    pub finding_count: i64,
    pub source_sha256: String,
    pub shared: bool,
    pub share_token: Option<String>,
    pub created_at: String,
}

fn sha256_hex(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn get_user_id(state: &AppState, headers: &axum::http::HeaderMap) -> Option<String> {
    let token = extract_session_token(headers)?;
    let conn = match state.db.conn.lock() {
        Ok(c) => c,
        Err(_) => return None,
    };
    conn.query_row(
        "SELECT user_id FROM sessions WHERE token = ?1",
        params![token],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

pub async fn save_scan(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SaveScanRequest>,
) -> Response {
    let user_id = match get_user_id(&state, &headers) {
        Some(uid) => uid,
        None => {
            return ErrorResponse {
                error: "Not authenticated".into(),
                code: 401,
            }
            .into_response()
        }
    };

    let id = Uuid::new_v4().to_string();
    let source_sha256 = sha256_hex(&req.source);
    let findings_json = serde_json::to_string(&req.findings).unwrap_or_else(|_| "[]".into());
    let finding_count = req.findings.len() as i64;

    let conn = match state.db.conn.lock() {
        Ok(c) => c,
        Err(_) => {
            return ErrorResponse {
                error: "Internal error".into(),
                code: 500,
            }
            .into_response();
        }
    };
    if let Err(_e) = conn.execute(
        "INSERT INTO scans (id, user_id, language, source_sha256, findings_json, provenance, finding_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, user_id, req.language, source_sha256, findings_json, req.provenance, finding_count],
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to save scan"})),
        )
            .into_response();
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({"id": id, "finding_count": finding_count})),
    )
        .into_response()
}

pub async fn list_scans(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let user_id = match get_user_id(&state, &headers) {
        Some(uid) => uid,
        None => {
            return ErrorResponse {
                error: "Not authenticated".into(),
                code: 401,
            }
            .into_response()
        }
    };

    let conn = match state.db.conn.lock() {
        Ok(c) => c,
        Err(_) => {
            return ErrorResponse {
                error: "Internal error".into(),
                code: 500,
            }
            .into_response();
        }
    };
    let mut stmt = match conn
        .prepare("SELECT id, language, finding_count, source_sha256, shared, created_at FROM scans WHERE user_id = ?1 ORDER BY created_at DESC")
    {
        Ok(s) => s,
        Err(_) => {
            return ErrorResponse {
                error: "Internal error".into(),
                code: 500,
            }
            .into_response();
        }
    };

    let scans: Vec<ScanSummary> = match stmt.query_map(params![user_id], |row| {
        Ok(ScanSummary {
            id: row.get(0)?,
            language: row.get(1)?,
            finding_count: row.get(2)?,
            source_sha256: row.get(3)?,
            shared: row.get::<_, i64>(4)? != 0,
            created_at: row.get(5)?,
        })
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => {
            return ErrorResponse {
                error: "Internal error".into(),
                code: 500,
            }
            .into_response();
        }
    };

    (StatusCode::OK, Json(scans)).into_response()
}

pub async fn get_scan(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user_id = match get_user_id(&state, &headers) {
        Some(uid) => uid,
        None => {
            return ErrorResponse {
                error: "Not authenticated".into(),
                code: 401,
            }
            .into_response()
        }
    };

    let conn = match state.db.conn.lock() {
        Ok(c) => c,
        Err(_) => {
            return ErrorResponse {
                error: "Internal error".into(),
                code: 500,
            }
            .into_response();
        }
    };
    let result = conn.query_row(
        "SELECT id, language, findings_json, provenance, finding_count, source_sha256, shared, share_token, created_at
         FROM scans WHERE id = ?1 AND user_id = ?2",
        params![id, user_id],
        |row| {
            let findings_str: String = row.get(2)?;
            let findings: Vec<serde_json::Value> =
                serde_json::from_str(&findings_str).unwrap_or_default();
            Ok(ScanDetail {
                id: row.get(0)?,
                language: row.get(1)?,
                findings,
                provenance: row.get(3)?,
                finding_count: row.get(4)?,
                source_sha256: row.get(5)?,
                shared: row.get::<_, i64>(6)? != 0,
                share_token: row.get(7)?,
                created_at: row.get(8)?,
            })
        },
    );

    match result {
        Ok(scan) => (StatusCode::OK, Json(scan)).into_response(),
        Err(_) => ErrorResponse {
            error: "Scan not found".into(),
            code: 404,
        }
        .into_response(),
    }
}

pub async fn share_scan(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user_id = match get_user_id(&state, &headers) {
        Some(uid) => uid,
        None => {
            return ErrorResponse {
                error: "Not authenticated".into(),
                code: 401,
            }
            .into_response()
        }
    };

    let share_token = Uuid::new_v4().to_string().replace('-', "");
    let conn = match state.db.conn.lock() {
        Ok(c) => c,
        Err(_) => {
            return ErrorResponse {
                error: "Internal error".into(),
                code: 500,
            }
            .into_response();
        }
    };

    let affected = match conn.execute(
        "UPDATE scans SET share_token = ?1, shared = 1 WHERE id = ?2 AND user_id = ?3",
        params![share_token, id, user_id],
    ) {
        Ok(a) => a,
        Err(_) => {
            return ErrorResponse {
                error: "Internal error".into(),
                code: 500,
            }
            .into_response();
        }
    };

    if affected == 0 {
        return ErrorResponse {
            error: "Scan not found".into(),
            code: 404,
        }
        .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "share_token": share_token,
            "url": format!("/r/{}", share_token),
        })),
    )
        .into_response()
}

pub async fn revoke_share(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user_id = match get_user_id(&state, &headers) {
        Some(uid) => uid,
        None => {
            return ErrorResponse {
                error: "Not authenticated".into(),
                code: 401,
            }
            .into_response()
        }
    };

    let conn = match state.db.conn.lock() {
        Ok(c) => c,
        Err(_) => {
            return ErrorResponse {
                error: "Internal error".into(),
                code: 500,
            }
            .into_response();
        }
    };
    let affected = match conn.execute(
        "UPDATE scans SET share_token = NULL, shared = 0 WHERE id = ?1 AND user_id = ?2",
        params![id, user_id],
    ) {
        Ok(a) => a,
        Err(_) => {
            return ErrorResponse {
                error: "Internal error".into(),
                code: 500,
            }
            .into_response();
        }
    };

    if affected == 0 {
        return ErrorResponse {
            error: "Scan not found".into(),
            code: 404,
        }
        .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "Share revoked"})),
    )
        .into_response()
}

pub async fn public_report(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    let conn = match state.db.conn.lock() {
        Ok(c) => c,
        Err(_) => {
            return ErrorResponse {
                error: "Internal error".into(),
                code: 500,
            }
            .into_response();
        }
    };
    let result = conn.query_row(
        "SELECT id, language, findings_json, provenance, finding_count, created_at
         FROM scans WHERE share_token = ?1 AND shared = 1",
        params![token],
        |row| {
            let findings_str: String = row.get(2)?;
            let findings: Vec<serde_json::Value> =
                serde_json::from_str(&findings_str).unwrap_or_default();
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "language": row.get::<_, String>(1)?,
                "findings": findings,
                "provenance": row.get::<_, String>(3)?,
                "finding_count": row.get::<_, i64>(4)?,
                "created_at": row.get::<_, String>(5)?,
                "report_type": "public_triage",
                "disclaimer": "This is a point-in-time structural triage, not a full audit. Results labeled experimental have lower confidence."
            }))
        },
    );

    match result {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(_) => ErrorResponse {
            error: "Report not found".into(),
            code: 404,
        }
        .into_response(),
    }
}
