use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, ErrorResponse, TokenBucket};

#[derive(Deserialize)]
pub struct WaitlistRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct WaitlistResponse {
    pub message: String,
}

fn is_valid_email(email: &str) -> bool {
    let email = email.trim().to_lowercase();
    if email.is_empty() || email.len() > 254 {
        return false;
    }
    let at_count = email.chars().filter(|c| *c == '@').count();
    if at_count != 1 {
        return false;
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if !domain.contains('.') {
        return false;
    }
    if local.starts_with('.')
        || local.ends_with('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return false;
    }
    true
}

pub async fn join_waitlist(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WaitlistRequest>,
) -> Response {
    let client_ip = crate::get_client_ip(&headers);

    {
        let mut limits = state.rate_limits.lock().await;
        let bucket = limits.entry(client_ip).or_insert_with(|| {
            TokenBucket::new(state.rate_limit_burst, state.rate_limit_per_second as f64)
        });

        if let Some(retry_after) = bucket.try_consume() {
            if retry_after > 0 {
                return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
                    "error": format!("Rate limit exceeded. Try again in {} seconds.", retry_after),
                    "code": 429,
                    "retry_after_seconds": retry_after,
                }))).into_response();
            }
        }
    }

    let email = req.email.trim().to_lowercase();

    if email.is_empty() {
        return ErrorResponse {
            error: "Email is required".into(),
            code: 400,
        }
        .into_response();
    }

    if !is_valid_email(&email) {
        return ErrorResponse {
            error: "Invalid email format".into(),
            code: 422,
        }
        .into_response();
    }

    let id = Uuid::new_v4().to_string();

    let conn = match state.db.conn.lock() {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WaitlistResponse {
                    message: "Internal error".into(),
                }),
            )
                .into_response();
        }
    };
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS waitlist (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            source TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        [],
    );

    let result = conn.execute(
        "INSERT OR IGNORE INTO waitlist (id, email) VALUES (?1, ?2)",
        params![id, email],
    );

    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(WaitlistResponse {
                message: "You're on the list!".into(),
            }),
        )
            .into_response(),
        Err(_) => (
            StatusCode::OK,
            Json(WaitlistResponse {
                message: "You're on the list!".into(),
            }),
        )
            .into_response(),
    }
}

pub async fn waitlist_count(State(state): State<Arc<AppState>>) -> Response {
    let conn = match state.db.conn.lock() {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response();
        }
    };
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM waitlist", [], |row| row.get(0))
        .unwrap_or(0);

    (StatusCode::OK, Json(serde_json::json!({"count": count}))).into_response()
}
