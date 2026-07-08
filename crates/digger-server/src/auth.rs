use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::{Json, State},
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::{get_client_ip, ErrorResponse, TokenBucket};

pub struct DbState {
    pub conn: Mutex<Connection>,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub created_at: String,
}

pub fn init_db(db_path: &str) -> Result<Arc<DbState>, ErrorResponse> {
    let conn = Connection::open(db_path).map_err(|e| format!("DB open error: {}", e))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;",
    )
    .map_err(|e| format!("PRAGMA error: {}", e))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            language TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            provenance TEXT NOT NULL DEFAULT 'local source',
            finding_count INTEGER NOT NULL DEFAULT 0,
            share_token TEXT UNIQUE,
            shared INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS watch_targets (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            target_descriptor TEXT NOT NULL,
            alert_channel TEXT NOT NULL,
            poll_interval_secs INTEGER NOT NULL DEFAULT 60,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS monitor_state (
            target_id TEXT PRIMARY KEY,
            last_revision TEXT,
            last_bundle_hash TEXT,
            last_finding_ids TEXT NOT NULL DEFAULT '[]',
            already_actioned_finding_ids TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS monitor_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            ran_at INTEGER NOT NULL,
            revision TEXT NOT NULL DEFAULT '',
            bundle_hash TEXT NOT NULL DEFAULT '',
            new_findings_count INTEGER NOT NULL DEFAULT 0,
            resolved_findings_count INTEGER NOT NULL DEFAULT 0,
            persisting_findings_count INTEGER NOT NULL DEFAULT 0,
            decisions TEXT NOT NULL DEFAULT '[]',
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_monitor_runs_target ON monitor_runs(target_id);
        CREATE INDEX IF NOT EXISTS idx_monitor_runs_tenant ON monitor_runs(tenant_id);",
    )
    .map_err(|e| format!("Migration error: {}", e))?;
    Ok(Arc::new(DbState {
        conn: Mutex::new(conn),
    }))
}

fn hash_password(password: &str) -> Result<String, ErrorResponse> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("password hash error: {}", e))?
        .to_string();
    Ok(hash)
}

fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

fn dummy_hash() -> String {
    #[allow(clippy::expect_used)] // invariant: argon2 default params are infallible
    hash_password("dummy_password_for_timing_consistency_!")
        .expect("argon2 default params are infallible")
}

fn is_strong_password(pw: &str) -> Result<(), ErrorResponse> {
    if pw.len() < 8 {
        return Err(ErrorResponse {
            error: "Password must be at least 8 characters".into(),
            code: 422,
        });
    }
    if !pw.chars().any(|c| c.is_uppercase()) {
        return Err(ErrorResponse {
            error: "Password must contain an uppercase letter".into(),
            code: 422,
        });
    }
    if !pw.chars().any(|c| c.is_lowercase()) {
        return Err(ErrorResponse {
            error: "Password must contain a lowercase letter".into(),
            code: 422,
        });
    }
    if !pw.chars().any(|c| c.is_ascii_digit()) {
        return Err(ErrorResponse {
            error: "Password must contain a digit".into(),
            code: 422,
        });
    }
    Ok(())
}

pub async fn signup(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
    Json(req): Json<SignupRequest>,
) -> Response {
    let client_ip = get_client_ip(&headers);
    {
        let mut limits = state.rate_limits.lock().await;
        let bucket = limits.entry(client_ip).or_insert_with(|| {
            TokenBucket::new(state.rate_limit_burst, state.rate_limit_per_second as f64)
        });
        if let Some(retry_after) = bucket.try_consume() {
            if retry_after > 0 {
                let err = crate::RateLimitError {
                    error: format!("Rate limit exceeded. Try again in {} seconds.", retry_after),
                    code: 429,
                    retry_after_seconds: retry_after,
                };
                let mut resp = (StatusCode::TOO_MANY_REQUESTS, axum::Json(err)).into_response();
                if let Ok(val) = retry_after.to_string().parse() {
                    resp.headers_mut().insert("retry-after", val);
                }
                return resp;
            }
        }
    }
    let email = req.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return ErrorResponse {
            error: "Invalid email format".into(),
            code: 422,
        }
        .into_response();
    }

    if let Err(err) = is_strong_password(&req.password) {
        return err.into_response();
    }

    let id = Uuid::new_v4().to_string();
    let hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            return e.into_response();
        }
    };

    let result = {
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
        conn.execute(
            "INSERT INTO users (id, email, password_hash) VALUES (?1, ?2, ?3)",
            rusqlite::params![id, email, hash],
        )
    };

    match result {
        Ok(_) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let user = UserResponse {
                id,
                email,
                created_at: format!("{}", now),
            };
            (StatusCode::CREATED, Json(user)).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE") || msg.contains("unique") {
                ErrorResponse {
                    error: "An account with this email already exists".into(),
                    code: 409,
                }
                .into_response()
            } else {
                ErrorResponse {
                    error: "Failed to create account".into(),
                    code: 500,
                }
                .into_response()
            }
        }
    }
}

pub async fn login(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Response {
    let client_ip = get_client_ip(&headers);
    {
        let mut limits = state.rate_limits.lock().await;
        let bucket = limits.entry(client_ip).or_insert_with(|| {
            TokenBucket::new(state.rate_limit_burst, state.rate_limit_per_second as f64)
        });
        if let Some(retry_after) = bucket.try_consume() {
            if retry_after > 0 {
                let err = crate::RateLimitError {
                    error: format!("Rate limit exceeded. Try again in {} seconds.", retry_after),
                    code: 429,
                    retry_after_seconds: retry_after,
                };
                let mut resp = (StatusCode::TOO_MANY_REQUESTS, axum::Json(err)).into_response();
                if let Ok(val) = retry_after.to_string().parse() {
                    resp.headers_mut().insert("retry-after", val);
                }
                return resp;
            }
        }
    }

    let email = req.email.trim().to_lowercase();

    let result = {
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
        conn.query_row(
            "SELECT id, password_hash FROM users WHERE email = ?1",
            rusqlite::params![email],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
    };

    let (user_id, hash) = match result {
        Ok(pair) => pair,
        Err(_) => {
            let _ = dummy_hash();
            return ErrorResponse {
                error: "Invalid email or password".into(),
                code: 401,
            }
            .into_response();
        }
    };

    if !verify_password(&req.password, &hash) {
        return ErrorResponse {
            error: "Invalid email or password".into(),
            code: 401,
        }
        .into_response();
    }

    let session_token = Uuid::new_v4().to_string();
    {
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
        let _ = conn.execute(
            "INSERT INTO sessions (token, user_id) VALUES (?1, ?2)",
            rusqlite::params![session_token, user_id],
        );
    }

    let cookie = format!(
        "digger_session={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        session_token,
        7 * 24 * 3600
    );

    let mut response = (
        StatusCode::OK,
        Json(serde_json::json!({"message": "Login successful"})),
    )
        .into_response();
    if let Ok(val) = cookie.parse() {
        response.headers_mut().insert(SET_COOKIE, val);
    }
    response
}

pub async fn logout(State(state): State<Arc<crate::AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = extract_session_token(&headers) {
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
        let _ = conn.execute(
            "DELETE FROM sessions WHERE token = ?1",
            rusqlite::params![token],
        );
    }

    let cookie = "digger_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
    let mut response = (
        StatusCode::OK,
        Json(serde_json::json!({"message": "Logged out"})),
    )
        .into_response();
    if let Ok(val) = cookie.parse() {
        response.headers_mut().insert(SET_COOKIE, val);
    }
    response
}

pub async fn me(State(state): State<Arc<crate::AppState>>, headers: HeaderMap) -> Response {
    let token = match extract_session_token(&headers) {
        Some(t) => t,
        None => {
            return ErrorResponse {
                error: "Not authenticated".into(),
                code: 401,
            }
            .into_response()
        }
    };

    let result = {
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
        conn.query_row(
            "SELECT u.id, u.email, u.created_at FROM users u
             JOIN sessions s ON u.id = s.user_id
             WHERE s.token = ?1",
            rusqlite::params![token],
            |row| {
                Ok(UserResponse {
                    id: row.get(0)?,
                    email: row.get(1)?,
                    created_at: row.get(2)?,
                })
            },
        )
    };

    match result {
        Ok(user) => (StatusCode::OK, Json(user)).into_response(),
        Err(_) => ErrorResponse {
            error: "Not authenticated".into(),
            code: 401,
        }
        .into_response(),
    }
}

pub fn extract_session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(token) = part.strip_prefix("digger_session=") {
            return Some(token.trim().to_string());
        }
    }
    None
}
