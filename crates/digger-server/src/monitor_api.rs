use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use digger_monitor::state::WatchTarget;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::extract_session_token;
use crate::AppState;
use crate::ErrorResponse;

#[derive(Deserialize)]
pub struct CreateTargetRequest {
    pub target_descriptor: String,
    pub alert_channel: String,
    pub poll_interval_secs: Option<u64>,
}

#[derive(Serialize)]
pub struct TargetResponse {
    pub id: String,
    pub target_descriptor: String,
    pub alert_channel: String,
    pub poll_interval_secs: u64,
    pub last_revision: Option<String>,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct RunRecordResponse {
    pub run_id: i64,
    pub target_id: String,
    pub revision: String,
    pub bundle_hash: String,
    pub new_findings_count: usize,
    pub resolved_findings_count: usize,
    pub persisting_findings_count: usize,
    pub decisions: Vec<serde_json::Value>,
    pub error: Option<String>,
    pub ran_at: u64,
}

fn get_tenant(state: &AppState, headers: &axum::http::HeaderMap) -> Option<String> {
    let token = extract_session_token(headers)?;
    let conn = match state.db.conn.lock() {
        Ok(c) => c,
        Err(_) => return None,
    };
    conn.query_row(
        "SELECT u.email FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.token = ?1",
        rusqlite::params![token],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

pub async fn create_target(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateTargetRequest>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant(&state, &headers) {
        Some(tid) => tid,
        None => {
            return ErrorResponse {
                error: "Not authenticated".into(),
                code: 401,
            }
            .into_response()
        }
    };

    if req.target_descriptor.trim().is_empty() {
        return ErrorResponse {
            error: "target_descriptor is required".into(),
            code: 422,
        }
        .into_response();
    }

    let target_id = uuid::Uuid::new_v4().to_string();
    let target = WatchTarget {
        tenant_id: tenant_id.clone(),
        target_descriptor: req.target_descriptor.clone(),
        alert_channel: req.alert_channel.clone(),
    };

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
        if let Err(e) = conn.execute(
            "INSERT INTO watch_targets (id, tenant_id, target_descriptor, alert_channel, poll_interval_secs)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![target_id, tenant_id, target.target_descriptor, target.alert_channel, req.poll_interval_secs.unwrap_or(60)],
        ) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }

    (
        StatusCode::CREATED,
        Json(TargetResponse {
            id: target_id,
            target_descriptor: target.target_descriptor,
            alert_channel: target.alert_channel,
            poll_interval_secs: req.poll_interval_secs.unwrap_or(60),
            last_revision: None,
            created_at: chrono_now(),
        }),
    )
        .into_response()
}

pub async fn list_targets(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match get_tenant(&state, &headers) {
        Some(tid) => tid,
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
        .prepare("SELECT id, tenant_id, target_descriptor, alert_channel, poll_interval_secs FROM watch_targets WHERE tenant_id = ?1 ORDER BY created_at DESC")
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
    let targets: Vec<TargetResponse> = stmt
        .query_map(rusqlite::params![tenant_id], |row| {
            let id: String = row.get(0)?;
            let state_row: Option<String> = conn
                .query_row(
                    "SELECT last_revision FROM monitor_state WHERE target_id = ?1",
                    rusqlite::params![id],
                    |r| r.get(0),
                )
                .ok();
            Ok(TargetResponse {
                id,
                target_descriptor: row.get(2)?,
                alert_channel: row.get(3)?,
                poll_interval_secs: row.get::<_, i64>(4)? as u64,
                last_revision: state_row,
                created_at: String::new(),
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_else(|_| Vec::new());

    Json(targets).into_response()
}

pub async fn get_target(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(target_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant(&state, &headers) {
        Some(tid) => tid,
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
        "SELECT tenant_id, target_descriptor, alert_channel, poll_interval_secs FROM watch_targets WHERE id = ?1",
        rusqlite::params![target_id],
        |row| {
            let t: String = row.get(0)?;
            if t != tenant_id {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let state_row: Option<String> = conn
                .query_row("SELECT last_revision FROM monitor_state WHERE target_id = ?1", rusqlite::params![target_id], |r| r.get(0))
                .ok();
            Ok(TargetResponse {
                id: target_id.clone(),
                target_descriptor: row.get(1)?,
                alert_channel: row.get(2)?,
                poll_interval_secs: row.get::<_, i64>(3)? as u64,
                last_revision: state_row,
                created_at: String::new(),
            })
        },
    );

    match result {
        Ok(target) => Json(target).into_response(),
        Err(_) => ErrorResponse {
            error: "Target not found".into(),
            code: 404,
        }
        .into_response(),
    }
}

pub async fn delete_target(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(target_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant(&state, &headers) {
        Some(tid) => tid,
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
        "DELETE FROM watch_targets WHERE id = ?1 AND tenant_id = ?2",
        rusqlite::params![target_id, tenant_id],
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
    let _ = conn.execute(
        "DELETE FROM monitor_state WHERE target_id = ?1",
        rusqlite::params![target_id],
    );
    drop(conn);

    if affected == 0 {
        return ErrorResponse {
            error: "Target not found".into(),
            code: 404,
        }
        .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "Target deleted"})),
    )
        .into_response()
}

pub async fn list_runs(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(target_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant(&state, &headers) {
        Some(tid) => tid,
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

    let target_exists: bool = conn
        .query_row(
            "SELECT 1 FROM watch_targets WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![target_id, tenant_id],
            |_| Ok(()),
        )
        .is_ok();

    if !target_exists {
        return ErrorResponse {
            error: "Target not found".into(),
            code: 404,
        }
        .into_response();
    }

    let mut stmt = match conn
        .prepare("SELECT id, target_id, ran_at, revision, bundle_hash, new_findings_count, resolved_findings_count, persisting_findings_count, decisions, error FROM monitor_runs WHERE target_id = ?1 AND tenant_id = ?2 ORDER BY ran_at DESC LIMIT 50")
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
    let runs: Vec<RunRecordResponse> = stmt
        .query_map(rusqlite::params![target_id, tenant_id], |row| {
            let decisions_str: String = row.get(9)?;
            let decisions: Vec<serde_json::Value> =
                serde_json::from_str(&decisions_str).unwrap_or_default();
            Ok(RunRecordResponse {
                run_id: row.get(0)?,
                target_id: row.get(1)?,
                ran_at: row.get(2)?,
                revision: row.get(3)?,
                bundle_hash: row.get(4)?,
                new_findings_count: row.get::<_, i64>(5)? as usize,
                resolved_findings_count: row.get::<_, i64>(6)? as usize,
                persisting_findings_count: row.get::<_, i64>(7)? as usize,
                decisions,
                error: row.get(10)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_else(|_| Vec::new());

    Json(runs).into_response()
}

pub async fn get_run(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(run_id): Path<i64>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant(&state, &headers) {
        Some(tid) => tid,
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
        "SELECT id, target_id, tenant_id, ran_at, revision, bundle_hash, new_findings_count, resolved_findings_count, persisting_findings_count, decisions, error FROM monitor_runs WHERE id = ?1",
        rusqlite::params![run_id],
        |row| {
            let t: String = row.get(2)?;
            if t != tenant_id {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let decisions_str: String = row.get(9)?;
            Ok(RunRecordResponse {
                run_id: row.get(0)?,
                target_id: row.get(1)?,
                ran_at: row.get(3)?,
                revision: row.get(4)?,
                bundle_hash: row.get(5)?,
                new_findings_count: row.get::<_, i64>(6)? as usize,
                resolved_findings_count: row.get::<_, i64>(7)? as usize,
                persisting_findings_count: row.get::<_, i64>(8)? as usize,
                decisions: serde_json::from_str(&decisions_str).unwrap_or_default(),
                error: row.get(10)?,
            })
        },
    );

    match result {
        Ok(run) => Json(run).into_response(),
        Err(_) => ErrorResponse {
            error: "Run not found".into(),
            code: 404,
        }
        .into_response(),
    }
}

pub async fn trigger_tick(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(target_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant(&state, &headers) {
        Some(tid) => tid,
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
    let target_result = conn.query_row(
        "SELECT tenant_id, target_descriptor, alert_channel FROM watch_targets WHERE id = ?1",
        rusqlite::params![target_id],
        |row| {
            Ok(WatchTarget {
                tenant_id: row.get(0)?,
                target_descriptor: row.get(1)?,
                alert_channel: row.get(2)?,
            })
        },
    );
    drop(conn);

    let target = match target_result {
        Ok(t) => t,
        Err(_) => {
            return ErrorResponse {
                error: "Target not found".into(),
                code: 404,
            }
            .into_response()
        }
    };

    if target.tenant_id != tenant_id {
        return ErrorResponse {
            error: "Target not found".into(),
            code: 404,
        }
        .into_response();
    }

    let source =
        digger_monitor::source::MockMonitorSource::new(vec![digger_monitor::source::Revision {
            id: format!("tick-{}", chrono_now()),
            content_hash: format!("hash-{}", chrono_now()),
        }]);

    let evidence = Arc::new(digger_evidence::InMemoryStore::new());
    let monitor_store = Arc::new(digger_monitor::store::InMemoryMonitorStore::new());
    let audit = Arc::new(digger_runtime::InMemoryAuditStore::new());
    let approvals = Arc::new(digger_runtime::ApprovalService::new(3600));
    let broker = Arc::new(digger_runtime::CredentialBroker::new(300));
    let connectors = std::collections::BTreeMap::new();
    let gw = Arc::new(digger_runtime::ActionGateway::new(
        digger_runtime::Policy::default(),
        evidence.clone(),
        audit,
        approvals,
        broker,
        connectors,
    ));
    let monitor = digger_monitor::monitor::Monitor::new(source, monitor_store, gw, evidence);
    let report = monitor.tick(&target, &target_id);

    let response = serde_json::json!({
        "revision": report.revision,
        "bundle_hash": report.bundle_hash,
        "new_findings": report.new_findings,
        "resolved_findings": report.resolved_findings,
        "persisting_findings": report.persisting_findings,
        "action_proposals": report.action_proposals.len(),
    });

    Json(response).into_response()
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", now)
}

#[derive(Serialize)]
pub struct MonitorStatusResponse {
    pub status: String,
    pub targets_count: usize,
    pub due_count: usize,
}

pub async fn monitor_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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
    let targets_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM watch_targets", [], |row| row.get(0))
        .unwrap_or(0);

    let due_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM monitor_state ms
             JOIN watch_targets wt ON ms.target_id = wt.id",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    Json(MonitorStatusResponse {
        status: "running".into(),
        targets_count: targets_count as usize,
        due_count: due_count as usize,
    })
    .into_response()
}
