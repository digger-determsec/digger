#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod auth;
pub mod confidence;
pub mod copilot;
pub mod monitor_api;
pub mod monitor_store;
pub mod scans;
pub mod waitlist;

use axum::{
    extract::{DefaultBodyLimit, Json, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

/// Combined application state: scan config + auth DB.
pub struct AppState {
    pub max_body_bytes: usize,
    pub max_source_bytes: usize,
    pub max_source_lines: usize,
    pub scan_timeout: Duration,
    pub semaphore: Arc<tokio::sync::Semaphore>,
    pub semaphore_wait: Duration,
    pub rate_limit_per_second: u32,
    pub rate_limit_burst: u32,
    pub rate_limits: Mutex<HashMap<std::net::IpAddr, TokenBucket>>,
    pub db: Arc<auth::DbState>,
    /// Optional API key for /scan endpoint. When Some, all scan requests
    /// must include X-Digger-Api-Key header. None + allow_open=false →
    /// rejected with 401 (fail-closed default).
    pub api_key: Option<String>,
    /// When true and api_key is None, /scan is fully open (local/dev mode).
    /// When false (default) and api_key is None, /scan rejects all traffic.
    pub allow_open: bool,
}

#[derive(Clone)]
pub struct TokenBucket {
    pub tokens: f64,
    pub last_refill: Instant,
    pub capacity: f64,
    pub refill_rate: f64,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_rate_per_sec: f64) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: Instant::now(),
            capacity: capacity as f64,
            refill_rate: refill_rate_per_sec,
        }
    }

    pub fn try_consume(&mut self) -> Option<u64> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Some(0)
        } else {
            let wait_secs = ((1.0 - self.tokens) / self.refill_rate).ceil() as u64;
            Some(wait_secs.max(1))
        }
    }
}

#[derive(Deserialize)]
pub struct ScanRequest {
    pub source: String,
    pub language: String,
}

#[derive(Serialize, Debug, thiserror::Error)]
#[error("{error}")]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

#[derive(Serialize, Debug, thiserror::Error)]
#[error("Rate limit exceeded")]
pub struct RateLimitError {
    pub error: String,
    pub code: u16,
    pub retry_after_seconds: u64,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, axum::Json(self)).into_response()
    }
}

impl From<String> for ErrorResponse {
    fn from(msg: String) -> Self {
        ErrorResponse {
            error: msg,
            code: 500,
        }
    }
}

pub async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"status": "ok"})),
    )
}

pub(crate) fn get_client_ip(headers: &HeaderMap) -> std::net::IpAddr {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(s) = forwarded.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse::<std::net::IpAddr>() {
                    return ip;
                }
            }
        }
    }
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
}

/// Constant-time equality for secret comparison (avoids the early-return
/// timing leak of `==`/`!=` on the api-key path). Not a generic util — kept
/// private to the auth check.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u8 = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= x ^ y;
    }
    diff == 0
}

/// Scan endpoint — stateless, no session required.
/// Auth posture (fail-closed by default):
///   api_key Some(k)          → require X-Digger-Api-Key == k (401 otherwise)
///   api_key None + allow_open=false → 401 with misconfiguration message
///   api_key None + allow_open=true  → open (explicit local/dev escape hatch)
pub(crate) async fn scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ScanRequest>,
) -> Response {
    match &state.api_key {
        Some(expected_key) => {
            let provided = headers
                .get("x-digger-api-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !constant_time_eq(provided.as_bytes(), expected_key.as_bytes()) {
                return ErrorResponse {
                    error: "Missing or invalid API key".into(),
                    code: 401,
                }
                .into_response();
            }
        }
        None if !state.allow_open => {
            return ErrorResponse {
                error: "Server is misconfigured: no DIGGER_API_KEY set and DIGGER_ALLOW_OPEN not enabled".into(),
                code: 401,
            }
            .into_response();
        }
        None => {} // allow_open=true → open
    }

    let client_ip = get_client_ip(&headers);

    {
        let mut limits = state.rate_limits.lock().await;
        let bucket = limits.entry(client_ip).or_insert_with(|| {
            TokenBucket::new(state.rate_limit_burst, state.rate_limit_per_second as f64)
        });

        if let Some(retry_after) = bucket.try_consume() {
            if retry_after > 0 {
                let err = RateLimitError {
                    error: format!("Rate limit exceeded. Try again in {} seconds.", retry_after),
                    code: 429,
                    retry_after_seconds: retry_after,
                };
                let mut resp = (StatusCode::TOO_MANY_REQUESTS, axum::Json(err)).into_response();
                if let Ok(hv) = retry_after.to_string().parse() {
                    resp.headers_mut().insert("retry-after", hv);
                }
                return resp;
            }
        }
    }

    if req.source.trim().is_empty() {
        return ErrorResponse {
            error: "source is empty".into(),
            code: 400,
        }
        .into_response();
    }

    if !matches!(req.language.as_str(), "evm" | "solana" | "op-layer") {
        return ErrorResponse {
            error: "language must be 'evm', 'solana', or 'op-layer'".into(),
            code: 400,
        }
        .into_response();
    }

    if req.source.len() > state.max_source_bytes {
        return ErrorResponse {
            error: format!(
                "source exceeds maximum size ({} bytes max)",
                state.max_source_bytes
            ),
            code: 413,
        }
        .into_response();
    }

    let line_count = req.source.lines().count();
    if line_count > state.max_source_lines {
        return ErrorResponse {
            error: format!(
                "source too complex ({} lines max, got {})",
                state.max_source_lines, line_count
            ),
            code: 422,
        }
        .into_response();
    }

    let _permit = match tokio::time::timeout(
        state.semaphore_wait,
        state.semaphore.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => {
            return ErrorResponse {
                error: "Scanner shutting down".into(),
                code: 503,
            }
            .into_response();
        }
        Err(_) => {
            return ErrorResponse {
                error: "Scanner busy — try again shortly".into(),
                code: 503,
            }
            .into_response();
        }
    };

    let source = req.source.clone();
    let language = req.language.clone();
    let result = tokio::time::timeout(state.scan_timeout, run_scan(&source, &language)).await;

    match result {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => ErrorResponse {
            error: "Internal scan error".into(),
            code: 500,
        }
        .into_response(),
        Err(_) => ErrorResponse {
            error: "Scan timed out — source may be too complex".into(),
            code: 408,
        }
        .into_response(),
    }
}

async fn run_scan(source: &str, language: &str) -> Result<Response, ErrorResponse> {
    if language == "op-layer" {
        let program = digger_oplayer::parse_op_program(source);
        let mut findings = Vec::new();
        for v in digger_oplayer::detect_unverified_attestation(&program) {
            findings.push(serde_json::json!({
                "detector": "op_unverified_attestation",
                "function": v.function_id,
                "kind": v.violation_kind,
                "severity": "high",
                "confidence": "experimental",
                "evidence_refs": [v.id],
            }));
        }
        for v in digger_oplayer::detect_control_plane_authority(&program) {
            findings.push(serde_json::json!({
                "detector": "op_control_plane_authority",
                "function": v.function_id,
                "kind": v.violation_kind,
                "severity": "high",
                "confidence": "experimental",
                "evidence_refs": [v.id],
            }));
        }
        for v in digger_oplayer::detect_fail_open_bootstrap(&program) {
            findings.push(serde_json::json!({
                "detector": "op_fail_open_bootstrap",
                "function": v.function_id,
                "kind": v.violation_kind,
                "severity": "high",
                "confidence": "experimental",
                "evidence_refs": [v.id],
            }));
        }
        for v in digger_oplayer::detect_silent_failover(&program) {
            findings.push(serde_json::json!({
                "detector": "op_silent_failover",
                "function": v.function_id,
                "kind": v.violation_kind,
                "severity": "high",
                "confidence": "experimental",
                "evidence_refs": [v.id],
            }));
        }
        return Ok((
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "findings": findings,
                "source_provenance": "local source",
                "confidence": "experimental",
            })),
        )
            .into_response());
    }

    let lang = match language {
        "evm" => "solidity",
        "solana" => "anchor",
        _ => unreachable!(),
    };

    let raw = digger_parser::parse_program(source, lang);
    let outcome = digger_pipeline::investigate_source(source, lang);

    let engine_hypotheses: Vec<serde_json::Value> = outcome
        .systems
        .iter()
        .flat_map(|sys| &sys.hypotheses.hypotheses)
        .map(|h| {
            serde_json::json!({
                "detector": format!("{}", h.hypothesis_type),
                "function": h.primary_function,
                "kind": h.description,
                "severity": format!("{:?}", h.severity),
                "confidence": "engine_derived",
                "evidence_refs": h.evidence.iter().map(|e| e.path_id.clone()).collect::<Vec<_>>(),
                "provenance": "engine",
            })
        })
        .collect();

    let mut findings = Vec::new();
    let is_solana = language == "solana";

    // Scan endpoint consumes raw source only. A future lifted-bytecode path MUST
    // set BytecodeOnly; the gate then caps it to experimental.
    let modality = confidence::EvidenceModality::SourceCorroborated;
    let conf_label = confidence::graduation_label(modality);

    if is_solana {
        if let Some(body) = digger_reconstruct::recover_source_body_graph(&raw) {
            for v in digger_reconstruct::detect_solana_access_violations(&body) {
                findings.push(serde_json::json!({
                    "detector": "solana_access_control",
                    "function": v.function_id,
                    "kind": v.violation_kind,
                    "severity": "high",
                    "confidence": "experimental",
                    "evidence_refs": [v.provenance.id],
                }));
            }
            for v in digger_reconstruct::detect_unvalidated_cpi(&body) {
                findings.push(serde_json::json!({
                    "detector": "solana_unvalidated_cpi",
                    "function": v.function_id,
                    "kind": v.violation_kind,
                    "severity": "high",
                    "confidence": "experimental",
                    "evidence_refs": [v.provenance.id],
                }));
            }
            for v in digger_reconstruct::detect_type_cosplay(&body) {
                findings.push(serde_json::json!({
                    "detector": "solana_type_cosplay",
                    "function": v.function_id,
                    "kind": v.violation_kind,
                    "severity": "high",
                    "confidence": "experimental",
                    "evidence_refs": [v.provenance.id],
                }));
            }
            for v in digger_reconstruct::detect_unchecked_owner(&body) {
                findings.push(serde_json::json!({
                    "detector": "solana_unchecked_account_owner",
                    "function": v.function_id,
                    "kind": v.violation_kind,
                    "severity": "high",
                    "confidence": "experimental",
                    "evidence_refs": [v.provenance.id],
                }));
            }
        }
    } else {
        for f in digger_reconstruct::detect_price_manipulation(source, &raw) {
            if !f.suppressed {
                findings.push(serde_json::json!({
                    "detector": "price_manipulation",
                    "function": f.function_name,
                    "kind": "PriceOracleManipulation",
                    "severity": "high",
                    "confidence": conf_label,
                    "evidence_refs": [f.function_name],
                }));
            }
        }
        for f in digger_reconstruct::detect_readonly_reentrancy(&raw) {
            if !f.suppressed {
                findings.push(serde_json::json!({
                    "detector": "readonly_reentrancy",
                    "function": f.function_id,
                    "kind": f.finding_kind,
                    "severity": "high",
                    "confidence": conf_label,
                    "evidence_refs": [f.provenance.id],
                }));
            }
        }
    }

    let confidence = if is_solana { "experimental" } else { "mixed" };

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "findings": findings,
            "engine_hypotheses": engine_hypotheses,
            "engine_derived": !engine_hypotheses.is_empty(),
            "source_provenance": "local source",
            "confidence": confidence,
        })),
    )
        .into_response())
}

pub struct ServerConfig {
    pub max_body_bytes: usize,
    pub max_source_bytes: usize,
    pub max_source_lines: usize,
    pub scan_timeout_secs: u64,
    pub concurrency: usize,
    pub semaphore_wait_secs: u64,
    pub rate_limit_per_second: u32,
    pub rate_limit_burst: u32,
    pub db_path: String,
    /// Optional API key for /scan. None = fail-closed unless allow_open.
    pub api_key: Option<String>,
    /// Explicit opt-in for open/allowlist-free mode when api_key is None.
    /// Must be set to true for local dev; defaults false for hosted safety.
    pub allow_open: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 512 * 1024,
            max_source_bytes: 512 * 1024,
            max_source_lines: 5000,
            scan_timeout_secs: 30,
            concurrency: 8,
            semaphore_wait_secs: 5,
            rate_limit_per_second: 10,
            rate_limit_burst: 20,
            db_path: "digger.db".into(),
            api_key: None,
            allow_open: false,
        }
    }
}

pub fn app(config: ServerConfig) -> Router {
    #[allow(clippy::expect_used)]
    // invariant: DB init is a startup requirement — caller must ensure writable path
    let db = auth::init_db(&config.db_path).expect("Failed to initialize database");

    let api_key = config.api_key.or_else(|| {
        let v = std::env::var("DIGGER_API_KEY").ok();
        if v.as_deref() == Some("") {
            None
        } else {
            v
        }
    });

    let allow_open =
        config.allow_open || std::env::var("DIGGER_ALLOW_OPEN").ok().as_deref() == Some("true");

    let state = Arc::new(AppState {
        max_body_bytes: config.max_body_bytes,
        max_source_bytes: config.max_source_bytes,
        max_source_lines: config.max_source_lines,
        scan_timeout: Duration::from_secs(config.scan_timeout_secs),
        semaphore: Arc::new(tokio::sync::Semaphore::new(config.concurrency)),
        semaphore_wait: Duration::from_secs(config.semaphore_wait_secs),
        rate_limit_per_second: config.rate_limit_per_second,
        rate_limit_burst: config.rate_limit_burst,
        rate_limits: Mutex::new(HashMap::new()),
        db,
        api_key,
        allow_open,
    });

    Router::new()
        .route("/healthz", get(healthz))
        .route("/scan", post(scan))
        .route("/auth/signup", post(auth::signup))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/me", get(auth::me))
        .route("/scans", post(scans::save_scan).get(scans::list_scans))
        .route("/scans/:id", get(scans::get_scan))
        .route(
            "/scans/:id/share",
            post(scans::share_scan).delete(scans::revoke_share),
        )
        .route("/r/:token", get(scans::public_report))
        .route("/waitlist", post(waitlist::join_waitlist))
        .route("/waitlist/count", get(waitlist::waitlist_count))
        .route(
            "/monitor/targets",
            post(monitor_api::create_target).get(monitor_api::list_targets),
        )
        .route(
            "/monitor/targets/:id",
            get(monitor_api::get_target).delete(monitor_api::delete_target),
        )
        .route("/monitor/targets/:id/runs", get(monitor_api::list_runs))
        .route("/monitor/targets/:id/tick", post(monitor_api::trigger_tick))
        .route("/monitor/runs/:id", get(monitor_api::get_run))
        .route("/monitor/status", get(monitor_api::monitor_status))
        .route("/copilot/explain", post(copilot::explain_handler))
        .route("/copilot/poc", post(copilot::poc_handler))
        .layer(DefaultBodyLimit::max(state.max_body_bytes))
        .with_state(state)
}

pub fn app_defaults() -> Router {
    app(ServerConfig {
        db_path: std::env::var("DIGGER_DB_PATH").unwrap_or_else(|_| ":memory:".into()),
        ..ServerConfig::default()
    })
}

// ── C37: Copilot module ──
// copilot.rs contains deterministic PoC generation + LLM-assisted explanation logic.
// The /copilot/explain endpoint is wired with session-based auth and owner scoping.

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_app() -> Router {
        app(ServerConfig {
            max_body_bytes: 1024 * 512,
            max_source_bytes: 512 * 1024,
            max_source_lines: 5000,
            scan_timeout_secs: 10,
            concurrency: 4,
            semaphore_wait_secs: 2,
            rate_limit_per_second: 100,
            rate_limit_burst: 200,
            db_path: ":memory:".into(),
            api_key: None,
            allow_open: true,
        })
    }

    fn test_app_with_rate_limit(rps: u32, burst: u32) -> Router {
        app(ServerConfig {
            max_body_bytes: 1024 * 512,
            max_source_bytes: 512 * 1024,
            max_source_lines: 5000,
            scan_timeout_secs: 10,
            concurrency: 4,
            semaphore_wait_secs: 2,
            rate_limit_per_second: rps,
            rate_limit_burst: burst,
            db_path: ":memory:".into(),
            api_key: None,
            allow_open: true,
        })
    }

    fn test_app_with_complexity(max_lines: usize) -> Router {
        app(ServerConfig {
            max_body_bytes: 1024 * 512,
            max_source_bytes: 512 * 1024,
            max_source_lines: max_lines,
            scan_timeout_secs: 10,
            concurrency: 4,
            semaphore_wait_secs: 2,
            rate_limit_per_second: 100,
            rate_limit_burst: 200,
            db_path: ":memory:".into(),
            api_key: None,
            allow_open: true,
        })
    }

    const EVM_SOURCE: &str = r#"contract V {
    uint256 public price;
    mapping(address => uint256) public reserves;
    function swap(address token, uint256 amount) external {
        (bool ok,) = token.call("");
        require(ok);
        uint256 currentPrice = price;
        uint256 output = (amount * currentPrice) / 1e18;
        reserves[token] += amount;
    }
}"#;

    fn scan_request(source: &str, lang: &str) -> Request<Body> {
        Request::builder()
            .uri("/scan")
            .method("POST")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "1.2.3.4")
            .body(Body::from(
                serde_json::json!({"source": source, "language": lang}).to_string(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn test_healthz_200() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_scan_contract_unchanged() {
        let app = test_app();
        let response = app.oneshot(scan_request(EVM_SOURCE, "evm")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["findings"].is_array());
        assert_eq!(json["source_provenance"], "local source");
        assert_eq!(json["confidence"], "mixed");
    }

    #[tokio::test]
    async fn test_empty_source_400() {
        let app = test_app();
        let response = app.oneshot(scan_request("", "evm")).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invalid_language_400() {
        let app = test_app();
        let response = app
            .oneshot(scan_request("contract X {}", "python"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_body_cap_413() {
        let app = app(ServerConfig {
            max_body_bytes: 100,
            db_path: ":memory:".into(),
            ..ServerConfig::default()
        });
        let source = "x".repeat(200);
        let response = app.oneshot(scan_request(&source, "evm")).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_complexity_cap_422() {
        let app = test_app_with_complexity(5);
        let source = "line1\nline2\nline3\nline4\nline5\nline6";
        let response = app.oneshot(scan_request(source, "evm")).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_rate_limit_429() {
        let app = test_app_with_rate_limit(2, 2);
        let ip = "10.0.0.1";

        let mut req1 = scan_request(EVM_SOURCE, "evm");
        req1.headers_mut().remove("x-forwarded-for");
        req1.headers_mut()
            .insert("x-forwarded-for", ip.parse().unwrap());
        let _r1 = app.clone().oneshot(req1).await.unwrap();

        let mut req2 = scan_request(EVM_SOURCE, "evm");
        req2.headers_mut().remove("x-forwarded-for");
        req2.headers_mut()
            .insert("x-forwarded-for", ip.parse().unwrap());
        let _r2 = app.clone().oneshot(req2).await.unwrap();

        let mut req3 = scan_request(EVM_SOURCE, "evm");
        req3.headers_mut().remove("x-forwarded-for");
        req3.headers_mut()
            .insert("x-forwarded-for", ip.parse().unwrap());
        let r3 = app.clone().oneshot(req3).await.unwrap();
        assert_eq!(r3.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(r3.headers().get("retry-after").is_some());
    }

    #[tokio::test]
    async fn test_rate_limit_independent_ips() {
        let app = test_app_with_rate_limit(100, 2);

        let mut req1 = scan_request(EVM_SOURCE, "evm");
        req1.headers_mut().remove("x-forwarded-for");
        req1.headers_mut()
            .insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        let r1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        let mut req2 = scan_request(EVM_SOURCE, "evm");
        req2.headers_mut().remove("x-forwarded-for");
        req2.headers_mut()
            .insert("x-forwarded-for", "10.0.0.2".parse().unwrap());
        let r2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_healthz_not_limited() {
        let app = test_app_with_rate_limit(0, 0);
        for _ in 0..5 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/healthz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn test_malformed_body_400() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from("not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_scan_solana_experimental() {
        let app = test_app();
        let source = r#"
#[program]
pub mod vuln {
    use super::*;
    pub fn mint(ctx: Context<Mint>, amt: u64) -> Result<()> {
        let m = &mut ctx.accounts.mint;
        m.supply += amt;
        Ok(())
    }
}
#[derive(Accounts)]
pub struct Mint<'info> {
    #[account(mut)]
    pub mint: Account<'info, TokenMint>,
}
"#;
        let response = app.oneshot(scan_request(source, "solana")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["confidence"], "experimental");
    }

    // ── C24: Auth tests ──

    fn auth_signup(email: &str, password: &str) -> Request<Body> {
        Request::builder()
            .uri("/auth/signup")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"email": email, "password": password}).to_string(),
            ))
            .unwrap()
    }

    fn auth_login(email: &str, password: &str) -> Request<Body> {
        Request::builder()
            .uri("/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"email": email, "password": password}).to_string(),
            ))
            .unwrap()
    }

    fn auth_logout() -> Request<Body> {
        Request::builder()
            .uri("/auth/logout")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap()
    }

    fn auth_me_with_cookie(cookie: &str) -> Request<Body> {
        Request::builder()
            .uri("/me")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap()
    }

    fn extract_cookie(response: &axum::http::Response<Body>) -> Option<String> {
        response
            .headers()
            .get("set-cookie")?
            .to_str()
            .ok()?
            .split(';')
            .next()
            .map(|s| s.to_string())
    }

    #[tokio::test]
    async fn test_signup_creates_user() {
        let app = test_app();
        let response = app
            .oneshot(auth_signup("test@example.com", "StrongP4ss"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["email"], "test@example.com");
        assert!(json["id"].is_string());
    }

    #[tokio::test]
    async fn test_signup_duplicate_409() {
        let app = test_app();
        let _ = app
            .clone()
            .oneshot(auth_signup("dup@example.com", "StrongP4ss"))
            .await
            .unwrap();
        let response = app
            .oneshot(auth_signup("dup@example.com", "StrongP4ss"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_signup_weak_password_422() {
        let app = test_app();
        let response = app
            .oneshot(auth_signup("weak@example.com", "short"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["error"].as_str().unwrap().contains("8 characters"));
    }

    #[tokio::test]
    async fn test_login_success_sets_session() {
        let app = test_app();
        let _ = app
            .clone()
            .oneshot(auth_signup("login@example.com", "StrongP4ss"))
            .await
            .unwrap();
        let response = app
            .oneshot(auth_login("login@example.com", "StrongP4ss"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = extract_cookie(&response);
        assert!(cookie.is_some());
        assert!(cookie.unwrap().contains("digger_session="));
    }

    #[tokio::test]
    async fn test_login_bad_password_401() {
        let app = test_app();
        let _ = app
            .clone()
            .oneshot(auth_signup("bad@example.com", "StrongP4ss"))
            .await
            .unwrap();
        let response = app
            .oneshot(auth_login("bad@example.com", "WrongPass1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_login_unknown_email_401() {
        let app = test_app();
        let response = app
            .oneshot(auth_login("nobody@example.com", "StrongP4ss"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "Invalid email or password");
    }

    #[tokio::test]
    async fn test_me_requires_auth() {
        let app = test_app();
        let response = app
            .oneshot(auth_me_with_cookie("digger_session=invalid"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_me_logged_in() {
        let app = test_app();
        let _ = app
            .clone()
            .oneshot(auth_signup("me@example.com", "StrongP4ss"))
            .await
            .unwrap();
        let login_resp = app
            .clone()
            .oneshot(auth_login("me@example.com", "StrongP4ss"))
            .await
            .unwrap();
        let cookie = extract_cookie(&login_resp).unwrap();

        let response = app.oneshot(auth_me_with_cookie(&cookie)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["email"], "me@example.com");
    }

    #[tokio::test]
    async fn test_logout_invalidates_session() {
        let app = test_app();
        let _ = app
            .clone()
            .oneshot(auth_signup("out@example.com", "StrongP4ss"))
            .await
            .unwrap();
        let login_resp = app
            .clone()
            .oneshot(auth_login("out@example.com", "StrongP4ss"))
            .await
            .unwrap();
        let cookie = extract_cookie(&login_resp).unwrap();

        let mut logout_req = auth_logout();
        logout_req
            .headers_mut()
            .insert("cookie", cookie.parse().unwrap());
        let _ = app.clone().oneshot(logout_req).await.unwrap();

        let response = app.oneshot(auth_me_with_cookie(&cookie)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_password_never_in_response() {
        let app = test_app();
        let response = app
            .oneshot(auth_signup("safe@example.com", "StrongP4ss"))
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("StrongP4ss"));
        assert!(!text.contains("password_hash"));
        assert!(!text.contains("$argon2"));
    }

    #[tokio::test]
    async fn test_scan_anonymous_still_works() {
        let app = test_app();
        let response = app.oneshot(scan_request(EVM_SOURCE, "evm")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── C25: Scan history + shareable report tests ──

    async fn signup_and_login(app: &Router, email: &str, password: &str) -> String {
        let _ = app
            .clone()
            .oneshot(auth_signup(email, password))
            .await
            .unwrap();
        let resp = app
            .clone()
            .oneshot(auth_login(email, password))
            .await
            .unwrap();
        extract_cookie(&resp).unwrap()
    }

    async fn save_scan_with_cookie(
        app: &Router,
        cookie: &str,
        findings: &[serde_json::Value],
    ) -> String {
        let body = serde_json::json!({
            "language": "evm",
            "source": "contract X {}",
            "findings": findings,
            "provenance": "local source",
        });
        let req = Request::builder()
            .uri("/scans")
            .method("POST")
            .header("content-type", "application/json")
            .header("cookie", cookie)
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
        j["id"].as_str().unwrap().to_string()
    }

    async fn share_scan_with_cookie(app: &Router, cookie: &str, scan_id: &str) -> String {
        let req = Request::builder()
            .uri(format!("/scans/{}/share", scan_id))
            .method("POST")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
        j["share_token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_save_scan_requires_auth() {
        let app = test_app();
        let body = serde_json::json!({"language":"evm","source":"x","findings":[],"provenance":"local source"});
        let req = Request::builder()
            .uri("/scans")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_save_scan_persists_no_raw_source() {
        let app = test_app();
        let cookie = signup_and_login(&app, "save@test.com", "StrongP4ss").await;
        let scan_id =
            save_scan_with_cookie(&app, &cookie, &[serde_json::json!({"detector":"test"})]).await;

        let req = Request::builder()
            .uri(format!("/scans/{}", scan_id))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert!(j.get("source_sha256").is_some());
    }

    #[tokio::test]
    async fn test_list_scans_owner_only() {
        let app = test_app();
        let cookie1 = signup_and_login(&app, "list1@test.com", "StrongP4ss").await;
        let _ = save_scan_with_cookie(&app, &cookie1, &[]).await;
        let cookie2 = signup_and_login(&app, "list2@test.com", "StrongP4ss").await;

        let req1 = Request::builder()
            .uri("/scans")
            .header("cookie", &cookie1)
            .body(Body::empty())
            .unwrap();
        let resp1 = app.clone().oneshot(req1).await.unwrap();
        let b1 = axum::body::to_bytes(resp1.into_body(), usize::MAX)
            .await
            .unwrap();
        let j1: Vec<serde_json::Value> = serde_json::from_slice(&b1).unwrap();
        assert_eq!(j1.len(), 1);

        let req2 = Request::builder()
            .uri("/scans")
            .header("cookie", &cookie2)
            .body(Body::empty())
            .unwrap();
        let resp2 = app.clone().oneshot(req2).await.unwrap();
        let b2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let j2: Vec<serde_json::Value> = serde_json::from_slice(&b2).unwrap();
        assert_eq!(j2.len(), 0);
    }

    #[tokio::test]
    async fn test_get_scan_nonowner_404() {
        let app = test_app();
        let cookie1 = signup_and_login(&app, "own1@test.com", "StrongP4ss").await;
        let scan_id = save_scan_with_cookie(&app, &cookie1, &[]).await;
        let cookie2 = signup_and_login(&app, "own2@test.com", "StrongP4ss").await;

        let req = Request::builder()
            .uri(format!("/scans/{}", scan_id))
            .header("cookie", &cookie2)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_share_creates_token() {
        let app = test_app();
        let cookie = signup_and_login(&app, "share@test.com", "StrongP4ss").await;
        let scan_id = save_scan_with_cookie(&app, &cookie, &[]).await;

        let token = share_scan_with_cookie(&app, &cookie, &scan_id).await;
        assert!(!token.is_empty());
    }

    #[tokio::test]
    async fn test_public_report_renders_when_shared() {
        let app = test_app();
        let cookie = signup_and_login(&app, "pub@test.com", "StrongP4ss").await;
        let scan_id = save_scan_with_cookie(
            &app,
            &cookie,
            &[serde_json::json!({"detector":"test","severity":"high","confidence":"experimental"})],
        )
        .await;

        let token = share_scan_with_cookie(&app, &cookie, &scan_id).await;

        let pub_req = Request::builder()
            .uri(format!("/r/{}", token))
            .body(Body::empty())
            .unwrap();
        let pub_resp = app.oneshot(pub_req).await.unwrap();
        assert_eq!(pub_resp.status(), StatusCode::OK);
        let pb = axum::body::to_bytes(pub_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let pj: serde_json::Value = serde_json::from_slice(&pb).unwrap();
        assert!(pj["findings"].is_array());
        assert_eq!(pj["findings"].as_array().unwrap().len(), 1);
        assert_eq!(pj["findings"][0]["confidence"], "experimental");
        assert!(pj["disclaimer"].as_str().unwrap().contains("triage"));
    }

    #[tokio::test]
    async fn test_public_report_404_when_not_shared() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/r/nonexistenttoken")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_revoke_share_then_404() {
        let app = test_app();
        let cookie = signup_and_login(&app, "revoke@test.com", "StrongP4ss").await;
        let scan_id = save_scan_with_cookie(&app, &cookie, &[]).await;
        let token = share_scan_with_cookie(&app, &cookie, &scan_id).await;

        let revoke_req = Request::builder()
            .uri(format!("/scans/{}/share", scan_id))
            .method("DELETE")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let revoke_resp = app.clone().oneshot(revoke_req).await.unwrap();
        assert_eq!(revoke_resp.status(), StatusCode::OK);

        let pub_req = Request::builder()
            .uri(format!("/r/{}", token))
            .body(Body::empty())
            .unwrap();
        let pub_resp = app.oneshot(pub_req).await.unwrap();
        assert_eq!(pub_resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_share_token_unguessable() {
        let app = test_app();
        let cookie = signup_and_login(&app, "entropy@test.com", "StrongP4ss").await;
        let id1 = save_scan_with_cookie(&app, &cookie, &[]).await;
        let id2 = save_scan_with_cookie(&app, &cookie, &[]).await;

        let t1 = share_scan_with_cookie(&app, &cookie, &id1).await;
        let t2 = share_scan_with_cookie(&app, &cookie, &id2).await;
        assert_ne!(t1, t2);
        assert!(t1.len() >= 32);
    }

    // ── C27: Waitlist tests ──

    fn waitlist_request(email: &str) -> Request<Body> {
        Request::builder()
            .uri("/waitlist")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({"email": email}).to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn test_waitlist_valid_email_persists() {
        let app = test_app();
        let resp = app
            .oneshot(waitlist_request("test@example.com"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let j: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(j["message"], "You're on the list!");
    }

    #[tokio::test]
    async fn test_waitlist_rate_limited() {
        let app = app(ServerConfig {
            max_body_bytes: 1024 * 512,
            max_source_bytes: 512 * 1024,
            max_source_lines: 5000,
            scan_timeout_secs: 10,
            concurrency: 4,
            semaphore_wait_secs: 2,
            rate_limit_per_second: 1,
            rate_limit_burst: 1,
            db_path: ":memory:".into(),
            api_key: None,
            allow_open: true,
        });
        let r1 = app
            .clone()
            .oneshot(waitlist_request("rl1@example.com"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = app
            .clone()
            .oneshot(waitlist_request("rl2@example.com"))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_waitlist_invalid_email_422() {
        let app = test_app();
        let resp = app.oneshot(waitlist_request("not-an-email")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_waitlist_duplicate_idempotent() {
        let app = test_app();
        let r1 = app
            .clone()
            .oneshot(waitlist_request("dup@example.com"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = app
            .oneshot(waitlist_request("dup@example.com"))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
    }

    // ── C35: Monitor API tests ──

    async fn create_and_login(app: &Router, email: &str, password: &str) -> String {
        let _ = app
            .clone()
            .oneshot(auth_signup(email, password))
            .await
            .unwrap();
        let resp = app
            .clone()
            .oneshot(auth_login(email, password))
            .await
            .unwrap();
        extract_cookie(&resp).unwrap()
    }

    fn monitor_target_request(cookie: &str, descriptor: &str, channel: &str) -> Request<Body> {
        Request::builder()
            .uri("/monitor/targets")
            .method("POST")
            .header("content-type", "application/json")
            .header("cookie", cookie)
            .body(Body::from(
                serde_json::json!({"target_descriptor": descriptor, "alert_channel": channel})
                    .to_string(),
            ))
            .unwrap()
    }

    fn monitor_get_targets(cookie: &str) -> Request<Body> {
        Request::builder()
            .uri("/monitor/targets")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_monitor_target_crud() {
        let app = test_app();
        let cookie = create_and_login(&app, "mon1@test.com", "StrongP4ss").await;

        // Create
        let r = app
            .clone()
            .oneshot(monitor_target_request(&cookie, "org/repo", "#alerts"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let target_id = body["id"].as_str().unwrap().to_string();

        // List
        let r = app
            .clone()
            .oneshot(monitor_get_targets(&cookie))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let targets: Vec<serde_json::Value> = serde_json::from_slice(
            &axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0]["id"].as_str().unwrap(), &target_id);

        // Get detail
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/monitor/targets/{}", target_id))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        // Delete
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/monitor/targets/{}", target_id))
                    .method("DELETE")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        // Verify deleted
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/monitor/targets/{}", target_id))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_monitor_unauthenticated_401() {
        let app = test_app();
        let r = app
            .oneshot(monitor_target_request(
                "digger_session=invalid",
                "org/repo",
                "#alerts",
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_monitor_cross_tenant_404() {
        let app = test_app();
        let cookie1 = create_and_login(&app, "t1@test.com", "StrongP4ss").await;
        let cookie2 = create_and_login(&app, "t2@test.com", "StrongP4ss").await;

        let r = app
            .clone()
            .oneshot(monitor_target_request(&cookie1, "org/repo", "#alerts"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let target_id = body["id"].as_str().unwrap().to_string();

        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/monitor/targets/{}", target_id))
                    .header("cookie", &cookie2)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_monitor_empty_descriptor_422() {
        let app = test_app();
        let cookie = create_and_login(&app, "desc@test.com", "StrongP4ss").await;
        let r = app
            .oneshot(
                Request::builder()
                    .uri("/monitor/targets")
                    .method("POST")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .body(Body::from(
                        serde_json::json!({"target_descriptor": "", "alert_channel": "#x"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_monitor_tick() {
        let app = test_app();
        let cookie = create_and_login(&app, "tick@test.com", "StrongP4ss").await;

        let r = app
            .clone()
            .oneshot(monitor_target_request(&cookie, "org/repo", "#alerts"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let target_id = body["id"].as_str().unwrap().to_string();

        let r = app
            .oneshot(
                Request::builder()
                    .uri(format!("/monitor/targets/{}/tick", target_id))
                    .method("POST")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(body["revision"].as_str().unwrap().starts_with("tick-"));
    }

    #[test]
    fn test_wal_mode_and_busy_timeout() {
        use rusqlite::Connection;
        let tmp = std::env::temp_dir().join(format!("digger_test_wal_{}", uuid::Uuid::new_v4()));
        let conn = Connection::open(&tmp).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(timeout, 5000);
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp.with_extension("db-shm"));
    }

    // ── C45: End-to-end integration tests ─────────────────────

    #[tokio::test]
    async fn test_c45_full_loop_auth_to_tick() {
        let app = test_app();
        let signup = app
            .clone()
            .oneshot(
                Request::post("/auth/signup")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(
                            &serde_json::json!({"email":"c45@test.com","password":"Test1234"}),
                        )
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(signup.status(), StatusCode::CREATED);
        let login = app
            .clone()
            .oneshot(
                Request::post("/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(
                            &serde_json::json!({"email":"c45@test.com","password":"Test1234"}),
                        )
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = extract_cookie(&login).unwrap();
        assert!(
            cookie.starts_with("digger_session="),
            "Must set session cookie"
        );
        // Verify Secure and HttpOnly in the raw Set-Cookie header
        let raw_cookie = login.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(
            raw_cookie.contains("HttpOnly"),
            "Cookie must have HttpOnly flag"
        );
        assert!(
            raw_cookie.contains("Secure"),
            "Cookie must have Secure flag"
        );
        assert!(
            raw_cookie.contains("SameSite=Strict"),
            "Cookie must have SameSite=Strict"
        );

        let create = app.clone().oneshot(
            Request::post("/monitor/targets")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .body(Body::from(serde_json::to_string(&serde_json::json!({"target_descriptor":"solana:fixture","alert_channel":"none","poll_interval_secs":1})).unwrap())).unwrap(),
        ).await.unwrap();
        assert!(
            create.status().is_success(),
            "Create target must succeed: {}",
            create.status()
        );
        let cid: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(create.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let tid = cid["id"].as_str().unwrap().to_string();

        let tick = app
            .clone()
            .oneshot(
                Request::post(format!("/monitor/targets/{}/tick", tid))
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tick.status(), StatusCode::OK);
        let tb: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(tick.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(tb["revision"].as_str().unwrap().starts_with("tick-"));
        assert!(tb["bundle_hash"].as_str().is_some());
        // Note: run records are ephemeral in the tick handler (InMemoryMonitorStore per request).
        // The full persistent run history requires the daemon, not the manual tick endpoint.
    }

    #[test]
    fn test_c45_restart_resume() {
        let tmp = std::env::temp_dir().join(format!("d45_rst_{}", uuid::Uuid::new_v4()));
        let db = tmp.to_string_lossy().to_string();
        let _ = auth::init_db(&db);
        {
            let c = rusqlite::Connection::open(&db).unwrap();
            c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
                .unwrap();
            c.execute("INSERT INTO watch_targets (id,tenant_id,target_descriptor,alert_channel,poll_interval_secs) VALUES (?1,?2,?3,?4,?5)",
              rusqlite::params!["t1","ten","solana:px","none",60]).unwrap();
            c.execute_batch("CREATE TABLE IF NOT EXISTS monitor_state(target_id TEXT PRIMARY KEY,last_revision TEXT,last_bundle_hash TEXT,last_finding_ids TEXT DEFAULT '[]',already_actioned_finding_ids TEXT DEFAULT '[]');").unwrap();
            c.execute("INSERT INTO monitor_state(target_id,last_revision,last_finding_ids,already_actioned_finding_ids) VALUES(?1,?2,?3,?4)",
              rusqlite::params!["t1","rev-1","[]","[]"]).unwrap();
        }
        {
            let c = rusqlite::Connection::open(&db).unwrap();
            assert_eq!(
                c.query_row("SELECT COUNT(*) FROM watch_targets", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                c.query_row("SELECT COUNT(*) FROM monitor_state", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                c.query_row(
                    "SELECT target_descriptor FROM watch_targets WHERE id='t1'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
                "solana:px"
            );
        }
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp.with_extension("db-shm"));
    }

    #[test]
    fn test_c45_schema_migration() {
        let tmp = std::env::temp_dir().join(format!("d45_mig_{}", uuid::Uuid::new_v4()));
        let db = tmp.to_string_lossy().to_string();
        {
            let c = rusqlite::Connection::open(&db).unwrap();
            c.execute_batch("CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);CREATE TABLE scans(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,language TEXT,findings TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);").unwrap();
            c.execute(
                "INSERT INTO users(id,email,password_hash) VALUES('u1','old@t.com','h')",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO scans(id,user_id,language,findings) VALUES('s1','u1','evm','[]')",
                [],
            )
            .unwrap();
        }
        let _ = auth::init_db(&db);
        {
            let c = rusqlite::Connection::open(&db).unwrap();
            assert_eq!(
                c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                c.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                c.query_row("SELECT COUNT(*) FROM watch_targets", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                c.query_row("SELECT COUNT(*) FROM monitor_state", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp.with_extension("db-shm"));
    }

    #[test]
    fn test_c45_wal_concurrent() {
        let tmp = std::env::temp_dir().join(format!("d45_wal_{}", uuid::Uuid::new_v4()));
        let db = tmp.to_string_lossy().to_string();
        let _ = auth::init_db(&db);
        let c1 = rusqlite::Connection::open(&db).unwrap();
        c1.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .unwrap();
        let c2 = rusqlite::Connection::open(&db).unwrap();
        c2.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .unwrap();
        for i in 0..10 {
            c1.execute("INSERT INTO watch_targets(id,tenant_id,target_descriptor,alert_channel,poll_interval_secs) VALUES(?1,?2,?3,?4,?5)",
                rusqlite::params![format!("a{}",i),"t1","d","none",60]).unwrap();
            c2.execute("INSERT INTO watch_targets(id,tenant_id,target_descriptor,alert_channel,poll_interval_secs) VALUES(?1,?2,?3,?4,?5)",
                rusqlite::params![format!("b{}",i),"t2","d","none",60]).unwrap();
        }
        assert_eq!(
            c1.query_row("SELECT COUNT(*) FROM watch_targets", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            20
        );
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp.with_extension("db-shm"));
    }

    #[tokio::test]
    async fn test_c45_scan_shape_unchanged() {
        let app = test_app();
        let resp = app.oneshot(
            Request::post("/scan").header("content-type","application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({"source":"pragma solidity ^0.8.0; contract X{}","language":"evm"})).unwrap())).unwrap(),
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(b.get("findings").is_some());
        assert!(b.get("source_provenance").is_some());
        assert!(b.get("confidence").is_some());
    }

    #[test]
    fn test_c45_degradation_no_copilot() {
        use digger_monitor::monitor::Monitor;
        use digger_monitor::source::MockMonitorSource;
        use digger_monitor::state::WatchTarget;
        use digger_monitor::store::InMemoryMonitorStore;

        let source = MockMonitorSource::new(vec![digger_monitor::source::Revision {
            id: "r".into(),
            content_hash: "h".into(),
        }]);
        let store = Arc::new(InMemoryMonitorStore::new());
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let gw = Arc::new(digger_runtime::ActionGateway::new(
            digger_runtime::Policy::default(),
            evidence.clone(),
            Arc::new(digger_runtime::InMemoryAuditStore::new()),
            Arc::new(digger_runtime::ApprovalService::new(3600)),
            Arc::new(digger_runtime::CredentialBroker::new(300)),
            std::collections::BTreeMap::new(),
        ));
        let monitor = Monitor::new(source, store, gw, evidence);
        let target = WatchTarget {
            tenant_id: "t1".into(),
            target_descriptor: "solana:x".into(),
            alert_channel: "none".into(),
        };
        let report = monitor.tick(&target, "tgt-x");
        assert!(
            !report.revision.is_empty(),
            "Tick must succeed without copilot"
        );
    }

    #[test]
    fn test_c45_daemon_run_once() {
        use digger_monitor::clock::MockClock;
        use digger_monitor::daemon::MonitorDaemon;
        use digger_monitor::history::InMemoryHistoryStore;
        use digger_monitor::monitor::Monitor;
        use digger_monitor::scheduler::TargetConfig;
        use digger_monitor::source::MockMonitorSource;
        use digger_monitor::state::WatchTarget;
        use digger_monitor::store::InMemoryMonitorStore;

        let store = Arc::new(InMemoryMonitorStore::new());
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let gw = Arc::new(digger_runtime::ActionGateway::new(
            digger_runtime::Policy::default(),
            evidence.clone(),
            Arc::new(digger_runtime::InMemoryAuditStore::new()),
            Arc::new(digger_runtime::ApprovalService::new(3600)),
            Arc::new(digger_runtime::CredentialBroker::new(300)),
            std::collections::BTreeMap::new(),
        ));
        let target = WatchTarget {
            tenant_id: "t1".into(),
            target_descriptor: "solana:d".into(),
            alert_channel: "none".into(),
        };
        use digger_monitor::store::MonitorStore;
        MonitorStore::save_target(&*store, "tgt-d", &target).unwrap();
        let source = MockMonitorSource::new(vec![digger_monitor::source::Revision {
            id: "d".into(),
            content_hash: "dh".into(),
        }]);
        let monitor = Monitor::new(source, store, gw, evidence);
        let clock = Arc::new(MockClock::new(0));
        let history = Arc::new(InMemoryHistoryStore::new());
        let mut daemon = MonitorDaemon::new(monitor, clock, history);
        daemon.register_target(
            "tgt-d",
            TargetConfig {
                target: target.clone(),
                poll_interval_secs: 60,
            },
        );
        let summary = daemon.run_once();
        assert!(
            !summary.ran.is_empty()
                || !summary.skipped_due_to_budget.is_empty()
                || !summary.backed_off.is_empty(),
            "Daemon should attempt at least one target: {:?}",
            summary
        );
    }

    // ── Phase 9: Copilot route-level integration tests ──

    fn copilot_explain_request(cookie: &str, finding_id: &str) -> Request<Body> {
        copilot_explain_request_with_context(cookie, finding_id, None)
    }

    fn copilot_explain_request_with_context(
        cookie: &str,
        finding_id: &str,
        context: Option<&str>,
    ) -> Request<Body> {
        let mut body = serde_json::json!({"finding_id": finding_id});
        if let Some(ctx) = context {
            body["context"] = serde_json::json!(ctx);
        }
        Request::builder()
            .uri("/copilot/explain")
            .method("POST")
            .header("content-type", "application/json")
            .header("cookie", cookie)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn copilot_poc_request(cookie: &str, finding_id: &str) -> Request<Body> {
        Request::builder()
            .uri("/copilot/poc")
            .method("POST")
            .header("content-type", "application/json")
            .header("cookie", cookie)
            .body(Body::from(
                serde_json::json!({"finding_id": finding_id}).to_string(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn test_copilot_auth_required() {
        let app = test_app();

        // No cookie → 401
        let req = Request::builder()
            .uri("/copilot/explain")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"finding_id": "f1"}).to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong cookie → 401
        let resp = app
            .clone()
            .oneshot(copilot_explain_request("digger_session=invalid", "f1"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Valid cookie → 200 (finding may not exist, but auth passes)
        let cookie = signup_and_login(&app, "auth@test.com", "StrongP4ss").await;
        let _ = save_scan_with_cookie(
            &app,
            &cookie,
            &[serde_json::json!({"finding_id":"f1","rule_id":"test","severity":"high","confidence":"experimental"})],
        )
        .await;
        let resp = app
            .oneshot(copilot_explain_request(&cookie, "f1"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_copilot_owner_scoping() {
        let app = test_app();
        let cookie_a = signup_and_login(&app, "owner_a@test.com", "StrongP4ss").await;
        let scan_id_a = save_scan_with_cookie(
            &app,
            &cookie_a,
            &[serde_json::json!({"finding_id":"fX","rule_id":"test","severity":"high","confidence":"experimental"})],
        )
        .await;
        assert!(!scan_id_a.is_empty());

        let cookie_b = signup_and_login(&app, "owner_b@test.com", "StrongP4ss").await;

        // User B requests fX → 404 (not in their scans)
        let resp = app
            .clone()
            .oneshot(copilot_explain_request(&cookie_b, "fX"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // User A requests fX → 200
        let resp = app
            .oneshot(copilot_explain_request(&cookie_a, "fX"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_copilot_rate_limit() {
        // rps=1 means slow refill, burst=2 per-IP bucket.
        // signup/login use default IP 127.0.0.1 → their own bucket (2 tokens, fine).
        // copilot uses IP 10.0.0.50 → separate bucket, 3 requests exhaust burst.
        let app = test_app_with_rate_limit(1, 2);
        let copilot_ip = "10.0.0.50";

        let cookie = signup_and_login(&app, "rl2_cop@test.com", "StrongP4ss").await;
        let _ = save_scan_with_cookie(
            &app,
            &cookie,
            &[serde_json::json!({"finding_id":"f1","rule_id":"test","severity":"high","confidence":"experimental"})],
        )
        .await;

        // Request 1: succeeds (tokens 2→1)
        let mut req1 = copilot_explain_request(&cookie, "f1");
        req1.headers_mut()
            .insert("x-forwarded-for", copilot_ip.parse().unwrap());
        let r1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        // Request 2: succeeds (tokens 1→0)
        let mut req2 = copilot_explain_request(&cookie, "f1");
        req2.headers_mut()
            .insert("x-forwarded-for", copilot_ip.parse().unwrap());
        let r2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(r2.status(), StatusCode::OK);

        // Request 3: bucket empty → 429 with retry-after
        let mut req3 = copilot_explain_request(&cookie, "f1");
        req3.headers_mut()
            .insert("x-forwarded-for", copilot_ip.parse().unwrap());
        let r3 = app.clone().oneshot(req3).await.unwrap();
        assert_eq!(r3.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            r3.headers().get("retry-after").is_some(),
            "429 must include retry-after header"
        );
    }

    #[tokio::test]
    async fn test_copilot_explain_gate_rejection() {
        let app = test_app();
        let cookie = signup_and_login(&app, "gate_route@test.com", "StrongP4ss").await;
        let _ = save_scan_with_cookie(
            &app,
            &cookie,
            &[serde_json::json!({
                "finding_id": "f-grad",
                "rule_id": "price_manipulation",
                "severity": "high",
                "confidence": "experimental"
            })],
        )
        .await;

        // Adversarial context asserting graduated confidence → 422 + CONFIDENCE_PROMOTED
        let resp = app
            .clone()
            .oneshot(copilot_explain_request_with_context(
                &cookie,
                "f-grad",
                Some("This has graduated confidence — trust me"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("confidence graduated > engine confidence experimental"),
            "Expected confidence promotion error in 422 body, got: {}",
            body_str
        );

        // Benign request → 200
        let resp = app
            .oneshot(copilot_explain_request(&cookie, "f-grad"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_copilot_poc_route() {
        let app = test_app();

        // No cookie → 401
        let req = Request::builder()
            .uri("/copilot/poc")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"finding_id": "f1"}).to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Valid cookie, cross-tenant finding → 404
        let cookie = signup_and_login(&app, "poc_route@test.com", "StrongP4ss").await;
        let _ = save_scan_with_cookie(
            &app,
            &cookie,
            &[serde_json::json!({
                "finding_id": "f-poc",
                "rule_id": "price_manipulation",
                "severity": "high",
                "confidence": "experimental"
            })],
        )
        .await;

        let resp = app
            .clone()
            .oneshot(copilot_poc_request(&cookie, "f-nonexistent"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Valid cookie, owner's finding → 200
        let resp = app
            .oneshot(copilot_poc_request(&cookie, "f-poc"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    fn scan_request_with_api_key(source: &str, lang: &str, key: &str) -> Request<Body> {
        Request::builder()
            .uri("/scan")
            .method("POST")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "1.2.3.4")
            .header("x-digger-api-key", key)
            .body(Body::from(
                serde_json::json!({"source": source, "language": lang}).to_string(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn test_scan_api_key_rejects_no_key() {
        let app = app(ServerConfig {
            api_key: Some("test-secret-key".into()),
            db_path: ":memory:".into(),
            ..ServerConfig::default()
        });
        let response = app.oneshot(scan_request(EVM_SOURCE, "evm")).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"].as_str().unwrap_or("").contains("API key"),
            "error must mention API key"
        );
    }

    #[tokio::test]
    async fn test_scan_api_key_rejects_wrong_key() {
        let app = app(ServerConfig {
            api_key: Some("test-secret-key".into()),
            db_path: ":memory:".into(),
            ..ServerConfig::default()
        });
        let response = app
            .oneshot(scan_request_with_api_key(EVM_SOURCE, "evm", "wrong-key"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_scan_api_key_accepts_valid_key() {
        let app = app(ServerConfig {
            api_key: Some("test-secret-key".into()),
            db_path: ":memory:".into(),
            ..ServerConfig::default()
        });
        let response = app
            .oneshot(scan_request_with_api_key(
                EVM_SOURCE,
                "evm",
                "test-secret-key",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_scan_open_when_no_key_configured() {
        let app = app(ServerConfig {
            api_key: None,
            allow_open: true,
            db_path: ":memory:".into(),
            ..ServerConfig::default()
        });
        let response = app.oneshot(scan_request(EVM_SOURCE, "evm")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_scan_fails_closed_when_unconfigured() {
        // Default posture: api_key=None, allow_open=false → must reject
        let closed_router = app(ServerConfig {
            api_key: None,
            allow_open: false,
            db_path: ":memory:".into(),
            ..ServerConfig::default()
        });
        let response = closed_router
            .oneshot(scan_request(EVM_SOURCE, "evm"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap_or("")
                .contains("misconfigured"),
            "error message must mention misconfiguration"
        );
        // Flip-proof: same request with allow_open=true → 200
        let open_router = app(ServerConfig {
            api_key: None,
            allow_open: true,
            db_path: ":memory:".into(),
            ..ServerConfig::default()
        });
        let response_open = open_router
            .oneshot(scan_request(EVM_SOURCE, "evm"))
            .await
            .unwrap();
        assert_eq!(response_open.status(), StatusCode::OK);
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(
            constant_time_eq(b"hello", b"hello"),
            "equal slices must match"
        );
        assert!(constant_time_eq(b"", b""), "empty equal slices must match");
        assert!(
            !constant_time_eq(b"hello", b"hellx"),
            "one-byte-different same-length must not match"
        );
        assert!(
            !constant_time_eq(b"key123", b"key12"),
            "prefix (different length) must not match"
        );
        assert!(
            !constant_time_eq(b"", b"k"),
            "empty vs nonempty must not match"
        );
    }

    #[tokio::test]
    async fn constant_time_eq_through_real_router() {
        let app = app(ServerConfig {
            api_key: Some("real-key-42".into()),
            db_path: ":memory:".into(),
            ..ServerConfig::default()
        });
        // correct key → 200
        let resp_ok = app
            .clone()
            .oneshot(scan_request_with_api_key(EVM_SOURCE, "evm", "real-key-42"))
            .await
            .unwrap();
        assert_eq!(resp_ok.status(), StatusCode::OK);
        // wrong key → 401
        let resp_bad = app
            .oneshot(scan_request_with_api_key(EVM_SOURCE, "evm", "wrong-key-xx"))
            .await
            .unwrap();
        assert_eq!(resp_bad.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_scan_op_layer_positive_fires_through_router() {
        let app = test_app();
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap().parent().unwrap().to_path_buf();
        let fixture = root.join("corpus/operational-layer/positive-feed-update/handler.ts");
        assert!(fixture.exists(), "fixture must exist: {:?}", fixture);
        let source = std::fs::read_to_string(&fixture).unwrap();

        let response = app
            .oneshot(scan_request(&source, "op-layer"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let findings = json["findings"].as_array().unwrap();
        assert!(
            !findings.is_empty(),
            "positive op-layer fixture must produce >=1 finding"
        );
        let op_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["detector"] == "op_unverified_attestation")
            .collect();
        assert_eq!(op_findings.len(), 1, "must have exactly 1 op-layer finding");
        assert_eq!(op_findings[0]["severity"], "high");
        assert_eq!(op_findings[0]["confidence"], "experimental");
    }

    #[tokio::test]
    async fn test_scan_op_layer_benign_zero_findings() {
        let app = test_app();
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap().parent().unwrap().to_path_buf();
        let fixture = root.join("corpus/operational-layer/benign-feed-with-verify/handler.ts");
        assert!(fixture.exists(), "fixture must exist: {:?}", fixture);
        let source = std::fs::read_to_string(&fixture).unwrap();

        let response = app
            .oneshot(scan_request(&source, "op-layer"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let findings = json["findings"].as_array().unwrap();
        let op_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["detector"] == "op_unverified_attestation")
            .collect();
        assert!(
            op_findings.is_empty(),
            "benign op-layer fixture must emit 0 op_unverified_attestation, got {:?}",
            op_findings
        );
    }

    #[tokio::test]
    async fn test_scan_invalid_language_still_400() {
        let app = test_app();
        let response = app
            .oneshot(scan_request("source code", "python"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_scan_op_cp_positive_through_router() {
        let app = test_app();
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap().parent().unwrap().to_path_buf();
        let fixture =
            root.join("corpus/operational-layer/positive-control-plane-routing/handler.ts");
        assert!(fixture.exists(), "fixture must exist: {:?}", fixture);
        let source = std::fs::read_to_string(&fixture).unwrap();

        let response = app
            .oneshot(scan_request(&source, "op-layer"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let findings = json["findings"].as_array().unwrap();
        assert!(
            !findings.is_empty(),
            "positive op-cp fixture must produce >=1 finding"
        );
        let cp_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["detector"] == "op_control_plane_authority")
            .collect();
        assert_eq!(
            cp_findings.len(),
            1,
            "must have exactly 1 op_control_plane_authority finding, got {:?}",
            cp_findings
        );
        assert_eq!(cp_findings[0]["severity"], "high");
        assert_eq!(cp_findings[0]["confidence"], "experimental");
    }

    #[tokio::test]
    async fn test_scan_op_cp_benign_zero_through_router() {
        let app = test_app();
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap().parent().unwrap().to_path_buf();
        let fixture =
            root.join("corpus/operational-layer/benign-control-plane-allowlisted/handler.ts");
        assert!(fixture.exists(), "fixture must exist: {:?}", fixture);
        let source = std::fs::read_to_string(&fixture).unwrap();

        let response = app
            .oneshot(scan_request(&source, "op-layer"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let findings = json["findings"].as_array().unwrap();
        let cp_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["detector"] == "op_control_plane_authority")
            .collect();
        assert!(
            cp_findings.is_empty(),
            "benign op-cp fixture must emit 0 op_control_plane_authority, got {:?}",
            cp_findings
        );
    }

    #[tokio::test]
    async fn test_scan_op_fob_positive_through_router() {
        let app = test_app();
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap().parent().unwrap().to_path_buf();
        let fixture = root.join("corpus/operational-layer/positive-fail-open-breaker/handler.ts");
        assert!(fixture.exists(), "fixture must exist: {:?}", fixture);
        let source = std::fs::read_to_string(&fixture).unwrap();

        let response = app
            .oneshot(scan_request(&source, "op-layer"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let findings = json["findings"].as_array().unwrap();
        assert!(
            !findings.is_empty(),
            "positive op-fob fixture must produce >=1 finding"
        );
        let fob_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["detector"] == "op_fail_open_bootstrap")
            .collect();
        assert_eq!(
            fob_findings.len(),
            1,
            "must have exactly 1 op_fail_open_bootstrap finding, got {:?}",
            fob_findings
        );
        assert_eq!(fob_findings[0]["severity"], "high");
        assert_eq!(fob_findings[0]["confidence"], "experimental");
    }

    #[tokio::test]
    async fn test_scan_op_fob_benign_zero_through_router() {
        let app = test_app();
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap().parent().unwrap().to_path_buf();
        let fixture = root.join("corpus/operational-layer/benign-fail-closed-breaker/handler.ts");
        assert!(fixture.exists(), "fixture must exist: {:?}", fixture);
        let source = std::fs::read_to_string(&fixture).unwrap();

        let response = app
            .oneshot(scan_request(&source, "op-layer"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let findings = json["findings"].as_array().unwrap();
        let fob_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["detector"] == "op_fail_open_bootstrap")
            .collect();
        assert!(
            fob_findings.is_empty(),
            "benign op-fob fixture must emit 0 op_fail_open_bootstrap, got {:?}",
            fob_findings
        );
    }

    #[tokio::test]
    async fn test_scan_op_sf_positive_through_router() {
        let app = test_app();
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap().parent().unwrap().to_path_buf();
        let fixture = root.join("corpus/operational-layer/positive-silent-failover/handler.ts");
        assert!(fixture.exists(), "fixture must exist: {:?}", fixture);
        let source = std::fs::read_to_string(&fixture).unwrap();

        let response = app
            .oneshot(scan_request(&source, "op-layer"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let findings = json["findings"].as_array().unwrap();
        assert!(
            !findings.is_empty(),
            "positive op-sf fixture must produce >=1 finding"
        );
        let sf_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["detector"] == "op_silent_failover")
            .collect();
        assert_eq!(
            sf_findings.len(),
            1,
            "must have exactly 1 op_silent_failover finding, got {:?}",
            sf_findings
        );
        assert_eq!(sf_findings[0]["severity"], "high");
        assert_eq!(sf_findings[0]["confidence"], "experimental");
    }

    #[tokio::test]
    async fn test_scan_op_sf_benign_zero_through_router() {
        let app = test_app();
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap().parent().unwrap().to_path_buf();
        let fixture = root.join("corpus/operational-layer/benign-failover-adjusted/handler.ts");
        assert!(fixture.exists(), "fixture must exist: {:?}", fixture);
        let source = std::fs::read_to_string(&fixture).unwrap();

        let response = app
            .oneshot(scan_request(&source, "op-layer"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let findings = json["findings"].as_array().unwrap();
        let sf_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["detector"] == "op_silent_failover")
            .collect();
        assert!(
            sf_findings.is_empty(),
            "benign op-sf fixture must emit 0 op_silent_failover, got {:?}",
            sf_findings
        );
    }

    #[tokio::test]
    async fn test_scan_endpoint_includes_engine_hypotheses() {
        let app = test_app();
        let response = app
            .oneshot(scan_request(
                "contract V { function withdraw() public { msg.sender.call(\"\"); } }",
                "evm",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["engine_derived"].as_bool().unwrap_or(false),
            "scan endpoint must return engine_derived: true"
        );
        let engine_hyps = json["engine_hypotheses"].as_array().unwrap();
        assert!(
            !engine_hyps.is_empty(),
            "scan endpoint must return non-empty engine_hypotheses"
        );
        for h in engine_hyps {
            assert_eq!(
                h["provenance"].as_str().unwrap(),
                "engine",
                "engine hypothesis must have provenance=engine"
            );
        }
    }
}
