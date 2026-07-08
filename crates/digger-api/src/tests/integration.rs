#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::util::ServiceExt;

    use crate::app::create_app;
    use crate::config::Config;

    const TEST_API_KEY: &str = "test-api-key-12345";

    fn test_config() -> Config {
        std::env::set_var("DIGGER_API_KEY", TEST_API_KEY);
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            cors_origins: vec!["*".into()],
            enable_logging: false,
        }
    }

    fn app() -> axum::Router {
        create_app(&test_config())
    }

    async fn get_json(uri: &str) -> serde_json::Value {
        let resp = app()
            .oneshot(
                Request::get(uri)
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn post_json(uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let resp = app()
            .oneshot(
                Request::post(uri)
                    .header("content-type", "application/json")
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        (status, body)
    }

    async fn get_raw(uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = app()
            .oneshot(
                Request::get(uri)
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        (status, body)
    }

    async fn delete_raw(uri: &str) -> StatusCode {
        let resp = app()
            .oneshot(
                Request::delete(uri)
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        resp.status()
    }

    // ── Health ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn health_returns_200() {
        let body = get_json("/api/v1/health").await;
        assert_eq!(body["status"], "healthy");
        assert!(body["version"].is_string());
        assert!(body["uptime_secs"].is_number());
    }

    // ── Version ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn version_returns_200() {
        let body = get_json("/api/v1/version").await;
        assert_eq!(body["schema_version"], "2.3");
        assert_eq!(body["phase_status"], "FROZEN");
        assert!(body["capabilities"].is_array());
        assert!(body["supported_languages"].is_array());
    }

    // ── Metrics ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn metrics_returns_200() {
        let body = get_json("/api/v1/metrics").await;
        assert!(body["requests_total"].is_number());
        assert!(body["latency_p50_ms"].is_number());
        assert!(body["uptime_secs"].is_number());
        assert!(body["pipeline_runs"].is_number());
    }

    // ── Scan ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn scan_returns_findings() {
        let (status, body) = post_json("/api/v1/scan", serde_json::json!({
            "code": "pragma solidity ^0.8.0; contract Foo { mapping(address => uint) balances; function withdraw() external { uint b = balances[msg.sender]; (bool ok,) = msg.sender.call{value: b}(\"\"); require(ok); balances[msg.sender] = 0; } }",
            "lang": "solidity"
        })).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["findings"].is_array());
        assert!(body["summary"].is_object());
        assert!(body["program_id"].is_string());
    }

    // ── Synthesize ───────────────────────────────────────────────────

    #[tokio::test]
    async fn synthesize_returns_chains() {
        let (status, body) = post_json("/api/v1/synthesize", serde_json::json!({
            "code": "pragma solidity ^0.8.0; contract Foo { function transfer(address to, uint amount) external { } }",
            "lang": "solidity"
        })).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["program_id"].is_string());
        assert!(body["total_chains"].is_number());
        assert!(body["report_json"].is_object());
    }

    // ── Validate ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn validate_returns_verdict() {
        let (status, body) = post_json(
            "/api/v1/validate",
            serde_json::json!({
                "chain_id": "test-chain",
                "code": "pragma solidity ^0.8.0; contract Foo {}",
                "lang": "solidity"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["verdict"].is_string());
        assert!(body["validation_score"].is_number());
        assert!(body["report_json"].is_object());
    }

    // ── Execute ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn execute_returns_result() {
        let (status, body) = post_json(
            "/api/v1/execute",
            serde_json::json!({
                "code": "pragma solidity ^0.8.0; contract Foo {}",
                "lang": "solidity"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["report_json"].is_object());
    }

    // ── Evaluate ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn evaluate_benchmark() {
        let (status, body) = post_json(
            "/api/v1/evaluate",
            serde_json::json!({
                "eval_type": "benchmark"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["eval_type"], "benchmark");
        assert!(body["result"].is_object());
    }

    #[tokio::test]
    async fn evaluate_unknown_type() {
        let (status, _body) = post_json(
            "/api/v1/evaluate",
            serde_json::json!({
                "eval_type": "unknown"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // ── Search ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn search_finds_protocols() {
        let (status, body) = post_json(
            "/api/v1/search",
            serde_json::json!({
                "q": "vault",
                "kind": "protocols"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["total"].is_number());
        assert!(body["results"].is_array());
    }

    #[tokio::test]
    async fn search_finds_benchmarks() {
        let (status, body) = post_json(
            "/api/v1/search",
            serde_json::json!({
                "q": "reentrancy",
                "kind": "benchmarks"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["results"].is_array());
    }

    // ── Knowledge Search ─────────────────────────────────────────────

    #[tokio::test]
    async fn knowledge_search_returns_results() {
        let body = get_json("/api/v1/knowledge/search").await;
        assert!(body["total"].is_number());
        assert!(body["results"].is_array());
    }

    // ── Protocol Packs ───────────────────────────────────────────────

    #[tokio::test]
    async fn protocol_packs_list() {
        let body = get_json("/api/v1/protocol-packs").await;
        let packs = body.as_array().unwrap();
        assert!(!packs.is_empty());
    }

    #[tokio::test]
    async fn protocol_pack_detail() {
        let body = get_json("/api/v1/protocol-packs/pack:vaults").await;
        assert!(body["id"].is_string());
        assert!(!body["invariants"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn protocol_pack_not_found() {
        let (status, _) = get_raw("/api/v1/protocol-packs/nonexistent").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── Knowledge Graph ──────────────────────────────────────────────

    #[tokio::test]
    async fn knowledge_graph() {
        let body = get_json("/api/v1/knowledge/graph").await;
        assert!(body.get("node_count").is_some());
        assert!(body.get("edge_count").is_some());
        assert!(body.get("summary").is_some());
    }

    // ── Finding ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn finding_not_found() {
        let (status, _) = get_raw("/api/v1/finding/nonexistent").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── Hypothesis ───────────────────────────────────────────────────

    #[tokio::test]
    async fn hypothesis_detail() {
        let (status, _) = get_raw("/api/v1/hypothesis/1").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── Report ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn report_detail() {
        let (status, _) = get_raw("/api/v1/report/test-id").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── OpenAPI ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn openapi_spec() {
        let body = get_json("/api/v1/openapi.json").await;
        assert_eq!(body["openapi"], "3.0.3");
        assert!(body["paths"].is_object());
        assert!(body["info"]["title"].as_str().unwrap().contains("Digger"));
    }

    // ── Ingestion ────────────────────────────────────────────────────

    #[tokio::test]
    async fn ingestion_status() {
        let body = get_json("/api/v1/ingestion/status").await;
        assert!(body["total_findings"].is_number());
        let sources = body["sources"].as_array().unwrap();
        assert!(!sources.is_empty());
    }

    // ── Benchmark ────────────────────────────────────────────────────

    #[tokio::test]
    async fn benchmark_status() {
        let body = get_json("/api/v1/benchmark/status").await;
        assert!(body["total_cases"].is_number());
        assert!(body["detection_rate"].is_number());
    }

    // ── Jobs ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_job_not_found() {
        let (status, _) = get_raw("/api/v1/jobs/nonexistent").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cancel_job_not_found() {
        let status = delete_raw("/api/v1/jobs/nonexistent").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── 404 ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let (status, _) = get_raw("/api/v1/nonexistent").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── Determinism ──────────────────────────────────────────────────

    #[tokio::test]
    async fn scan_deterministic() {
        let code = serde_json::json!({
            "code": "pragma solidity ^0.8.0; contract Foo {}",
            "lang": "solidity"
        });
        let (_, body1) = post_json("/api/v1/scan", code.clone()).await;
        let (_, body2) = post_json("/api/v1/scan", code).await;
        assert_eq!(body1["program_id"], body2["program_id"]);
        assert_eq!(body1["findings"], body2["findings"]);
    }

    // ── Concurrent safety ────────────────────────────────────────────

    #[tokio::test]
    async fn concurrent_health_checks() {
        let app = app();
        let mut handles = vec![];
        for _ in 0..10 {
            let app = app.clone();
            handles.push(tokio::spawn(async move {
                let resp = app
                    .oneshot(
                        Request::get("/api/v1/health")
                            .header("x-api-key", TEST_API_KEY)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // P0b: Cross-tenant authorization integration tests
    // ══════════════════════════════════════════════════════════════════

    /// Create an org via bootstrap key and return its ID.
    async fn create_org(router: &axum::Router, name: &str) -> String {
        let resp = router
            .clone()
            .oneshot(
                Request::post("/api/v1/orgs")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"name":"{}","user_id":"admin"}}"#,
                        name
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        body["id"].as_str().unwrap().to_string()
    }

    /// Create a stored API key for the given org.
    async fn create_key_for_org(router: &axum::Router, org_id: &str) -> String {
        let resp = router
            .clone()
            .oneshot(
                Request::post("/api/v1/keys")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"name":"k","org_id":"{}"}}"#,
                        org_id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        body["key"].as_str().unwrap().to_string()
    }

    /// GAP 1: keyA accessing its own org = 200
    #[tokio::test]
    async fn p0b_own_org_200() {
        let app = app();
        let org_id = create_org(&app, "TenantOwn").await;
        let key = create_key_for_org(&app, &org_id).await;
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_id))
                    .header("x-api-key", &key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// GAP 1: keyA accessing different org = 404 NOT 403 (no existence leak)
    #[tokio::test]
    async fn p0b_cross_tenant_404() {
        let app = app();
        let org_id = create_org(&app, "TenantCross").await;
        let key = create_key_for_org(&app, &org_id).await;
        let resp = app
            .oneshot(
                Request::get("/api/v1/orgs/does-not-match")
                    .header("x-api-key", &key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "must be 404 not 403");
    }

    /// GAP 1: admin/bootstrap key bypasses org check = 200
    #[tokio::test]
    async fn p0b_admin_bypasses_org() {
        let app = app();
        let org_id = create_org(&app, "TenantAdminBypass").await;
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_id))
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "admin must bypass org scoping"
        );
    }

    /// GAP 1: no API key -> 401 on protected routes
    #[tokio::test]
    async fn p0b_no_key_401() {
        let resp = app()
            .oneshot(Request::get("/api/v1/orgs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ══════════════════════════════════════════════════════════════════
    // P2: Key expiry tests
    // ══════════════════════════════════════════════════════════════════

    /// Create an org and key that expires in the past -> 401
    #[tokio::test]
    async fn p2_expired_key_returns_401() {
        let app = app();
        let org_id = create_org(&app, "TenantExpired").await;
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/keys")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"name":"exp","org_id":"{}","expires_at":"2020-01-01T00:00:00Z"}}"#,
                        org_id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let key = body["key"].as_str().unwrap().to_string();

        // Expired key -> 401
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_id))
                    .header("x-api-key", &key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "expired key must return 401"
        );
    }

    /// Non-expired key -> 200
    #[tokio::test]
    async fn p2_non_expired_key_returns_200() {
        let app = app();
        let org_id = create_org(&app, "TenantNotExpired").await;
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/keys")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"name":"valid","org_id":"{}","expires_at":"2099-01-01T00:00:00Z"}}"#,
                        org_id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let key = body["key"].as_str().unwrap().to_string();

        // Non-expired key -> 200
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_id))
                    .header("x-api-key", &key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "non-expired key must return 200"
        );
    }

    /// No expiry (None) stays backward-compatible -> 200
    #[tokio::test]
    async fn p2_no_expiry_backward_compatible() {
        let app = app();
        let org_id = create_org(&app, "TenantNoExpiry").await;
        let key = create_key_for_org(&app, &org_id).await;
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_id))
                    .header("x-api-key", &key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "no-expiry key must still work"
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // P3: Lifecycle + operability tests
    // ══════════════════════════════════════════════════════════════════

    /// Full key lifecycle: create -> use -> revoke -> denied
    #[tokio::test]
    async fn p3_full_key_lifecycle() {
        let app = app();
        let org_id = create_org(&app, "TenantLifecycle").await;

        // 1. Create key -> 201
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/keys")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"name":"lc","org_id":"{}"}}"#,
                        org_id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let key = body["key"].as_str().unwrap().to_string();

        // 2. Use key -> 200
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_id))
                    .header("x-api-key", &key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 3. Revoke key
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}/keys", org_id))
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let keys: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let key_id = keys[0]["id"].as_str().unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::delete(format!("/api/v1/orgs/{}/keys/{}", org_id, key_id))
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // 4. Revoked key -> 401
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_id))
                    .header("x-api-key", &key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "revoked key must return 401"
        );
    }

    /// Health probe is exempt from auth (returns 200 with no key)
    #[tokio::test]
    async fn p3_health_exempt_from_auth() {
        let resp = app()
            .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "health must be accessible without auth"
        );
    }

    /// Version probe is also exempt (ops needs to verify deployment)
    #[tokio::test]
    async fn p3_version_exempt_from_auth() {
        let resp = app()
            .oneshot(Request::get("/api/v1/version").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "version must be accessible without auth"
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // F3a: Real rate-limit tests (exercise middleware, not pure fn)
    // ══════════════════════════════════════════════════════════════════

    use std::net::{SocketAddr, SocketAddrV4};

    /// Mutex to serialize TRUSTED_PROXIES env var access across parallel tests.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Build a minimal app with a shared limiter so we can drain buckets.
    fn app_with_limiter() -> (axum::Router, crate::rate_limit::RateLimiter) {
        let platform_store = digger_platform::config::create_storage();
        let _ = platform_store.init();
        let state = crate::app::AppState {
            job_store: crate::jobs::new_job_store(),
            platform_store,
            start_time: std::time::Instant::now(),
            limiter: crate::rate_limit::new_rate_limiter(),
        };
        let limiter = state.limiter.clone();
        let lim2 = limiter.clone();
        let app = axum::Router::new()
            .route("/api/v1/health", axum::routing::get(|| async { "ok" }))
            .with_state(state)
            .layer(axum::middleware::from_fn(crate::security::security_layer))
            .layer(axum::middleware::from_fn(crate::timing::timing_layer))
            .layer(axum::middleware::from_fn(move |req, next| {
                let lim = lim2.clone();
                async move { crate::rate_limit::rate_limit_layer(lim, req, next).await }
            }));
        (app, limiter)
    }

    /// Pre-drain a bucket so the next request from that peer key hits 429.
    async fn drain_bucket(limiter: &crate::rate_limit::RateLimiter, peer_key: &str) {
        let mut buckets = limiter.write().await;
        buckets.insert(
            peer_key.to_string(),
            crate::rate_limit::Bucket {
                tokens: 0.1,
                last_refill: std::time::Instant::now(),
            },
        );
    }

    #[tokio::test]
    async fn f3a_same_peer_second_request_429() {
        let (app, limiter) = app_with_limiter();
        let addr: SocketAddr = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 8080).into();
        drain_bucket(&limiter, "10.0.0.1").await;

        let mut req = Request::get("/api/v1/health")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn f3a_different_peers_independent_buckets() {
        let (app, limiter) = app_with_limiter();
        drain_bucket(&limiter, "10.0.0.1").await;

        // Peer A -> 429
        let mut req_a = Request::get("/api/v1/health")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        req_a
            .extensions_mut()
            .insert(axum::extract::ConnectInfo::<std::net::SocketAddr>(
                SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 8080).into(),
            ));
        let resp_a = app.clone().oneshot(req_a).await.unwrap();
        assert_eq!(resp_a.status(), StatusCode::TOO_MANY_REQUESTS);

        // Peer B -> 200 (independent bucket)
        let mut req_b = Request::get("/api/v1/health")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        req_b
            .extensions_mut()
            .insert(axum::extract::ConnectInfo::<std::net::SocketAddr>(
                SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 2), 8080).into(),
            ));
        let resp_b = app.oneshot(req_b).await.unwrap();
        assert_eq!(resp_b.status(), StatusCode::OK);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f3a_untrusted_xff_does_not_rotate() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("TRUSTED_PROXIES");
        let (app, limiter) = app_with_limiter();
        drain_bucket(&limiter, "10.0.0.1").await;

        let mut req = Request::get("/api/v1/health")
            .header("x-api-key", TEST_API_KEY)
            .header("x-forwarded-for", "203.0.113.50")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo::<std::net::SocketAddr>(
                SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 8080).into(),
            ));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f3a_trusted_xff_honored() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("TRUSTED_PROXIES", "10.0.0.1");

        let (app, limiter) = app_with_limiter();
        let addr: SocketAddr = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 8080).into();

        // Drain bucket for XFF client 203.0.113.50
        drain_bucket(&limiter, "203.0.113.50").await;

        // Request 1: XFF = 203.0.113.50 (drained bucket) -> 429
        let mut req1 = Request::get("/api/v1/health")
            .header("x-api-key", TEST_API_KEY)
            .header("x-forwarded-for", "203.0.113.50")
            .body(Body::empty())
            .unwrap();
        req1.extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        assert_eq!(
            app.clone().oneshot(req1).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS,
            "drained trusted-XFF client must be 429"
        );

        // Request 2: XFF = 198.51.100.7 (different client, fresh bucket) -> 200
        let mut req2 = Request::get("/api/v1/health")
            .header("x-api-key", TEST_API_KEY)
            .header("x-forwarded-for", "198.51.100.7")
            .body(Body::empty())
            .unwrap();
        req2.extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        assert_eq!(
            app.oneshot(req2).await.unwrap().status(),
            StatusCode::OK,
            "different trusted-XFF client must have its own bucket"
        );

        std::env::remove_var("TRUSTED_PROXIES");
    }

    /// Spoofed XFF from an UNTRUSTED peer does NOT rotate/reset the limiter.
    /// Peer 10.0.0.1 is NOT in TRUSTED_PROXIES, so XFF is ignored.
    /// The bucket is keyed on the actual peer IP, not the XFF value.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f1_untrusted_xff_does_not_rotate_bucket() {
        let _guard = ENV_MUTEX.lock().unwrap();
        use std::net::{SocketAddr, SocketAddrV4};

        std::env::set_var("TRUSTED_PROXIES", "192.168.1.1");
        let app = app();
        let path = "/api/v1/orgs";

        // Request from peer 10.0.0.1 with spoofed XFF
        let mut req = Request::get(path)
            .header("x-api-key", TEST_API_KEY)
            .header("x-forwarded-for", "203.0.113.50")
            .body(Body::empty())
            .unwrap();
        let addr: SocketAddr = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 8080).into();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        let resp = app.oneshot(req).await.unwrap();
        // Should pass (first request for this peer)
        assert_eq!(resp.status(), StatusCode::OK);
        // The bucket is keyed on "10.0.0.1" (real peer), not "203.0.113.50" (spoofed XFF)

        std::env::remove_var("TRUSTED_PROXIES");
    }

    /// XFF from a TRUSTED proxy IS honored (peer is in TRUSTED_PROXIES).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f1_trusted_xff_is_honored() {
        let _guard = ENV_MUTEX.lock().unwrap();
        use std::net::{SocketAddr, SocketAddrV4};

        std::env::set_var("TRUSTED_PROXIES", "10.0.0.1");
        let app = app();
        let path = "/api/v1/orgs";

        // Peer is 10.0.0.1 (trusted proxy), XFF says 203.0.113.50
        let mut req = Request::get(path)
            .header("x-api-key", TEST_API_KEY)
            .header("x-forwarded-for", "203.0.113.50")
            .body(Body::empty())
            .unwrap();
        let addr: SocketAddr = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 8080).into();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // The bucket should be keyed on "203.0.113.50" (from XFF), not "10.0.0.1" (peer)

        std::env::remove_var("TRUSTED_PROXIES");
    }

    /// ConnectInfo fallback: when no ConnectInfo is in extensions,
    /// peer_addr falls back to "unknown" (not crash).
    #[tokio::test]
    async fn f1_no_connectinfo_falls_back_gracefully() {
        let app = app();
        let resp = app
            .oneshot(
                Request::get("/api/v1/orgs")
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request without ConnectInfo must still work"
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // F3b: IDOR router tests — keyA reaching orgB resources by ID
    // ══════════════════════════════════════════════════════════════════

    /// Create an org via bootstrap key, return (org_id, stored_key).
    async fn f3b_setup_org(router: &axum::Router, name: &str) -> (String, String) {
        let resp = router
            .clone()
            .oneshot(
                Request::post("/api/v1/orgs")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"name":"{}","user_id":"admin"}}"#,
                        name
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let org_id = body["id"].as_str().unwrap().to_string();

        let resp = router
            .clone()
            .oneshot(
                Request::post("/api/v1/keys")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"name":"k","org_id":"{}"}}"#,
                        org_id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let key = body["key"].as_str().unwrap().to_string();
        (org_id, key)
    }

    /// Create a project under an org, return project_id.
    async fn f3b_create_project(
        router: &axum::Router,
        org_id: &str,
        key: &str,
        name: &str,
    ) -> String {
        let resp = router
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/orgs/{}/projects", org_id))
                    .header("x-api-key", key)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"name":"{}"}}"#, name)))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        body["id"].as_str().unwrap().to_string()
    }

    /// keyA accessing orgA's project = 200; keyB accessing same = 404.
    #[tokio::test]
    async fn f3b_idor_project() {
        let app = app();
        let (org_a, key_a) = f3b_setup_org(&app, "IdorProjA").await;
        let (org_b, key_b) = f3b_setup_org(&app, "IdorProjB").await;
        let project_id = f3b_create_project(&app, &org_a, &key_a, "Proj").await;

        // Owner -> 200
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/projects/{}", project_id))
                    .header("x-api-key", &key_a)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Cross-tenant -> 404
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/projects/{}", project_id))
                    .header("x-api-key", &key_b)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "cross-tenant must 404"
        );

        // Prevent unused warnings
        let _ = org_b;
    }

    /// keyB accessing orgA's REAL scan by ID = 404; owner = 200.
    #[tokio::test]
    async fn f3b_idor_scan() {
        let app = app();
        let (org_a, key_a) = f3b_setup_org(&app, "IdorScanA").await;
        let (_, key_b) = f3b_setup_org(&app, "IdorScanB").await;

        // Create a project for orgA
        let project_id = f3b_create_project(&app, &org_a, &key_a, "ScanProj").await;

        // Create a REAL scan via the router API
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/orgs/{}/scans", org_a))
                    .header("x-api-key", &key_a)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"project_id":"{}","language":"solidity","code":"contract V {{ }}"}}"#,
                        project_id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "scan creation must succeed");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let scan_id = body["id"].as_str().unwrap().to_string();

        // Owner (keyA) GET scan -> 200
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/scans/{}", scan_id))
                    .header("x-api-key", &key_a)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "owner must access own scan");

        // Cross-tenant (keyB) GET scan -> 404
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/scans/{}", scan_id))
                    .header("x-api-key", &key_b)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "cross-tenant must 404 for orgA scan"
        );
    }

    /// WORKLOG: Reports have no router-level creation endpoint.
    /// Reports are generated by the scan pipeline. verify_org in get_report_detail
    /// runs AFTER the resource lookup, so a nonexistent-id test doesn't exercise it.
    /// TODO: add direct report IDOR test once report creation is exposed.
    #[tokio::test]
    async fn f3b_idor_report_worklogged() {
        let app = app();
        let (_, key_b) = f3b_setup_org(&app, "IdorRptW").await;
        let resp = app
            .oneshot(
                Request::get("/api/v1/reports/nonexistent-id")
                    .header("x-api-key", &key_b)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// keyB listing scans of orgA's project = 404.
    #[tokio::test]
    async fn f3b_idor_list_scans() {
        let app = app();
        let (org_a, key_a) = f3b_setup_org(&app, "IdorListA").await;
        let (_, key_b) = f3b_setup_org(&app, "IdorListB").await;
        let project_id = f3b_create_project(&app, &org_a, &key_a, "ListProj").await;

        // Owner -> 200
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/projects/{}/scans", project_id))
                    .header("x-api-key", &key_a)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Cross-tenant -> 404
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/projects/{}/scans", project_id))
                    .header("x-api-key", &key_b)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "cross-tenant must 404 for orgA scans"
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // F3c-1: P2 fail-closed on malformed expires_at
    // ══════════════════════════════════════════════════════════════════

    /// A key with malformed expires_at must be rejected (401), not silently accepted.
    #[tokio::test]
    async fn f3c_malformed_expires_at_rejected() {
        let app = app();
        let org_id = f3b_setup_org(&app, "TenantMalformed").await;
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/keys")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"name":"mal","org_id":"{}","expires_at":"NOT-A-DATE"}}"#,
                        org_id.0
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        // The key creation should still succeed (record stores the raw string)
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let key = body["key"].as_str().unwrap().to_string();

        // Using the key with malformed expires_at must return 401 (fail-closed)
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_id.0))
                    .header("x-api-key", &key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "malformed expires_at must be rejected (fail-closed)"
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // F3c-2: P0b real-second-org cross-tenant test
    // ══════════════════════════════════════════════════════════════════

    /// Create TWO REAL orgs with keys; keyA -> orgB's own resource = 404;
    /// keyA -> orgA's own resource = 200. Proves cross-tenant denial with
    /// a REAL second org (not just a nonexistent id).
    #[tokio::test]
    async fn f3c_real_cross_tenant_denial() {
        let app = app();
        let (org_a, key_a) = f3b_setup_org(&app, "CrossTenantA").await;
        let (org_b, key_b) = f3b_setup_org(&app, "CrossTenantB").await;

        // keyA -> orgA = 200
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_a))
                    .header("x-api-key", &key_a)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "keyA must access orgA");

        // keyA -> orgB = 404 (cross-tenant denial with REAL second org)
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_b))
                    .header("x-api-key", &key_a)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "keyA must NOT access orgB (real cross-tenant denial)"
        );

        // keyB -> orgB = 200 (keyB's own org works)
        let resp = app
            .oneshot(
                Request::get(format!("/api/v1/orgs/{}", org_b))
                    .header("x-api-key", &key_b)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "keyB must access orgB");
    }

    // ══════════════════════════════════════════════════════════════════
    // Item 4: Route inventory sweep — table-driven verify_org coverage
    // ══════════════════════════════════════════════════════════════════

    /// Exhaustive table-driven test: every org-scoped route returns 404
    /// when accessed with a key from the WRONG org. Proves verify_org is
    /// wired on every org/id-addressed endpoint.
    #[tokio::test]
    async fn item4_route_inventory_wrong_org_returns_404() {
        let app = app();
        let (org_a, key_a) = f3b_setup_org(&app, "InvOrgA").await;
        let (_, key_b) = f3b_setup_org(&app, "InvOrgB").await;

        let project_id = f3b_create_project(&app, &org_a, &key_a, "InvProj").await;

        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/orgs/{}/scans", org_a))
                    .header("x-api-key", &key_a)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"project_id":"{}","language":"solidity","code":"contract V {{ }}"}}"#,
                        project_id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let scan_id = body["id"].as_str().unwrap().to_string();

        // Routes where keyB (orgB) must get 404 for orgA resources:
        let org_routes: Vec<String> = vec![
            format!("/api/v1/orgs/{}", org_a),
            format!("/api/v1/orgs/{}/projects", org_a),
            format!("/api/v1/orgs/{}/keys", org_a),
        ];

        for path in &org_routes {
            let resp = app
                .clone()
                .oneshot(
                    Request::get(path.as_str())
                        .header("x-api-key", &key_b)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "keyB must 404 on GET {}",
                path
            );
        }

        let id_routes: Vec<String> = vec![
            format!("/api/v1/projects/{}", project_id),
            format!("/api/v1/scans/{}", scan_id),
            format!("/api/v1/projects/{}/scans", project_id),
        ];

        for path in &id_routes {
            let resp = app
                .clone()
                .oneshot(
                    Request::get(path.as_str())
                        .header("x-api-key", &key_b)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "keyB must 404 on GET {}",
                path
            );
        }

        // Id-addressed routes where keyB must 404 for orgA resources:
        let id_routes: Vec<(&str, String)> = vec![
            ("GET", format!("/api/v1/projects/{}", project_id)),
            ("GET", format!("/api/v1/scans/{}", scan_id)),
            ("GET", format!("/api/v1/projects/{}/scans", project_id)),
        ];

        for (method, path) in &id_routes {
            let resp = app
                .clone()
                .oneshot(
                    Request::get(path.as_str())
                        .header("x-api-key", &key_b)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "keyB (orgB) must 404 on {} {} (orgA resource)",
                method,
                path
            );
        }
    }

    /// Routes EXEMPT from org check (health, version, metrics, global keys).
    /// These are auth-protected but NOT org-scoped — any valid key can access them.
    #[tokio::test]
    async fn item4_exempt_routes_accessible_by_any_key() {
        let app = app();
        let (_, key_a) = f3b_setup_org(&app, "ExemptOrg").await;

        let exempt_routes = vec![
            "/api/v1/health",
            "/api/v1/version",
            "/api/v1/keys",
            "/api/v1/orgs",
        ];

        for path in &exempt_routes {
            let resp = app
                .clone()
                .oneshot(
                    Request::get(*path)
                        .header("x-api-key", &key_a)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                resp.status() == StatusCode::OK,
                "exempt route {} must return 200, got {:?}",
                path,
                resp.status()
            );
        }
    }
}
