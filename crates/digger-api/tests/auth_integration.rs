/// Integration tests for auth and API key lifecycle.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use digger_api::handlers;
use tower::ServiceExt;

use std::sync::OnceLock;
use tokio::sync::Mutex;

fn env_guard() -> &'static Mutex<()> {
    static ENV_GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_GUARD.get_or_init(|| Mutex::new(()))
}

fn set_api_key(key: &str) {
    unsafe {
        std::env::set_var("DIGGER_API_KEY", key);
    }
}

fn build_auth_router() -> axum::Router {
    use axum::routing::get;
    let store = digger_platform::config::create_storage();
    let _ = store.init();
    let state = digger_api::app::AppState {
        job_store: digger_api::jobs::new_job_store(),
        platform_store: store,
        start_time: std::time::Instant::now(),
        limiter: digger_api::rate_limit::new_rate_limiter(),
    };
    axum::Router::new()
        .route("/api/v1/orgs", get(|| async { "ok" }))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            digger_api::auth::auth_layer,
        ))
}

// ── Auth bootstrap key tests ────────────────────────────────────

#[tokio::test]
async fn test_correct_key_passes() {
    let _guard = env_guard().lock().await;
    let saved = std::env::var("DIGGER_API_KEY").ok();
    set_api_key("test-key-123");
    let resp = build_auth_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/orgs")
                .header("x-api-key", "test-key-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Restore env to avoid clobbering other crate tests running in parallel.
    match saved {
        Some(v) => set_api_key(&v),
        None => unsafe { std::env::remove_var("DIGGER_API_KEY") },
    }
}

#[tokio::test]
async fn test_wrong_key_returns_401() {
    let _guard = env_guard().lock().await;
    set_api_key("test-key-123");
    let resp = build_auth_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/orgs")
                .header("x-api-key", "wrong-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_missing_header_returns_401() {
    let _guard = env_guard().lock().await;
    set_api_key("test-key-123");
    let resp = build_auth_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/orgs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_empty_key_returns_401() {
    let _guard = env_guard().lock().await;
    set_api_key("");
    let resp = build_auth_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/orgs")
                .header("x-api-key", "anything")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_unset_key_returns_401() {
    let _guard = env_guard().lock().await;
    let saved = std::env::var("DIGGER_API_KEY").ok();
    unsafe {
        std::env::remove_var("DIGGER_API_KEY");
    }
    let resp = build_auth_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/orgs")
                .header("x-api-key", "anything")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Restore env
    match saved {
        Some(v) => set_api_key(&v),
        None => { /* was already unset, leave it */ }
    }
}

// ── API Key lifecycle tests ────────────────────────────────────

#[test]
fn test_key_lifecycle_create_validate_revoke() {
    use digger_platform::api_keys;

    let store = digger_platform::config::create_storage();
    let _ = store.init();

    // Create a key
    let secret = api_keys::create_key(&*store, "test-key", "test-org", None)
        .expect("create_key should succeed");
    assert!(
        secret.key.contains('.'),
        "key should be prefix.secret format"
    );
    assert!(!secret.id.is_empty());

    // Validate the key — should succeed (same store)
    let record = api_keys::validate_key(&*store, &secret.key)
        .expect("validate_key should succeed for freshly created key");
    assert_eq!(record.name, "test-key");
    assert_eq!(record.org_id, "test-org");
    assert!(!record.revoked);

    // List keys — should include our key
    let keys = api_keys::list_keys(&*store, "test-org");
    assert!(keys.iter().any(|k| k.id == record.id));

    // Revoke the key
    api_keys::revoke_key(&*store, "test-org", &record.id).expect("revoke_key should succeed");

    // Validate after revoke — should fail
    let result = api_keys::validate_key(&*store, &secret.key);
    assert!(result.is_err(), "revoked key should not validate");

    // List keys — should still exist but be revoked
    let keys = api_keys::list_keys(&*store, "test-org");
    let revoked = keys
        .iter()
        .find(|k| k.id == record.id)
        .expect("revoked key should still be in list");
    assert!(revoked.revoked);
}

#[test]
fn test_key_hashed_at_rest() {
    use digger_platform::api_keys;

    let store = digger_platform::config::create_storage();
    let _ = store.init();

    let secret = api_keys::create_key(&*store, "hash-test", "org", None).unwrap();

    let stored = store.read_json("api_keys", &secret.id).unwrap();
    let stored_str = serde_json::to_string(&stored).unwrap();
    assert!(
        !stored_str.contains(&secret.key),
        "Stored record must not contain plaintext key"
    );
    assert!(
        stored_str.contains(&secret.prefix),
        "Stored record should contain the prefix"
    );
}

#[test]
fn test_prefix_secret_parsing() {
    use digger_platform::api_keys;

    let store = digger_platform::config::create_storage();
    let _ = store.init();
    let secret = api_keys::create_key(&*store, "parse-test", "org", None).unwrap();
    let result = api_keys::validate_key(&*store, &secret.key);
    assert!(result.is_ok(), "valid key should parse");

    let result = api_keys::validate_key(&*store, "no-dot-separator");
    assert!(result.is_err(), "missing dot separator should fail");

    let wrong = format!("{}.wrongsecret", secret.prefix);
    let result = api_keys::validate_key(&*store, &wrong);
    assert!(result.is_err(), "wrong secret should fail");
}

// ── HTTP-through-router auth test (FIX C) ───────────────────────
// Exercises the full middleware stack: auth_layer → validate_key.
// Create a stored key, use it → 200, revoke it, use again → 401.

#[tokio::test]
async fn test_http_stored_key_auth_200_then_401_after_revoke() {
    let _guard = env_guard().lock().await;
    use digger_platform::api_keys;

    let store = digger_platform::config::create_storage();
    let _ = store.init();

    // Create a real API key
    let secret = api_keys::create_key(&*store, "router-test", "test-org", None).unwrap();

    // Build a router with real auth middleware and a protected health endpoint
    let state = digger_api::app::AppState {
        job_store: digger_api::jobs::new_job_store(),
        platform_store: store.clone(),
        start_time: std::time::Instant::now(),
        limiter: digger_api::rate_limit::new_rate_limiter(),
    };
    let router = axum::Router::new()
        .route("/api/v1/orgs", axum::routing::get(|| async { "ok" }))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            digger_api::auth::auth_layer,
        ));

    // Clear DIGGER_API_KEY so bootstrap doesn't interfere; save for restore
    let saved_api_key = std::env::var("DIGGER_API_KEY").ok();
    unsafe {
        std::env::remove_var("DIGGER_API_KEY");
    }

    // Step 1: Call with valid stored key → expect 200
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/orgs")
                .header("x-api-key", &secret.key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "valid stored key should return 200"
    );

    // Step 2: Revoke the key
    api_keys::revoke_key(&*store, "test-org", &secret.id).unwrap();

    // Step 3: Call again with same key → expect 401
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/orgs")
                .header("x-api-key", &secret.key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "revoked key should return 401"
    );
    // Restore env
    if let Some(v) = saved_api_key {
        set_api_key(&v);
    }
}

// ── SSRF tests ──────────────────────────────────────────────────

#[test]
fn test_ssrf_blocks_private_ips() {
    assert!(digger_api::net_guard::validate_external_url("https://10.0.0.5/repo").is_err());
    assert!(digger_api::net_guard::validate_external_url("https://127.0.0.1/repo").is_err());
    assert!(digger_api::net_guard::validate_external_url("https://169.254.169.254/repo").is_err());
    assert!(digger_api::net_guard::validate_external_url("http://example.com/repo").is_err());
}

#[test]
fn test_ssrf_blocks_loopback() {
    assert!(digger_api::net_guard::validate_external_url("https://127.0.0.1/repo").is_err());
    assert!(digger_api::net_guard::validate_external_url("https://0.0.0.0/repo").is_err());
}

#[test]
fn test_ssrf_blocks_git_protocol() {
    assert!(digger_api::net_guard::validate_external_url("git://github.com/user/repo").is_err());
}

#[test]
fn test_webhook_ssrf_blocks_private_ip() {
    assert!(digger_api::net_guard::validate_external_url("http://169.254.169.254/hook").is_err());
    assert!(digger_api::net_guard::validate_external_url("https://10.0.0.1/hook").is_err());
}

#[test]
fn test_webhook_ssrf_allows_valid_host() {
    assert!(digger_api::net_guard::validate_external_url("https://example.com/hook").is_ok());
}

// ── Org-scoped revoke tests ────────────────────────────────────

#[tokio::test]
async fn test_org_scoped_revoke_wrong_org_returns_404() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use digger_platform::api_keys;
    use tower::ServiceExt;

    let _guard = env_guard().lock().await;

    let store = digger_platform::config::create_storage();
    let _ = store.init();

    // Create a key in orgA
    let secret = api_keys::create_key(&*store, "scoped-test", "orgA", None).unwrap();

    let state = digger_api::app::AppState {
        job_store: digger_api::jobs::new_job_store(),
        platform_store: store.clone(),
        start_time: std::time::Instant::now(),
        limiter: digger_api::rate_limit::new_rate_limiter(),
    };

    // Set bootstrap key so auth passes for health endpoint
    unsafe {
        std::env::set_var("DIGGER_API_KEY", "test-bootstrap-scoped");
    }

    let router = axum::Router::new()
        .route(
            "/api/v1/orgs/:org_id/keys/:key_id",
            axum::routing::delete(handlers::keys::revoke_key),
        )
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            digger_api::auth::auth_layer,
        ));

    // Try to revoke from orgB → should 404 (not 403)
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/orgs/orgB/keys/{}", secret.id))
                .header("x-api-key", "test-bootstrap-scoped")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "wrong org should return 404"
    );

    // Key should still be valid
    let result = api_keys::validate_key(&*store, &secret.key);
    assert!(
        result.is_ok(),
        "key must still be valid after wrong-org revoke attempt"
    );

    // Now revoke from correct org → should 204
    let resp = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/orgs/orgA/keys/{}", secret.id))
                .header("x-api-key", "test-bootstrap-scoped")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "correct org should return 204"
    );

    // Key should now be revoked
    let result = api_keys::validate_key(&*store, &secret.key);
    assert!(
        result.is_err(),
        "key must be revoked after correct-org revoke"
    );

    // Restore env
    unsafe {
        std::env::remove_var("DIGGER_API_KEY");
    }
}
