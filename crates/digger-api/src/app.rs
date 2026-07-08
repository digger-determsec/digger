/// Axum application builder — routes, state, middleware.
use axum::routing::{delete, get, post};
use axum::Router;
use std::sync::Arc;
use std::time::Instant;

use crate::config::Config;
use crate::handlers;
use crate::jobs;
use crate::rate_limit::{new_rate_limiter, RateLimiter};
use digger_platform::storage::Storage;

#[derive(Clone)]
pub struct AppState {
    pub job_store: jobs::JobStore,
    pub platform_store: Arc<dyn Storage>,
    pub start_time: Instant,
    pub limiter: RateLimiter,
}

fn dashboard_dir() -> std::path::PathBuf {
    let candidates = [
        std::path::PathBuf::from("dashboard/dist"),
        std::path::PathBuf::from("../dashboard/dist"),
        std::path::PathBuf::from("../../dashboard/dist"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    candidates[0].clone()
}

pub fn create_app(_config: &Config) -> Router {
    let platform_store = digger_platform::config::create_storage();
    let _ = platform_store.init();
    if let Err(e) = digger_platform::seed::seed_defaults(&*platform_store) {
        eprintln!("warning: failed to seed default workspace: {}", e);
    }

    let state = AppState {
        job_store: jobs::new_job_store(),
        platform_store,
        start_time: Instant::now(),
        limiter: new_rate_limiter(),
    };

    let cors = crate::middleware::cors_layer();
    let limiter = state.limiter.clone();

    // ── Non-org-scoped routes (no OrgGuard) ──
    let global_routes = Router::new()
        // System
        .route("/api/v1/health", get(handlers::system::health))
        .route("/api/v1/version", get(handlers::system::version))
        .route("/api/v1/metrics", get(handlers::system::metrics))
        // Analysis
        .route("/api/v1/scan", post(handlers::scan::scan))
        .route("/api/v1/synthesize", post(handlers::synthesize::synthesize))
        .route("/api/v1/validate", post(handlers::validate::validate))
        .route("/api/v1/execute", post(handlers::execute::execute))
        .route("/api/v1/evaluate", post(handlers::evaluate::evaluate))
        // Search
        .route("/api/v1/search", post(handlers::search::search))
        // Knowledge
        .route("/api/v1/knowledge/search", get(handlers::knowledge::search))
        .route(
            "/api/v1/protocol-packs",
            get(handlers::knowledge::get_protocol_packs),
        )
        .route(
            "/api/v1/protocol-packs/:id",
            get(handlers::knowledge::get_protocol_pack),
        )
        .route(
            "/api/v1/knowledge/graph",
            get(handlers::knowledge::graph_query),
        )
        // Resources
        .route("/api/v1/finding/:id", get(handlers::resources::get_finding))
        .route(
            "/api/v1/hypothesis/:id",
            get(handlers::resources::get_hypothesis),
        )
        .route("/api/v1/report/:id", get(handlers::resources::get_report))
        // Jobs
        .route("/api/v1/jobs/:id", get(handlers::scan::get_job))
        .route("/api/v1/jobs/:id", delete(handlers::scan::cancel_job))
        // Ingestion
        .route("/api/v1/ingestion/status", get(handlers::ingestion::status))
        .route("/api/v1/ingestion/run", post(handlers::ingestion::run))
        // OpenAPI
        .route("/api/v1/openapi.json", get(handlers::openapi::openapi_spec))
        // Benchmark
        .route(
            "/api/v1/benchmark/run",
            post(handlers::benchmark::run_benchmark),
        )
        .route(
            "/api/v1/benchmark/status",
            get(handlers::benchmark::benchmark_status),
        )
        // Platform: org-level (no org in path)
        .route("/api/v1/orgs", post(handlers::platform::create_org))
        .route("/api/v1/orgs", get(handlers::platform::list_orgs))
        // Platform: Projects (no org in path)
        .route("/api/v1/projects/:id", get(handlers::platform::get_project))
        // Platform: Scans (no org in path)
        .route("/api/v1/scans/:id", get(handlers::platform::get_scan))
        .route(
            "/api/v1/scans/:id/compare",
            post(handlers::platform::compare_scans),
        )
        // Platform: Reports
        .route(
            "/api/v1/reports/:id",
            get(handlers::platform::get_report_detail),
        )
        .route(
            "/api/v1/reports/:id/lineage",
            get(handlers::platform::report_lineage),
        )
        .route(
            "/api/v1/reports/:id/diff",
            post(handlers::platform::diff_reports),
        )
        // Artifacts
        .route(
            "/api/v1/scans/:scan_id/artifacts",
            get(handlers::platform::list_artifacts),
        )
        .route(
            "/api/v1/artifacts/:id",
            get(handlers::platform::get_artifact),
        )
        // Webhooks (id-based, not org-scoped)
        .route(
            "/api/v1/webhooks/:id",
            delete(handlers::platform::delete_webhook),
        )
        // API Keys: create + list-default (no org path)
        .route("/api/v1/keys", post(handlers::keys::create_key))
        .route("/api/v1/keys", get(handlers::keys::list_keys_default))
        // Explanation
        .route(
            "/api/v1/explain/scan",
            post(handlers::explanation::explain_scan),
        )
        .route(
            "/api/v1/explain/synthesis",
            post(handlers::explanation::explain_synthesis),
        )
        .route(
            "/api/v1/explain/full",
            post(handlers::explanation::explain_full),
        )
        // Repo Scan
        .route("/api/v1/scan/repo", post(handlers::repo_scan::scan_repo));

    // ── Org-scoped routes (OrgGuard enforces key.org == path.org) ──
    let org_routes = Router::new()
        // Org detail
        .route("/api/v1/orgs/:org_id", get(handlers::platform::get_org))
        .route(
            "/api/v1/orgs/:org_id",
            delete(handlers::platform::delete_org),
        )
        .route(
            "/api/v1/orgs/:org_id/members",
            post(handlers::platform::add_member),
        )
        // Org projects
        .route(
            "/api/v1/orgs/:org_id/projects",
            post(handlers::platform::create_project),
        )
        .route(
            "/api/v1/orgs/:org_id/projects",
            get(handlers::platform::list_projects),
        )
        // Org scans
        .route(
            "/api/v1/orgs/:org_id/scans",
            post(handlers::platform::create_scan),
        )
        // Org scans via project
        .route(
            "/api/v1/projects/:project_id/scans",
            get(handlers::platform::list_scans),
        )
        // Org webhooks
        .route(
            "/api/v1/orgs/:org_id/webhooks",
            post(handlers::platform::register_webhook),
        )
        .route(
            "/api/v1/orgs/:org_id/webhooks",
            get(handlers::platform::list_webhooks),
        )
        // Org API keys
        .route("/api/v1/orgs/:org_id/keys", get(handlers::keys::list_keys))
        .route(
            "/api/v1/orgs/:org_id/keys/:key_id",
            delete(handlers::keys::revoke_key),
        );

    let api_routes = global_routes.merge(org_routes);

    let dash_path = dashboard_dir();
    let index_path = dash_path.join("index.html");

    let dashboard_service = tower_http::services::ServeDir::new(&dash_path)
        .append_index_html_on_directories(true)
        .not_found_service(tower_http::services::ServeFile::new(&index_path));

    Router::new()
        .merge(api_routes)
        .fallback_service(dashboard_service)
        .with_state(state.clone())
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(cors)
        .layer(axum::middleware::from_fn(crate::middleware::add_request_id))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::auth_layer,
        ))
        .layer(axum::middleware::from_fn(crate::security::security_layer))
        .layer(axum::middleware::from_fn(crate::timing::timing_layer))
        .layer(axum::middleware::from_fn(move |req, next| {
            let limiter = limiter.clone();
            async move { crate::rate_limit::rate_limit_layer(limiter, req, next).await }
        }))
}
