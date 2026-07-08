/// Middleware — CORS, logging, request ID.
use axum::http::{HeaderValue, Method, Request};
use axum::middleware::Next;
use axum::response::Response;
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Build CORS middleware — configurable via DIGGER_CORS_ORIGIN env var.
/// Defaults to same-origin (empty header = browser blocks cross-origin).
pub fn cors_layer() -> CorsLayer {
    let mut layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any);

    match std::env::var("DIGGER_CORS_ORIGIN") {
        Ok(origin) if !origin.is_empty() => {
            if origin == "*" {
                layer = layer.allow_origin(AllowOrigin::any());
            } else if let Ok(val) = HeaderValue::from_str(&origin) {
                layer = layer.allow_origin(val);
            }
        }
        _ => {
            // Default: no cross-origin allowed (same-origin only)
        }
    }

    layer
}

use tower_http::cors::Any;

/// Add request ID header.
pub async fn add_request_id(mut request: Request<axum::body::Body>, next: Next) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    if let Ok(hv) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert("x-request-id", hv);
    }
    let mut response = next.run(request).await;
    if let Ok(hv) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", hv);
    }
    response
}
