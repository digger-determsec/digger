/// Security middleware — request size limits, content-type enforcement, input validation.
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024; // 10MB

/// Enforce request body size limits and content-type on POST/PUT routes.
pub async fn security_layer(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let method = req.method().clone();
    let uri = req.uri().path().to_string();

    // Skip health checks and OPTIONS from strict checks
    if uri.starts_with("/api/v1/health") || method == axum::http::Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    // For POST requests, enforce content-type and body size
    if method == axum::http::Method::POST || method == axum::http::Method::PUT {
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !content_type.contains("application/json") && !uri.contains("openapi") {
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }

        // Check content-length before reading body
        if let Some(content_length) = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            if content_length > MAX_REQUEST_BODY_BYTES as u64 {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
        }
    }

    Ok(next.run(req).await)
}
