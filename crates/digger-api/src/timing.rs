/// Request timing middleware — records latency for every request.
use axum::body::Body;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

pub async fn timing_layer(req: Request<Body>, next: Next) -> Response {
    let start = Instant::now();
    let path = req.uri().path().to_string();

    crate::metrics::GLOBAL_METRICS
        .active_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let mut response = next.run(req).await;

    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    let status = response.status().as_u16();

    crate::metrics::GLOBAL_METRICS.record_request(status, &path, elapsed);
    crate::metrics::GLOBAL_METRICS
        .active_connections
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

    // Add timing headers
    if let Ok(val) = format!("{:.1}ms", elapsed).parse::<axum::http::HeaderValue>() {
        response
            .headers_mut()
            .insert(axum::http::HeaderName::from_static("x-response-time"), val);
    }

    // Log non-health requests
    if !path.starts_with("/api/v1/health") && !path.starts_with("/api/v1/metrics") {
        eprintln!("[{}] {} {:.1}ms {}", chrono_utc(), path, elapsed, status,);
    }

    response
}

fn chrono_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}s", secs)
}
