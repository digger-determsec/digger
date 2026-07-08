/// Rate limiting middleware — token bucket per IP with TTL eviction.
///
/// Client IP resolution: only honors `X-Forwarded-For` when the direct peer
/// is in the `TRUSTED_PROXIES` environment variable (comma-separated IPs).
/// Fail-closed: when TRUSTED_PROXIES is unset or empty, XFF is IGNORED
/// and the peer address is used directly.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[cfg_attr(test, allow(dead_code))]
pub struct Bucket {
    pub(crate) tokens: f64,
    pub(crate) last_refill: Instant,
}

pub type RateLimiter = Arc<RwLock<HashMap<String, Bucket>>>;

pub fn new_rate_limiter() -> RateLimiter {
    Arc::new(RwLock::new(HashMap::new()))
}

const RATE_LIMIT: f64 = 60.0;
const BURST: f64 = 120.0;
const REFILL_INTERVAL_SECS: f64 = 60.0;
const BUCKET_TTL_SECS: f64 = 3600.0;

/// Load the set of trusted proxy IPs from the TRUSTED_PROXIES env var.
/// Returns empty set when unset (fail-closed default).
fn trusted_proxies() -> HashSet<String> {
    std::env::var("TRUSTED_PROXIES")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Derive the client IP for rate limiting.
///
/// Only honors X-Forwarded-For when the peer address is in the trusted
/// proxy set. Otherwise returns the peer address directly. Fail-closed:
/// empty TRUSTED_PROXIES = XFF ignored entirely.
fn derive_client_ip(peer_addr: &str, xff: Option<&str>, trusted: &HashSet<String>) -> String {
    if trusted.is_empty() {
        // No trusted proxies configured — ignore XFF entirely
        return peer_addr.to_string();
    }
    if trusted.contains(peer_addr) {
        // Peer is a trusted proxy — honor XFF
        if let Some(xff_val) = xff {
            let first = xff_val.split(',').next().unwrap_or("").trim();
            if !first.is_empty() {
                return first.to_string();
            }
        }
    }
    // Peer is not trusted, or no XFF — use peer address
    peer_addr.to_string()
}

pub async fn rate_limit_layer(
    limiter: RateLimiter,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract real peer address from ConnectInfo (set by into_make_service_with_connect_info).
    // Fallback to "unknown" if ConnectInfo is not available (e.g. in tests without the full serve stack).
    let peer_addr = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());

    let trusted = trusted_proxies();
    let ip = derive_client_ip(&peer_addr, xff, &trusted);

    let now = Instant::now();
    let mut buckets = limiter.write().await;

    // Evict stale buckets to prevent memory leak
    if buckets.len() > 1000 {
        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill).as_secs_f64() < BUCKET_TTL_SECS
        });
    }

    let bucket = buckets.entry(ip).or_insert_with(|| Bucket {
        tokens: BURST,
        last_refill: now,
    });

    let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
    if elapsed > 0.0 {
        let refill = elapsed * (RATE_LIMIT / REFILL_INTERVAL_SECS);
        bucket.tokens = (bucket.tokens + refill).min(BURST);
        bucket.last_refill = now;
    }

    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        drop(buckets);
        Ok(next.run(req).await)
    } else {
        drop(buckets);
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_trusted_proxies_ignores_xff() {
        let trusted = trusted_proxies(); // empty when unset
        let ip = derive_client_ip("10.0.0.1", Some("203.0.113.50"), &trusted);
        assert_eq!(
            ip, "10.0.0.1",
            "XFF must be ignored when no trusted proxies"
        );
    }

    #[test]
    fn trusted_proxy_honors_xff() {
        let mut trusted = HashSet::new();
        trusted.insert("10.0.0.1".to_string());
        let ip = derive_client_ip("10.0.0.1", Some("203.0.113.50"), &trusted);
        assert_eq!(ip, "203.0.113.50", "XFF from trusted proxy must be honored");
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        let mut trusted = HashSet::new();
        trusted.insert("10.0.0.1".to_string());
        let ip = derive_client_ip("192.168.1.1", Some("203.0.113.50"), &trusted);
        assert_eq!(ip, "192.168.1.1", "XFF from untrusted peer must be ignored");
    }

    #[test]
    fn empty_xff_falls_back_to_peer() {
        let mut trusted = HashSet::new();
        trusted.insert("10.0.0.1".to_string());
        let ip = derive_client_ip("10.0.0.1", None, &trusted);
        assert_eq!(ip, "10.0.0.1", "missing XFF falls back to peer");
    }

    #[test]
    fn malformed_xff_falls_back_to_peer() {
        let mut trusted = HashSet::new();
        trusted.insert("10.0.0.1".to_string());
        let ip = derive_client_ip("10.0.0.1", Some("   ,  "), &trusted);
        assert_eq!(ip, "10.0.0.1", "whitespace-only XFF falls back to peer");
    }
}
