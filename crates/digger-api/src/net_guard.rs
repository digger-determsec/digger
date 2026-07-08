/// Network egress guard — validates URLs and resolved IPs before any outbound connection.
/// Prevents SSRF, internal network access, and cloud metadata abuse.
use std::net::{IpAddr, ToSocketAddrs};

use crate::error::ApiError;

/// Validate that an external URL points to an allowed host.
///
/// Checks: scheme (HTTPS-only in production), hostname extraction, DNS resolution,
/// and IP blocking (loopback, private, link-local, cloud metadata, ULA).
pub fn validate_external_url(url: &str) -> Result<(), ApiError> {
    let lower = url.to_lowercase();

    // Block git:// transport (plain-text, insecure)
    if lower.starts_with("git://") {
        return Err(ApiError::BadRequest(
            "git:// transport is not allowed".into(),
        ));
    }

    // Block http:// unless dev mode
    if lower.starts_with("http://") {
        let dev_only = std::env::var("DIGGER_ALLOW_INSECURE").unwrap_or_default() == "1";
        if !dev_only {
            return Err(ApiError::BadRequest(
                "http:// is not allowed; use https://".into(),
            ));
        }
    }

    if !lower.starts_with("https://") && !lower.starts_with("http://") {
        return Err(ApiError::BadRequest(
            "Only https:// URLs are allowed".into(),
        ));
    }

    let host = extract_host(url)?;
    validate_host_ip(&host)?;

    Ok(())
}

/// Extract hostname from a URL string.
fn extract_host(url: &str) -> Result<String, ApiError> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("git://"))
        .ok_or_else(|| ApiError::BadRequest("Unsupported URL scheme".into()))?;

    let host = without_scheme
        .split('@')
        .next_back()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme)
        .split('/')
        .next()
        .unwrap_or(without_scheme);

    if host.is_empty() {
        return Err(ApiError::BadRequest("Empty hostname".into()));
    }
    Ok(host.to_string())
}

/// Resolve hostname and check IP against blocklist.
fn validate_host_ip(host: &str) -> Result<(), ApiError> {
    let addrs = format!("{}:443", host)
        .to_socket_addrs()
        .map_err(|e| ApiError::BadRequest(format!("DNS resolution failed: {}", e)))?;

    for addr in addrs {
        let ip = addr.ip();
        if is_blocked_ip(ip) {
            return Err(ApiError::BadRequest(format!(
                "IP address {} is blocked (private/loopback/link-local/cloud-metadata)",
                ip
            )));
        }
    }

    Ok(())
}

/// Check if an IP address should be blocked for outbound connections.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()       // 127.0.0.0/8
                || v4.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local() // 169.254.0.0/16 (includes cloud metadata 169.254.169.254)
                || v4.octets() == [0, 0, 0, 0]
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.octets()[0] == 0xfe // fe80::/10 (link-local)
                || v6.octets()[0] == 0xfc // fc00::/7 (ULA)
                || v6.octets()[0] == 0xfd // fd00::/7 (ULA)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_loopback() {
        assert!(validate_external_url("https://127.0.0.1/repo").is_err());
        assert!(validate_external_url("https://127.0.0.1:8080/repo").is_err());
    }

    #[test]
    fn test_blocks_private_network() {
        assert!(validate_external_url("https://10.0.0.5/repo").is_err());
        assert!(validate_external_url("https://172.16.0.1/repo").is_err());
        assert!(validate_external_url("https://192.168.1.1/repo").is_err());
    }

    #[test]
    fn test_blocks_link_local() {
        assert!(validate_external_url("https://169.254.169.254/repo").is_err());
    }

    #[test]
    fn test_blocks_unspecified() {
        assert!(validate_external_url("https://0.0.0.0/repo").is_err());
    }

    #[test]
    fn test_blocks_git_protocol() {
        assert!(validate_external_url("git://github.com/user/repo").is_err());
    }

    #[test]
    fn test_blocks_http_in_production() {
        assert!(validate_external_url("http://example.com/repo").is_err());
    }

    #[test]
    fn test_allows_https() {
        // github.com resolves to a public IP, should pass
        assert!(validate_external_url("https://github.com/user/repo").is_ok());
    }

    #[test]
    fn test_extract_host_basic() {
        assert_eq!(
            extract_host("https://github.com/user/repo.git").unwrap(),
            "github.com"
        );
    }
}
