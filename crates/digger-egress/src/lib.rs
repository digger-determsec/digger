use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

// ═══════════════════════════════════════════════════════════════════
// Global egress policy — set once at startup, checked at every choke point
// ═══════════════════════════════════════════════════════════════════

static GLOBAL_POLICY: OnceLock<Mutex<EgressPolicy>> = OnceLock::new();

/// Initialize the global egress policy. Call once at CLI startup.
pub fn init_global(policy: EgressPolicy) {
    let _ = GLOBAL_POLICY.set(Mutex::new(policy));
}

/// Authorize egress through the global policy. Called at every HTTP choke point.
/// Returns Ok(()) if allowed, Err(EgressError) if denied.
/// Panics if init_global() was never called (programming error).
pub fn authorize_global(url: &str, purpose: &str) -> Result<(), EgressError> {
    let lock = GLOBAL_POLICY
        .get()
        .expect("egress policy not initialized — call init_global() first");
    let mut policy = lock.lock().expect("egress policy lock poisoned");
    policy.authorize(url, purpose)
}

/// Redact secret query parameters (apikey, key, token, etc.) from a URL.
/// Returns a sanitized URL safe for display in prompts and logs.
pub fn redact_url(url: &str) -> String {
    let secret_params = ["apikey", "api_key", "key", "token", "secret", "password"];
    if let Some(qpos) = url.find('?') {
        let base = &url[..=qpos];
        let query = &url[qpos + 1..];
        let redacted_params: Vec<String> = query
            .split('&')
            .map(|param| {
                if let Some((name, _value)) = param.split_once('=') {
                    let lower = name.to_lowercase();
                    if secret_params.iter().any(|sp| lower.contains(sp)) {
                        format!("{}=****", name)
                    } else {
                        param.to_string()
                    }
                } else {
                    param.to_string()
                }
            })
            .collect();
        format!("{}{}", base, redacted_params.join("&"))
    } else {
        url.to_string()
    }
}

/// Errors from the egress gate.
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("network access denied: {0}")]
    Denied(String),

    #[error("trust store error: {0}")]
    TrustStore(String),

    #[error("user declined egress to {host}")]
    UserDeclined { host: String },
}

/// Policy controlling whether network egress is allowed.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// If true, all egress is blocked regardless of trust store.
    pub offline: bool,
    /// If true, silently allow without prompting.
    pub assume_yes: bool,
    /// Per-host overrides from --allow-egress flags.
    pub allow_hosts: Vec<String>,
    /// In-memory trust store.
    store: TrustStore,
}

/// Trust store: maps (scheme, host) -> trusted purposes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TrustStore {
    /// Key: "SCHEME://HOST", value: list of trusted purposes.
    entries: HashMap<String, Vec<String>>,
}

impl TrustStore {
    fn path() -> PathBuf {
        dirs_home().join(".digger").join("trust.json")
    }

    fn load() -> Self {
        let path = Self::path();
        match fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    fn save(&self) -> Result<(), EgressError> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| EgressError::TrustStore(format!("cannot create ~/.digger/: {e}")))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| EgressError::TrustStore(format!("serialize error: {e}")))?;
        fs::write(&path, &json)
            .map_err(|e| EgressError::TrustStore(format!("write error: {e}")))?;
        // Best-effort set file mode to 0600 (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn is_trusted(&self, key: &str, purpose: &str) -> bool {
        self.entries
            .get(key)
            .map(|purposes| purposes.iter().any(|p| p == purpose))
            .unwrap_or(false)
    }

    fn trust(&mut self, key: &str, purpose: &str) {
        self.entries
            .entry(key.to_string())
            .or_default()
            .push(purpose.to_string());
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

impl EgressPolicy {
    /// Create from CLI flags.
    pub fn new(offline: bool, assume_yes: bool, allow_hosts: Vec<String>) -> Self {
        Self {
            offline,
            assume_yes,
            allow_hosts,
            store: TrustStore::load(),
        }
    }

    /// Authorize network egress to a specific host for a given purpose.
    /// Blocks if offline, checks trust store, prompts if TTY, or denies.
    pub fn authorize(&mut self, url: &str, purpose: &str) -> Result<(), EgressError> {
        // Parse scheme + host from URL
        let (scheme, host) = parse_url_host(url)
            .ok_or_else(|| EgressError::Denied(format!("invalid URL: {url}")))?;

        // Offline mode: hard block
        if self.offline {
            return Err(EgressError::Denied(format!(
                "offline mode: blocked egress to {scheme}://{host} ({purpose})"
            )));
        }

        // --allow-egress flag: trusted per-session
        if self.allow_hosts.contains(&host) {
            return Ok(());
        }

        // Trust store: already trusted?
        let key = format!("{}://{}", scheme.to_uppercase(), host);
        if self.store.is_trusted(&key, purpose) {
            return Ok(());
        }

        // Non-TTY: fail closed
        if !is_tty() || self.assume_yes {
            if self.assume_yes {
                // Auto-trust and persist
                self.store.trust(&key, purpose);
                let _ = self.store.save();
                return Ok(());
            }
            return Err(EgressError::Denied(format!(
                "non-interactive session: blocked egress to {scheme}://{host} ({purpose}). \
                 Use --allow-egress {host} or --assume-yes to proceed."
            )));
        }

        // TTY: interactive prompt
        print!("digger: allow network access to {scheme}://{host} for {purpose}? [y/N] ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| EgressError::TrustStore(format!("read error: {e}")))?;
        let trimmed = input.trim().to_lowercase();
        if trimmed == "y" || trimmed == "yes" {
            self.store.trust(&key, purpose);
            let _ = self.store.save();
            Ok(())
        } else {
            Err(EgressError::UserDeclined { host: host.clone() })
        }
    }

    /// Authorize and return the result without mutating trust store.
    /// Used for dry-run / check modes.
    pub fn check(&self, url: &str, purpose: &str) -> Result<(), EgressError> {
        let (scheme, host) = parse_url_host(url)
            .ok_or_else(|| EgressError::Denied(format!("invalid URL: {url}")))?;

        if self.offline {
            return Err(EgressError::Denied(format!(
                "offline mode: blocked egress to {scheme}://{host} ({purpose})"
            )));
        }
        if self.allow_hosts.contains(&host) {
            return Ok(());
        }
        let key = format!("{}://{}", scheme.to_uppercase(), host);
        if self.store.is_trusted(&key, purpose) {
            return Ok(());
        }
        Err(EgressError::Denied(format!(
            "not authorized: {scheme}://{host} ({purpose}). \
             Use --allow-egress {host} to trust."
        )))
    }
}

/// Parse scheme and host from a URL.
fn parse_url_host(url: &str) -> Option<(String, String)> {
    // Handle both http:// and https://
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split('/').next()?;
    // Strip port if present
    let host = host.split(':').next()?;
    let scheme = if url.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    Some((scheme.to_string(), host.to_string()))
}

/// Check if stdin is a TTY (interactive terminal).
fn is_tty() -> bool {
    use std::io::IsTerminal;
    io::stdin().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_simple() {
        let (scheme, host) = parse_url_host("https://api.etherscan.io/api").unwrap();
        assert_eq!(scheme, "https");
        assert_eq!(host, "api.etherscan.io");
    }

    #[test]
    fn parse_url_with_port() {
        let (scheme, host) = parse_url_host("https://rpc.example.com:8545").unwrap();
        assert_eq!(scheme, "https");
        assert_eq!(host, "rpc.example.com");
    }

    #[test]
    fn parse_url_http() {
        let (scheme, host) = parse_url_host("http://localhost:3000/api").unwrap();
        assert_eq!(scheme, "http");
        assert_eq!(host, "localhost");
    }

    #[test]
    fn offline_blocks_everything() {
        let mut policy = EgressPolicy::new(true, false, vec![]);
        let err = policy
            .authorize("https://api.etherscan.io/api", "fetch-source")
            .unwrap_err();
        assert!(err.to_string().contains("offline mode"));
    }

    #[test]
    fn allow_host_bypasses_trust() {
        let mut policy = EgressPolicy::new(false, false, vec!["api.etherscan.io".to_string()]);
        assert!(policy
            .authorize("https://api.etherscan.io/api", "fetch-source")
            .is_ok());
    }

    #[test]
    fn deny_non_interactive_no_trust() {
        let mut policy = EgressPolicy::new(false, false, vec![]);
        // When not TTY and not assume_yes and not trusted, should deny
        let result = policy.authorize("https://unknown.host/api", "test");
        if !is_tty() {
            assert!(result.is_err());
        }
    }

    #[test]
    fn check_does_not_mutate() {
        let policy = EgressPolicy::new(false, false, vec![]);
        let before = policy.store.entries.len();
        let _ = policy.check("https://unknown.host/api", "test");
        // check() must not add entries to the trust store
        assert_eq!(policy.store.entries.len(), before);
    }

    #[test]
    fn global_authorize_offline_blocks_and_allowed_host_passes() {
        // OnceLock can only be set once per process — test both behaviors in one test.
        init_global(EgressPolicy::new(true, false, vec![]));
        let result = authorize_global("https://api.etherscan.io/api", "test-purpose");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("offline mode"));
        // Note: cannot re-init OnceLock, so we test offline-only here.
        // The allowed-host path is covered by the per-instance authorize tests.
    }

    #[test]
    fn redact_url_strips_secret_params() {
        let url = "https://api.etherscan.io/api?module=contract&action=getsourcecode&address=0x123&apikey=mysupersecretkey";
        let redacted = redact_url(url);
        assert!(
            !redacted.contains("mysupersecretkey"),
            "API key must not appear in redacted URL"
        );
        assert!(
            redacted.contains("apikey=****"),
            "Redacted param should show ****"
        );
        assert!(
            redacted.contains("address=0x123"),
            "Non-secret params must be preserved"
        );
    }

    #[test]
    fn redact_url_no_params_unchanged() {
        let url = "https://api.etherscan.io/api";
        assert_eq!(redact_url(url), url);
    }

    #[test]
    fn redact_url_multiple_secrets() {
        let url = "https://host/api?token=abc&key=def&safe=value";
        let redacted = redact_url(url);
        assert!(redacted.contains("token=****"));
        assert!(redacted.contains("key=****"));
        assert!(redacted.contains("safe=value"));
    }
}
