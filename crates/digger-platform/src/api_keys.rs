use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// An API key for authenticating agents/clients.
///
/// The `secret` is generated exactly once and returned to the caller.
/// Only `secret_hash` is persisted — plaintext secrets are never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub id: String,
    pub prefix: String,
    pub secret_hash: String,
    pub name: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub created_at: String,
    pub last_used: Option<String>,
    pub revoked: bool,
    /// Optional expiry timestamp (ISO 8601). If None, the key never expires.
    pub expires_at: Option<String>,
}

/// The secret value returned exactly once on creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeySecret {
    pub key: String,
    pub id: String,
    pub prefix: String,
}

const COLLECTION: &str = "api_keys";

/// Generate a new API key, store only the hash, return the secret.
pub fn create_key(
    store: &dyn crate::storage::Storage,
    name: &str,
    org_id: &str,
    project_id: Option<&str>,
) -> Result<ApiKeySecret, String> {
    create_key_with_expiry(store, name, org_id, project_id, None)
}

/// Create a key with an optional expiry time.
pub fn create_key_with_expiry(
    store: &dyn crate::storage::Storage,
    name: &str,
    org_id: &str,
    project_id: Option<&str>,
    expires_at: Option<String>,
) -> Result<ApiKeySecret, String> {
    let id = uuid::Uuid::new_v4().to_string();
    let secret = generate_secret();
    let prefix = secret[..8].to_string();
    // Hash the full secret (not prefix.secret) — validate_key extracts the secret part after '.'
    let secret_hash = sha256_hex(&secret);
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let record = ApiKeyRecord {
        id: id.clone(),
        prefix,
        secret_hash,
        name: name.to_string(),
        org_id: org_id.to_string(),
        project_id: project_id.map(|s| s.to_string()),
        created_at: now,
        last_used: None,
        revoked: false,
        expires_at,
    };

    let value = serde_json::to_value(&record).map_err(|e| e.to_string())?;
    store
        .write_json(COLLECTION, &id, &value)
        .map_err(|e| format!("{:?}", e))?;

    Ok(ApiKeySecret {
        key: format!("{}.{}", record.prefix, secret),
        id,
        prefix: record.prefix,
    })
}

/// List API key metadata (never the secret).
pub fn list_keys(store: &dyn crate::storage::Storage, org_id: &str) -> Vec<ApiKeyRecord> {
    store
        .list_all_json(COLLECTION)
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .filter(|k: &ApiKeyRecord| k.org_id == org_id)
        .collect()
}

/// Revoke an API key by ID, scoped to an org. Returns NotFound if the key
/// doesn't exist or belongs to a different org.
pub fn revoke_key(
    store: &dyn crate::storage::Storage,
    org_id: &str,
    key_id: &str,
) -> Result<(), String> {
    let value = store
        .read_json(COLLECTION, key_id)
        .map_err(|e| format!("{:?}", e))?;
    let mut record: ApiKeyRecord = serde_json::from_value(value).map_err(|e| format!("{:?}", e))?;
    if record.org_id != org_id {
        return Err("not found".into());
    }
    record.revoked = true;
    let updated = serde_json::to_value(&record).map_err(|e| e.to_string())?;
    store
        .write_json(COLLECTION, key_id, &updated)
        .map_err(|e| format!("{:?}", e))?;
    Ok(())
}

/// Validate a raw API key string against stored hashes.
/// Returns the resolved ApiKeyRecord if valid and not revoked.
pub fn validate_key(
    store: &dyn crate::storage::Storage,
    raw_key: &str,
) -> Result<ApiKeyRecord, String> {
    let (prefix, secret) = parse_key(raw_key)?;
    let secret_hash = sha256_hex(&secret);

    let all_keys = store.list_all_json(COLLECTION);
    for v in all_keys {
        if let Ok(record) = serde_json::from_value::<ApiKeyRecord>(v) {
            if record.prefix == prefix && record.secret_hash == secret_hash && !record.revoked {
                // Check expiry
                if let Some(ref expires) = record.expires_at {
                    match chrono::DateTime::parse_from_rfc3339(expires) {
                        Ok(exp) => {
                            if chrono::Utc::now() > exp {
                                return Err("API key has expired".into());
                            }
                        }
                        Err(_) => {
                            // Malformed expires_at — fail-closed (reject)
                            return Err("API key has invalid expiry".into());
                        }
                    }
                }
                return Ok(record);
            }
        }
    }
    Err("invalid or revoked API key".into())
}

fn parse_key(raw: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = raw.splitn(2, '.').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err("invalid API key format (expected prefix.secret)".into());
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn generate_secret() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    hex::encode(&bytes)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
