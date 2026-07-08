use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// A redacting wrapper that hides secrets in Debug/Display/Serialize.
/// Makes it a compile-time mistake to accidentally log or serialize raw secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactingSecret(String);

impl RedactingSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedactingSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***")
    }
}

impl fmt::Display for RedactingSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***")
    }
}

impl Serialize for RedactingSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("***")
    }
}

impl<'de> Deserialize<'de> for RedactingSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(RedactingSecret::new)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialHandle {
    pub handle_id: String,
    pub tenant_id: String,
    pub action_type: String,
    pub scope: String,
    pub secret: RedactingSecret,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub struct CredentialBroker {
    base_secrets: std::sync::Mutex<BTreeMap<String, RedactingSecret>>,
    handles: std::sync::Mutex<Vec<CredentialHandle>>,
    ttl_secs: u64,
}

impl CredentialBroker {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            base_secrets: std::sync::Mutex::new(BTreeMap::new()),
            handles: std::sync::Mutex::new(Vec::new()),
            ttl_secs,
        }
    }

    pub fn register_secret(&self, key: &str, secret: &str) {
        let mut secrets = self.base_secrets.lock().unwrap_or_else(|p| p.into_inner());
        secrets.insert(key.to_string(), RedactingSecret::new(secret.to_string()));
    }

    pub fn issue_scoped(
        &self,
        tenant_id: &str,
        action_type: &str,
        scope: &str,
    ) -> CredentialHandle {
        let now = now_secs();
        let key = format!("{}:{}", tenant_id, action_type);
        let secret = {
            let secrets = self.base_secrets.lock().unwrap_or_else(|p| p.into_inner());
            secrets
                .get(&key)
                .cloned()
                .unwrap_or_else(|| RedactingSecret::new("not-configured".into()))
        };

        let handle = CredentialHandle {
            handle_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            action_type: action_type.to_string(),
            scope: scope.to_string(),
            secret,
            issued_at: now,
            expires_at: now + self.ttl_secs,
        };

        let mut handles = self.handles.lock().unwrap_or_else(|p| p.into_inner());
        handles.push(handle.clone());
        handle
    }

    pub fn is_valid(&self, handle: &CredentialHandle) -> bool {
        now_secs() <= handle.expires_at
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
