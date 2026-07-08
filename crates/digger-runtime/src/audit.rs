use digger_evidence::{canonicalize, sha256_hex};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::connectors::ConnectorError;
use crate::types::{Decision, PolicyDecision};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_id: String,
    pub action_id: String,
    pub tenant_id: String,
    pub policy_version_hash: String,
    pub bundle_hash: String,
    pub decision: Decision,
    pub decision_reasons: Vec<String>,
    pub effective_scopes: Vec<String>,
    pub request_hash: String,
    pub response_hash: Option<String>,
    pub approval_id: Option<String>,
    pub prev_event_hash: Option<String>,
    pub event_hash: String,
    pub created_at: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyChainResult {
    pub valid: bool,
    pub event_count: usize,
    pub broken_at: Option<usize>,
    pub details: Vec<String>,
}

pub trait AuditStore: Send + Sync {
    fn append(&self, event: &AuditEvent) -> Result<(), ConnectorError>;
    fn list_events(&self, tenant_id: &str) -> Result<Vec<AuditEvent>, ConnectorError>;
    fn last_event_hash(&self, tenant_id: &str) -> Option<String>;
}

pub struct InMemoryAuditStore {
    events: std::sync::Mutex<BTreeMap<String, Vec<AuditEvent>>>,
}

impl InMemoryAuditStore {
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(BTreeMap::new()),
        }
    }
}

impl Default for InMemoryAuditStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditStore for InMemoryAuditStore {
    fn append(&self, event: &AuditEvent) -> Result<(), ConnectorError> {
        let mut events = self
            .events
            .lock()
            .map_err(|e| format!("lock poisoned: {e}"))?;
        events
            .entry(event.tenant_id.clone())
            .or_default()
            .push(event.clone());
        Ok(())
    }

    fn list_events(&self, tenant_id: &str) -> Result<Vec<AuditEvent>, ConnectorError> {
        let events = self
            .events
            .lock()
            .map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(events.get(tenant_id).cloned().unwrap_or_default())
    }

    fn last_event_hash(&self, tenant_id: &str) -> Option<String> {
        let events = self.events.lock().unwrap_or_else(|p| p.into_inner());
        events
            .get(tenant_id)
            .and_then(|v| v.last())
            .map(|e| e.event_hash.clone())
    }
}

pub fn create_audit_event(
    action_id: &str,
    tenant_id: &str,
    decision: &PolicyDecision,
    request_hash: &str,
    prev_event_hash: Option<&str>,
) -> AuditEvent {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let content = serde_json::json!({
        "action_id": action_id,
        "tenant_id": tenant_id,
        "policy_version_hash": decision.policy_version_hash,
        "bundle_hash": decision.bundle_hash,
        "decision": format!("{:?}", decision.decision).to_lowercase(),
        "decision_reasons": decision.decision_reasons,
        "effective_scopes": decision.effective_scopes,
        "request_hash": request_hash,
        "response_hash": serde_json::Value::Null,
        "approval_id": serde_json::Value::Null,
        "prev_event_hash": prev_event_hash,
    });

    let event_hash = sha256_hex(canonicalize(&content).as_bytes());

    AuditEvent {
        event_id: Uuid::new_v4().to_string(),
        action_id: action_id.to_string(),
        tenant_id: tenant_id.to_string(),
        policy_version_hash: decision.policy_version_hash.clone(),
        bundle_hash: decision.bundle_hash.clone(),
        decision: decision.decision.clone(),
        decision_reasons: decision.decision_reasons.clone(),
        effective_scopes: decision.effective_scopes.clone(),
        request_hash: request_hash.to_string(),
        response_hash: None,
        approval_id: None,
        prev_event_hash: prev_event_hash.map(|s| s.to_string()),
        event_hash,
        created_at: format!("{}", now),
        latency_ms: 0,
    }
}

pub fn verify_audit_chain(events: &[AuditEvent]) -> VerifyChainResult {
    let mut details = Vec::new();
    let mut prev_hash: Option<String> = None;

    for (i, event) in events.iter().enumerate() {
        if event.prev_event_hash != prev_hash {
            details.push(format!(
                "Event {}: prev_event_hash mismatch: expected {:?}, got {:?}",
                i, prev_hash, event.prev_event_hash
            ));
            return VerifyChainResult {
                valid: false,
                event_count: events.len(),
                broken_at: Some(i),
                details,
            };
        }
        prev_hash = Some(event.event_hash.clone());
    }

    VerifyChainResult {
        valid: true,
        event_count: events.len(),
        broken_at: None,
        details,
    }
}
