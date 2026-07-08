use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::connectors::ConnectorError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub approval_id: String,
    pub action_id: String,
    pub actor: String,
    pub allowed_scope: Vec<String>,
    pub expiry_secs: u64,
    pub nonce: String,
    pub status: ApprovalStatus,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "granted")]
    Granted,
    #[serde(rename = "consumed")]
    Consumed,
    #[serde(rename = "expired")]
    Expired,
    #[serde(rename = "denied")]
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalToken {
    pub approval_id: String,
    pub action_id: String,
    pub nonce: String,
    pub scope: Vec<String>,
    pub expires_at: u64,
}

pub struct ApprovalService {
    approvals: std::sync::Mutex<BTreeMap<String, ApprovalRequest>>,
    tokens: std::sync::Mutex<BTreeMap<String, ApprovalToken>>,
    burned_nonces: std::sync::Mutex<Vec<String>>,
    default_expiry_secs: u64,
}

impl ApprovalService {
    pub fn new(default_expiry_secs: u64) -> Self {
        Self {
            approvals: std::sync::Mutex::new(BTreeMap::new()),
            tokens: std::sync::Mutex::new(BTreeMap::new()),
            burned_nonces: std::sync::Mutex::new(Vec::new()),
            default_expiry_secs,
        }
    }

    pub fn create_approval(
        &self,
        action_id: &str,
        actor: &str,
        allowed_scope: Vec<String>,
    ) -> ApprovalRequest {
        let now = now_secs();
        let approval = ApprovalRequest {
            approval_id: Uuid::new_v4().to_string(),
            action_id: action_id.to_string(),
            actor: actor.to_string(),
            allowed_scope,
            expiry_secs: self.default_expiry_secs,
            nonce: Uuid::new_v4().to_string().replace('-', ""),
            status: ApprovalStatus::Pending,
            created_at: format!("{}", now),
        };
        let mut approvals = self.approvals.lock().unwrap_or_else(|p| p.into_inner());
        approvals.insert(approval.approval_id.clone(), approval.clone());
        approval
    }

    pub fn grant(&self, approval_id: &str) -> Result<ApprovalToken, ConnectorError> {
        let mut approvals = self
            .approvals
            .lock()
            .map_err(|e| format!("lock poisoned: {e}"))?;
        let approval = approvals
            .get_mut(approval_id)
            .ok_or_else(|| ConnectorError::from("Approval not found".to_string()))?;

        if approval.status != ApprovalStatus::Pending {
            return Err(format!("Approval is not pending: {:?}", approval.status).into());
        }

        approval.status = ApprovalStatus::Granted;
        let now = now_secs();
        let token = ApprovalToken {
            approval_id: approval_id.to_string(),
            action_id: approval.action_id.clone(),
            nonce: approval.nonce.clone(),
            scope: approval.allowed_scope.clone(),
            expires_at: now + approval.expiry_secs,
        };

        let mut tokens = self
            .tokens
            .lock()
            .map_err(|e| format!("lock poisoned: {e}"))?;
        tokens.insert(token.approval_id.clone(), token.clone());
        Ok(token)
    }

    pub fn consume(&self, approval_id: &str, nonce: &str) -> Result<ApprovalToken, ConnectorError> {
        let token = {
            let tokens = self
                .tokens
                .lock()
                .map_err(|e| format!("lock poisoned: {e}"))?;
            tokens
                .get(approval_id)
                .cloned()
                .ok_or_else(|| ConnectorError::from("No approval token found".to_string()))?
        };

        {
            let burned = self
                .burned_nonces
                .lock()
                .map_err(|e| format!("lock poisoned: {e}"))?;
            if burned.contains(&token.nonce) {
                return Err(ConnectorError::from(
                    "Nonce already burned (replay detected)".to_string(),
                ));
            }
        }

        if token.nonce != nonce {
            return Err(ConnectorError::from("Nonce mismatch".to_string()));
        }

        let now = now_secs();
        if now > token.expires_at {
            return Err(ConnectorError::from("Approval token expired".to_string()));
        }

        {
            let mut burned = self
                .burned_nonces
                .lock()
                .map_err(|e| format!("lock poisoned: {e}"))?;
            burned.push(nonce.to_string());
        }

        {
            let mut approvals = self
                .approvals
                .lock()
                .map_err(|e| format!("lock poisoned: {e}"))?;
            if let Some(a) = approvals.get_mut(approval_id) {
                a.status = ApprovalStatus::Consumed;
            }
        }

        Ok(token)
    }

    pub fn scope_covers(&self, token: &ApprovalToken, required_scope: &[String]) -> bool {
        required_scope.iter().all(|s| token.scope.contains(s))
    }

    pub fn get_approval(&self, approval_id: &str) -> Option<ApprovalRequest> {
        self.approvals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(approval_id)
            .cloned()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
