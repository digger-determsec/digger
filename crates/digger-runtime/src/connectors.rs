use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorClass {
    Transient,
    Permanent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ConnectorError {
    pub message: String,
    pub error_class: ErrorClass,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorOutput {
    pub success: bool,
    pub output_url: Option<String>,
    pub output_id: Option<String>,
    pub raw_output: String,
}

/// Extract a short identifier from an idempotency key (up to 8 bytes).
/// Panic-free: returns the full key if shorter than 8 bytes.
fn short_id(key: &str) -> &str {
    key.get(..8).unwrap_or(key)
}

pub trait Connector: Send + Sync {
    fn name(&self) -> &str;
    fn execute(
        &self,
        input: &ConnectorInput,
        idempotency_key: &str,
    ) -> Result<ConnectorOutput, ConnectorError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorInput {
    pub action_id: String,
    pub tenant_id: String,
    pub action_type: String,
    pub payload: serde_json::Value,
    pub credential_handle: String,
}

// ── Mock GitHub Connector ──────────────────────────────────────

pub struct MockGitHubConnector {
    pub should_fail: bool,
    pub error_class: Option<ErrorClass>,
}

impl MockGitHubConnector {
    pub fn new() -> Self {
        Self {
            should_fail: false,
            error_class: None,
        }
    }

    pub fn failing(class: ErrorClass) -> Self {
        Self {
            should_fail: true,
            error_class: Some(class),
        }
    }
}

impl Default for MockGitHubConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl Connector for MockGitHubConnector {
    fn name(&self) -> &str {
        "github.create_pr"
    }

    fn execute(
        &self,
        input: &ConnectorInput,
        idempotency_key: &str,
    ) -> Result<ConnectorOutput, ConnectorError> {
        if self.should_fail {
            let class = self.error_class.clone().unwrap_or(ErrorClass::Permanent);
            return Err(ConnectorError {
                message: format!("Mock GitHub error for action {}", input.action_id),
                error_class: class.clone(),
                retryable: class == ErrorClass::Transient,
            });
        }
        Ok(ConnectorOutput {
            success: true,
            output_url: Some(format!(
                "https://github.com/mock/pr/{}",
                short_id(idempotency_key)
            )),
            output_id: Some(format!("pr-{}", short_id(idempotency_key))),
            raw_output: "PR created successfully".into(),
        })
    }
}

// ── Mock Slack Connector ──────────────────────────────────────

pub struct MockSlackConnector {
    pub should_fail: bool,
}

impl MockSlackConnector {
    pub fn new() -> Self {
        Self { should_fail: false }
    }
}

impl Default for MockSlackConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl Connector for MockSlackConnector {
    fn name(&self) -> &str {
        "slack.post_message"
    }

    fn execute(
        &self,
        input: &ConnectorInput,
        idempotency_key: &str,
    ) -> Result<ConnectorOutput, ConnectorError> {
        if self.should_fail {
            return Err(ConnectorError {
                message: format!("Mock Slack error for action {}", input.action_id),
                error_class: ErrorClass::Transient,
                retryable: true,
            });
        }
        Ok(ConnectorOutput {
            success: true,
            output_url: Some(format!(
                "https://mock.slack.com/msg/{}",
                short_id(idempotency_key)
            )),
            output_id: Some(format!("msg-{}", short_id(idempotency_key))),
            raw_output: "Message posted successfully".into(),
        })
    }
}

// ── Dry-Run Scoped Pause Connector ──────────────────────────────

/// A propose-only connector for ScopedPause actions.
/// Emits the proposed pause into the approval queue and stops at the gate.
/// Any real-execution connector is behind config and disabled by default.
pub struct DryRunScopedPauseConnector;

impl DryRunScopedPauseConnector {
    pub fn new() -> Self {
        Self
    }
}

impl From<String> for ConnectorError {
    fn from(msg: String) -> Self {
        ConnectorError {
            message: msg,
            error_class: ErrorClass::Permanent,
            retryable: false,
        }
    }
}

impl Default for DryRunScopedPauseConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl Connector for DryRunScopedPauseConnector {
    fn name(&self) -> &str {
        "scoped.pause.dry_run"
    }

    fn execute(
        &self,
        input: &ConnectorInput,
        idempotency_key: &str,
    ) -> Result<ConnectorOutput, ConnectorError> {
        // Dry-run only: emit the proposed pause into the approval log.
        // Never executes the actual pause. The real connector is behind
        // config and disabled by default.
        Ok(ConnectorOutput {
            success: true,
            output_url: Some(format!(
                "scoped-pause://dry-run/{}",
                short_id(idempotency_key)
            )),
            output_id: Some(format!("pause-{}", short_id(idempotency_key))),
            raw_output: format!(
                "Dry-run: proposed pause for {} on action {} — awaiting human approval",
                input.action_type, input.action_id
            ),
        })
    }
}
