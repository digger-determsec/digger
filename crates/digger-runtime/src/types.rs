use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Actor {
    pub user_id: String,
    pub agent_id: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionType {
    #[serde(rename = "github.create_pr")]
    GithubCreatePr,
    #[serde(rename = "slack.post_message")]
    SlackPostMessage,
    #[serde(rename = "ci.trigger_workflow")]
    CiTriggerWorkflow,
    #[serde(rename = "scoped.pause")]
    ScopedPause,
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GithubCreatePr => write!(f, "github.create_pr"),
            Self::SlackPostMessage => write!(f, "slack.post_message"),
            Self::CiTriggerWorkflow => write!(f, "ci.trigger_workflow"),
            Self::ScopedPause => write!(f, "scoped.pause"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionTarget {
    #[serde(rename = "repo")]
    Repo { repo: String, branch: String },
    #[serde(rename = "channel")]
    Channel {
        channel: String,
        workspace: Option<String>,
    },
    #[serde(rename = "workflow")]
    Workflow {
        name: String,
        ref_name: String,
        protected: bool,
    },
    #[serde(rename = "program")]
    Program {
        chain: String,
        address: String,
        function: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionRequest {
    pub action_id: String,
    pub tenant_id: String,
    pub actor: Actor,
    pub action_type: ActionType,
    pub target: ActionTarget,
    pub payload: serde_json::Value,
    pub evidence_bundle_id: String,
    pub finding_ids: Vec<String>,
    pub justification: String,
    pub requested_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny,
    #[serde(rename = "require_approval")]
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub decision_reasons: Vec<String>,
    pub effective_scopes: Vec<String>,
    pub policy_version_hash: String,
    pub bundle_hash: String,
    pub evaluated_at: String,
}
