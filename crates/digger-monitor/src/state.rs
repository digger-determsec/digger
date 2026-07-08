use digger_runtime::PolicyDecision;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchTarget {
    pub tenant_id: String,
    pub target_descriptor: String,
    pub alert_channel: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitorState {
    pub last_revision: Option<String>,
    pub last_bundle_hash: Option<String>,
    pub last_finding_ids: Vec<String>,
    pub already_actioned_finding_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingDiff {
    pub new_findings: Vec<String>,
    pub resolved_findings: Vec<String>,
    pub persisting_findings: Vec<String>,
}

pub fn diff_findings(old_ids: &[String], new_ids: &[String]) -> FindingDiff {
    let old_set: std::collections::BTreeSet<&String> = old_ids.iter().collect();
    let new_set: std::collections::BTreeSet<&String> = new_ids.iter().collect();

    FindingDiff {
        new_findings: new_set.difference(&old_set).cloned().cloned().collect(),
        resolved_findings: old_set.difference(&new_set).cloned().cloned().collect(),
        persisting_findings: new_set.intersection(&old_set).cloned().cloned().collect(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionProposal {
    pub action_type: String,
    pub finding_id: String,
    pub policy_decision: PolicyDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TickReport {
    pub revision: String,
    pub bundle_hash: String,
    pub new_findings: Vec<String>,
    pub resolved_findings: Vec<String>,
    pub persisting_findings: Vec<String>,
    pub action_proposals: Vec<ActionProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copilot_explanations: Option<Vec<crate::history::FindingExplanationRecord>>,
}
