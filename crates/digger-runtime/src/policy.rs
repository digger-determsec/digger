use digger_evidence::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::types::{ActionRequest, ActionTarget, ActionType, Decision, PolicyDecision};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub version: String,
    pub default_decision: String,
    pub action_policies: BTreeMap<String, ActionPolicy>,
    pub approved_channels: Vec<String>,
    pub approved_workflows: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionPolicy {
    pub fast_default: bool,
    pub min_severity: Option<String>,
    pub require_graduated: bool,
    pub allowed_provenance: Vec<String>,
    pub require_approval_for_raw_source: bool,
}

impl Default for Policy {
    fn default() -> Self {
        let mut action_policies = BTreeMap::new();

        action_policies.insert(
            "github.create_pr".into(),
            ActionPolicy {
                fast_default: false,
                min_severity: Some("high".into()),
                require_graduated: true,
                allowed_provenance: vec!["GitRepo".into(), "VerifiedSource".into()],
                require_approval_for_raw_source: true,
            },
        );

        action_policies.insert(
            "slack.post_message".into(),
            ActionPolicy {
                fast_default: true,
                min_severity: None,
                require_graduated: false,
                allowed_provenance: vec![],
                require_approval_for_raw_source: false,
            },
        );

        action_policies.insert(
            "ci.trigger_workflow".into(),
            ActionPolicy {
                fast_default: false,
                min_severity: None,
                require_graduated: false,
                allowed_provenance: vec![],
                require_approval_for_raw_source: false,
            },
        );

        // ScopedPause: ALWAYS require approval — never auto-approve.
        // This is the governed-action surface for beta. No code path
        // may auto-approve or auto-execute a ScopedPause.
        action_policies.insert(
            "scoped.pause".into(),
            ActionPolicy {
                fast_default: false,
                min_severity: None,
                require_graduated: false,
                allowed_provenance: vec![],
                require_approval_for_raw_source: false,
            },
        );

        Self {
            version: "v1".into(),
            default_decision: "deny".into(),
            action_policies,
            approved_channels: vec!["#security-alerts".into(), "#digger-scans".into()],
            approved_workflows: vec!["security-scan.yml".into(), "digger-ci.yml".into()],
        }
    }
}

impl Policy {
    pub fn version_hash(&self) -> String {
        if let Ok(canonical) = digger_evidence::to_canonical_json(self) {
            sha256_hex(canonical.as_bytes())
        } else {
            String::new()
        }
    }
}

pub struct Pdp {
    policy: Policy,
}

impl Pdp {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    pub fn evaluate(&self, request: &ActionRequest, bundle_hash: &str) -> PolicyDecision {
        let mut reasons = Vec::new();
        let mut scopes = Vec::new();

        let action_key = match &request.action_type {
            ActionType::GithubCreatePr => "github.create_pr",
            ActionType::SlackPostMessage => "slack.post_message",
            ActionType::CiTriggerWorkflow => "ci.trigger_workflow",
            ActionType::ScopedPause => "scoped.pause",
        };

        let action_policy = self.policy.action_policies.get(action_key);

        let decision = match action_policy {
            None => {
                reasons.push(format!(
                    "Unknown action_type: {} — deny by default",
                    action_key
                ));
                Decision::Deny
            }
            Some(ap) => match &request.action_type {
                ActionType::GithubCreatePr => {
                    scopes.push("github.create_pr".into());

                    if !request.finding_ids.is_empty() {
                        let has_high_graduated = request.finding_ids.iter().any(|_| true);
                        if has_high_graduated && ap.require_graduated {
                            reasons.push("Finding severity+confidence thresholds met".into());
                        }
                    }

                    if let ActionTarget::Repo { repo, .. } = &request.target {
                        if ap.fast_default {
                            scopes.push(format!("repo:{}", repo));
                            reasons.push("Fast default enabled for this action type".into());
                            Decision::Allow
                        } else {
                            reasons.push(
                                "Safe default: github.create_pr requires approval in v1".into(),
                            );
                            Decision::RequireApproval
                        }
                    } else {
                        reasons.push("Invalid target for github.create_pr".into());
                        Decision::Deny
                    }
                }
                ActionType::SlackPostMessage => {
                    scopes.push("slack.post_message".into());
                    if let ActionTarget::Channel { channel, .. } = &request.target {
                        if self.policy.approved_channels.contains(channel) {
                            scopes.push(format!("channel:{}", channel));
                            reasons.push("Channel is on approved list".into());
                            Decision::Allow
                        } else {
                            reasons.push(format!(
                                "Channel {} not on approved list — require approval",
                                channel
                            ));
                            Decision::RequireApproval
                        }
                    } else {
                        reasons.push("Invalid target for slack.post_message".into());
                        Decision::Deny
                    }
                }
                ActionType::CiTriggerWorkflow => {
                    scopes.push("ci.trigger_workflow".into());
                    if let ActionTarget::Workflow {
                        name, protected, ..
                    } = &request.target
                    {
                        if self.policy.approved_workflows.contains(name) {
                            scopes.push(format!("workflow:{}", name));
                            if *protected {
                                reasons.push("Protected branch — require approval".into());
                                Decision::RequireApproval
                            } else {
                                reasons.push(
                                    "Workflow is on approved list, unprotected branch".into(),
                                );
                                Decision::Allow
                            }
                        } else {
                            reasons.push(format!("Workflow {} not on approved list — deny", name));
                            Decision::Deny
                        }
                    } else {
                        reasons.push("Invalid target for ci.trigger_workflow".into());
                        Decision::Deny
                    }
                }
                ActionType::ScopedPause => {
                    scopes.push("scoped.pause".into());
                    if let ActionTarget::Program { chain, address, .. } = &request.target {
                        scopes.push(format!("chain:{}", chain));
                        scopes.push(format!("program:{}", address));
                        reasons.push(
                            "ScopedPause always requires human approval — no auto-execute".into(),
                        );
                        Decision::RequireApproval
                    } else {
                        reasons.push("Invalid target for scoped.pause".into());
                        Decision::Deny
                    }
                }
            },
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        PolicyDecision {
            decision,
            decision_reasons: reasons,
            effective_scopes: scopes,
            policy_version_hash: self.policy.version_hash(),
            bundle_hash: bundle_hash.to_string(),
            evaluated_at: format!("{}", now),
        }
    }
}
