use std::sync::Arc;

use digger_runtime::{ActionGateway, ActionTarget, ActionType, Actor, Decision};

use crate::copilot_bridge::MonitorCopilot;
use crate::source::{MonitorSource, Revision};
use crate::state::{diff_findings, ActionProposal, MonitorState, TickReport, WatchTarget};
use crate::store::MonitorStore;

pub struct Monitor<S: MonitorSource> {
    source: S,
    store: Arc<dyn MonitorStore>,
    gateway: Arc<ActionGateway>,
    evidence_store: Arc<dyn digger_evidence::EvidenceStore>,
    copilot: Option<Arc<dyn MonitorCopilot>>,
}

impl<S: MonitorSource> Monitor<S> {
    pub fn new(
        source: S,
        store: Arc<dyn MonitorStore>,
        gateway: Arc<ActionGateway>,
        evidence_store: Arc<dyn digger_evidence::EvidenceStore>,
    ) -> Self {
        Self {
            source,
            store,
            gateway,
            evidence_store,
            copilot: None,
        }
    }

    pub fn with_copilot(mut self, copilot: Arc<dyn MonitorCopilot>) -> Self {
        self.copilot = Some(copilot);
        self
    }

    pub fn gateway(&self) -> &ActionGateway {
        &self.gateway
    }

    pub fn store(&self) -> &dyn MonitorStore {
        self.store.as_ref()
    }

    pub fn tick(&self, target: &WatchTarget, target_id: &str) -> TickReport {
        let state = self.store.get_state(target_id).unwrap_or_default();

        // Step 1: Check if revision changed
        let current = match self.source.current_revision() {
            Some(r) => r,
            None => {
                return TickReport {
                    revision: String::new(),
                    bundle_hash: String::new(),
                    new_findings: Vec::new(),
                    resolved_findings: Vec::new(),
                    persisting_findings: Vec::new(),
                    action_proposals: Vec::new(),
                    copilot_explanations: None,
                };
            }
        };

        if Some(&current.id) == state.last_revision.as_ref() {
            return TickReport {
                revision: current.id,
                bundle_hash: state.last_bundle_hash.unwrap_or_default(),
                new_findings: Vec::new(),
                resolved_findings: Vec::new(),
                persisting_findings: state.last_finding_ids.clone(),
                action_proposals: Vec::new(),
                copilot_explanations: None,
            };
        }

        // Step 2: Scan (deterministic engine-as-library)
        let findings_json = run_scan(&current);

        // Step 3: Ingest into EvidenceBundle
        let (findings, artifacts) =
            digger_evidence::ingest_scan_result(&findings_json, env!("CARGO_PKG_VERSION"));
        let mut builder = digger_evidence::BundleBuilder::new(
            digger_evidence::EngineVersion {
                semver: env!("CARGO_PKG_VERSION").into(),
                git_sha: "HEAD".into(),
            },
            digger_evidence::InputDescriptor {
                kind: "monitor".into(),
                value: target.target_descriptor.clone(),
            },
        )
        .tenant_id(&target.tenant_id);
        for f in findings {
            builder = builder.add_finding(f);
        }
        for a in artifacts {
            builder = builder.add_artifact(a);
        }
        let bundle = builder.build();

        let bundle_hash = bundle.bundle_hash.clone();
        let _ = self.evidence_store.save_bundle(&bundle);
        let new_finding_ids: Vec<String> = bundle
            .findings
            .iter()
            .map(|f| f.finding_id.clone())
            .collect();

        // Step 4: Finding diff
        let diff = diff_findings(&state.last_finding_ids, &new_finding_ids);

        // Step 5: Propose actions for new, unactioned findings
        let mut proposals = Vec::new();
        let mut new_actioned = state.already_actioned_finding_ids.clone();

        for fid in &diff.new_findings {
            if new_actioned.contains(fid) {
                continue;
            }

            // Always propose slack alert for new findings
            let slack_decision = self.gateway.evaluate(&digger_runtime::ActionRequest {
                action_id: uuid::Uuid::new_v4().to_string(),
                tenant_id: target.tenant_id.clone(),
                actor: Actor {
                    user_id: "monitor".into(),
                    agent_id: Some("digger-monitor".into()),
                    session_id: None,
                },
                action_type: ActionType::SlackPostMessage,
                target: ActionTarget::Channel {
                    channel: target.alert_channel.clone(),
                    workspace: None,
                },
                payload: serde_json::json!({
                    "finding_id": fid,
                    "bundle_hash": bundle_hash,
                    "revision": current.id,
                    "message": format!("New finding {} detected in {}", fid, target.target_descriptor),
                }),
                evidence_bundle_id: bundle.id.clone(),
                finding_ids: vec![fid.clone()],
                justification: "Automated monitor alert for new finding".into(),
                requested_at: now_str(),
            });

            let slack_proposal = ActionProposal {
                action_type: "slack.post_message".into(),
                finding_id: fid.clone(),
                policy_decision: slack_decision,
            };
            proposals.push(slack_proposal);

            // Execute slack immediately if allowed
            if let Some(slack_prop) = proposals.last() {
                if slack_prop.policy_decision.decision == Decision::Allow {
                    let _ = self.gateway.execute_allow(&digger_runtime::ActionRequest {
                        action_id: uuid::Uuid::new_v4().to_string(),
                        tenant_id: target.tenant_id.clone(),
                        actor: Actor {
                            user_id: "monitor".into(),
                            agent_id: Some("digger-monitor".into()),
                            session_id: None,
                        },
                        action_type: ActionType::SlackPostMessage,
                        target: ActionTarget::Channel {
                            channel: target.alert_channel.clone(),
                            workspace: None,
                        },
                        payload: serde_json::json!({
                            "finding_id": fid,
                            "message": format!("New finding {} detected", fid),
                        }),
                        evidence_bundle_id: bundle.id.clone(),
                        finding_ids: vec![fid.clone()],
                        justification: "Monitor alert".into(),
                        requested_at: now_str(),
                    });
                }
            }

            // Propose github.create_pr (will get require_approval per safe default)
            let gh_decision = self.gateway.evaluate(&digger_runtime::ActionRequest {
                action_id: uuid::Uuid::new_v4().to_string(),
                tenant_id: target.tenant_id.clone(),
                actor: Actor {
                    user_id: "monitor".into(),
                    agent_id: Some("digger-monitor".into()),
                    session_id: None,
                },
                action_type: ActionType::GithubCreatePr,
                target: ActionTarget::Repo {
                    repo: target.target_descriptor.clone(),
                    branch: current.id.clone(),
                },
                payload: serde_json::json!({
                    "finding_id": fid,
                    "bundle_hash": bundle_hash,
                }),
                evidence_bundle_id: bundle.id.clone(),
                finding_ids: vec![fid.clone()],
                justification: "Automated PR proposal for new finding".into(),
                requested_at: now_str(),
            });

            let gh_proposal = ActionProposal {
                action_type: "github.create_pr".into(),
                finding_id: fid.clone(),
                policy_decision: gh_decision,
            };
            proposals.push(gh_proposal);

            new_actioned.push(fid.clone());
        }

        // Step 6: Persist updated state
        let updated_state = MonitorState {
            last_revision: Some(current.id.clone()),
            last_bundle_hash: Some(bundle_hash.clone()),
            last_finding_ids: new_finding_ids.clone(),
            already_actioned_finding_ids: new_actioned,
        };
        let _ = self.store.save_state(target_id, &updated_state);

        // Step 7: Best-effort Copilot explanation for new findings
        let explanations = if let Some(copilot) = &self.copilot {
            if !diff.new_findings.is_empty() {
                let mut expls = Vec::new();
                for fid in &diff.new_findings {
                    let finding = bundle.findings.iter().find(|f| f.finding_id == *fid);
                    let rule_id = finding.map(|f| f.rule_id.as_str()).unwrap_or("unknown");
                    if let Some(record) = copilot.explain(fid, rule_id) {
                        expls.push(record);
                    }
                }
                if expls.is_empty() {
                    None
                } else {
                    Some(expls)
                }
            } else {
                None
            }
        } else {
            None
        };

        // Step 8: Return report
        TickReport {
            revision: current.id,
            bundle_hash,
            new_findings: diff.new_findings,
            resolved_findings: diff.resolved_findings,
            persisting_findings: diff.persisting_findings,
            action_proposals: proposals,
            copilot_explanations: explanations,
        }
    }
}

fn run_scan(revision: &Revision) -> serde_json::Value {
    let source_code = format!(
        "// scanned at revision {}\ncontract Monitor {{ uint256 x; }}",
        revision.id
    );
    let raw = digger_parser::parse_program(&source_code, "solidity");
    let mut findings = Vec::new();

    for f in digger_reconstruct::detect_price_manipulation(&source_code, &raw) {
        if !f.suppressed {
            findings.push(serde_json::json!({
                "detector": "price_manipulation",
                "function": f.function_name,
                "kind": "PriceOracleManipulation",
                "severity": "high",
                "confidence": "graduated",
            }));
        }
    }
    for f in digger_reconstruct::detect_readonly_reentrancy(&raw) {
        if !f.suppressed {
            findings.push(serde_json::json!({
                "detector": "readonly_reentrancy",
                "function": f.function_id,
                "kind": f.finding_kind,
                "severity": "high",
                "confidence": "graduated",
            }));
        }
    }

    serde_json::json!({
        "findings": findings,
        "source_provenance": "local source",
        "confidence": "mixed",
    })
}

fn now_str() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}", now)
}
