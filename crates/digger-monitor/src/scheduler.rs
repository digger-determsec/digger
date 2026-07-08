use digger_runtime::{ActionTarget, ActionType, Actor, Decision};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::clock::{Clock, Timestamp};
use crate::history::{DecisionRecord, MonitorHistoryStore, MonitorRunRecord};
use crate::monitor::Monitor;
use crate::source::MonitorSource;
use crate::state::WatchTarget;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetConfig {
    pub target: WatchTarget,
    pub poll_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantBudget {
    pub max_ticks_per_window: usize,
    pub window_secs: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct TargetRuntime {
    config: TargetConfig,
    pub(crate) next_due_at: Timestamp,
    backoff_level: u32,
    tick_count: usize,
    unresolved_age: BTreeMap<String, usize>,
    escalated: BTreeSet<String>,
}

pub struct Scheduler<S: MonitorSource> {
    monitor: Monitor<S>,
    clock: Arc<dyn Clock>,
    pub(crate) targets: BTreeMap<String, TargetRuntime>,
    budgets: BTreeMap<String, TenantBudget>,
    history: Arc<dyn MonitorHistoryStore>,
    target_ids: Vec<String>,
}

impl<S: MonitorSource> Scheduler<S> {
    pub fn new(
        monitor: Monitor<S>,
        clock: Arc<dyn Clock>,
        history: Arc<dyn MonitorHistoryStore>,
    ) -> Self {
        Self {
            monitor,
            clock,
            targets: BTreeMap::new(),
            budgets: BTreeMap::new(),
            history,
            target_ids: Vec::new(),
        }
    }

    pub fn register_target(&mut self, target_id: &str, config: TargetConfig) {
        let now = self.clock.now();
        self.targets.insert(
            target_id.to_string(),
            TargetRuntime {
                next_due_at: now,
                config,
                backoff_level: 0,
                tick_count: 0,
                unresolved_age: BTreeMap::new(),
                escalated: BTreeSet::new(),
            },
        );
        self.target_ids.push(target_id.to_string());
        self.target_ids.sort();
    }

    pub fn set_budget(&mut self, tenant_id: &str, budget: TenantBudget) {
        self.budgets.insert(tenant_id.to_string(), budget);
    }

    pub fn run_due(&mut self) -> SchedulerReport {
        let now = self.clock.now();
        let mut ran = Vec::new();
        let mut skipped_budget = Vec::new();
        let mut backed_off = Vec::new();

        let target_ids: Vec<String> = self.target_ids.clone();

        for target_id in &target_ids {
            // Phase 1: Read (immutable borrow)
            let (is_due, tenant_id, poll_interval, target_clone) = {
                let runtime = match self.targets.get(target_id) {
                    Some(r) => r,
                    None => continue,
                };
                let tenant_id = runtime.config.target.tenant_id.clone();
                let poll_interval = runtime.config.poll_interval_secs;
                let is_due = runtime.next_due_at <= now;
                let target_clone = runtime.config.target.clone();
                (is_due, tenant_id, poll_interval, target_clone)
            };

            if !is_due {
                continue;
            }

            // Check budget (needs only history, not targets)
            if let Some(budget) = self.budgets.get(&tenant_id) {
                let window_start = now.saturating_sub(budget.window_secs);
                let recent_count = self
                    .history
                    .list_by_tenant(&tenant_id)
                    .iter()
                    .filter(|r| r.ran_at >= window_start)
                    .count();
                if recent_count >= budget.max_ticks_per_window {
                    skipped_budget.push(target_id.clone());
                    continue;
                }
            }

            // Run tick
            let report_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.monitor.tick(&target_clone, target_id)
            }));

            match report_result {
                Ok(report) => {
                    let has_denials = report
                        .action_proposals
                        .iter()
                        .any(|p| p.policy_decision.decision == Decision::Deny);

                    let record = MonitorRunRecord {
                        target_id: target_id.clone(),
                        tenant_id: tenant_id.clone(),
                        ran_at: now,
                        revision: report.revision.clone(),
                        bundle_hash: report.bundle_hash.clone(),
                        new_findings_count: report.new_findings.len(),
                        resolved_findings_count: report.resolved_findings.len(),
                        persisting_findings_count: report.persisting_findings.len(),
                        decisions: report
                            .action_proposals
                            .iter()
                            .map(|p| DecisionRecord {
                                action_type: p.action_type.clone(),
                                finding_id: p.finding_id.clone(),
                                decision: format!("{:?}", p.policy_decision.decision),
                            })
                            .collect(),
                        error: has_denials.then(|| "some actions denied".into()),
                        explanations: report.copilot_explanations.clone(),
                    };
                    self.history.append(&record);

                    // Update runtime state
                    if let Some(runtime) = self.targets.get_mut(target_id) {
                        runtime.next_due_at = now + poll_interval;
                        runtime.backoff_level = 0;
                        runtime.tick_count += 1;

                        let state = self
                            .monitor
                            .store()
                            .get_state(target_id)
                            .unwrap_or_default();
                        for fid in &state.last_finding_ids {
                            *runtime.unresolved_age.entry(fid.clone()).or_insert(0) += 1;
                        }
                        for fid in &report.resolved_findings {
                            runtime.unresolved_age.remove(fid);
                            runtime.escalated.remove(fid);
                        }
                    }

                    // Escalation check
                    self.check_escalations(target_id, &tenant_id, now);

                    ran.push(target_id.clone());
                }
                Err(_) => {
                    if let Some(runtime) = self.targets.get_mut(target_id) {
                        runtime.backoff_level = (runtime.backoff_level + 1).min(5);
                        let backoff_secs = 2u64.pow(runtime.backoff_level) * poll_interval;
                        runtime.next_due_at = now + backoff_secs;
                    }
                    backed_off.push(target_id.clone());

                    self.history.append(&MonitorRunRecord {
                        target_id: target_id.clone(),
                        tenant_id: tenant_id.clone(),
                        ran_at: now,
                        revision: String::new(),
                        bundle_hash: String::new(),
                        new_findings_count: 0,
                        resolved_findings_count: 0,
                        persisting_findings_count: 0,
                        decisions: Vec::new(),
                        error: Some("tick panicked".into()),
                        explanations: None,
                    });
                }
            }
        }

        SchedulerReport {
            ran,
            skipped_due_to_budget: skipped_budget,
            backed_off,
        }
    }

    fn check_escalations(&mut self, target_id: &str, tenant_id: &str, now: Timestamp) {
        let threshold = 5usize;

        let findings_to_escalate: Vec<String> = {
            match self.targets.get(target_id) {
                Some(r) => r
                    .unresolved_age
                    .iter()
                    .filter(|(fid, age)| **age >= threshold && !r.escalated.contains(fid.as_str()))
                    .map(|(fid, _)| fid.clone())
                    .collect(),
                None => return,
            }
        };

        for finding_id in findings_to_escalate {
            if let Some(runtime) = self.targets.get_mut(target_id) {
                runtime.escalated.insert(finding_id.clone());
            }

            let state = self
                .monitor
                .store()
                .get_state(target_id)
                .unwrap_or_default();
            let bundle_hash = state.last_bundle_hash.clone().unwrap_or_default();
            let channel = self
                .targets
                .get(target_id)
                .map(|r| r.config.target.alert_channel.clone())
                .unwrap_or_default();

            let decision = self
                .monitor
                .gateway()
                .evaluate(&digger_runtime::ActionRequest {
                    action_id: uuid::Uuid::new_v4().to_string(),
                    tenant_id: tenant_id.to_string(),
                    actor: Actor {
                        user_id: "scheduler".into(),
                        agent_id: Some("digger-scheduler".into()),
                        session_id: None,
                    },
                    action_type: ActionType::SlackPostMessage,
                    target: ActionTarget::Channel {
                        channel: format!("{}-escalation", channel),
                        workspace: None,
                    },
                    payload: serde_json::json!({"finding_id": finding_id, "escalation": true}),
                    evidence_bundle_id: bundle_hash.clone(),
                    finding_ids: vec![finding_id.clone()],
                    justification: "Escalation: finding persisted unactioned".into(),
                    requested_at: format!("{}", now),
                });

            self.history.append(&MonitorRunRecord {
                target_id: target_id.to_string(),
                tenant_id: tenant_id.to_string(),
                ran_at: now,
                revision: state.last_revision.clone().unwrap_or_default(),
                bundle_hash: bundle_hash.clone(),
                new_findings_count: 0,
                resolved_findings_count: 0,
                persisting_findings_count: 0,
                decisions: vec![DecisionRecord {
                    action_type: "escalation".into(),
                    finding_id,
                    decision: format!("{:?}", decision.decision),
                }],
                error: None,
                explanations: None,
            });

            if decision.decision == Decision::Allow {
                let _ = self
                    .monitor
                    .gateway()
                    .execute_allow(&digger_runtime::ActionRequest {
                        action_id: uuid::Uuid::new_v4().to_string(),
                        tenant_id: tenant_id.to_string(),
                        actor: Actor {
                            user_id: "scheduler".into(),
                            agent_id: Some("digger-scheduler".into()),
                            session_id: None,
                        },
                        action_type: ActionType::SlackPostMessage,
                        target: ActionTarget::Channel {
                            channel: format!("{}-escalation", channel),
                            workspace: None,
                        },
                        payload: serde_json::json!({"escalation": true}),
                        evidence_bundle_id: bundle_hash,
                        finding_ids: vec![],
                        justification: "Escalation".into(),
                        requested_at: format!("{}", now),
                    });
            }
        }
    }

    pub fn history(&self) -> &dyn MonitorHistoryStore {
        self.history.as_ref()
    }

    pub(crate) fn targets(&self) -> &BTreeMap<String, TargetRuntime> {
        &self.targets
    }

    pub fn clock_now(&self) -> Timestamp {
        self.clock.now()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchedulerReport {
    pub ran: Vec<String>,
    pub skipped_due_to_budget: Vec<String>,
    pub backed_off: Vec<String>,
}
