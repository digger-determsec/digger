#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod clock;
pub mod copilot_bridge;
pub mod daemon;
pub mod history;
pub mod monitor;
pub mod onchain;
pub mod scheduler;
pub mod source;
pub mod state;
pub mod store;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, MockClock};
    use crate::history::MonitorHistoryStore;
    use crate::scheduler::{Scheduler, TargetConfig, TenantBudget};
    use crate::source::{MockMonitorSource, Revision};
    use crate::state::{MonitorState, WatchTarget};
    use crate::store::MonitorStore;
    use digger_runtime::{ActionTarget, ActionType, Actor, Decision, Policy};
    use std::sync::Arc;

    fn target(id: &str, channel: &str) -> WatchTarget {
        WatchTarget {
            tenant_id: "t1".into(),
            target_descriptor: format!("org/{}", id),
            alert_channel: channel.into(),
        }
    }

    fn make_gw() -> Arc<digger_runtime::ActionGateway> {
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let audit = Arc::new(digger_runtime::InMemoryAuditStore::new());
        let approvals = Arc::new(digger_runtime::ApprovalService::new(3600));
        let broker = Arc::new(digger_runtime::CredentialBroker::new(300));
        Arc::new(digger_runtime::ActionGateway::new(
            Policy::default(),
            evidence,
            audit,
            approvals,
            broker,
            std::collections::BTreeMap::new(),
        ))
    }

    fn rev(id: &str) -> Revision {
        Revision {
            id: id.into(),
            content_hash: format!("h-{}", id),
        }
    }

    fn make_daemon(
        revisions: Vec<crate::source::Revision>,
    ) -> crate::daemon::MonitorDaemon<crate::source::MockMonitorSource> {
        let clock = Arc::new(crate::clock::MockClock::new(0));
        let source = crate::source::MockMonitorSource::new(revisions);
        let store = Arc::new(store::InMemoryMonitorStore::new());
        let gw = make_gw();
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let history = Arc::new(history::InMemoryHistoryStore::new());
        let mon = monitor::Monitor::new(source, store, gw, evidence);
        crate::daemon::MonitorDaemon::new(mon, clock, history)
    }

    // ── Clock ──
    #[test]
    fn test_mock_clock_advance() {
        let mut clock = MockClock::new(1000);
        assert_eq!(clock.now(), 1000);
        clock.advance(300);
        assert_eq!(clock.now(), 1300);
    }

    // ── Monitor tick ──
    #[test]
    fn test_monitor_tick_noop_same_revision() {
        let source = MockMonitorSource::new(vec![rev("r1")]);
        let store = Arc::new(store::InMemoryMonitorStore::new());
        let gw = make_gw();
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let mon = monitor::Monitor::new(source, store, gw, evidence);
        let t = target("repo", "#alerts");
        let r1 = mon.tick(&t, "t1");
        assert_eq!(r1.revision, "r1");
        let r2 = mon.tick(&t, "t1");
        assert!(r2.new_findings.is_empty());
    }

    // ── Scheduler ──
    #[test]
    fn test_target_not_due() {
        let clock = Arc::new(MockClock::new(0));
        let source = MockMonitorSource::new(vec![]);
        let store = Arc::new(store::InMemoryMonitorStore::new());
        let gw = make_gw();
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let history = Arc::new(history::InMemoryHistoryStore::new());
        let mon = monitor::Monitor::new(source, store, gw, evidence);
        let mut sched = Scheduler::new(mon, clock, history);
        sched.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 100,
            },
        );
        sched.targets.get_mut("t1").unwrap().next_due_at = 200;
        assert!(sched.run_due().ran.is_empty());
    }

    #[test]
    fn test_target_due_runs() {
        let clock = Arc::new(MockClock::new(0));
        let source = MockMonitorSource::new(vec![rev("r1")]);
        let store = Arc::new(store::InMemoryMonitorStore::new());
        let gw = make_gw();
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let history = Arc::new(history::InMemoryHistoryStore::new());
        let mon = monitor::Monitor::new(source, store, gw, evidence);
        let mut sched = Scheduler::new(mon, clock, history);
        sched.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 60,
            },
        );
        assert_eq!(sched.run_due().ran.len(), 1);
    }

    #[test]
    fn test_budget_skips_when_over() {
        let clock = Arc::new(MockClock::new(0));
        let source = MockMonitorSource::new(vec![rev("r1")]);
        let store = Arc::new(store::InMemoryMonitorStore::new());
        let gw = make_gw();
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let history = Arc::new(history::InMemoryHistoryStore::new());
        let mon = monitor::Monitor::new(source, store, gw, evidence);
        let mut sched = Scheduler::new(mon, clock, history);
        sched.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 1,
            },
        );
        sched.set_budget(
            "t1",
            TenantBudget {
                max_ticks_per_window: 1,
                window_secs: 3600,
            },
        );
        assert_eq!(sched.run_due().ran.len(), 1);
        sched.targets.get_mut("t1").unwrap().next_due_at = 0;
        assert_eq!(sched.run_due().skipped_due_to_budget.len(), 1);
    }

    #[test]
    fn test_history_records_tick() {
        let clock = Arc::new(MockClock::new(0));
        let source = MockMonitorSource::new(vec![rev("r1")]);
        let store = Arc::new(store::InMemoryMonitorStore::new());
        let gw = make_gw();
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let history = Arc::new(history::InMemoryHistoryStore::new());
        let mon = monitor::Monitor::new(source, store, gw, evidence);
        let mut sched = Scheduler::new(mon, clock, history.clone());
        sched.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 60,
            },
        );
        let _ = sched.run_due();
        assert_eq!(history.list_by_target("t1").len(), 1);
    }

    #[test]
    fn test_deterministic_ordering() {
        let clock = Arc::new(MockClock::new(0));
        let history = Arc::new(history::InMemoryHistoryStore::new());
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let make = || {
            monitor::Monitor::new(
                MockMonitorSource::new(vec![rev("r1"), rev("r1")]),
                Arc::new(store::InMemoryMonitorStore::new()),
                make_gw(),
                evidence.clone(),
            )
        };
        let mut sched = Scheduler::new(make(), clock, history);
        sched.register_target(
            "z_target",
            TargetConfig {
                target: target("z", "#a"),
                poll_interval_secs: 1,
            },
        );
        sched.register_target(
            "a_target",
            TargetConfig {
                target: target("a", "#b"),
                poll_interval_secs: 1,
            },
        );
        let r = sched.run_due();
        assert_eq!(r.ran[0], "a_target");
        assert_eq!(r.ran[1], "z_target");
    }

    // ── FindingDiff ──
    #[test]
    fn test_finding_diff() {
        let d = state::diff_findings(&["f1".into(), "f2".into()], &["f2".into(), "f3".into()]);
        assert!(d.new_findings.contains(&"f3".into()));
        assert!(d.resolved_findings.contains(&"f1".into()));
        assert!(d.persisting_findings.contains(&"f2".into()));
    }

    #[test]
    fn test_finding_diff_empty() {
        assert!(state::diff_findings(&[], &[]).new_findings.is_empty());
    }

    // ── State ──
    #[test]
    fn test_state_persist() {
        let s = Arc::new(store::InMemoryMonitorStore::new());
        let state = MonitorState {
            last_revision: Some("r1".into()),
            ..Default::default()
        };
        s.save_state("t1", &state).unwrap();
        assert_eq!(s.get_state("t1").unwrap().last_revision, Some("r1".into()));
    }

    // ── Gateway bypass ──
    #[test]
    fn test_cannot_bypass() {
        let evidence = Arc::new(digger_evidence::InMemoryStore::new());
        let gw = Arc::new(digger_runtime::ActionGateway::new(
            Policy::default(),
            evidence,
            Arc::new(digger_runtime::InMemoryAuditStore::new()),
            Arc::new(digger_runtime::ApprovalService::new(3600)),
            Arc::new(digger_runtime::CredentialBroker::new(300)),
            std::collections::BTreeMap::new(),
        ));
        let bad = digger_runtime::ActionRequest {
            action_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: "t1".into(),
            actor: Actor {
                user_id: "evil".into(),
                agent_id: None,
                session_id: None,
            },
            action_type: ActionType::SlackPostMessage,
            target: ActionTarget::Channel {
                channel: "#x".into(),
                workspace: None,
            },
            payload: serde_json::json!({}),
            evidence_bundle_id: "nope".into(),
            finding_ids: vec!["f1".into()],
            justification: "x".into(),
            requested_at: "2026-01-01".into(),
        };
        assert_eq!(gw.evaluate(&bad).decision, Decision::Deny);
    }

    // ── Daemon ──
    #[test]
    fn test_daemon_run_once() {
        let mut d = make_daemon(vec![rev("r1")]);
        d.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 60,
            },
        );
        assert_eq!(d.run_once().ran.len(), 1);
    }

    #[test]
    fn test_daemon_not_due() {
        let mut d = make_daemon(vec![]);
        d.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 60,
            },
        );
        d.scheduler_mut().targets.get_mut("t1").unwrap().next_due_at = 999;
        assert!(d.run_once().ran.is_empty());
    }

    #[test]
    fn test_daemon_determinism() {
        let mut d1 = make_daemon(vec![rev("r1")]);
        d1.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 60,
            },
        );
        let mut d2 = make_daemon(vec![rev("r1")]);
        d2.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 60,
            },
        );
        let s1 = d1.run_once();
        let s2 = d2.run_once();
        assert_eq!(s1.ran, s2.ran);
        assert_eq!(s1.tick_time, s2.tick_time);
    }

    // ── Onchain ──
    #[test]
    fn test_chain_state_hash() {
        let s = onchain::ChainState::Evm(onchain::EvmState {
            address: "0x1".into(),
            code_hash: "0x1".into(),
            implementation_address: None,
            admin: None,
        });
        assert_eq!(s.canonical_hash(), s.canonical_hash());
    }

    #[test]
    fn test_chain_state_changes() {
        let old = onchain::ChainState::Evm(onchain::EvmState {
            address: "0x1".into(),
            code_hash: "0x1".into(),
            implementation_address: Some("0xa".into()),
            admin: None,
        });
        let new = onchain::ChainState::Evm(onchain::EvmState {
            address: "0x1".into(),
            code_hash: "0x2".into(),
            implementation_address: Some("0xb".into()),
            admin: None,
        });
        assert_eq!(onchain::detect_state_changes(&old, &new).len(), 2);
    }

    // ── C41: Copilot ──

    struct MockCopilot {
        response: Option<crate::history::FindingExplanationRecord>,
    }

    impl MockCopilot {
        fn available() -> Self {
            Self {
                response: Some(crate::history::FindingExplanationRecord {
                    finding_id: "any".into(),
                    rule_id: "any".into(),
                    explanation: "mock".into(),
                    disclaimer: "grounded in deterministic finding".into(),
                    precedent_titles: vec!["bZx".into()],
                }),
            }
        }
        fn unavailable() -> Self {
            Self { response: None }
        }
    }

    impl crate::copilot_bridge::MonitorCopilot for MockCopilot {
        fn explain(
            &self,
            finding_id: &str,
            rule_id: &str,
        ) -> Option<crate::history::FindingExplanationRecord> {
            self.response
                .as_ref()
                .map(|r| crate::history::FindingExplanationRecord {
                    finding_id: finding_id.into(),
                    rule_id: rule_id.into(),
                    explanation: r.explanation.clone(),
                    disclaimer: r.disclaimer.clone(),
                    precedent_titles: r.precedent_titles.clone(),
                })
        }
    }

    #[test]
    fn test_no_copilot_tick_ok() {
        let mut d = make_daemon(vec![rev("r1")]);
        d.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 60,
            },
        );
        assert!(d.run_once().ran.len() <= 1);
    }

    #[test]
    fn test_copilot_set_tick_ok() {
        let copilot = Arc::new(MockCopilot::available());
        let mon = monitor::Monitor::new(
            MockMonitorSource::new(vec![rev("r1")]),
            Arc::new(store::InMemoryMonitorStore::new()),
            make_gw(),
            Arc::new(digger_evidence::InMemoryStore::new()),
        )
        .with_copilot(copilot);
        let r = mon.tick(&target("r", "#a"), "t1");
        assert!(r.revision.starts_with("r1"));
    }

    #[test]
    fn test_copilot_failure_no_break() {
        let copilot = Arc::new(MockCopilot::unavailable());
        let mon = monitor::Monitor::new(
            MockMonitorSource::new(vec![rev("r1")]),
            Arc::new(store::InMemoryMonitorStore::new()),
            make_gw(),
            Arc::new(digger_evidence::InMemoryStore::new()),
        )
        .with_copilot(copilot);
        let mut sched = Scheduler::new(
            mon,
            Arc::new(MockClock::new(0)),
            Arc::new(history::InMemoryHistoryStore::new()),
        );
        sched.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 60,
            },
        );
        assert!(!sched.run_due().ran.is_empty());
    }

    #[test]
    fn test_copilot_with_scheduler() {
        let copilot = Arc::new(MockCopilot::available());
        let mon = monitor::Monitor::new(
            MockMonitorSource::new(vec![rev("r1")]),
            Arc::new(store::InMemoryMonitorStore::new()),
            make_gw(),
            Arc::new(digger_evidence::InMemoryStore::new()),
        )
        .with_copilot(copilot);
        let h = Arc::new(history::InMemoryHistoryStore::new());
        let mut sched = Scheduler::new(mon, Arc::new(MockClock::new(0)), h.clone());
        sched.register_target(
            "t1",
            TargetConfig {
                target: target("r", "#a"),
                poll_interval_secs: 60,
            },
        );
        let _ = sched.run_due();
        assert_eq!(h.list_by_target("t1").len(), 1);
    }
}
