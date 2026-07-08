use crate::clock::Clock;
use crate::history::MonitorHistoryStore;
use crate::monitor::Monitor;
use crate::scheduler::{Scheduler, TargetConfig};
use crate::source::MonitorSource;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonTickSummary {
    pub ran: Vec<String>,
    pub skipped_due_to_budget: Vec<String>,
    pub backed_off: Vec<String>,
    pub tick_time: u64,
    pub next_wake_in_secs: u64,
}

pub struct MonitorDaemon<S: MonitorSource + 'static> {
    scheduler: Scheduler<S>,
}

impl<S: MonitorSource + 'static> MonitorDaemon<S> {
    pub fn new(
        monitor: Monitor<S>,
        clock: Arc<dyn Clock>,
        history: Arc<dyn MonitorHistoryStore>,
    ) -> Self {
        Self {
            scheduler: Scheduler::new(monitor, clock, history),
        }
    }

    pub fn register_target(&mut self, target_id: &str, config: TargetConfig) {
        self.scheduler.register_target(target_id, config);
    }

    pub fn scheduler(&self) -> &Scheduler<S> {
        &self.scheduler
    }

    pub fn scheduler_mut(&mut self) -> &mut Scheduler<S> {
        &mut self.scheduler
    }

    pub fn run_once(&mut self) -> DaemonTickSummary {
        let report = self.scheduler.run_due();
        let now = self.scheduler.clock_now();
        let next_wake = self
            .scheduler
            .targets()
            .values()
            .map(|t| {
                if t.next_due_at > now {
                    t.next_due_at.saturating_sub(now)
                } else {
                    0
                }
            })
            .min()
            .unwrap_or(300);

        DaemonTickSummary {
            ran: report.ran,
            skipped_due_to_budget: report.skipped_due_to_budget,
            backed_off: report.backed_off,
            tick_time: now,
            next_wake_in_secs: next_wake.min(300),
        }
    }
}
