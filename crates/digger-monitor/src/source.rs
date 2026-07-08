use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Revision {
    pub id: String,
    pub content_hash: String,
}

pub trait MonitorSource: Send + Sync {
    fn current_revision(&self) -> Option<Revision>;
}

pub struct MockMonitorSource {
    revisions: VecDeque<Revision>,
}

impl MockMonitorSource {
    pub fn new(revisions: Vec<Revision>) -> Self {
        Self {
            revisions: revisions.into(),
        }
    }
}

impl MonitorSource for MockMonitorSource {
    fn current_revision(&self) -> Option<Revision> {
        self.revisions.front().cloned()
    }
}

impl MockMonitorSource {
    pub fn advance(&mut self) {
        self.revisions.pop_front();
    }
}
