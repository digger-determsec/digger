use crate::history::FindingExplanationRecord;

/// Minimal synchronous copilot trait for the monitor to call.
/// Returns Some(explanation) if the copilot can explain, None on error.
pub trait MonitorCopilot: Send + Sync {
    fn explain(&self, finding_id: &str, rule_id: &str) -> Option<FindingExplanationRecord>;
}
