use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitorRunRecord {
    pub target_id: String,
    pub tenant_id: String,
    pub ran_at: u64,
    pub revision: String,
    pub bundle_hash: String,
    pub new_findings_count: usize,
    pub resolved_findings_count: usize,
    pub persisting_findings_count: usize,
    pub decisions: Vec<DecisionRecord>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanations: Option<Vec<FindingExplanationRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingExplanationRecord {
    pub finding_id: String,
    pub rule_id: String,
    pub explanation: String,
    pub disclaimer: String,
    pub precedent_titles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionRecord {
    pub action_type: String,
    pub finding_id: String,
    pub decision: String,
}

pub trait MonitorHistoryStore: Send + Sync {
    fn append(&self, record: &MonitorRunRecord);
    fn list_by_target(&self, target_id: &str) -> Vec<MonitorRunRecord>;
    fn list_by_tenant(&self, tenant_id: &str) -> Vec<MonitorRunRecord>;
}

pub struct InMemoryHistoryStore {
    records: std::sync::Mutex<BTreeMap<String, Vec<MonitorRunRecord>>>,
}

impl InMemoryHistoryStore {
    pub fn new() -> Self {
        Self {
            records: std::sync::Mutex::new(BTreeMap::new()),
        }
    }
}

impl Default for InMemoryHistoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorHistoryStore for InMemoryHistoryStore {
    fn append(&self, record: &MonitorRunRecord) {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        records
            .entry(record.tenant_id.clone())
            .or_default()
            .push(record.clone());
    }

    fn list_by_target(&self, target_id: &str) -> Vec<MonitorRunRecord> {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        records
            .values()
            .flat_map(|v| v.iter())
            .filter(|r| r.target_id == target_id)
            .cloned()
            .collect()
    }

    fn list_by_tenant(&self, tenant_id: &str) -> Vec<MonitorRunRecord> {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        records.get(tenant_id).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(target: &str, tenant: &str) -> MonitorRunRecord {
        MonitorRunRecord {
            target_id: target.to_string(),
            tenant_id: tenant.to_string(),
            ran_at: 1,
            revision: "r1".to_string(),
            bundle_hash: "h1".to_string(),
            new_findings_count: 0,
            resolved_findings_count: 0,
            persisting_findings_count: 0,
            decisions: Vec::new(),
            error: None,
            explanations: None,
        }
    }

    #[test]
    fn history_recovers_from_poisoned_mutex() {
        let store = InMemoryHistoryStore::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.records.lock().unwrap();
            panic!("intentional poison");
        }));
        assert!(result.is_err());
        assert!(store.records.is_poisoned());

        store.append(&rec("tgt", "tenant"));
        assert_eq!(store.list_by_tenant("tenant").len(), 1);
        assert_eq!(store.list_by_target("tgt").len(), 1);
        assert!(store.list_by_tenant("missing").is_empty());
    }
}
