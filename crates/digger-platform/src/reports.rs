/// Versioned reports — immutable, traceable, diffable.
use crate::models::now_iso;
use crate::models::*;
use crate::storage::{Storage, StorageError};
use uuid::Uuid;

pub struct ReportManager<'a> {
    store: &'a dyn Storage,
}

impl<'a> ReportManager<'a> {
    pub fn new(store: &'a dyn Storage) -> Self {
        Self { store }
    }

    pub fn create(
        &self,
        project_id: &str,
        org_id: &str,
        scan_id: &str,
        report_type: ReportType,
        content: serde_json::Value,
    ) -> Result<Report, StorageError> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let content_str = serde_json::to_string(&content)?;
        let mut hasher = DefaultHasher::new();
        content_str.hash(&mut hasher);
        let content_hash = format!("{:x}", hasher.finish());

        let existing = self.list_for_scan(scan_id);
        let version = (existing.len() as u32) + 1;
        let previous_version = existing.last().map(|r| r.id.clone());

        let report = Report {
            id: Uuid::new_v4().to_string(),
            project_id: project_id.to_string(),
            org_id: org_id.to_string(),
            scan_id: scan_id.to_string(),
            version,
            report_type,
            content,
            content_hash,
            previous_version,
            created_at: now_iso(),
        };
        let val = serde_json::to_value(&report)?;
        self.store.write_json("reports", &report.id, &val)?;
        Ok(report)
    }

    pub fn get(&self, id: &str) -> Result<Report, StorageError> {
        let val = self.store.read_json("reports", id)?;
        Ok(serde_json::from_value(val)?)
    }

    pub fn list_for_scan(&self, scan_id: &str) -> Vec<Report> {
        let mut reports: Vec<Report> = self
            .store
            .list_all_json("reports")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Report>(v).ok())
            .filter(|r| r.scan_id == scan_id)
            .collect();
        reports.sort_by_key(|r| r.version);
        reports
    }

    pub fn list_for_project(&self, project_id: &str, limit: usize) -> Vec<Report> {
        let mut reports: Vec<Report> = self
            .store
            .list_all_json("reports")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Report>(v).ok())
            .filter(|r| r.project_id == project_id)
            .collect();
        reports.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        reports.truncate(limit);
        reports
    }

    pub fn diff(&self, id_a: &str, id_b: &str) -> Result<ReportDiff, StorageError> {
        if id_a == id_b {
            return Err(format!(
                "cannot diff report '{}' with itself (same ID provided)",
                id_a
            )
            .into());
        }
        let a = self.get(id_a)?;
        let b = self.get(id_b)?;
        let a_keys = collect_json_keys(&a.content);
        let b_keys = collect_json_keys(&b.content);
        let added: Vec<String> = b_keys
            .iter()
            .filter(|k| !a_keys.contains(k))
            .cloned()
            .collect();
        let removed: Vec<String> = a_keys
            .iter()
            .filter(|k| !b_keys.contains(k))
            .cloned()
            .collect();

        Ok(ReportDiff {
            report_a_id: a.id.clone(),
            report_b_id: b.id.clone(),
            version_a: a.version,
            version_b: b.version,
            same_content: a.content_hash == b.content_hash,
            same_type: a.report_type == b.report_type,
            content_a_size: serde_json::to_string(&a.content).unwrap_or_default().len(),
            content_b_size: serde_json::to_string(&b.content).unwrap_or_default().len(),
            keys_added: added.len(),
            keys_removed: removed.len(),
            added_keys: added,
            removed_keys: removed,
        })
    }

    pub fn trace_lineage(&self, id: &str) -> Result<Vec<Report>, StorageError> {
        use std::collections::HashSet;
        let mut lineage = Vec::new();
        let mut visited = HashSet::new();
        let mut current = self.get(id)?;
        if !visited.insert(current.id.clone()) {
            return Ok(lineage);
        }
        lineage.push(current.clone());
        while let Some(prev_id) = &current.previous_version {
            if !visited.insert(prev_id.clone()) {
                break;
            }
            match self.get(prev_id) {
                Ok(prev) => {
                    current = prev;
                    lineage.push(current.clone());
                }
                Err(_) => break,
            }
        }
        lineage.reverse();
        Ok(lineage)
    }

    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        self.store.delete("reports", id)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportDiff {
    pub report_a_id: String,
    pub report_b_id: String,
    pub version_a: u32,
    pub version_b: u32,
    pub same_content: bool,
    pub same_type: bool,
    pub content_a_size: usize,
    pub content_b_size: usize,
    pub keys_added: usize,
    pub keys_removed: usize,
    pub added_keys: Vec<String>,
    pub removed_keys: Vec<String>,
}

fn collect_json_keys(val: &serde_json::Value) -> Vec<String> {
    match val {
        serde_json::Value::Object(map) => map.keys().cloned().collect(),
        _ => vec![],
    }
}
