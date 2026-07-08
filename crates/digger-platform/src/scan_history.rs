use crate::models::*;
/// Persistent scan history — record every scan with metadata, status, inputs, outputs.
use crate::models::{iso_to_epoch_secs, now_iso};
use crate::storage::{Storage, StorageError};
use uuid::Uuid;

pub struct ScanHistoryManager<'a> {
    store: &'a dyn Storage,
}

impl<'a> ScanHistoryManager<'a> {
    pub fn new(store: &'a dyn Storage) -> Self {
        Self { store }
    }

    pub fn create(
        &self,
        project_id: &str,
        org_id: &str,
        language: &str,
        code: &str,
    ) -> Result<ScanRecord, StorageError> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        code.hash(&mut hasher);
        let code_hash = format!("{:x}", hasher.finish());
        let now = now_iso();
        let preview = if code.len() > 200 {
            // Floor to 200 bytes on a valid char boundary
            let mut end = 200;
            while end > 0 && !code.is_char_boundary(end) {
                end -= 1;
            }
            code[..end].to_string()
        } else {
            code.to_string()
        };

        let record = ScanRecord {
            id: Uuid::new_v4().to_string(),
            project_id: project_id.to_string(),
            org_id: org_id.to_string(),
            status: ScanStatus::Queued,
            language: language.to_string(),
            code_hash,
            input_preview: preview,
            hypothesis_count: 0,
            findings_count: 0,
            execution_count: 0,
            error: None,
            created_at: now.clone(),
            started_at: None,
            completed_at: None,
            duration_ms: None,
            report_id: None,
            artifacts: vec![],
        };
        let val = serde_json::to_value(&record)?;
        self.store.write_json("scans", &record.id, &val)?;
        Ok(record)
    }

    pub fn get(&self, id: &str) -> Result<ScanRecord, StorageError> {
        let val = self.store.read_json("scans", id)?;
        Ok(serde_json::from_value(val)?)
    }

    pub fn list_for_project(&self, project_id: &str, limit: usize) -> Vec<ScanRecord> {
        let mut scans: Vec<ScanRecord> = self
            .store
            .list_all_json("scans")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<ScanRecord>(v).ok())
            .filter(|s| s.project_id == project_id)
            .collect();
        scans.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        scans.truncate(limit);
        scans
    }

    pub fn list_for_org(&self, org_id: &str, limit: usize) -> Vec<ScanRecord> {
        let mut scans: Vec<ScanRecord> = self
            .store
            .list_all_json("scans")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<ScanRecord>(v).ok())
            .filter(|s| s.org_id == org_id)
            .collect();
        scans.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        scans.truncate(limit);
        scans
    }

    pub fn update_status(&self, id: &str, status: ScanStatus) -> Result<ScanRecord, StorageError> {
        let mut record = self.get(id)?;
        match &status {
            ScanStatus::Running => {
                record.started_at = Some(now_iso());
            }
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled => {
                record.completed_at = Some(now_iso());
                if let (Some(started), Some(completed)) = (&record.started_at, &record.completed_at)
                {
                    let s = iso_to_epoch_secs(started);
                    let c = iso_to_epoch_secs(completed);
                    record.duration_ms = Some((c.saturating_sub(s)) * 1000);
                }
            }
            _ => {}
        }
        record.status = status;
        let val = serde_json::to_value(&record)?;
        self.store.write_json("scans", &record.id, &val)?;
        Ok(record)
    }

    pub fn update_results(
        &self,
        id: &str,
        hypotheses: usize,
        findings: usize,
        executions: usize,
        report_id: &str,
        artifacts: Vec<String>,
    ) -> Result<ScanRecord, StorageError> {
        let mut record = self.get(id)?;
        record.hypothesis_count = hypotheses;
        record.findings_count = findings;
        record.execution_count = executions;
        record.report_id = Some(report_id.to_string());
        record.artifacts = artifacts;
        let val = serde_json::to_value(&record)?;
        self.store.write_json("scans", &record.id, &val)?;
        Ok(record)
    }

    pub fn compare(&self, id_a: &str, id_b: &str) -> Result<ScanComparison, StorageError> {
        if id_a == id_b {
            return Err(format!(
                "cannot compare scan '{}' with itself (same ID provided)",
                id_a
            )
            .into());
        }
        let a = self.get(id_a)?;
        let b = self.get(id_b)?;
        Ok(ScanComparison {
            scan_a_id: a.id.clone(),
            scan_b_id: b.id.clone(),
            hypothesis_diff: b.hypothesis_count as i64 - a.hypothesis_count as i64,
            findings_diff: b.findings_count as i64 - a.findings_count as i64,
            execution_diff: b.execution_count as i64 - a.execution_count as i64,
            same_code: a.code_hash == b.code_hash,
            same_language: a.language == b.language,
        })
    }

    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        self.store.delete("scans", id)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanComparison {
    pub scan_a_id: String,
    pub scan_b_id: String,
    pub hypothesis_diff: i64,
    pub findings_diff: i64,
    pub execution_diff: i64,
    pub same_code: bool,
    pub same_language: bool,
}
