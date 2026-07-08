/// Persistent job system — replace in-memory jobs with storage backend.
use crate::models::now_iso;
use crate::models::*;
use crate::storage::{Storage, StorageError};
use uuid::Uuid;

pub struct JobManager<'a> {
    store: &'a dyn Storage,
}

impl<'a> JobManager<'a> {
    pub fn new(store: &'a dyn Storage) -> Self {
        Self { store }
    }

    pub fn create(
        &self,
        org_id: &str,
        project_id: &str,
        kind: JobKind,
        input: serde_json::Value,
    ) -> Result<PersistentJob, StorageError> {
        let now = now_iso();
        let job = PersistentJob {
            id: Uuid::new_v4().to_string(),
            org_id: org_id.to_string(),
            project_id: project_id.to_string(),
            kind,
            status: JobStatus::Queued,
            progress: 0.0,
            input,
            result: None,
            error: None,
            retry_count: 0,
            max_retries: 3,
            created_at: now.clone(),
            started_at: None,
            completed_at: None,
            updated_at: now,
        };
        let val = serde_json::to_value(&job)?;
        self.store.write_json("jobs", &job.id, &val)?;
        Ok(job)
    }

    pub fn get(&self, id: &str) -> Result<PersistentJob, StorageError> {
        let val = self.store.read_json("jobs", id)?;
        Ok(serde_json::from_value(val)?)
    }

    pub fn update_status(
        &self,
        id: &str,
        status: JobStatus,
        progress: f64,
    ) -> Result<PersistentJob, StorageError> {
        let mut job = self.get(id)?;
        job.status = status.clone();
        job.progress = progress;
        job.updated_at = now_iso();
        match &status {
            JobStatus::Running if job.started_at.is_none() => {
                job.started_at = Some(now_iso());
            }
            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled => {
                job.completed_at = Some(now_iso());
            }
            _ => {}
        }
        let val = serde_json::to_value(&job)?;
        self.store.write_json("jobs", &job.id, &val)?;
        Ok(job)
    }

    pub fn set_result(
        &self,
        id: &str,
        result: serde_json::Value,
    ) -> Result<PersistentJob, StorageError> {
        let mut job = self.get(id)?;
        job.result = Some(result);
        job.status = JobStatus::Completed;
        job.progress = 1.0;
        job.completed_at = Some(now_iso());
        job.updated_at = now_iso();
        let val = serde_json::to_value(&job)?;
        self.store.write_json("jobs", &job.id, &val)?;
        Ok(job)
    }

    pub fn set_error(&self, id: &str, error: String) -> Result<PersistentJob, StorageError> {
        let mut job = self.get(id)?;
        job.error = Some(error);
        job.status = JobStatus::Failed;
        job.completed_at = Some(now_iso());
        job.updated_at = now_iso();
        let val = serde_json::to_value(&job)?;
        self.store.write_json("jobs", &job.id, &val)?;
        Ok(job)
    }

    pub fn retry(&self, id: &str) -> Result<PersistentJob, StorageError> {
        let mut job = self.get(id)?;
        if job.retry_count >= job.max_retries {
            return Err(format!(
                "Max retries ({}) exceeded for job '{}'",
                job.max_retries, job.id
            )
            .into());
        }
        job.retry_count += 1;
        job.status = JobStatus::Queued;
        job.error = None;
        job.result = None;
        job.progress = 0.0;
        job.updated_at = now_iso();
        let val = serde_json::to_value(&job)?;
        self.store.write_json("jobs", &job.id, &val)?;
        Ok(job)
    }

    pub fn list_for_project(&self, project_id: &str, limit: usize) -> Vec<PersistentJob> {
        let mut jobs: Vec<PersistentJob> = self
            .store
            .list_all_json("jobs")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<PersistentJob>(v).ok())
            .filter(|j| j.project_id == project_id)
            .collect();
        jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        jobs.truncate(limit);
        jobs
    }

    pub fn list_for_org(&self, org_id: &str, limit: usize) -> Vec<PersistentJob> {
        let mut jobs: Vec<PersistentJob> = self
            .store
            .list_all_json("jobs")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<PersistentJob>(v).ok())
            .filter(|j| j.org_id == org_id)
            .collect();
        jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        jobs.truncate(limit);
        jobs
    }

    pub fn list_by_status(&self, status: &JobStatus) -> Vec<PersistentJob> {
        self.store
            .list_all_json("jobs")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<PersistentJob>(v).ok())
            .filter(|j| j.status == *status)
            .collect()
    }

    pub fn cancel(&self, id: &str) -> Result<PersistentJob, StorageError> {
        self.update_status(id, JobStatus::Cancelled, 0.0)
    }

    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        self.store.delete("jobs", id)
    }
}
