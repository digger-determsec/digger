/// Async job runner for long-running operations.
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type JobStore = Arc<RwLock<HashMap<String, Job>>>;

/// A background job.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Job {
    pub id: String,
    pub kind: JobKind,
    pub status: JobStatus,
    pub progress: f64,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum JobKind {
    Scan,
    Synthesize,
    Validate,
    Verify,
    Benchmark,
    Ingestion,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Create a new job store.
pub fn new_job_store() -> JobStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Create a new job.
pub async fn create_job(store: &JobStore, kind: JobKind) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let job = Job {
        id: id.clone(),
        kind,
        status: JobStatus::Queued,
        progress: 0.0,
        created_at: now_iso(),
        started_at: None,
        completed_at: None,
        result: None,
        error: None,
    };
    let mut jobs = store.write().await;
    jobs.insert(id.clone(), job);
    id
}

/// Get job status.
pub async fn get_job(store: &JobStore, id: &str) -> Option<Job> {
    let jobs = store.read().await;
    jobs.get(id).cloned()
}

/// Update job status.
pub async fn update_job(store: &JobStore, id: &str, status: JobStatus, progress: f64) {
    let mut jobs = store.write().await;
    if let Some(job) = jobs.get_mut(id) {
        match &status {
            JobStatus::Running if job.started_at.is_none() => {
                job.started_at = Some(now_iso());
            }
            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled => {
                job.completed_at = Some(now_iso());
            }
            _ => {}
        }
        job.status = status;
        job.progress = progress;
    }
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}s", secs)
}
