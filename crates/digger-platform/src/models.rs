/// Platform data models — organizations, projects, scans, reports, artifacts, jobs, webhooks.
use serde::{Deserialize, Serialize};

// ─── Organization ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub members: Vec<Member>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Member {
    pub user_id: String,
    pub role: Role,
    pub joined_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Role {
    Owner,
    Admin,
    Member,
    Viewer,
}

// ─── Project ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Project {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub description: String,
    pub settings: ProjectSettings,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectSettings {
    pub default_language: String,
    pub scan_timeout_secs: u64,
    pub notifications_enabled: bool,
}

impl Default for ProjectSettings {
    fn default() -> Self {
        Self {
            default_language: "solidity".into(),
            scan_timeout_secs: 300,
            notifications_enabled: false,
        }
    }
}

// ─── Scan History ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanRecord {
    pub id: String,
    pub project_id: String,
    pub org_id: String,
    pub status: ScanStatus,
    pub language: String,
    pub code_hash: String,
    pub input_preview: String,
    pub hypothesis_count: usize,
    pub findings_count: usize,
    pub execution_count: usize,
    pub error: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub report_id: Option<String>,
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

// ─── Versioned Reports ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Report {
    pub id: String,
    pub project_id: String,
    pub org_id: String,
    pub scan_id: String,
    pub version: u32,
    pub report_type: ReportType,
    pub content: serde_json::Value,
    pub content_hash: String,
    pub previous_version: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportType {
    Scan,
    Synthesis,
    Validation,
    Execution,
    Evaluation,
    Benchmark,
}

// ─── Artifacts ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Artifact {
    pub id: String,
    pub scan_id: String,
    pub project_id: String,
    pub kind: ArtifactKind,
    pub name: String,
    pub version: u32,
    pub content: serde_json::Value,
    pub content_hash: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ArtifactKind {
    SourceCode,
    ParsedIr,
    SystemGraph,
    KnowledgeReferences,
    Hypothesis,
    ExploitChain,
    ValidationReport,
    ExecutionTranscript,
    EvaluationReport,
}

// ─── Persistent Jobs ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistentJob {
    pub id: String,
    pub org_id: String,
    pub project_id: String,
    pub kind: JobKind,
    pub status: JobStatus,
    pub progress: f64,
    pub input: serde_json::Value,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobKind {
    Scan,
    Synthesize,
    Validate,
    Execute,
    Evaluate,
    Benchmark,
    Ingestion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Retrying,
}

// ─── Webhooks ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Webhook {
    pub id: String,
    pub org_id: String,
    pub url: String,
    pub events: Vec<WebhookEvent>,
    pub secret: String,
    pub active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WebhookEvent {
    ScanCompleted,
    ScanFailed,
    JobCompleted,
    ReportGenerated,
    IngestionCompleted,
    BenchmarkCompleted,
    EvaluationCompleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebhookDelivery {
    pub id: String,
    pub webhook_id: String,
    pub event: WebhookEvent,
    pub payload: serde_json::Value,
    pub status: DeliveryStatus,
    pub attempt: u32,
    pub max_attempts: u32,
    pub response_code: Option<u16>,
    pub error: Option<String>,
    pub created_at: String,
    pub delivered_at: Option<String>,
    pub next_retry_at: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Retrying,
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

fn secs_to_iso(secs: u64) -> String {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let mut y = 1970u64;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let feb = if is_leap(y) { 29 } else { 28 };
    let cumulative = [
        0,
        31,
        31 + feb,
        31 + feb + 31,
        31 + feb + 61,
        31 + feb + 91,
        31 + feb + 121,
        31 + feb + 152,
        31 + feb + 183,
        31 + feb + 213,
        31 + feb + 244,
        31 + feb + 274,
        31 + feb + 304,
    ];
    let mut m = 12u64;
    for i in 0..12u64 {
        if remaining < cumulative[(i + 1) as usize] {
            m = i + 1;
            break;
        }
    }
    let d = remaining - cumulative[(m - 1) as usize] + 1;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

pub fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs_to_iso(secs)
}

pub fn now_iso_secs(offset: u64) -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + offset;
    secs_to_iso(secs)
}

pub fn iso_to_epoch_secs(s: &str) -> u64 {
    let parse = |start: usize, end: usize| -> u64 {
        s.get(start..end).and_then(|x| x.parse().ok()).unwrap_or(0)
    };
    let year = parse(0, 4);
    let month = parse(5, 7).clamp(1, 12);
    let day = parse(8, 10).max(1);
    let hour = parse(11, 13);
    let minute = parse(14, 16);
    let second = parse(17, 19);
    let mut total_days: u64 = 0;
    for y in 1970..year {
        total_days += if is_leap(y) { 366 } else { 365 };
    }
    let leap = is_leap(year);
    let feb = if leap { 29 } else { 28 };
    let month_days = [31u64, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for days in month_days.iter().take((month - 1) as usize) {
        total_days += days;
    }
    total_days += day.saturating_sub(1);
    total_days * 86400 + hour * 3600 + minute * 60 + second
}
