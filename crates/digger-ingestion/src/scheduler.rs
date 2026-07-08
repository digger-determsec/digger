/// Production ingestion scheduler.
///
/// Supports:
/// - Configurable polling intervals per source
/// - Manual refresh triggers
/// - Source-specific refresh
/// - Graceful retries with deterministic limits
/// - Resumable interrupted ingestion
/// - State persistence to disk
use crate::IngestionError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default polling interval (6 hours).
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 21600;

/// Maximum retry attempts before giving up.
pub const MAX_RETRIES: u32 = 3;

/// Backoff multiplier per retry.
pub const RETRY_BACKOFF_MULTIPLIER: u64 = 2;

/// State directory for scheduler persistence.
pub const SCHEDULER_DIR: &str = ".digger/scheduler";

/// State of a source in the scheduler.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SourceState {
    /// Idle, waiting for next poll.
    Idle,
    /// Currently syncing.
    Syncing,
    /// Sync failed, will retry.
    Failed { retries_remaining: u32 },
    /// Paused by user (manual).
    Paused,
    /// Disabled by configuration.
    Disabled,
}

/// Configuration for a source's scheduling behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSchedule {
    /// Source identifier.
    pub source_id: String,
    /// Polling interval in seconds.
    pub poll_interval_secs: u64,
    /// Whether this source is enabled.
    pub enabled: bool,
}

impl Default for SourceSchedule {
    fn default() -> Self {
        Self {
            source_id: String::new(),
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            enabled: true,
        }
    }
}

/// Persisted state for a single source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSchedulerState {
    /// Current state.
    pub state: SourceState,
    /// Last successful sync timestamp.
    pub last_sync: Option<String>,
    /// Next scheduled sync timestamp.
    pub next_sync: Option<String>,
    /// Last error message.
    pub last_error: Option<String>,
    /// Number of consecutive failures.
    pub consecutive_failures: u32,
    /// Total successful syncs.
    pub total_syncs: u64,
    /// Total failed syncs.
    pub total_failures: u64,
}

impl Default for SourceSchedulerState {
    fn default() -> Self {
        Self {
            state: SourceState::Idle,
            last_sync: None,
            next_sync: None,
            last_error: None,
            consecutive_failures: 0,
            total_syncs: 0,
            total_failures: 0,
        }
    }
}

/// Complete scheduler state persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerState {
    /// Scheduler format version.
    pub version: u32,
    /// Per-source states.
    pub sources: BTreeMap<String, SourceSchedulerState>,
    /// Per-source configurations.
    pub schedules: BTreeMap<String, SourceSchedule>,
}

impl Default for SchedulerState {
    fn default() -> Self {
        Self {
            version: 1,
            sources: BTreeMap::new(),
            schedules: BTreeMap::new(),
        }
    }
}

/// Production ingestion scheduler.
pub struct Scheduler {
    /// State directory.
    state_dir: PathBuf,
    #[allow(dead_code)]
    /// Corpus directory.
    corpus_dir: PathBuf,
    /// Persisted state.
    state: SchedulerState,
}

impl Scheduler {
    /// Create a new scheduler with default configuration.
    pub fn new(trigger_dir: &str, corpus_dir: &str) -> Self {
        let state_dir = PathBuf::from(trigger_dir)
            .parent()
            .map(|p| p.join("scheduler"))
            .unwrap_or_else(|| PathBuf::from(SCHEDULER_DIR));

        let mut scheduler = Self {
            state_dir,
            corpus_dir: PathBuf::from(corpus_dir),
            state: SchedulerState::default(),
        };

        scheduler.state = SchedulerState::load(&scheduler.state_dir);
        scheduler
    }

    /// Create a scheduler with explicit state directory.
    pub fn with_state_dir(state_dir: PathBuf, corpus_dir: &str) -> Self {
        let mut scheduler = Self {
            state_dir,
            corpus_dir: PathBuf::from(corpus_dir),
            state: SchedulerState::default(),
        };

        scheduler.state = SchedulerState::load(&scheduler.state_dir);
        scheduler
    }

    /// Register a source with a polling interval.
    pub fn register_source(&mut self, source_id: &str, poll_interval_secs: u64, enabled: bool) {
        self.state.schedules.insert(
            source_id.to_string(),
            SourceSchedule {
                source_id: source_id.to_string(),
                poll_interval_secs,
                enabled,
            },
        );
        self.state.sources.entry(source_id.to_string()).or_default();
        let _ = self.state.save(&self.state_dir);
    }

    /// Check if a source is due for sync.
    pub fn is_due(&self, source_id: &str) -> bool {
        let _schedule = match self.state.schedules.get(source_id) {
            Some(s) if s.enabled => s,
            _ => return false,
        };

        let source_state = match self.state.sources.get(source_id) {
            Some(s) => s,
            None => return true, // Never synced → due
        };

        match &source_state.state {
            SourceState::Disabled | SourceState::Paused => return false,
            _ => {}
        }

        match &source_state.next_sync {
            Some(next) => {
                let now = Self::now_secs();
                match parse_timestamp(next) {
                    Ok(next_secs) => now >= next_secs,
                    Err(e) => {
                        eprintln!("Warning: Failed to parse timestamp '{}': {}", next, e);
                        true
                    }
                }
            }
            None => true, // Never scheduled → due
        }
    }

    /// Mark a source as syncing.
    pub fn mark_syncing(&mut self, source_id: &str) {
        if let Some(state) = self.state.sources.get_mut(source_id) {
            state.state = SourceState::Syncing;
            let _ = self.state.save(&self.state_dir);
        }
    }

    /// Mark a source sync as successful.
    pub fn mark_success(&mut self, source_id: &str) {
        if let Some(state) = self.state.sources.get_mut(source_id) {
            let now = Self::now_secs();
            let interval = self
                .state
                .schedules
                .get(source_id)
                .map(|s| s.poll_interval_secs)
                .unwrap_or(DEFAULT_POLL_INTERVAL_SECS);

            state.state = SourceState::Idle;
            state.last_sync = Some(Self::format_timestamp(now));
            state.next_sync = Some(Self::format_timestamp(now + interval));
            state.last_error = None;
            state.consecutive_failures = 0;
            state.total_syncs += 1;
            let _ = self.state.save(&self.state_dir);
        }
    }

    /// Mark a source sync as failed with retry logic.
    pub fn mark_failure(&mut self, source_id: &str, error: &str) {
        if let Some(state) = self.state.sources.get_mut(source_id) {
            state.consecutive_failures += 1;
            state.total_failures += 1;
            state.last_error = Some(error.to_string());

            if state.consecutive_failures >= MAX_RETRIES {
                state.state = SourceState::Failed {
                    retries_remaining: 0,
                };
            } else {
                let backoff = RETRY_BACKOFF_MULTIPLIER.pow(state.consecutive_failures);
                let retry_secs = 60 * backoff; // 2min, 4min, 8min
                let now = Self::now_secs();
                state.state = SourceState::Failed {
                    retries_remaining: MAX_RETRIES - state.consecutive_failures,
                };
                state.next_sync = Some(Self::format_timestamp(now + retry_secs));
            }
            let _ = self.state.save(&self.state_dir);
        }
    }

    /// Pause a source.
    pub fn pause(&mut self, source_id: &str) {
        if let Some(state) = self.state.sources.get_mut(source_id) {
            state.state = SourceState::Paused;
            let _ = self.state.save(&self.state_dir);
        }
    }

    /// Resume a paused source.
    pub fn resume(&mut self, source_id: &str) {
        if let Some(state) = self.state.sources.get_mut(source_id) {
            state.state = SourceState::Idle;
            state.next_sync = Some(Self::format_timestamp(Self::now_secs()));
            let _ = self.state.save(&self.state_dir);
        }
    }

    /// Force refresh a source (manual trigger).
    pub fn force_refresh(&mut self, source_id: &str) {
        if let Some(state) = self.state.sources.get_mut(source_id) {
            state.state = SourceState::Idle;
            state.next_sync = Some(Self::format_timestamp(Self::now_secs()));
            let _ = self.state.save(&self.state_dir);
        }
    }

    /// Get sources that are due for sync.
    pub fn get_due_sources(&self) -> Vec<String> {
        self.state
            .schedules
            .keys()
            .filter(|id| self.is_due(id))
            .cloned()
            .collect()
    }

    /// Get status summary for all sources.
    pub fn get_status(&self) -> Vec<(String, SourceState, Option<String>, Option<String>)> {
        self.state
            .sources
            .iter()
            .map(|(id, s)| {
                (
                    id.clone(),
                    s.state.clone(),
                    s.last_sync.clone(),
                    s.last_error.clone(),
                )
            })
            .collect()
    }

    /// Get the number of retries remaining for a source.
    pub fn retries_remaining(&self, source_id: &str) -> u32 {
        self.state
            .sources
            .get(source_id)
            .and_then(|s| match &s.state {
                SourceState::Failed { retries_remaining } => Some(*retries_remaining),
                _ => None,
            })
            .unwrap_or(MAX_RETRIES)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn format_timestamp(secs: u64) -> String {
        let days = secs / 86400;
        let time_of_day = secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        let mut y = 1970u64;
        let mut remaining = days;
        loop {
            let days_in_year =
                if (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400) {
                    366
                } else {
                    365
                };
            if remaining < days_in_year {
                break;
            }
            remaining -= days_in_year;
            y += 1;
        }

        let leap = (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
        let month_days = [
            31u64,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut m = 0usize;
        while m < 12 && remaining >= month_days[m] {
            remaining -= month_days[m];
            m += 1;
        }
        let month = m + 1;
        let day = remaining + 1;

        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            y, month, day, hours, minutes, seconds
        )
    }
}

/// Parse an ISO-8601 timestamp back to seconds since epoch.
fn parse_timestamp(ts: &str) -> Result<u64, IngestionError> {
    // Simple parser for "YYYY-MM-DDTHH:MM:SSZ" format
    let parts: Vec<&str> = ts.trim_end_matches('Z').split(['T', '-', ':']).collect();
    if parts.len() != 6 {
        return Err(IngestionError::Parse(format!(
            "Invalid timestamp format: {}",
            ts
        )));
    }
    let year: u64 = parts[0]
        .parse()
        .map_err(|_| IngestionError::Parse("invalid year".into()))?;
    let month: u64 = parts[1]
        .parse()
        .map_err(|_| IngestionError::Parse("invalid month".into()))?;
    let day: u64 = parts[2]
        .parse()
        .map_err(|_| IngestionError::Parse("invalid day".into()))?;
    let hours: u64 = parts[3]
        .parse()
        .map_err(|_| IngestionError::Parse("invalid hours".into()))?;
    let minutes: u64 = parts[4]
        .parse()
        .map_err(|_| IngestionError::Parse("invalid minutes".into()))?;
    let seconds: u64 = parts[5]
        .parse()
        .map_err(|_| IngestionError::Parse("invalid seconds".into()))?;

    // Days since epoch
    let mut total_days = 0u64;
    for y in 1970..year {
        total_days += if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
    }

    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let month_days = [
        31u64,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    for m in 1..month {
        total_days += month_days[(m - 1) as usize];
    }
    total_days += day - 1;

    Ok(total_days * 86400 + hours * 3600 + minutes * 60 + seconds)
}

impl SchedulerState {
    fn load(state_dir: &Path) -> Self {
        let path = state_dir.join("scheduler.json");
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(state) = serde_json::from_str::<SchedulerState>(&content) {
                    return state;
                }
            }
        }
        Self::default()
    }

    fn save(&self, state_dir: &Path) -> Result<(), IngestionError> {
        std::fs::create_dir_all(state_dir)?;
        let path = state_dir.join("scheduler.json");
        let json =
            serde_json::to_string_pretty(self).map_err(|e| IngestionError::Other(e.to_string()))?;
        std::fs::write(&path, json)?;
        Ok(())
    }
}

// Legacy compatibility — keep old trigger methods working
impl Scheduler {
    /// Legacy: Check if a trigger file exists.
    pub fn has_trigger(&self, source: &str) -> bool {
        self.state_dir
            .parent()
            .map(|p| {
                p.join("triggers")
                    .join(format!("{}.trigger", source))
                    .exists()
            })
            .unwrap_or(false)
    }

    /// Legacy: Create a trigger file.
    pub fn create_trigger(&self, source: &str) -> Result<(), IngestionError> {
        let trigger_dir = self
            .state_dir
            .parent()
            .map(|p| p.join("triggers"))
            .unwrap_or_else(|| PathBuf::from(".digger/triggers"));
        std::fs::create_dir_all(&trigger_dir)?;
        std::fs::write(trigger_dir.join(format!("{}.trigger", source)), "ingest")?;
        Ok(())
    }

    /// Legacy: Remove a trigger file.
    pub fn remove_trigger(&self, source: &str) -> Result<(), IngestionError> {
        let trigger_dir = self
            .state_dir
            .parent()
            .map(|p| p.join("triggers"))
            .unwrap_or_else(|| PathBuf::from(".digger/triggers"));
        let path = trigger_dir.join(format!("{}.trigger", source));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Legacy: List all active triggers.
    pub fn list_triggers(&self) -> Vec<String> {
        let trigger_dir = self
            .state_dir
            .parent()
            .map(|p| p.join("triggers"))
            .unwrap_or_else(|| PathBuf::from(".digger/triggers"));
        let mut triggers = Vec::new();
        if trigger_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&trigger_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".trigger") {
                        triggers.push(name.replace(".trigger", ""));
                    }
                }
            }
        }
        triggers.sort();
        triggers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "digger_scheduler_test_{}_{:?}",
            std::process::id(),
            id
        ))
    }

    #[test]
    fn test_trigger_lifecycle() {
        let dir = test_dir();
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let state_dir = dir.join("scheduler");
        let scheduler = Scheduler::with_state_dir(state_dir.clone(), dir.to_str().unwrap());

        assert!(!scheduler.has_trigger("test"));
        scheduler.create_trigger("test").unwrap();
        assert!(scheduler.has_trigger("test"));
        scheduler.remove_trigger("test").unwrap();
        assert!(!scheduler.has_trigger("test"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_register_and_due() {
        let dir = test_dir();
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let state_dir = dir.join("scheduler");
        let mut scheduler = Scheduler::with_state_dir(state_dir, dir.to_str().unwrap());
        scheduler.register_source("test", 60, true);

        // Should be due immediately (never synced)
        assert!(scheduler.is_due("test"));

        // After marking success, should not be due
        scheduler.mark_syncing("test");
        scheduler.mark_success("test");
        assert!(!scheduler.is_due("test"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_retry_on_failure() {
        let dir = test_dir();
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let state_dir = dir.join("scheduler");
        let mut scheduler = Scheduler::with_state_dir(state_dir, dir.to_str().unwrap());
        scheduler.register_source("test", 60, true);

        // First failure — should have retries remaining
        scheduler.mark_failure("test", "error 1");
        assert_eq!(scheduler.retries_remaining("test"), MAX_RETRIES - 1);

        // Second failure
        scheduler.mark_failure("test", "error 2");
        assert_eq!(scheduler.retries_remaining("test"), MAX_RETRIES - 2);

        // Third failure — exhausted
        scheduler.mark_failure("test", "error 3");
        assert_eq!(scheduler.retries_remaining("test"), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_pause_resume() {
        let dir = test_dir();
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let state_dir = dir.join("scheduler");
        let mut scheduler = Scheduler::with_state_dir(state_dir, dir.to_str().unwrap());
        scheduler.register_source("test", 60, true);

        scheduler.pause("test");
        assert!(!scheduler.is_due("test"));

        scheduler.resume("test");
        assert!(scheduler.is_due("test"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_disabled_source() {
        let dir = test_dir();
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let state_dir = dir.join("scheduler");
        let mut scheduler = Scheduler::with_state_dir(state_dir, dir.to_str().unwrap());
        scheduler.register_source("test", 60, false);

        assert!(!scheduler.is_due("test"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_state_persistence() {
        let dir = test_dir();
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let state_dir = dir.join("scheduler");
        {
            let mut scheduler = Scheduler::with_state_dir(state_dir.clone(), dir.to_str().unwrap());
            scheduler.register_source("test", 60, true);
            scheduler.mark_syncing("test");
            scheduler.mark_success("test");
        }

        // Reload and verify state persisted
        let scheduler = Scheduler::with_state_dir(state_dir, dir.to_str().unwrap());
        assert!(!scheduler.is_due("test"));
        let status = scheduler.get_status();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].0, "test");

        let _ = fs::remove_dir_all(&dir);
    }
}
