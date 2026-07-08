use digger_monitor::history::{MonitorHistoryStore, MonitorRunRecord};
use digger_monitor::onchain::ProviderError;
use digger_monitor::state::{MonitorState, WatchTarget};
use digger_monitor::store::MonitorStore;
use rusqlite::params;

use crate::ErrorResponse;

pub struct SqliteMonitorStore {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

impl SqliteMonitorStore {
    pub fn new(conn: rusqlite::Connection) -> Self {
        // invariant: schema DDL is a valid constant — failure means a fundamental
        // sqlite/build issue that should halt the process
        #[allow(clippy::expect_used)] // invariant: schema DDL is a valid constant
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS watch_targets (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                target_descriptor TEXT NOT NULL,
                alert_channel TEXT NOT NULL,
                poll_interval_secs INTEGER NOT NULL DEFAULT 60,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS monitor_state (
                target_id TEXT PRIMARY KEY,
                last_revision TEXT,
                last_bundle_hash TEXT,
                last_finding_ids TEXT NOT NULL DEFAULT '[]',
                already_actioned_finding_ids TEXT NOT NULL DEFAULT '[]',
                FOREIGN KEY (target_id) REFERENCES watch_targets(id)
            );
            CREATE TABLE IF NOT EXISTS monitor_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                ran_at INTEGER NOT NULL,
                revision TEXT NOT NULL DEFAULT '',
                bundle_hash TEXT NOT NULL DEFAULT '',
                new_findings_count INTEGER NOT NULL DEFAULT 0,
                resolved_findings_count INTEGER NOT NULL DEFAULT 0,
                persisting_findings_count INTEGER NOT NULL DEFAULT 0,
                decisions TEXT NOT NULL DEFAULT '[]',
                error TEXT,
                explanations TEXT DEFAULT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_monitor_runs_target ON monitor_runs(target_id);
            CREATE INDEX IF NOT EXISTS idx_monitor_runs_tenant ON monitor_runs(tenant_id);",
        )
        .expect("invariant: schema DDL is a valid constant");
        Self {
            conn: std::sync::Mutex::new(conn),
        }
    }
}

impl MonitorStore for SqliteMonitorStore {
    fn get_state(&self, target_id: &str) -> Option<MonitorState> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT last_revision, last_bundle_hash, last_finding_ids, already_actioned_finding_ids FROM monitor_state WHERE target_id = ?1",
            params![target_id],
            |row| {
                let last_revision: Option<String> = row.get(0)?;
                let last_bundle_hash: Option<String> = row.get(1)?;
                let finding_ids_str: String = row.get(2)?;
                let actioned_str: String = row.get(3)?;
                Ok(MonitorState {
                    last_revision,
                    last_bundle_hash,
                    last_finding_ids: serde_json::from_str(&finding_ids_str).unwrap_or_default(),
                    already_actioned_finding_ids: serde_json::from_str(&actioned_str).unwrap_or_default(),
                })
            },
        )
        .ok()
    }

    fn save_state(&self, target_id: &str, state: &MonitorState) -> Result<(), ProviderError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO monitor_state (target_id, last_revision, last_bundle_hash, last_finding_ids, already_actioned_finding_ids)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                target_id,
                state.last_revision,
                state.last_bundle_hash,
                serde_json::to_string(&state.last_finding_ids).unwrap_or_default(),
                serde_json::to_string(&state.already_actioned_finding_ids).unwrap_or_default(),
            ],
        )
        .map(|_| ())
        .map_err(|e| ProviderError::from(e.to_string()))
    }

    fn get_target(&self, target_id: &str) -> Option<WatchTarget> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT tenant_id, target_descriptor, alert_channel FROM watch_targets WHERE id = ?1",
            params![target_id],
            |row| {
                Ok(WatchTarget {
                    tenant_id: row.get(0)?,
                    target_descriptor: row.get(1)?,
                    alert_channel: row.get(2)?,
                })
            },
        )
        .ok()
    }

    fn save_target(&self, target_id: &str, target: &WatchTarget) -> Result<(), ProviderError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO watch_targets (id, tenant_id, target_descriptor, alert_channel)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                target_id,
                target.tenant_id,
                target.target_descriptor,
                target.alert_channel
            ],
        )
        .map(|_| ())
        .map_err(|e| ProviderError::from(e.to_string()))
    }
}

impl SqliteMonitorStore {
    pub fn list_targets(&self, tenant_id: &str) -> Vec<(String, WatchTarget)> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = match conn
            .prepare("SELECT id, tenant_id, target_descriptor, alert_channel FROM watch_targets WHERE tenant_id = ?1 ORDER BY created_at DESC")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![tenant_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                WatchTarget {
                    tenant_id: row.get(1)?,
                    target_descriptor: row.get(2)?,
                    alert_channel: row.get(3)?,
                },
            ))
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_else(|_| Vec::new())
    }

    pub fn delete_target(&self, target_id: &str, tenant_id: &str) -> Result<bool, ErrorResponse> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let affected = conn
            .execute(
                "DELETE FROM watch_targets WHERE id = ?1 AND tenant_id = ?2",
                params![target_id, tenant_id],
            )
            .map_err(|e| e.to_string())?;
        conn.execute(
            "DELETE FROM monitor_state WHERE target_id = ?1",
            params![target_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(affected > 0)
    }
}

impl MonitorHistoryStore for SqliteMonitorStore {
    fn append(&self, record: &MonitorRunRecord) {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let explanations_json = record
            .explanations
            .as_ref()
            .map(|e| serde_json::to_string(e).unwrap_or_default());
        let _ = conn.execute(
            "INSERT INTO monitor_runs (target_id, tenant_id, ran_at, revision, bundle_hash, new_findings_count, resolved_findings_count, persisting_findings_count, decisions, error, explanations)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.target_id,
                record.tenant_id,
                record.ran_at,
                record.revision,
                record.bundle_hash,
                record.new_findings_count as i64,
                record.resolved_findings_count as i64,
                record.persisting_findings_count as i64,
                serde_json::to_string(&record.decisions).unwrap_or_default(),
                record.error,
                explanations_json,
            ],
        );
    }

    fn list_by_target(&self, target_id: &str) -> Vec<MonitorRunRecord> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = match conn
            .prepare("SELECT target_id, tenant_id, ran_at, revision, bundle_hash, new_findings_count, resolved_findings_count, persisting_findings_count, decisions, error FROM monitor_runs WHERE target_id = ?1 ORDER BY ran_at DESC")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![target_id], |row| {
            let decisions_str: String = row.get(8)?;
            Ok(MonitorRunRecord {
                target_id: row.get(0)?,
                tenant_id: row.get(1)?,
                ran_at: row.get(2)?,
                revision: row.get(3)?,
                bundle_hash: row.get(4)?,
                new_findings_count: row.get::<_, i64>(5)? as usize,
                resolved_findings_count: row.get::<_, i64>(6)? as usize,
                persisting_findings_count: row.get::<_, i64>(7)? as usize,
                decisions: serde_json::from_str(&decisions_str).unwrap_or_default(),
                error: row.get(9)?,
                explanations: None,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_else(|_| Vec::new())
    }

    fn list_by_tenant(&self, tenant_id: &str) -> Vec<MonitorRunRecord> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = match conn
            .prepare("SELECT target_id, tenant_id, ran_at, revision, bundle_hash, new_findings_count, resolved_findings_count, persisting_findings_count, decisions, error FROM monitor_runs WHERE tenant_id = ?1 ORDER BY ran_at DESC")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![tenant_id], |row| {
            let decisions_str: String = row.get(8)?;
            Ok(MonitorRunRecord {
                target_id: row.get(0)?,
                tenant_id: row.get(1)?,
                ran_at: row.get(2)?,
                revision: row.get(3)?,
                bundle_hash: row.get(4)?,
                new_findings_count: row.get::<_, i64>(5)? as usize,
                resolved_findings_count: row.get::<_, i64>(6)? as usize,
                persisting_findings_count: row.get::<_, i64>(7)? as usize,
                decisions: serde_json::from_str(&decisions_str).unwrap_or_default(),
                error: row.get(9)?,
                explanations: None,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_else(|_| Vec::new())
    }
}

impl SqliteMonitorStore {
    pub fn get_run(&self, run_id: i64) -> Option<MonitorRunRecord> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT target_id, tenant_id, ran_at, revision, bundle_hash, new_findings_count, resolved_findings_count, persisting_findings_count, decisions, error FROM monitor_runs WHERE id = ?1",
            params![run_id],
            |row| {
                let decisions_str: String = row.get(8)?;
                Ok(MonitorRunRecord {
                    target_id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    ran_at: row.get(2)?,
                    revision: row.get(3)?,
                    bundle_hash: row.get(4)?,
                    new_findings_count: row.get::<_, i64>(5)? as usize,
                    resolved_findings_count: row.get::<_, i64>(6)? as usize,
                    persisting_findings_count: row.get::<_, i64>(7)? as usize,
                    decisions: serde_json::from_str(&decisions_str).unwrap_or_default(),
                    error: row.get(9)?,
                    explanations: None,
                })
            },
        )
        .ok()
    }

    pub fn list_runs(
        &self,
        target_id: &str,
        tenant_id: &str,
        limit: usize,
    ) -> Vec<(i64, MonitorRunRecord)> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = match conn
            .prepare("SELECT id, target_id, tenant_id, ran_at, revision, bundle_hash, new_findings_count, resolved_findings_count, persisting_findings_count, decisions, error FROM monitor_runs WHERE target_id = ?1 AND tenant_id = ?2 ORDER BY ran_at DESC LIMIT ?3")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![target_id, tenant_id, limit as i64], |row| {
            let decisions_str: String = row.get(9)?;
            Ok((
                row.get::<_, i64>(0)?,
                MonitorRunRecord {
                    target_id: row.get(1)?,
                    tenant_id: row.get(2)?,
                    ran_at: row.get(3)?,
                    revision: row.get(4)?,
                    bundle_hash: row.get(5)?,
                    new_findings_count: row.get::<_, i64>(6)? as usize,
                    resolved_findings_count: row.get::<_, i64>(7)? as usize,
                    persisting_findings_count: row.get::<_, i64>(8)? as usize,
                    decisions: serde_json::from_str(&decisions_str).unwrap_or_default(),
                    error: row.get(10)?,
                    explanations: None,
                },
            ))
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_else(|_| Vec::new())
    }
}
