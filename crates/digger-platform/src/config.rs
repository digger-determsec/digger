use crate::json_storage::JsonStorage;
use crate::object_storage::ObjectStorage;
use crate::postgres_storage::PostgresStorage;
use crate::sqlite_storage::SqliteStorage;
use crate::storage::Storage;
/// Storage configuration — select backend from environment or defaults.
use std::sync::Arc;

/// Create a boxed Storage from the DIGGER_STORAGE_BACKEND env var.
///
/// Supported values:
/// - "json" (default): JsonStorage
/// - "sqlite": SqliteStorage
/// - "postgres": PostgresStorage
/// - "object": ObjectStorage
pub fn create_storage() -> Arc<dyn Storage> {
    let backend = std::env::var("DIGGER_STORAGE_BACKEND").unwrap_or_else(|_| "json".into());
    match backend.as_str() {
        "json" => {
            let dir =
                std::env::var("DIGGER_STORAGE_DIR").unwrap_or_else(|_| "platform_data".into());
            Arc::new(JsonStorage::new(dir))
        }
        "sqlite" => {
            let path = std::env::var("DIGGER_SQLITE_PATH").unwrap_or_else(|_| "digger.db".into());
            Arc::new(SqliteStorage::new(&path))
        }
        "postgres" => {
            let conn = std::env::var("DIGGER_DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/digger".into());
            Arc::new(PostgresStorage::new(&conn))
        }
        "object" => {
            let bucket = std::env::var("DIGGER_S3_BUCKET").unwrap_or_else(|_| "digger-data".into());
            let prefix = std::env::var("DIGGER_S3_PREFIX").unwrap_or_else(|_| "v1".into());
            Arc::new(ObjectStorage::new(&bucket, &prefix))
        }
        other => {
            eprintln!("Unknown storage backend '{}', falling back to json", other);
            let dir =
                std::env::var("DIGGER_STORAGE_DIR").unwrap_or_else(|_| "platform_data".into());
            Arc::new(JsonStorage::new(dir))
        }
    }
}
