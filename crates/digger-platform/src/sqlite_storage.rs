/// SQLite storage backend — placeholder for future implementation.
use crate::storage::{ErrorKind, Storage, StorageError};

pub struct SqliteStorage {
    _db_path: String,
}

impl SqliteStorage {
    pub fn new(db_path: &str) -> Self {
        Self {
            _db_path: db_path.to_string(),
        }
    }
}

fn not_implemented() -> StorageError {
    StorageError {
        kind: ErrorKind::NotImplemented,
        message: "SQLite backend not yet implemented".into(),
    }
}

impl Storage for SqliteStorage {
    fn init(&self) -> Result<(), StorageError> {
        Err(not_implemented())
    }
    fn write_json(
        &self,
        _collection: &str,
        _id: &str,
        _data: &serde_json::Value,
    ) -> Result<(), StorageError> {
        Err(not_implemented())
    }
    fn read_json(&self, _collection: &str, _id: &str) -> Result<serde_json::Value, StorageError> {
        Err(not_implemented())
    }
    fn delete(&self, _collection: &str, _id: &str) -> Result<(), StorageError> {
        Err(not_implemented())
    }
    fn list_ids(&self, _collection: &str) -> Vec<String> {
        vec![]
    }
    fn list_all_json(&self, _collection: &str) -> Vec<serde_json::Value> {
        vec![]
    }
    fn exists(&self, _collection: &str, _id: &str) -> bool {
        false
    }
    fn backend_name(&self) -> &str {
        "sqlite"
    }
}
