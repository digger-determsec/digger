/// PostgreSQL storage backend — placeholder for future implementation.
use crate::storage::{ErrorKind, Storage, StorageError};

pub struct PostgresStorage {
    _connection_string: String,
}

impl PostgresStorage {
    pub fn new(connection_string: &str) -> Self {
        Self {
            _connection_string: connection_string.to_string(),
        }
    }
}

fn not_implemented() -> StorageError {
    StorageError {
        kind: ErrorKind::NotImplemented,
        message: "PostgreSQL backend not yet implemented".into(),
    }
}

impl Storage for PostgresStorage {
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
        "postgres"
    }
}
