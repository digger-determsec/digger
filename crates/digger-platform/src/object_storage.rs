/// Object storage backend — placeholder for S3/GCS/Azure Blob.
use crate::storage::{ErrorKind, Storage, StorageError};

pub struct ObjectStorage {
    _bucket: String,
    _prefix: String,
}

impl ObjectStorage {
    pub fn new(bucket: &str, prefix: &str) -> Self {
        Self {
            _bucket: bucket.to_string(),
            _prefix: prefix.to_string(),
        }
    }
}

fn not_implemented() -> StorageError {
    StorageError {
        kind: ErrorKind::NotImplemented,
        message: "Object storage backend not yet implemented".into(),
    }
}

impl Storage for ObjectStorage {
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
        "object"
    }
}
