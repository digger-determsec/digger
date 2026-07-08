//! Storage trait — abstracts all persistence operations for the platform.
//!
//! Business logic depends only on this trait. No module should reference
//! concrete storage implementations directly.

#[derive(Debug, Clone, thiserror::Error)]
#[error("{kind:?}: {message}")]
pub struct StorageError {
    pub kind: ErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    NotFound,
    AlreadyExists,
    Serialization,
    Io,
    Constraint,
    NotImplemented,
    Other,
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            message: e.to_string(),
        }
    }
}
impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        Self {
            kind: ErrorKind::Serialization,
            message: e.to_string(),
        }
    }
}
impl From<String> for StorageError {
    fn from(s: String) -> Self {
        Self {
            kind: ErrorKind::Other,
            message: s,
        }
    }
}

/// The storage interface that all platform services depend on.
/// Uses serde_json::Value for serialization to remain dyn-compatible.
pub trait Storage: Send + Sync {
    fn init(&self) -> Result<(), StorageError>;
    fn write_json(
        &self,
        collection: &str,
        id: &str,
        data: &serde_json::Value,
    ) -> Result<(), StorageError>;
    fn read_json(&self, collection: &str, id: &str) -> Result<serde_json::Value, StorageError>;
    fn delete(&self, collection: &str, id: &str) -> Result<(), StorageError>;
    fn list_ids(&self, collection: &str) -> Vec<String>;
    fn list_all_json(&self, collection: &str) -> Vec<serde_json::Value>;
    fn exists(&self, collection: &str, id: &str) -> bool;
    fn backend_name(&self) -> &str;
    fn backend_version(&self) -> &str {
        "1.0"
    }
}
