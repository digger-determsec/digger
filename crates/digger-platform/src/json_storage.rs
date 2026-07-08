use crate::storage::{Storage, StorageError};
/// JSON file-based storage backend — implements the Storage trait.
use std::path::{Path, PathBuf};

pub struct JsonStorage {
    base_dir: PathBuf,
}

impl JsonStorage {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

const COLLECTIONS: &[&str] = &[
    "orgs",
    "projects",
    "scans",
    "reports",
    "artifacts",
    "jobs",
    "webhooks",
    "api_keys",
    "scan_contexts",
];

/// C4 FIX: Validate that an ID contains only safe characters and cannot escape the base directory.
fn validate_id(id: &str) -> Result<(), StorageError> {
    if id.is_empty() {
        return Err(StorageError {
            kind: crate::storage::ErrorKind::Constraint,
            message: "ID cannot be empty".into(),
        });
    }
    if id.len() > 128 {
        return Err(StorageError {
            kind: crate::storage::ErrorKind::Constraint,
            message: "ID too long (max 128 chars)".into(),
        });
    }
    for ch in id.chars() {
        if !ch.is_alphanumeric() && ch != '-' && ch != '_' && ch != '.' {
            return Err(StorageError {
                kind: crate::storage::ErrorKind::Constraint,
                message: format!("Invalid character '{}' in ID", ch),
            });
        }
    }
    if id.contains("..") {
        return Err(StorageError {
            kind: crate::storage::ErrorKind::Constraint,
            message: "ID cannot contain '..'".into(),
        });
    }
    if id.starts_with('.') {
        return Err(StorageError {
            kind: crate::storage::ErrorKind::Constraint,
            message: "ID cannot start with '.'".into(),
        });
    }
    Ok(())
}

/// H1 FIX: Validate collection name — must be one of the known collections.
fn validate_collection(collection: &str) -> Result<(), StorageError> {
    if !COLLECTIONS.contains(&collection) {
        return Err(StorageError {
            kind: crate::storage::ErrorKind::Constraint,
            message: format!(
                "Invalid collection '{}'. Allowed: {:?}",
                collection, COLLECTIONS
            ),
        });
    }
    Ok(())
}

impl Storage for JsonStorage {
    fn init(&self) -> Result<(), StorageError> {
        std::fs::create_dir_all(&self.base_dir)?;
        for subdir in COLLECTIONS {
            std::fs::create_dir_all(self.base_dir.join(subdir))?;
        }
        Ok(())
    }

    fn write_json(
        &self,
        collection: &str,
        id: &str,
        data: &serde_json::Value,
    ) -> Result<(), StorageError> {
        validate_id(id)?;
        let dir = self.base_dir.join(collection);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.json", id));
        let json = serde_json::to_string_pretty(data)?;

        // C3 FIX: Atomic write — write to temp file, then rename.
        let tmp_path = dir.join(format!("{}.tmp.{}", id, std::process::id()));
        std::fs::write(&tmp_path, &json)?;
        std::fs::rename(&tmp_path, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            StorageError::from(e)
        })?;
        Ok(())
    }

    fn read_json(&self, collection: &str, id: &str) -> Result<serde_json::Value, StorageError> {
        validate_id(id)?;
        let path = self.base_dir.join(collection).join(format!("{}.json", id));
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    fn delete(&self, collection: &str, id: &str) -> Result<(), StorageError> {
        validate_id(id)?;
        let path = self.base_dir.join(collection).join(format!("{}.json", id));
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    fn list_ids(&self, collection: &str) -> Vec<String> {
        if validate_collection(collection).is_err() {
            return vec![];
        }
        let dir = self.base_dir.join(collection);
        if !dir.exists() {
            return vec![];
        }
        std::fs::read_dir(dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
            })
            .collect()
    }

    fn list_all_json(&self, collection: &str) -> Vec<serde_json::Value> {
        self.list_ids(collection)
            .iter()
            .filter_map(|id| self.read_json(collection, id).ok())
            .collect()
    }

    fn exists(&self, collection: &str, id: &str) -> bool {
        validate_collection(collection).is_ok()
            && validate_id(id).is_ok()
            && self
                .base_dir
                .join(collection)
                .join(format!("{}.json", id))
                .exists()
    }

    fn backend_name(&self) -> &str {
        "json"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_id_allows_normal() {
        assert!(validate_id("abc-123_def").is_ok());
        assert!(validate_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn validate_id_blocks_path_traversal() {
        assert!(validate_id("../../etc/passwd").is_err());
        assert!(validate_id("foo/../../bar").is_err());
    }

    #[test]
    fn validate_id_blocks_dotfiles() {
        assert!(validate_id(".hidden").is_err());
    }

    #[test]
    fn validate_id_blocks_empty() {
        assert!(validate_id("").is_err());
    }

    #[test]
    fn validate_id_blocks_special_chars() {
        assert!(validate_id("id with spaces").is_err());
        assert!(validate_id("id/with/slashes").is_err());
        assert!(validate_id("id\\with\\backslashes").is_err());
    }

    #[test]
    fn atomic_write_survives_concurrent_access() {
        let tmp = std::env::temp_dir().join(format!("digger_test_atomic_{}", uuid::Uuid::new_v4()));
        let storage = JsonStorage::new(&tmp);
        storage.init().unwrap();

        let mut handles = vec![];
        for i in 0..20 {
            let storage2 = JsonStorage::new(&tmp);
            let id = format!("item-{}", i);
            handles.push(std::thread::spawn(move || {
                let data = serde_json::json!({"id": id, "value": i});
                for _ in 0..10 {
                    storage2.write_json("test", &id, &data).unwrap();
                    let _ = storage2.read_json("test", &id);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        for i in 0..20 {
            let id = format!("item-{}", i);
            let val: serde_json::Value = storage.read_json("test", &id).unwrap();
            assert_eq!(val["id"], id);
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// WS5a: scan_history UTF-8 boundary — byte 200 straddles a 4-byte char.
    /// The old code[..200] panics because byte 200 falls mid-crawl (U+1F980, 4 bytes).
    /// The new char-boundary floor backs off to byte 198 (end of the last full char).
    #[test]
    fn test_scan_history_utf8_boundary_does_not_panic() {
        // 198 ASCII 'a' chars (198 bytes) + 20 crawl emoji (4 bytes each = 80 bytes)
        // Total 278 bytes. Crawl starts at byte 198, occupies bytes 198-201.
        // Byte 200 is the 3rd byte of crawl → NOT a char boundary.
        let code = format!("{}{}", "a".repeat(198), "\u{1F980}".repeat(20));
        assert_eq!(code.len(), 278, "total must be 278 bytes");
        assert!(
            !code.is_char_boundary(200),
            "byte 200 must NOT be a char boundary"
        );

        let store = JsonStorage::new(
            std::env::temp_dir().join(format!("digger_test_utf8_{}", uuid::Uuid::new_v4())),
        );
        let result = crate::scan_history::ScanHistoryManager::new(&store);
        let record = result.create("proj", "org", "solidity", &code);
        assert!(record.is_ok());
        let r = record.unwrap();

        // Preview must be on a char boundary and strictly < 200 bytes
        // (boundary floor backed off from 200 to 198 to avoid the mid-char cut)
        assert!(
            r.input_preview.is_char_boundary(r.input_preview.len()),
            "preview must end on a char boundary"
        );
        assert!(
            r.input_preview.len() < 200,
            "preview must be < 200 bytes (backed off from mid-char at byte 200)"
        );
        assert_eq!(
            r.input_preview.len(),
            198,
            "preview should be exactly 198 bytes (198 ASCII 'a' chars before the crawl)"
        );
    }

    /// WS5b: iso_to_epoch_secs on malformed input — must not panic.
    /// Before the fix, fixed-index slicing s[0..4] panics on strings < 19 bytes.
    /// After: s.get(start..end).and_then(|x| x.parse().ok()).unwrap_or(0) returns 0.
    #[test]
    fn test_iso_to_epoch_malformed_does_not_panic() {
        use crate::models::iso_to_epoch_secs;
        // Empty string — all parses return 0, no panic
        assert_eq!(iso_to_epoch_secs(""), 0);
        // Non-numeric — all parses return 0, no panic
        assert_eq!(iso_to_epoch_secs("abc"), 0);
        // Truncated — year+month parse OK, day defaults to 1, no panic
        let truncated = iso_to_epoch_secs("2026-06");
        let full = iso_to_epoch_secs("2026-06-20T12:00:00");
        assert!(
            truncated < full,
            "truncated timestamp must produce a smaller epoch than the full one"
        );
    }
}
