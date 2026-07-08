/// Artifact storage — persist and version all generated pipeline artifacts.
use crate::models::now_iso;
use crate::models::*;
use crate::storage::{Storage, StorageError};
use uuid::Uuid;

pub struct ArtifactManager<'a> {
    store: &'a dyn Storage,
}

impl<'a> ArtifactManager<'a> {
    pub fn new(store: &'a dyn Storage) -> Self {
        Self { store }
    }

    pub fn store(
        &self,
        scan_id: &str,
        project_id: &str,
        kind: ArtifactKind,
        name: &str,
        content: serde_json::Value,
    ) -> Result<Artifact, StorageError> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let content_str = serde_json::to_string(&content)?;
        let mut hasher = DefaultHasher::new();
        content_str.hash(&mut hasher);
        let content_hash = format!("{:x}", hasher.finish());

        let existing = self.list_for_scan(scan_id);
        let version = existing
            .iter()
            .filter(|a| a.kind == kind && a.name == name)
            .map(|a| a.version)
            .max()
            .unwrap_or(0)
            + 1;

        let artifact = Artifact {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            project_id: project_id.to_string(),
            kind,
            name: name.to_string(),
            version,
            content,
            content_hash,
            created_at: now_iso(),
        };
        let val = serde_json::to_value(&artifact)?;
        self.store.write_json("artifacts", &artifact.id, &val)?;
        Ok(artifact)
    }

    pub fn get(&self, id: &str) -> Result<Artifact, StorageError> {
        let val = self.store.read_json("artifacts", id)?;
        Ok(serde_json::from_value(val)?)
    }

    pub fn list_for_scan(&self, scan_id: &str) -> Vec<Artifact> {
        self.store
            .list_all_json("artifacts")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Artifact>(v).ok())
            .filter(|a| a.scan_id == scan_id)
            .collect()
    }

    pub fn list_for_project(&self, project_id: &str, limit: usize) -> Vec<Artifact> {
        let mut artifacts: Vec<Artifact> = self
            .store
            .list_all_json("artifacts")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Artifact>(v).ok())
            .filter(|a| a.project_id == project_id)
            .collect();
        artifacts.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        artifacts.truncate(limit);
        artifacts
    }

    pub fn get_version(
        &self,
        scan_id: &str,
        kind: &ArtifactKind,
        name: &str,
        version: u32,
    ) -> Result<Artifact, StorageError> {
        self.store
            .list_all_json("artifacts")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Artifact>(v).ok())
            .find(|a| {
                a.scan_id == scan_id && a.kind == *kind && a.name == name && a.version == version
            })
            .ok_or_else(|| format!("Artifact {} v{} not found", name, version).into())
    }

    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        self.store.delete("artifacts", id)
    }
}
