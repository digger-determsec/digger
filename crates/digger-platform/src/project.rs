/// Project management — create, list, update settings.
use crate::models::now_iso;
use crate::models::*;
use crate::storage::{Storage, StorageError};
use uuid::Uuid;

pub struct ProjectManager<'a> {
    store: &'a dyn Storage,
}

impl<'a> ProjectManager<'a> {
    pub fn new(store: &'a dyn Storage) -> Self {
        Self { store }
    }

    pub fn create(
        &self,
        org_id: &str,
        name: &str,
        description: &str,
    ) -> Result<Project, StorageError> {
        let now = now_iso();
        let project = Project {
            id: Uuid::new_v4().to_string(),
            org_id: org_id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            settings: ProjectSettings::default(),
            created_at: now.clone(),
            updated_at: now,
        };
        let val = serde_json::to_value(&project)?;
        self.store.write_json("projects", &project.id, &val)?;
        Ok(project)
    }

    pub fn get(&self, id: &str) -> Result<Project, StorageError> {
        let val = self.store.read_json("projects", id)?;
        Ok(serde_json::from_value(val)?)
    }

    pub fn list_for_org(&self, org_id: &str) -> Vec<Project> {
        self.store
            .list_all_json("projects")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Project>(v).ok())
            .filter(|p| p.org_id == org_id)
            .collect()
    }

    pub fn update_settings(
        &self,
        id: &str,
        settings: ProjectSettings,
    ) -> Result<Project, StorageError> {
        let mut project = self.get(id)?;
        project.settings = settings;
        project.updated_at = now_iso();
        let val = serde_json::to_value(&project)?;
        self.store.write_json("projects", &project.id, &val)?;
        Ok(project)
    }

    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        self.store.delete("projects", id)
    }
}
