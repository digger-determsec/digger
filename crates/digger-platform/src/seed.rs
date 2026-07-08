/// Default workspace seeding.
///
/// Idempotently creates the canonical `personal` organization ("Personal
/// Workspace") and `my-research` project ("My Research"). Users must never be
/// forced to create an organization before scanning.
///
/// See `docs/architecture/01-platform-ownership.md` and ADR-0001.
use crate::models::{now_iso, Member, Organization, Project, ProjectSettings, Role};
use crate::storage::{Storage, StorageError};

/// Canonical default organization id. Never randomized.
pub const DEFAULT_ORG_ID: &str = "personal";
/// Canonical default project id. Never randomized.
pub const DEFAULT_PROJECT_ID: &str = "my-research";
/// Owner attributed to auto-seeded local records.
const DEFAULT_OWNER_ID: &str = "local";

/// Ensure the default Personal Workspace organization and My Research project
/// exist. Idempotent: existing records are never overwritten, so user edits
/// are preserved across restarts.
pub fn seed_defaults(store: &dyn Storage) -> Result<(), StorageError> {
    if !store.exists("orgs", DEFAULT_ORG_ID) {
        let now = now_iso();
        let org = Organization {
            id: DEFAULT_ORG_ID.to_string(),
            name: "Personal Workspace".to_string(),
            owner_id: DEFAULT_OWNER_ID.to_string(),
            members: vec![Member {
                user_id: DEFAULT_OWNER_ID.to_string(),
                role: Role::Owner,
                joined_at: now.clone(),
            }],
            created_at: now.clone(),
            updated_at: now,
        };
        let val = serde_json::to_value(&org)?;
        store.write_json("orgs", DEFAULT_ORG_ID, &val)?;
    }

    if !store.exists("projects", DEFAULT_PROJECT_ID) {
        let now = now_iso();
        let project = Project {
            id: DEFAULT_PROJECT_ID.to_string(),
            org_id: DEFAULT_ORG_ID.to_string(),
            name: "My Research".to_string(),
            description: "Default research project for quick scans.".to_string(),
            settings: ProjectSettings::default(),
            created_at: now.clone(),
            updated_at: now,
        };
        let val = serde_json::to_value(&project)?;
        store.write_json("projects", DEFAULT_PROJECT_ID, &val)?;
    }

    Ok(())
}
