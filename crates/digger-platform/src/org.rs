/// Organization management — create, list, add members, check ownership.
use crate::models::now_iso;
use crate::models::*;
use crate::storage::{Storage, StorageError};
use uuid::Uuid;

pub struct OrgManager<'a> {
    store: &'a dyn Storage,
}

impl<'a> OrgManager<'a> {
    pub fn new(store: &'a dyn Storage) -> Self {
        Self { store }
    }

    pub fn create(&self, name: &str, owner_id: &str) -> Result<Organization, StorageError> {
        let now = now_iso();
        let org = Organization {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_id: owner_id.to_string(),
            members: vec![Member {
                user_id: owner_id.to_string(),
                role: Role::Owner,
                joined_at: now.clone(),
            }],
            created_at: now.clone(),
            updated_at: now,
        };
        let val = serde_json::to_value(&org)?;
        self.store.write_json("orgs", &org.id, &val)?;
        Ok(org)
    }

    pub fn get(&self, id: &str) -> Result<Organization, StorageError> {
        let val = self.store.read_json("orgs", id)?;
        Ok(serde_json::from_value(val)?)
    }

    pub fn list(&self) -> Vec<Organization> {
        self.store
            .list_all_json("orgs")
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect()
    }

    pub fn add_member(
        &self,
        org_id: &str,
        user_id: &str,
        role: Role,
    ) -> Result<Organization, StorageError> {
        let mut org = self.get(org_id)?;
        if org.members.iter().any(|m| m.user_id == user_id) {
            return Err("User is already a member".to_string().into());
        }
        org.members.push(Member {
            user_id: user_id.to_string(),
            role,
            joined_at: now_iso(),
        });
        org.updated_at = now_iso();
        let val = serde_json::to_value(&org)?;
        self.store.write_json("orgs", &org.id, &val)?;
        Ok(org)
    }

    pub fn remove_member(&self, org_id: &str, user_id: &str) -> Result<Organization, StorageError> {
        let mut org = self.get(org_id)?;
        org.members.retain(|m| m.user_id != user_id);
        org.updated_at = now_iso();
        let val = serde_json::to_value(&org)?;
        self.store.write_json("orgs", &org.id, &val)?;
        Ok(org)
    }

    pub fn check_access(&self, org_id: &str, user_id: &str) -> bool {
        self.get(org_id)
            .is_ok_and(|org| org.members.iter().any(|m| m.user_id == user_id))
    }

    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        self.store.delete("orgs", id)
    }
}
