use std::collections::BTreeMap;

use crate::onchain::ProviderError;
use crate::state::{MonitorState, WatchTarget};

pub trait MonitorStore: Send + Sync {
    fn get_state(&self, target_id: &str) -> Option<MonitorState>;
    fn save_state(&self, target_id: &str, state: &MonitorState) -> Result<(), ProviderError>;
    fn get_target(&self, target_id: &str) -> Option<WatchTarget>;
    fn save_target(&self, target_id: &str, target: &WatchTarget) -> Result<(), ProviderError>;
}

pub struct InMemoryMonitorStore {
    states: std::sync::Mutex<BTreeMap<String, MonitorState>>,
    targets: std::sync::Mutex<BTreeMap<String, WatchTarget>>,
}

impl InMemoryMonitorStore {
    pub fn new() -> Self {
        Self {
            states: std::sync::Mutex::new(BTreeMap::new()),
            targets: std::sync::Mutex::new(BTreeMap::new()),
        }
    }
}

impl Default for InMemoryMonitorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorStore for InMemoryMonitorStore {
    fn get_state(&self, target_id: &str) -> Option<MonitorState> {
        self.states
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(target_id)
            .cloned()
    }

    fn save_state(&self, target_id: &str, state: &MonitorState) -> Result<(), ProviderError> {
        self.states
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(target_id.to_string(), state.clone());
        Ok(())
    }

    fn get_target(&self, target_id: &str) -> Option<WatchTarget> {
        self.targets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(target_id)
            .cloned()
    }

    fn save_target(&self, target_id: &str, target: &WatchTarget) -> Result<(), ProviderError> {
        self.targets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(target_id.to_string(), target.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::MonitorState;

    #[test]
    fn store_recovers_from_poisoned_mutex() {
        let store = InMemoryMonitorStore::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.states.lock().unwrap();
            panic!("intentional poison");
        }));
        assert!(result.is_err());
        assert!(store.states.is_poisoned());

        assert!(store.get_state("t1").is_none());
        let state = MonitorState {
            last_revision: Some("r1".to_string()),
            ..MonitorState::default()
        };
        store.save_state("t1", &state).expect("save after poison");
        assert_eq!(
            store.get_state("t1").and_then(|s| s.last_revision),
            Some("r1".to_string())
        );

        let result2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.targets.lock().unwrap();
            panic!("intentional poison");
        }));
        assert!(result2.is_err());
        assert!(store.targets.is_poisoned());
        assert!(store.get_target("t1").is_none());
    }
}
