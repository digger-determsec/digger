use digger_evidence::{canonicalize, sha256_hex};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::source::{MonitorSource, Revision};

// ── Chain State ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainType {
    #[serde(rename = "evm")]
    Evm,
    #[serde(rename = "solana")]
    Solana,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvmState {
    pub address: String,
    pub code_hash: String,
    pub implementation_address: Option<String>,
    pub admin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolanaState {
    pub program_id: String,
    pub program_data_hash: String,
    pub upgrade_authority: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainState {
    #[serde(rename = "evm")]
    Evm(EvmState),
    #[serde(rename = "solana")]
    Solana(SolanaState),
}

impl ChainState {
    pub fn chain_type(&self) -> ChainType {
        match self {
            ChainState::Evm(_) => ChainType::Evm,
            ChainState::Solana(_) => ChainType::Solana,
        }
    }

    pub fn canonical_hash(&self) -> String {
        let canonical =
            canonicalize(&serde_json::to_value(self).unwrap_or(serde_json::Value::Null));
        sha256_hex(canonical.as_bytes())
    }
}

// ── State Changes ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StateChange {
    ImplementationChanged {
        old: String,
        new: String,
    },
    CodeHashChanged {
        old: String,
        new: String,
    },
    UpgradeAuthorityChanged {
        old: Option<String>,
        new: Option<String>,
    },
    AdminChanged {
        old: Option<String>,
        new: Option<String>,
    },
}

// ── Chain State Provider ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    #[error("network error: {0}")]
    NetworkError(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("target not found: {0}")]
    TargetNotFound(String),
    #[error("{0}")]
    Message(String),
}

impl From<String> for ProviderError {
    fn from(msg: String) -> Self {
        ProviderError::NetworkError(msg)
    }
}

pub trait ChainStateProvider: Send + Sync {
    fn get_state(&self, target_id: &str) -> Result<ChainState, ProviderError>;
    fn get_code(&self, target_id: &str) -> Result<String, ProviderError>;
}

// ── Mock Chain State Provider ──────────────────────────────────

pub struct MockChainStateProvider {
    states: BTreeMap<String, Vec<ChainState>>,
    codes: BTreeMap<String, Vec<String>>,
    current_index: BTreeMap<String, usize>,
}

impl MockChainStateProvider {
    pub fn new() -> Self {
        Self {
            states: BTreeMap::new(),
            codes: BTreeMap::new(),
            current_index: BTreeMap::new(),
        }
    }

    pub fn push_state(&mut self, target_id: &str, state: ChainState) {
        self.states
            .entry(target_id.to_string())
            .or_default()
            .push(state);
    }

    pub fn push_code(&mut self, target_id: &str, code: String) {
        self.codes
            .entry(target_id.to_string())
            .or_default()
            .push(code);
    }
}

impl Default for MockChainStateProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainStateProvider for MockChainStateProvider {
    fn get_state(&self, target_id: &str) -> Result<ChainState, ProviderError> {
        let states = self
            .states
            .get(target_id)
            .ok_or_else(|| ProviderError::TargetNotFound(format!("No state for {}", target_id)))?;
        let idx = self.current_index.get(target_id).copied().unwrap_or(0);
        if idx >= states.len() {
            return Err(ProviderError::TargetNotFound(format!(
                "No more states for {}",
                target_id
            )));
        }
        Ok(states[idx].clone())
    }

    fn get_code(&self, target_id: &str) -> Result<String, ProviderError> {
        let codes = self
            .codes
            .get(target_id)
            .ok_or_else(|| ProviderError::TargetNotFound(format!("No code for {}", target_id)))?;
        let idx = self.current_index.get(target_id).copied().unwrap_or(0);
        if idx >= codes.len() {
            return Err(ProviderError::TargetNotFound(format!(
                "No more code for {}",
                target_id
            )));
        }
        Ok(codes[idx].clone())
    }
}

impl MockChainStateProvider {
    pub fn advance(&mut self, target_id: &str) {
        let idx = self.current_index.entry(target_id.to_string()).or_insert(0);
        *idx += 1;
    }
}

// ── State Change Detection ─────────────────────────────────────

pub fn detect_state_changes(old: &ChainState, new: &ChainState) -> Vec<StateChange> {
    let mut changes = Vec::new();

    match (old, new) {
        (ChainState::Evm(old_evm), ChainState::Evm(new_evm)) => {
            if old_evm.code_hash != new_evm.code_hash {
                changes.push(StateChange::CodeHashChanged {
                    old: old_evm.code_hash.clone(),
                    new: new_evm.code_hash.clone(),
                });
            }
            if old_evm.implementation_address != new_evm.implementation_address {
                changes.push(StateChange::ImplementationChanged {
                    old: old_evm.implementation_address.clone().unwrap_or_default(),
                    new: new_evm.implementation_address.clone().unwrap_or_default(),
                });
            }
            if old_evm.admin != new_evm.admin {
                changes.push(StateChange::AdminChanged {
                    old: old_evm.admin.clone(),
                    new: new_evm.admin.clone(),
                });
            }
        }
        (ChainState::Solana(old_sol), ChainState::Solana(new_sol)) => {
            if old_sol.program_data_hash != new_sol.program_data_hash {
                changes.push(StateChange::CodeHashChanged {
                    old: old_sol.program_data_hash.clone(),
                    new: new_sol.program_data_hash.clone(),
                });
            }
            if old_sol.upgrade_authority != new_sol.upgrade_authority {
                changes.push(StateChange::UpgradeAuthorityChanged {
                    old: old_sol.upgrade_authority.clone(),
                    new: new_sol.upgrade_authority.clone(),
                });
            }
        }
        _ => {}
    }

    changes
}

// ── ChainStateSource (implements MonitorSource) ────────────────

pub struct ChainStateSource {
    provider: Box<dyn ChainStateProvider>,
    target_id: String,
    last_state: Option<ChainState>,
}

impl ChainStateSource {
    pub fn new(provider: Box<dyn ChainStateProvider>, target_id: String) -> Self {
        Self {
            provider,
            target_id,
            last_state: None,
        }
    }

    pub fn last_state(&self) -> Option<&ChainState> {
        self.last_state.as_ref()
    }
    pub fn provider(&self) -> &dyn ChainStateProvider {
        self.provider.as_ref()
    }

    pub fn detect_changes(&self) -> Vec<StateChange> {
        match self.provider.get_state(&self.target_id) {
            Ok(new_state) => {
                if let Some(ref old) = self.last_state {
                    detect_state_changes(old, &new_state)
                } else {
                    vec![]
                }
            }
            Err(_) => vec![],
        }
    }
}

impl MonitorSource for ChainStateSource {
    fn current_revision(&self) -> Option<Revision> {
        let state = self.provider.get_state(&self.target_id).ok()?;
        let hash = state.canonical_hash();
        Some(Revision {
            id: hash.clone(),
            content_hash: hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hash_is_deterministic_and_stable() {
        let state = ChainState::Evm(EvmState {
            address: "0xabc".to_string(),
            code_hash: "0xdeadbeef".to_string(),
            implementation_address: Some("0x111".to_string()),
            admin: None,
        });
        let h1 = state.canonical_hash();
        let h2 = state.canonical_hash();
        assert_eq!(h1, h2, "canonical hash must be deterministic");
        assert_eq!(h1.len(), 64, "sha256 hex digest must be 64 chars");

        let other = ChainState::Evm(EvmState {
            address: "0xabc".to_string(),
            code_hash: "0xcafe".to_string(),
            implementation_address: Some("0x111".to_string()),
            admin: None,
        });
        assert_ne!(h1, other.canonical_hash());
    }
}
