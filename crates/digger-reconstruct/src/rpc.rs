//! RPC abstraction (ADR-0011). The sandbox has no internet, so retrieval is
//! behind a trait with deterministic providers: a fixture provider (for tests/
//! offline) and a raw-bytecode provider (caller supplies bytes directly).
//! A live JSON-RPC provider implements the same trait in CI.

use std::collections::BTreeMap;

/// Block reference. Reconstruction PINS to a concrete number for determinism;
/// `Latest` is only valid at request time and must be resolved before pinning.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BlockRef {
    Latest,
    Number(u64),
}

impl BlockRef {
    pub fn key(&self) -> String {
        match self {
            BlockRef::Latest => "latest".into(),
            BlockRef::Number(n) => n.to_string(),
        }
    }
}

/// Immutable retrieval coordinate. Address is lower-cased hex for stability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Coordinate {
    pub chain_id: u64,
    pub address: String,
    pub block: BlockRef,
}

impl Coordinate {
    pub fn new(chain_id: u64, address: &str, block: BlockRef) -> Self {
        Coordinate {
            chain_id,
            address: address.to_ascii_lowercase(),
            block,
        }
    }
    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.chain_id, self.address, self.block.key())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Minimal deterministic retrieval surface needed by address resolution (A3).
pub trait RpcProvider {
    fn get_code(&self, coord: &Coordinate) -> Result<Vec<u8>, RpcError>;
    /// Read a 32-byte storage slot (used for proxy implementation slots).
    fn get_storage_at(&self, coord: &Coordinate, slot: &str) -> Result<[u8; 32], RpcError>;
}

/// Deterministic, in-memory fixtures keyed by Coordinate / (Coordinate, slot).
#[derive(Debug, Default, Clone)]
pub struct FixtureRpcProvider {
    code: BTreeMap<String, Vec<u8>>,
    storage: BTreeMap<String, [u8; 32]>,
}

impl FixtureRpcProvider {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_code(mut self, coord: &Coordinate, code: Vec<u8>) -> Self {
        self.code.insert(coord.key(), code);
        self
    }
    pub fn with_storage(mut self, coord: &Coordinate, slot: &str, value: [u8; 32]) -> Self {
        self.storage.insert(
            format!("{}|{}", coord.key(), slot.to_ascii_lowercase()),
            value,
        );
        self
    }
}

impl RpcProvider for FixtureRpcProvider {
    fn get_code(&self, coord: &Coordinate) -> Result<Vec<u8>, RpcError> {
        self.code
            .get(&coord.key())
            .cloned()
            .ok_or_else(|| RpcError::NotFound(coord.key()))
    }
    fn get_storage_at(&self, coord: &Coordinate, slot: &str) -> Result<[u8; 32], RpcError> {
        let k = format!("{}|{}", coord.key(), slot.to_ascii_lowercase());
        self.storage.get(&k).cloned().ok_or(RpcError::NotFound(k))
    }
}

/// Bypasses addressing entirely: returns caller-supplied runtime bytecode.
/// Storage reads are unsupported (no proxy resolution on raw input).
#[derive(Debug, Clone)]
pub struct RawBytecodeProvider {
    bytecode: Vec<u8>,
}

impl RawBytecodeProvider {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
}

impl RpcProvider for RawBytecodeProvider {
    fn get_code(&self, _coord: &Coordinate) -> Result<Vec<u8>, RpcError> {
        Ok(self.bytecode.clone())
    }
    fn get_storage_at(&self, _coord: &Coordinate, _slot: &str) -> Result<[u8; 32], RpcError> {
        Err(RpcError::Unsupported(
            "raw bytecode provider has no storage".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_roundtrip() {
        let c = Coordinate::new(1, "0xAbC", BlockRef::Number(100));
        let p = FixtureRpcProvider::new().with_code(&c, vec![0x60, 0x80]);
        assert_eq!(p.get_code(&c).unwrap(), vec![0x60, 0x80]);
        // address is case-insensitive via lower-casing
        let c2 = Coordinate::new(1, "0xabc", BlockRef::Number(100));
        assert_eq!(p.get_code(&c2).unwrap(), vec![0x60, 0x80]);
    }
    #[test]
    fn raw_provider_ignores_address() {
        let p = RawBytecodeProvider::new(vec![1, 2, 3]);
        let c = Coordinate::new(1, "0x0", BlockRef::Latest);
        assert_eq!(p.get_code(&c).unwrap(), vec![1, 2, 3]);
        assert!(p.get_storage_at(&c, "0x0").is_err());
    }
}
