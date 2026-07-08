//! Chain-agnostic recovered interface layer (Gen5 A3 / ADR-0013).
//!
//! Generation 5 reasons about *interfaces*, never blockchain-specific ABI
//! terminology. Reconstruction depends only on [`RecoveredInterface`] and the
//! [`InterfaceRecoverer`] trait:
//!
//! ```text
//! RecoveredInterface
//!   |- RecoveredAbi               (EVM)
//!   |- RecoveredInstructionLayout (Solana)
//!   |- RecoveredModuleInterface   (Move, future)
//!   |- RecoveredWasmInterface     (WASM, future)
//! ```
//!
//! A3.1 recovers DETERMINISTIC interface facts only and NEVER names. EVM
//! recovers function selectors plus syntactically-observed parameter/return
//! word layouts. Solana (populated in a later sub-phase) recovers Anchor
//! discriminators, instruction/account layouts, signer + writable/read-only
//! classification, and deterministically-derivable PDA relationships. Names are
//! never inferred for any chain.

use crate::lifter::{node_id, LiftedProgram, RecoveredSelector, TargetKind};
use crate::provenance::Provenance;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InterfaceKind {
    Evm,
    Solana,
    Move,
    Wasm,
}

/// Chain-agnostic recovered interface. Exactly one concrete `detail` variant is
/// populated; the reconstruction engine never matches on chain specifics beyond
/// this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredInterface {
    /// Deterministic content-addressed id (`iface:<digest>`).
    pub id: String,
    pub kind: InterfaceKind,
    pub detail: InterfaceDetail,
    pub provenance: Provenance,
}

impl RecoveredInterface {
    pub fn make_id(canon: &str) -> String {
        node_id("iface", canon)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceDetail {
    Evm(RecoveredAbi),
    Solana(RecoveredInstructionLayout),
    Move(RecoveredModuleInterface),
    Wasm(RecoveredWasmInterface),
}

// ---------------- EVM (A3.1, implemented) ----------------

/// Deterministic SYNTACTIC observation of which 32-byte calldata word slots a
/// function body reads. NOT type inference and NOT a name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterLayout {
    /// Distinct calldata word indices `k` observed via `PUSH (4 + 32k)` +
    /// `CALLDATALOAD`. Sorted, deduped. Empty when none observed.
    pub observed_word_slots: Vec<usize>,
    pub provenance: Provenance,
}

/// Deterministic observation of returned word count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnLayout {
    /// Number of 32-byte words returned, when deterministically observable from
    /// a `PUSH <len> PUSH <off> RETURN` immediate pattern (len % 32 == 0).
    /// `None` when not deterministically observable.
    pub observed_return_words: Option<usize>,
    pub provenance: Provenance,
}

/// A recovered EVM function: structured selector + observed parameter/return
/// layouts. NO name field — selectors are one-way hashes; any human name is a
/// LATER deterministic Engine-Knowledge enrichment attached by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredFunction {
    /// Deterministic content-addressed id (`fn:<digest>`).
    pub id: String,
    pub selector: RecoveredSelector,
    pub parameters: ParameterLayout,
    pub returns: ReturnLayout,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredAbi {
    /// Deterministic content-addressed id (`abi:<digest>`).
    pub id: String,
    pub functions: Vec<RecoveredFunction>,
    pub provenance: Provenance,
}

// ---------------- Solana (A3.1 shapes; population is a later sub-phase) ----------------

/// Deterministically-derivable PDA relationship facts (no names).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdaRelationship {
    /// Count of seeds deterministically observed for the PDA derivation.
    pub observed_seed_count: usize,
}

/// A recovered Solana account slot: position + signer/writable classification.
/// A first-class `RecoveredFact` (deterministic id + provenance).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredAccount {
    /// Deterministic content-addressed id (`acct:<digest>`).
    pub id: String,
    pub index: usize,
    pub is_signer: bool,
    pub is_writable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pda: Option<PdaRelationship>,
    pub provenance: Provenance,
}

/// A recovered Solana instruction: Anchor/native discriminator + account layout.
/// NO instruction name is inferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredSolanaInstruction {
    /// Deterministic content-addressed id (`six:<digest>`).
    pub id: String,
    /// Anchor 8-byte discriminator (or native layout discriminator bytes).
    pub discriminator: Vec<u8>,
    pub accounts: Vec<RecoveredAccount>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredInstructionLayout {
    /// Deterministic content-addressed id (`ixl:<digest>`).
    pub id: String,
    pub instructions: Vec<RecoveredSolanaInstruction>,
    pub provenance: Provenance,
}

// ---------------- Move / WASM (future) ----------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredModuleInterface {
    pub id: String,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredWasmInterface {
    pub id: String,
    pub provenance: Provenance,
}

/// Chain-agnostic interface recovery. Each concrete lifter family supplies a
/// recoverer; the reconstruction engine depends ONLY on this trait, never on a
/// specific chain's ABI concepts.
pub trait InterfaceRecoverer {
    fn target(&self) -> TargetKind;
    fn recover_interface(&self, program: &LiftedProgram) -> RecoveredInterface;
}
