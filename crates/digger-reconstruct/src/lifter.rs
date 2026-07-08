//! Generic bytecode lifting abstraction (Gen5 A2 + pre-A3 refinements).
//!
//! The reconstruction engine depends ONLY on [`BytecodeLifter`]; it is never
//! coupled to EVM. Concrete lifters:
//!
//! ```text
//! BytecodeLifter
//!   |- EvmBytecodeLifter   (implemented)
//!   |- SolanaBpfLifter     (future)
//!   |- MoveBytecodeLifter  (future)
//!   |- WasmLifter          (future)
//! ```
//!
//! Lifters emit the canonical Recovered* objects below. Raw opcode parsing is
//! NOT part of this surface and must stay private to each concrete lifter.
//!
//! ## Pre-A3 refinements
//! * Every Recovered* node carries a deterministic, content-addressed `id`
//!   (`insn:` / `bb:` / `cfg:` / `dispatch:` / `sel:` / `dispatcher:`).
//!   Vector indices remain only as *local* CFG ordinals; cross-object
//!   references (e.g. future Research Graph nodes) MUST use the deterministic
//!   `id`, never the ordinal.
//! * Recovered entrypoints are first-class structured objects
//!   ([`RecoveredSelector`]) rather than raw hex. Future deterministic
//!   enrichment attaches by `id` WITHOUT changing reconstruction outputs.
//! * Dispatcher recovery records the exact deterministic [`RecoveryPattern`]
//!   responsible for recovery (explainability without heuristics).

use crate::digest::fnv1a_64;
use crate::provenance::Provenance;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetKind {
    Evm,
    SolanaBpf,
    Move,
    Wasm,
}

/// Deterministic, content-addressed identity for a recovered node.
///
/// The `id` is a pure function of the node's recovered content (never a vector
/// index, never wall-clock, never address-of). Equal content => equal id, so
/// future Research Graph nodes can reference recovered artifacts by `id`
/// stably across runs.
pub fn node_id(kind: &str, canon: &str) -> String {
    format!("{}:{}", kind, fnv1a_64(canon.as_bytes()))
}

/// The exact deterministic pattern that produced a recovery. This is structural
/// evidence, not a heuristic: `steps` lists the ordered, observed primitives the
/// lifter matched. It is blockchain-agnostic so each lifter can describe its own
/// dispatch/entry pattern, e.g.
///
/// * EVM dispatcher: `PUSH4`, `EQ`, `PUSH`, `JUMPI`
/// * Solana (future): instruction discriminator, program entrypoint,
///   CPI invocation, account access pattern
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPattern {
    /// Stable pattern family identifier, e.g. `evm.dispatcher.push4_eq_push_jumpi`.
    pub kind: String,
    /// Ordered deterministic primitives matched during recovery.
    pub steps: Vec<String>,
}

impl RecoveryPattern {
    pub fn new(kind: impl Into<String>, steps: &[&str]) -> Self {
        RecoveryPattern {
            kind: kind.into(),
            steps: steps.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredInstruction {
    /// Deterministic content-addressed id (`insn:<digest>`).
    pub id: String,
    pub offset: usize,
    pub mnemonic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operand: Option<String>,
    pub size: usize,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockTerminator {
    FallThrough,
    Jump { target: Option<usize> },
    ConditionalJump { target: Option<usize> },
    Stop,
    Return,
    Revert,
    Invalid,
    SelfDestruct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredBasicBlock {
    /// Deterministic content-addressed id (`bb:<digest>`).
    pub id: String,
    /// Local CFG ordinal. Internal topology only; NOT a cross-object reference.
    pub index: usize,
    pub start: usize,
    pub end: usize,
    pub instruction_offsets: Vec<usize>,
    pub terminator: BlockTerminator,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    FallThrough,
    Jump,
    BranchTaken,
    BranchNotTaken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgEdge {
    /// Local ordinals (internal topology).
    pub from: usize,
    pub to: usize,
    /// Deterministic block ids — the canonical cross-object reference.
    pub from_id: String,
    pub to_id: String,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredCFG {
    /// Deterministic content-addressed id (`cfg:<digest>`).
    pub id: String,
    pub entry: usize,
    pub blocks: Vec<RecoveredBasicBlock>,
    pub edges: Vec<CfgEdge>,
    pub provenance: Provenance,
}

/// A recovered entrypoint, as a first-class structured object.
///
/// For EVM this is a 4-byte function selector. Future metadata (resolved
/// signature, Engine-Knowledge name, ABI fragment) attaches deterministically
/// BY `id` in a later sub-phase and MUST NOT mutate this object — reconstruction
/// outputs stay stable. Solana's Anchor discriminators / native instruction
/// layouts will be modelled as analogous first-class objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredSelector {
    /// Deterministic content-addressed id (`sel:<digest>`).
    pub id: String,
    /// Canonical 0x-prefixed selector hex (e.g. `0xa9059cbb`).
    pub selector: String,
    /// Raw selector bytes (4 for EVM).
    pub bytes: Vec<u8>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchEntry {
    /// Deterministic content-addressed id (`dispatch:<digest>`).
    pub id: String,
    /// First-class structured entrypoint (not raw hex).
    pub selector: RecoveredSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_offset: Option<usize>,
    /// Local CFG ordinal of the target block (internal topology).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_block: Option<usize>,
    /// Deterministic id of the target block (canonical cross-object reference).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_block_id: Option<String>,
    /// The exact deterministic pattern responsible for this recovery.
    pub pattern: RecoveryPattern,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredDispatcher {
    /// Deterministic content-addressed id (`dispatcher:<digest>`).
    pub id: String,
    pub entries: Vec<DispatchEntry>,
    pub has_fallback: bool,
    /// The dispatch pattern family this dispatcher was recovered from.
    pub pattern: RecoveryPattern,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredSelectorSet {
    /// Deterministic content-addressed id (`selset:<digest>`).
    pub id: String,
    /// Structured entrypoint objects, sorted + deduped by canonical selector.
    pub selectors: Vec<RecoveredSelector>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiftedProgram {
    /// Deterministic content-addressed id (`program:<digest>`).
    pub id: String,
    pub target: TargetKind,
    pub instructions: Vec<RecoveredInstruction>,
    pub cfg: RecoveredCFG,
    pub dispatcher: RecoveredDispatcher,
    pub selectors: RecoveredSelectorSet,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LiftError {
    #[error("empty bytecode")]
    Empty,
}

/// Generic lifting interface. Reconstruction depends ONLY on this trait.
pub trait BytecodeLifter {
    fn target(&self) -> TargetKind;
    fn lift(&self, runtime_bytecode: &[u8]) -> Result<LiftedProgram, LiftError>;
}
