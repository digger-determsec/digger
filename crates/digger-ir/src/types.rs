/// A type reference within the IR.
///
/// Used to represent input/output parameter types in functions
/// and type annotations on state variables.
#[derive(Debug, Clone)]
pub struct Type {
    pub name: String,
}

// ─────────────────────────────────────────────────────────────
// Universal IR Primitives — Language-Agnostic Type Aliases
//
// These aliases establish the canonical semantic model that ALL
// language frontends must reduce to before reaching the graph engine.
//
// The graph engine is FROZEN. It consumes:
//   - functions (as ExecutableUnit)
//   - state     (as StorageUnit)
//   - calls     (as CallEdge)
//   - edges     (as semantic Edge variants)
//
// When adding a new language (Rust, Anchor, Move, CosmWasm):
//   1. Parse language-specific AST
//   2. Normalize into ExecutableUnit / StorageUnit / CallEdge
//   3. Populate RawProgram (which maps to SystemIR)
//   4. Language-specific details go ONLY into metadata
//
// NEVER add language-specific fields to SystemIR.
// NEVER add new core IR types for a specific language.
// NEVER put graph-relevant data in metadata.
// ─────────────────────────────────────────────────────────────

/// An executable unit of code — the universal primitive for anything
/// that can be called, invoked, or executed.
///
/// Language mapping:
///   Solidity: function, constructor, fallback, receive, modifier
///   Rust:     fn, method, associated fn, closure (if named)
///   Anchor:   instruction handler (pub fn in #[program] mod)
///   Move:     script function, public function
///   CosmWasm: execute handler, query handler, migrate handler
///
/// Fields:
///   id/name   — unique identifier within the program
///   visibility — who can call this unit (public/private/internal/external)
///   body       — source code for pattern matching (authority, state, calls)
///
/// The graph builder pattern-matches on `body` to detect:
///   - State mutations (contains "=", "+=", "-=")
///   - External calls (contains ".call", "invoke")
///   - Authority checks (contains "require", "signer", "has_one")
///   - Value transfers (contains "transfer", "value")
///
/// If a language construct cannot be reduced to a single body string,
/// it must be split into multiple ExecutableUnits or use metadata.
pub type ExecutableUnit = crate::function::Function;

/// A unit of persistent storage — the universal primitive for anything
/// that holds state across transactions.
///
/// Language mapping:
///   Solidity: state variable (mapping, address, uint, etc.)
///   Rust:     static, const (if mutable context), struct field
///   Anchor:   account struct field (simplified)
///   Move:     resource field
///   CosmWasm: state item, state map entry
///
/// Fields:
///   id/name — unique identifier within the program
///   ty      — type representation (used for pattern matching)
///
/// The graph builder checks if ExecutableUnit bodies reference
/// StorageUnit names to detect read/write access patterns.
pub type StorageUnit = crate::state::StateVariable;

/// The top-level IR — a complete program representation.
///
/// Contains:
///   - All ExecutableUnits (functions/methods/handlers)
///   - All StorageUnits (state variables/accounts)
///   - All Edges (call, state, authority, external relationships)
///
/// This is the STABLE CONTRACT between parser and graph engine.
/// Do NOT add fields to this struct for language-specific features.
pub type ProgramIR = crate::system::SystemIR;
