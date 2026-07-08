use crate::{Edge, Function, Language, StateVariable};

/// The complete program IR — the stable contract between parser and engines.
///
/// This struct is FROZEN. Do NOT add fields for language-specific features.
/// All language complexity MUST be reduced into the three universal primitives:
///   - `functions` → ExecutableUnit
///   - `state`     → StorageUnit
///   - `edges`     → semantic relationships
///
/// See [`ProgramIR`](crate::types::ProgramIR) for usage guidelines.
///
/// # Architecture
///
/// ```text
/// Language AST → Parser → RawProgram → Graph Builder → SystemIR → Hypothesis Engine
/// ```
///
/// The graph builder consumes RawProgram and produces SystemIR.
/// The hypothesis engine consumes SystemIR and produces findings.
/// Neither engine ever sees language-specific AST structures.
#[derive(Debug, Clone)]
pub struct SystemIR {
    /// Program identifier (filename, module name, etc.).
    pub program_id: String,
    /// Source language — for reporting only, not for engine logic.
    pub language: Language,
    /// All executable units (functions, methods, handlers).
    pub functions: Vec<Function>,
    /// All storage units (state variables, account fields).
    pub state: Vec<StateVariable>,
    /// All semantic edges (call, state, authority, external).
    pub edges: Vec<Edge>,
}
