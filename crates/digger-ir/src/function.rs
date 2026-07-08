use crate::{Effects, Type, Visibility};

/// An executable unit of code.
///
/// This is the universal primitive for anything that can be invoked.
/// All language frontends MUST reduce their constructs to this type.
///
/// See [`ExecutableUnit`](crate::types::ExecutableUnit) for language mapping rules.
#[derive(Debug, Clone)]
pub struct Function {
    /// Unique identifier within the program.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Contract/module this function belongs to (empty string for free functions).
    pub contract: String,
    /// Who can invoke this unit.
    pub visibility: Visibility,
    /// Input parameter types.
    pub inputs: Vec<Type>,
    /// Output types.
    pub outputs: Vec<Type>,
    /// Applied modifiers/guards (names only).
    pub modifiers: Vec<String>,
    /// What this unit does — used by hypothesis engine.
    pub effects: Effects,
}
