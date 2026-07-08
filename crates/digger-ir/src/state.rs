/// A unit of persistent storage.
///
/// This is the universal primitive for anything that holds state.
/// All language frontends MUST reduce their storage constructs to this type.
///
/// See [`StorageUnit`](crate::types::StorageUnit) for language mapping rules.
#[derive(Debug, Clone)]
pub struct StateVariable {
    /// Unique identifier within the program.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Type representation (used for pattern matching by graph builder).
    pub ty: String,
    /// Whether this storage unit can be modified.
    pub mutable: bool,
}
