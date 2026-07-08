/// Language-agnostic call classification.
///
/// Replaces EVM-specific strings (.call, delegatecall) and Solana-specific
/// strings (invoke, invoke_signed) with a unified semantic model.
///
/// Parsers populate this; graph engine and hypothesis engine consume it.
///
/// # Language Mapping
///
/// | Language  | Pattern                    | CallKind       |
/// |-----------|----------------------------|----------------|
/// | Solidity  | `.call`, `.delegatecall`   | External       |
/// | Solidity  | `.staticcall`              | External       |
/// | Solidity  | `.transfer`                | External       |
/// | Solana    | `invoke`, `invoke_signed`  | CrossProgram   |
/// | Anchor    | `CpiContext`               | CrossProgram   |
/// | Rust      | `module::function()`       | Internal       |
/// | Any       | direct call in same scope  | Internal       |
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallKind {
    /// External call to another contract/program via low-level mechanism.
    External,

    /// Cross-program invocation — calling into a different program/contract.
    CrossProgram,

    /// Internal call within the same program/contract.
    Internal,

    /// Call classification unknown or not yet determined.
    #[default]
    Unknown,
}

/// A call relationship between two executable units.
///
/// Represents "from calls to" — the most basic call graph edge.
/// Language-agnostic: works for Solidity functions, Rust methods,
/// Anchor instructions, Move functions, etc.
#[derive(Debug, Clone)]
pub struct CallEdge {
    /// Caller's name (must match an ExecutableUnit name).
    pub from: String,
    /// Callee's name (must match an ExecutableUnit name or be "external").
    pub to: String,
}

/// A state access relationship.
///
/// Records that an executable unit reads or writes a storage unit.
/// The graph builder detects this by pattern-matching function bodies
/// against state variable names.
#[derive(Debug, Clone)]
pub struct StateEdge {
    /// The executable unit that accesses state.
    pub function: String,
    /// The storage unit being accessed.
    pub state: String,
    /// Access type: "read" or "write".
    pub access: String,
}

/// An authority check relationship.
///
/// Records whether an executable unit enforces an authority constraint.
/// The graph builder detects this by looking for patterns like
/// "require", "assert", "signer", "has_one", "Signer" in function bodies.
#[derive(Debug, Clone)]
pub struct AuthorityEdge {
    /// The executable unit being checked.
    pub function: String,
    /// Source of authority: "signer", "pda", "msg_sender", "unknown".
    pub authority_source: String,
    /// Whether the check is enforced: "enforced", "missing", "implicit".
    pub check_type: String,
}

/// An external dependency relationship.
///
/// Records that an executable unit makes calls outside the program.
/// This is the primary signal for reentrancy, trust boundary, and
/// cross-program interaction analysis.
#[derive(Debug, Clone)]
pub struct ExternalCallEdge {
    /// The executable unit making the external call.
    pub function: String,
    /// The external target (contract name, "external", "cpi", etc.).
    pub target: String,
    /// Risk indicators: ["external_call"], ["cpi"], ["cpi", "signed"], etc.
    pub risk_flags: Vec<String>,
}

/// All semantic edge types in the IR.
///
/// The hypothesis engine matches on these variants to generate findings.
/// This enum is FROZEN — do not add language-specific variants.
#[derive(Debug, Clone)]
pub enum Edge {
    /// "A calls B" relationship.
    Call(CallEdge),
    /// "A reads/writes B" relationship.
    State(StateEdge),
    /// "A has/misses authority check" relationship.
    Authority(AuthorityEdge),
    /// "A depends on external B" relationship.
    External(ExternalCallEdge),
}

impl std::fmt::Display for CallKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::External => write!(f, "External"),
            Self::CrossProgram => write!(f, "CrossProgram"),
            Self::Internal => write!(f, "Internal"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}
