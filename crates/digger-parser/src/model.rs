use serde_json::Value;
use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────
// Semantic layer — consumed by graph builder and hypothesis engine
//
// These types represent analysis-ready facts extracted from source.
// They must be language-agnostic: no EVM-specific or Solana-specific
// naming in field names or type names.
// ─────────────────────────────────────────────────────────────

/// Top-level program representation after parsing.
///
/// Contains only the semantic data needed by the graph builder.
/// Language-specific AST enrichment lives in `metadata`.
#[derive(Debug, Clone)]
pub struct RawProgram {
    /// Extracted functions — the primary analysis units.
    pub functions: Vec<RawFunction>,
    /// Extracted state variables — tracked for state mutation analysis.
    pub state: Vec<RawState>,
    /// Extracted call relationships — feeds into call graph and external graph.
    pub calls: Vec<RawCall>,
    /// Ordered operations per function — for execution ordering analysis.
    pub operations: Vec<RawOperation>,
    /// Original source text — used for body extraction and future features.
    pub source: String,
    /// Language-specific AST enrichment — never consumed by graph/hypothesis engines.
    /// Parsers populate this; report layer may read it for display.
    pub metadata: AnalysisMetadata,
}

impl Default for RawProgram {
    fn default() -> Self {
        Self {
            functions: vec![],
            state: vec![],
            calls: vec![],
            operations: vec![],
            source: String::new(),
            metadata: AnalysisMetadata::default(),
        }
    }
}

/// A function extracted from source code.
///
/// Language-agnostic: the graph builder uses `name`, `body`, and `visibility`
/// for pattern matching. Language-specific details (mutability, modifiers, etc.)
/// live in the metadata bag.
#[derive(Debug, Clone)]
pub struct RawFunction {
    /// Function name or identifier.
    pub name: String,
    /// Contract/module this function belongs to (empty string for free functions).
    pub contract: String,
    /// Visibility: "public", "private", "internal", "external", "unknown".
    pub visibility: String,
    /// Parameter signatures as strings.
    pub inputs: Vec<String>,
    /// Source code body — used for pattern matching by graph builder.
    pub body: String,
    /// Whether the function body contains arithmetic operations (*, /, %)
    /// detected from the parsed AST (not text substring matching).
    pub has_arithmetic: bool,
}

impl Default for RawFunction {
    fn default() -> Self {
        Self {
            name: String::new(),
            contract: String::new(),
            visibility: "unknown".into(),
            inputs: vec![],
            body: String::new(),
            has_arithmetic: false,
        }
    }
}

/// A state variable extracted from source code.
///
/// Language-agnostic: the graph builder uses `name` and `ty` for
/// state mutation pattern matching.
#[derive(Debug, Clone)]
pub struct RawState {
    /// Variable name or identifier.
    pub name: String,
    /// Type representation as string.
    pub ty: String,
}

impl Default for RawState {
    fn default() -> Self {
        Self {
            name: String::new(),
            ty: String::new(),
        }
    }
}

/// A call relationship extracted from source code.
///
/// Uses `CallKind` for language-agnostic classification instead of
/// EVM-specific strings like ".call" or Solana-specific "invoke".
#[derive(Debug, Clone)]
pub struct RawCall {
    /// Calling function name.
    pub from: String,
    /// Target (function name, contract, or external).
    pub to: String,
    /// Language-agnostic call classification.
    pub kind: digger_ir::CallKind,
}

/// An ordered operation within a function body.
///
/// Represents the sequential execution order of operations.
/// Used for checks-effects-interactions analysis and ordering-aware reasoning.
#[derive(Debug, Clone, PartialEq)]
pub struct RawOperation {
    /// Function this operation belongs to.
    pub function: String,
    /// Sequence index within the function (0-based).
    pub index: usize,
    /// Operation kind.
    pub kind: OperationKind,
    /// Target or subject (state variable name, call target, etc.).
    pub target: String,
}

/// Kind of operation in a function body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OperationKind {
    /// State variable read.
    StateRead,
    /// State variable write.
    StateWrite,
    /// External call (any kind: .call, delegatecall, interface call, etc.).
    ExternalCall,
    /// Internal function call.
    InternalCall,
    /// Authority check (require, assert, signer check).
    AuthorityCheck,
    /// Value transfer.
    ValueTransfer,
}

impl std::fmt::Display for OperationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateRead => write!(f, "StateRead"),
            Self::StateWrite => write!(f, "StateWrite"),
            Self::ExternalCall => write!(f, "ExternalCall"),
            Self::InternalCall => write!(f, "InternalCall"),
            Self::AuthorityCheck => write!(f, "AuthorityCheck"),
            Self::ValueTransfer => write!(f, "ValueTransfer"),
        }
    }
}

impl Default for RawCall {
    fn default() -> Self {
        Self {
            from: String::new(),
            to: String::new(),
            kind: digger_ir::CallKind::Unknown,
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Metadata layer — AST enrichment, never consumed by engines
//
// This is the controlled escape hatch for language-specific data.
// Parsers populate it; report layer may read it.
// Graph engine and hypothesis engine NEVER touch this.
// ─────────────────────────────────────────────────────────────

/// Language-specific AST enrichment bag.
///
/// Holds structural data that parsers extract but the analysis engine
/// does not need. This prevents IR schema explosion when adding new
/// languages (Rust, Anchor, Move, CosmWasm).
///
/// Rules:
/// - Graph engine must NOT read from this
/// - Hypothesis engine must NOT read from this
/// - Parsers write to this
/// - Report layer may read from this for display
#[derive(Debug, Clone, Default)]
pub struct AnalysisMetadata {
    /// Contract/module definitions with inheritance and type info.
    pub contracts: Vec<ContractMeta>,
    /// Event definitions.
    pub events: Vec<EventMeta>,
    /// Custom error definitions.
    pub errors: Vec<ErrorMeta>,
    /// Struct definitions.
    pub structs: Vec<StructMeta>,
    /// Enum definitions.
    pub enums: Vec<EnumMeta>,
    /// Modifier definitions (Solidity) or similar guard patterns.
    pub modifiers: Vec<ModifierMeta>,
    /// Using directives, imports, or similar.
    pub using_directives: Vec<String>,
    /// Language-specific function enrichment (mutability, return types, etc.).
    pub function_details: BTreeMap<String, FunctionMeta>,
    /// Language-specific state variable enrichment.
    pub state_details: BTreeMap<String, StateMeta>,
    /// Arbitrary key-value escape hatch for future languages.
    pub extra: BTreeMap<String, Value>,
}

/// Contract or module metadata.
#[derive(Debug, Clone)]
pub struct ContractMeta {
    pub name: String,
    /// "contract", "interface", "abstract", "library", "module", "program"
    pub kind: String,
    pub inheritance: Vec<String>,
    pub function_names: Vec<String>,
    pub state_var_names: Vec<String>,
}

/// Event metadata.
#[derive(Debug, Clone)]
pub struct EventMeta {
    pub name: String,
    pub params: Vec<String>,
    pub anonymous: bool,
}

/// Custom error metadata.
#[derive(Debug, Clone)]
pub struct ErrorMeta {
    pub name: String,
    pub params: Vec<String>,
}

/// Struct metadata.
#[derive(Debug, Clone)]
pub struct StructMeta {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

/// Enum metadata.
#[derive(Debug, Clone)]
pub struct EnumMeta {
    pub name: String,
    pub values: Vec<String>,
}

/// Modifier or guard metadata.
#[derive(Debug, Clone)]
pub struct ModifierMeta {
    pub name: String,
    pub params: Vec<String>,
    pub body: String,
}

/// Per-function metadata enrichment.
///
/// This is the METADATA layer — never consumed by graph or hypothesis engines.
/// Parsers populate this with language-specific enrichment.
/// Report layer may read this for display.
#[derive(Debug, Clone, Default)]
pub struct FunctionMeta {
    /// Function type: "function", "constructor", "fallback", "receive", "modifier"
    pub fn_type: String,
    /// Mutability: "nonpayable", "payable", "view", "pure", "async"
    pub mutability: String,
    /// Modifier names applied to this function.
    pub modifiers: Vec<String>,
    /// Return type signatures.
    pub return_types: Vec<String>,

    // ── Rust-specific enrichment (metadata only) ──
    /// Execution context classification.
    /// Rust: "free_fn", "impl_method", "trait_impl_method"
    /// Solidity: "function", "constructor", "fallback", "receive", "modifier"
    /// Anchor: "instruction_handler"
    pub execution_context: String,

    /// Rust concurrency kind: "sync", "async"
    /// Other languages: empty or "nonpayable"
    pub rust_kind: String,

    /// Container path — the qualified path to this function.
    /// Rust: "crate::module::Type::method"
    /// Solidity: "ContractName.functionName"
    pub container_path: String,

    /// Body source extraction mode.
    /// "reconstructed" — body rebuilt from AST nodes (lossy)
    /// "AST-derived" — body extracted via span offsets (lossless)
    /// "fallback_regex" — body from regex parser (approximate)
    pub body_source_mode: String,

    /// Whether body reconstruction lost precision.
    /// true for reconstructed bodies (macros, complex expressions simplified)
    /// false for AST-derived or regex bodies
    pub loss_of_precision: bool,
}

/// Per-state-variable metadata enrichment.
#[derive(Debug, Clone, Default)]
pub struct StateMeta {
    /// Visibility: "public", "private", "internal"
    pub visibility: String,
    /// Whether the variable is constant.
    pub is_constant: bool,
    /// Whether the variable is immutable.
    pub is_immutable: bool,
}

// ── D-IR1: Per-account type + constraint binding ──────────────────

/// Wrapper type classification for Anchor account fields.
///
/// TYPED accounts have Anchor-validated discriminator + owner on deserialize.
/// RAW accounts have NO discriminator/owner validation — type-cosplay risk.
/// SIGNER is authorization-only, not a type/owner guard.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum AccountWrapperType {
    TYPED,
    RAW,
    SIGNER,
    UNKNOWN,
}

/// Structured constraint bound to a specific account field.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AccountConstraint {
    pub kind: String,
    pub target: String,
}

/// Per-account metadata for an Anchor #[derive(Accounts)] struct.
///
/// Captures the Rust type wrapper, structured constraints, and flags
/// for each account field. Stored in metadata.extra["anchor_accounts_{struct}"].
/// Detectors do NOT consume this yet — purely additive metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AccountModel {
    pub name: String,
    pub wrapper_type: AccountWrapperType,
    pub constraints: Vec<AccountConstraint>,
    pub is_init: bool,
    pub is_signer: bool,
}
