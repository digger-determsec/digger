/// Normalization layer — maps language-specific AST to universal IR primitives.
///
/// # Architecture
///
/// ```text
/// Language AST
///      ↓
/// ┌─────────────────────────────────┐
/// │  Normalization Layer            │
/// │  (this module)                  │
/// │                                 │
/// │  AST → ExecutableUnit           │
/// │  AST → StorageUnit              │
/// │  AST → CallEdge                 │
/// │                                 │
/// │  Language details → metadata     │
/// └─────────────────────────────────┘
///      ↓
/// RawProgram (stable contract)
///      ↓
/// Graph Engine (frozen, unchanged)
/// ```
///
/// # Rules
///
/// 1. Every language construct MUST reduce to one of the three primitives
/// 2. If a construct cannot reduce cleanly, split into multiple primitives
/// 3. Language-specific details go ONLY into metadata
/// 4. metadata MUST NOT contain graph-relevant information
use crate::model::{AnalysisMetadata, RawProgram};

// ─────────────────────────────────────────────────────────────
// Normalization rules — documented per language
// ─────────────────────────────────────────────────────────────

/// Solidity normalization rules.
///
/// # AST → IR Mapping
///
/// | Solidity AST        | IR Primitive    | Notes                           |
/// |---------------------|-----------------|---------------------------------|
/// | `function`          | ExecutableUnit  | body = source code              |
/// | `constructor`       | ExecutableUnit  | name = "constructor"            |
/// | `fallback`          | ExecutableUnit  | name = "fallback"               |
/// | `receive`           | ExecutableUnit  | name = "receive"                |
/// | `modifier`          | ExecutableUnit  | name = modifier name            |
/// | `contract`          | metadata only   | ContractMeta                    |
/// | `interface`         | metadata only   | ContractMeta(kind="interface")  |
/// | `abstract contract` | metadata only   | ContractMeta(kind="abstract")   |
/// | `library`           | metadata only   | ContractMeta(kind="library")    |
/// | state variable      | StorageUnit     | name + ty                       |
/// | `mapping`           | StorageUnit     | ty = "mapping(K => V)"          |
/// | `event`             | metadata only   | EventMeta                       |
/// | `error`             | metadata only   | ErrorMeta                       |
/// | `struct`            | metadata only   | StructMeta                      |
/// | `enum`              | metadata only   | EnumMeta                        |
/// | inheritance         | metadata only   | ContractMeta.inheritance        |
/// | `.call`             | CallEdge        | kind=External, target="external"|
/// | `.delegatecall`     | CallEdge        | kind=External, target="delegate"|
/// | `.staticcall`       | CallEdge        | kind=External, target="static"  |
/// | `.transfer`         | CallEdge        | kind=External, target="transfer"|
pub const SOLIDITY_RULES: &str = "See module docs for normalize::solidity";

/// Rust normalization rules (implemented in `rust_syn.rs`).
///
/// # AST → IR Mapping
///
/// | Rust AST              | IR Primitive    | Notes                          |
/// |-----------------------|-----------------|--------------------------------|
/// | `fn`                  | ExecutableUnit  | body = reconstructed source    |
/// | `pub fn`              | ExecutableUnit  | visibility = "public"          |
/// | `fn` (in impl)        | ExecutableUnit  | name = "Type::method"          |
/// | `fn` (in trait impl)  | ExecutableUnit  | name = "Type::method"          |
/// | `mod`                 | metadata only   | ContractMeta(kind="module")    |
/// | `impl`                | metadata only   | ContractMeta(kind="impl")      |
/// | `trait`               | metadata only   | ContractMeta(kind="trait")     |
/// | `struct`              | metadata only   | StructMeta                     |
/// | `enum`                | metadata only   | EnumMeta                       |
/// | `static mut`          | StorageUnit     | mutable static                 |
/// | `static` (immutable)  | metadata only   | StateMeta (immutable)          |
/// | `const`               | metadata only   | StateMeta (constant)           |
/// | `use`                 | metadata only   | using_directives               |
/// | function call         | CallEdge        | kind=Internal                  |
/// | external crate call   | CallEdge        | kind=CrossProgram              |
/// | `async fn`            | ExecutableUnit  | mutability="async" in metadata |
/// | macros                | opaque body     | never expanded                 |
///
/// # Key Decisions
///
/// - `impl` blocks are NOT ExecutableUnits — they contain ExecutableUnits
/// - `trait` definitions are metadata — trait impls produce ExecutableUnits
/// - Module boundaries are metadata — they don't affect execution semantics
/// - Lifetimes and generics are metadata — they don't affect call graph
/// - Macros are opaque — treated as body content, never expanded
/// - Async functions are normal ExecutableUnits (async is metadata only)
pub const RUST_RULES: &str = "See module docs for normalize::rust";

/// Anchor normalization rules.
///
/// # AST → IR Mapping
///
/// | Anchor AST              | IR Primitive    | Notes                         |
/// |-------------------------|-----------------|-------------------------------|
/// | `pub fn instruction()`  | ExecutableUnit  | body = source code            |
/// | `#[program] mod`        | metadata only   | ContractMeta(kind="program")  |
/// | `#[derive(Accounts)]`   | metadata only   | StructMeta (account struct)   |
/// | `#[account]`            | StorageUnit     | ty = "anchor_account"         |
/// | `Account<'info, T>`     | metadata only   | StateMeta (account constraint)|
/// | `Signer<'info>`         | metadata only   | authority detection via body  |
/// | `has_one` constraint    | metadata only   | authority detection via body  |
/// | `invoke`                | CallEdge        | kind=CrossProgram             |
/// | `invoke_signed`         | CallEdge        | kind=CrossProgram             |
/// | `CpiContext`            | CallEdge        | kind=CrossProgram             |
/// | `require!`              | body pattern    | authority detection via body  |
///
/// # Key Decisions
///
/// - Account constraints are metadata, NOT StorageUnit fields
/// - Authority detection happens via body pattern matching (graph engine)
/// - CPI detection happens via body pattern matching (graph engine)
/// - Anchor-specific types (AccountInfo, etc.) are metadata only
/// - The #[account] attribute produces a StorageUnit for the account itself
pub const ANCHOR_RULES: &str = "See module docs for normalize::anchor";

// ─────────────────────────────────────────────────────────────
// Validation — enforce IR contract and metadata boundaries
// ─────────────────────────────────────────────────────────────

/// Validation error — describes an IR contract violation.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{field}: {message}")]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

// ─────────────────────────────────────────────────────────────
// Metadata classification boundary — strict whitelist
//
// metadata = observational layer ONLY
// metadata = NOT semantic layer
// metadata = NOT reasoning layer
// metadata = NOT execution model
//
// If graph engine would need it → it does NOT belong in metadata.
// If hypothesis engine would need it → it does NOT belong in metadata.
// ─────────────────────────────────────────────────────────────

/// Strict whitelist for execution_context values.
///
/// These are SIMPLE CLASSIFICATION LABELS only.
/// They must NOT contain control flow, call semantics, or authority reasoning.
const VALID_EXECUTION_CONTEXTS: &[&str] = &[
    "free_fn",
    "impl_method",
    "trait_impl_method",
    "function",
    "constructor",
    "fallback",
    "receive",
    "modifier",
    "instruction_handler",
    "unknown",
];

/// Strict whitelist for rust_kind values.
///
/// This is a LANGUAGE FINGERPRINT only.
/// It must NOT contain execution semantics.
const VALID_RUST_KINDS: &[&str] = &["sync", "async"];

/// Strict whitelist for body_source_mode values.
///
/// This is TRACEABILITY INFORMATION only.
/// It must NOT contain body content or execution logic.
const VALID_BODY_SOURCE_MODES: &[&str] = &["reconstructed", "AST-derived", "fallback_regex"];

/// Forbidden semantic patterns — must NOT appear in ANY metadata value.
///
/// These patterns represent concepts that belong in the IR or engines,
/// not in the metadata annotation layer.
const FORBIDDEN_SEMANTIC_PATTERNS: &[&str] = &[
    // Call graph semantics — belongs in IR edges
    "call_graph",
    "call_edges",
    "call_chain",
    // Authority reasoning — belongs in hypothesis engine
    "authority_flow",
    "authority_check",
    "signer_verification",
    // Execution flow — belongs in graph engine
    "execution_flow",
    "control_flow",
    "data_flow",
    // Vulnerability inference — belongs in hypothesis engine
    "vulnerability",
    "reentrancy",
    "overflow",
    "underflow",
    "risk_score",
    "attack_vector",
    "exploit",
    // State mutation analysis — belongs in graph engine
    "mutation_analysis",
    "state_transition",
    "state_dependency",
];

/// Validate that a RawProgram conforms to the IR contract.
///
/// Checks:
/// 1. No empty function names
/// 2. No empty state variable names
/// 3. No empty call from/to
pub fn validate_raw_program(program: &RawProgram) -> Vec<ValidationError> {
    let mut errors = vec![];

    for f in &program.functions {
        if f.name.is_empty() {
            errors.push(ValidationError {
                field: "functions".into(),
                message: "ExecutableUnit has empty name".into(),
            });
        }
        if f.visibility.is_empty() {
            errors.push(ValidationError {
                field: format!("functions.{}", f.name),
                message: "ExecutableUnit has empty visibility".into(),
            });
        }
    }

    for s in &program.state {
        if s.name.is_empty() {
            errors.push(ValidationError {
                field: "state".into(),
                message: "StorageUnit has empty name".into(),
            });
        }
    }

    for c in &program.calls {
        if c.from.is_empty() {
            errors.push(ValidationError {
                field: "calls".into(),
                message: "CallEdge has empty 'from'".into(),
            });
        }
        if c.to.is_empty() {
            errors.push(ValidationError {
                field: format!("calls.{}", c.from),
                message: "CallEdge has empty 'to'".into(),
            });
        }
    }

    errors
}

/// Validate metadata discipline — strict boundary enforcement.
///
/// # Invariant
///
/// metadata = annotation layer ONLY
/// metadata ≠ semantic layer
/// metadata ≠ reasoning layer
/// metadata ≠ execution model
///
/// # What's allowed in metadata
/// - Descriptive classification (execution_context, rust_kind)
/// - Traceability information (body_source_mode, loss_of_precision)
/// - Language fingerprinting (container_path, mutability)
/// - Structural enrichment (contracts, events, structs, enums)
/// - Debugging hints, parser diagnostics
///
/// # What's NOT allowed in metadata
/// - Call semantics (who calls whom)
/// - Authority relationships (who checks what)
/// - State mutation patterns (who writes what)
/// - Execution flow data
/// - Vulnerability inference
/// - Control flow interpretation
/// - Any value that could be consumed by graph/hypothesis engine
pub fn validate_metadata_discipline(metadata: &AnalysisMetadata) -> Vec<ValidationError> {
    let mut errors = vec![];

    // ── 1. Validate extra map keys ──
    for key in metadata.extra.keys() {
        let lower = key.to_lowercase();
        for pattern in FORBIDDEN_SEMANTIC_PATTERNS {
            if lower.contains(pattern) {
                errors.push(ValidationError {
                    field: format!("metadata.extra.{}", key),
                    message: format!(
                        "Key '{}' contains forbidden semantic pattern '{}' — metadata must NOT contain reasoning data",
                        key, pattern
                    ),
                });
            }
        }
    }

    // ── 2. Validate function_details field values ──
    for (name, detail) in &metadata.function_details {
        // execution_context: strict whitelist
        let ctx = &detail.execution_context;
        if !ctx.is_empty() && !VALID_EXECUTION_CONTEXTS.contains(&ctx.as_str()) {
            errors.push(ValidationError {
                field: format!("function_details.{}.execution_context", name),
                message: format!(
                    "execution_context '{}' not in whitelist {:?} — must be a simple classification label",
                    ctx, VALID_EXECUTION_CONTEXTS
                ),
            });
        }

        // rust_kind: strict whitelist
        let kind = &detail.rust_kind;
        if !kind.is_empty() && !VALID_RUST_KINDS.contains(&kind.as_str()) {
            errors.push(ValidationError {
                field: format!("function_details.{}.rust_kind", name),
                message: format!(
                    "rust_kind '{}' not in whitelist {:?} — must be a language fingerprint only",
                    kind, VALID_RUST_KINDS
                ),
            });
        }

        // body_source_mode: strict whitelist
        let mode = &detail.body_source_mode;
        if !mode.is_empty() && !VALID_BODY_SOURCE_MODES.contains(&mode.as_str()) {
            errors.push(ValidationError {
                field: format!("function_details.{}.body_source_mode", name),
                message: format!(
                    "body_source_mode '{}' not in whitelist {:?} — must be traceability info only",
                    mode, VALID_BODY_SOURCE_MODES
                ),
            });
        }

        // container_path: must NOT contain semantic patterns
        let path = &detail.container_path;
        if !path.is_empty() {
            let lower = path.to_lowercase();
            for pattern in FORBIDDEN_SEMANTIC_PATTERNS {
                if lower.contains(pattern) {
                    errors.push(ValidationError {
                        field: format!("function_details.{}.container_path", name),
                        message: format!(
                            "container_path '{}' contains forbidden semantic pattern '{}' — must be structural only",
                            path, pattern
                        ),
                    });
                }
            }
        }
    }

    // ── 3. Validate metadata string values don't leak semantics ──
    // Scan all string values in extra for forbidden patterns
    for (key, value) in &metadata.extra {
        if let Some(s) = value.as_str() {
            let lower = s.to_lowercase();
            for pattern in FORBIDDEN_SEMANTIC_PATTERNS {
                if lower.contains(pattern) {
                    errors.push(ValidationError {
                        field: format!("metadata.extra.{}", key),
                        message: format!(
                            "Value contains forbidden semantic pattern '{}' — metadata values must NOT contain reasoning data",
                            pattern
                        ),
                    });
                }
            }
        }
    }

    errors
}

/// Check if an execution_context value is in the strict whitelist.
pub fn is_valid_execution_context(ctx: &str) -> bool {
    VALID_EXECUTION_CONTEXTS.contains(&ctx)
}

/// Check if a rust_kind value is in the strict whitelist.
pub fn is_valid_rust_kind(kind: &str) -> bool {
    VALID_RUST_KINDS.contains(&kind)
}

/// Check if a body_source_mode value is in the strict whitelist.
#[cfg(test)]
fn is_valid_body_source_mode(mode: &str) -> bool {
    VALID_BODY_SOURCE_MODES.contains(&mode)
}

/// Full validation — check both IR contract and metadata discipline.
pub fn validate(program: &RawProgram) -> Vec<ValidationError> {
    let mut errors = validate_raw_program(program);
    errors.extend(validate_metadata_discipline(&program.metadata));
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use digger_ir::CallKind;

    // ─────────────────────────────────────────────────────────────
    // IR contract validation
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_valid_program() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "deposit".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "balances[msg.sender] += msg.value".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "balances".into(),
                ty: "mapping".into(),
                ..Default::default()
            }],
            calls: vec![RawCall {
                from: "deposit".into(),
                to: "external".into(),
                kind: CallKind::External,
            }],
            ..Default::default()
        };

        let errors = validate(&program);
        assert!(
            errors.is_empty(),
            "Valid program should have no errors: {:?}",
            errors
        );
    }

    #[test]
    fn test_empty_function_name() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "test".into(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let errors = validate_raw_program(&program);
        assert!(!errors.is_empty(), "Empty function name should be caught");
        assert!(errors[0].field == "functions");
    }

    #[test]
    fn test_empty_call_from() {
        let program = RawProgram {
            calls: vec![RawCall {
                from: "".into(),
                to: "external".into(),
                kind: CallKind::External,
            }],
            ..Default::default()
        };

        let errors = validate_raw_program(&program);
        assert!(!errors.is_empty(), "Empty call 'from' should be caught");
    }

    // ─────────────────────────────────────────────────────────────
    // Metadata key validation — forbidden semantic patterns
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_metadata_key_forbidden_patterns() {
        let forbidden_keys = vec![
            "call_graph_data",
            "my_authority_flow",
            "execution_flow_info",
            "reentrancy_tracker",
            "data_flow_graph",
            "vulnerability_list",
            "mutation_analysis",
            "state_transitions",
            "signer_verification",
        ];

        for key in forbidden_keys {
            let mut metadata = AnalysisMetadata::default();
            metadata.extra.insert(key.into(), serde_json::json!(null));

            let errors = validate_metadata_discipline(&metadata);
            assert!(
                !errors.is_empty(),
                "Key '{}' should be caught as containing forbidden semantic pattern",
                key
            );
        }
    }

    #[test]
    fn test_metadata_clean_extra() {
        let mut metadata = AnalysisMetadata::default();
        metadata
            .extra
            .insert("parser_diagnostics".into(), serde_json::json!("ok"));
        metadata
            .extra
            .insert("ast_snapshot".into(), serde_json::json!({}));
        metadata
            .extra
            .insert("language_fingerprint".into(), serde_json::json!("rust"));

        let errors = validate_metadata_discipline(&metadata);
        assert!(
            errors.is_empty(),
            "Clean metadata should pass: {:?}",
            errors
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Metadata value validation — semantic leakage in values
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_metadata_value_forbidden_patterns() {
        // Values containing semantic patterns should be rejected
        let bad_values = vec![
            ("description", "function has call_graph dependency"),
            ("notes", "authority_flow detected here"),
            ("hint", "potential reentrancy in this path"),
            ("analysis", "control_flow shows loop"),
        ];

        for (key, value) in bad_values {
            let mut metadata = AnalysisMetadata::default();
            metadata.extra.insert(key.into(), serde_json::json!(value));

            let errors = validate_metadata_discipline(&metadata);
            assert!(
                !errors.is_empty(),
                "Value '{}' for key '{}' should be caught as semantic leakage",
                value,
                key
            );
        }
    }

    // ─────────────────────────────────────────────────────────────
    // execution_context whitelist enforcement
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_execution_context_whitelist_valid() {
        let valid = [
            "free_fn",
            "impl_method",
            "trait_impl_method",
            "function",
            "constructor",
            "fallback",
            "receive",
            "modifier",
            "instruction_handler",
            "unknown",
        ];
        for ctx in valid {
            assert!(
                is_valid_execution_context(ctx),
                "execution_context '{}' should be in whitelist",
                ctx
            );
        }
    }

    #[test]
    fn test_execution_context_whitelist_rejected() {
        let invalid = [
            "call_graph",
            "state_access",
            "authority",
            "reentrancy",
            "vulnerable",
            "safe",
            "risky",
            "custom_context",
        ];
        for ctx in invalid {
            assert!(
                !is_valid_execution_context(ctx),
                "execution_context '{}' should be rejected",
                ctx
            );
        }
    }

    #[test]
    fn test_execution_context_validation_in_function_details() {
        let mut metadata = AnalysisMetadata::default();
        metadata.function_details.insert(
            "test".into(),
            FunctionMeta {
                execution_context: "invalid_context".into(),
                ..Default::default()
            },
        );

        let errors = validate_metadata_discipline(&metadata);
        assert!(
            !errors.is_empty(),
            "Invalid execution_context should be caught"
        );
        assert!(errors[0].field.contains("execution_context"));
    }

    // ─────────────────────────────────────────────────────────────
    // rust_kind whitelist enforcement
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_rust_kind_whitelist_valid() {
        for kind in &["sync", "async"] {
            assert!(
                is_valid_rust_kind(kind),
                "rust_kind '{}' should be in whitelist",
                kind
            );
        }
    }

    #[test]
    fn test_rust_kind_whitelist_rejected() {
        let invalid = ["parallel", "concurrent", "blocking", "tokio", "custom"];
        for kind in invalid {
            assert!(
                !is_valid_rust_kind(kind),
                "rust_kind '{}' should be rejected",
                kind
            );
        }
    }

    #[test]
    fn test_rust_kind_validation_in_function_details() {
        let mut metadata = AnalysisMetadata::default();
        metadata.function_details.insert(
            "test".into(),
            FunctionMeta {
                rust_kind: "tokio".into(),
                ..Default::default()
            },
        );

        let errors = validate_metadata_discipline(&metadata);
        assert!(!errors.is_empty(), "Invalid rust_kind should be caught");
        assert!(errors[0].field.contains("rust_kind"));
    }

    // ─────────────────────────────────────────────────────────────
    // body_source_mode whitelist enforcement
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_body_source_mode_whitelist_valid() {
        for mode in &["reconstructed", "AST-derived", "fallback_regex"] {
            assert!(
                is_valid_body_source_mode(mode),
                "body_source_mode '{}' should be in whitelist",
                mode
            );
        }
    }

    #[test]
    fn test_body_source_mode_whitelist_rejected() {
        let invalid = ["raw", "parsed", "interpreted", "custom"];
        for mode in invalid {
            assert!(
                !is_valid_body_source_mode(mode),
                "body_source_mode '{}' should be rejected",
                mode
            );
        }
    }

    // ─────────────────────────────────────────────────────────────
    // container_path validation — no semantic patterns
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_container_path_forbidden_patterns() {
        let mut metadata = AnalysisMetadata::default();
        metadata.function_details.insert(
            "test".into(),
            FunctionMeta {
                container_path: "reentrancy::vulnerable::attack".into(),
                ..Default::default()
            },
        );

        let errors = validate_metadata_discipline(&metadata);
        assert!(
            !errors.is_empty(),
            "container_path with forbidden pattern should be caught"
        );
    }

    #[test]
    fn test_container_path_clean() {
        let mut metadata = AnalysisMetadata::default();
        metadata.function_details.insert(
            "test".into(),
            FunctionMeta {
                container_path: "crate::vault::Vault::deposit".into(),
                ..Default::default()
            },
        );

        let errors = validate_metadata_discipline(&metadata);
        assert!(
            errors.is_empty(),
            "Clean container_path should pass: {:?}",
            errors
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Full validation integration
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_full_validation_clean_program() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "deposit".into(),
                visibility: "public".into(),
                inputs: vec!["amount: u64".into()],
                body: "self.balance += amount".into(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let errors = validate(&program);
        assert!(
            errors.is_empty(),
            "Clean program should pass full validation: {:?}",
            errors
        );
    }
}
