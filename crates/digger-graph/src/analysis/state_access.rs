use digger_ir::StateEdge;
/// State Access Analyzer — deterministic structural state access detection.
///
/// Replaces substring-based state mutation detection with a structural
/// analyzer that detects:
/// - Simple writes: `name = value`
/// - Compound writes: `name += value`, `name -= value`
/// - Indexed writes: `name[key] = value`
/// - Struct field writes: `self.name = value`
/// - Member writes: `account.name = value`
/// - Delete operations: `delete name[key]`
///
/// # Rules
///
/// 1. Deterministic: same input → same output
/// 2. No AI, no heuristics, no regex-only solution
/// 3. Backward compatible with existing graph engine
/// 4. All output sorted for determinism
use digger_parser::model::RawProgram;
use serde::{Deserialize, Serialize};

/// Type of state access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateAccessType {
    Read,
    Write,
}

impl std::fmt::Display for StateAccessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
        }
    }
}

/// A detected state access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAccess {
    pub state_name: String,
    pub access_type: StateAccessType,
    pub function_name: String,
    pub evidence: String,
}

/// Result of state access analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAccessResult {
    pub reads: Vec<StateAccess>,
    pub writes: Vec<StateAccess>,
    pub summary: StateAccessSummary,
}

/// Summary of state access analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateAccessSummary {
    pub total_reads: usize,
    pub total_writes: usize,
    pub total_accesses: usize,
    pub state_vars_read: Vec<String>,
    pub state_vars_written: Vec<String>,
}

/// Analyze state access patterns from RawProgram.
///
/// This is the ONLY entry point. Deterministic: same input → same output.
pub fn analyze_state_access(program: &RawProgram) -> StateAccessResult {
    let mut reads = vec![];
    let mut writes = vec![];

    for func in &program.functions {
        for state in &program.state {
            let body = &func.body;

            // Find all occurrences with identifier boundary checks
            let accesses = find_state_accesses(body, &state.name);

            for access in accesses {
                if access.is_write {
                    writes.push(StateAccess {
                        state_name: state.name.clone(),
                        access_type: StateAccessType::Write,
                        function_name: func.name.clone(),
                        evidence: access.evidence,
                    });
                } else {
                    reads.push(StateAccess {
                        state_name: state.name.clone(),
                        access_type: StateAccessType::Read,
                        function_name: func.name.clone(),
                        evidence: format!("{} referenced in body", state.name),
                    });
                }
            }
        }
    }

    // Sort for deterministic output
    reads.sort_by(|a, b| (&a.state_name, &a.function_name).cmp(&(&b.state_name, &b.function_name)));
    writes
        .sort_by(|a, b| (&a.state_name, &a.function_name).cmp(&(&b.state_name, &b.function_name)));

    let mut state_vars_read: Vec<String> = reads.iter().map(|a| a.state_name.clone()).collect();
    state_vars_read.sort();
    state_vars_read.dedup();

    let mut state_vars_written: Vec<String> = writes.iter().map(|a| a.state_name.clone()).collect();
    state_vars_written.sort();
    state_vars_written.dedup();

    let summary = StateAccessSummary {
        total_reads: reads.len(),
        total_writes: writes.len(),
        total_accesses: reads.len() + writes.len(),
        state_vars_read,
        state_vars_written,
    };

    StateAccessResult {
        reads,
        writes,
        summary,
    }
}

/// Convert StateAccessResult to StateEdge list for graph engine compatibility.
pub fn to_state_edges(result: &StateAccessResult) -> Vec<StateEdge> {
    let mut edges = vec![];

    for access in result.reads.iter().chain(result.writes.iter()) {
        edges.push(StateEdge {
            function: access.function_name.clone(),
            state: access.state_name.clone(),
            access: access.access_type.to_string(),
        });
    }

    edges
}

// ─────────────────────────────────────────────────────────────
// Internal: Access detection
// ─────────────────────────────────────────────────────────────

/// Result of a single state access detection.
struct AccessDetection {
    is_write: bool,
    evidence: String,
}

/// Find all state accesses in body for a given state variable.
///
/// Uses identifier boundary checking to prevent false positives.
fn find_state_accesses(body: &str, state_name: &str) -> Vec<AccessDetection> {
    let mut results = vec![];
    let mut pos = 0;

    while let Some(idx) = body[pos..].find(state_name) {
        let abs_idx = pos + idx;

        // Check identifier boundary: character before must not be alphanumeric or underscore
        if abs_idx > 0 {
            let before_char = body.as_bytes()[abs_idx - 1] as char;
            if before_char.is_alphanumeric() || before_char == '_' {
                pos = abs_idx + state_name.len();
                continue;
            }
        }

        // Check identifier boundary: character after must not be alphanumeric or underscore
        let after_name = abs_idx + state_name.len();
        if after_name < body.len() {
            let after_char = body.as_bytes()[after_name] as char;
            if after_char.is_alphanumeric() || after_char == '_' {
                pos = after_name;
                continue;
            }
        }

        // Check for `delete` keyword before the state name
        if is_delete_context(body, abs_idx) {
            let end = find_statement_end(body, abs_idx);
            let evidence = body[abs_idx..end.min(body.len())].to_string();
            results.push(AccessDetection {
                is_write: true,
                evidence: format!("delete {}", evidence),
            });
            pos = after_name;
            continue;
        }

        // Check what follows the state name
        if after_name < body.len() {
            let rest = &body[after_name..];

            if is_write_pattern(rest) {
                let end = find_statement_end(body, abs_idx);
                let evidence = body[abs_idx..end.min(body.len())].to_string();
                results.push(AccessDetection {
                    is_write: true,
                    evidence,
                });
            } else {
                results.push(AccessDetection {
                    is_write: false,
                    evidence: format!("{} referenced in body", state_name),
                });
            }
        }

        pos = after_name;
    }

    results
}

/// Check if the state name is in a `delete` context.
///
/// Handles:
/// - `delete balances[user]`
/// - `delete self.balance`
/// - `delete account.balance`
fn is_delete_context(body: &str, state_pos: usize) -> bool {
    // Look backwards from state_pos for the `delete` keyword
    let before = &body[..state_pos];
    let trimmed = before.trim_end();

    // Direct: delete name
    if trimmed.ends_with("delete") {
        return true;
    }

    // Member access: delete self.name, delete account.name
    // Check for pattern: delete <identifier>.
    if trimmed.ends_with('.') {
        let without_dot = trimmed.trim_end_matches('.');
        let parts: Vec<&str> = without_dot.split_whitespace().collect();
        // Check if "delete" is one of the words before the dot
        if parts.iter().any(|p| *p == "delete") {
            return true;
        }
    }

    false
}

/// Check if the text after a variable name is a write pattern.
///
/// Handles:
/// - Simple assignment: `= value` (not `==`)
/// - Compound assignment: `+=`, `-=`, `*=`, `/=`, `%=`
/// - Indexed write: `[key] = value`
/// - Nested indexed write: `[key1][key2] = value`
fn is_write_pattern(text: &str) -> bool {
    let trimmed = text.trim_start();

    // Direct assignment: = (but not ==)
    if trimmed.starts_with('=') && !trimmed.starts_with("==") {
        return true;
    }

    // Compound assignment: +=, -=, *=, /=, %=
    if trimmed.starts_with("+=")
        || trimmed.starts_with("-=")
        || trimmed.starts_with("*=")
        || trimmed.starts_with("/=")
        || trimmed.starts_with("%=")
    {
        return true;
    }

    // Indexed write: [key] = or [key] += etc.
    // Also handles nested: [key1][key2] = value
    if trimmed.starts_with('[') {
        return is_indexed_write(trimmed);
    }

    false
}

/// Check if an indexed expression is a write.
///
/// Handles nested brackets: `[key1][key2] = value`
fn is_indexed_write(text: &str) -> bool {
    let mut pos = 0;
    let bytes = text.as_bytes();

    // Skip through all bracket pairs
    while pos < bytes.len() && bytes[pos] == b'[' {
        // Find matching closing bracket
        let mut depth = 0;
        let mut i = pos;
        while i < bytes.len() {
            match bytes[i] {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        pos = i + 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if depth != 0 {
            return false; // Unbalanced brackets
        }

        // Skip whitespace
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }

        // Check if next char is [ (nested) or assignment
        if pos < bytes.len() && bytes[pos] == b'[' {
            continue; // nested bracket
        }

        break;
    }

    // After brackets, check for assignment
    if pos < bytes.len() {
        let rest = &text[pos..];
        let trimmed = rest.trim_start();
        if (trimmed.starts_with('=') && !trimmed.starts_with("=="))
            || trimmed.starts_with("+=")
            || trimmed.starts_with("-=")
            || trimmed.starts_with("*=")
            || trimmed.starts_with("/=")
            || trimmed.starts_with("%=")
        {
            return true;
        }
    }

    false
}

/// Find the end of a statement (semicolon or newline).
fn find_statement_end(body: &str, start: usize) -> usize {
    for (i, ch) in body[start..].char_indices() {
        if ch == ';' || ch == '\n' {
            return start + i;
        }
    }
    body.len()
}

/// Detect external calls in body.
pub fn has_external_call(body: &str) -> bool {
    body.contains(".call")
        || body.contains(".call(")
        || body.contains(".call{")
        || body.contains(".delegatecall")
        || body.contains(".staticcall")
        || body.contains("invoke(")
        || body.contains("invoke_signed(")
}

/// Detect authority checks in body.
pub fn has_authority_check(body: &str) -> bool {
    body.contains("require")
        || body.contains("assert")
        || body.contains("is_signer")
        || body.contains("has_one")
        || body.contains("msg.sender")
        || contains_word(body, "signer")
        || contains_word(body, "Signer")
}

/// Check if body contains a word as a standalone token (not part of a larger identifier).
fn contains_word(body: &str, word: &str) -> bool {
    if let Some(start) = body.find(word) {
        let before_ok = start == 0 || !body.as_bytes()[start - 1].is_ascii_alphanumeric();
        let end = start + word.len();
        let after_ok = end >= body.len() || !body.as_bytes()[end].is_ascii_alphanumeric();
        before_ok && after_ok
    } else {
        false
    }
}
