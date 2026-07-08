#![allow(clippy::needless_update, clippy::len_zero)]

/// State Access Analyzer Contract Tests — Phase 5.0 Deep Audit
///
/// These tests enforce the state access analyzer contract.
use digger_graph::analysis::state_access::*;
use digger_parser::model::*;

fn make_program(functions: Vec<RawFunction>, state: Vec<RawState>) -> RawProgram {
    RawProgram {
        functions,
        state,
        calls: vec![],
        ..Default::default()
    }
}

fn make_function(name: &str, body: &str) -> RawFunction {
    RawFunction {
        name: name.into(),
        visibility: "public".into(),
        inputs: vec![],
        body: body.into(),
        ..Default::default()
    }
}

fn make_state(name: &str, ty: &str) -> RawState {
    RawState {
        name: name.into(),
        ty: ty.into(),
        ..Default::default()
    }
}

// ─────────────────────────────────────────────────────────────
// 1. Delete pattern support
// ─────────────────────────────────────────────────────────────

#[test]
fn delete_mapping_detected_as_write() {
    let program = make_program(
        vec![make_function("clear", "delete balances[user]")],
        vec![make_state("balances", "mapping")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(
        result.writes.len(),
        1,
        "delete balances[user] must be detected as write"
    );
    assert_eq!(result.writes[0].state_name, "balances");
}

#[test]
fn delete_indexed_detected_as_write() {
    let program = make_program(
        vec![make_function("clear", "delete mapping[key]")],
        vec![make_state("mapping", "mapping")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(
        result.writes.len(),
        1,
        "delete mapping[key] must be detected as write"
    );
}

#[test]
fn delete_self_member_detected_as_write() {
    let program = make_program(
        vec![make_function("clear", "delete self.balance")],
        vec![make_state("balance", "u64")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(
        result.writes.len(),
        1,
        "delete self.balance must be detected as write"
    );
}

// ─────────────────────────────────────────────────────────────
// 2. Identifier boundary correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn variable_not_false_positive_in_larger_identifier() {
    // state var: x
    // code: max_value = 1
    // 'x' appears inside 'max_value' but should NOT be detected as access
    let program = make_program(
        vec![make_function("test", "max_value = 1")],
        vec![make_state("x", "u64")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(
        result.writes.len(),
        0,
        "x should NOT be detected in max_value"
    );
    assert_eq!(
        result.reads.len(),
        0,
        "x should NOT be detected in max_value"
    );
}

#[test]
fn variable_not_false_positive_as_suffix() {
    // state var: balance
    // code: totalBalance = 100
    let program = make_program(
        vec![make_function("test", "totalBalance = 100")],
        vec![make_state("balance", "u64")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(
        result.writes.len(),
        0,
        "balance should NOT be detected in totalBalance"
    );
}

#[test]
fn variable_not_false_positive_as_prefix() {
    // state var: data
    // code: database = connect()
    let program = make_program(
        vec![make_function("test", "database = connect()")],
        vec![make_state("data", "bytes")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(
        result.writes.len(),
        0,
        "data should NOT be detected in database"
    );
}

#[test]
fn variable_detected_with_underscore_boundary() {
    // state var: x
    // code: x_1 = 10 — x is followed by underscore, so NOT a match
    let program = make_program(
        vec![make_function("test", "x_1 = 10")],
        vec![make_state("x", "u64")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(result.writes.len(), 0, "x should NOT be detected in x_1");
}

#[test]
fn variable_detected_standalone() {
    // state var: x
    // code: x = 10 — exact match
    let program = make_program(
        vec![make_function("test", "x = 10")],
        vec![make_state("x", "u64")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(result.writes.len(), 1, "x should be detected as standalone");
}

#[test]
fn variable_detected_with_space_boundary() {
    // state var: x
    // code: let y = x + 1
    let program = make_program(
        vec![make_function("test", "let y = x + 1")],
        vec![make_state("x", "u64")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(
        result.reads.len(),
        1,
        "x should be detected with space boundary"
    );
}

// ─────────────────────────────────────────────────────────────
// 3. Nested indexed access
// ─────────────────────────────────────────────────────────────

#[test]
fn nested_indexed_write_detected() {
    let program = make_program(
        vec![make_function("set", "mapping[key1][key2] = value")],
        vec![make_state("mapping", "mapping")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(
        result.writes.len(),
        1,
        "mapping[key1][key2] = value must be detected as write"
    );
}

#[test]
fn nested_indexed_compound_write_detected() {
    let program = make_program(
        vec![make_function("inc", "balances[user][token] += amount")],
        vec![make_state("balances", "mapping")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(
        result.writes.len(),
        1,
        "balances[user][token] += amount must be detected as write"
    );
}

#[test]
fn nested_indexed_subtraction_detected() {
    let program = make_program(
        vec![make_function("dec", "balances[user][token] -= amount")],
        vec![make_state("balances", "mapping")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(
        result.writes.len(),
        1,
        "balances[user][token] -= amount must be detected as write"
    );
}

// ─────────────────────────────────────────────────────────────
// 4. Read/write classification audit
// ─────────────────────────────────────────────────────────────

#[test]
fn equality_is_read() {
    let program = make_program(
        vec![make_function("check", "require(owner == msg.sender)")],
        vec![make_state("owner", "address")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(result.writes.len(), 0);
    assert_eq!(result.reads.len(), 1);
}

#[test]
fn not_equal_is_read() {
    let program = make_program(
        vec![make_function("check", "require(owner != address(0))")],
        vec![make_state("owner", "address")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(result.writes.len(), 0);
    assert_eq!(result.reads.len(), 1);
}

#[test]
fn greater_equal_is_read() {
    let program = make_program(
        vec![make_function(
            "check",
            "require(balances[msg.sender] >= amount)",
        )],
        vec![make_state("balances", "mapping")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(result.writes.len(), 0);
    assert_eq!(result.reads.len(), 1);
}

#[test]
fn less_equal_is_read() {
    let program = make_program(
        vec![make_function(
            "check",
            "require(amount <= balances[msg.sender])",
        )],
        vec![make_state("balances", "mapping")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(result.writes.len(), 0);
    assert_eq!(result.reads.len(), 1);
}

#[test]
fn require_is_read() {
    let program = make_program(
        vec![make_function("check", "require(balances[user] > 0)")],
        vec![make_state("balances", "mapping")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(result.writes.len(), 0);
    assert_eq!(result.reads.len(), 1);
}

#[test]
fn assert_is_read() {
    let program = make_program(
        vec![make_function("check", "assert(owner != address(0))")],
        vec![make_state("owner", "address")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(result.writes.len(), 0);
    assert_eq!(result.reads.len(), 1);
}

// ─────────────────────────────────────────────────────────────
// 5. Determinism and ordering
// ─────────────────────────────────────────────────────────────

#[test]
fn deterministic_output() {
    let program = make_program(
        vec![make_function("test", "x = 1; y = 2")],
        vec![make_state("x", "u64"), make_state("y", "u64")],
    );

    let r1 = analyze_state_access(&program);
    let r2 = analyze_state_access(&program);
    let r3 = analyze_state_access(&program);

    assert_eq!(r1.summary, r2.summary);
    assert_eq!(r2.summary, r3.summary);
    assert_eq!(r1.writes.len(), r2.writes.len());
}

#[test]
fn stable_ordering() {
    let program = make_program(
        vec![
            make_function("fn_b", "x = 1"),
            make_function("fn_a", "x = 2"),
        ],
        vec![make_state("x", "u64")],
    );

    let result = analyze_state_access(&program);
    for i in 1..result.writes.len() {
        let prev = (
            &result.writes[i - 1].state_name,
            &result.writes[i - 1].function_name,
        );
        let curr = (
            &result.writes[i].state_name,
            &result.writes[i].function_name,
        );
        assert!(prev <= curr);
    }
}

// ─────────────────────────────────────────────────────────────
// 6. Backward compatibility
// ─────────────────────────────────────────────────────────────

#[test]
fn to_state_edges_produces_valid_edges() {
    let program = make_program(
        vec![make_function("test", "x = 1")],
        vec![make_state("x", "u64")],
    );
    let result = analyze_state_access(&program);
    let edges = to_state_edges(&result);

    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].function, "test");
    assert_eq!(edges[0].state, "x");
    assert_eq!(edges[0].access, "write");
}

#[test]
fn serialization_roundtrip() {
    let program = make_program(
        vec![make_function("test", "x = 1; y = 2")],
        vec![make_state("x", "u64"), make_state("y", "u64")],
    );
    let result = analyze_state_access(&program);
    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: StateAccessResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.writes.len(), result.writes.len());
    assert_eq!(deserialized.reads.len(), result.reads.len());
}

// ─────────────────────────────────────────────────────────────
// 7. Complex real-world patterns
// ─────────────────────────────────────────────────────────────

#[test]
fn real_world_withdraw_pattern() {
    let body = "require(balances[msg.sender] >= amount, \"Insufficient\"); (bool success, ) = msg.sender.call{value: amount}(\"\"); require(success); balances[msg.sender] -= amount;";
    let program = make_program(
        vec![make_function("withdraw", body)],
        vec![make_state("balances", "mapping")],
    );
    let result = analyze_state_access(&program);
    // balances appears multiple times: 2 reads (require, require) + 1 write (-=)
    // Actually: require(balances[msg.sender] >= amount) — read
    // balances[msg.sender] -= amount — write
    assert!(
        result.writes.len() >= 1,
        "Must detect balances write in withdraw"
    );
}

#[test]
fn real_world_deposit_pattern() {
    let body = "balances[msg.sender] += msg.value;";
    let program = make_program(
        vec![make_function("deposit", body)],
        vec![make_state("balances", "mapping")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(result.writes.len(), 1);
}

#[test]
fn real_world_constructor_pattern() {
    let body = "owner = msg.sender; paused = false;";
    let program = make_program(
        vec![make_function("constructor", body)],
        vec![make_state("owner", "address"), make_state("paused", "bool")],
    );
    let result = analyze_state_access(&program);
    assert_eq!(result.writes.len(), 2);
}

// ─────────────────────────────────────────────────────────────
// 8. Empty input handling
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_program_produces_empty_result() {
    let program = RawProgram::default();
    let result = analyze_state_access(&program);
    assert_eq!(result.reads.len(), 0);
    assert_eq!(result.writes.len(), 0);
    assert_eq!(result.summary.total_accesses, 0);
}
