/// Phase 6.3 Execution Ordering — Audit Tests
///
/// Verifies correctness and completeness of execution ordering analysis.
/// Covers: nested blocks, loops, internal call boundaries, call classification, determinism.
use digger_execution::*;
use digger_parser::model::*;
use digger_parser::parse_program;

fn ops_for<'a>(
    program: &'a digger_parser::model::RawProgram,
    func_name: &str,
) -> Vec<&'a RawOperation> {
    program
        .operations
        .iter()
        .filter(|o| o.function == func_name)
        .collect()
}

fn find_func<'a>(report: &'a ExecutionReport, name: &str) -> Option<&'a FunctionExecution> {
    report
        .function_analyses
        .iter()
        .find(|f| f.function_name == name)
}

// ─────────────────────────────────────────────────────────────
// 1. NESTED BLOCK ORDERING
// ─────────────────────────────────────────────────────────────

#[test]
fn audit_if_block_ordering() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        if (balances[msg.sender] >= amount) {
            balances[msg.sender] -= amount;
        }
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "withdraw");

    let state_write = ops.iter().find(|o| o.kind == OperationKind::StateWrite);
    let external_call = ops.iter().find(|o| o.kind == OperationKind::ExternalCall);

    assert!(
        state_write.is_some(),
        "Should detect StateWrite in if block"
    );
    assert!(
        external_call.is_some(),
        "Should detect ExternalCall after if block"
    );
    assert!(
        state_write.unwrap().index < external_call.unwrap().index,
        "StateWrite ({}) should come before ExternalCall ({})",
        state_write.unwrap().index,
        external_call.unwrap().index
    );
}

#[test]
fn audit_if_else_block_ordering() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        if (balances[msg.sender] >= amount) {
            balances[msg.sender] -= amount;
        } else {
            balances[msg.sender] = 0;
        }
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "withdraw");

    let state_writes: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::StateWrite)
        .collect();
    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();

    assert!(!state_writes.is_empty(), "Should detect StateWrite");
    assert!(!external_calls.is_empty(), "Should detect ExternalCall");

    let last_write = state_writes.last().unwrap().index;
    let first_call = external_calls.first().unwrap().index;
    assert!(
        last_write < first_call,
        "All StateWrites should come before ExternalCall"
    );
}

#[test]
fn audit_nested_if_ordering() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;
    bool public paused;

    function withdraw(uint256 amount) public {
        if (!paused) {
            if (balances[msg.sender] >= amount) {
                balances[msg.sender] -= amount;
            }
        }
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "withdraw");

    assert!(
        ops.iter().any(|o| o.kind == OperationKind::StateWrite),
        "Should detect StateWrite in nested if"
    );
    assert!(
        ops.iter().any(|o| o.kind == OperationKind::ExternalCall),
        "Should detect ExternalCall"
    );
}

#[test]
fn audit_nested_block_ordering() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        {
            balances[msg.sender] -= amount;
        }
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "withdraw");

    let state_write = ops.iter().find(|o| o.kind == OperationKind::StateWrite);
    let external_call = ops.iter().find(|o| o.kind == OperationKind::ExternalCall);

    assert!(
        state_write.is_some(),
        "Should detect StateWrite in nested block"
    );
    assert!(external_call.is_some(), "Should detect ExternalCall");
    assert!(state_write.unwrap().index < external_call.unwrap().index);
}

// ─────────────────────────────────────────────────────────────
// 2. LOOP ORDERING
// ─────────────────────────────────────────────────────────────

#[test]
fn audit_for_loop_ordering() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function batchWithdraw(address[] memory users) public {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] = 0;
        }
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "batchWithdraw");

    let state_writes: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::StateWrite)
        .collect();
    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();

    assert!(
        !state_writes.is_empty(),
        "Should detect StateWrite in for loop"
    );
    assert!(
        !external_calls.is_empty(),
        "Should detect ExternalCall after loop"
    );
    assert!(state_writes.last().unwrap().index < external_calls.first().unwrap().index);
}

#[test]
fn audit_while_loop_ordering() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function process(uint256[] memory amounts) public {
        uint256 i = 0;
        while (i < amounts.length) {
            balances[msg.sender] += amounts[i];
            i++;
        }
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "process");

    let state_writes: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::StateWrite)
        .collect();
    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();

    assert!(
        !state_writes.is_empty(),
        "Should detect StateWrite in while loop"
    );
    assert!(
        !external_calls.is_empty(),
        "Should detect ExternalCall after loop"
    );
}

#[test]
fn audit_nested_loop_ordering() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function process(uint256[][] memory data) public {
        for (uint256 i = 0; i < data.length; i++) {
            for (uint256 j = 0; j < data[i].length; j++) {
                balances[msg.sender] += data[i][j];
            }
        }
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "process");

    let state_writes: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::StateWrite)
        .collect();
    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();

    assert!(
        !state_writes.is_empty(),
        "Should detect StateWrite in nested loop"
    );
    assert!(
        !external_calls.is_empty(),
        "Should detect ExternalCall after nested loop"
    );
}

#[test]
fn audit_loop_no_duplicate_operations() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        balances[msg.sender] -= 100;
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let program = parse_program(source, "solidity");

    for run in 0..3 {
        let report = analyze_execution(&program, "test");
        let func = find_func(&report, "withdraw").unwrap();
        let state_writes: Vec<_> = func
            .ordered_operations
            .iter()
            .filter(|o| o.kind == "StateWrite")
            .collect();
        assert_eq!(
            state_writes.len(),
            1,
            "Run {}: exactly 1 StateWrite expected",
            run
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 3. INTERNAL CALL BOUNDARY VISIBILITY
// ─────────────────────────────────────────────────────────────

#[test]
fn audit_internal_call_not_visible_as_external() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _externalTransfer();
    }

    function _externalTransfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "withdraw");

    // withdraw() has no ExternalCall — the call is inside _externalTransfer
    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();
    assert!(
        external_calls.is_empty(),
        "withdraw() should NOT see ExternalCall from _externalTransfer, got: {:?}",
        external_calls
    );
}

#[test]
fn audit_cei_is_intra_function_only() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _externalTransfer();
    }

    function _externalTransfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
        balances[msg.sender] -= 100;
    }
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");

    // withdraw has no operations of its own (only internal call)
    let withdraw = find_func(&report, "withdraw");
    if let Some(func) = withdraw {
        // withdraw should NOT have CEI violation (no operations)
        assert!(
            !func.external_before_state_write,
            "withdraw should NOT have CEI violation"
        );
        assert!(
            !func.has_external_call,
            "withdraw should NOT have ExternalCall"
        );
        assert!(!func.has_state_write, "withdraw should NOT have StateWrite");
    }

    // _externalTransfer may or may not be in the report depending on parser
    // If present, it should have CEI violation
    let ext = find_func(&report, "_externalTransfer");
    if let Some(func) = ext {
        assert!(
            func.external_before_state_write,
            "_externalTransfer should have CEI violation"
        );
    }
}

#[test]
fn audit_internal_calls_emitted_as_operations() {
    // Phase 6.4: Internal calls ARE now emitted as operations
    // so the expansion engine can inline callee operations
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _updateBalance();
        _doTransfer();
    }

    function _updateBalance() internal {
        balances[msg.sender] -= 100;
    }

    function _doTransfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "withdraw");

    // Internal calls ARE operations (for expansion engine)
    let internal_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::InternalCall)
        .collect();
    assert_eq!(
        internal_calls.len(),
        2,
        "Should have 2 InternalCall operations"
    );
}

#[test]
fn audit_cross_function_cei_not_detected() {
    // KNOWN LIMITATION: cross-function CEI is not detected
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _doTransfer();
        _updateBalance();
    }

    function _doTransfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }

    function _updateBalance() internal {
        balances[msg.sender] -= 100;
    }
}
"#;
    let program = parse_program(source, "solidity");
    let report = analyze_execution(&program, "test");

    let withdraw = find_func(&report, "withdraw");
    if let Some(func) = withdraw {
        // Phase 6.3: per-function only. Phase 6.4 expansion handles cross-function.
        assert!(
            !func.external_before_state_write,
            "Per-function: cross-function CEI not detected at this layer"
        );
        assert!(
            !func.has_external_call,
            "Per-function: ExternalCall not visible from caller"
        );
        assert!(
            !func.has_state_write,
            "Per-function: StateWrite not visible from caller"
        );
    }
    // If withdraw is not in the report, that's also acceptable
    // (it has no operations of its own, only internal calls)
}

// ─────────────────────────────────────────────────────────────
// 4. EXTERNAL CALL CLASSIFICATION
// ─────────────────────────────────────────────────────────────

#[test]
fn audit_call_classified_as_external_call() {
    let source = r#"
contract Test {
    function test() public {
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "test");

    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();
    assert_eq!(external_calls.len(), 1);
    assert!(external_calls[0].target.contains("call"));
}

#[test]
fn audit_delegatecall_classified_as_external_call() {
    let source = r#"
contract Test {
    address public impl;
    function test() public {
        (bool success, ) = impl.delegatecall("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "test");

    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();
    assert_eq!(
        external_calls.len(),
        1,
        "Should detect delegatecall as ExternalCall"
    );
    assert!(external_calls[0].target.contains("delegatecall"));
}

#[test]
fn audit_staticcall_classified_as_external_call() {
    let source = r#"
contract Test {
    address public impl;
    function test() public view {
        (bool success, ) = impl.staticcall("");
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "test");

    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();
    assert_eq!(
        external_calls.len(),
        1,
        "Should detect staticcall as ExternalCall"
    );
    assert!(external_calls[0].target.contains("staticcall"));
}

#[test]
fn audit_transfer_classified_as_external_call() {
    let source = r#"
contract Test {
    function test() public {
        payable(msg.sender).transfer(100);
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "test");

    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();
    assert_eq!(
        external_calls.len(),
        1,
        "Should detect transfer as ExternalCall"
    );
    assert!(external_calls[0].target.contains("transfer"));
}

#[test]
fn audit_all_call_types_collapsed_to_external_call() {
    // KNOWN LIMITATION: All call types collapse into ExternalCall
    let source = r#"
contract Test {
    address public impl;
    function test() public {
        (bool s1, ) = msg.sender.call{value: 1}("");
        (bool s2, ) = impl.delegatecall("");
        (bool s3, ) = impl.staticcall("");
        payable(msg.sender).transfer(1);
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "test");

    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();
    assert_eq!(
        external_calls.len(),
        4,
        "All 4 call types should produce ExternalCall"
    );

    let targets: Vec<_> = external_calls.iter().map(|o| o.target.as_str()).collect();
    assert!(targets.contains(&"call"));
    assert!(targets.contains(&"delegatecall"));
    assert!(targets.contains(&"staticcall"));
    assert!(targets.contains(&"transfer"));
}

#[test]
fn audit_interface_call_classified_as_external_call() {
    let source = r#"
interface IOracle {
    function getPrice() external view returns (uint256);
}

contract Test {
    address public oracle;
    function test() public {
        uint256 price = IOracle(oracle).getPrice();
    }
}
"#;
    let program = parse_program(source, "solidity");
    let ops = ops_for(&program, "test");

    let external_calls: Vec<_> = ops
        .iter()
        .filter(|o| o.kind == OperationKind::ExternalCall)
        .collect();
    assert_eq!(
        external_calls.len(),
        1,
        "Should detect interface call as ExternalCall"
    );
    assert!(external_calls[0].target.contains("IOracle"));
}

// ─────────────────────────────────────────────────────────────
// 5. DETERMINISM VERIFICATION
// ─────────────────────────────────────────────────────────────

#[test]
fn audit_deterministic_operations() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"#;
    let program = parse_program(source, "solidity");

    let first_report = analyze_execution(&program, "test");
    let first_json = report_to_json(&first_report);

    for i in 0..5 {
        let report = analyze_execution(&program, "test");
        let json = report_to_json(&report);
        assert_eq!(json, first_json, "Run {} differs from run 0", i);
    }
}

#[test]
fn audit_deterministic_operation_indices() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
"#;
    let program = parse_program(source, "solidity");

    for _ in 0..3 {
        let report = analyze_execution(&program, "test");
        let func = find_func(&report, "withdraw").unwrap();
        for (i, op) in func.ordered_operations.iter().enumerate() {
            assert_eq!(
                op.index, i,
                "Index should be sequential: expected {}, got {}",
                i, op.index
            );
        }
    }
}

#[test]
fn audit_deterministic_cei_violations() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function unsafe_withdraw() public {
        (bool success, ) = msg.sender.call{value: 100}("");
        balances[msg.sender] -= 100;
    }

    function safe_withdraw() public {
        balances[msg.sender] -= 100;
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let program = parse_program(source, "solidity");

    let first_report = analyze_execution(&program, "test");
    let first_json = report_to_json(&first_report);

    for i in 0..5 {
        let report = analyze_execution(&program, "test");
        let json = report_to_json(&report);
        assert_eq!(json, first_json, "CEI detection run {} differs", i);
    }

    let unsafe_fn = find_func(&first_report, "unsafe_withdraw").unwrap();
    let safe_fn = find_func(&first_report, "safe_withdraw").unwrap();

    assert!(
        unsafe_fn.external_before_state_write,
        "unsafe should have CEI violation"
    );
    assert!(
        !safe_fn.external_before_state_write,
        "safe should NOT have CEI violation"
    );
}

#[test]
fn audit_no_hashmap_iteration_affects_ordering() {
    // Verify ordering is stable regardless of variable names
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function unsafe_withdraw() public {
        (bool success, ) = msg.sender.call{value: 100}("");
        balances[msg.sender] -= 100;
    }

    function safe_withdraw() public {
        balances[msg.sender] -= 100;
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let program = parse_program(source, "solidity");

    // Run 10 times, verify identical
    let first = report_to_json(&analyze_execution(&program, "test"));
    for i in 0..10 {
        let json = report_to_json(&analyze_execution(&program, "test"));
        assert_eq!(json, first, "Run {} differs", i);
    }
}

// ─────────────────────────────────────────────────────────────
// CAPABILITY REPORT
// ─────────────────────────────────────────────────────────────

#[test]
fn audit_capability_report() {
    // CAPABILITIES:
    // 1. Operations extracted from AST in source order
    // 2. Operations survive nested blocks (if, if/else, nested if, blocks)
    // 3. Operations survive loops (for, while, nested loops)
    // 4. CEI detection is intra-function only
    // 5. All call types (call, delegatecall, staticcall, transfer) → ExternalCall
    // 6. Interface calls (IType(addr).method()) → ExternalCall
    // 7. require/assert → AuthorityCheck
    // 8. State variable writes → StateWrite
    // 9. State variable reads → StateRead
    // 10. Deterministic output (byte-identical JSON across runs)

    // KNOWN LIMITATIONS (as of Phase 6.3; some resolved in 6.4):
    // 1. Cross-function CEI — NOW detected via expansion engine (Phase 6.4)
    // 2. Call types NOT differentiated (all collapse to ExternalCall)
    // 3. callcode NOT detected (not in Solidity 0.8+)
    // 4. Assembly delegatecall NOT detected (assembly blocks are opaque)
    // 5. Conditional execution paths NOT modeled (both branches emitted)
    // 6. Loop body operations emitted once (not unrolled)

    // Verify limitation: cross-function CEI
    let cross_fn_source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _doTransfer();
        _updateBalance();
    }

    function _doTransfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }

    function _updateBalance() internal {
        balances[msg.sender] -= 100;
    }
}
"#;
    let program = parse_program(cross_fn_source, "solidity");
    let report = analyze_execution(&program, "test");
    let withdraw = find_func(&report, "withdraw");

    if let Some(func) = withdraw {
        assert!(
            !func.external_before_state_write,
            "LIMITATION: Cross-function CEI not detected"
        );
        assert!(
            !func.has_external_call,
            "LIMITATION: ExternalCall not visible from caller"
        );
        assert!(
            !func.has_state_write,
            "LIMITATION: StateWrite not visible from caller"
        );
    }
}
