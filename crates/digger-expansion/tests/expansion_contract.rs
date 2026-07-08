/// Cross-Function Expansion Contract Tests — Phase 6.4
use digger_expansion::*;
use digger_parser::parse_program;

fn expand_source(source: &str) -> ExpansionReport {
    let program = parse_program(source, "solidity");
    expand_program(&program, "test")
}

// ─────────────────────────────────────────────────────────────
// 1. Single-level expansion
// ─────────────────────────────────────────────────────────────

#[test]
fn single_level_expansion() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _transfer();
        _updateBalance();
    }

    function _transfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }

    function _updateBalance() internal {
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = expand_source(source);

    let withdraw = report
        .expanded_functions
        .iter()
        .find(|f| f.function_name == "withdraw")
        .unwrap();

    assert!(withdraw.has_expansions, "withdraw should have expansions");
    assert!(
        withdraw.operations.iter().any(|o| o.kind == "ExternalCall"),
        "Should see ExternalCall from _transfer expansion"
    );
    assert!(
        withdraw.operations.iter().any(|o| o.kind == "StateWrite"),
        "Should see StateWrite from _updateBalance expansion"
    );
}

// ─────────────────────────────────────────────────────────────
// 2. Multi-level expansion
// ─────────────────────────────────────────────────────────────

#[test]
fn multi_level_expansion() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _doTransfer();
    }

    function _doTransfer() internal {
        _externalTransfer();
    }

    function _externalTransfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let report = expand_source(source);

    let withdraw = report
        .expanded_functions
        .iter()
        .find(|f| f.function_name == "withdraw")
        .unwrap();

    assert!(withdraw.has_expansions, "withdraw should have expansions");
    assert!(withdraw.max_depth >= 2, "Should have depth >= 2");
    assert!(
        withdraw.operations.iter().any(|o| o.kind == "ExternalCall"),
        "Should see ExternalCall from deep expansion"
    );

    // The ExternalCall should originate from _externalTransfer
    let ext_call = withdraw
        .operations
        .iter()
        .find(|o| o.kind == "ExternalCall")
        .unwrap();
    assert_eq!(ext_call.origin_function, "_externalTransfer");
    assert!(
        ext_call.call_chain.contains(&"_doTransfer".to_string()),
        "Call chain should include _doTransfer"
    );
}

// ─────────────────────────────────────────────────────────────
// 3. Recursive call detection
// ─────────────────────────────────────────────────────────────

#[test]
fn recursive_call_detection() {
    let source = r#"
contract Test {
    function a() public {
        b();
    }

    function b() internal {
        a();
    }
}
"#;
    let report = expand_source(source);

    // Should detect the cycle
    assert!(
        !report.cycles.is_empty(),
        "Should detect cycle, got: {:?}",
        report.cycles
    );

    let cycle = &report.cycles[0];
    assert!(
        cycle.cycle_path.len() >= 2,
        "Cycle should have at least 2 functions"
    );
}

// ─────────────────────────────────────────────────────────────
// 4. Cycle termination
// ─────────────────────────────────────────────────────────────

#[test]
fn cycle_termination() {
    let source = r#"
contract Test {
    function a() public {
        b();
    }

    function b() internal {
        c();
    }

    function c() internal {
        a();
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let report = expand_source(source);

    // Should terminate (no infinite recursion)
    // The expansion should complete and produce a report
    assert!(!report.expanded_functions.is_empty());

    // Should detect the cycle
    assert!(!report.cycles.is_empty(), "Should detect cycle");
}

// ─────────────────────────────────────────────────────────────
// 5. Expanded CEI detection
// ─────────────────────────────────────────────────────────────

#[test]
fn expanded_cei_detection() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _transfer();
        _updateBalance();
    }

    function _transfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }

    function _updateBalance() internal {
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = expand_source(source);

    // Should detect cross-function CEI violation
    assert!(
        !report.expanded_cei_violations.is_empty(),
        "Should detect expanded CEI violation, got: {:?}",
        report.expanded_cei_violations
    );

    let violation = &report.expanded_cei_violations[0];
    assert_eq!(violation.base.function_name, "withdraw");
    assert_eq!(violation.external_call_origin, "_transfer");
    assert_eq!(violation.state_write_origin, "_updateBalance");
    assert_eq!(violation.base.severity, digger_ir::Severity::High);
}

#[test]
fn no_expanded_cei_when_safe() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _updateBalance();
        _transfer();
    }

    function _updateBalance() internal {
        balances[msg.sender] -= 100;
    }

    function _transfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let report = expand_source(source);

    // Should NOT detect CEI violation (state write before external call)
    let withdraw_violations: Vec<_> = report
        .expanded_cei_violations
        .iter()
        .filter(|v| v.base.function_name == "withdraw")
        .collect();

    assert!(
        withdraw_violations.is_empty(),
        "Should NOT detect CEI violation when safe, got: {:?}",
        withdraw_violations
    );
}

// ─────────────────────────────────────────────────────────────
// 6. Deterministic ordering
// ─────────────────────────────────────────────────────────────

#[test]
fn deterministic_ordering() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _transfer();
        _updateBalance();
    }

    function _transfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }

    function _updateBalance() internal {
        balances[msg.sender] -= 100;
    }
}
"#;
    let program = parse_program(source, "solidity");

    let first = expand_program(&program, "test");
    let first_json = report_to_json(&first);

    for i in 0..5 {
        let report = expand_program(&program, "test");
        let json = report_to_json(&report);
        assert_eq!(json, first_json, "Run {} differs from run 0", i);
    }
}

// ─────────────────────────────────────────────────────────────
// 7. Stable serialization
// ─────────────────────────────────────────────────────────────

#[test]
fn stable_serialization() {
    let source = r#"
contract Test {
    function withdraw() public {
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let report = expand_source(source);

    let json1 = report_to_json(&report);
    let json2 = report_to_json(&report);
    assert_eq!(json1, json2);
}

#[test]
fn serialization_roundtrip() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _transfer();
        _updateBalance();
    }

    function _transfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }

    function _updateBalance() internal {
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = expand_source(source);

    let json = report_to_json(&report);
    let deserialized = report_from_json(&json).unwrap();

    assert_eq!(deserialized.protocol_id, report.protocol_id);
    assert_eq!(
        deserialized.expanded_functions.len(),
        report.expanded_functions.len()
    );
    assert_eq!(
        deserialized.expanded_cei_violations.len(),
        report.expanded_cei_violations.len()
    );
}

// ─────────────────────────────────────────────────────────────
// 8. Duplicate prevention
// ─────────────────────────────────────────────────────────────

#[test]
fn no_duplicate_operations() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _transfer();
        _transfer();  // called twice
    }

    function _transfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let report = expand_source(source);

    let withdraw = report
        .expanded_functions
        .iter()
        .find(|f| f.function_name == "withdraw")
        .unwrap();

    // Should have 2 ExternalCall operations (one per call site)
    let external_calls: Vec<_> = withdraw
        .operations
        .iter()
        .filter(|o| o.kind == "ExternalCall")
        .collect();

    assert_eq!(
        external_calls.len(),
        2,
        "Should have 2 ExternalCall operations (one per call site)"
    );
}

// ─────────────────────────────────────────────────────────────
// 9. Deep call chains (20+ functions)
// ─────────────────────────────────────────────────────────────

#[test]
fn deep_call_chain() {
    // Build a chain: withdraw -> f0 -> f1 -> ... -> f19 -> external
    let mut source = String::from("contract Test {\n");
    source.push_str("    function withdraw() public {\n");
    source.push_str("        f0();\n");
    source.push_str("    }\n");

    for i in 0..20 {
        source.push_str(&format!("    function f{}() internal {{\n", i));
        if i < 19 {
            source.push_str(&format!("        f{}();\n", i + 1));
        } else {
            source.push_str("        (bool success, ) = msg.sender.call{value: 1}(\"\");\n");
        }
        source.push_str("    }\n");
    }

    source.push_str("}\n");

    let report = expand_source(&source);

    let withdraw = report
        .expanded_functions
        .iter()
        .find(|f| f.function_name == "withdraw")
        .unwrap();

    assert!(withdraw.has_expansions, "Should have expansions");
    assert!(
        withdraw.max_depth >= 20,
        "Should have depth >= 20, got: {}",
        withdraw.max_depth
    );
    assert!(
        withdraw.operations.iter().any(|o| o.kind == "ExternalCall"),
        "Should see ExternalCall from deep chain"
    );
}

// ─────────────────────────────────────────────────────────────
// 10. Byte-identical output across runs
// ─────────────────────────────────────────────────────────────

#[test]
fn byte_identical_output() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function withdraw() public {
        _transfer();
        _updateBalance();
    }

    function _transfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }

    function _updateBalance() internal {
        balances[msg.sender] -= 100;
    }
}
"#;
    let program = parse_program(source, "solidity");

    let r1 = expand_program(&program, "test");
    let j1 = report_to_json(&r1);

    for i in 0..10 {
        let r = expand_program(&program, "test");
        let j = report_to_json(&r);
        assert_eq!(j.as_bytes(), j1.as_bytes(), "Run {} byte-differs", i);
    }
}

// ─────────────────────────────────────────────────────────────
// 11. Expansion traces
// ─────────────────────────────────────────────────────────────

#[test]
fn expansion_traces_present() {
    let source = r#"
contract Test {
    function withdraw() public {
        _transfer();
    }

    function _transfer() internal {
        (bool success, ) = msg.sender.call{value: 100}("");
    }
}
"#;
    let report = expand_source(source);

    assert!(!report.traces.is_empty(), "Should have expansion traces");

    let trace = &report.traces[0];
    assert_eq!(trace.caller_function, "withdraw");
    assert_eq!(trace.callee_function, "_transfer");
    assert_eq!(trace.depth, 1);
    assert!(!trace.operation_indices.is_empty());
}

// ─────────────────────────────────────────────────────────────
// 12. No expansion for leaf functions
// ─────────────────────────────────────────────────────────────

#[test]
fn leaf_function_no_expansion() {
    let source = r#"
contract Test {
    mapping(address => uint256) public balances;

    function _updateBalance() internal {
        balances[msg.sender] -= 100;
    }
}
"#;
    let report = expand_source(source);

    let func = report
        .expanded_functions
        .iter()
        .find(|f| f.function_name == "_updateBalance")
        .unwrap();

    assert!(
        !func.has_expansions,
        "Leaf function should not have expansions"
    );
    assert_eq!(func.max_depth, 0);
}

// ─────────────────────────────────────────────────────────────
// 13. No AI or heuristics
// ─────────────────────────────────────────────────────────────

#[test]
fn no_ai_or_heuristics() {
    let source = r#"
contract Test {
    function foo() public {}
}
"#;
    let report = expand_source(source);
    let json = report_to_json(&report);

    assert!(!json.contains("confidence"));
    assert!(!json.contains("probability"));
    assert!(!json.contains("heuristic"));
    assert!(!json.contains("risk_score"));
}

#[test]
fn test_cross_function_expansion_reveals_hidden_operation() {
    use digger_parser::model::*;

    let program = RawProgram {
        functions: vec![
            RawFunction {
                name: "caller".into(),
                contract: String::new(),
                visibility: "public".into(),
                inputs: vec![],
                body: "callee()".into(),
                has_arithmetic: false,
            },
            RawFunction {
                name: "callee".into(),
                contract: String::new(),
                visibility: "internal".into(),
                inputs: vec![],
                body: "(bool ok,) = token.call(...) balances[addr] = 0".into(),
                has_arithmetic: false,
            },
        ],
        state: vec![
            RawState {
                name: "balances".into(),
                ty: "mapping(address => uint256)".into(),
            },
            RawState {
                name: "totalSupply".into(),
                ty: "uint256".into(),
            },
        ],
        calls: vec![RawCall {
            from: "caller".into(),
            to: "callee".into(),
            kind: digger_ir::CallKind::Internal,
        }],
        operations: vec![
            RawOperation {
                function: "caller".into(),
                index: 0,
                kind: OperationKind::InternalCall,
                target: "callee".into(),
            },
            RawOperation {
                function: "callee".into(),
                index: 0,
                kind: OperationKind::StateRead,
                target: "balances".into(),
            },
            RawOperation {
                function: "callee".into(),
                index: 1,
                kind: OperationKind::ExternalCall,
                target: "token".into(),
            },
            RawOperation {
                function: "callee".into(),
                index: 2,
                kind: OperationKind::StateWrite,
                target: "totalSupply".into(),
            },
        ],
        source: String::new(),
        metadata: AnalysisMetadata::default(),
    };

    let report = expand_program(&program, "test");

    let caller_stream = report
        .expanded_functions
        .iter()
        .find(|f| f.function_name == "caller")
        .expect("caller should be in expanded_functions");

    assert!(
        caller_stream.has_expansions,
        "caller should have cross-function expansions"
    );

    let has_callee_state_write = caller_stream.operations.iter().any(|op| {
        op.kind == "StateWrite" && op.target == "totalSupply" && op.origin_function == "callee"
    });
    assert!(
        has_callee_state_write,
        "expanded operations of caller should contain callee's StateWrite on totalSupply"
    );

    let has_callee_external_call = caller_stream.operations.iter().any(|op| {
        op.kind == "ExternalCall" && op.target == "token" && op.origin_function == "callee"
    });
    assert!(
        has_callee_external_call,
        "expanded operations of caller should contain callee's ExternalCall on token"
    );

    assert!(
        report.cycles.is_empty(),
        "no cycles should be detected in a simple caller→callee graph"
    );

    let json = report_to_json(&report);
    let deserialized = report_from_json(&json).expect("JSON round-trip should succeed");
    assert_eq!(report, deserialized);
}

#[test]
fn test_expansion_determinism() {
    use digger_parser::model::*;

    let program = RawProgram {
        functions: vec![
            RawFunction {
                name: "deposit".into(),
                contract: String::new(),
                visibility: "external".into(),
                inputs: vec![],
                body: "balances[msg.sender] += msg.value".into(),
                has_arithmetic: false,
            },
            RawFunction {
                name: "withdraw".into(),
                contract: String::new(),
                visibility: "external".into(),
                inputs: vec![],
                body: "_send(balances[msg.sender]) balances[msg.sender]=0".into(),
                has_arithmetic: false,
            },
            RawFunction {
                name: "_send".into(),
                contract: String::new(),
                visibility: "internal".into(),
                inputs: vec![],
                body: "(bool ok,) = msg.sender.call{value: amount}(\"\")".into(),
                has_arithmetic: false,
            },
        ],
        state: vec![RawState {
            name: "balances".into(),
            ty: "mapping(address => uint256)".into(),
        }],
        calls: vec![RawCall {
            from: "withdraw".into(),
            to: "_send".into(),
            kind: digger_ir::CallKind::Internal,
        }],
        operations: vec![
            RawOperation {
                function: "deposit".into(),
                index: 0,
                kind: OperationKind::StateWrite,
                target: "balances".into(),
            },
            RawOperation {
                function: "withdraw".into(),
                index: 0,
                kind: OperationKind::InternalCall,
                target: "_send".into(),
            },
            RawOperation {
                function: "withdraw".into(),
                index: 1,
                kind: OperationKind::StateWrite,
                target: "balances".into(),
            },
            RawOperation {
                function: "_send".into(),
                index: 0,
                kind: OperationKind::ExternalCall,
                target: "msg.sender".into(),
            },
        ],
        source: String::new(),
        metadata: AnalysisMetadata::default(),
    };

    let r1 = expand_program(&program, "test");
    let r2 = expand_program(&program, "test");

    let j1 = report_to_json(&r1);
    let j2 = report_to_json(&r2);

    assert_eq!(j1, j2, "expansion output must be deterministic");
    assert_eq!(
        j1.as_bytes(),
        j2.as_bytes(),
        "expansion JSON must be byte-identical across runs"
    );
    assert_eq!(r1, r2, "expansion reports must be structurally equal");
}
