/// Authority Propagation Contract Tests — Phase 7.2
use digger_graph::analysis::*;
use digger_parser::parse_program;

fn propagate_source(source: &str) -> AuthorityGraph {
    let program = parse_program(source, "solidity");
    propagate_authority(&program)
}

// ─────────────────────────────────────────────────────────────
// 1. Helper-function authority
// ─────────────────────────────────────────────────────────────

#[test]
fn helper_function_inherits_authority() {
    let source = r#"
contract Vault {
    address public owner;

    function withdraw() public {
        _checkOwner();
        _doTransfer();
    }

    function _checkOwner() internal {
        require(msg.sender == owner);
    }

    function _doTransfer() internal {
        // sends ETH
    }
}
"#;
    let graph = propagate_source(source);

    // _checkOwner has direct authority
    let check_owner = graph
        .relations
        .iter()
        .find(|r| r.function == "_checkOwner")
        .unwrap();
    assert!(
        check_owner.enforced,
        "_checkOwner should have enforced authority"
    );

    // withdraw calls _checkOwner, so it should inherit authority
    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    assert!(
        withdraw.enforced,
        "withdraw should inherit authority from _checkOwner"
    );
}

#[test]
fn helper_without_authority_not_propagated() {
    let source = r#"
contract Vault {
    address public owner;

    function withdraw() public {
        _doTransfer();
    }

    function _doTransfer() internal {
        // sends ETH, no authority check
    }
}
"#;
    let graph = propagate_source(source);

    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    assert!(
        !withdraw.enforced,
        "withdraw should NOT have authority (callee has none)"
    );
}

// ─────────────────────────────────────────────────────────────
// 2. Nested helper chains
// ─────────────────────────────────────────────────────────────

#[test]
fn nested_helper_chain_propagation() {
    let source = r#"
contract Vault {
    address public owner;

    function withdraw() public {
        _validateAndTransfer();
    }

    function _validateAndTransfer() internal {
        _checkOwner();
        _doTransfer();
    }

    function _checkOwner() internal {
        require(msg.sender == owner);
    }

    function _doTransfer() internal {
        // sends ETH
    }
}
"#;
    let graph = propagate_source(source);

    // _checkOwner has direct authority
    let check_owner = graph
        .relations
        .iter()
        .find(|r| r.function == "_checkOwner")
        .unwrap();
    assert!(
        check_owner.enforced,
        "_checkOwner should have enforced authority"
    );

    // _validateAndTransfer calls _checkOwner → inherits authority
    let validate = graph
        .relations
        .iter()
        .find(|r| r.function == "_validateAndTransfer")
        .unwrap();
    assert!(
        validate.enforced,
        "_validateAndTransfer should inherit authority from _checkOwner"
    );

    // withdraw calls _validateAndTransfer → inherits authority transitively
    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    assert!(
        withdraw.enforced,
        "withdraw should inherit authority through the chain"
    );
}

// ─────────────────────────────────────────────────────────────
// 3. Multiple modifiers
// ─────────────────────────────────────────────────────────────

#[test]
fn multiple_modifiers_preserved() {
    let source = r#"
contract Vault {
    address public owner;
    bool public paused;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier whenNotPaused() {
        require(!paused);
        _;
    }

    function withdraw() public onlyOwner whenNotPaused {
        // sends ETH
    }
}
"#;
    let graph = propagate_source(source);

    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    assert!(
        withdraw.enforced,
        "withdraw should have enforced authority from onlyOwner"
    );
    assert!(
        withdraw.modifiers.contains(&"onlyOwner".to_string()),
        "withdraw should list onlyOwner modifier"
    );
    assert!(
        withdraw.modifiers.contains(&"whenNotPaused".to_string()),
        "withdraw should list whenNotPaused modifier"
    );
}

// ─────────────────────────────────────────────────────────────
// 4. Recursive call protection
// ─────────────────────────────────────────────────────────────

#[test]
fn recursive_call_terminates() {
    let source = r#"
contract Test {
    address public owner;

    function a() public {
        b();
    }

    function b() internal {
        a();
        require(msg.sender == owner);
    }
}
"#;
    let graph = propagate_source(source);

    // Should terminate without infinite recursion
    assert!(!graph.relations.is_empty(), "Should produce results");

    // b has direct authority
    let b = graph.relations.iter().find(|r| r.function == "b").unwrap();
    assert!(b.enforced, "b should have enforced authority");
}

#[test]
fn mutual_recursion_terminates() {
    let source = r#"
contract Test {
    address public owner;

    function a() public {
        b();
    }

    function b() internal {
        c();
    }

    function c() internal {
        a();
        require(msg.sender == owner);
    }
}
"#;
    let graph = propagate_source(source);

    // Should terminate
    assert!(!graph.relations.is_empty(), "Should produce results");
}

// ─────────────────────────────────────────────────────────────
// 5. Deterministic propagation
// ─────────────────────────────────────────────────────────────

#[test]
fn propagation_deterministic() {
    let source = r#"
contract Vault {
    address public owner;

    function withdraw() public {
        _checkOwner();
    }

    function _checkOwner() internal {
        require(msg.sender == owner);
    }
}
"#;

    let g1 = propagate_source(source);
    let g2 = propagate_source(source);
    let g3 = propagate_source(source);

    assert_eq!(g1, g2);
    assert_eq!(g2, g3);
}

#[test]
fn propagation_chains_sorted() {
    let source = r#"
contract Test {
    address public owner;

    function zebra() public { _check(); }
    function alpha() public { _check(); }
    function _check() internal { require(msg.sender == owner); }
}
"#;
    let graph = propagate_source(source);

    for i in 1..graph.propagation_chains.len() {
        assert!(
            graph.propagation_chains[i - 1] <= graph.propagation_chains[i],
            "Propagation chains must be sorted"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 6. Serialization stability
// ─────────────────────────────────────────────────────────────

#[test]
fn serialization_roundtrip() {
    let source = r#"
contract Vault {
    address public owner;

    function withdraw() public {
        _checkOwner();
    }

    function _checkOwner() internal {
        require(msg.sender == owner);
    }
}
"#;
    let graph = propagate_source(source);

    let json = serde_json::to_string_pretty(&graph).unwrap();
    let deserialized: AuthorityGraph = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized, graph);
}

#[test]
fn serialization_stable() {
    let source = r#"
contract Vault {
    address public owner;

    function withdraw() public {
        _checkOwner();
    }

    function _checkOwner() internal {
        require(msg.sender == owner);
    }
}
"#;
    let graph = propagate_source(source);

    let json1 = serde_json::to_string(&graph).unwrap();
    let json2 = serde_json::to_string(&graph).unwrap();
    assert_eq!(json1, json2);
}

// ─────────────────────────────────────────────────────────────
// 7. Regression: Phase 7.1 behavior preserved
// ─────────────────────────────────────────────────────────────

#[test]
fn regression_owner_check_still_detected() {
    let source = r#"
contract Ownable {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function changeOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}
"#;
    let graph = propagate_source(source);

    let change_owner = graph
        .relations
        .iter()
        .find(|r| r.function == "changeOwner")
        .unwrap();
    assert!(
        change_owner.enforced,
        "changeOwner should still have enforced authority"
    );
    assert!(
        !change_owner.is_invariant,
        "changeOwner should not be invariant"
    );
}

#[test]
fn regression_balance_check_still_invariant() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
    }
}
"#;
    let graph = propagate_source(source);

    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    assert!(
        withdraw.is_invariant,
        "Balance check should still be classified as invariant"
    );
    assert!(
        !withdraw.enforced,
        "Balance check should not be enforced authority"
    );
}

#[test]
fn regression_initialization_still_invariant() {
    let source = r#"
contract Initializable {
    bool public initialized;

    function initialize() public {
        require(!initialized);
        initialized = true;
    }
}
"#;
    let graph = propagate_source(source);

    let init = graph
        .relations
        .iter()
        .find(|r| r.function == "initialize")
        .unwrap();
    assert!(
        init.is_invariant,
        "Initialization guard should still be invariant"
    );
}

// ─────────────────────────────────────────────────────────────
// 8. Propagation doesn't override direct authority
// ─────────────────────────────────────────────────────────────

#[test]
fn direct_authority_not_overridden() {
    let source = r#"
contract Vault {
    address public owner;
    address public admin;

    function withdraw() public {
        require(msg.sender == admin);
        _checkOwner();
    }

    function _checkOwner() internal {
        require(msg.sender == owner);
    }
}
"#;
    let graph = propagate_source(source);

    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    // withdraw has its own authority (admin), should not be overridden by _checkOwner's authority
    assert!(withdraw.enforced, "withdraw should have enforced authority");
    assert_eq!(
        withdraw.source,
        AuthoritySource::MsgSender,
        "withdraw should keep its own source"
    );
}

// ─────────────────────────────────────────────────────────────
// 9. Summary statistics updated after propagation
// ─────────────────────────────────────────────────────────────

#[test]
fn summary_updated_after_propagation() {
    let source = r#"
contract Vault {
    address public owner;

    function withdraw() public {
        _checkOwner();
    }

    function deposit() public {
        // no authority
    }

    function _checkOwner() internal {
        require(msg.sender == owner);
    }
}
"#;
    let graph = propagate_source(source);

    // _checkOwner has direct authority, withdraw inherits it
    assert!(graph
        .enforced_functions
        .contains(&"_checkOwner".to_string()));
    assert!(graph.enforced_functions.contains(&"withdraw".to_string()));
    // deposit has no authority
    assert!(graph.missing_authority.contains(&"deposit".to_string()));
    // Summary should reflect propagated authority
    assert!(
        graph.summary.enforced_count >= 2,
        "Should have at least 2 enforced functions"
    );
}

// ─────────────────────────────────────────────────────────────
// 10. No AI or heuristics
// ─────────────────────────────────────────────────────────────

#[test]
fn no_ai_or_heuristics() {
    let source = r#"
contract Test {
    function foo() public {}
}
"#;
    let graph = propagate_source(source);
    let json = serde_json::to_string(&graph).unwrap();

    assert!(!json.contains("confidence"));
    assert!(!json.contains("probability"));
    assert!(!json.contains("heuristic"));
    assert!(!json.contains("risk_score"));
}
