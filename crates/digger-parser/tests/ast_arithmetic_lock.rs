//! Lock tests for AST-derived arithmetic detection.
//!
//! These tests freeze the contract: state-var reads inside arithmetic
//! subtrees are recorded via AST walk, local vars are not, and plain
//! add/sub does NOT set has_arithmetic.

use digger_parser::parse_program;

#[test]
fn lock_arith_state_var_read_in_mul_subtree() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public reserves;

    function withdraw(uint256 share) public {
        uint256 total = balances[msg.sender] * reserves[msg.sender];
        balances[msg.sender] -= share;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let withdraw_fn = program
        .functions
        .iter()
        .find(|f| f.name == "withdraw")
        .unwrap();
    assert!(
        withdraw_fn.has_arithmetic,
        "withdraw must have has_arithmetic"
    );
    let sria = program.metadata.extra.get("ast_arith_sria:withdraw");
    assert!(sria.is_some(), "ast_arith_sria:withdraw must exist");
    let set: std::collections::BTreeSet<String> =
        serde_json::from_value(sria.unwrap().clone()).unwrap();
    assert!(
        set.contains("balances"),
        "balances in state_reads_in_arithmetic"
    );
    assert!(
        set.contains("reserves"),
        "reserves in state_reads_in_arithmetic"
    );
}

#[test]
fn lock_arith_local_var_not_recorded() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function compute() public view returns (uint256) {
        uint256 localBal = 100;
        uint256 result = localBal * 2;
        return result;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let compute_fn = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    assert!(
        compute_fn.has_arithmetic,
        "compute must have has_arithmetic"
    );
    match program.metadata.extra.get("ast_arith_sria:compute") {
        None => {}
        Some(val) => {
            let set: std::collections::BTreeSet<String> =
                serde_json::from_value(val.clone()).unwrap();
            assert!(
                !set.contains("localBal"),
                "localBal is local, not state var"
            );
            assert!(!set.contains("result"), "result is local, not state var");
        }
    }
}

#[test]
fn lock_no_arith_on_plain_add_sub() {
    let code = r#"
contract ERC20 {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) public returns (bool) {
        balances[msg.sender] = balances[msg.sender] - amount;
        balances[to] = balances[to] + amount;
        return true;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let transfer_fn = program
        .functions
        .iter()
        .find(|f| f.name == "transfer")
        .unwrap();
    assert!(
        !transfer_fn.has_arithmetic,
        "plain add/sub must not set has_arithmetic"
    );
}

// ── Unchecked-block lock tests ──

/// Positive: arithmetic inside unchecked{} -> has_unchecked_arithmetic TRUE.
#[test]
fn lock_unchecked_arith_inside_unchecked_block() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function compute(uint256 rate) public {
        uint256 value;
        unchecked {
            value = balances[msg.sender] * rate;
        }
    }
}
"#;
    let program = parse_program(code, "solidity");
    let compute_fn = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    assert!(
        compute_fn.has_arithmetic,
        "compute must have has_arithmetic"
    );
    // Check metadata for unchecked flag
    let has_unchecked = program.metadata.extra.get("ast_unchecked_arith:compute");
    assert!(
        has_unchecked.is_some(),
        "ast_unchecked_arith:compute must exist for unchecked block"
    );
    assert!(
        has_unchecked.unwrap().as_bool().unwrap_or(false),
        "ast_unchecked_arith must be true when mul inside unchecked"
    );
}

/// Negative: arithmetic OUTSIDE unchecked{} -> has_unchecked_arithmetic FALSE.
#[test]
fn lock_unchecked_arith_outside_unchecked() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function compute(uint256 rate) public {
        uint256 value = balances[msg.sender] * rate;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let compute_fn = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    assert!(
        compute_fn.has_arithmetic,
        "compute must have has_arithmetic"
    );
    let has_unchecked = program.metadata.extra.get("ast_unchecked_arith:compute");
    assert!(
        has_unchecked.is_none() || !has_unchecked.unwrap().as_bool().unwrap_or(false),
        "ast_unchecked_arith must be FALSE when mul is outside unchecked"
    );
}

/// Negative: plain add/sub inside unchecked{} -> still governed by narrowed arith set.
/// has_unchecked_arithmetic should be FALSE because add/sub don't set has_arithmetic.
#[test]
fn lock_unchecked_add_sub_in_unchecked() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function compute() public {
        unchecked {
            balances[msg.sender] += 1;
        }
    }
}
"#;
    let program = parse_program(code, "solidity");
    let compute_fn = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    assert!(
        !compute_fn.has_arithmetic,
        "add/sub inside unchecked must NOT set has_arithmetic"
    );
    // unchecked flag may or may not be set -- but since has_arithmetic is false,
    // the unchecked_arith flag is meaningless for the detector
}

// ── Caller-scoped write lock tests (U4) ──

/// Positive: balances[msg.sender] = ... → caller_scoped flag TRUE.
#[test]
fn lock_caller_scoped_sender_index() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) public {
        balances[msg.sender] += amount;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _deposit = program
        .functions
        .iter()
        .find(|f| f.name == "deposit")
        .unwrap();
    // Note: += does NOT set has_arithmetic (mirrors plain add/subtract rule).
    // The caller_scoped flag is independent.
    let flag = program.metadata.extra.get("ast_caller_scoped:deposit");
    assert!(flag.is_some(), "ast_caller_scoped:deposit must exist");
    assert!(
        flag.unwrap().as_bool().unwrap_or(false),
        "flag must be true for msg.sender-indexed write"
    );
}

/// Hard-gate: Poly-style global consensus write → caller_scoped FALSE.
/// This lock prevents the flag from ever demoting Poly's putCurEpoch* TP.
#[test]
fn lock_caller_scoped_poly_global_consensus_write() {
    let code = r#"
contract Governance {
    mapping(bytes32 => bytes32) public epochConnectPubKeys;

    function putCurEpochConnectPubKeys(bytes32[4] calldata newKeys) public {
        epochConnectPubKeys[currentEpoch] = newKeys[0];
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "putCurEpochConnectPubKeys")
        .unwrap();
    let flag = program
        .metadata
        .extra
        .get("ast_caller_scoped:putCurEpochConnectPubKeys");
    assert!(
        flag.is_none() || !flag.unwrap().as_bool().unwrap_or(false),
        "Poly global consensus write must NOT be flagged caller_scoped"
    );
}
#[test]
fn lock_caller_scoped_global_write() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public reserves;

    function updateReserves(address user, uint256 amount) public {
        reserves[user] += amount;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "updateReserves")
        .unwrap();
    let flag = program
        .metadata
        .extra
        .get("ast_caller_scoped:updateReserves");
    assert!(
        flag.is_none() || !flag.unwrap().as_bool().unwrap_or(false),
        "global write (not msg.sender-keyed) must NOT set caller_scoped flag"
    );
}

// ── Precision-loss ordering lock tests (U2) ──

/// Positive: a / b * c → precision_loss_ordering TRUE.
#[test]
fn lock_precision_loss_div_before_mul() {
    let code = r#"
contract Vault {
    uint256 public rate;

    function compute(uint256 a, uint256 b, uint256 c) public view returns (uint256) {
        return a / b * c;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    let flag = program.metadata.extra.get("ast_prec_loss:compute");
    assert!(
        flag.is_some(),
        "ast_prec_loss:compute must exist for div-before-mul"
    );
    assert!(
        flag.unwrap().as_bool().unwrap_or(false),
        "div-before-mul must set precision_loss_ordering"
    );
}

/// Negative: a * b / c (mul-then-div, safe ordering) → flag FALSE.
#[test]
fn lock_precision_loss_mul_then_div_safe() {
    let code = r#"
contract Vault {
    function compute(uint256 a, uint256 b, uint256 c) public view returns (uint256) {
        return a * b / c;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    let flag = program.metadata.extra.get("ast_prec_loss:compute");
    assert!(
        flag.is_none() || !flag.unwrap().as_bool().unwrap_or(false),
        "mul-then-div must NOT set precision_loss_ordering"
    );
}

/// Negative: pure mul, no div → flag FALSE.
#[test]
fn lock_precision_loss_pure_mul() {
    let code = r#"
contract Vault {
    function compute(uint256 a, uint256 b) public view returns (uint256) {
        return a * b;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    let flag = program.metadata.extra.get("ast_prec_loss:compute");
    assert!(
        flag.is_none() || !flag.unwrap().as_bool().unwrap_or(false),
        "pure mul must NOT set precision_loss_ordering"
    );
}

/// Negative: pure div, no mul parent → flag FALSE.
#[test]
fn lock_precision_loss_pure_div() {
    let code = r#"
contract Vault {
    function compute(uint256 a, uint256 b) public view returns (uint256) {
        return a / b;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    let flag = program.metadata.extra.get("ast_prec_loss:compute");
    assert!(
        flag.is_none() || !flag.unwrap().as_bool().unwrap_or(false),
        "pure div must NOT set precision_loss_ordering"
    );
}

/// Poly-style guard: global consensus write must NOT flag precision_loss either.
#[test]
fn lock_precision_loss_poly_unaffected() {
    let code = r#"
contract Governance {
    mapping(bytes32 => bytes32) public epochConnectPubKeys;

    function putCurEpochConnectPubKeys(bytes32[4] calldata newKeys) public {
        epochConnectPubKeys[currentEpoch] = newKeys[0];
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "putCurEpochConnectPubKeys")
        .unwrap();
    let flag = program
        .metadata
        .extra
        .get("ast_prec_loss:putCurEpochConnectPubKeys");
    assert!(
        flag.is_none() || !flag.unwrap().as_bool().unwrap_or(false),
        "Poly global write must NOT set precision_loss_ordering"
    );
}

// ── Precision-loss walker lock tests (strip_parens fix) ──

/// Positive: (a / b) * c → flag true (parens transparent).
#[test]
fn lock_precision_loss_div_before_mul_parens() {
    let code = r#"
contract Vault {
    function compute(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return (a / b) * c;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    let flag = program.metadata.extra.get("ast_prec_loss:compute");
    assert!(flag.is_some(), "ast_prec_loss:compute must exist");
    assert!(
        flag.unwrap().as_bool().unwrap_or(false),
        "div-before-mul with parens must set flag"
    );
}

/// Positive: x = (a / b) * c → flag true (AssignMultiply path).
#[test]
fn lock_precision_loss_assign_div_before_mul() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    function compute(uint256 a, uint256 b, uint256 c) public {
        balances[msg.sender] = (a / b) * c;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    let flag = program.metadata.extra.get("ast_prec_loss:compute");
    assert!(flag.is_some(), "assign div-before-mul must set flag");
    assert!(flag.unwrap().as_bool().unwrap_or(false));
}

/// Negative: (a + b) * c → flag false (no divide).
#[test]
fn lock_precision_loss_add_before_mul() {
    let code = r#"
contract Vault {
    function compute(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return (a + b) * c;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    let flag = program.metadata.extra.get("ast_prec_loss:compute");
    assert!(
        flag.is_none() || !flag.unwrap().as_bool().unwrap_or(false),
        "add-before-mul must NOT set flag"
    );
}

/// Negative: (a * b) + c → flag false (no divide feeding multiply).
#[test]
fn lock_precision_loss_mul_then_add() {
    let code = r#"
contract Vault {
    function compute(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return (a * b) + c;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let _f = program
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .unwrap();
    let flag = program.metadata.extra.get("ast_prec_loss:compute");
    assert!(
        flag.is_none() || !flag.unwrap().as_bool().unwrap_or(false),
        "mul-then-add must NOT set flag"
    );
}
