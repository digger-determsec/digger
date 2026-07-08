//! Builder-level lock tests: verify that the IR Effects layer correctly
//! propagates AST-derived arithmetic signals from the parser.

use digger_graph::build_system_ir_with_language;
use digger_ir::Language;
use digger_parser::parse_program;

/// Builder lock: state-var in mul → has_arithmetic true + SRIA contains it.
#[test]
fn builder_lock_solidity_state_var_mul() {
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
    let raw = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(raw, Language::Solidity);
    let f = ir.functions.iter().find(|f| f.name == "withdraw").unwrap();
    assert!(
        f.effects.has_arithmetic,
        "IR: withdraw must have has_arithmetic"
    );
    let vf = f
        .effects
        .value_flow
        .as_ref()
        .expect("value_flow must be set");
    assert!(
        vf.state_reads_in_arithmetic
            .contains(&"balances".to_string()),
        "balances in SRIA"
    );
    assert!(
        vf.state_reads_in_arithmetic
            .contains(&"reserves".to_string()),
        "reserves in SRIA"
    );
}

/// Builder lock: plain add/sub → has_arithmetic FALSE at IR level.
#[test]
fn builder_lock_solidity_add_sub_no_flag() {
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
    let raw = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(raw, Language::Solidity);
    let f = ir.functions.iter().find(|f| f.name == "transfer").unwrap();
    assert!(
        !f.effects.has_arithmetic,
        "add/sub must NOT have has_arithmetic at IR level"
    );
}

/// Builder lock: Solidity fn with arithmetic on params only → SRIA empty.
#[test]
fn builder_lock_solidity_arith_no_state_vars() {
    let code = r#"
contract Vault {
    function compute(uint256 a, uint256 b) public pure returns (uint256) {
        return a * b + a / b;
    }
}
"#;
    let raw = parse_program(code, "solidity");
    let ir = build_system_ir_with_language(raw, Language::Solidity);
    let f = ir.functions.iter().find(|f| f.name == "compute").unwrap();
    assert!(f.effects.has_arithmetic, "compute must have has_arithmetic");
    let vf = f
        .effects
        .value_flow
        .as_ref()
        .expect("value_flow must be set");
    assert!(
        vf.state_reads_in_arithmetic.is_empty(),
        "pure arithmetic on params must have EMPTY SRIA"
    );
}
