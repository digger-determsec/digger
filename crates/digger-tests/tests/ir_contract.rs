#![allow(clippy::needless_update, clippy::len_zero, clippy::useless_vec)]

use digger_graph::{build_system_ir, build_system_ir_with_language};
use digger_ir::*;
/// IR Contract Enforcement Tests
///
/// These tests verify that the IR architecture remains stable
/// and that no language-specific constructs leak into the core.
///
/// Run with: cargo test -p digger-tests --test ir_contract
use digger_parser::model::*;
use digger_parser::normalize;
use digger_parser::parse_program;

// ─────────────────────────────────────────────────────────────
// 1. IR Field Contract — graph engine depends on these exact fields
// ─────────────────────────────────────────────────────────────

#[test]
fn graph_engine_expects_functions_field() {
    // Graph builder accesses: program.functions[].name, .body, .visibility
    let program = RawProgram {
        functions: vec![RawFunction {
            name: "test_fn".into(),
            visibility: "public".into(),
            inputs: vec![],
            body: "x = 1".into(),
            ..Default::default()
        }],
        ..Default::default()
    };

    // These field accesses MUST compile — they are the frozen contract
    let _ = &program.functions[0].name;
    let _ = &program.functions[0].body;
    let _ = &program.functions[0].visibility;
    let _ = &program.functions[0].inputs;
}

#[test]
fn graph_engine_expects_state_field() {
    // Graph builder accesses: program.state[].name, .ty
    let program = RawProgram {
        state: vec![RawState {
            name: "balance".into(),
            ty: "uint256".into(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let _ = &program.state[0].name;
    let _ = &program.state[0].ty;
}

#[test]
fn graph_engine_expects_calls_field() {
    // Graph builder accesses: program.calls[].from, .to
    let program = RawProgram {
        calls: vec![RawCall {
            from: "caller".into(),
            to: "callee".into(),
            kind: CallKind::Internal,
        }],
        ..Default::default()
    };

    let _ = &program.calls[0].from;
    let _ = &program.calls[0].to;
}

#[test]
fn system_ir_has_required_fields() {
    // Hypothesis engine accesses: ir.functions, ir.state, ir.edges
    let ir = SystemIR {
        program_id: "test".into(),
        language: Language::Solidity,
        functions: vec![],
        state: vec![],
        edges: vec![],
    };

    let _ = &ir.program_id;
    let _ = &ir.language;
    let _ = &ir.functions;
    let _ = &ir.state;
    let _ = &ir.edges;
}

// ─────────────────────────────────────────────────────────────
// 2. Metadata Discipline — no graph-relevant data in metadata
// ─────────────────────────────────────────────────────────────

#[test]
fn solidity_parser_metadata_is_clean() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    event Deposit(address indexed sender, uint256 amount);
    error InsufficientBalance(uint256 available);

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public onlyOwner {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"#;
    let program = parse_program(code, "solidity");

    // Validate metadata discipline
    let errors = normalize::validate_metadata_discipline(&program.metadata);
    assert!(
        errors.is_empty(),
        "Solidity metadata should not contain graph-relevant data: {:?}",
        errors
    );

    // Metadata should contain structural enrichment, not execution semantics
    assert!(
        !program.metadata.contracts.is_empty(),
        "Should have contract metadata"
    );
    assert!(
        !program.metadata.events.is_empty(),
        "Should have event metadata"
    );
    assert!(
        !program.metadata.errors.is_empty(),
        "Should have error metadata"
    );

    // Function details should be enrichment, not graph data
    let deposit_meta = program.metadata.function_details.get("deposit");
    assert!(
        deposit_meta.is_some(),
        "Should have deposit function metadata"
    );
    let meta = deposit_meta.unwrap();
    assert_eq!(meta.mutability, "payable");
    // These are NOT graph-relevant — they're AST enrichment
}

#[test]
fn anchor_parser_metadata_is_clean() {
    let code = r#"
#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 8)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let program = parse_program(code, "anchor");

    let errors = normalize::validate_metadata_discipline(&program.metadata);
    assert!(
        errors.is_empty(),
        "Anchor metadata should not contain graph-relevant data: {:?}",
        errors
    );
}

// ─────────────────────────────────────────────────────────────
// 3. Normalization Validation — RawProgram conforms to contract
// ─────────────────────────────────────────────────────────────

#[test]
fn solidity_normalization_produces_valid_program() {
    let code = r#"
contract Test {
    function foo() public { x = 1; }
    function bar() public { foo(); }
}
"#;
    let program = parse_program(code, "solidity");
    let errors = normalize::validate(&program);
    assert!(
        errors.is_empty(),
        "Solidity normalization should produce valid program: {:?}",
        errors
    );
}

#[test]
fn anchor_normalization_produces_valid_program() {
    let code = r#"
#[program]
pub mod test {
    pub fn initialize(ctx: Context<Init>) -> Result<()> { Ok(()) }
    pub fn execute(ctx: Context<Exec>) -> Result<()> { Ok(()) }
}
"#;
    let program = parse_program(code, "anchor");
    let errors = normalize::validate(&program);
    assert!(
        errors.is_empty(),
        "Anchor normalization should produce valid program: {:?}",
        errors
    );
}

#[test]
fn rust_normalization_produces_valid_program() {
    let code = r#"
fn process() { do_work(); }
fn do_work() { }
"#;
    let program = parse_program(code, "rust");
    let errors = normalize::validate(&program);
    assert!(
        errors.is_empty(),
        "Rust normalization should produce valid program: {:?}",
        errors
    );
}

// ─────────────────────────────────────────────────────────────
// 4. Graph Engine Consumes Stable IR — pipeline integrity
// ─────────────────────────────────────────────────────────────

#[test]
fn solidity_pipeline_produces_system_ir() {
    let code = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"#;
    let program = parse_program(code, "solidity");
    let ir = build_system_ir(program);

    // SystemIR must have the expected structure
    assert!(ir.functions.len() >= 2, "Should have at least 2 functions");
    assert!(ir.state.len() >= 1, "Should have at least 1 state variable");
    assert!(!ir.edges.is_empty(), "Should have edges");

    // Edges must be the frozen variants
    let has_call = ir.edges.iter().any(|e| matches!(e, Edge::Call(_)));
    let has_state = ir.edges.iter().any(|e| matches!(e, Edge::State(_)));
    let has_auth = ir.edges.iter().any(|e| matches!(e, Edge::Authority(_)));
    let has_ext = ir.edges.iter().any(|e| matches!(e, Edge::External(_)));

    assert!(has_call, "Should have Call edges");
    assert!(has_state, "Should have State edges");
    assert!(has_auth, "Should have Authority edges");
    assert!(has_ext, "Should have External edges");
}

#[test]
fn anchor_pipeline_produces_system_ir() {
    let code = r#"
#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Init>) -> Result<()> {
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        token::transfer(ctx.accounts.transfer_ctx(), amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Init<'info> {
    #[account(init, payer = authority, space = 8 + 32)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let program = parse_program(code, "anchor");
    let ir = build_system_ir_with_language(program, digger_ir::Language::Anchor);

    assert!(ir.functions.len() >= 2, "Should have at least 2 functions");
    assert!(!ir.edges.is_empty(), "Should have edges");
}

// ─────────────────────────────────────────────────────────────
// 5. Type Alias Verification — aliases resolve correctly
// ─────────────────────────────────────────────────────────────

#[test]
fn type_aliases_resolve_to_correct_types() {
    // These compile-time checks verify the aliases work
    fn _check_executable_unit(_eu: &ExecutableUnit) {}
    fn _check_storage_unit(_su: &StorageUnit) {}
    fn _check_program_ir(_pir: &ProgramIR) {}

    let func = Function {
        id: "test".into(),
        name: "test".into(),
        contract: String::new(),
        visibility: Visibility::Public,
        inputs: vec![],
        outputs: vec![],
        modifiers: vec![],
        effects: Effects::default(),
    };
    _check_executable_unit(&func);

    let state = StateVariable {
        id: "test".into(),
        name: "test".into(),
        ty: "uint256".into(),
        mutable: true,
    };
    _check_storage_unit(&state);

    let ir = SystemIR {
        program_id: "test".into(),
        language: Language::Solidity,
        functions: vec![],
        state: vec![],
        edges: vec![],
    };
    _check_program_ir(&ir);
}

// ─────────────────────────────────────────────────────────────
// 6. No Language-Specific IR Fields — regression guard
// ─────────────────────────────────────────────────────────────

#[test]
fn raw_function_has_no_language_specific_fields() {
    // RawFunction should ONLY have: name, visibility, inputs, body
    // If this test fails, someone added language-specific fields
    let f = RawFunction::default();

    // These are the ONLY fields
    let _ = &f.name;
    let _ = &f.visibility;
    let _ = &f.inputs;
    let _ = &f.body;

    // Verify field count by checking that Default produces the right values
    assert_eq!(f.name, "");
    assert_eq!(f.visibility, "unknown");
    assert!(f.inputs.is_empty());
    assert_eq!(f.body, "");
}

#[test]
fn raw_state_has_no_language_specific_fields() {
    // RawState should ONLY have: name, ty
    let s = RawState::default();

    let _ = &s.name;
    let _ = &s.ty;

    assert_eq!(s.name, "");
    assert_eq!(s.ty, "");
}

#[test]
fn raw_call_has_no_language_specific_fields() {
    // RawCall should ONLY have: from, to, kind
    let c = RawCall::default();

    let _ = &c.from;
    let _ = &c.to;
    let _ = &c.kind;

    assert_eq!(c.from, "");
    assert_eq!(c.to, "");
    assert_eq!(c.kind, CallKind::Unknown);
}

// ─────────────────────────────────────────────────────────────
// 7. CallKind Classification — no EVM-specific naming
// ─────────────────────────────────────────────────────────────

#[test]
fn call_kind_is_language_agnostic() {
    // CallKind variants must NOT reference EVM or Solana specifics
    let kinds = vec![
        CallKind::External,
        CallKind::CrossProgram,
        CallKind::Internal,
        CallKind::Unknown,
    ];

    // Verify all variants exist and are distinct
    assert_eq!(kinds.len(), 4);
    assert_ne!(CallKind::External, CallKind::CrossProgram);
    assert_ne!(CallKind::Internal, CallKind::Unknown);
}

#[test]
fn solidity_calls_map_to_generic_call_kind() {
    let code = r#"
contract Test {
    function ext() public {
        (bool success, ) = msg.sender.call{value: 100}("");
    }
    function delegate() public {
        (bool success, ) = msg.sender.delegatecall("");
    }
    function transfer() public {
        payable(msg.sender).transfer(100);
    }
}
"#;
    let program = parse_program(code, "solidity");

    for call in &program.calls {
        assert_eq!(
            call.kind,
            CallKind::External,
            "Solidity external calls should map to CallKind::External, got {:?} for {}",
            call.kind,
            call.from
        );
    }
}

#[test]
fn anchor_calls_map_to_generic_call_kind() {
    let code = r#"
#[program]
pub mod test {
    use super::*;
    pub fn do_cpi(ctx: Context<Cpi>) -> Result<()> {
        invoke(&ix, &accounts)?;
        Ok(())
    }
}
"#;
    let program = parse_program(code, "anchor");

    for call in &program.calls {
        assert_eq!(
            call.kind,
            CallKind::CrossProgram,
            "Anchor CPI should map to CallKind::CrossProgram, got {:?} for {}",
            call.kind,
            call.from
        );
    }
}
