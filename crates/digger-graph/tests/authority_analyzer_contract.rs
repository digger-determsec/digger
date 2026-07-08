/// Authority Analyzer Contract Tests — Phase 7.1
use digger_graph::analysis::*;
use digger_parser::parse_program;

fn analyze_source(source: &str) -> AuthorityGraph {
    let program = parse_program(source, "solidity");
    analyze_authority(&program)
}

// ─────────────────────────────────────────────────────────────
// 1. Owner checks
// ─────────────────────────────────────────────────────────────

#[test]
fn owner_check_detected() {
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
    let graph = analyze_source(source);

    let change_owner = graph
        .relations
        .iter()
        .find(|r| r.function == "changeOwner")
        .unwrap();
    assert!(
        change_owner.enforced,
        "changeOwner should have enforced authority"
    );
    assert!(
        !change_owner.is_invariant,
        "changeOwner should not be invariant-only"
    );
    // Unified analyzer: msg.sender == owner → MsgSender with Ownership check
    // (more accurate than OwnerVariable — the authority source is msg.sender)
    assert_eq!(change_owner.source, AuthoritySource::MsgSender);
    assert_eq!(change_owner.check_type, AuthorityCheckType::Ownership);
}

#[test]
fn msg_sender_check_detected() {
    let source = r#"
contract Vault {
    address public admin;

    function setAdmin(address newAdmin) public {
        require(msg.sender == admin);
        admin = newAdmin;
    }
}
"#;
    let graph = analyze_source(source);

    let set_admin = graph
        .relations
        .iter()
        .find(|r| r.function == "setAdmin")
        .unwrap();
    assert!(
        set_admin.enforced,
        "setAdmin should have enforced authority"
    );
    assert_eq!(set_admin.source, AuthoritySource::MsgSender);
}

// ─────────────────────────────────────────────────────────────
// 2. AccessControl roles
// ─────────────────────────────────────────────────────────────

#[test]
fn role_check_detected() {
    let source = r#"
contract AccessControl {
    mapping(address => mapping(bytes32 => bool)) public roles;

    function grantRole(bytes32 role, address account) public {
        require(roles[msg.sender][role]);
        roles[account][role] = true;
    }
}
"#;
    let graph = analyze_source(source);

    let grant = graph
        .relations
        .iter()
        .find(|r| r.function == "grantRole")
        .unwrap();
    assert!(grant.enforced, "grantRole should have enforced authority");
    assert_eq!(grant.source, AuthoritySource::RoleMapping);
    assert_eq!(grant.check_type, AuthorityCheckType::Role);
}

// ─────────────────────────────────────────────────────────────
// 3. Modifier propagation
// ─────────────────────────────────────────────────────────────

#[test]
fn modifier_propagation() {
    let source = r#"
contract Ownable {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function withdraw() public onlyOwner {
        // sends ETH
    }

    function pause() public onlyOwner {
        // pauses contract
    }
}
"#;
    let graph = analyze_source(source);

    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    let pause = graph
        .relations
        .iter()
        .find(|r| r.function == "pause")
        .unwrap();

    assert!(
        withdraw.enforced,
        "withdraw should inherit authority from onlyOwner"
    );
    assert!(
        pause.enforced,
        "pause should inherit authority from onlyOwner"
    );
    assert!(
        !withdraw.modifiers.is_empty(),
        "withdraw should have modifiers"
    );
    assert!(!pause.modifiers.is_empty(), "pause should have modifiers");

    // Check propagation chains
    assert!(
        graph
            .propagation_chains
            .iter()
            .any(|(m, f)| m == "onlyOwner" && f == "withdraw"),
        "Should have propagation chain from onlyOwner to withdraw"
    );
}

// ─────────────────────────────────────────────────────────────
// 4. Nested helper functions
// ─────────────────────────────────────────────────────────────

#[test]
fn helper_function_authority() {
    let source = r#"
contract Vault {
    address public owner;

    function withdraw() public {
        require(msg.sender == owner);
        _doTransfer();
    }

    function _doTransfer() internal {
        // sends ETH
    }
}
"#;
    let graph = analyze_source(source);

    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    assert!(withdraw.enforced, "withdraw should have enforced authority");

    // _doTransfer has no authority check itself
    let do_transfer = graph.relations.iter().find(|r| r.function == "_doTransfer");
    if let Some(dt) = do_transfer {
        assert!(
            !dt.enforced,
            "_doTransfer should not have its own authority"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 5. PDA authorities (Solana)
// ─────────────────────────────────────────────────────────────

#[test]
fn pda_authority_detected() {
    let source = r#"
#[program]
mod my_program {
    use super::*;

    pub fn update_config(ctx: Context<UpdateConfig>) -> Result<()> {
        // has_one = authority in account constraints
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(has_one = authority)]
    pub config: Account<'info, Config>,
    pub authority: Signer<'info>,
}
"#;
    let graph = analyze_source(source);

    // The has_one pattern should be detected as PDA authority
    let update = graph
        .relations
        .iter()
        .find(|r| r.function == "update_config");
    if let Some(u) = update {
        assert!(
            u.source == AuthoritySource::PdaAuthority || u.source == AuthoritySource::Signer,
            "Should detect PDA or Signer authority, got: {:?}",
            u.source
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 6. Multisig authorities
// ─────────────────────────────────────────────────────────────

#[test]
fn multisig_authority_detected() {
    let source = r#"
contract Multisig {
    mapping(address => bool) public signers;
    uint256 public threshold;
    uint256 public approvalCount;

    function approve() public {
        require(signers[msg.sender]);
        approvalCount += 1;
    }

    function execute() public {
        require(approvalCount >= threshold);
        // execute transaction
    }
}
"#;
    let graph = analyze_source(source);

    let _execute = graph
        .relations
        .iter()
        .find(|r| r.function == "execute")
        .unwrap();
    // execute has a require that checks threshold — this is a multisig pattern
    // The threshold check is an invariant (balance check), not authority
    // But the signers check in approve IS authority
    let approve = graph
        .relations
        .iter()
        .find(|r| r.function == "approve")
        .unwrap();
    assert!(approve.enforced, "approve should have enforced authority");
}

// ─────────────────────────────────────────────────────────────
// 7. Governance authorities
// ─────────────────────────────────────────────────────────────

#[test]
fn governance_authority_detected() {
    let source = r#"
contract Governor {
    mapping(uint256 => bool) public proposals;

    function executeProposal(uint256 proposalId) public {
        require(proposals[proposalId]);
        // execute governance action
    }
}
"#;
    let graph = analyze_source(source);

    let execute = graph
        .relations
        .iter()
        .find(|r| r.function == "executeProposal")
        .unwrap();
    // This has require + proposal, so it should be detected as governance
    assert!(
        execute.enforced || execute.is_invariant,
        "Should be either enforced or invariant"
    );
}

// ─────────────────────────────────────────────────────────────
// 8. Negative cases — ordinary invariants
// ─────────────────────────────────────────────────────────────

#[test]
fn balance_check_is_invariant() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
    }
}
"#;
    let graph = analyze_source(source);

    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    // require(balances[msg.sender] >= amount) is an invariant, not authority
    assert!(
        withdraw.is_invariant,
        "Balance check should be classified as invariant"
    );
    assert!(
        !withdraw.enforced,
        "Balance check should not be enforced authority"
    );
}

#[test]
fn initialized_check_is_invariant() {
    let source = r#"
contract Initializable {
    bool public initialized;

    function initialize() public {
        require(!initialized);
        initialized = true;
    }
}
"#;
    let graph = analyze_source(source);

    let init = graph
        .relations
        .iter()
        .find(|r| r.function == "initialize")
        .unwrap();
    // require(!initialized) is an invariant guard, not authority
    assert!(
        init.is_invariant,
        "Initialization guard should be classified as invariant"
    );
}

#[test]
fn success_check_is_invariant() {
    let source = r#"
contract Vault {
    function transfer() public {
        (bool success, ) = msg.sender.call{value: 100}("");
        require(success);
    }
}
"#;
    let graph = analyze_source(source);

    let transfer = graph
        .relations
        .iter()
        .find(|r| r.function == "transfer")
        .unwrap();
    // require(success) is a result check, not authority
    assert!(
        transfer.is_invariant,
        "Success check should be classified as invariant"
    );
}

#[test]
fn no_check_is_missing() {
    let source = r#"
contract Vault {
    address public owner;

    function withdraw() public {
        // No check at all
    }
}
"#;
    let graph = analyze_source(source);

    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    assert!(!withdraw.enforced, "No check should not be enforced");
    assert!(!withdraw.is_invariant, "No check should not be invariant");
    assert_eq!(withdraw.check_type, AuthorityCheckType::Missing);
}

// ─────────────────────────────────────────────────────────────
// 9. Deterministic ordering
// ─────────────────────────────────────────────────────────────

#[test]
fn deterministic_output() {
    let source = r#"
contract Test {
    address public owner;
    function a() public { require(msg.sender == owner); }
    function b() public { require(msg.sender == owner); }
    function c() public { require(msg.sender == owner); }
}
"#;

    let g1 = analyze_source(source);
    let g2 = analyze_source(source);
    let g3 = analyze_source(source);

    assert_eq!(g1, g2);
    assert_eq!(g2, g3);
}

#[test]
fn relations_sorted_by_function_name() {
    let source = r#"
contract Test {
    function zebra() public { require(msg.sender != address(0)); }
    function alpha() public { require(msg.sender != address(0)); }
    function middle() public { require(msg.sender != address(0)); }
}
"#;
    let graph = analyze_source(source);

    for i in 1..graph.relations.len() {
        assert!(
            graph.relations[i - 1].function <= graph.relations[i].function,
            "Relations must be sorted by function name"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 10. Serialization
// ─────────────────────────────────────────────────────────────

#[test]
fn serialization_roundtrip() {
    let source = r#"
contract Test {
    address public owner;
    function withdraw() public { require(msg.sender == owner); }
}
"#;
    let graph = analyze_source(source);

    let json = serde_json::to_string_pretty(&graph).unwrap();
    let deserialized: AuthorityGraph = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized, graph);
}

#[test]
fn serialization_stable() {
    let source = r#"
contract Test {
    address public owner;
    function withdraw() public { require(msg.sender == owner); }
}
"#;
    let graph = analyze_source(source);

    let json1 = serde_json::to_string(&graph).unwrap();
    let json2 = serde_json::to_string(&graph).unwrap();
    assert_eq!(json1, json2);
}

// ─────────────────────────────────────────────────────────────
// 11. Summary statistics
// ─────────────────────────────────────────────────────────────

#[test]
fn summary_correct() {
    let source = r#"
contract Test {
    address public owner;

    function authorized() public {
        require(msg.sender == owner);
    }

    function invariant_only() public {
        require(true);
    }

    function missing() public {
        // no check
    }
}
"#;
    let graph = analyze_source(source);

    assert_eq!(graph.summary.total_functions, 3);
    assert!(
        graph.summary.enforced_count >= 1,
        "Should have at least 1 enforced"
    );
    assert!(
        graph.summary.missing_count >= 1,
        "Should have at least 1 missing"
    );
    assert!(graph.summary.enforcement_rate >= 0.0);
    assert!(graph.summary.enforcement_rate <= 1.0);
}

// ─────────────────────────────────────────────────────────────
// 12. No AI or heuristics
// ─────────────────────────────────────────────────────────────

#[test]
fn no_ai_or_heuristics() {
    let source = r#"
contract Test {
    function foo() public {}
}
"#;
    let graph = analyze_source(source);
    let json = serde_json::to_string(&graph).unwrap();

    assert!(!json.contains("confidence"));
    assert!(!json.contains("probability"));
    assert!(!json.contains("heuristic"));
    assert!(!json.contains("risk_score"));
}

// ─────────────────────────────────────────────────────────────
// Phase 7.3.1 — Modifier Authority Unification Tests
// ─────────────────────────────────────────────────────────────

#[test]
fn modifier_owner_check_detected() {
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
    let graph = analyze_source(source);

    let change_owner = graph
        .relations
        .iter()
        .find(|r| r.function == "changeOwner")
        .unwrap();
    assert!(
        change_owner.enforced,
        "changeOwner should inherit authority from onlyOwner"
    );
    assert_eq!(change_owner.source, AuthoritySource::MsgSender);
}

#[test]
fn modifier_signer_detected() {
    let source = r#"
#[program]
mod my_program {
    pub fn process(ctx: Context<Process>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Process<'info> {
    pub authority: Signer<'info>,
}
"#;
    let graph = analyze_source(source);

    // Signer pattern should be detected
    let process = graph.relations.iter().find(|r| r.function == "process");
    if let Some(p) = process {
        assert!(
            p.source == AuthoritySource::Signer || p.enforced,
            "Should detect Signer authority"
        );
    }
}

#[test]
fn modifier_has_one_detected() {
    let source = r#"
#[program]
mod my_program {
    pub fn update(ctx: Context<Update>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(has_one = authority)]
    pub config: Account<'info, Config>,
    pub authority: Signer<'info>,
}
"#;
    let graph = analyze_source(source);

    let update = graph.relations.iter().find(|r| r.function == "update");
    if let Some(u) = update {
        assert!(
            u.source == AuthoritySource::PdaAuthority || u.source == AuthoritySource::Signer,
            "Should detect PDA or Signer authority"
        );
    }
}

#[test]
fn modifier_constraint_detected() {
    let source = r#"
#[program]
mod my_program {
    pub fn admin_action(ctx: Context<AdminAction>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct AdminAction<'info> {
    #[account(constraint = config.authority == user.key())]
    pub config: Account<'info, Config>,
    pub user: Signer<'info>,
}
"#;
    let graph = analyze_source(source);

    let admin = graph
        .relations
        .iter()
        .find(|r| r.function == "admin_action");
    if let Some(a) = admin {
        assert!(
            a.source == AuthoritySource::PdaAuthority || a.source == AuthoritySource::Signer,
            "Should detect constraint-based authority"
        );
    }
}

#[test]
fn modifier_balance_invariant() {
    let source = r#"
contract Vault {
    mapping(address => uint256) public balances;

    modifier hasBalance(uint256 amount) {
        require(balances[msg.sender] >= amount);
        _;
    }

    function withdraw(uint256 amount) public hasBalance(amount) {
        balances[msg.sender] -= amount;
    }
}
"#;
    let graph = analyze_source(source);

    let withdraw = graph
        .relations
        .iter()
        .find(|r| r.function == "withdraw")
        .unwrap();
    // The modifier is invariant (balance check), so it doesn't provide authority.
    // The function body has no authority check either → missing.
    assert!(
        !withdraw.enforced,
        "Balance modifier should not provide authority"
    );
    assert!(
        !withdraw.is_invariant,
        "Function itself is not invariant (modifier is)"
    );
}

#[test]
fn modifier_initialization_invariant() {
    let source = r#"
contract Initializable {
    bool public initialized;

    modifier initializer() {
        require(!initialized);
        _;
    }

    function init() public initializer {
        initialized = true;
    }
}
"#;
    let graph = analyze_source(source);

    let init = graph
        .relations
        .iter()
        .find(|r| r.function == "init")
        .unwrap();
    // The modifier is invariant (initialization guard), so it doesn't provide authority.
    // The function body has no authority check → missing.
    assert!(
        !init.enforced,
        "Initialization modifier should not provide authority"
    );
    assert!(
        !init.is_invariant,
        "Function itself is not invariant (modifier is)"
    );
}

#[test]
fn modifier_success_check_invariant() {
    let source = r#"
contract Vault {
    modifier checkSuccess(bool success) {
        require(success);
        _;
    }

    function transfer(bool success) public checkSuccess(success) {
        // transfer logic
    }
}
"#;
    let graph = analyze_source(source);

    let transfer = graph
        .relations
        .iter()
        .find(|r| r.function == "transfer")
        .unwrap();
    // The modifier is invariant (success check), so it doesn't provide authority.
    // The function body has no authority check → missing.
    assert!(
        !transfer.enforced,
        "Success check modifier should not provide authority"
    );
    assert!(
        !transfer.is_invariant,
        "Function itself is not invariant (modifier is)"
    );
}

#[test]
fn modifier_empty_body() {
    let source = r#"
contract Test {
    modifier noop() {
        _;
    }

    function foo() public noop {
        // no-op
    }
}
"#;
    let graph = analyze_source(source);

    let foo = graph
        .relations
        .iter()
        .find(|r| r.function == "foo")
        .unwrap();
    assert!(!foo.enforced, "Empty modifier should not provide authority");
    assert!(!foo.is_invariant, "Empty modifier should not be invariant");
}

#[test]
fn function_and_modifier_same_body_same_analysis() {
    // If a function body and a modifier body contain identical authority patterns,
    // they should produce the same authority classification.
    let source = r#"
contract Test {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function withModifier() public onlyOwner {
        // uses modifier
    }

    function withInlineCheck() public {
        require(msg.sender == owner);
        // inline check
    }
}
"#;
    let graph = analyze_source(source);

    let with_modifier = graph
        .relations
        .iter()
        .find(|r| r.function == "withModifier")
        .unwrap();
    let with_inline = graph
        .relations
        .iter()
        .find(|r| r.function == "withInlineCheck")
        .unwrap();

    // Both should have the same authority source
    assert_eq!(
        with_modifier.source, with_inline.source,
        "Same authority pattern should produce same source"
    );
    assert_eq!(
        with_modifier.enforced, with_inline.enforced,
        "Same authority pattern should produce same enforcement"
    );
    assert_eq!(
        with_modifier.is_invariant, with_inline.is_invariant,
        "Same authority pattern should produce same invariant classification"
    );
}
