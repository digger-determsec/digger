//! Owner-guard recognition tests.
//!
//! Verifies the authority-bypass detector correctly recognizes functions behind
//! owner/access modifiers that delegate to private helpers — including cross-file
//! inheritance resolution and name-collision safety.

use digger_graph::build_system_ir_with_language;
use digger_hypothesis::derive;
use digger_hypothesis::models::{HypothesisSeverity, HypothesisType};
use digger_ir::Language;
use digger_parser::parse_program;

// ── Same-file tests ──────────────────────────────────────────

/// POSITIVE: ownerOnly modifier delegates to _ownerOnly() containing
/// require(msg.sender == owner). Guarded function must NOT be flagged.
#[test]
fn positive_owner_guard_same_file() {
    let source = r#"
        contract Owned {
            address private _owner;
            modifier ownerOnly() { _ownerOnly(); _; }
            function _ownerOnly() private view { require(msg.sender == _owner); }
            function setFee(uint32 f) external ownerOnly { fee = f; }
            uint32 fee;
        }
    "#;
    let program = parse_program(source, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();
    assert!(
        auth.iter()
            .find(|h| h.primary_function == "setFee")
            .is_none(),
        "setFee should be recognized as owner-guarded"
    );
}

/// NEGATIVE 1: modifier delegates to a helper WITHOUT authority check.
/// The function must still be flagged.
#[test]
fn negative_fake_modifier_still_flagged() {
    let source = r#"
        contract FakeGuard {
            address private _owner;
            modifier fakeOwnerOnly() { _fakeCheck(); _; }
            function _fakeCheck() private view { require(block.number > 0); }
            function setConfig(uint256 v) external fakeOwnerOnly { config = v; }
            uint256 config;
        }
    "#;
    let program = parse_program(source, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();
    let sc = auth.iter().find(|h| h.primary_function == "setConfig");
    assert!(
        sc.is_some(),
        "setConfig with fake guard should still be flagged"
    );
    assert_eq!(sc.unwrap().severity, HypothesisSeverity::Critical);
}

/// NEGATIVE 2: genuinely permissionless state-mutating function with no modifier.
#[test]
fn negative_no_modifier_still_flagged() {
    let source = r#"
        contract OpenVault {
            mapping(address => uint256) public balances;
            function deposit() external { balances[msg.sender] += msg.value; }
        }
    "#;
    let program = parse_program(source, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();
    assert!(
        auth.iter()
            .find(|h| h.primary_function == "deposit")
            .is_some(),
        "deposit with no modifier must still be flagged"
    );
}

// ── Cross-file tests ─────────────────────────────────────────

/// Cross-file positive: NetworkSettings inherits Owned, uses ownerOnly.
/// Modifier + helper are in Owned.sol. Must NOT be flagged when both parsed together.
#[test]
fn cross_file_owner_guard_recognized() {
    let owned = include_str!("fixtures/real-corpus/bancor/contracts/utility/Owned.sol");
    let ns = include_str!("fixtures/real-corpus/bancor/contracts/NetworkSettings.sol");
    let combined = format!("{}\n\n{}", owned, ns);
    let program = parse_program(&combined, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();
    assert!(
        auth.iter()
            .find(|h| h.primary_function == "setNetworkFee")
            .is_none(),
        "setNetworkFee should be recognized as owner-guarded via cross-file resolution"
    );
}

/// Cross-file NEGATIVE: a modifier that delegates to a fake check across files.
#[test]
fn cross_file_fake_modifier_still_flagged() {
    let base = r#"
        contract BaseGuard {
            modifier safeGuard() { _fakeCheck(); _; }
            function _fakeCheck() private view { require(block.number > 0); }
        }
    "#;
    let child = r#"
        contract Child is BaseGuard {
            uint256 public config;
            function setConfig(uint256 v) external safeGuard { config = v; }
        }
    "#;
    let combined = format!("{}\n\n{}", base, child);
    let program = parse_program(&combined, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();
    let sc = auth.iter().find(|h| h.primary_function == "setConfig");
    assert!(
        sc.is_some(),
        "setConfig behind fake cross-file guard should still be flagged"
    );
    assert_eq!(sc.unwrap().severity, HypothesisSeverity::Critical);
}

/// RECALL GUARD: Poly-style function with no modifier, parsed alongside Owned.
/// Detection only (severity assertion not guaranteed — the old OR-logic may
/// demote mapping-only writers to Medium on main).
#[test]
fn recall_guard_poly_detected() {
    let owned = include_str!("fixtures/real-corpus/bancor/contracts/utility/Owned.sol");
    let poly = r#"
        contract PolyConfig {
            mapping(bytes32 => mapping(address => bytes)) public configs;
            function putCurEpochConnectPubKeyBytes(bytes memory d) external {
                configs[0][msg.sender] = d;
            }
        }
    "#;
    let combined = format!("{}\n\n{}", owned, poly);
    let program = parse_program(&combined, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();
    assert!(
        auth.iter()
            .find(|h| h.primary_function == "putCurEpochConnectPubKeyBytes")
            .is_some(),
        "Poly-style function must still be detected alongside Owned.sol"
    );
}

/// RECALL GUARD 2: Poly-style function with no modifier (no Owned.sol present).
#[test]
fn recall_guard_poly_no_modifier() {
    let source = r#"
        contract PolyConfig {
            mapping(bytes32 => mapping(address => bytes)) public configs;
            function putCurEpochConnectPubKeyBytes(bytes memory d) external {
                configs[0][msg.sender] = d;
            }
        }
    "#;
    let program = parse_program(source, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();
    assert!(
        auth.iter()
            .find(|h| h.primary_function == "putCurEpochConnectPubKeyBytes")
            .is_some(),
        "Poly-style function without modifier must be detected"
    );
}

// ── Name-collision negative control ──────────────────────────

/// NAME-COLLISION test: ContractA has a fake _check() (no authority) while
/// ContractB has a real _check() (require(msg.sender == owner)). ContractA
/// uses a modifier that delegates to _check(). With the unscoped global lookup,
/// the resolver would find ContractB's real _check() and incorrectly suppress
/// the finding. With inheritance-scoped resolution, ContractA's own fake _check()
/// is found first, and the function MUST stay flagged.
#[test]
fn name_collision_fake_helper_not_suppressed() {
    let source = r#"
        contract RealGuard {
            modifier realGuard() { _check(); _; }
            function _check() private view { require(msg.sender == owner); }
            address owner;
            function setA(uint256 v) external realGuard { a = v; }
            uint256 a;
        }

        contract FakeGuard {
            modifier fakeGuard() { _check(); _; }
            function _check() private view { require(block.number > 0); }
            function setB(uint256 v) external fakeGuard { b = v; }
            uint256 b;
        }
    "#;
    let program = parse_program(source, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();

    // setA: real guard -> should NOT be flagged
    assert!(
        auth.iter().find(|h| h.primary_function == "setA").is_none(),
        "setA with real guard should be recognized"
    );

    // setB: fake guard -> MUST still be flagged (this would fail with global lookup)
    let set_b = auth.iter().find(|h| h.primary_function == "setB");
    assert!(set_b.is_some(),
        "setB with fake guard must still be flagged — global lookup would incorrectly suppress this");
    assert_eq!(
        set_b.unwrap().severity,
        HypothesisSeverity::Critical,
        "Fake-guarded function must stay Critical"
    );
}

// ── Getter-FP filter tests ─────────────────────────────────

/// A read-only getter with NO state writes must NOT appear as a
/// Medium-severity catch-all AuthorityBypassCandidate.
#[test]
fn getter_no_state_writes_not_catchall_flagged() {
    let source = r#"
        contract Registry {
            uint256 private _totalSupply;
            function getTotalSupply() external view returns (uint256) {
                return _totalSupply;
            }
        }
    "#;
    let program = parse_program(source, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();
    assert!(
        auth.iter()
            .find(|h| h.primary_function == "getTotalSupply")
            .is_none(),
        "Read-only getter with no state writes must NOT be flagged"
    );
}

/// A state-mutating unguarded setter with no modifier MUST still be flagged.
#[test]
fn state_mutating_setter_still_flagged() {
    let source = r#"
        contract Vault {
            uint256 public totalSupply;
            function mint(uint256 amount) external {
                totalSupply += amount;
            }
        }
    "#;
    let program = parse_program(source, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();
    let mint = auth.iter().find(|h| h.primary_function == "mint");
    assert!(
        mint.is_some(),
        "State-mutating setter with no modifier must still be flagged"
    );
}

// ── Constructor exclusion tests ─────────────────────────────

/// Constructor must NOT appear in authority-bypass hypotheses.
#[test]
fn constructor_not_flagged() {
    let source = r#"
        contract Vault {
            uint256 public totalSupply;
            constructor(uint256 initial) {
                totalSupply = initial;
            }
            function mint(uint256 amount) external {
                totalSupply += amount;
            }
        }
    "#;
    let program = parse_program(source, "solidity");
    let ir = build_system_ir_with_language(program, Language::Solidity);
    let result = derive(&ir);
    let auth: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();
    assert!(
        auth.iter()
            .find(|h| h.primary_function == "constructor")
            .is_none(),
        "Constructor must NOT be flagged as authority bypass"
    );
    assert!(
        auth.iter().find(|h| h.primary_function == "mint").is_some(),
        "State-mutating mint must still be flagged"
    );
}
