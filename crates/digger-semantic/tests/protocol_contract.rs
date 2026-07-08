#![allow(clippy::needless_update, clippy::useless_vec, clippy::len_zero)]
use digger_graph::build_system_ir;
use digger_ir::*;
use digger_parser::model::*;
/// Protocol Model Contract Tests — Phase 4.1
///
/// These tests enforce the protocol model contract.
use digger_semantic::*;

fn make_vault_ir() -> SystemIR {
    let program = RawProgram {
        functions: vec![
            RawFunction {
                name: "deposit".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "balances[msg.sender] += msg.value".into(),
                ..Default::default()
            },
            RawFunction {
                name: "withdraw".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "require(balances[msg.sender] >= amount); (bool success, ) = msg.sender.call{value: amount}(\"\"); balances[msg.sender] -= amount".into(),
                ..Default::default()
            },
            RawFunction {
                name: "setOwner".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "require(msg.sender == owner); owner = newOwner".into(),
                ..Default::default()
            },
        ],
        state: vec![
            RawState { name: "balances".into(), ty: "mapping".into(), ..Default::default() },
            RawState { name: "owner".into(), ty: "address".into(), ..Default::default() },
        ],
        calls: vec![
            RawCall { from: "withdraw".into(), to: "external".into(), kind: CallKind::External },
        ],
        ..Default::default()
    };
    build_system_ir(program)
}

fn make_empty_ir() -> SystemIR {
    SystemIR {
        program_id: "empty".into(),
        language: Language::Solidity,
        functions: vec![],
        state: vec![],
        edges: vec![],
    }
}

// ─────────────────────────────────────────────────────────────
// 1. Deterministic output
// ─────────────────────────────────────────────────────────────

#[test]
fn protocol_deterministic() {
    let ir = make_vault_ir();
    let r1 = extract(&ir);
    let r2 = extract(&ir);
    let r3 = extract(&ir);

    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

// ─────────────────────────────────────────────────────────────
// 2. Stable ordering
// ─────────────────────────────────────────────────────────────

#[test]
fn protocol_ordering_stable() {
    let ir = make_vault_ir();
    let r1 = extract(&ir);
    let r2 = extract(&ir);

    // Roles sorted by name
    let names1: Vec<_> = r1.roles.iter().map(|r| &r.name).collect();
    let names2: Vec<_> = r2.roles.iter().map(|r| &r.name).collect();
    assert_eq!(names1, names2);

    // Assets sorted by name
    let assets1: Vec<_> = r1.assets.iter().map(|a| &a.name).collect();
    let assets2: Vec<_> = r2.assets.iter().map(|a| &a.name).collect();
    assert_eq!(assets1, assets2);

    // Invariants sorted by name
    let inv1: Vec<_> = r1.invariants.iter().map(|i| &i.name).collect();
    let inv2: Vec<_> = r2.invariants.iter().map(|i| &i.name).collect();
    assert_eq!(inv1, inv2);
}

// ─────────────────────────────────────────────────────────────
// 3. Roundtrip serialization
// ─────────────────────────────────────────────────────────────

#[test]
fn protocol_serialization_roundtrip() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: ProtocolDefinition = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.name, result.name);
    assert_eq!(deserialized.protocol_type, result.protocol_type);
    assert_eq!(deserialized.roles.len(), result.roles.len());
    assert_eq!(deserialized.assets.len(), result.assets.len());
    assert_eq!(deserialized.invariants.len(), result.invariants.len());
}

#[test]
fn protocol_serialization_stable() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    let json1 = serde_json::to_string_pretty(&result).unwrap();
    let json2 = serde_json::to_string_pretty(&result).unwrap();
    assert_eq!(json1, json2);
}

// ─────────────────────────────────────────────────────────────
// 4. Invariant consistency
// ─────────────────────────────────────────────────────────────

#[test]
fn vault_has_balance_invariant() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    let balance_inv = result
        .invariants
        .iter()
        .find(|i| i.invariant_type == InvariantType::BalanceNonNegative);
    assert!(
        balance_inv.is_some(),
        "Vault should have BalanceNonNegative invariant"
    );
}

#[test]
fn vault_has_withdrawal_ordering_invariant() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    let ordering_inv = result
        .invariants
        .iter()
        .find(|i| i.invariant_type == InvariantType::WithdrawalOrdering);
    assert!(
        ordering_inv.is_some(),
        "Vault should have WithdrawalOrdering invariant"
    );
}

#[test]
fn vault_has_access_control_invariant() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    let access_inv = result
        .invariants
        .iter()
        .find(|i| i.invariant_type == InvariantType::AccessControl);
    assert!(
        access_inv.is_some(),
        "Vault should have AccessControl invariant"
    );
}

#[test]
fn invariant_related_state_not_empty() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    for inv in &result.invariants {
        assert!(
            !inv.related_state.is_empty()
                || inv.invariant_type == InvariantType::WithdrawalOrdering,
            "Invariant '{}' should have related state",
            inv.name
        );
        assert!(
            !inv.description.is_empty(),
            "Invariant '{}' should have description",
            inv.name
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 5. Role consistency
// ─────────────────────────────────────────────────────────────

#[test]
fn vault_has_owner_role() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    let owner = result
        .roles
        .iter()
        .find(|r| r.role_type == ProtocolRoleType::Owner);
    assert!(owner.is_some(), "Vault should have Owner role");
}

#[test]
fn vault_has_user_role() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    let user = result
        .roles
        .iter()
        .find(|r| r.role_type == ProtocolRoleType::User);
    assert!(user.is_some(), "Vault should have User role");
}

#[test]
fn role_functions_not_empty() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    for role in &result.roles {
        assert!(
            !role.functions.is_empty(),
            "Role '{}' should have functions",
            role.name
        );
        assert!(
            !role.description.is_empty(),
            "Role '{}' should have description",
            role.name
        );
    }
}

#[test]
fn roles_sorted_by_name() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    for i in 1..result.roles.len() {
        assert!(
            result.roles[i - 1].name <= result.roles[i].name,
            "Roles must be sorted by name"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 6. Empty input handling
// ─────────────────────────────────────────────────────────────

#[test]
fn empty_ir_produces_empty_protocol() {
    let ir = make_empty_ir();
    let result = extract(&ir);

    assert_eq!(result.roles.len(), 0);
    assert_eq!(result.assets.len(), 0);
    assert_eq!(result.entry_points.len(), 0);
    assert_eq!(result.protocol_type, "generic");
}

#[test]
fn empty_ir_serializes() {
    let ir = make_empty_ir();
    let result = extract(&ir);

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: ProtocolDefinition = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.name, "empty");
    assert_eq!(deserialized.roles.len(), 0);
}

// ─────────────────────────────────────────────────────────────
// 7. Protocol type inference
// ─────────────────────────────────────────────────────────────

#[test]
fn vault_protocol_type_detected() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    assert_eq!(
        result.protocol_type, "vault",
        "Protocol with deposit/withdraw should be classified as vault"
    );
}

#[test]
fn generic_protocol_type_fallback() {
    let program = RawProgram {
        functions: vec![RawFunction {
            name: "doSomething".into(),
            visibility: "public".into(),
            inputs: vec![],
            body: "x = 1".into(),
            ..Default::default()
        }],
        state: vec![RawState {
            name: "x".into(),
            ty: "u64".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let ir = build_system_ir(program);
    let result = extract(&ir);

    assert_eq!(
        result.protocol_type, "generic",
        "Protocol without clear patterns should be generic"
    );
}

// ─────────────────────────────────────────────────────────────
// 8. Asset classification
// ─────────────────────────────────────────────────────────────

#[test]
fn balance_asset_classified() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    let balances = result.assets.iter().find(|a| a.name == "balances");
    assert!(balances.is_some(), "Should identify balances asset");
    assert_eq!(
        balances.unwrap().asset_type,
        ProtocolAssetType::TokenBalance,
        "balances should be classified as TokenBalance"
    );
}

#[test]
fn assets_sorted_by_name() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    for i in 1..result.assets.len() {
        assert!(
            result.assets[i - 1].name <= result.assets[i].name,
            "Assets must be sorted by name"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 9. Entry points
// ─────────────────────────────────────────────────────────────

#[test]
fn vault_entry_points_detected() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    assert!(
        result.entry_points.len() >= 2,
        "Vault should have at least 2 entry points"
    );

    let names: Vec<_> = result.entry_points.iter().map(|e| &e.function).collect();
    assert!(names.contains(&&"deposit".to_string()));
    assert!(names.contains(&&"withdraw".to_string()));
}

#[test]
fn entry_points_sorted() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    for i in 1..result.entry_points.len() {
        assert!(
            result.entry_points[i - 1].function <= result.entry_points[i].function,
            "Entry points must be sorted by function name"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 10. Summary correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn summary_matches_actual_counts() {
    let ir = make_vault_ir();
    let result = extract(&ir);

    assert_eq!(result.summary.total_roles, result.roles.len());
    assert_eq!(result.summary.total_assets, result.assets.len());
    assert_eq!(result.summary.total_invariants, result.invariants.len());
    assert_eq!(result.summary.total_entry_points, result.entry_points.len());
    assert_eq!(result.summary.protocol_type, result.protocol_type);
}
