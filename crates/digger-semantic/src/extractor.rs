use crate::models::*;
use digger_graph::analysis::{
    AuthorityBoundaryGraph, CrossProgramGraph, ExecutionGraph, StateDependencyGraph,
};
/// Protocol Model Extractor — deterministic extraction from graph outputs.
///
/// Infers protocol structure from:
/// - Functions (entry points, roles)
/// - State variables (assets)
/// - Ownership patterns (roles)
/// - Asset movement paths (invariants)
///
/// Does NOT detect vulnerabilities. Only models protocol intent.
use digger_ir::SystemIR;

/// Extract a ProtocolDefinition from SystemIR.
///
/// This is the ONLY entry point. Deterministic: same input → same output.
pub fn extract(ir: &SystemIR) -> ProtocolDefinition {
    let exec = ExecutionGraph::build(ir);
    let state_dep = StateDependencyGraph::build(ir);
    let auth = AuthorityBoundaryGraph::build(ir);
    let cross = CrossProgramGraph::build(ir);

    let roles = extract_roles(ir, &exec, &auth, &cross);
    let assets = extract_assets(ir, &state_dep);
    let invariants = extract_invariants(ir, &state_dep, &auth, &cross);
    let entry_points = extract_entry_points(ir, &exec, &cross);
    let protocol_type = infer_protocol_type(ir, &assets, &entry_points);

    let summary = ProtocolSummary {
        total_roles: roles.len(),
        total_assets: assets.len(),
        total_invariants: invariants.len(),
        total_entry_points: entry_points.len(),
        protocol_type: protocol_type.clone(),
    };

    ProtocolDefinition {
        name: ir.program_id.clone(),
        protocol_type,
        roles,
        assets,
        invariants,
        entry_points,
        summary,
    }
}

/// Extract roles from function patterns and authority checks.
fn extract_roles(
    _ir: &SystemIR,
    exec: &ExecutionGraph,
    auth: &AuthorityBoundaryGraph,
    cross: &CrossProgramGraph,
) -> Vec<ProtocolRole> {
    let mut roles = vec![];

    // Identify owner role: functions with authority enforcement
    let owner_functions: Vec<String> = auth.enforced.iter().cloned().collect();
    if !owner_functions.is_empty() {
        roles.push(ProtocolRole {
            name: "Owner".into(),
            role_type: ProtocolRoleType::Owner,
            functions: owner_functions.clone(),
            description: "Contract owner with authority-enforced functions".into(),
        });
    }

    // Identify admin role: functions with authority but not in entry points
    let admin_functions: Vec<String> = auth
        .enforced
        .iter()
        .filter(|f| !exec.entry_points.contains(f))
        .cloned()
        .collect();
    if !admin_functions.is_empty() && admin_functions != owner_functions {
        roles.push(ProtocolRole {
            name: "Admin".into(),
            role_type: ProtocolRoleType::Admin,
            functions: admin_functions,
            description: "Administrative functions with elevated privileges".into(),
        });
    }

    // Identify user role: entry points without authority
    let user_functions: Vec<String> = exec
        .entry_points
        .iter()
        .filter(|f| !auth.is_enforced(f))
        .cloned()
        .collect();
    if !user_functions.is_empty() {
        roles.push(ProtocolRole {
            name: "User".into(),
            role_type: ProtocolRoleType::User,
            functions: user_functions,
            description: "Regular user functions without authority requirements".into(),
        });
    }

    // Identify external actor role: functions with external calls
    let external_functions: Vec<String> = cross.external_callers.clone();
    if !external_functions.is_empty() {
        roles.push(ProtocolRole {
            name: "ExternalActor".into(),
            role_type: ProtocolRoleType::ExternalActor,
            functions: external_functions,
            description: "External contracts or programs that interact with this protocol".into(),
        });
    }

    // Sort for deterministic output
    roles.sort_by(|a, b| a.name.cmp(&b.name));
    roles
}

/// Extract assets from state variables.
fn extract_assets(ir: &SystemIR, state_dep: &StateDependencyGraph) -> Vec<ProtocolAsset> {
    let mut assets = vec![];

    for state_var in &ir.state {
        let asset_type = classify_asset(&state_var.name, &state_var.ty);
        let readers = state_dep.readers_of(&state_var.name);
        let writers = state_dep.states_written_by(&state_var.name);

        let description = match asset_type {
            ProtocolAssetType::TokenBalance => {
                format!("Token balance tracked by '{}'", state_var.name)
            }
            ProtocolAssetType::NativeBalance => {
                format!("Native currency balance tracked by '{}'", state_var.name)
            }
            ProtocolAssetType::InternalAccounting => {
                format!("Internal accounting variable '{}'", state_var.name)
            }
        };

        assets.push(ProtocolAsset {
            name: state_var.name.clone(),
            asset_type,
            readers,
            writers,
            description,
        });
    }

    // Sort for deterministic output
    assets.sort_by(|a, b| a.name.cmp(&b.name));
    assets
}

/// Classify an asset type from name and type string.
fn classify_asset(name: &str, ty: &str) -> ProtocolAssetType {
    let name_lower = name.to_lowercase();
    let ty_lower = ty.to_lowercase();

    if name_lower.contains("balance") || name_lower.contains("amount") {
        if ty_lower.contains("mapping") || ty_lower.contains("uint") || ty_lower.contains("u64") {
            return ProtocolAssetType::TokenBalance;
        }
    }

    if name_lower.contains("balance") && !ty_lower.contains("mapping") {
        return ProtocolAssetType::NativeBalance;
    }

    if name_lower.contains("supply") || name_lower.contains("total") {
        return ProtocolAssetType::InternalAccounting;
    }

    if ty_lower.contains("mapping") {
        return ProtocolAssetType::TokenBalance;
    }

    ProtocolAssetType::InternalAccounting
}

/// Extract invariants from structural patterns.
fn extract_invariants(
    ir: &SystemIR,
    state_dep: &StateDependencyGraph,
    auth: &AuthorityBoundaryGraph,
    cross: &CrossProgramGraph,
) -> Vec<ProtocolInvariant> {
    let mut invariants = vec![];

    // Balance non-negative invariant
    let balance_vars: Vec<String> = ir
        .state
        .iter()
        .filter(|s| {
            let name_lower = s.name.to_lowercase();
            name_lower.contains("balance") || name_lower.contains("amount")
        })
        .map(|s| s.name.clone())
        .collect();

    if !balance_vars.is_empty() {
        let mut related_fns: Vec<String> = balance_vars
            .iter()
            .flat_map(|v| state_dep.readers_of(v))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        related_fns.sort();

        invariants.push(ProtocolInvariant {
            name: "BalanceNonNegative".into(),
            invariant_type: InvariantType::BalanceNonNegative,
            description: format!(
                "Balances [{}] must not be negative — underflow would indicate accounting error",
                balance_vars.join(", ")
            ),
            related_state: balance_vars.clone(),
            related_functions: related_fns,
        });
    }

    // Supply conservation invariant (if no mint/burn detected)
    let supply_vars: Vec<String> = ir
        .state
        .iter()
        .filter(|s| {
            let name_lower = s.name.to_lowercase();
            name_lower.contains("supply") || name_lower.contains("total")
        })
        .map(|s| s.name.clone())
        .collect();

    let has_mint_or_burn = ir.functions.iter().any(|f| {
        let name_lower = f.name.to_lowercase();
        name_lower.contains("mint") || name_lower.contains("burn")
    });

    if !supply_vars.is_empty() && !has_mint_or_burn {
        invariants.push(ProtocolInvariant {
            name: "SupplyConservation".into(),
            invariant_type: InvariantType::SupplyConservation,
            description: format!(
                "Supply variables [{}] must remain constant — no mint/burn functions detected",
                supply_vars.join(", ")
            ),
            related_state: supply_vars,
            related_functions: vec![],
        });
    }

    // Withdrawal ordering invariant
    let has_external_calls = !cross.external_callers.is_empty();
    let has_balance_writes = !balance_vars.is_empty();

    if has_external_calls && has_balance_writes {
        let withdraw_fns: Vec<String> = ir
            .functions
            .iter()
            .filter(|f| {
                let name_lower = f.name.to_lowercase();
                name_lower.contains("withdraw")
                    || name_lower.contains("drain")
                    || name_lower.contains("transfer")
            })
            .map(|f| f.name.clone())
            .collect();

        if !withdraw_fns.is_empty() {
            invariants.push(ProtocolInvariant {
                name: "WithdrawalOrdering".into(),
                invariant_type: InvariantType::WithdrawalOrdering,
                description: "Withdrawal functions must reduce balance before external calls (checks-effects-interactions)".into(),
                related_state: balance_vars.iter().cloned().collect(),
                related_functions: withdraw_fns,
            });
        }
    }

    // Access control invariant
    let unguarded_writers: Vec<String> = auth
        .unguarded_mutations
        .iter()
        .filter(|p| p.is_public)
        .map(|p| p.function.clone())
        .collect();

    if !unguarded_writers.is_empty() {
        let related_state: Vec<String> = auth
            .unguarded_mutations
            .iter()
            .flat_map(|p| p.state_vars.clone())
            .collect();

        invariants.push(ProtocolInvariant {
            name: "AccessControl".into(),
            invariant_type: InvariantType::AccessControl,
            description: format!(
                "Functions [{}] modify state without authority — access control invariant violated",
                unguarded_writers.join(", ")
            ),
            related_state,
            related_functions: unguarded_writers,
        });
    }

    // Immutability guard invariant
    let immutable_vars: Vec<String> = ir
        .state
        .iter()
        .filter(|s| {
            // Check if variable is only written by constructor/initializer
            let writers = state_dep.states_written_by(&s.name);
            writers.iter().all(|w| {
                let w_lower = w.to_lowercase();
                w_lower.contains("constructor") || w_lower.contains("init")
            })
        })
        .map(|s| s.name.clone())
        .collect();

    if !immutable_vars.is_empty() {
        invariants.push(ProtocolInvariant {
            name: "ImmutabilityGuard".into(),
            invariant_type: InvariantType::ImmutabilityGuard,
            description: format!(
                "Variables [{}] are only written during initialization — should remain immutable",
                immutable_vars.join(", ")
            ),
            related_state: immutable_vars,
            related_functions: vec![],
        });
    }

    // Sort for deterministic output
    invariants.sort_by(|a, b| a.name.cmp(&b.name));
    invariants
}

/// Extract entry points with role classification.
fn extract_entry_points(
    ir: &SystemIR,
    exec: &ExecutionGraph,
    cross: &CrossProgramGraph,
) -> Vec<ProtocolEntryPoint> {
    let mut entry_points = vec![];

    for func in &ir.functions {
        // Only include public/external functions
        if func.visibility != digger_ir::Visibility::Public
            && func.visibility != digger_ir::Visibility::External
        {
            continue;
        }

        let is_entry = exec.entry_points.contains(&func.name);
        let makes_external = cross.external_callers.contains(&func.name);
        let modifies_state = ir.edges.iter().any(|e| {
            matches!(e, digger_ir::Edge::State(s) if s.function == func.name && s.access == "write")
        });

        // Classify primary role
        let has_authority = ir.edges.iter().any(|e| {
            matches!(e, digger_ir::Edge::Authority(a) if a.function == func.name && a.check_type == "enforced")
        });

        let primary_role = if has_authority {
            ProtocolRoleType::Owner
        } else if is_entry {
            ProtocolRoleType::User
        } else {
            ProtocolRoleType::ExternalActor
        };

        entry_points.push(ProtocolEntryPoint {
            function: func.name.clone(),
            primary_role,
            modifies_state,
            makes_external_calls: makes_external,
        });
    }

    // Sort for deterministic output
    entry_points.sort_by(|a, b| a.function.cmp(&b.function));
    entry_points
}

/// Infer protocol type from structure.
fn infer_protocol_type(
    ir: &SystemIR,
    assets: &[ProtocolAsset],
    _entry_points: &[ProtocolEntryPoint],
) -> String {
    let fn_names: Vec<String> = ir.functions.iter().map(|f| f.name.to_lowercase()).collect();
    let has_deposit = fn_names.iter().any(|n| n.contains("deposit"));
    let has_withdraw = fn_names.iter().any(|n| n.contains("withdraw"));
    let has_swap = fn_names.iter().any(|n| n.contains("swap"));
    let has_lend = fn_names
        .iter()
        .any(|n| n.contains("lend") || n.contains("borrow"));
    let has_mint = fn_names.iter().any(|n| n.contains("mint"));
    let has_burn = fn_names.iter().any(|n| n.contains("burn"));
    let has_transfer = fn_names.iter().any(|n| n.contains("transfer"));

    let has_token_assets = assets
        .iter()
        .any(|a| a.asset_type == ProtocolAssetType::TokenBalance);

    if has_swap {
        "dex".into()
    } else if has_lend {
        "lending".into()
    } else if has_mint && has_burn {
        "token".into()
    } else if has_deposit && has_withdraw {
        "vault".into()
    } else if has_transfer && has_token_assets {
        "token".into()
    } else {
        "generic".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_parser::model::*;

    fn make_ir(program: RawProgram) -> SystemIR {
        digger_graph::build_system_ir(program)
    }

    fn empty_ir() -> SystemIR {
        make_ir(RawProgram::default())
    }

    #[test]
    fn extract_empty_ir() {
        let ir = empty_ir();
        let def = extract(&ir);
        assert_eq!(def.protocol_type, "generic");
    }

    #[test]
    fn extract_deterministic() {
        let ir = make_ir(RawProgram {
            functions: vec![RawFunction {
                name: "deposit".into(),
                visibility: "public".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "balances".into(),
                ty: "mapping".into(),
            }],
            ..Default::default()
        });
        let r1 = extract(&ir);
        let r2 = extract(&ir);
        assert_eq!(r1, r2);
    }

    #[test]
    fn extract_roles_sorted() {
        let ir = make_ir(RawProgram {
            functions: vec![
                RawFunction {
                    name: "deposit".into(),
                    visibility: "public".into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "setOwner".into(),
                    visibility: "public".into(),
                    ..Default::default()
                },
            ],
            state: vec![RawState {
                name: "owner".into(),
                ty: "address".into(),
            }],
            ..Default::default()
        });
        let def = extract(&ir);
        for i in 1..def.roles.len() {
            assert!(def.roles[i - 1].name <= def.roles[i].name);
        }
    }

    #[test]
    fn extract_assets_sorted() {
        let ir = make_ir(RawProgram {
            state: vec![
                RawState {
                    name: "total_supply".into(),
                    ty: "u64".into(),
                },
                RawState {
                    name: "balances".into(),
                    ty: "mapping".into(),
                },
            ],
            ..Default::default()
        });
        let def = extract(&ir);
        for i in 1..def.assets.len() {
            assert!(def.assets[i - 1].name <= def.assets[i].name);
        }
    }

    #[test]
    fn infer_vault_type() {
        let ir = make_ir(RawProgram {
            functions: vec![
                RawFunction {
                    name: "deposit".into(),
                    visibility: "public".into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "withdraw".into(),
                    visibility: "public".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        let def = extract(&ir);
        assert_eq!(def.protocol_type, "vault");
    }

    #[test]
    fn infer_dex_type() {
        let ir = make_ir(RawProgram {
            functions: vec![RawFunction {
                name: "swap".into(),
                visibility: "public".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        let def = extract(&ir);
        assert_eq!(def.protocol_type, "dex");
    }

    #[test]
    fn infer_generic_fallback() {
        let ir = make_ir(RawProgram {
            functions: vec![RawFunction {
                name: "doStuff".into(),
                visibility: "public".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        let def = extract(&ir);
        assert_eq!(def.protocol_type, "generic");
    }

    #[test]
    fn summary_counts_match() {
        let ir = make_ir(RawProgram {
            functions: vec![RawFunction {
                name: "deposit".into(),
                visibility: "public".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "balances".into(),
                ty: "mapping".into(),
            }],
            ..Default::default()
        });
        let def = extract(&ir);
        assert_eq!(def.summary.total_roles, def.roles.len());
        assert_eq!(def.summary.total_assets, def.assets.len());
        assert_eq!(def.summary.total_invariants, def.invariants.len());
        assert_eq!(def.summary.total_entry_points, def.entry_points.len());
    }

    #[test]
    fn serialization_roundtrip() {
        let ir = make_ir(RawProgram {
            functions: vec![RawFunction {
                name: "deposit".into(),
                visibility: "public".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "balances".into(),
                ty: "mapping".into(),
            }],
            ..Default::default()
        });
        let def = extract(&ir);
        let json = serde_json::to_string(&def).unwrap();
        let restored: ProtocolDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, def.name);
        assert_eq!(restored.protocol_type, def.protocol_type);
    }
}
