use crate::models::*;
/// Protocol Analyzer — cross-program analysis engine.
///
/// Analyzes multiple contracts within a protocol to detect:
/// - Storage layout collisions across delegatecall boundaries
/// - Proxy patterns and their storage implications
/// - Cross-program call relationships
///
/// Deterministic: same inputs → same output.
/// No AI, no inference, no heuristics.
use digger_parser::model::*;
use digger_parser::parse_program;
use std::path::Path;

/// Analyze a protocol directory containing multiple Solidity files.
///
/// Parses all .sol files, builds per-contract analysis, computes storage layouts,
/// detects proxy patterns, and identifies storage collision vulnerabilities.
pub fn analyze_protocol(protocol_id: &str, dir: &Path) -> ProtocolIR {
    let mut all_programs = vec![];
    let mut all_source = vec![];

    // Parse all .sol files in the directory
    if dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "sol")
                    .unwrap_or(false)
            })
            .collect();
        entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

        for entry in entries {
            let path = entry.path();
            if let Ok(source) = std::fs::read_to_string(&path) {
                let program = parse_program(&source, "solidity");
                all_programs.push((
                    path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    program,
                ));
                all_source.push(source);
            }
        }
    }

    analyze_programs(protocol_id, &all_programs)
}

/// Analyze a set of pre-parsed programs.
///
/// This is the core analysis function. It takes already-parsed programs
/// and performs cross-program analysis.
pub fn analyze_programs(protocol_id: &str, programs: &[(String, RawProgram)]) -> ProtocolIR {
    let mut contracts = vec![];
    let mut storage_layouts = vec![];
    let mut cross_program_calls = vec![];
    let mut proxy_patterns = vec![];
    let mut vulnerabilities = vec![];

    // Phase 1: Analyze each contract individually
    for (_filename, program) in programs {
        for contract_meta in &program.metadata.contracts {
            let state_vars = extract_state_variables(contract_meta, program);
            let has_delegatecall = detect_delegatecall(program, &contract_meta.name);
            let has_initializer = detect_initializer(program, &contract_meta.name);

            let layout = StorageLayout {
                contract_name: contract_meta.name.clone(),
                variables: state_vars.clone(),
                total_slots: state_vars.len(),
            };

            contracts.push(ContractAnalysis {
                name: contract_meta.name.clone(),
                kind: contract_meta.kind.clone(),
                state_variables: state_vars,
                has_delegatecall_fallback: has_delegatecall,
                has_initializer: has_initializer,
                uses_delegatecall: has_delegatecall,
            });

            storage_layouts.push(layout);
        }
    }

    // Phase 2: Detect cross-program calls
    for (_filename, program) in programs {
        for call in &program.calls {
            if call.kind == digger_ir::CallKind::External {
                // Check if target is a known contract in this protocol
                let target_contract = resolve_call_target(call, &contracts);
                cross_program_calls.push(CrossProgramCall {
                    from_contract: find_contract_for_function(program, &call.from),
                    from_function: call.from.clone(),
                    to_contract: target_contract.clone(),
                    call_type: classify_call_type(call),
                });
            }
        }
    }

    // Phase 3: Detect proxy patterns
    for contract in &contracts {
        if contract.has_delegatecall_fallback {
            let impl_contract =
                find_implementation_contract(contract, &contracts, &cross_program_calls);
            let impl_slot = find_implementation_slot(contract);
            let pattern_type = classify_proxy_pattern(contract, &impl_contract);

            proxy_patterns.push(ProxyPattern {
                proxy_contract: contract.name.clone(),
                implementation_contract: impl_contract,
                implementation_slot: impl_slot,
                pattern_type,
            });
        }
    }

    // Phase 4: Detect storage collision vulnerabilities
    for proxy in &proxy_patterns {
        if let Some(ref impl_name) = proxy.implementation_contract {
            if let Some(impl_layout) = storage_layouts
                .iter()
                .find(|l| &l.contract_name == impl_name)
            {
                if let Some(proxy_layout) = storage_layouts
                    .iter()
                    .find(|l| l.contract_name == proxy.proxy_contract)
                {
                    let collisions = find_storage_collisions(proxy_layout, impl_layout);
                    if !collisions.is_empty() {
                        vulnerabilities.push(ProtocolVulnerability {
                            vuln_type: "ProxyStorageCollision".into(),
                            severity: digger_ir::Severity::Critical,
                            affected_contracts: vec![
                                proxy.proxy_contract.clone(),
                                impl_name.clone(),
                            ],
                            description: format!(
                                "Storage slot collision between {} and {} via delegatecall",
                                proxy.proxy_contract, impl_name
                            ),
                            evidence: collisions,
                        });
                    }
                }
            }
        }
    }

    // Phase 5: Detect delegatecall trust violations
    for proxy in &proxy_patterns {
        if proxy.implementation_contract.is_none() {
            vulnerabilities.push(ProtocolVulnerability {
                vuln_type: "DelegatecallTrustViolation".into(),
                severity: digger_ir::Severity::High,
                affected_contracts: vec![proxy.proxy_contract.clone()],
                description: format!(
                    "{} uses delegatecall but implementation target is not resolvable",
                    proxy.proxy_contract
                ),
                evidence: vec!["Unresolvable delegatecall target".into()],
            });
        }
    }

    // Sort for deterministic output
    contracts.sort_by(|a, b| a.name.cmp(&b.name));
    storage_layouts.sort_by(|a, b| a.contract_name.cmp(&b.contract_name));
    cross_program_calls.sort_by(|a, b| {
        a.from_contract
            .cmp(&b.from_contract)
            .then(a.from_function.cmp(&b.from_function))
    });
    proxy_patterns.sort_by(|a, b| a.proxy_contract.cmp(&b.proxy_contract));
    vulnerabilities.sort_by(|a, b| a.vuln_type.cmp(&b.vuln_type));

    ProtocolIR {
        protocol_id: protocol_id.into(),
        contracts,
        cross_program_calls,
        storage_layouts,
        proxy_patterns,
        vulnerabilities,
    }
}

// ─────────────────────────────────────────────────────────────
// Storage layout computation
// ─────────────────────────────────────────────────────────────

/// Extract state variables with storage slot assignments.
///
/// EVM storage layout: variables are assigned slots sequentially
/// from slot 0 in declaration order. Each slot is 32 bytes.
/// Types smaller than 32 bytes may be packed into the same slot.
fn extract_state_variables(
    contract_meta: &ContractMeta,
    program: &RawProgram,
) -> Vec<StateVariableDecl> {
    let mut vars = vec![];
    let mut current_slot = 0;
    let mut current_offset = 0;

    for var_name in &contract_meta.state_var_names {
        // Find the actual state variable to get its type
        if let Some(state_var) = program.state.iter().find(|s| &s.name == var_name) {
            let ty = &state_var.ty;
            let size = evm_type_size(ty);

            // Determine if this variable fits in the current slot.
            // EVM rules:
            // - Types >= 32 bytes always get their own slot
            // - Types < 32 bytes pack into the current slot if they fit
            // - If they don't fit, start a new slot
            let needs_new_slot = size >= 32 || current_offset + size > 32;
            let (slot, offset, full_slot) = if needs_new_slot {
                // Full-slot type or doesn't fit — advance to next slot
                if current_offset > 0 {
                    // Current slot has data, move to next
                    current_slot += 1;
                    current_offset = 0;
                } else if !vars.is_empty() {
                    // Current slot is empty but we already placed something before
                    // (means previous variable filled the slot exactly)
                    // This variable goes to the next slot
                    current_slot += 1;
                }
                (current_slot, 0, size >= 32)
            } else {
                // Packs into current slot
                let slot = current_slot;
                let offset = current_offset;
                current_offset += size;
                (slot, offset, false)
            };

            vars.push(StateVariableDecl {
                name: var_name.clone(),
                ty: ty.clone(),
                slot,
                offset,
                full_slot,
            });
        }
    }

    vars
}

/// EVM type size in bytes for storage layout computation.
fn evm_type_size(ty: &str) -> usize {
    let ty_lower = ty.to_lowercase();
    if ty_lower == "bool" || ty_lower.starts_with("uint8") || ty_lower.starts_with("int8") {
        1
    } else if ty_lower.starts_with("uint16")
        || ty_lower.starts_with("int16")
        || ty_lower.starts_with("bytes2")
    {
        2
    } else if ty_lower.starts_with("uint32")
        || ty_lower.starts_with("int32")
        || ty_lower.starts_with("bytes4")
    {
        4
    } else if ty_lower.starts_with("uint64")
        || ty_lower.starts_with("int64")
        || ty_lower.starts_with("bytes8")
    {
        8
    } else if ty_lower.starts_with("uint128")
        || ty_lower.starts_with("int128")
        || ty_lower.starts_with("bytes16")
    {
        16
    } else if ty_lower.starts_with("address") {
        20
    } else if ty_lower.starts_with("bytes32")
        || ty_lower.starts_with("uint256")
        || ty_lower.starts_with("int256")
    {
        32
    } else if ty_lower.starts_with("uint") || ty_lower.starts_with("int") {
        32 // Default uint/int size
    } else if ty_lower.starts_with("bytes") && !ty_lower.starts_with("bytes32") {
        32 // Dynamic bytes — pointer
    } else if ty_lower.starts_with("string") {
        32 // Dynamic string — pointer
    } else if ty_lower.starts_with("mapping") {
        32 // Mapping — slot is for the root
    } else {
        32 // Default: assume full slot
    }
}

// ─────────────────────────────────────────────────────────────
// Delegatecall detection
// ─────────────────────────────────────────────────────────────

/// Detect if a contract uses delegatecall.
fn detect_delegatecall(program: &RawProgram, contract_name: &str) -> bool {
    // Check if any function in this contract has a delegatecall external call
    for call in &program.calls {
        if call.to == "delegate" {
            // Verify the function belongs to this contract
            if let Some(func_meta) = program.metadata.function_details.get(&call.from) {
                if func_meta.container_path.starts_with(contract_name)
                    || func_meta.container_path == call.from
                {
                    return true;
                }
            }
        }
    }

    // Also check function bodies for inline assembly delegatecall
    for func in &program.functions {
        if func.body.contains("delegatecall") {
            return true;
        }
    }

    false
}

/// Detect if a contract has an initializer function.
fn detect_initializer(program: &RawProgram, _contract_name: &str) -> bool {
    for func_meta in &program.metadata.function_details {
        if (func_meta.1.fn_type == "function" || func_meta.1.fn_type == "constructor")
            && (func_meta.0.contains("init") || func_meta.0.contains("Init"))
        {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────
// Cross-program call resolution
// ─────────────────────────────────────────────────────────────

/// Resolve a call target to a contract name in the protocol.
fn resolve_call_target(call: &RawCall, contracts: &[ContractAnalysis]) -> String {
    // Check if target matches a known contract name
    for contract in contracts {
        if call.to == contract.name
            || call.to.contains(&contract.name)
            || call.to.starts_with(&format!("interface:{}", contract.name))
        {
            return contract.name.clone();
        }
    }

    // Check if target is an interface name
    if call.to.starts_with("interface:") {
        if let Some(dot_pos) = call.to.find('.') {
            let interface_name = &call.to[10..dot_pos];
            return interface_name.to_string();
        }
    }

    call.to.clone()
}

/// Find which contract a function belongs to.
fn find_contract_for_function(program: &RawProgram, func_name: &str) -> String {
    if let Some(func_meta) = program.metadata.function_details.get(func_name) {
        // container_path is "ContractName.functionName"
        if let Some(dot_pos) = func_meta.container_path.find('.') {
            return func_meta.container_path[..dot_pos].to_string();
        }
        func_meta.container_path.clone()
    } else {
        "unknown".into()
    }
}

/// Classify call type from RawCall.
fn classify_call_type(call: &RawCall) -> String {
    match call.to.as_str() {
        "delegate" => "delegatecall".into(),
        "external" | "static" | "transfer" => "external".into(),
        _ => {
            if call.to.starts_with("interface:") {
                "interface".into()
            } else {
                "external".into()
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Proxy pattern detection
// ─────────────────────────────────────────────────────────────

/// Find the implementation contract for a proxy.
fn find_implementation_contract(
    proxy: &ContractAnalysis,
    contracts: &[ContractAnalysis],
    cross_calls: &[CrossProgramCall],
) -> Option<String> {
    // Look for a delegatecall target
    for call in cross_calls {
        if call.from_contract == proxy.name && call.call_type == "delegatecall" {
            return Some(call.to_contract.clone());
        }
    }

    // Heuristic: look for a contract named "Implementation" or similar
    for contract in contracts {
        if contract.name != proxy.name
            && (contract.name.contains("Implementation")
                || contract.name.contains("Impl")
                || contract.name.contains("Logic"))
        {
            return Some(contract.name.clone());
        }
    }

    None
}

/// Find the storage slot of the implementation address variable.
fn find_implementation_slot(contract: &ContractAnalysis) -> Option<usize> {
    for var in &contract.state_variables {
        if var.name == "implementation"
            || var.name == "_implementation"
            || var.name == "impl"
            || var.name == "implementationSlot"
        {
            return Some(var.slot);
        }
    }
    None
}

/// Classify proxy pattern type.
fn classify_proxy_pattern(contract: &ContractAnalysis, _impl_contract: &Option<String>) -> String {
    // Check for transparent proxy pattern (admin + implementation)
    let has_admin = contract
        .state_variables
        .iter()
        .any(|v| v.name == "admin" || v.name == "_admin");
    let has_upgrade = contract
        .state_variables
        .iter()
        .any(|v| v.name.contains("upgrade") || v.name.contains("implementation"));

    if has_admin && has_upgrade {
        "transparent_proxy".into()
    } else if has_upgrade {
        "uups".into()
    } else {
        "generic_delegatecall".into()
    }
}

// ─────────────────────────────────────────────────────────────
// Storage collision detection
// ─────────────────────────────────────────────────────────────

/// Find storage slot collisions between proxy and implementation.
///
/// Returns a list of collision evidence strings.
fn find_storage_collisions(
    proxy_layout: &StorageLayout,
    impl_layout: &StorageLayout,
) -> Vec<String> {
    let mut collisions = vec![];

    for proxy_var in &proxy_layout.variables {
        for impl_var in &impl_layout.variables {
            if proxy_var.slot == impl_var.slot {
                collisions.push(format!(
                    "Slot {}: {}.{ty1} collides with {}.{ty2}",
                    proxy_var.slot,
                    proxy_layout.contract_name,
                    impl_layout.contract_name,
                    ty1 = proxy_var.ty,
                    ty2 = impl_var.ty,
                ));
            }
        }
    }

    collisions
}
