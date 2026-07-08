use digger_ir::*;
use digger_parser::model::*;

pub fn build(program: RawProgram) -> SystemIR {
    build_with_language(program, digger_ir::Language::Unknown)
}

pub fn build_with_language(program: RawProgram, language: digger_ir::Language) -> SystemIR {
    // Build a set of functions that have external calls (from AST-based detection + assembly extraction)
    let mut fns_with_external_calls: std::collections::HashSet<String> = program
        .calls
        .iter()
        .filter(|c| c.kind == digger_ir::CallKind::External)
        .map(|c| c.from.clone())
        .collect();

    // Also include functions with ExternalCall operations (from assembly extraction)
    for op in &program.operations {
        if op.kind == digger_parser::model::OperationKind::ExternalCall {
            fns_with_external_calls.insert(op.function.clone());
        }
    }

    let mut functions: Vec<Function> = program
        .functions
        .iter()
        .map(|f| Function {
            id: f.name.clone(),
            name: f.name.clone(),
            contract: f.contract.clone(),
            visibility: match f.visibility.as_str() {
                "public" | "external" => Visibility::Public,
                "private" => Visibility::Private,
                "internal" => Visibility::Internal,
                _ => Visibility::Internal,
            },
            inputs: vec![],
            outputs: vec![],
            modifiers: vec![],
            effects: Effects {
                state_mutation: (f.body.contains("= ")
                    || f.body.contains("+=")
                    || f.body.contains("-=")
                    || f.body.contains("*=")
                    || f.body.contains("/=")
                    || f.body.contains("%=")
                    || f.body.contains("["))
                    && !f.body.contains("!=")
                    && !f.body.contains(">=")
                    && !f.body.contains("<=")
                    && !f.body.contains("=="),
                // Phase 6.1: Use AST-based call detection AND substring matching
                // AST detects interface calls (IType(addr).method())
                // Substring catches patterns the AST might miss (invoke, .call in assembly)
                external_call: fns_with_external_calls.contains(&f.name)
                    || f.body.contains(".call")
                    || f.body.contains("invoke"),
                authority_required: f.body.contains("require") || f.body.contains("signer"),
                value_transfer: f.body.contains("transfer") || f.body.contains("value"),
                // Arithmetic detection: for Solidity, the parser's AST walk is
                // authoritative — trust f.has_arithmetic alone. Text patterns
                // re-add false positives for Solidity. For Rust/Anchor/test
                // fixtures where f.has_arithmetic is always false, text OR is
                // the only source of this signal.
                has_arithmetic: if matches!(language, digger_ir::Language::Solidity) {
                    f.has_arithmetic
                } else {
                    f.has_arithmetic
                        || f.body.contains(".mul(")
                        || f.body.contains(".div(")
                        || f.body.contains("mulDiv(")
                        || f.body.contains("mulDivDown(")
                        || f.body.contains("mulDivUp(")
                        || f.body.contains("wmul(")
                        || f.body.contains("wdiv(")
                        || f.body.contains(" * ")
                        || f.body.contains(" / ")
                        || f.body.contains(" % ")
                },
                // Detect temporal guards: block.number/timestamp comparisons,
                // require/assert with time conditions, known guard modifiers
                // (nonReentrant, whenNotPaused), or named delay/timelock/snapshot
                // state variables. TEXT signal — detects presence of guard syntax,
                // not semantic sufficiency. Absence is the vulnerability indicator.
                has_temporal_guard: f.body.contains("block.number")
                    || f.body.contains("block.timestamp")
                    || f.body.contains("blockts")
                    || f.body.contains("nonReentrant")
                    || f.body.contains("whenNotPaused")
                    || f.body.contains("whenPaused")
                    || f.body.contains("onlyOwner")
                    || f.body.contains("onlyAdmin")
                    || f.body.contains("timelock")
                    || f.body.contains("Timelock")
                    || f.body.contains("withdrawalDelay")
                    || f.body.contains("unlockTime")
                    || f.body.contains("snapshot")
                    || f.body.contains("Snapshot")
                    || f.body.contains("lastAction")
                    || f.body.contains("lastDeposit")
                    || f.body.contains("lastDistribution")
                    || f.body.contains("cooldown")
                    || f.body.contains("Cooldown"),
                value_flow: None,
                // Unchecked arithmetic: from parser metadata.extra (Solidity unchecked{} blocks)
                has_unchecked_arithmetic: program
                    .metadata
                    .extra
                    .get(&format!("ast_unchecked_arith:{}", f.name))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                writes_caller_scoped_state: program
                    .metadata
                    .extra
                    .get(&format!("ast_caller_scoped:{}", f.name))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                has_precision_loss_ordering: program
                    .metadata
                    .extra
                    .get(&format!("ast_prec_loss:{}", f.name))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            },
        })
        .collect();

    let state = program
        .state
        .iter()
        .map(|s| StateVariable {
            id: s.name.clone(),
            name: s.name.clone(),
            ty: s.ty.clone(),
            mutable: true,
        })
        .collect();

    let mut edges = vec![];
    edges.extend(super::call_graph::build(&program));
    edges.extend(super::state_graph::build(&program));
    edges.extend(super::authority_graph::build(&program));
    edges.extend(super::external_graph::build(&program));

    // Phase 8: Extract Anchor #[derive(Accounts)] constraints into edges
    if language == digger_ir::Language::Anchor {
        edges.extend(extract_anchor_constraints(&program));
    }

    // Phase 9: Propagate has_arithmetic through INTERNAL call chains only.
    // Contract-scoped: a call edge only propagates if caller and callee share
    // the same contract (or either has no contract — free functions). This
    // prevents cross-contract false edges in concatenated sources from
    // infecting functions like deposit/transferFrom with unrelated arithmetic.
    {
        // Build function name → contract lookup
        let fn_contract: std::collections::BTreeMap<String, String> = functions
            .iter()
            .map(|f| (f.name.clone(), f.contract.clone()))
            .collect();

        let same_contract = |from: &str, to: &str| -> bool {
            let c_from = fn_contract.get(from).map(|s| s.as_str()).unwrap_or("");
            let c_to = fn_contract.get(to).map(|s| s.as_str()).unwrap_or("");
            // Same contract if both have the same non-empty contract name,
            // or either is a free function (empty contract = library/global).
            c_from == c_to || c_from.is_empty() || c_to.is_empty()
        };

        // Pass 1: propagate to any same-contract function
        let arithmetic_fns_1: std::collections::BTreeSet<String> = functions
            .iter()
            .filter(|f| f.effects.has_arithmetic)
            .map(|f| f.name.clone())
            .collect();
        for f in functions.iter_mut() {
            if !f.effects.has_arithmetic {
                let hits = edges.iter().any(|e| match e {
                    Edge::Call(c) => {
                        c.from == f.name
                            && arithmetic_fns_1.contains(&c.to)
                            && same_contract(&c.from, &c.to)
                    }
                    _ => false,
                });
                if hits {
                    f.effects.has_arithmetic = true;
                }
            }
        }
        // Pass 2: propagate to value-transferring callers (same contract only)
        let arithmetic_fns_2: std::collections::BTreeSet<String> = functions
            .iter()
            .filter(|f| f.effects.has_arithmetic)
            .map(|f| f.name.clone())
            .collect();
        for f in functions.iter_mut() {
            if !f.effects.has_arithmetic && f.effects.value_transfer {
                let hits = edges.iter().any(|e| match e {
                    Edge::Call(c) => {
                        c.from == f.name
                            && arithmetic_fns_2.contains(&c.to)
                            && same_contract(&c.from, &c.to)
                    }
                    _ => false,
                });
                if hits {
                    f.effects.has_arithmetic = true;
                }
            }
        }
    }

    // Phase 10: Build structured value-flow per function from graph edges.
    // Replaces the flat boolean has_arithmetic with data-flow-aware signals
    // that capture WHICH state variables participate in arithmetic.
    {
        // Common balance/reserve variable name patterns (structural, not target-specific).
        let balance_names: std::collections::BTreeSet<&str> = [
            "balance",
            "balances",
            "totalSupply",
            "total_supply",
            "reserve",
            "reserves",
            "deposit",
            "deposits",
            "staked",
            "stakedAmount",
            "staked_amount",
            "locked",
            "lockedAmount",
            "share",
            "shares",
            "amount",
            "pool",
        ]
        .iter()
        .copied()
        .collect();

        // Build function name → body text lookup from RawProgram
        let body_map: std::collections::BTreeMap<String, String> = program
            .functions
            .iter()
            .map(|f| (f.name.clone(), f.body.clone()))
            .collect();

        // Build function name → AST-derived state-reads-in-arithmetic lookup from metadata.extra.
        // Replaces the text-based body_lower.contains(var_name) name-match.
        let ast_sria_map: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
            program
                .metadata
                .extra
                .iter()
                .filter(|(k, _)| k.starts_with("ast_arith_sria:"))
                .filter_map(|(k, v)| {
                    let fn_name = k.strip_prefix("ast_arith_sria:")?.to_string();
                    let set: std::collections::BTreeSet<String> =
                        serde_json::from_value(v.clone()).ok()?;
                    Some((fn_name, set))
                })
                .collect();

        for f in functions.iter_mut() {
            let body = body_map.get(&f.name).map(|s| s.as_str()).unwrap_or("");
            let body_lower = body.to_lowercase();

            // Collect state reads and writes from edges
            let mut state_reads = Vec::new();
            let mut state_writes = Vec::new();
            for e in &edges {
                if let Edge::State(s) = e {
                    if s.function == f.name {
                        match s.access.as_str() {
                            "read" => state_reads.push(s.state.clone()),
                            "write" => state_writes.push(s.state.clone()),
                            _ => {}
                        }
                    }
                }
            }

            // Find state reads that appear in arithmetic context.
            // For Solidity: AST-derived SRIA map is authoritative. An absent entry
            // means "empty set" (no state reads in arithmetic), NOT "fall back to text."
            // For Rust/Anchor: text fallback is the only source.
            let has_arith = f.effects.has_arithmetic;
            let state_reads_in_arithmetic: Vec<String> = if has_arith {
                if matches!(language, digger_ir::Language::Solidity) {
                    // Solidity: AST map is authoritative (absent = empty)
                    if let Some(ast_sria) = ast_sria_map.get(&f.name) {
                        state_reads
                            .iter()
                            .filter(|var| ast_sria.contains(var.as_str()))
                            .cloned()
                            .collect()
                    } else {
                        Vec::new() // AST walked, found no state reads in arithmetic
                    }
                } else if let Some(ast_sria) = ast_sria_map.get(&f.name) {
                    // Non-Solidity with AST data (shouldn't happen, but safe fallback)
                    state_reads
                        .iter()
                        .filter(|var| ast_sria.contains(var.as_str()))
                        .cloned()
                        .collect()
                } else {
                    // Non-Solidity: text fallback
                    state_reads
                        .iter()
                        .filter(|var| body_lower.contains(&var.to_lowercase()))
                        .cloned()
                        .collect()
                }
            } else {
                Vec::new()
            };

            let arithmetic_feeds_value_transfer = has_arith && f.effects.value_transfer;

            let reads_balance_through_arithmetic = state_reads_in_arithmetic
                .iter()
                .any(|var| balance_names.contains(var.to_lowercase().as_str()));

            f.effects.value_flow = Some(ValueFlow {
                state_reads,
                state_writes,
                state_reads_in_arithmetic,
                arithmetic_feeds_value_transfer,
                reads_balance_through_arithmetic,
            });
        }
    }

    SystemIR {
        program_id: "program".into(),
        language,
        functions,
        state,
        edges,
    }
}

/// Extract authority edges from Anchor #[derive(Accounts)] struct constraints.
///
/// Reads metadata.extra entries for anchor_struct_* and creates Authority edges
/// for has_one, signer, constraint, owner, seeds, bump, executable, address patterns.
fn extract_anchor_constraints(program: &RawProgram) -> Vec<Edge> {
    let mut edges = vec![];

    // Find all Anchor account structs in metadata
    for (key, value) in &program.metadata.extra {
        if !key.starts_with("anchor_struct_") {
            continue;
        }

        // Parse the JSON metadata
        let constraints = match value.get("constraints") {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => continue,
        };

        let struct_name = match value.get("name") {
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => continue,
        };

        // Find functions that use this struct as a parameter
        let using_functions: Vec<String> = program
            .functions
            .iter()
            .filter(|f| {
                f.body.contains(&struct_name) || f.inputs.iter().any(|i| i.contains(&struct_name))
            })
            .map(|f| f.name.clone())
            .collect();

        for constraint_json in constraints {
            let _field = constraint_json
                .get("field")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let constraint_str = constraint_json
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Extract constraint type from the attribute string
            // Patterns: #[account(mut, has_one = authority, seeds = [...], bump)]
            let constraint_lower = constraint_str.to_lowercase();

            for func_name in &using_functions {
                // ── has_one constraint → Authority edge (enforced) ──
                if constraint_lower.contains("has_one") {
                    // Extract the referenced field: has_one = X
                    let referenced_field = extract_has_one_target(constraint_str);
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: func_name.clone(),
                        authority_source: format!("has_one:{}", referenced_field),
                        check_type: "enforced".into(),
                    }));
                }

                // ── Signer type → Authority edge (enforced) ──
                if constraint_lower.contains("signer") && !constraint_lower.contains("has_one") {
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: func_name.clone(),
                        authority_source: "signer".into(),
                        check_type: "enforced".into(),
                    }));
                }

                // ── constraint = ... with authority patterns → Authority edge ──
                if constraint_lower.contains("constraint")
                    && (constraint_lower.contains("authority")
                        || constraint_lower.contains("owner")
                        || constraint_lower.contains("signer"))
                {
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: func_name.clone(),
                        authority_source: "constraint".into(),
                        check_type: "enforced".into(),
                    }));
                }

                // ── owner constraint → Authority edge (enforced) ──
                if constraint_lower.contains("owner") && !constraint_lower.contains("has_one") {
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: func_name.clone(),
                        authority_source: "owner".into(),
                        check_type: "enforced".into(),
                    }));
                }

                // ── seeds constraint → record as authority (PDA derivation) ──
                if constraint_lower.contains("seeds") {
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: func_name.clone(),
                        authority_source: "pda_seeds".into(),
                        check_type: "enforced".into(),
                    }));
                }

                // ── bump constraint → record as authority (PDA bump validation) ──
                if constraint_lower.contains("bump") {
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: func_name.clone(),
                        authority_source: "pda_bump".into(),
                        check_type: "enforced".into(),
                    }));
                }

                // ── executable constraint → record as authority (program type check) ──
                if constraint_lower.contains("executable") {
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: func_name.clone(),
                        authority_source: "executable".into(),
                        check_type: "enforced".into(),
                    }));
                }

                // ── address constraint → record as authority (address validation) ──
                if constraint_lower.contains("address") {
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: func_name.clone(),
                        authority_source: "address".into(),
                        check_type: "enforced".into(),
                    }));
                }
            }
        }
    }

    // ── Emit "missing" edges for accounts WITHOUT authority constraints ──
    //
    // Two classes, both purely from anchor_accounts_* metadata (no body text):
    //   has_one: TYPED Account<T> that is MUTABLE and lacks has_one/owner/seeds/constraint.
    //            Account<T> enforces program-ownership + discriminator by construction;
    //            has_one targets authority binding, not type safety.
    //   owner:   RAW AccountInfo without owner check.
    //
    // Suppression rules (per-account, not per-instruction):
    //   - Signer accounts never fire (type-level authority).
    //   - init accounts never fire (gated by payer Signer).
    //
    for (key, value) in &program.metadata.extra {
        if !key.starts_with("anchor_accounts_") {
            continue;
        }

        let struct_name = key.strip_prefix("anchor_accounts_").unwrap_or("");
        let accounts = match value.as_array() {
            Some(arr) => arr,
            None => continue,
        };

        // Find functions that use this struct as a parameter
        let using_functions: Vec<String> = program
            .functions
            .iter()
            .filter(|f| {
                f.body.contains(struct_name) || f.inputs.iter().any(|i| i.contains(struct_name))
            })
            .map(|f| f.name.clone())
            .collect();

        for account_json in accounts {
            let account_name = account_json
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Classify account by wrapper_type (RAW, TYPED, SIGNER)
            let wrapper = account_json
                .get("wrapper_type")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN");

            let is_signer_from_wrapper = wrapper == "SIGNER";
            let is_raw = wrapper == "RAW";
            let is_typed = wrapper == "TYPED";

            let is_signer_flag = account_json
                .get("is_signer")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let is_signer = is_signer_flag || is_signer_from_wrapper;

            let has_authority_constraint = account_json
                .get("constraints")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter().any(|c| {
                        c.get("kind")
                            .and_then(|v| v.as_str())
                            .map(|k| matches!(k, "has_one" | "owner" | "constraint" | "seeds"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            let is_init = account_json
                .get("is_init")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let missing_has_one = is_typed
                && !is_signer
                && !has_authority_constraint
                && !is_init
                && account_json
                    .get("constraints")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter().any(|c| {
                            c.get("kind")
                                .and_then(|v| v.as_str())
                                .map(|k| k == "mut")
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);

            let missing_owner = is_raw && !is_signer && !has_authority_constraint && !is_init;

            // ── S2: missing-signer ──
            // If ANY sibling has has_one = <this account>, this account is an
            // authority target. Fire ONLY when the target is RAW (no type
            // discriminator). TYPED Account<T> targets provide ownership +
            // discriminator by construction — the signer requirement is a
            // substrate-wall question the metadata can't resolve.
            let is_authority_target = accounts.iter().any(|other| {
                other
                    .get("constraints")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter().any(|c| {
                            c.get("kind").and_then(|v| v.as_str()) == Some("has_one")
                                && c.get("target").and_then(|v| v.as_str()) == Some(account_name)
                        })
                    })
                    .unwrap_or(false)
            });
            let missing_signer = is_authority_target && is_raw && !is_signer && !is_init;

            if missing_has_one || missing_owner || missing_signer {
                for func_name in &using_functions {
                    let constraint_class = if missing_has_one {
                        "has_one"
                    } else if missing_signer {
                        "signer"
                    } else {
                        "owner"
                    };
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: func_name.clone(),
                        authority_source: format!("account:{}:{}", constraint_class, account_name),
                        check_type: "missing".into(),
                    }));
                }
            }

            // Enforced edge for Signer accounts (type-level authority)
            if is_signer {
                for func_name in &using_functions {
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: func_name.clone(),
                        authority_source: "signer".into(),
                        check_type: "enforced".into(),
                    }));
                }
            }
        }
    }

    // Deduplicate edges using a HashSet for O(n) performance
    let mut seen = std::collections::HashSet::new();
    edges.retain(|e| {
        let key = edge_key(e);
        seen.insert(key)
    });

    edges
}

fn edge_key(e: &Edge) -> (String, String, String) {
    match e {
        Edge::Call(c) => ("Call".into(), c.from.clone(), c.to.clone()),
        Edge::State(s) => ("State".into(), s.function.clone(), s.state.clone()),
        Edge::Authority(a) => (
            "Authority".into(),
            a.function.clone(),
            a.authority_source.clone(),
        ),
        Edge::External(ex) => ("External".into(), ex.function.clone(), ex.target.clone()),
    }
}

/// Extract the target field from a has_one = X constraint.
fn extract_has_one_target(constraint_str: &str) -> String {
    // Look for has_one = X pattern
    if let Some(start) = constraint_str.find("has_one") {
        let rest = &constraint_str[start..];
        if let Some(eq_pos) = rest.find('=') {
            let after_eq = rest[eq_pos + 1..].trim();
            // Extract the identifier after =
            let target: String = after_eq
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !target.is_empty() {
                return target;
            }
        }
    }
    "unknown".into()
}
