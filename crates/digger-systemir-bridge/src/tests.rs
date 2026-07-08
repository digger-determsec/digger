//! B6 tests: golden snapshot, determinism, multi-protocol honesty.
//!
//! All SystemIR types lack Serialize/PartialEq, so golden assertions use
//! Debug formatting (format!("{:?}", ...)).

use super::*;
use digger_ir::Edge;
use digger_protocol_model::capability_graph::{Capability, CapabilityKind};
use digger_protocol_model::permissions::PermissionAction;
use digger_protocol_model::DependencyKind;
use digger_reconstruct::provenance::ReconstructionStage;
use digger_reconstruct::RecoveredAddress;

fn make_test_inputs() -> (ProtocolModel, InvestigationPlan, ResearchContext) {
    let input = ::digger_protocol_model::model::ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    };
    let model = ProtocolModel::build(&input);
    let plan = ::digger_investigation::build_investigation_plan(&model);
    let context =
        ::digger_research_context::assemble_research_context(&model, &plan, &dummy_graph());
    (model, plan, context)
}

fn dummy_graph() -> ::digger_research_graph::graph::ResearchGraph {
    let input = ::digger_protocol_model::model::ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    };
    let model = ProtocolModel::build(&input);
    let plan = ::digger_investigation::build_investigation_plan(&model);
    ::digger_research_graph::builder::build_research_graph(&model, &plan)
}

fn cap(id: &str, kind: CapabilityKind) -> Capability {
    use digger_protocol_model::derive_provenance;
    let provenance = derive_provenance(&format!("cap|{}", id), id);
    Capability {
        id: id.to_string(),
        kind,
        basis_fact_ids: vec![],
        provenance,
    }
}

// ── Golden snapshot test ──────────────────────────────────────

#[test]
fn golden_snapshot_full_bridged_output() {
    // Build a realistic ProtocolModel with a mix of capabilities.
    // We hand-build a ResolvedContext with specific capabilities + permissions
    // to test the full bridge path deterministically.
    let capabilities = vec![
        cap("cap:upgrade_guarded", CapabilityKind::Upgrade),
        cap("cap:mint_unguarded", CapabilityKind::Mint),
        cap("cap:pause_unguarded", CapabilityKind::Pause),
        cap("cap:oracle1", CapabilityKind::OracleDependency),
    ];
    let permissions = vec![
        // Upgrade: guarded (holder=Some)
        digger_protocol_model::permissions::Permission::new(
            PermissionAction::Upgrade,
            Some(RecoveredAddress::Resolved("0xupgrade_auth".into())),
            "cap:upgrade_guarded".to_string(),
        ),
        // Mint: unguarded (holder=None)
        digger_protocol_model::permissions::Permission::new(
            PermissionAction::Mint,
            None,
            "cap:mint_unguarded".to_string(),
        ),
        // Pause: unguarded (holder=None)
        digger_protocol_model::permissions::Permission::new(
            PermissionAction::Pause,
            None,
            "cap:pause_unguarded".to_string(),
        ),
    ];

    // Build a minimal InvestigationPlan with one target.
    let input = ::digger_protocol_model::model::ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    };
    let model = ProtocolModel::build(&input);
    let plan = ::digger_investigation::build_investigation_plan(&model);
    let context =
        ::digger_research_context::assemble_research_context(&model, &plan, &dummy_graph());

    // Synthesize functions + edges from our hand-built capabilities.
    let functions = map_functions::synthesize_functions(&capabilities, &permissions);
    let names: Vec<String> = functions.iter().map(|f| f.name.clone()).collect();
    let edges = map_edges::map_to_edges(&capabilities, &permissions, &[], &[], &names);

    let system_ir = SystemIR {
        program_id: model.id.clone(),
        language: Language::Unknown,
        functions,
        state: Vec::new(),
        edges,
    };

    let mut systems = BTreeMap::new();
    systems.insert(model.id.clone(), system_ir);

    let plan_priority = build_plan_priority(&plan);
    let provenance = derive_bridge_provenance(&context.id, &model.id, &plan.id);

    let output = BridgedOutput {
        systems,
        context_id: context.id.clone(),
        provenance,
        plan_priority,
    };

    let debug = format!("{:?}", output);

    // Snapshot assertions: verify key structural properties.
    // (We can't assert byte-identical due to content-addressed ids changing
    // across runs, but we can assert structural invariants.)

    // 1. Exactly one system entry.
    assert_eq!(output.systems.len(), 1, "exactly one system entry");
    assert!(output.systems.contains_key(&model.id));

    // 2. SystemIR has correct program_id.
    let ir = output.systems.get(&model.id).unwrap();
    assert_eq!(ir.program_id, model.id);
    assert_eq!(ir.language, Language::Unknown);

    // 3. Functions: 4 capabilities → 4 functions (unique names).
    assert_eq!(ir.functions.len(), 4, "4 capabilities → 4 functions");
    let func_names: Vec<&str> = ir.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(func_names.contains(&"__gen5::upgrade"));
    assert!(func_names.contains(&"__gen5::mint"));
    assert!(func_names.contains(&"__gen5::pause"));
    assert!(func_names.contains(&"__gen5::oracle_dependency"));

    // 4. Effects: upgrade has authority_required=true, others false.
    let upgrade_fn = ir
        .functions
        .iter()
        .find(|f| f.name == "__gen5::upgrade")
        .unwrap();
    assert!(upgrade_fn.effects.authority_required, "guarded upgrade");
    assert!(upgrade_fn.effects.state_mutation);
    assert!(upgrade_fn.modifiers.is_empty());

    let mint_fn = ir
        .functions
        .iter()
        .find(|f| f.name == "__gen5::mint")
        .unwrap();
    assert!(!mint_fn.effects.authority_required, "unguarded mint");
    assert!(mint_fn.effects.value_transfer);

    let pause_fn = ir
        .functions
        .iter()
        .find(|f| f.name == "__gen5::pause")
        .unwrap();
    assert!(!pause_fn.effects.authority_required, "unguarded pause");

    let oracle_fn = ir
        .functions
        .iter()
        .find(|f| f.name == "__gen5::oracle_dependency")
        .unwrap();
    assert!(
        !oracle_fn.effects.authority_required,
        "permissionless oracle"
    );
    assert!(oracle_fn.effects.external_call);

    // 5. Edges: 2 Authority (upgrade enforced + mint missing + pause missing) + 1 External (oracle)
    let auth_edges: Vec<_> = ir
        .edges
        .iter()
        .filter(|e| matches!(e, Edge::Authority(_)))
        .collect();
    let ext_edges: Vec<_> = ir
        .edges
        .iter()
        .filter(|e| matches!(e, Edge::External(_)))
        .collect();
    assert_eq!(
        auth_edges.len(),
        3,
        "upgrade enforced + mint missing + pause missing"
    );
    assert_eq!(ext_edges.len(), 1, "oracle dependency");

    // 6. State is empty.
    assert!(ir.state.is_empty());

    // 7. context_id matches.
    assert_eq!(output.context_id, context.id);

    // 8. plan_priority: empty for empty model (no targets with rank > 0).
    assert!(output.plan_priority.is_empty() || output.plan_priority.values().all(|&r| r > 0));

    // 9. Provenance triple.
    assert_eq!(
        output.provenance.originating_evidence,
        digger_reconstruct::provenance::EvidenceSource::Inferred
    );
    assert_eq!(output.provenance.stage, ReconstructionStage::Enrich);
    assert!(output.provenance.basis.is_some());

    // 10. Debug output is non-empty (sanity).
    assert!(!debug.is_empty());
}

// ── Determinism test ──────────────────────────────────────────

#[test]
fn determinism_byte_identical_debug() {
    let (model, plan, context) = make_test_inputs();
    let out1 = bridge_to_systemir(&model, &plan, &context);
    let out2 = bridge_to_systemir(&model, &plan, &context);

    // BridgedOutput doesn't derive PartialEq, so compare via Debug.
    let d1 = format!("{:?}", out1);
    let d2 = format!("{:?}", out2);
    assert_eq!(
        d1, d2,
        "two bridge calls must produce byte-identical Debug output"
    );
}

// ── Multi-protocol honesty test ───────────────────────────────

#[test]
fn multi_protocol_honesty_no_fabrication() {
    // Build a ResearchContext that references a foreign protocol id.
    let (model, plan, context) = make_test_inputs();
    let output = bridge_to_systemir(&model, &plan, &context);

    // systems should have EXACTLY ONE entry (the current protocol).
    assert_eq!(output.systems.len(), 1, "only one system entry");
    assert!(output.systems.contains_key(&model.id));

    // Foreign protocol ids do NOT appear as fabricated systems.
    // The context references only the current protocol (empty model),
    // so no foreign ids should be in systems.
    for key in output.systems.keys() {
        assert_eq!(
            key, &model.id,
            "only the current protocol should be in systems"
        );
    }
}

#[test]
fn multi_protocol_honesty_with_foreign_refs() {
    // Simulate a context with a foreign protocol reference.
    let (model, plan, mut ctx) = make_test_inputs();
    ctx.referenced_protocol_ids
        .insert("protocol:foreign_xyz".to_string());
    let output = bridge_to_systemir(&model, &plan, &ctx);

    // Still exactly one system entry — the foreign id is NOT fabricated.
    assert_eq!(output.systems.len(), 1);
    assert!(output.systems.contains_key(&model.id));
    assert!(
        !output.systems.contains_key("protocol:foreign_xyz"),
        "foreign protocol must NOT be fabricated into a system"
    );
}

// ── Plan priority wiring test ─────────────────────────────────

#[test]
fn plan_priority_wired_from_real_plan() {
    let (model, plan, context) = make_test_inputs();
    let output = bridge_to_systemir(&model, &plan, &context);

    // For an empty model, the plan has no targets with rank > 0,
    // so plan_priority should be empty.
    assert!(output.plan_priority.is_empty());
}

// ── Provenance lineage test ───────────────────────────────────

#[test]
fn provenance_includes_plan_id() {
    let (model, plan, context) = make_test_inputs();
    let output = bridge_to_systemir(&model, &plan, &context);

    // Provenance basis should include model.id, plan.id, and context.id.
    let basis = output
        .provenance
        .basis
        .as_ref()
        .expect("basis must be present");
    assert!(basis.contains(&model.id), "basis must contain model id");
    assert!(basis.contains(&plan.id), "basis must contain plan id");
    assert!(basis.contains(&context.id), "basis must contain context id");
}

// ── Preserved safety-critical tests ───────────────────────────

#[test]
fn guard_fidelity_holder_none_means_unguarded() {
    let c = cap("cap:pause_none", CapabilityKind::Pause);
    let p = vec![digger_protocol_model::permissions::Permission::new(
        PermissionAction::Pause,
        None,
        "cap:pause_none".to_string(),
    )];
    let f = map_functions::synthesize_functions(&[c], &p);
    assert!(!f[0].effects.authority_required);
}

#[test]
fn guard_fidelity_holder_resolved_means_guarded() {
    let c = cap("cap:burn_resolved", CapabilityKind::Burn);
    let p = vec![digger_protocol_model::permissions::Permission::new(
        PermissionAction::Burn,
        Some(RecoveredAddress::Resolved("0xburner".into())),
        "cap:burn_resolved".to_string(),
    )];
    let f = map_functions::synthesize_functions(&[c], &p);
    assert!(f[0].effects.authority_required);
}

#[test]
fn end_to_end_unguarded_surfaces_missing() {
    let caps = vec![
        cap("cap:mint_real", CapabilityKind::Mint),
        cap("cap:pause_real", CapabilityKind::Pause),
    ];
    let perms = vec![
        digger_protocol_model::permissions::Permission::new(
            PermissionAction::Mint,
            None,
            "cap:mint_real".to_string(),
        ),
        digger_protocol_model::permissions::Permission::new(
            PermissionAction::Pause,
            None,
            "cap:pause_real".to_string(),
        ),
    ];
    let fns = map_functions::synthesize_functions(&caps, &perms);
    let names: Vec<String> = fns.iter().map(|f| f.name.clone()).collect();
    let edges = map_edges::map_to_edges(&caps, &perms, &[], &[], &names);
    let auth: Vec<_> = edges
        .iter()
        .filter(|e| matches!(e, Edge::Authority(_)))
        .collect();
    assert_eq!(auth.len(), 2);
    for e in &auth {
        if let Edge::Authority(a) = e {
            assert_eq!(a.check_type, "missing");
        }
    }
}

// ── Explicit permissionless / oracle edge tests (restored) ────

#[test]
fn no_authority_edge_for_permissionless() {
    let capabilities = vec![cap("cap:fl1", CapabilityKind::FlashLoan)];
    let functions = map_functions::synthesize_functions(&capabilities, &[]);
    let names: Vec<String> = functions.iter().map(|f| f.name.clone()).collect();
    let edges = map_edges::map_to_edges(&capabilities, &[], &[], &[], &names);
    let auth: Vec<_> = edges
        .iter()
        .filter(|e| matches!(e, Edge::Authority(_)))
        .collect();
    assert!(auth.is_empty(), "flash loan must NOT have authority edge");
}

#[test]
fn no_authority_edge_for_oracle() {
    let capabilities = vec![cap("cap:oracle1", CapabilityKind::OracleDependency)];
    let functions = map_functions::synthesize_functions(&capabilities, &[]);
    let names: Vec<String> = functions.iter().map(|f| f.name.clone()).collect();
    let edges = map_edges::map_to_edges(&capabilities, &[], &[], &[], &names);
    let auth: Vec<_> = edges
        .iter()
        .filter(|e| matches!(e, Edge::Authority(_)))
        .collect();
    assert!(auth.is_empty(), "oracle must NOT have authority edge");
}

// ── State tests ──────────────────────────────────────────────

#[test]
fn state_always_empty() {
    let (model, plan, context) = make_test_inputs();
    let output = bridge_to_systemir(&model, &plan, &context);
    let ir = output.systems.get(&model.id).unwrap();
    assert!(ir.state.is_empty());
}

// ── Determinism enforcement tests ────────────────────────

/// Build a non-trivial ProtocolModel with:
/// - Two capabilities of the SAME kind (forces name disambiguation)
/// - One permission with holder=Some, one with holder=None
/// - One TrustBoundary::UpgradeAuthority
/// - One external-call kind with a matching dependency
fn make_diverse_inputs() -> (ProtocolModel, InvestigationPlan, ResearchContext) {
    use digger_protocol_model::trust::{TrustBoundary, TrustBoundaryKind};

    let input = ::digger_protocol_model::model::ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    };
    let mut model = ProtocolModel::build(&input);

    // Add capabilities: two of the SAME kind (Mint) + upgrade + oracle
    model.capability_graph.capabilities = vec![
        cap("cap:mint_a", CapabilityKind::Mint),
        cap("cap:mint_b", CapabilityKind::Mint), // same kind — disambiguation test
        cap("cap:upgrade", CapabilityKind::Upgrade),
        cap("cap:oracle", CapabilityKind::OracleDependency),
    ];

    // Add permissions: one guarded (holder=Some), one unguarded (holder=None)
    model.permissions = vec![
        digger_protocol_model::permissions::Permission::new(
            PermissionAction::Upgrade,
            Some(RecoveredAddress::Resolved("0xauth".into())),
            "cap:upgrade".to_string(),
        ),
        digger_protocol_model::permissions::Permission::new(
            PermissionAction::Mint,
            None,
            "cap:mint_a".to_string(),
        ),
    ];

    // Add trust boundary
    model.trust_boundaries = vec![TrustBoundary {
        id: "tb:upgrade".to_string(),
        kind: TrustBoundaryKind::UpgradeAuthority,
        inside_id: "cap:upgrade".to_string(),
        outside_id: "0xauth".to_string(),
        provenance: digger_protocol_model::derive_provenance("tb|upgrade", "upgrade"),
    }];

    // Add dependency for oracle
    model.dependencies = vec![::digger_protocol_model::RecoveredDependency {
        id: "dep:oracle".to_string(),
        kind: DependencyKind::PriceOracle,
        address: RecoveredAddress::Resolved("oracle_feed".into()),
        detail: digger_reconstruct::DependencyDetail::Evm(
            digger_reconstruct::EvmDependency::default(),
        ),
        provenance: digger_protocol_model::derive_provenance("dep|oracle", "oracle"),
    }];

    let plan = ::digger_investigation::build_investigation_plan(&model);
    let context =
        ::digger_research_context::assemble_research_context(&model, &plan, &dummy_graph());
    (model, plan, context)
}

/// Bridge determinism: two calls on identical inputs produce byte-identical output.
#[test]
fn bridge_determinism_idempotent() {
    let (model, plan, context) = make_diverse_inputs();

    let out1 = bridge_to_systemir(&model, &plan, &context);
    let out2 = bridge_to_systemir(&model, &plan, &context);

    let debug1 = format!("{:?}", out1);
    let debug2 = format!("{:?}", out2);
    assert_eq!(
        debug1, debug2,
        "two bridges of identical inputs must be byte-identical"
    );
}

/// Bridge determinism: input ORDER does not affect output.
///
/// NOTE: bridge_to_systemir resolves capabilities/permissions via resolve_context,
/// which only admits elements whose ids are in the ResearchContext's
/// referenced_node_ids. For synthetic inputs that set is empty, so the full-bridge
/// path produces empty functions/edges and cannot exercise canonical ordering.
/// We therefore assert input-order invariance at the layer where ordering runs:
/// synthesize_functions + map_to_edges, on a populated capability/permission set,
/// evaluated forward vs fully reversed. Non-empty assertions guard against vacuity.
#[test]
fn bridge_determinism_input_order_invariant() {
    let caps_fwd = vec![
        cap("cap:mint_a", CapabilityKind::Mint),
        cap("cap:mint_b", CapabilityKind::Mint),
        cap("cap:upgrade", CapabilityKind::Upgrade),
        cap("cap:oracle", CapabilityKind::OracleDependency),
    ];
    let perms_fwd = vec![
        digger_protocol_model::permissions::Permission::new(
            PermissionAction::Upgrade,
            Some(RecoveredAddress::Resolved("0xauth".into())),
            "cap:upgrade".to_string(),
        ),
        digger_protocol_model::permissions::Permission::new(
            PermissionAction::Mint,
            None,
            "cap:mint_a".to_string(),
        ),
    ];

    let mut caps_rev = caps_fwd.clone();
    caps_rev.reverse();
    let mut perms_rev = perms_fwd.clone();
    perms_rev.reverse();

    // Forward path.
    let fns_fwd = map_functions::synthesize_functions(&caps_fwd, &perms_fwd);
    let mut names_fwd: Vec<String> = fns_fwd.iter().map(|f| f.name.clone()).collect();
    let edges_fwd = map_edges::map_to_edges(&caps_fwd, &perms_fwd, &[], &[], &names_fwd);

    // Reversed path: reverse the capability/permission inputs AND the
    // function_names handed to map_to_edges, so canonical ordering is genuinely
    // exercised on permuted pre-sort sequences.
    let fns_rev = map_functions::synthesize_functions(&caps_rev, &perms_rev);
    names_fwd.reverse();
    let names_rev = names_fwd;
    let edges_rev = map_edges::map_to_edges(&caps_rev, &perms_rev, &[], &[], &names_rev);

    // Non-empty guard: if these ever become empty the test is meaningless.
    assert_eq!(fns_fwd.len(), 4, "expected 4 synthesized functions");
    assert!(!edges_fwd.is_empty(), "expected a non-empty edge set");

    assert_eq!(
        format!("{:?}", fns_fwd),
        format!("{:?}", fns_rev),
        "function order must be invariant to input order"
    );
    assert_eq!(
        format!("{:?}", edges_fwd),
        format!("{:?}", edges_rev),
        "edge order must be invariant to input order"
    );
}

/// Direct test: canonical_function_order sorts by id ascending regardless of input permutation.
#[test]
fn ordering_function_order_is_canonical_and_permutation_invariant() {
    use digger_ir::{Effects, Function, Visibility};
    let mk = |id: &str| Function {
        id: id.to_string(),
        name: format!("fn_{}", id),
        contract: String::new(),
        visibility: Visibility::Public,
        inputs: vec![],
        outputs: vec![],
        modifiers: vec![],
        effects: Effects {
            state_mutation: false,
            external_call: false,
            authority_required: false,
            value_transfer: false,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
    };
    let mut a = vec![mk("c"), mk("a"), mk("b")];
    let mut b = a.clone();
    b.reverse();
    crate::ordering::canonical_function_order(&mut a);
    crate::ordering::canonical_function_order(&mut b);
    let ids_a: Vec<&str> = a.iter().map(|f| f.id.as_str()).collect();
    let ids_b: Vec<&str> = b.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids_a, vec!["a", "b", "c"], "must sort by id ascending");
    assert_eq!(ids_a, ids_b, "order must be invariant to input order");
}

/// Direct test: canonical_edge_order sorts by (kind_tag, primary, secondary) regardless of input permutation.
#[test]
fn ordering_edge_order_is_canonical_and_permutation_invariant() {
    use digger_ir::{AuthorityEdge, Edge, ExternalCallEdge};
    let mk_auth = |f: &str| {
        Edge::Authority(AuthorityEdge {
            function: f.to_string(),
            authority_source: "unknown".into(),
            check_type: "missing".into(),
        })
    };
    let mk_ext = |f: &str| {
        Edge::External(ExternalCallEdge {
            function: f.to_string(),
            target: "external".into(),
            risk_flags: vec!["external_call".into()],
        })
    };
    let mut a = vec![
        mk_ext("__gen5::oracle"),
        mk_auth("__gen5::mint"),
        mk_auth("__gen5::burn"),
    ];
    let mut b = a.clone();
    b.reverse();
    crate::ordering::canonical_edge_order(&mut a);
    crate::ordering::canonical_edge_order(&mut b);
    let keys_a: Vec<String> = a.iter().map(|e| format!("{:?}", e)).collect();
    let keys_b: Vec<String> = b.iter().map(|e| format!("{:?}", e)).collect();
    assert_eq!(
        keys_a, keys_b,
        "edge order must be invariant to input permutation"
    );
}

/// ADR-0026: bridge abstains from language and state.
/// The bridge emits Language::Unknown and empty state for every protocol.
/// A future edit that fabricates language or state would break this test.
#[test]
fn bridge_abstains_language_and_state() {
    // ADR-0026: bridge recovers neither language nor concrete storage;
    // emits Language::Unknown and empty state rather than fabricate.
    let (model, plan, context) = make_diverse_inputs();
    let output = bridge_to_systemir(&model, &plan, &context);

    for (key, ir) in &output.systems {
        assert_eq!(
            ir.language,
            digger_ir::Language::Unknown,
            "ADR-0026 violation: bridge must emit Language::Unknown for protocol {}",
            key
        );
        assert!(
            ir.state.is_empty(),
            "ADR-0026 violation: bridge must emit empty state for protocol {}",
            key
        );
    }
}
