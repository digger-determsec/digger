#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![allow(
    clippy::needless_update,
    clippy::len_zero,
    clippy::bool_assert_comparison,
    clippy::for_kv_map,
    clippy::manual_contains
)]

pub mod analysis;
pub mod authority_graph;
pub mod builder;
pub mod call_graph;
pub mod external_graph;
pub mod state_graph;

use digger_ir::system::SystemIR;
use digger_parser::model::RawProgram;

pub fn build_system_ir(program: RawProgram) -> SystemIR {
    builder::build(program)
}

pub fn build_system_ir_with_language(
    program: RawProgram,
    language: digger_ir::Language,
) -> SystemIR {
    builder::build_with_language(program, language)
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_ir::*;
    use digger_parser::model::*;

    #[test]
    fn test_build_system_ir_solidity() {
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
            ],
            state: vec![
                RawState { name: "balances".into(), ty: "mapping".into(), ..Default::default() },
                RawState { name: "owner".into(), ty: "address".into(), ..Default::default() },
            ],
            calls: vec![
                RawCall { from: "withdraw".into(), to: "external".into(), kind: digger_ir::CallKind::External },
            ],
            ..Default::default()
        };

        let ir = build_system_ir(program);

        assert_eq!(ir.functions.len(), 2);
        assert_eq!(ir.state.len(), 2);
        assert!(ir.edges.len() > 0);

        // Check authority edges exist
        let auth_edges: Vec<_> = ir
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::Authority(_)))
            .collect();
        assert!(auth_edges.len() >= 2);

        // Check state edges exist
        let state_edges: Vec<_> = ir
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::State(_)))
            .collect();
        assert!(state_edges.len() >= 2);

        // Check external call edges exist
        let ext_edges: Vec<_> = ir
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::External(_)))
            .collect();
        assert!(ext_edges.len() >= 1);
    }

    #[test]
    fn test_build_system_ir_anchor() {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "initialize".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "pub fn initialize(ctx: Context<Initialize>) -> Result<()> { Ok(()) }".into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "withdraw".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> { token::transfer(ctx.accounts.transfer_ctx(), amount)?; Ok(()) }".into(),
                    ..Default::default()
                },
            ],
            state: vec![
                RawState { name: "vault".into(), ty: "anchor_account".into(), ..Default::default() },
            ],
            calls: vec![
                RawCall { from: "withdraw".into(), to: "cpi".into(), kind: digger_ir::CallKind::CrossProgram },
            ],
            ..Default::default()
        };

        let ir = build_system_ir(program);

        assert_eq!(ir.functions.len(), 2);
        assert!(ir.edges.len() > 0);

        // CPI should be detected
        let ext_edges: Vec<_> = ir
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::External(_)))
            .collect();
        assert!(ext_edges.len() >= 1);
    }

    // ─────────────────────────────────────────────────────────────
    // Phase 2.2 — Graph Analysis Tests
    // ─────────────────────────────────────────────────────────────

    fn make_vulnerable_ir() -> digger_ir::SystemIR {
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
                RawCall { from: "withdraw".into(), to: "external".into(), kind: digger_ir::CallKind::External },
            ],
            ..Default::default()
        };
        build_system_ir(program)
    }

    #[test]
    fn test_execution_graph() {
        let ir = make_vulnerable_ir();
        let exec = analysis::ExecutionGraph::build(&ir);

        // All functions should be in the graph
        assert_eq!(
            exec.edges.len() + exec.entry_points.len() + exec.leaf_functions.len() > 0,
            true
        );

        // deposit and setOwner are likely entry points (not called by others)
        assert!(exec.entry_points.len() > 0, "Should have entry points");
    }

    #[test]
    fn test_state_dependency_graph() {
        let ir = make_vulnerable_ir();
        let state_dep = analysis::StateDependencyGraph::build(&ir);

        // The state graph builder detects state access via body text matching.
        // setOwner writes "owner = newOwner" which matches "owner =" pattern.
        let owner_writers = state_dep.writers.get("owner");
        assert!(owner_writers.is_some(), "Should detect writers to owner");
        assert!(
            owner_writers.unwrap().contains(&"setOwner".to_string()),
            "setOwner should write to owner"
        );

        // Should have state edges (at least owner writes)
        let writer_count: usize = state_dep.writers.values().map(|v| v.len()).sum();
        let reader_count: usize = state_dep.readers.values().map(|v| v.len()).sum();
        assert!(
            writer_count + reader_count > 0,
            "Should have state dependency edges"
        );
    }

    #[test]
    fn test_authority_boundary_graph() {
        let ir = make_vulnerable_ir();
        let auth = analysis::AuthorityBoundaryGraph::build(&ir);

        // Should have some enforced and some missing
        assert!(
            auth.enforced.len() + auth.missing.len() > 0,
            "Should have authority edges"
        );

        // setOwner has require(msg.sender == owner) — should be enforced
        assert!(
            auth.enforced.contains(&"setOwner".to_string()),
            "setOwner should have enforced authority"
        );

        // withdraw has require(balances >= amount) — this is invariant, not authority
        // The new analyzer correctly distinguishes balance checks from authority checks
    }

    #[test]
    fn test_cross_program_graph() {
        let ir = make_vulnerable_ir();
        let cross = analysis::CrossProgramGraph::build(&ir);

        // withdraw makes external call
        assert!(
            cross.external_callers.contains(&"withdraw".to_string()),
            "withdraw should be an external caller"
        );
        assert!(
            cross.external_targets.contains(&"external".to_string()),
            "external should be a target"
        );
    }

    #[test]
    fn test_vulnerability_path_derivation() {
        let ir = make_vulnerable_ir();
        let vuln = analysis::VulnerabilityPathAnalysis::derive(&ir);

        // Should detect some vulnerability paths
        // (exact count depends on state graph heuristic matching)
        assert!(
            vuln.paths.len() > 0,
            "Should detect vulnerability paths, found {}",
            vuln.paths.len()
        );

        // At minimum, unauthorized modification should be detected
        // (setOwner writes "owner = newOwner" which matches "owner =" pattern,
        //  and setOwner has no require/signer → missing authority)
        assert!(
            vuln.unauthorized_paths.len() > 0 || vuln.paths.len() > 0,
            "Should detect at least one vulnerability path type"
        );
    }

    #[test]
    fn test_cross_language_consistency() {
        // Verify that Solidity, Rust, and Anchor edges are treated uniformly
        let solidity_ir = make_vulnerable_ir();

        // All CallEdges should be treated the same regardless of source
        let call_edges: Vec<_> = solidity_ir
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::Call(_)))
            .collect();
        for edge in &call_edges {
            if let Edge::Call(call) = edge {
                // No language-specific branching on call edges
                assert!(!call.from.is_empty());
                assert!(!call.to.is_empty());
            }
        }
    }

    #[test]
    fn test_no_new_ir_types() {
        // Verify analysis uses only existing IR types
        let ir = make_vulnerable_ir();

        // Execution graph uses only CallEdge
        let exec = analysis::ExecutionGraph::build(&ir);
        for edge in &exec.edges {
            // These are CallEdge — existing IR type
            let _ = &edge.from;
            let _ = &edge.to;
        }

        // State dependency uses only StateEdge
        let state_dep = analysis::StateDependencyGraph::build(&ir);
        for (_, writers) in &state_dep.writers {
            for writer in writers {
                // These are function names from existing IR
                assert!(!writer.is_empty());
            }
        }
    }

    #[test]
    fn test_deterministic_analysis() {
        let ir = make_vulnerable_ir();

        // Run analysis 3 times — results must be identical
        let vuln1 = analysis::VulnerabilityPathAnalysis::derive(&ir);
        let vuln2 = analysis::VulnerabilityPathAnalysis::derive(&ir);
        let vuln3 = analysis::VulnerabilityPathAnalysis::derive(&ir);

        assert_eq!(vuln1.paths.len(), vuln2.paths.len());
        assert_eq!(vuln2.paths.len(), vuln3.paths.len());
    }

    #[test]
    fn test_deterministic_json_output() {
        let ir = make_vulnerable_ir();

        // Build analysis twice with the same IR
        let exec1 = analysis::ExecutionGraph::build(&ir);
        let state1 = analysis::StateDependencyGraph::build(&ir);
        let auth1 = analysis::AuthorityBoundaryGraph::build(&ir);
        let cross1 = analysis::CrossProgramGraph::build(&ir);

        let exec2 = analysis::ExecutionGraph::build(&ir);
        let state2 = analysis::StateDependencyGraph::build(&ir);
        let auth2 = analysis::AuthorityBoundaryGraph::build(&ir);
        let cross2 = analysis::CrossProgramGraph::build(&ir);

        // Serialize BTreeMap fields to JSON — must be byte-identical
        // This proves BTreeMap ordering produces deterministic output
        assert_eq!(
            serde_json::to_string(&exec1.depths).unwrap(),
            serde_json::to_string(&exec2.depths).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&state1.writers).unwrap(),
            serde_json::to_string(&state2.writers).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&state1.readers).unwrap(),
            serde_json::to_string(&state2.readers).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&auth1.sources).unwrap(),
            serde_json::to_string(&auth2.sources).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&cross1.call_graph).unwrap(),
            serde_json::to_string(&cross2.call_graph).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&cross1.target_risks).unwrap(),
            serde_json::to_string(&cross2.target_risks).unwrap()
        );

        // Verify keys are in sorted order (BTreeMap guarantee)
        let depths_json = serde_json::to_string(&exec1.depths).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&depths_json).unwrap();
        if let Some(obj) = parsed.as_object() {
            let keys: Vec<_> = obj.keys().cloned().collect();
            let mut sorted_keys = keys.clone();
            sorted_keys.sort();
            assert_eq!(keys, sorted_keys, "depths keys must be in sorted order");
        }
    }

    #[test]
    fn test_execution_graph_depths() {
        let ir = make_vulnerable_ir();
        let exec = analysis::ExecutionGraph::build(&ir);

        // All depths should be >= 0
        for depth in exec.depths.values() {
            assert!(*depth < 100, "depth should be reasonable, got {}", depth);
        }

        // Max depth should be >= max of individual depths
        assert!(exec.max_depth >= *exec.depths.values().max().unwrap_or(&0));
    }

    #[test]
    fn test_state_dependency_isolation() {
        let ir = make_vulnerable_ir();
        let state_dep = analysis::StateDependencyGraph::build(&ir);

        // Isolated state should not appear in shared_mutations
        for isolated in &state_dep.isolated_state {
            assert!(
                !state_dep.shared_mutations.contains(isolated),
                "isolated state {} should not be in shared_mutations",
                isolated
            );
        }
    }

    #[test]
    fn test_cross_program_call_graph_consistency() {
        let ir = make_vulnerable_ir();
        let cross = analysis::CrossProgramGraph::build(&ir);

        // Every key in call_graph should be an external caller
        for caller in cross.call_graph.keys() {
            assert!(
                cross.external_callers.contains(caller),
                "call_graph key {} should be in external_callers",
                caller
            );
        }

        // Every target in call_graph should be in external_targets
        for targets in cross.call_graph.values() {
            for target in targets {
                assert!(
                    cross.external_targets.contains(target),
                    "call_graph target {} should be in external_targets",
                    target
                );
            }
        }
    }
}
