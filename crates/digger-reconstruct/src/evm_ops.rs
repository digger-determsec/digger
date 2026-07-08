//! EVM operation recoverer (C5.2) — EXPERIMENTAL.
//!
//! Walks `LiftedProgram` instructions per function (via selector → reachable-block
//! partitioning) and classifies opcodes into `RecoveredOperation`s.
//!
//! **EXPERIMENTAL:** Achieves 12.8% recall on real solc-0.8.35-compiled bytecode
//! (ADR-0029). HIGH precision (no fabricated ops) but LOW recall due to compiler
//! transforms (optimizer, inlining, JUMP vs CALL, register allocation).
//! Source-path body recovery (`recover_source_body_graph`) is the first-class
//! operation-recovery path at 100% recall.
//!
//! Chain-agnostic `OperationKind` reused from `digger_parser::model`.
//! Evidence: `RuntimeBytecode`, `ReconstructionStage::Recover`.
//! Ordering: PC-offset (deterministic).
//! "Absent not empty": no grounded ops → no `RecoveredBody`.

use crate::body::{RecoveredBody, RecoveredBodyGraph, RecoveredOperation};
use crate::confidence::ConfidenceTier;
use crate::lifter::LiftedProgram;
use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};
use digger_parser::model::OperationKind;

/// Recovered body graph from an EVM LiftedProgram.
///
/// **EXPERIMENTAL:** Achieves 12.8% recall on real optimized bytecode (ADR-0029).
/// HIGH precision (no fabricated ops) but LOW recall due to compiler transforms.
/// Source-path body recovery (`recover_source_body_graph`) is the first-class
/// operation-recovery path at 100% recall.
///
/// Walks the dispatcher entries, partitions instructions by function via
/// reachable-block analysis (reusing the same pattern as EvmInterfaceRecoverer),
/// and classifies each instruction into a `RecoveredOperation`.
pub fn recover_evm_body_graph(program: &LiftedProgram) -> Option<RecoveredBodyGraph> {
    let mut bodies: Vec<RecoveredBody> = Vec::new();

    for entry in &program.dispatcher.entries {
        let fn_id = entry.selector.selector.clone();
        let target_block = match entry.target_block {
            Some(b) => b,
            None => continue,
        };

        let blocks = crate::evm::reachable_blocks(program, target_block);
        let insns = crate::evm::instructions_in(program, &blocks);

        let ops = recover_operations_for_function(&fn_id, &insns);
        if ops.is_empty() {
            continue;
        }

        let op_ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        let body_prov = Provenance::new(
            EvidenceSource::RuntimeBytecode,
            ReconstructionStage::Recover,
            ConfidenceTier::Recovered,
            &format!("body|{}", fn_id),
        );
        bodies.push(RecoveredBody {
            id: RecoveredBody::make_id(&fn_id, &op_ids),
            function_id: fn_id,
            operations: ops,
            provenance: body_prov,
            struct_context: None,
        });
    }

    if bodies.is_empty() {
        return None;
    }

    let body_ids: Vec<&str> = bodies.iter().map(|b| b.id.as_str()).collect();
    let graph_prov = Provenance::new(
        EvidenceSource::RuntimeBytecode,
        ReconstructionStage::Recover,
        ConfidenceTier::Recovered,
        "bodygraph|evm",
    );

    Some(RecoveredBodyGraph {
        id: RecoveredBodyGraph::make_id(&body_ids),
        bodies,
        provenance: graph_prov,
        account_models: std::collections::BTreeMap::new(),
    })
}

/// Recover operations for a single function's instructions (PC-ordered).
fn recover_operations_for_function(
    fn_id: &str,
    insns: &[&crate::lifter::RecoveredInstruction],
) -> Vec<RecoveredOperation> {
    let mut ops = Vec::new();
    let mut idx = 0usize;

    for insn in insns {
        let classified = classify_instruction(fn_id, idx, insn, insns);
        for op in classified {
            ops.push(op);
            idx += 1;
        }
    }

    ops
}

/// Classify a single instruction into zero or more operations.
/// Returns empty vec for unclassifiable instructions (do not fabricate).
fn classify_instruction(
    fn_id: &str,
    idx: usize,
    insn: &crate::lifter::RecoveredInstruction,
    all_insns: &[&crate::lifter::RecoveredInstruction],
) -> Vec<RecoveredOperation> {
    let mnemonic = &insn.mnemonic;

    match mnemonic.as_str() {
        "SLOAD" => {
            vec![make_op(
                fn_id,
                idx,
                OperationKind::StateRead,
                "slot:?",
                EvidenceSource::RuntimeBytecode,
                ConfidenceTier::Recovered,
                insn,
            )]
        }
        "SSTORE" => {
            vec![make_op(
                fn_id,
                idx,
                OperationKind::StateWrite,
                "slot:?",
                EvidenceSource::RuntimeBytecode,
                ConfidenceTier::Recovered,
                insn,
            )]
        }
        "CALL" | "CALLCODE" => {
            let mut result = vec![make_op(
                fn_id,
                idx,
                OperationKind::ExternalCall,
                "external",
                EvidenceSource::RuntimeBytecode,
                ConfidenceTier::Recovered,
                insn,
            )];
            if check_value_transfer(insn, all_insns) {
                result.push(make_op(
                    fn_id,
                    idx + 1,
                    OperationKind::ValueTransfer,
                    "value",
                    EvidenceSource::RuntimeBytecode,
                    ConfidenceTier::Recovered,
                    insn,
                ));
            }
            result
        }
        "DELEGATECALL" | "STATICCALL" => {
            vec![make_op(
                fn_id,
                idx,
                OperationKind::ExternalCall,
                "external",
                EvidenceSource::RuntimeBytecode,
                ConfidenceTier::Recovered,
                insn,
            )]
        }
        "CALLER" if is_authority_pattern(insn, idx, all_insns) => {
            vec![make_op(
                fn_id,
                idx,
                OperationKind::AuthorityCheck,
                "authority",
                EvidenceSource::RuntimeBytecode,
                ConfidenceTier::Inferred,
                insn,
            )]
        }
        _ => vec![],
    }
}

fn make_op(
    fn_id: &str,
    idx: usize,
    kind: OperationKind,
    target: &str,
    source: EvidenceSource,
    confidence: ConfidenceTier,
    insn: &crate::lifter::RecoveredInstruction,
) -> RecoveredOperation {
    let prov = Provenance::new(
        source,
        ReconstructionStage::Recover,
        confidence,
        &format!("op|{}|{}|{}", fn_id, insn.offset, kind),
    );
    RecoveredOperation {
        id: RecoveredOperation::make_id(fn_id, idx, &kind, target),
        function_id: fn_id.to_string(),
        index: idx,
        kind,
        target: target.into(),
        provenance: prov,
    }
}

/// Best-effort: detect if CALL has a non-zero value argument.
/// Conservative: returns false unless a clear non-zero value pattern is found.
fn check_value_transfer(
    _insn: &crate::lifter::RecoveredInstruction,
    all_insns: &[&crate::lifter::RecoveredInstruction],
) -> bool {
    // CALL uses stack: gas, addr, value, argsOffset, argsLength, retOffset, retLength
    // The value is the 3rd argument from top. Look for PUSH <non-zero> within the
    // window before this CALL.
    let pos = match all_insns.iter().position(|i| std::ptr::eq(*i, _insn)) {
        Some(p) => p,
        None => return false,
    };
    let start = pos.saturating_sub(6);
    for prev in all_insns[start..pos].iter() {
        if prev.mnemonic.starts_with("PUSH") {
            if let Some(val) = parse_const(&prev.operand) {
                if val > 0 && (val as u128) < (1u128 << 96) {
                    // Reasonable ETH value range
                    return true;
                }
            }
        }
    }
    false
}

/// Best-effort: detect CALLER + EQ authority-check pattern.
fn is_authority_pattern(
    _insn: &crate::lifter::RecoveredInstruction,
    idx: usize,
    all_insns: &[&crate::lifter::RecoveredInstruction],
) -> bool {
    let window_end = (idx + 4).min(all_insns.len());
    for next in all_insns.iter().take(window_end).skip(idx + 1) {
        if next.mnemonic == "EQ" {
            return true;
        }
    }
    false
}

fn parse_const(operand: &Option<String>) -> Option<u64> {
    let s = operand.as_ref()?;
    let h = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(h, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifter::{
        RecoveredCFG, RecoveredDispatcher, RecoveredInstruction, RecoveredSelectorSet,
        RecoveryPattern, TargetKind,
    };
    use crate::provenance::Provenance;

    fn test_prov(s: &str) -> Provenance {
        Provenance::new(
            EvidenceSource::RuntimeBytecode,
            ReconstructionStage::Lift,
            ConfidenceTier::Recovered,
            s,
        )
    }

    fn insn(offset: usize, mnemonic: &str, operand: Option<&str>) -> RecoveredInstruction {
        RecoveredInstruction {
            id: crate::lifter::node_id("insn", &format!("{}|{}", offset, mnemonic)),
            offset,
            mnemonic: mnemonic.to_string(),
            operand: operand.map(|s| s.to_string()),
            size: 1,
            provenance: test_prov(&format!("insn|{}", offset)),
        }
    }

    fn make_program(insns: Vec<RecoveredInstruction>, selector: &str) -> LiftedProgram {
        use crate::lifter::RecoveredSelector;
        let sel_bytes: Vec<u8> = (0..4).collect();
        LiftedProgram {
            id: crate::lifter::node_id("program", "test"),
            target: TargetKind::Evm,
            instructions: insns,
            cfg: RecoveredCFG {
                id: crate::lifter::node_id("cfg", "test"),
                entry: 0,
                blocks: vec![crate::lifter::RecoveredBasicBlock {
                    id: crate::lifter::node_id("bb", "test"),
                    index: 0,
                    start: 0,
                    end: 100,
                    instruction_offsets: (0..100).collect(),
                    terminator: crate::lifter::BlockTerminator::Stop,
                    provenance: test_prov("block"),
                }],
                edges: vec![],
                provenance: test_prov("cfg"),
            },
            dispatcher: RecoveredDispatcher {
                id: crate::lifter::node_id("dispatch", "test"),
                entries: vec![crate::lifter::DispatchEntry {
                    id: crate::lifter::node_id("entry", selector),
                    selector: RecoveredSelector {
                        id: crate::lifter::node_id("sel", selector),
                        selector: selector.to_string(),
                        bytes: sel_bytes,
                        provenance: test_prov("sel"),
                    },
                    target_offset: None,
                    target_block: Some(0),
                    target_block_id: Some(crate::lifter::node_id("bb", "test")),
                    pattern: RecoveryPattern::new("test", &[]),
                    provenance: test_prov("entry"),
                }],
                has_fallback: false,
                pattern: RecoveryPattern::new("test", &[]),
                provenance: test_prov("dispatch"),
            },
            selectors: RecoveredSelectorSet {
                id: crate::lifter::node_id("sels", "test"),
                selectors: vec![],
                provenance: test_prov("sels"),
            },
            provenance: test_prov("program"),
        }
    }

    #[test]
    fn sload_and_sstore_produce_state_ops() {
        let prog = make_program(
            vec![
                insn(0, "PUSH1", Some("0x04")),
                insn(1, "SLOAD", None),
                insn(2, "PUSH1", Some("0x01")),
                insn(3, "SSTORE", None),
                insn(4, "STOP", None),
            ],
            "aabbccdd",
        );
        let body_graph = recover_evm_body_graph(&prog).expect("should produce body");
        assert_eq!(body_graph.bodies.len(), 1);
        let body = &body_graph.bodies[0];
        let ops = &body.operations;
        assert!(ops.iter().any(|o| o.kind == OperationKind::StateRead));
        assert!(ops.iter().any(|o| o.kind == OperationKind::StateWrite));
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn call_produces_external_call() {
        let prog = make_program(
            vec![
                insn(
                    0,
                    "PUSH20",
                    Some("0x1234567890abcdef1234567890abcdef12345678"),
                ),
                insn(1, "CALL", None),
                insn(2, "STOP", None),
            ],
            "aabbccdd",
        );
        let body_graph = recover_evm_body_graph(&prog).expect("should produce body");
        let ops = &body_graph.bodies[0].operations;
        assert!(ops.iter().any(|o| o.kind == OperationKind::ExternalCall));
    }

    #[test]
    fn authority_pattern_detected() {
        let prog = make_program(
            vec![
                insn(0, "CALLER", None),
                insn(1, "EQ", None),
                insn(2, "PUSH1", Some("0x20")),
                insn(3, "JUMPI", None),
                insn(4, "STOP", None),
            ],
            "aabbccdd",
        );
        let body_graph = recover_evm_body_graph(&prog).expect("should produce body");
        let ops = &body_graph.bodies[0].operations;
        assert!(ops.iter().any(|o| o.kind == OperationKind::AuthorityCheck));
    }

    #[test]
    fn no_ops_yields_none() {
        let prog = make_program(vec![insn(0, "STOP", None)], "aabbccdd");
        let result = recover_evm_body_graph(&prog);
        assert!(result.is_none(), "STOP-only function should yield None");
    }

    #[test]
    fn determinism() {
        let prog = make_program(
            vec![
                insn(0, "SLOAD", None),
                insn(1, "SSTORE", None),
                insn(2, "STOP", None),
            ],
            "aabbccdd",
        );
        let a = format!("{:#?}", recover_evm_body_graph(&prog));
        let b = format!("{:#?}", recover_evm_body_graph(&prog));
        assert_eq!(a, b);
    }

    #[test]
    fn lifter_produces_dispatcher_for_real_bytecode() {
        // Reentrancy fixture: PUSH4 0xa9059cbb + EQ + PUSH2 0x0b + JUMPI + STOP | SLOAD+SSTORE+CALL+STOP
        let hex_str =
            "63a9059cbb1461000b570060005460015573aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf100";
        let bytecode: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
            .collect();
        let lifter = crate::EvmBytecodeLifter::new();
        let program = crate::lift_with(&lifter, &bytecode).expect("lift should succeed");
        eprintln!("dispatcher entries: {}", program.dispatcher.entries.len());
        for e in &program.dispatcher.entries {
            eprintln!(
                "  selector={} target_block={:?} target_offset={:?}",
                e.selector.selector, e.target_block, e.target_offset
            );
        }
        eprintln!("instructions: {}", program.instructions.len());
        eprintln!("cfg blocks: {}", program.cfg.blocks.len());
        assert!(
            !program.dispatcher.entries.is_empty(),
            "lifter should find dispatcher entries"
        );

        // Now recover ops from the lifted program
        let body_graph = recover_evm_body_graph(&program);
        let body_graph = body_graph.expect("should produce body graph");
        assert_eq!(body_graph.bodies.len(), 1);
        let body = &body_graph.bodies[0];
        assert!(!body.operations.is_empty(), "should recover operations");
        eprintln!("recovered ops: {}", body.operations.len());
        for op in &body.operations {
            eprintln!(
                "  op: idx={} kind={:?} target={}",
                op.index, op.kind, op.target
            );
        }
    }
}
