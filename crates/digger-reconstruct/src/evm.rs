//! EVM bytecode lifter (Gen5 A2 + pre-A3 refinements). Implements
//! [`BytecodeLifter`] for the EVM.
//!
//! Raw opcode parsing lives in the PRIVATE `raw` submodule and is never exposed
//! outside this lifter — callers only ever see the canonical Recovered* objects.
//! Scope: opcode decode, instruction recovery, basic blocks, jump-target
//! recovery, CFG, dispatcher, function selectors. NOTHING else (no ABI,
//! storage, proxy, architecture, or SystemIR).
//!
//! Pre-A3 refinements: every emitted node carries a deterministic content
//! addressed id; selectors are structured [`RecoveredSelector`] objects; the
//! dispatcher records the exact deterministic [`RecoveryPattern`]
//! (PUSH4 → EQ → PUSH → JUMPI).

use std::collections::{BTreeMap, BTreeSet};

use crate::confidence::ConfidenceTier;
use crate::digest::digest_str;
use crate::lifter::*;
use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};

mod raw {
    pub(super) const PUSH_MN: [&str; 33] = [
        "PUSH0", "PUSH1", "PUSH2", "PUSH3", "PUSH4", "PUSH5", "PUSH6", "PUSH7", "PUSH8", "PUSH9",
        "PUSH10", "PUSH11", "PUSH12", "PUSH13", "PUSH14", "PUSH15", "PUSH16", "PUSH17", "PUSH18",
        "PUSH19", "PUSH20", "PUSH21", "PUSH22", "PUSH23", "PUSH24", "PUSH25", "PUSH26", "PUSH27",
        "PUSH28", "PUSH29", "PUSH30", "PUSH31", "PUSH32",
    ];
    pub(super) const DUP_MN: [&str; 16] = [
        "DUP1", "DUP2", "DUP3", "DUP4", "DUP5", "DUP6", "DUP7", "DUP8", "DUP9", "DUP10", "DUP11",
        "DUP12", "DUP13", "DUP14", "DUP15", "DUP16",
    ];
    pub(super) const SWAP_MN: [&str; 16] = [
        "SWAP1", "SWAP2", "SWAP3", "SWAP4", "SWAP5", "SWAP6", "SWAP7", "SWAP8", "SWAP9", "SWAP10",
        "SWAP11", "SWAP12", "SWAP13", "SWAP14", "SWAP15", "SWAP16",
    ];
    pub(super) const LOG_MN: [&str; 5] = ["LOG0", "LOG1", "LOG2", "LOG3", "LOG4"];

    pub(super) fn base_mnemonic(op: u8) -> &'static str {
        match op {
            0x00 => "STOP",
            0x01 => "ADD",
            0x02 => "MUL",
            0x03 => "SUB",
            0x04 => "DIV",
            0x05 => "SDIV",
            0x06 => "MOD",
            0x07 => "SMOD",
            0x08 => "ADDMOD",
            0x09 => "MULMOD",
            0x0a => "EXP",
            0x0b => "SIGNEXTEND",
            0x10 => "LT",
            0x11 => "GT",
            0x12 => "SLT",
            0x13 => "SGT",
            0x14 => "EQ",
            0x15 => "ISZERO",
            0x16 => "AND",
            0x17 => "OR",
            0x18 => "XOR",
            0x19 => "NOT",
            0x1a => "BYTE",
            0x1b => "SHL",
            0x1c => "SHR",
            0x1d => "SAR",
            0x20 => "KECCAK256",
            0x30 => "ADDRESS",
            0x31 => "BALANCE",
            0x32 => "ORIGIN",
            0x33 => "CALLER",
            0x34 => "CALLVALUE",
            0x35 => "CALLDATALOAD",
            0x36 => "CALLDATASIZE",
            0x37 => "CALLDATACOPY",
            0x38 => "CODESIZE",
            0x39 => "CODECOPY",
            0x3a => "GASPRICE",
            0x3b => "EXTCODESIZE",
            0x3c => "EXTCODECOPY",
            0x3d => "RETURNDATASIZE",
            0x3e => "RETURNDATACOPY",
            0x3f => "EXTCODEHASH",
            0x40 => "BLOCKHASH",
            0x41 => "COINBASE",
            0x42 => "TIMESTAMP",
            0x43 => "NUMBER",
            0x44 => "PREVRANDAO",
            0x45 => "GASLIMIT",
            0x46 => "CHAINID",
            0x47 => "SELFBALANCE",
            0x48 => "BASEFEE",
            0x50 => "POP",
            0x51 => "MLOAD",
            0x52 => "MSTORE",
            0x53 => "MSTORE8",
            0x54 => "SLOAD",
            0x55 => "SSTORE",
            0x56 => "JUMP",
            0x57 => "JUMPI",
            0x58 => "PC",
            0x59 => "MSIZE",
            0x5a => "GAS",
            0x5b => "JUMPDEST",
            0xf0 => "CREATE",
            0xf1 => "CALL",
            0xf2 => "CALLCODE",
            0xf3 => "RETURN",
            0xf4 => "DELEGATECALL",
            0xf5 => "CREATE2",
            0xfa => "STATICCALL",
            0xfd => "REVERT",
            0xfe => "INVALID",
            0xff => "SELFDESTRUCT",
            _ => "UNKNOWN",
        }
    }

    pub(super) fn mnemonic_and_push(op: u8) -> (&'static str, usize) {
        match op {
            0x5f => ("PUSH0", 0),
            0x60..=0x7f => (PUSH_MN[(op - 0x5f) as usize], (op - 0x5f) as usize),
            0x80..=0x8f => (DUP_MN[(op - 0x80) as usize], 0),
            0x90..=0x9f => (SWAP_MN[(op - 0x90) as usize], 0),
            0xa0..=0xa4 => (LOG_MN[(op - 0xa0) as usize], 0),
            _ => (base_mnemonic(op), 0),
        }
    }

    #[derive(Clone)]
    pub(super) struct RawInsn {
        pub offset: usize,
        pub mnemonic: &'static str,
        pub operand: Vec<u8>,
        pub size: usize,
    }

    impl RawInsn {
        pub(super) fn is_push(&self) -> bool {
            self.mnemonic.starts_with("PUSH") && self.mnemonic != "PUSH0"
        }
        pub(super) fn operand_u64(&self) -> Option<u64> {
            if self.operand.is_empty() {
                return None;
            }
            let mut v: u64 = 0;
            for &b in self.operand.iter() {
                v = (v << 8) | b as u64;
            }
            Some(v)
        }
        pub(super) fn operand_hex(&self) -> Option<String> {
            if self.operand.is_empty() {
                return None;
            }
            let mut s = String::from("0x");
            for b in &self.operand {
                s.push_str(&format!("{:02x}", b));
            }
            Some(s)
        }
    }

    pub(super) fn decode(code: &[u8]) -> Vec<RawInsn> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < code.len() {
            let op = code[i];
            let (mnemonic, push) = mnemonic_and_push(op);
            let mut operand = Vec::new();
            let mut size = 1usize;
            if push > 0 {
                let start = i + 1;
                let end = core::cmp::min(start + push, code.len());
                if start < end {
                    operand.extend_from_slice(&code[start..end]);
                }
                size = 1 + push;
            }
            out.push(RawInsn {
                offset: i,
                mnemonic,
                operand,
                size,
            });
            i += size;
        }
        out
    }
}

const TERMINALS: [&str; 5] = ["STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"];

pub struct EvmBytecodeLifter;

impl EvmBytecodeLifter {
    pub fn new() -> Self {
        EvmBytecodeLifter
    }
}

impl Default for EvmBytecodeLifter {
    fn default() -> Self {
        EvmBytecodeLifter
    }
}

fn prov(stage: ReconstructionStage, input: &str) -> Provenance {
    Provenance::new(
        EvidenceSource::RuntimeBytecode,
        stage,
        ConfidenceTier::Recovered,
        input,
    )
}

fn term_tag(t: &BlockTerminator) -> String {
    format!("{:?}", t)
}

impl BytecodeLifter for EvmBytecodeLifter {
    fn target(&self) -> TargetKind {
        TargetKind::Evm
    }

    fn lift(&self, runtime_bytecode: &[u8]) -> Result<LiftedProgram, LiftError> {
        if runtime_bytecode.is_empty() {
            return Err(LiftError::Empty);
        }
        let code_digest = {
            let mut s = String::from("0x");
            for b in runtime_bytecode {
                s.push_str(&format!("{:02x}", b));
            }
            digest_str(&s)
        };

        let rawv = raw::decode(runtime_bytecode);

        // ---- instruction recovery (Disassemble) ----
        let mut instructions = Vec::with_capacity(rawv.len());
        for ins in &rawv {
            let operand = ins.operand_hex();
            let canon = format!(
                "{}|{}|{}|{}",
                ins.offset,
                ins.mnemonic,
                operand.as_deref().unwrap_or(""),
                ins.size
            );
            instructions.push(RecoveredInstruction {
                id: node_id("insn", &canon),
                offset: ins.offset,
                mnemonic: ins.mnemonic.to_string(),
                operand,
                size: ins.size,
                provenance: prov(
                    ReconstructionStage::Disassemble,
                    &format!("evm:insn:{}:{}", ins.offset, ins.mnemonic),
                ),
            });
        }

        // ---- leaders ----
        let mut leaders: BTreeSet<usize> = BTreeSet::new();
        if let Some(first) = rawv.first() {
            leaders.insert(first.offset);
        }
        for (gi, ins) in rawv.iter().enumerate() {
            if ins.mnemonic == "JUMPDEST" {
                leaders.insert(ins.offset);
            }
            let is_jump = ins.mnemonic == "JUMP" || ins.mnemonic == "JUMPI";
            let is_terminal = TERMINALS.contains(&ins.mnemonic);
            if is_jump || is_terminal {
                if let Some(next) = rawv.get(gi + 1) {
                    leaders.insert(next.offset);
                }
            }
            if is_jump && gi >= 1 {
                let prev = &rawv[gi - 1];
                if prev.is_push() {
                    if let Some(t) = prev.operand_u64() {
                        leaders.insert(t as usize);
                    }
                }
            }
        }
        let valid_offsets: BTreeSet<usize> = rawv.iter().map(|i| i.offset).collect();
        let leaders: BTreeSet<usize> = leaders
            .into_iter()
            .filter(|o| valid_offsets.contains(o))
            .collect();

        // ---- basic blocks (Lift) ----
        struct TmpBlock {
            start: usize,
            idxs: Vec<usize>,
        }
        let mut tmp: Vec<TmpBlock> = Vec::new();
        for (gi, ins) in rawv.iter().enumerate() {
            if tmp.is_empty() || leaders.contains(&ins.offset) {
                tmp.push(TmpBlock {
                    start: ins.offset,
                    idxs: Vec::new(),
                });
            }
            if let Some(last) = tmp.last_mut() {
                last.idxs.push(gi);
            }
        }
        let start_to_index: BTreeMap<usize, usize> =
            tmp.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
        let block_index_of = |off: usize| -> Option<usize> { start_to_index.get(&off).copied() };

        let mut blocks: Vec<RecoveredBasicBlock> = Vec::with_capacity(tmp.len());
        for (index, b) in tmp.iter().enumerate() {
            let last_gi = match b.idxs.last() {
                Some(&g) => g,
                None => continue,
            };
            let last = &rawv[last_gi];
            let end = last.offset + last.size - 1;
            let mn = last.mnemonic;
            let terminator = if mn == "JUMP" {
                let t = if last_gi >= 1 && rawv[last_gi - 1].is_push() {
                    rawv[last_gi - 1].operand_u64().map(|v| v as usize)
                } else {
                    None
                };
                BlockTerminator::Jump { target: t }
            } else if mn == "JUMPI" {
                let t = if last_gi >= 1 && rawv[last_gi - 1].is_push() {
                    rawv[last_gi - 1].operand_u64().map(|v| v as usize)
                } else {
                    None
                };
                BlockTerminator::ConditionalJump { target: t }
            } else if mn == "STOP" {
                BlockTerminator::Stop
            } else if mn == "RETURN" {
                BlockTerminator::Return
            } else if mn == "REVERT" {
                BlockTerminator::Revert
            } else if mn == "INVALID" {
                BlockTerminator::Invalid
            } else if mn == "SELFDESTRUCT" {
                BlockTerminator::SelfDestruct
            } else {
                BlockTerminator::FallThrough
            };

            let offsets: Vec<usize> = b.idxs.iter().map(|&gi| rawv[gi].offset).collect();
            let canon = format!(
                "{}|{}|{}|{}",
                b.start,
                end,
                term_tag(&terminator),
                offsets
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            blocks.push(RecoveredBasicBlock {
                id: node_id("bb", &canon),
                index,
                start: b.start,
                end,
                instruction_offsets: offsets,
                terminator,
                provenance: prov(
                    ReconstructionStage::Lift,
                    &format!("evm:bb:{}:{}", b.start, end),
                ),
            });
        }
        let block_ids: Vec<String> = blocks.iter().map(|b| b.id.clone()).collect();

        // ---- CFG edges (Lift) ----
        let mut edges: Vec<CfgEdge> = Vec::new();
        for idx in 0..blocks.len() {
            let next_start = blocks.get(idx + 1).map(|b| b.start);
            let from_id = block_ids[idx].clone();
            match blocks[idx].terminator.clone() {
                BlockTerminator::Jump { target: Some(t) } => {
                    if let Some(tb) = block_index_of(t) {
                        edges.push(CfgEdge {
                            from: idx,
                            to: tb,
                            from_id: from_id.clone(),
                            to_id: block_ids[tb].clone(),
                            kind: EdgeKind::Jump,
                        });
                    }
                }
                BlockTerminator::Jump { target: None } => {}
                BlockTerminator::ConditionalJump { target } => {
                    if let Some(t) = target {
                        if let Some(tb) = block_index_of(t) {
                            edges.push(CfgEdge {
                                from: idx,
                                to: tb,
                                from_id: from_id.clone(),
                                to_id: block_ids[tb].clone(),
                                kind: EdgeKind::BranchTaken,
                            });
                        }
                    }
                    if let Some(ns) = next_start {
                        if let Some(nb) = block_index_of(ns) {
                            edges.push(CfgEdge {
                                from: idx,
                                to: nb,
                                from_id: from_id.clone(),
                                to_id: block_ids[nb].clone(),
                                kind: EdgeKind::BranchNotTaken,
                            });
                        }
                    }
                }
                BlockTerminator::FallThrough => {
                    if let Some(ns) = next_start {
                        if let Some(nb) = block_index_of(ns) {
                            edges.push(CfgEdge {
                                from: idx,
                                to: nb,
                                from_id: from_id.clone(),
                                to_id: block_ids[nb].clone(),
                                kind: EdgeKind::FallThrough,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        // ---- dispatcher + selectors (Recover) ----
        let pattern = RecoveryPattern::new(
            "evm.dispatcher.push4_eq_push_jumpi",
            &["PUSH4", "EQ", "PUSH", "JUMPI"],
        );
        let mut entries: Vec<DispatchEntry> = Vec::new();
        let mut seen_selectors: BTreeSet<String> = BTreeSet::new();
        for i in 0..rawv.len() {
            if rawv[i].mnemonic != "PUSH4" {
                continue;
            }
            let sel_hex = match rawv[i].operand_hex() {
                Some(s) => s,
                None => continue,
            };
            let mut j = i + 1;
            let mut steps = 0;
            let mut eq = None;
            while j < rawv.len() && steps < 4 {
                if rawv[j].mnemonic == "EQ" {
                    eq = Some(j);
                    break;
                }
                j += 1;
                steps += 1;
            }
            let eqj = match eq {
                Some(x) => x,
                None => continue,
            };
            let mut p = eqj + 1;
            let mut s2 = 0;
            let mut destp = None;
            while p < rawv.len() && s2 < 3 {
                if rawv[p].is_push() {
                    destp = Some(p);
                    break;
                }
                p += 1;
                s2 += 1;
            }
            let destp = match destp {
                Some(x) => x,
                None => continue,
            };
            let mut q = destp + 1;
            let mut s3 = 0;
            let mut jumpi = false;
            while q < rawv.len() && s3 < 2 {
                if rawv[q].mnemonic == "JUMPI" {
                    jumpi = true;
                    break;
                }
                q += 1;
                s3 += 1;
            }
            if !jumpi {
                continue;
            }
            let target_offset = rawv[destp].operand_u64().map(|v| v as usize);
            let target_block = target_offset.and_then(block_index_of);
            let target_block_id = target_block.map(|ix| block_ids[ix].clone());
            if seen_selectors.insert(sel_hex.clone()) {
                let selector = RecoveredSelector {
                    id: node_id("sel", &sel_hex),
                    selector: sel_hex.clone(),
                    bytes: rawv[i].operand.clone(),
                    provenance: prov(
                        ReconstructionStage::Recover,
                        &format!("evm:selector:{}", sel_hex),
                    ),
                };
                let entry_canon = format!("{}|{:?}|{:?}", sel_hex, target_offset, target_block_id);
                entries.push(DispatchEntry {
                    id: node_id("dispatch", &entry_canon),
                    selector,
                    target_offset,
                    target_block,
                    target_block_id,
                    pattern: pattern.clone(),
                    provenance: prov(
                        ReconstructionStage::Recover,
                        &format!("evm:dispatch:{}", sel_hex),
                    )
                    .with_basis("PUSH4,EQ,PUSH,JUMPI"),
                });
            }
        }
        entries.sort_by(|a, b| a.selector.selector.cmp(&b.selector.selector));

        let has_fallback = rawv.iter().any(|i| i.mnemonic == "REVERT");
        let dispatcher = RecoveredDispatcher {
            id: node_id("dispatcher", &format!("{}|{}", code_digest, has_fallback)),
            entries: entries.clone(),
            has_fallback,
            pattern: pattern.clone(),
            provenance: prov(
                ReconstructionStage::Recover,
                &format!("evm:dispatcher:{}", code_digest),
            ),
        };

        let mut sel_objs: Vec<RecoveredSelector> =
            entries.iter().map(|e| e.selector.clone()).collect();
        sel_objs.sort_by(|a, b| a.selector.cmp(&b.selector));
        sel_objs.dedup_by(|a, b| a.selector == b.selector);
        let selset_canon = sel_objs
            .iter()
            .map(|s| s.selector.clone())
            .collect::<Vec<_>>()
            .join(",");
        let selector_set = RecoveredSelectorSet {
            id: node_id("selset", &selset_canon),
            selectors: sel_objs,
            provenance: prov(
                ReconstructionStage::Recover,
                &format!("evm:selectors:{}", selset_canon),
            ),
        };

        // ---- CFG (consumes blocks + edges) ----
        let cfg_canon = format!(
            "{}|{}|{}",
            0usize,
            block_ids.join(","),
            edges
                .iter()
                .map(|e| format!("{}-{}:{:?}", e.from_id, e.to_id, e.kind))
                .collect::<Vec<_>>()
                .join(",")
        );
        let cfg = RecoveredCFG {
            id: node_id("cfg", &cfg_canon),
            entry: 0,
            blocks,
            edges,
            provenance: prov(
                ReconstructionStage::Lift,
                &format!("evm:cfg:{}", code_digest),
            ),
        };

        Ok(LiftedProgram {
            id: node_id("program", &format!("{:?}|{}", TargetKind::Evm, code_digest)),
            target: TargetKind::Evm,
            instructions,
            cfg,
            dispatcher,
            selectors: selector_set,
            provenance: prov(
                ReconstructionStage::Lift,
                &format!("evm:program:{}", code_digest),
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ReconstructionEngine;

    const SAMPLE: &[u8] = &[
        0x80, 0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x14, 0x61, 0x00, 0x1a, 0x57, 0x80, 0x63, 0x70, 0xa0,
        0x82, 0x31, 0x14, 0x61, 0x00, 0x1f, 0x57, 0x60, 0x00, 0x80, 0xfd, 0x5b, 0x60, 0x01, 0x60,
        0x00, 0x5b, 0x00,
    ];

    #[test]
    fn empty_is_error() {
        assert_eq!(EvmBytecodeLifter::new().lift(&[]), Err(LiftError::Empty));
    }

    #[test]
    fn full_pipeline_recovery() {
        let lifter = EvmBytecodeLifter::new();
        let eng = ReconstructionEngine::new(&lifter);
        let p = eng.lift(SAMPLE).unwrap();
        assert_eq!(p.target, TargetKind::Evm);
        assert_eq!(p.instructions.len(), 18);
        assert_eq!(p.instructions[1].mnemonic, "PUSH4");
        assert_eq!(p.instructions[1].operand.as_deref(), Some("0xa9059cbb"));
        let sels: Vec<String> = p
            .selectors
            .selectors
            .iter()
            .map(|s| s.selector.clone())
            .collect();
        assert_eq!(
            sels,
            vec!["0x70a08231".to_string(), "0xa9059cbb".to_string()]
        );
        assert_eq!(p.dispatcher.entries.len(), 2);
        assert!(p.dispatcher.has_fallback);
        assert_eq!(
            p.dispatcher.pattern.steps,
            vec!["PUSH4", "EQ", "PUSH", "JUMPI"]
        );
        assert!(p
            .dispatcher
            .entries
            .iter()
            .all(|e| e.target_block_id.is_some()));
        assert!(p
            .dispatcher
            .entries
            .iter()
            .all(|e| e.pattern.steps.len() == 4));
        assert_eq!(p.cfg.blocks.len(), 5);
        assert!(!p.cfg.edges.is_empty());
        // deterministic content-addressed ids (never vector indices)
        assert!(p.id.starts_with("program:"));
        assert!(p.cfg.id.starts_with("cfg:"));
        assert!(p.dispatcher.id.starts_with("dispatcher:"));
        assert!(p.instructions.iter().all(|i| i.id.starts_with("insn:")));
        assert!(p.cfg.blocks.iter().all(|b| b.id.starts_with("bb:")));
        assert!(p
            .selectors
            .selectors
            .iter()
            .all(|s| s.id.starts_with("sel:")));
        assert!(p
            .cfg
            .edges
            .iter()
            .all(|e| !e.from_id.is_empty() && !e.to_id.is_empty()));
        // selector objects carry their raw 4 bytes
        assert!(p.selectors.selectors.iter().all(|s| s.bytes.len() == 4));
    }

    #[test]
    fn deterministic_ids() {
        let l = EvmBytecodeLifter::new();
        let a = l.lift(SAMPLE).unwrap();
        let b = l.lift(SAMPLE).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.cfg.blocks[0].id, b.cfg.blocks[0].id);
    }
}

// >>> A3.1 EVM INTERFACE RECOVERY (generated) >>>

use crate::interface::{
    InterfaceDetail, InterfaceKind, InterfaceRecoverer, ParameterLayout, RecoveredAbi,
    RecoveredFunction, RecoveredInterface, ReturnLayout,
};

/// Recovers a chain-agnostic [`RecoveredInterface`] (EVM variant
/// [`RecoveredAbi`]) from a lifted EVM program. DETERMINISTIC and name-free: it
/// observes selectors plus the calldata word slots and return-word counts
/// syntactically present in the recovered instruction stream. It never inverts
/// a selector to a name and never infers parameter/return *types*.
pub struct EvmInterfaceRecoverer;

impl EvmInterfaceRecoverer {
    pub fn new() -> Self {
        EvmInterfaceRecoverer
    }
}
impl Default for EvmInterfaceRecoverer {
    fn default() -> Self {
        EvmInterfaceRecoverer
    }
}

fn iface_prov(input: &str) -> Provenance {
    Provenance::new(
        EvidenceSource::Selectors,
        ReconstructionStage::Recover,
        ConfidenceTier::Recovered,
        input,
    )
}

/// Forward-reachable block ordinals from `entry` over CFG edges (deterministic).
pub(crate) fn reachable_blocks(program: &LiftedProgram, entry: usize) -> Vec<usize> {
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut stack = vec![entry];
    while let Some(b) = stack.pop() {
        if !seen.insert(b) {
            continue;
        }
        for e in &program.cfg.edges {
            if e.from == b && !seen.contains(&e.to) {
                stack.push(e.to);
            }
        }
    }
    seen.into_iter().collect()
}

/// Instructions (ascending by offset) belonging to the given block ordinals.
pub(crate) fn instructions_in<'a>(
    program: &'a LiftedProgram,
    blocks: &[usize],
) -> Vec<&'a RecoveredInstruction> {
    let mut offsets: BTreeSet<usize> = BTreeSet::new();
    for &b in blocks {
        if let Some(blk) = program.cfg.blocks.iter().find(|x| x.index == b) {
            for &o in &blk.instruction_offsets {
                offsets.insert(o);
            }
        }
    }
    let mut out: Vec<&RecoveredInstruction> = program
        .instructions
        .iter()
        .filter(|i| offsets.contains(&i.offset))
        .collect();
    out.sort_by_key(|i| i.offset);
    out
}

fn parse_const(operand: &Option<String>) -> Option<u64> {
    let s = operand.as_ref()?;
    let h = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(h, 16).ok()
}

/// Distinct calldata word slots observed via `PUSH (4 + 32k)` + `CALLDATALOAD`.
fn observe_params(insns: &[&RecoveredInstruction]) -> Vec<usize> {
    let mut slots: BTreeSet<usize> = BTreeSet::new();
    for w in insns.windows(2) {
        let (prev, cur) = (w[0], w[1]);
        if cur.mnemonic == "CALLDATALOAD" && prev.mnemonic.starts_with("PUSH") {
            if let Some(c) = parse_const(&prev.operand) {
                if c >= 4 && (c - 4) % 32 == 0 {
                    slots.insert(((c - 4) / 32) as usize);
                }
            }
        }
    }
    slots.into_iter().collect()
}

/// Return word count from an immediate `PUSH <len> PUSH <off> RETURN` pattern.
fn observe_returns(insns: &[&RecoveredInstruction]) -> Option<usize> {
    for w in insns.windows(3) {
        if w[2].mnemonic == "RETURN"
            && w[1].mnemonic.starts_with("PUSH")
            && w[0].mnemonic.starts_with("PUSH")
        {
            if let Some(len) = parse_const(&w[0].operand) {
                if len % 32 == 0 {
                    return Some((len / 32) as usize);
                }
            }
        }
    }
    None
}

impl InterfaceRecoverer for EvmInterfaceRecoverer {
    fn target(&self) -> TargetKind {
        TargetKind::Evm
    }

    fn recover_interface(&self, program: &LiftedProgram) -> RecoveredInterface {
        let mut functions: Vec<RecoveredFunction> = Vec::new();
        for entry in &program.dispatcher.entries {
            let (params, rets) = match entry.target_block {
                Some(b) => {
                    let blocks = reachable_blocks(program, b);
                    let insns = instructions_in(program, &blocks);
                    (observe_params(&insns), observe_returns(&insns))
                }
                None => (Vec::new(), None),
            };
            let sel = entry.selector.clone();
            let p_canon = format!("{}|params|{:?}", sel.selector, params);
            let r_canon = format!("{}|returns|{:?}", sel.selector, rets);
            let parameters = ParameterLayout {
                observed_word_slots: params,
                provenance: iface_prov(&p_canon),
            };
            let returns = ReturnLayout {
                observed_return_words: rets,
                provenance: iface_prov(&r_canon),
            };
            let fn_canon = format!(
                "{}|{:?}|{:?}",
                sel.selector, parameters.observed_word_slots, returns.observed_return_words
            );
            functions.push(RecoveredFunction {
                id: node_id("fn", &fn_canon),
                selector: sel,
                parameters,
                returns,
                provenance: iface_prov(&fn_canon),
            });
        }
        functions.sort_by(|a, b| a.selector.selector.cmp(&b.selector.selector));
        let abi_canon: String = functions
            .iter()
            .map(|f| f.id.clone())
            .collect::<Vec<_>>()
            .join(",");
        let abi = RecoveredAbi {
            id: node_id("abi", &abi_canon),
            functions,
            provenance: iface_prov(&format!("abi|{}", abi_canon)),
        };
        let iface_canon = format!("evm|{}|{}", program.id, abi.id);
        RecoveredInterface {
            id: RecoveredInterface::make_id(&iface_canon),
            kind: InterfaceKind::Evm,
            detail: InterfaceDetail::Evm(abi),
            provenance: iface_prov(&iface_canon),
        }
    }
}

#[cfg(test)]
mod a3_iface_tests {
    use super::*;
    use crate::interface::*;
    const SAMPLE: [u8; 33] = [
        0x80, 0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x14, 0x61, 0x00, 0x1a, 0x57, 0x80, 0x63, 0x70, 0xa0,
        0x82, 0x31, 0x14, 0x61, 0x00, 0x1f, 0x57, 0x60, 0x00, 0x80, 0xfd, 0x5b, 0x60, 0x01, 0x60,
        0x00, 0x5b, 0x00,
    ];
    #[test]
    fn recovers_evm_abi_without_names() {
        let program = EvmBytecodeLifter::new().lift(&SAMPLE).unwrap();
        let iface = EvmInterfaceRecoverer::new().recover_interface(&program);
        assert_eq!(iface.kind, InterfaceKind::Evm);
        assert!(iface.id.starts_with("iface:"));
        let abi = match &iface.detail {
            InterfaceDetail::Evm(a) => a,
            _ => panic!("expected evm abi"),
        };
        assert_eq!(abi.functions.len(), 2);
        let sels: Vec<String> = abi
            .functions
            .iter()
            .map(|f| f.selector.selector.clone())
            .collect();
        assert_eq!(
            sels,
            vec!["0x70a08231".to_string(), "0xa9059cbb".to_string()]
        );
        for f in &abi.functions {
            assert!(f.parameters.observed_word_slots.is_empty());
            assert_eq!(f.returns.observed_return_words, None);
            assert!(f.id.starts_with("fn:"));
        }
    }
    #[test]
    fn interface_recovery_is_deterministic() {
        let p = EvmBytecodeLifter::new().lift(&SAMPLE).unwrap();
        let r = EvmInterfaceRecoverer::new();
        assert_eq!(r.recover_interface(&p), r.recover_interface(&p));
    }
    #[test]
    fn observes_calldata_and_return_words_deterministically() {
        fn insn(mn: &str, op: Option<&str>) -> RecoveredInstruction {
            RecoveredInstruction {
                id: node_id("insn", &format!("{}|{:?}", mn, op)),
                offset: 0,
                mnemonic: mn.to_string(),
                operand: op.map(|s| s.to_string()),
                size: 1,
                provenance: iface_prov("t"),
            }
        }
        let p1 = insn("PUSH1", Some("0x04"));
        let c1 = insn("CALLDATALOAD", None);
        let p2 = insn("PUSH1", Some("0x24"));
        let c2 = insn("CALLDATALOAD", None);
        let v: Vec<&RecoveredInstruction> = vec![&p1, &c1, &p2, &c2];
        assert_eq!(observe_params(&v), vec![0usize, 1usize]);
        let l = insn("PUSH1", Some("0x40"));
        let o = insn("PUSH1", Some("0x00"));
        let r = insn("RETURN", None);
        let rv: Vec<&RecoveredInstruction> = vec![&l, &o, &r];
        assert_eq!(observe_returns(&rv), Some(2));
    }
}

// <<< A3.1 EVM INTERFACE RECOVERY (generated) <<<

// >>> A3.2 EVM DEPLOYMENT & UPGRADE RECOVERY (generated) >>>
pub use self::a3_2_deploy::EvmDeploymentRecoverer;

/// Deterministic EVM deployment & upgrade recovery (A3.2). Isolated in a
/// submodule so its imports never collide with the rest of `evm`.
mod a3_2_deploy {
    use crate::confidence::ConfidenceTier;
    use crate::deployment::*;
    use crate::digest::fnv1a_64;
    use crate::evidence_requirement::EvidenceRequirement;
    use crate::lifter::{node_id, TargetKind};
    use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};
    use crate::MAX_PROXY_DEPTH;

    // ---- Well-known deterministic constants (public standards) ----
    // EIP-1967 slots.
    const EIP1967_IMPL_SLOT: &str =
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
    const EIP1967_ADMIN_SLOT: &str =
        "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
    const EIP1967_BEACON_SLOT: &str =
        "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
    // UUPS upgrade selectors.
    const SEL_UPGRADE_TO: u32 = 0x3659cfe6; // upgradeTo(address)
    const SEL_UPGRADE_TO_AND_CALL: u32 = 0x4f1ef286; // upgradeToAndCall(address,bytes)
                                                     // Diamond (EIP-2535) loupe selectors.
    const LOUPE: [(u32, &str); 4] = [
        (0x7a0ed627, "0x7a0ed627"), // facets()
        (0xadfca15e, "0xadfca15e"), // facetFunctionSelectors(address)
        (0x52ef6b2c, "0x52ef6b2c"), // facetAddresses()
        (0xcdffacc6, "0xcdffacc6"), // facetAddress(bytes4)
    ];
    // EIP-1167 minimal-proxy runtime pattern: prefix + 20-byte addr + suffix.
    const MP_PREFIX: [u8; 10] = [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
    const MP_SUFFIX: [u8; 15] = [
        0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3,
    ];

    fn hx(b: &[u8]) -> String {
        let mut s = String::from("0x");
        for x in b {
            s.push_str(&format!("{:02x}", x));
        }
        s
    }

    fn parse_hex(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0))
            .collect()
    }

    /// Walk opcodes, returning every PUSH (opcode, immediate bytes), respecting
    /// push immediate sizes so data bytes are never misread as opcodes.
    fn scan_pushes(code: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < code.len() {
            let op = code[i];
            if (0x60..=0x7f).contains(&op) {
                let sz = (op - 0x60 + 1) as usize;
                let start = i + 1;
                let end = (start + sz).min(code.len());
                out.push((op, code[start..end].to_vec()));
                i = end;
            } else {
                i += 1;
            }
        }
        out
    }

    /// Detect an EIP-1167 minimal proxy and return its embedded implementation.
    fn detect_minimal_proxy(code: &[u8]) -> Option<String> {
        if code.len() < 45 {
            return None;
        }
        let mut i = 0;
        while i + 45 <= code.len() {
            if code[i..i + 10] == MP_PREFIX && code[i + 30..i + 45] == MP_SUFFIX {
                return Some(hx(&code[i + 10..i + 30]));
            }
            i += 1;
        }
        None
    }

    /// Resolve an address from a 32-byte storage word (low 20 bytes) if present.
    fn resolve_slot(storage: &StorageEvidence, slot: &str) -> RecoveredAddress {
        match storage.get(slot) {
            Some(word) => {
                let b = parse_hex(word);
                if b.len() >= 20 {
                    RecoveredAddress::Resolved(hx(&b[b.len() - 20..]))
                } else {
                    RecoveredAddress::unresolved(vec![EvidenceRequirement::NeedsStorage(
                        slot.to_string(),
                    )])
                }
            }
            None => RecoveredAddress::unresolved(vec![EvidenceRequirement::NeedsStorage(
                slot.to_string(),
            )]),
        }
    }

    fn mechanism_for(f: ProxyFamily) -> &'static str {
        match f {
            ProxyFamily::Eip1967 => "eip1967.implementation_slot",
            ProxyFamily::Transparent => "transparent.admin_slot",
            ProxyFamily::Uups => "uups.upgradeTo",
            ProxyFamily::Beacon => "eip1967.beacon_slot",
            ProxyFamily::Diamond => "diamond.diamondCut",
            ProxyFamily::MinimalProxy => "minimal.immutable_clone",
        }
    }

    /// Deterministic EVM deployment recoverer. Recovers proxy TOPOLOGY (not mere
    /// presence): families, implementation chain, upgrade authority, upgrade
    /// path, relationships, and reproducible metadata. Fully functional offline
    /// (addresses become `Unresolved`, recording the evidence that would resolve
    /// them). Storage is evidence only -- never privileged truth.
    pub struct EvmDeploymentRecoverer;

    impl EvmDeploymentRecoverer {
        pub fn new() -> Self {
            EvmDeploymentRecoverer
        }
    }
    impl Default for EvmDeploymentRecoverer {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DeploymentRecoverer for EvmDeploymentRecoverer {
        fn target(&self) -> TargetKind {
            TargetKind::Evm
        }

        fn recover_deployment(
            &self,
            runtime_bytecode: &[u8],
            storage: &StorageEvidence,
        ) -> RecoveredDeployment {
            let code = runtime_bytecode;
            let code_hex = hx(code);
            let prov = |ev: EvidenceSource, tier: ConfidenceTier| {
                Provenance::new(ev, ReconstructionStage::Recover, tier, &code_hex)
            };

            let pushes = scan_pushes(code);
            let has_push32 = |slot: &str| {
                let b = parse_hex(slot);
                pushes
                    .iter()
                    .any(|(op, imm)| *op == 0x7f && imm[..] == b[..])
            };
            let has_sel = |sel: u32| {
                let b = sel.to_be_bytes();
                pushes
                    .iter()
                    .any(|(op, imm)| *op == 0x63 && imm[..] == b[..])
            };

            let mut proxies: Vec<RecoveredProxy> = Vec::new();

            // 1) Minimal proxy (fully offline -- implementation embedded in code).
            if let Some(addr) = detect_minimal_proxy(code) {
                proxies.push(RecoveredProxy {
                    id: node_id("proxy", &format!("minimal|{}", addr)),
                    family: ProxyFamily::MinimalProxy,
                    detected_via: DetectionMethod::BytecodePattern,
                    implementation_slot: None,
                    admin_slot: None,
                    beacon_slot: None,
                    implementation: RecoveredAddress::Resolved(addr),
                    facet_selectors: Vec::new(),
                    provenance: prov(EvidenceSource::ProxyInfo, ConfidenceTier::Recovered),
                });
            }

            // 2) Diamond (loupe selectors present).
            let mut facet_selectors: Vec<String> = LOUPE
                .iter()
                .filter(|(s, _)| has_sel(*s))
                .map(|(_, h)| h.to_string())
                .collect();
            facet_selectors.sort();
            if !facet_selectors.is_empty() {
                proxies.push(RecoveredProxy {
                    id: node_id("proxy", &format!("diamond|{}", facet_selectors.join(","))),
                    family: ProxyFamily::Diamond,
                    detected_via: DetectionMethod::SelectorPresence,
                    implementation_slot: None,
                    admin_slot: None,
                    beacon_slot: None,
                    implementation: RecoveredAddress::unresolved(vec![
                        EvidenceRequirement::NeedsExplorerArtifact,
                        EvidenceRequirement::NeedsStorage(
                            "diamond facet storage (DiamondStorage / loupe)".to_string(),
                        ),
                    ]),
                    facet_selectors,
                    provenance: prov(EvidenceSource::ProxyInfo, ConfidenceTier::Recovered),
                });
            }

            // 3) Beacon (EIP-1967 beacon slot present).
            if has_push32(EIP1967_BEACON_SLOT) {
                proxies.push(RecoveredProxy {
                    id: node_id("proxy", "beacon"),
                    family: ProxyFamily::Beacon,
                    detected_via: DetectionMethod::StorageSlot,
                    implementation_slot: None,
                    admin_slot: None,
                    beacon_slot: Some(EIP1967_BEACON_SLOT.to_string()),
                    implementation: resolve_slot(storage, EIP1967_BEACON_SLOT),
                    facet_selectors: Vec::new(),
                    provenance: prov(EvidenceSource::ProxyInfo, ConfidenceTier::Recovered),
                });
            }

            // 4) EIP-1967 family (impl slot) -> refine UUPS / Transparent / generic.
            if has_push32(EIP1967_IMPL_SLOT) {
                let has_admin = has_push32(EIP1967_ADMIN_SLOT);
                let is_uups = has_sel(SEL_UPGRADE_TO) || has_sel(SEL_UPGRADE_TO_AND_CALL);
                let family = if is_uups {
                    ProxyFamily::Uups
                } else if has_admin {
                    ProxyFamily::Transparent
                } else {
                    ProxyFamily::Eip1967
                };
                proxies.push(RecoveredProxy {
                    id: node_id("proxy", &format!("{:?}", family)),
                    family,
                    detected_via: DetectionMethod::StorageSlot,
                    implementation_slot: Some(EIP1967_IMPL_SLOT.to_string()),
                    admin_slot: if has_admin {
                        Some(EIP1967_ADMIN_SLOT.to_string())
                    } else {
                        None
                    },
                    beacon_slot: None,
                    implementation: resolve_slot(storage, EIP1967_IMPL_SLOT),
                    facet_selectors: Vec::new(),
                    provenance: prov(EvidenceSource::ProxyInfo, ConfidenceTier::Recovered),
                });
            }

            // Deterministic ordering + de-dup.
            proxies.sort_by(|a, b| (a.family, &a.id).cmp(&(b.family, &b.id)));
            proxies.dedup_by(|a, b| a.id == b.id);

            // Implementation chain + upgrade path + relationships (bounded).
            let mut implementation_chain: Vec<ImplementationHop> = Vec::new();
            let mut upgrade_path: Vec<UpgradeStep> = Vec::new();
            let mut relationships: Vec<DeploymentRelationship> = Vec::new();
            let mut truncated = false;
            for (idx, px) in proxies.iter().enumerate() {
                if idx as u8 >= MAX_PROXY_DEPTH {
                    truncated = true;
                    break;
                }
                implementation_chain.push(ImplementationHop {
                    depth: idx as u8,
                    family: px.family,
                    address: px.implementation.clone(),
                });
                if px.family != ProxyFamily::MinimalProxy {
                    upgrade_path.push(UpgradeStep {
                        family: px.family,
                        mechanism: mechanism_for(px.family).to_string(),
                    });
                }
                if let RecoveredAddress::Resolved(addr) = &px.implementation {
                    relationships.push(DeploymentRelationship {
                        from: px.id.clone(),
                        to: format!("addr:{}", addr),
                        kind: RelationshipKind::DelegatesTo,
                    });
                }
                if px.family == ProxyFamily::Beacon {
                    relationships.push(DeploymentRelationship {
                        from: px.id.clone(),
                        to: EIP1967_BEACON_SLOT.to_string(),
                        kind: RelationshipKind::PointsToBeacon,
                    });
                }
                for fs in &px.facet_selectors {
                    relationships.push(DeploymentRelationship {
                        from: px.id.clone(),
                        to: format!("selector:{}", fs),
                        kind: RelationshipKind::HasFacet,
                    });
                }
            }

            // Upgrade authority from the first upgradeable (non-minimal) proxy.
            let upgrade_authority = proxies
                .iter()
                .find(|p| p.family != ProxyFamily::MinimalProxy)
                .map(|p| {
                    let (kind, address) = match p.family {
                        ProxyFamily::Transparent => (
                            AuthorityKind::ProxyAdmin,
                            resolve_slot(storage, EIP1967_ADMIN_SLOT),
                        ),
                        ProxyFamily::Beacon => (
                            AuthorityKind::BeaconOwner,
                            RecoveredAddress::unresolved(vec![EvidenceRequirement::NeedsRpc(
                                "beacon.owner()".to_string(),
                            )]),
                        ),
                        ProxyFamily::Diamond => (
                            AuthorityKind::DiamondOwner,
                            RecoveredAddress::unresolved(vec![EvidenceRequirement::NeedsStorage(
                                "diamond owner storage".to_string(),
                            )]),
                        ),
                        _ => (
                            AuthorityKind::UpgradeAuthority,
                            RecoveredAddress::unresolved(vec![EvidenceRequirement::NeedsRpc(
                                "uups implementation owner()".to_string(),
                            )]),
                        ),
                    };
                    RecoveredAuthority {
                        id: node_id("auth", &format!("{:?}", kind)),
                        kind,
                        address,
                        provenance: prov(EvidenceSource::ProxyInfo, ConfidenceTier::Recovered),
                    }
                });
            if let Some(a) = &upgrade_authority {
                if let Some(p0) = proxies
                    .iter()
                    .find(|p| p.family != ProxyFamily::MinimalProxy)
                {
                    relationships.push(DeploymentRelationship {
                        from: p0.id.clone(),
                        to: a.id.clone(),
                        kind: RelationshipKind::AdministeredBy,
                    });
                }
            }

            let metadata = DeploymentMetadata {
                runtime_code_len: code.len(),
                runtime_code_digest: fnv1a_64(code),
            };

            let evm_canon = format!(
                "{}|{}|{}",
                code_hex,
                proxies.len(),
                implementation_chain.len()
            );
            let evm = EvmDeployment {
                id: node_id("evmdeploy", &evm_canon),
                proxies,
                implementation_chain,
                upgrade_authority,
                upgrade_path,
                relationships,
                metadata,
                truncated_at_max_depth: truncated,
                provenance: prov(EvidenceSource::ProxyInfo, ConfidenceTier::Recovered),
            };
            RecoveredDeployment {
                id: RecoveredDeployment::make_id(&evm.id),
                kind: DeploymentKind::Evm,
                detail: DeploymentDetail::Evm(evm),
                provenance: prov(EvidenceSource::ProxyInfo, ConfidenceTier::Recovered),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::fact::RecoveredFact;

        fn impl_or_panic(d: &RecoveredDeployment) -> &EvmDeployment {
            match &d.detail {
                DeploymentDetail::Evm(e) => e,
                _ => panic!("expected EVM deployment"),
            }
        }

        #[test]
        fn minimal_proxy_resolves_offline() {
            let addr = [0x42u8; 20];
            let mut code = Vec::new();
            code.extend_from_slice(&MP_PREFIX);
            code.extend_from_slice(&addr);
            code.extend_from_slice(&MP_SUFFIX);
            let d =
                EvmDeploymentRecoverer::new().recover_deployment(&code, &StorageEvidence::empty());
            let e = impl_or_panic(&d);
            assert_eq!(e.proxies.len(), 1);
            assert_eq!(e.proxies[0].family, ProxyFamily::MinimalProxy);
            assert_eq!(e.proxies[0].detected_via, DetectionMethod::BytecodePattern);
            assert_eq!(
                e.proxies[0].implementation,
                RecoveredAddress::Resolved(format!("0x{}", "42".repeat(20)))
            );
            // Minimal proxies are immutable: no upgrade path.
            assert!(e.upgrade_path.is_empty());
            assert!(e.proxies[0].fact_id().starts_with("proxy:"));
        }

        #[test]
        fn uups_detected_unresolved_offline_then_resolved_with_storage() {
            let slot = parse_hex(EIP1967_IMPL_SLOT);
            let mut code = vec![0x7f];
            code.extend_from_slice(&slot);
            code.push(0x63);
            code.extend_from_slice(&SEL_UPGRADE_TO.to_be_bytes());
            // Offline: detected as UUPS, implementation Unresolved.
            let d0 =
                EvmDeploymentRecoverer::new().recover_deployment(&code, &StorageEvidence::empty());
            let e0 = impl_or_panic(&d0);
            assert_eq!(e0.proxies.len(), 1);
            assert_eq!(e0.proxies[0].family, ProxyFamily::Uups);
            assert!(!e0.proxies[0].implementation.is_resolved());
            assert_eq!(e0.upgrade_path.len(), 1);
            assert_eq!(e0.upgrade_path[0].mechanism, "uups.upgradeTo");
            // With storage evidence: implementation resolves deterministically.
            let mut word = vec![0u8; 12];
            word.extend_from_slice(&[0x11u8; 20]);
            let storage = StorageEvidence::empty().with_slot(EIP1967_IMPL_SLOT, hx(&word));
            let d1 = EvmDeploymentRecoverer::new().recover_deployment(&code, &storage);
            let e1 = impl_or_panic(&d1);
            assert_eq!(
                e1.proxies[0].implementation,
                RecoveredAddress::Resolved(format!("0x{}", "11".repeat(20)))
            );
        }

        #[test]
        fn transparent_has_admin_authority() {
            let impl_slot = parse_hex(EIP1967_IMPL_SLOT);
            let admin_slot = parse_hex(EIP1967_ADMIN_SLOT);
            let mut code = vec![0x7f];
            code.extend_from_slice(&impl_slot);
            code.push(0x7f);
            code.extend_from_slice(&admin_slot);
            let d =
                EvmDeploymentRecoverer::new().recover_deployment(&code, &StorageEvidence::empty());
            let e = impl_or_panic(&d);
            assert_eq!(e.proxies[0].family, ProxyFamily::Transparent);
            assert!(e.proxies[0].admin_slot.is_some());
            let auth = e.upgrade_authority.as_ref().expect("authority");
            assert_eq!(auth.kind, AuthorityKind::ProxyAdmin);
        }

        #[test]
        fn deterministic_same_input_same_ids() {
            let addr = [0x42u8; 20];
            let mut code = Vec::new();
            code.extend_from_slice(&MP_PREFIX);
            code.extend_from_slice(&addr);
            code.extend_from_slice(&MP_SUFFIX);
            let a =
                EvmDeploymentRecoverer::new().recover_deployment(&code, &StorageEvidence::empty());
            let b =
                EvmDeploymentRecoverer::new().recover_deployment(&code, &StorageEvidence::empty());
            assert_eq!(a, b);
        }

        #[test]
        fn non_proxy_code_is_a_direct_deployment_fact() {
            let code = vec![0x60, 0x00, 0x60, 0x00, 0xfd];
            let d =
                EvmDeploymentRecoverer::new().recover_deployment(&code, &StorageEvidence::empty());
            let e = impl_or_panic(&d);
            assert!(e.proxies.is_empty());
            assert!(e.upgrade_authority.is_none());
            assert_eq!(e.metadata.runtime_code_len, 5);
        }
    }
}
// <<< A3.2 EVM DEPLOYMENT & UPGRADE RECOVERY (generated) <<<

// >>> A3.3 EVM PROVIDER ADDRESS RESOLUTION (generated) >>>
pub use self::a3_3_resolve::{
    recover_evm_deployment_via_provider, EvmAddressResolver, EvmResolutionEvidence, ResolvedHop,
};

/// Deterministic provider-driven EVM address resolution (A3.3). The provider is
/// an EVIDENCE source ONLY: this module collects code + storage into evidence,
/// then hands that evidence to the deterministic A3.2 recoverer. It NEVER builds
/// `SystemIR` and NEVER bypasses reconstruction. Offline reconstruction stays
/// fully functional (a provider that lacks storage simply records the
/// requirement instead of fabricating an address).
mod a3_3_resolve {
    use super::a3_2_deploy::EvmDeploymentRecoverer;
    use crate::confidence::ConfidenceTier;
    use crate::deployment::{
        DeploymentRecoverer, RecoveredAddress, RecoveredDeployment, StorageEvidence,
    };
    use crate::evidence::{EvidenceCategory, EvidenceItem};
    use crate::evidence_requirement::EvidenceRequirement;
    use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};
    use crate::rpc::{BlockRef, Coordinate, RpcError, RpcProvider};
    use crate::MAX_PROXY_DEPTH;

    // EIP-1967 implementation slot (public standard constant).
    const EIP1967_IMPL_SLOT: &str =
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

    fn hex_lower(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push_str(&format!("{:02x}", x));
        }
        s
    }

    fn last20(word: &[u8; 32]) -> [u8; 20] {
        let mut a = [0u8; 20];
        a.copy_from_slice(&word[12..32]);
        a
    }

    fn is_zero(b: &[u8]) -> bool {
        b.iter().all(|x| *x == 0)
    }

    fn code_evidence(coord_key: &str, code: &[u8]) -> EvidenceItem {
        let payload = format!("{}|0x{}", coord_key, hex_lower(code));
        let prov = Provenance::new(
            EvidenceSource::RuntimeBytecode,
            ReconstructionStage::Fetch,
            ConfidenceTier::Recovered,
            &payload,
        );
        EvidenceItem::categorized(
            EvidenceCategory::RpcEvidence,
            EvidenceSource::RuntimeBytecode,
            "rpc_get_code",
            payload,
            prov,
        )
    }

    fn storage_evidence(coord_key: &str, slot: &str, value_hex: &str) -> EvidenceItem {
        let payload = format!("{}|{}|0x{}", coord_key, slot, value_hex);
        let prov = Provenance::new(
            EvidenceSource::StorageRecovery,
            ReconstructionStage::Fetch,
            ConfidenceTier::Recovered,
            &payload,
        );
        EvidenceItem::categorized(
            EvidenceCategory::RpcEvidence,
            EvidenceSource::StorageRecovery,
            "rpc_get_storage",
            payload,
            prov,
        )
    }

    /// One resolved hop in the implementation chain (provider-driven).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ResolvedHop {
        pub depth: u8,
        pub address: String,
        pub implementation: RecoveredAddress,
    }

    /// Deterministic evidence collected from the provider. This is the ONLY
    /// thing that flows into reconstruction -- never a half-built deployment.
    #[derive(Debug, Clone)]
    pub struct EvmResolutionEvidence {
        /// Runtime code of the ROOT address (fed to the deterministic recoverer).
        pub root_code: Vec<u8>,
        /// Storage slots gathered as evidence (EIP-1967 implementation slot).
        pub storage: StorageEvidence,
        /// Every evidence item produced (all `RpcEvidence`).
        pub items: Vec<EvidenceItem>,
        /// The bounded implementation chain that was followed.
        pub hops: Vec<ResolvedHop>,
        /// True when traversal stopped at MAX_PROXY_DEPTH.
        pub truncated_at_max_depth: bool,
    }

    /// Provider-driven EVM address resolver. Pins a chain id + block for
    /// determinism; emits evidence; performs bounded implementation-chain
    /// traversal with proxy resolution and storage retrieval.
    pub struct EvmAddressResolver {
        chain_id: u64,
        block: BlockRef,
    }

    impl EvmAddressResolver {
        pub fn new(chain_id: u64, block: BlockRef) -> Self {
            EvmAddressResolver { chain_id, block }
        }

        /// Provider -> Evidence. Follows the EIP-1967 implementation chain up to
        /// MAX_PROXY_DEPTH, turning every network read into deterministic
        /// evidence. Offline (no storage) it records the requirement instead.
        pub fn collect(
            &self,
            provider: &dyn RpcProvider,
            root_address: &str,
        ) -> Result<EvmResolutionEvidence, RpcError> {
            let mut items = Vec::new();
            let mut storage = StorageEvidence::empty();
            let mut hops = Vec::new();
            let mut root_code = Vec::new();
            let mut current = root_address.to_string();
            let mut depth: u8 = 0;
            let mut truncated = false;

            loop {
                let coord = Coordinate::new(self.chain_id, &current, self.block.clone());
                // Root code is mandatory; a downstream hop whose code is
                // unavailable simply terminates traversal (the resolved hop is
                // already recorded) -- never fabricated, never an error.
                let code = if depth == 0 {
                    provider.get_code(&coord)?
                } else {
                    match provider.get_code(&coord) {
                        Ok(c) => c,
                        Err(_) => break,
                    }
                };
                items.push(code_evidence(&coord.key(), &code));
                if depth == 0 {
                    root_code = code.clone();
                }

                match provider.get_storage_at(&coord, EIP1967_IMPL_SLOT) {
                    Ok(word) => {
                        let value_hex = hex_lower(&word);
                        storage = storage.with_slot(EIP1967_IMPL_SLOT, format!("0x{}", value_hex));
                        items.push(storage_evidence(
                            &coord.key(),
                            EIP1967_IMPL_SLOT,
                            &value_hex,
                        ));
                        let impl_bytes = last20(&word);
                        if is_zero(&impl_bytes) {
                            // Slot empty: `current` is a terminal (non-proxy) contract.
                            break;
                        }
                        let impl_addr = format!("0x{}", hex_lower(&impl_bytes));
                        hops.push(ResolvedHop {
                            depth,
                            address: current.clone(),
                            implementation: RecoveredAddress::Resolved(impl_addr.clone()),
                        });
                        if depth + 1 >= MAX_PROXY_DEPTH {
                            truncated = true;
                            break;
                        }
                        current = impl_addr;
                        depth += 1;
                    }
                    Err(_) => {
                        // No storage available: record the deterministic need.
                        hops.push(ResolvedHop {
                            depth,
                            address: current.clone(),
                            implementation: RecoveredAddress::unresolved(vec![
                                EvidenceRequirement::NeedsStorage(EIP1967_IMPL_SLOT.to_string()),
                            ]),
                        });
                        break;
                    }
                }
            }

            Ok(EvmResolutionEvidence {
                root_code,
                storage,
                items,
                hops,
                truncated_at_max_depth: truncated,
            })
        }
    }

    /// Convenience: Provider -> Evidence -> deterministic Reconstruction. The
    /// recovery step is the SAME A3.2 deterministic recoverer; the provider
    /// never short-circuits it. Stays in `evm` so the engine has no chain code.
    pub fn recover_evm_deployment_via_provider(
        provider: &dyn RpcProvider,
        chain_id: u64,
        root_address: &str,
        block: BlockRef,
    ) -> Result<RecoveredDeployment, RpcError> {
        let evidence = EvmAddressResolver::new(chain_id, block).collect(provider, root_address)?;
        Ok(
            EvmDeploymentRecoverer::new()
                .recover_deployment(&evidence.root_code, &evidence.storage),
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::deployment::{DeploymentDetail, ProxyFamily};
        use crate::rpc::{FixtureRpcProvider, RawBytecodeProvider};

        fn uups_code() -> Vec<u8> {
            let s = EIP1967_IMPL_SLOT.strip_prefix("0x").unwrap();
            let slot: Vec<u8> = (0..32)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            let mut c = vec![0x7f];
            c.extend_from_slice(&slot);
            c.push(0x63);
            c.extend_from_slice(&0x3659cfe6u32.to_be_bytes());
            c
        }

        fn impl_word(byte: u8) -> [u8; 32] {
            let mut w = [0u8; 32];
            #[allow(clippy::needless_range_loop)]
            for i in 12..32 {
                w[i] = byte;
            }
            w
        }

        #[test]
        fn resolves_implementation_via_provider_and_feeds_reconstruction() {
            let root = "0x1111111111111111111111111111111111111111";
            let code = uups_code();
            let coord = Coordinate::new(1, root, BlockRef::Number(100));
            let provider = FixtureRpcProvider::new()
                .with_code(&coord, code.clone())
                .with_storage(&coord, EIP1967_IMPL_SLOT, impl_word(0x22));
            let ev = EvmAddressResolver::new(1, BlockRef::Number(100))
                .collect(&provider, root)
                .unwrap();
            assert!(ev
                .items
                .iter()
                .all(|i| i.category == EvidenceCategory::RpcEvidence));
            assert!(!ev.items.is_empty());
            assert_eq!(
                ev.hops[0].implementation,
                RecoveredAddress::Resolved(format!("0x{}", "22".repeat(20)))
            );
            let dep =
                recover_evm_deployment_via_provider(&provider, 1, root, BlockRef::Number(100))
                    .unwrap();
            match &dep.detail {
                DeploymentDetail::Evm(e) => {
                    assert_eq!(e.proxies[0].family, ProxyFamily::Uups);
                    assert_eq!(
                        e.proxies[0].implementation,
                        RecoveredAddress::Resolved(format!("0x{}", "22".repeat(20)))
                    );
                }
                _ => panic!("expected EVM"),
            }
        }

        #[test]
        fn offline_records_requirement_not_fabrication() {
            let root = "0x1111111111111111111111111111111111111111";
            let provider = RawBytecodeProvider::new(uups_code());
            let ev = EvmAddressResolver::new(1, BlockRef::Latest)
                .collect(&provider, root)
                .unwrap();
            assert_eq!(ev.hops.len(), 1);
            assert!(!ev.hops[0].implementation.is_resolved());
            assert!(!ev.hops[0].implementation.requirements().is_empty());
        }

        #[test]
        fn bounded_recursion_truncates_at_max_depth() {
            let block = BlockRef::Number(1);
            let mut provider = FixtureRpcProvider::new();
            let mut addrs = Vec::new();
            for n in 0..(MAX_PROXY_DEPTH as u16 + 3) {
                addrs.push(format!("0x{:040x}", n + 1));
            }
            for n in 0..addrs.len() {
                let coord = Coordinate::new(1, &addrs[n], block.clone());
                provider = provider.with_code(&coord, uups_code());
                let next = if n + 1 < addrs.len() { n + 1 } else { n };
                let mut w = [0u8; 32];
                let nb = ((next as u64) + 1).to_be_bytes();
                w[24..32].copy_from_slice(&nb);
                provider = provider.with_storage(&coord, EIP1967_IMPL_SLOT, w);
            }
            let ev = EvmAddressResolver::new(1, block)
                .collect(&provider, &addrs[0])
                .unwrap();
            assert!(ev.truncated_at_max_depth);
            assert_eq!(ev.hops.len(), MAX_PROXY_DEPTH as usize);
        }
    }
}
// <<< A3.3 EVM PROVIDER ADDRESS RESOLUTION (generated) <<<
