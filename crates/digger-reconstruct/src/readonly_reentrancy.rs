use crate::confidence::ConfidenceTier;
use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};
use digger_parser::model::{OperationKind, RawProgram};
use serde::{Deserialize, Serialize};

/// C6.14 -- Read-only reentrancy detector with data-flow criticality.
///
/// Detection rule (ADR-0033, updated C6.14):
/// A finding is emitted when ALL of the following hold:
/// 1. A function has an ExternalCall operation
/// 2. A StateRead AFTER the ExternalCall is SECURITY-CRITICAL:
///    the read appears BEFORE a StateWrite or ValueTransfer in the
///    operation sequence (the read value feeds into the write computation).
///    Reads that appear AFTER a StateWrite are compound-assignment reads
///    (reading the old value before incrementing) and are NOT critical.
/// 3. No protective guard is present (no CEI ordering, no AuthorityCheck
///    before the ExternalCall).
///
/// DATA-FLOW CRITICALITY (structural, not positional):
/// The IR lacks explicit data-flow edges. We approximate by ordering:
/// - StateRead BEFORE StateWrite = critical (read feeds into write)
/// - StateRead AFTER StateWrite = benign (compound assignment)
///
/// GUARD DETECTION:
/// - CEI ordering: all StateWrites appear before the ExternalCall
/// - Reentrancy lock: AuthorityCheck before the ExternalCall
///
/// BOUNDARY WITH CEI DETECTOR:
/// CEI fires on ExternalCall -> StateWrite (write-path reentrancy).
/// This fires on ExternalCall -> critical StateRead (read-path reentrancy).
/// Different finding kinds, no double-count.
/// A read-only reentrancy finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadonlyReentrancyFinding {
    pub id: String,
    pub function_id: String,
    pub finding_kind: String,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
    pub provenance: Provenance,
}

impl ReadonlyReentrancyFinding {
    pub fn make_id(function_id: &str) -> String {
        format!("ror:{}", function_id)
    }
}

pub fn detect_readonly_reentrancy(program: &RawProgram) -> Vec<ReadonlyReentrancyFinding> {
    let mut findings = Vec::new();

    for func in &program.functions {
        let ops: Vec<_> = program
            .operations
            .iter()
            .filter(|o| o.function == func.name)
            .collect();

        if ops.is_empty() {
            continue;
        }

        // Step 1: Find the index of the first ExternalCall
        let ext_idx = match ops
            .iter()
            .position(|o| o.kind == OperationKind::ExternalCall)
        {
            Some(i) => i,
            None => continue,
        };

        // Step 2: CEI guard -- state finalized before call
        let has_write_before = ops[..ext_idx]
            .iter()
            .any(|o| o.kind == OperationKind::StateWrite);
        let has_write_after = ops[ext_idx + 1..]
            .iter()
            .any(|o| o.kind == OperationKind::StateWrite);
        if has_write_before && !has_write_after {
            continue;
        }

        // Step 3: Reentrancy lock guard -- AuthorityCheck before ExternalCall
        let has_auth_before = ops[..ext_idx]
            .iter()
            .any(|o| o.kind == OperationKind::AuthorityCheck);
        if has_auth_before {
            continue;
        }

        // Step 4: Data-flow criticality -- find a StateRead that appears
        // BEFORE a StateWrite or ValueTransfer (after the ExternalCall).
        // This means the read value feeds into the write computation.
        // Compound assignment reads (StateRead AFTER StateWrite to same target)
        // are benign -- they read the old value before incrementing.
        let post_ext = &ops[ext_idx + 1..];
        let mut found_critical_read = false;

        for (ri, read_op) in post_ext.iter().enumerate() {
            if read_op.kind != OperationKind::StateRead {
                continue;
            }

            // Check if this is a compound assignment: same target written BEFORE the read
            let is_compound = post_ext[..ri]
                .iter()
                .any(|o| o.kind == OperationKind::StateWrite && o.target == read_op.target);
            if is_compound {
                continue; // Compound assignment -- benign
            }

            // Check if there's a StateWrite or ValueTransfer AFTER this read
            for write_op in post_ext[ri + 1..].iter() {
                if write_op.kind == OperationKind::StateWrite
                    || write_op.kind == OperationKind::ValueTransfer
                {
                    found_critical_read = true;
                    break;
                }
            }
            if found_critical_read {
                break;
            }
        }

        if !found_critical_read {
            continue;
        }

        // Step 5: Emit finding
        let prov = Provenance::new(
            EvidenceSource::SourceCode,
            ReconstructionStage::Recover,
            ConfidenceTier::Recovered,
            &format!("ror|{}|read_before_write", func.name),
        );

        findings.push(ReadonlyReentrancyFinding {
            id: ReadonlyReentrancyFinding::make_id(&func.name),
            function_id: func.name.clone(),
            finding_kind: "ReadOnlyReentrancy".into(),
            suppressed: false,
            suppression_reason: None,
            provenance: prov,
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_parser::model::{RawFunction, RawOperation};

    fn make_fn(name: &str) -> RawFunction {
        RawFunction {
            name: name.into(),
            contract: String::new(),
            visibility: "public".into(),
            inputs: vec![],
            body: String::new(),
            has_arithmetic: false,
        }
    }

    #[test]
    fn no_external_call_no_finding() {
        let program = RawProgram {
            functions: vec![make_fn("deposit")],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::StateRead,
                    target: "price".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::StateWrite,
                    target: "balance".into(),
                },
            ],
            ..Default::default()
        };
        assert!(detect_readonly_reentrancy(&program).is_empty());
    }

    #[test]
    fn external_call_no_state_read_no_finding() {
        let program = RawProgram {
            functions: vec![make_fn("deposit")],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "transfer".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::StateWrite,
                    target: "balance".into(),
                },
            ],
            ..Default::default()
        };
        assert!(detect_readonly_reentrancy(&program).is_empty());
    }

    #[test]
    fn cei_ordered_no_finding() {
        let program = RawProgram {
            functions: vec![make_fn("deposit")],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::StateWrite,
                    target: "balance".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::ExternalCall,
                    target: "transfer".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 2,
                    kind: OperationKind::StateRead,
                    target: "price".into(),
                },
            ],
            ..Default::default()
        };
        assert!(detect_readonly_reentrancy(&program).is_empty());
    }

    #[test]
    fn guarded_no_finding() {
        let program = RawProgram {
            functions: vec![make_fn("deposit")],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::AuthorityCheck,
                    target: "require".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::ExternalCall,
                    target: "transfer".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 2,
                    kind: OperationKind::StateRead,
                    target: "price".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 3,
                    kind: OperationKind::StateWrite,
                    target: "balance".into(),
                },
            ],
            ..Default::default()
        };
        assert!(detect_readonly_reentrancy(&program).is_empty());
    }

    #[test]
    fn read_before_write_finding() {
        // ExternalCall -> StateRead -> StateWrite (read before write = critical)
        let program = RawProgram {
            functions: vec![make_fn("deposit")],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "transfer".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::StateRead,
                    target: "price".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 2,
                    kind: OperationKind::StateWrite,
                    target: "balance".into(),
                },
            ],
            ..Default::default()
        };
        let findings = detect_readonly_reentrancy(&program);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_kind, "ReadOnlyReentrancy");
    }

    #[test]
    fn compound_assignment_not_critical() {
        // ExternalCall -> StateWrite -> StateRead (read AFTER write = compound assignment, benign)
        let program = RawProgram {
            functions: vec![make_fn("deposit")],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "transfer".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::StateWrite,
                    target: "totalDeposited".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 2,
                    kind: OperationKind::StateRead,
                    target: "totalDeposited".into(),
                },
            ],
            ..Default::default()
        };
        assert!(detect_readonly_reentrancy(&program).is_empty());
    }

    #[test]
    fn no_write_after_read_not_critical() {
        // ExternalCall -> StateRead (no StateWrite after = benign)
        let program = RawProgram {
            functions: vec![make_fn("deposit")],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "transfer".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::StateRead,
                    target: "log_value".into(),
                },
            ],
            ..Default::default()
        };
        assert!(detect_readonly_reentrancy(&program).is_empty());
    }

    #[test]
    fn read_with_intermediate_ops_critical() {
        // ExternalCall -> StateRead -> InternalCall -> StateWrite
        // (read before write even with intermediates = critical)
        let program = RawProgram {
            functions: vec![make_fn("deposit")],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "transfer".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::StateRead,
                    target: "poolBalance".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 2,
                    kind: OperationKind::InternalCall,
                    target: "computeShares".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 3,
                    kind: OperationKind::StateWrite,
                    target: "shares".into(),
                },
            ],
            ..Default::default()
        };
        let findings = detect_readonly_reentrancy(&program);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn boundary_cei_detector_no_overlap() {
        // ROR finding_kind is "ReadOnlyReentrancy", distinct from CEI
        let program = RawProgram {
            functions: vec![make_fn("deposit")],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "transfer".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::StateRead,
                    target: "price".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 2,
                    kind: OperationKind::StateWrite,
                    target: "balance".into(),
                },
            ],
            ..Default::default()
        };
        let findings = detect_readonly_reentrancy(&program);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_kind, "ReadOnlyReentrancy");
    }
}
