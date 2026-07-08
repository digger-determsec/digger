use crate::models::*;
/// Execution ordering engine — checks-effects-interactions analysis.
///
/// Analyzes the ordered operations within each function to detect
/// when external calls occur before state writes (CEI violations).
///
/// Deterministic: same inputs → same output.
/// No AI, no inference, no heuristics.
use digger_parser::model::*;

/// Analyze execution ordering for a program.
///
/// Takes a RawProgram with operations and produces an ExecutionReport
/// with per-function analysis and CEI violation detection.
pub fn analyze_execution(program: &RawProgram, protocol_id: &str) -> ExecutionReport {
    let mut function_analyses = vec![];
    let mut cei_violations = vec![];

    // Group operations by function
    let mut func_ops: std::collections::BTreeMap<String, Vec<&RawOperation>> =
        std::collections::BTreeMap::new();
    for op in &program.operations {
        func_ops.entry(op.function.clone()).or_default().push(op);
    }

    // Analyze each function
    for (func_name, ops) in &func_ops {
        let has_external_call = ops.iter().any(|o| o.kind == OperationKind::ExternalCall);
        let has_state_write = ops.iter().any(|o| o.kind == OperationKind::StateWrite);
        let has_authority_check = ops.iter().any(|o| o.kind == OperationKind::AuthorityCheck);

        // Check for CEI violation: external call before state write
        let mut external_before_state_write = false;
        if has_external_call && has_state_write {
            // Find the first external call and first state write
            let first_external = ops.iter().find(|o| o.kind == OperationKind::ExternalCall);
            let first_state_write = ops.iter().find(|o| o.kind == OperationKind::StateWrite);

            if let (Some(ext), Some(write)) = (first_external, first_state_write) {
                if ext.index < write.index {
                    external_before_state_write = true;

                    cei_violations.push(CEIViolation {
                        function_name: func_name.to_string(),
                        external_call_index: ext.index,
                        state_write_index: write.index,
                        external_call_target: ext.target.clone(),
                        state_variable: write.target.clone(),
                        severity: digger_ir::Severity::High,
                    });
                }
            }
        }

        let ordered_operations: Vec<OperationEntry> = ops
            .iter()
            .map(|o| OperationEntry {
                index: o.index,
                kind: o.kind.to_string(),
                target: o.target.clone(),
            })
            .collect();

        function_analyses.push(FunctionExecution {
            function_name: func_name.to_string(),
            ordered_operations,
            has_external_call,
            has_state_write,
            has_authority_check,
            external_before_state_write,
        });
    }

    // Sort for deterministic output
    function_analyses.sort_by(|a, b| a.function_name.cmp(&b.function_name));
    cei_violations.sort_by(|a, b| {
        a.function_name
            .cmp(&b.function_name)
            .then(a.external_call_index.cmp(&b.external_call_index))
    });

    let summary = ExecutionSummary {
        total_functions: function_analyses.len(),
        functions_with_external_calls: function_analyses
            .iter()
            .filter(|f| f.has_external_call)
            .count(),
        functions_with_state_writes: function_analyses
            .iter()
            .filter(|f| f.has_state_write)
            .count(),
        functions_with_cei_violations: function_analyses
            .iter()
            .filter(|f| f.external_before_state_write)
            .count(),
        total_cei_violations: cei_violations.len(),
    };

    ExecutionReport {
        protocol_id: protocol_id.into(),
        function_analyses,
        cei_violations,
        summary,
    }
}

/// Serialize report to JSON (deterministic, pretty-printed).
pub fn report_to_json(report: &ExecutionReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

/// Deserialize report from JSON.
pub fn report_from_json(json: &str) -> Result<ExecutionReport, ExecutionError> {
    serde_json::from_str(json).map_err(|e| ExecutionError::InvalidReportJson(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> ExecutionReport {
        ExecutionReport {
            protocol_id: "test".into(),
            function_analyses: vec![FunctionExecution {
                function_name: "deposit".into(),
                ordered_operations: vec![OperationEntry {
                    index: 0,
                    kind: "StateWrite".into(),
                    target: "balances".into(),
                }],
                has_external_call: false,
                has_state_write: true,
                has_authority_check: false,
                external_before_state_write: false,
            }],
            cei_violations: vec![],
            summary: ExecutionSummary {
                total_functions: 1,
                functions_with_external_calls: 0,
                functions_with_state_writes: 1,
                functions_with_cei_violations: 0,
                total_cei_violations: 0,
            },
        }
    }

    #[test]
    fn roundtrip_json_serde() {
        let report = sample_report();
        let json = report_to_json(&report);
        let restored = report_from_json(&json).unwrap();
        assert_eq!(restored, report);
    }

    #[test]
    fn from_json_empty_object() {
        let result = report_from_json("{}");
        assert!(result.is_err());
    }

    #[test]
    fn from_json_malformed() {
        let result = report_from_json("not json at all");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid report JSON"));
    }

    #[test]
    fn to_json_empty_report() {
        let report = ExecutionReport {
            protocol_id: "empty".into(),
            function_analyses: vec![],
            cei_violations: vec![],
            summary: ExecutionSummary {
                total_functions: 0,
                functions_with_external_calls: 0,
                functions_with_state_writes: 0,
                functions_with_cei_violations: 0,
                total_cei_violations: 0,
            },
        };
        let json = report_to_json(&report);
        let restored = report_from_json(&json).unwrap();
        assert_eq!(restored.function_analyses.len(), 0);
    }

    #[test]
    fn analyze_empty_program() {
        use digger_parser::model::*;
        let program = RawProgram::default();
        let report = analyze_execution(&program, "empty");
        assert_eq!(report.function_analyses.len(), 0);
        assert_eq!(report.cei_violations.len(), 0);
    }

    #[test]
    fn analyze_program_with_multiple_functions() {
        let program = digger_parser::parse_program(
            r#"
contract Test {
    mapping(address => uint256) public balances;
    function alpha() public { balances[msg.sender] = 1; }
    function beta() public { (bool s, ) = msg.sender.call{value: 1}(""); }
}
"#,
            "solidity",
        );
        let report = analyze_execution(&program, "multi");
        assert!(report.function_analyses.len() >= 2);
        assert_eq!(report.protocol_id, "multi");
    }
}
