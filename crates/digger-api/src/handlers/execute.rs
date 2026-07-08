use crate::app::AppState;
use crate::error::ApiError;
use crate::models::analysis::*;
use axum::extract::State;
/// Execute handler — wraps Gen 4 execution and verification.
use axum::Json;

pub async fn execute(
    State(_state): State<AppState>,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, ApiError> {
    let raw = digger_parser::parse_program(&req.code, &req.lang);
    let language = match req.lang.as_str() {
        "solidity" | "sol" => digger_ir::Language::Solidity,
        "anchor" => digger_ir::Language::Anchor,
        "rust" | "rs" => digger_ir::Language::Rust,
        _ => digger_ir::Language::Unknown,
    };
    let ir = digger_graph::build_system_ir_with_language(raw, language);

    let inputs = digger_synthesis::engine::SynthesisInputs {
        ir: Some(&ir),
        expansion: None,
        transitions: None,
        lifecycles: None,
        temporal: None,
        actors: None,
        economics: None,
        verification: None,
        adversarial: None,
        protocol: None,
        surface: None,
    };

    let syn_report = digger_synthesis::engine::synthesize(
        &inputs,
        &digger_synthesis::engine::SynthesisConfig::default(),
    );

    let exec_result = syn_report.execution_packages.first().map(|pkg| {
        let exec_config = digger_synthesis::execution_engine::ExecutionConfig::default();
        let transcript = digger_synthesis::execution_engine::execute_exploit(pkg, &exec_config);

        ExecuteResult {
            confirmation_status: format!("{:?}", transcript.status),
            transcript_entries: transcript.entries.len(),
            total_gas: transcript.gas_summary.total_gas,
            state_diff: StateDiffResult {
                storage_changes: transcript.state_diff.storage_changes.len(),
                balance_changes: transcript.state_diff.balance_changes.len(),
                authority_changes: transcript.state_diff.authority_changes.len(),
            },
            economic_outcome: EconomicOutcomeResult {
                net_profit: transcript.economic_outcome.net_profit.clone(),
                gas_cost: transcript.economic_outcome.gas_cost,
            },
            execution_hash: transcript.deterministic_hash,
        }
    });

    Ok(Json(ExecuteResponse {
        execution_result: exec_result,
        report_json: serde_json::json!({
            "program_id": ir.program_id,
            "chains_synthesized": syn_report.total_chains,
        }),
    }))
}
