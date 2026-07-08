use crate::app::AppState;
use crate::error::ApiError;
use crate::models::analysis::*;
use axum::extract::State;
/// Synthesize handler — wraps Gen 3 exploit synthesis pipeline.
use axum::Json;

pub async fn synthesize(
    State(_state): State<AppState>,
    Json(req): Json<SynthesizeRequest>,
) -> Result<Json<SynthesizeResponse>, ApiError> {
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

    let report = digger_synthesis::engine::synthesize(
        &inputs,
        &digger_synthesis::engine::SynthesisConfig::default(),
    );
    let program_id = report.protocol_id.clone();

    Ok(Json(SynthesizeResponse {
        program_id,
        total_chains: report.total_chains,
        viable_chains: report.viable_chains,
        eliminated_chains: report.eliminated_chains,
        confirmed: report.confirmations.len(),
        report_json: serde_json::to_value(&report).unwrap_or_default(),
    }))
}
