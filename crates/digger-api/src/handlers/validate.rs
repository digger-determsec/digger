use crate::app::AppState;
use crate::error::ApiError;
use crate::models::analysis::*;
use axum::extract::State;
/// Validate handler — wraps Gen 3.2 validation pipeline.
use axum::Json;

pub async fn validate(
    State(_state): State<AppState>,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, ApiError> {
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

    let matching = if !req.chain_id.is_empty() {
        syn_report
            .rankings
            .iter()
            .find(|r| r.chain_id == req.chain_id)
    } else {
        syn_report.rankings.first()
    };
    let chain_id = matching.map(|r| r.chain_id.clone()).unwrap_or_default();
    let validation_score = matching.map(|r| r.score).unwrap_or(0.0);
    let confirmed = syn_report.confirmations.len();

    let verdict = if confirmed > 0 {
        "Valid".into()
    } else if validation_score > 0.5 {
        "PartiallyValid".into()
    } else {
        "Invalid".into()
    };

    Ok(Json(ValidateResponse {
        chain_id,
        validation_score,
        verdict,
        report_json: serde_json::json!({
            "synthesis": {
                "total_chains": syn_report.total_chains,
                "viable_chains": syn_report.viable_chains,
                "eliminated": syn_report.eliminated_chains,
            },
            "validation_score": validation_score,
            "confirmed": confirmed,
            "rankings": syn_report.rankings.len(),
        }),
    }))
}
