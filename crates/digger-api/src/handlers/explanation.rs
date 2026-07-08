use crate::app::AppState;
use crate::error::ApiError;
use crate::models::analysis::*;
use axum::extract::State;
/// Explanation handler — generates deterministic NL reports from structured output.
use axum::Json;

pub async fn explain_scan(
    State(_state): State<AppState>,
    Json(req): Json<ExplainRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let raw = digger_parser::parse_program(&req.code, &req.lang);
    let language = match req.lang.as_str() {
        "solidity" | "sol" => digger_ir::Language::Solidity,
        "anchor" => digger_ir::Language::Anchor,
        "rust" | "rs" => digger_ir::Language::Rust,
        _ => digger_ir::Language::Unknown,
    };
    let ir = digger_graph::build_system_ir_with_language(raw, language);
    let result = digger_hypothesis::derive(&ir);

    let scan_json = serde_json::json!({
        "findings": result.hypotheses.iter().map(|h| {
            serde_json::json!({
                "id": h.id.0,
                "type": h.hypothesis_type.to_string(),
                "severity": format!("{:?}", h.severity),
                "description": h.description,
                "function": h.primary_function,
                "evidence_count": h.evidence.len(),
            })
        }).collect::<Vec<_>>(),
        "summary": result.summary,
        "program_id": result.program_id,
    });

    let report = digger_explanation::scan_report::explain_scan(&scan_json);
    let markdown = digger_explanation::scan_report::render_scan_markdown(&report);

    Ok(Json(serde_json::json!({
        "format": "markdown",
        "report": markdown,
        "metadata": {
            "title": report.title,
            "finding_count": report.finding_count,
            "severity_breakdown": report.severity_breakdown,
        },
    })))
}

pub async fn explain_synthesis(
    State(_state): State<AppState>,
    Json(req): Json<ExplainRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
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
    let syn_json = serde_json::to_value(&syn_report).unwrap_or_default();

    let report = digger_explanation::synthesis_report::explain_synthesis(&syn_json);
    let markdown = digger_explanation::synthesis_report::render_synthesis_markdown(&report);

    Ok(Json(serde_json::json!({
        "format": "markdown",
        "report": markdown,
        "metadata": {
            "chain_count": report.chain_count,
            "viable_count": report.viable_count,
            "confirmed_count": report.confirmed_count,
        },
    })))
}

pub async fn explain_full(
    State(_state): State<AppState>,
    Json(req): Json<ExplainRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let raw = digger_parser::parse_program(&req.code, &req.lang);
    let language = match req.lang.as_str() {
        "solidity" | "sol" => digger_ir::Language::Solidity,
        "anchor" => digger_ir::Language::Anchor,
        "rust" | "rs" => digger_ir::Language::Rust,
        _ => digger_ir::Language::Unknown,
    };
    let ir = digger_graph::build_system_ir_with_language(raw, language);

    // Scan
    let scan_result = digger_hypothesis::derive(&ir);
    let scan_json = serde_json::json!({
        "findings": scan_result.hypotheses.iter().map(|h| {
            serde_json::json!({
                "id": h.id.0, "type": h.hypothesis_type.to_string(),
                "severity": format!("{:?}", h.severity), "description": h.description,
                "function": h.primary_function, "evidence_count": h.evidence.len(),
            })
        }).collect::<Vec<_>>(),
        "summary": scan_result.summary, "program_id": scan_result.program_id,
    });

    // Synthesis
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
    let syn_json = serde_json::to_value(&syn_report).unwrap_or_default();

    let validation_json = syn_report.rankings.first().map(|r| {
        serde_json::json!({
            "chain_id": r.chain_id,
            "validation_score": r.score,
            "verdict": if syn_report.confirmations.iter().any(|c| c.chain_id == r.chain_id) {
                "Valid"
            } else if r.score > 0.5 {
                "PartiallyValid"
            } else {
                "Invalid"
            },
        })
    });

    let execution_json = syn_report.execution_packages.first().map(|pkg| {
        let exec_config = digger_synthesis::execution_engine::ExecutionConfig::default();
        let transcript = digger_synthesis::execution_engine::execute_exploit(pkg, &exec_config);
        serde_json::json!({
            "execution_result": {
                "confirmation_status": format!("{:?}", transcript.status),
                "transcript_entries": transcript.entries.len(),
                "total_gas": transcript.gas_summary.total_gas,
                "state_diff": {
                    "storage_changes": transcript.state_diff.storage_changes.len(),
                    "balance_changes": transcript.state_diff.balance_changes.len(),
                    "authority_changes": transcript.state_diff.authority_changes.len(),
                },
                "execution_hash": transcript.deterministic_hash,
            },
        })
    });

    let summary = digger_explanation::executive::generate_executive_summary(
        &scan_json,
        &syn_json,
        validation_json.as_ref(),
        execution_json.as_ref(),
    );
    let markdown = digger_explanation::executive::render_executive_markdown(&summary);

    Ok(Json(serde_json::json!({
        "format": "markdown",
        "report": markdown,
        "metadata": {
            "program_id": summary.program_id,
            "overall_risk": summary.overall_risk,
            "key_findings": summary.key_findings,
        },
    })))
}
