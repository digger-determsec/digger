/// Analysis endpoint request/response types.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ─── Scan ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub code: String,
    pub lang: String,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub findings: Vec<serde_json::Value>,
    pub summary: serde_json::Value,
    pub program_id: String,
}

// ─── Synthesize ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SynthesizeRequest {
    pub code: String,
    pub lang: String,
}

#[derive(Debug, Serialize)]
pub struct SynthesizeResponse {
    pub program_id: String,
    pub total_chains: usize,
    pub viable_chains: usize,
    pub eliminated_chains: usize,
    pub confirmed: usize,
    pub report_json: serde_json::Value,
}

// ─── Validate ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub chain_id: String,
    pub code: String,
    pub lang: String,
}

#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub chain_id: String,
    pub validation_score: f64,
    pub verdict: String,
    pub report_json: serde_json::Value,
}

// ─── Execute ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ExecuteRequest {
    pub code: String,
    pub lang: String,
}

#[derive(Debug, Serialize)]
pub struct ExecuteResponse {
    pub execution_result: Option<ExecuteResult>,
    pub report_json: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ExecuteResult {
    pub confirmation_status: String,
    pub transcript_entries: usize,
    pub total_gas: u64,
    pub state_diff: StateDiffResult,
    pub economic_outcome: EconomicOutcomeResult,
    pub execution_hash: String,
}

#[derive(Debug, Serialize)]
pub struct StateDiffResult {
    pub storage_changes: usize,
    pub balance_changes: usize,
    pub authority_changes: usize,
}

#[derive(Debug, Serialize)]
pub struct EconomicOutcomeResult {
    pub net_profit: BTreeMap<String, f64>,
    pub gas_cost: f64,
}

// ─── Evaluate ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    pub eval_type: Option<String>,
    pub corpus_dir: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    pub eval_type: String,
    pub result: serde_json::Value,
}

// ─── Job Status ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct JobStatusResponse {
    pub id: String,
    pub status: String,
    pub progress: f64,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

// ─── Explain ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ExplainRequest {
    pub code: String,
    pub lang: String,
}
