#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![allow(clippy::useless_format, clippy::single_char_add_str)]

mod audit_triage_cmd;
mod benchmark;
mod chain_trace;
mod ci_mode;
mod commands;
mod dashboard_cmd;
mod engine_triage;
mod evidence_package_cmd;
mod fuzz_evidence_cmd;
mod fuzz_maturity_cmd;
mod hypothesis_cmd;
mod output;
mod pipeline;
mod proof_task_cmd;
mod repo_intelligence_cmd;
mod report;
mod report_cmd;
mod report_draft_cmd;
mod scan_live;
mod source_triage;
mod synthesize_cmd;
mod validate;
mod verify_claim_cmd;

fn main() {
    commands::run();
}
