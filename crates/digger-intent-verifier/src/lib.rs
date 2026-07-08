#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

//! Digger Intent Verifier — offline calldata/instruction decoder.
//!
//! Explains what a transaction actually does, flagging dangerous intent.
//! Pure, deterministic, no network by default.

pub mod evm;
pub mod intent_model;
pub mod solana;

pub use evm::{decode_eip712, decode_evm_calldata, decode_tx_json};
pub use intent_model::{DecodedCall, IntentAnalysis, RiskLevel};
pub use solana::{decode_solana_instruction, decode_solana_transaction_json};
