#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Digger Explanation Layer — deterministic natural-language reports from structured output.
//!
//! This crate consumes structured JSON produced by Digger Core and generates
//! human-readable explanations. It performs ZERO analysis — all reasoning
//! happened in the core pipeline. This is purely a formatting/presentation layer.

pub mod execution_report;
pub mod executive;
pub mod scan_report;
pub mod synthesis_report;
pub mod templates;
pub mod validation_report;
