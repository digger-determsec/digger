//! Digger SDK for Rust — wraps the public REST API.
//!
//! ```rust,no_run
//! use digger_sdk::DiggerClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = DiggerClient::new("http://localhost:3000", None);
//!     let health = client.health().await.unwrap();
//!     println!("Status: {}", health["status"]);
//! }
//! ```

pub mod client;

pub use client::{DiggerClient, ApiError, ScanResult, SynthesisResult, ValidationReport, ExecutionResult, BenchmarkResult, SearchResult, OrgInfo, ProjectInfo, ScanRecord, ReportInfo, WebhookInfo};
