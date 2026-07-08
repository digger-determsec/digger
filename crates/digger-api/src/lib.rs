#![forbid(unsafe_code)]
#![recursion_limit = "256"]
/// Digger API — REST interface for the deterministic blockchain security platform.
pub mod app;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod jobs;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod net_guard;
pub mod org_guard;
pub mod rate_limit;
pub mod security;
pub mod timing;
pub mod webhook_signing;

#[cfg(test)]
mod tests;

pub use app::create_app;
pub use config::Config;
