#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Digger agent truth layer — deterministic read-only serialization over
/// engine output, deterministic validator, guardrails.
///
/// No model providers, no API keys, no outbound network.
/// All types project from digger-evidence and digger-txwatch engine output.
pub mod contract;
pub mod guardrails;

/// Permanent regression gate: no model-provider or network dependencies.
/// This test verifies that digger-agent's Cargo.toml does not contain
/// any model-provider SDK, HTTP client, or API key handling dependency.
/// If a dependency is reintroduced, this test must be explicitly updated
/// (and the re-introduction must be reviewed for non-fabrication compliance).
#[cfg(test)]
mod no_provider_guard {
    #[test]
    fn test_no_model_provider_or_network_deps() {
        let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

        let forbidden = [
            "openai",
            "anthropic",
            "gemini",
            "reqwest",
            "surf",
            "hyper",
            "ureq",
            "isahc",
            "reqwless",
        ];

        for dep in &forbidden {
            assert!(
                !manifest.contains(dep),
                "digger-agent must not depend on '{}' — this is a model-provider/network dep",
                dep
            );
        }

        // Also verify no API key env vars are read at compile time
        assert!(
            !manifest.contains("API_KEY") || manifest.contains("DIGGER_API_KEY"),
            "digger-agent must not reference external API keys"
        );
    }
}
