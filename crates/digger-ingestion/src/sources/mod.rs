/// Source registry — manages all knowledge sources.
pub mod code4rena;
pub mod defihacklabs;
pub mod defillama;
pub mod github_advisories;
pub mod immunefi;
pub mod rekt;
pub mod sherlock;
pub mod slowmist;
pub mod solana_docs;

/// Source configuration.
#[derive(Debug, Clone)]
pub struct SourceConfig {
    pub source_id: String,
    pub source_kind: String,
    pub fetch_url: String,
    pub enabled: bool,
}

/// Get all configured sources.
pub fn get_sources() -> Vec<SourceConfig> {
    vec![
        SourceConfig {
            source_id: "code4rena".into(),
            source_kind: "audit_repository".into(),
            fetch_url: "https://github.com/code-423n4".into(),
            enabled: true,
        },
        SourceConfig {
            source_id: "sherlock".into(),
            source_kind: "audit_repository".into(),
            fetch_url: "https://github.com/sherlock-audit".into(),
            enabled: true,
        },
        SourceConfig {
            source_id: "defillama".into(),
            source_kind: "exploit_postmortem".into(),
            fetch_url: "https://api.llama.fi/hacks".into(),
            enabled: true,
        },
        SourceConfig {
            source_id: "slowmist".into(),
            source_kind: "exploit_postmortem".into(),
            fetch_url: "https://github.com/slowmist/papers".into(),
            enabled: true,
        },
        SourceConfig {
            source_id: "rekt".into(),
            source_kind: "exploit_postmortem".into(),
            fetch_url: "https://github.com/RektHQ/Reports".into(),
            enabled: true,
        },
        SourceConfig {
            source_id: "defihacklabs".into(),
            source_kind: "exploit_postmortem".into(),
            fetch_url: "https://github.com/SunWeb3Sec/DeFiHackLabs".into(),
            enabled: true,
        },
        SourceConfig {
            source_id: "immunefi".into(),
            source_kind: "exploit_postmortem".into(),
            fetch_url: "https://immunefi.com".into(),
            enabled: false, // Stub — no public API
        },
        SourceConfig {
            source_id: "github-advisories".into(),
            source_kind: "exploit_postmortem".into(),
            fetch_url: "https://api.github.com/advisories".into(),
            enabled: true,
        },
        SourceConfig {
            source_id: "solana-docs".into(),
            source_kind: "protocol_documentation".into(),
            fetch_url: "https://github.com/coral-xyz/anchor".into(),
            enabled: true,
        },
    ]
}
