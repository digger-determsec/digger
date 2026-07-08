use serde::{Deserialize, Serialize};
use std::fmt;

/// Chain identifiers for block explorer API routing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    EthereumMainnet,
    Arbitrum,
    Optimism,
    Polygon,
    Base,
    Sepolia,
}

impl Chain {
    pub fn etherscan_api_url(&self) -> String {
        match self {
            Chain::EthereumMainnet => "https://api.etherscan.io/v2/api?chainid=1".to_string(),
            Chain::Arbitrum => "https://api.arbiscan.io/v2/api?chainid=42161".to_string(),
            Chain::Optimism => "https://api-optimistic.etherscan.io/v2/api?chainid=10".to_string(),
            Chain::Polygon => "https://api.polygonscan.com/v2/api?chainid=137".to_string(),
            Chain::Base => "https://api.basescan.org/v2/api?chainid=8453".to_string(),
            Chain::Sepolia => {
                "https://api-sepolia.etherscan.io/v2/api?chainid=11155111".to_string()
            }
        }
    }

    pub fn from_name(s: &str) -> Result<Self, ExplorerError> {
        match s.to_lowercase().as_str() {
            "ethereum" | "mainnet" | "eth" => Ok(Chain::EthereumMainnet),
            "arbitrum" | "arb" | "arb1" => Ok(Chain::Arbitrum),
            "optimism" | "op" | "optimistic" => Ok(Chain::Optimism),
            "polygon" | "matic" | "pol" => Ok(Chain::Polygon),
            "base" => Ok(Chain::Base),
            "sepolia" | "eth-sepolia" => Ok(Chain::Sepolia),
            _ => Err(ExplorerError::UnsupportedChain(s.to_string())),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Chain::EthereumMainnet => "ethereum",
            Chain::Arbitrum => "arbitrum",
            Chain::Optimism => "optimism",
            Chain::Polygon => "polygon",
            Chain::Base => "base",
            Chain::Sepolia => "sepolia",
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Source code fetched from a block explorer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchedSource {
    /// Whether the contract source was verified on the explorer.
    pub verified: bool,
    /// The verified source code (single file or combined).
    pub source: String,
    /// Compiler version reported by the explorer (e.g. "0.8.19+commit.7dd6d404").
    pub compiler_version: String,
    /// Optimization settings (e.g. "200 runs").
    pub optimization: String,
    /// Contract name as reported by the explorer.
    pub contract_name: String,
    /// ABI if the explorer provides it.
    pub abi: Option<String>,
    /// If this is a proxy, the implementation address.
    pub implementation_address: Option<String>,
    /// Whether the explorer identifies this as a proxy contract.
    pub is_proxy: bool,
    /// The EVM version (e.g. "london", "paris").
    pub evm_version: Option<String>,
}

/// Errors from explorer interactions.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExplorerError {
    /// Contract source not verified on this explorer.
    #[error("Contract at {0} is not verified")]
    NotVerified(String),
    /// Network or API error.
    #[error("Network error: {0}")]
    NetworkError(String),
    /// Rate limit exceeded.
    #[error("Rate limited by explorer API")]
    RateLimited,
    /// Unsupported chain.
    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),
    /// Invalid address format.
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    /// API returned an unexpected response.
    #[error("API error: {0}")]
    ApiError(String),
}

/// Trait for fetching verified source from block explorers.
///
/// All network access goes through this trait for testability.
/// Implementations must handle rate limits, unverified contracts,
/// and proxy detection gracefully.
pub trait SourceFetcher: Send + Sync {
    /// Fetch verified source for an address on a given chain.
    fn fetch_source(&self, chain: &Chain, address: &str) -> Result<FetchedSource, ExplorerError>;

    /// Validate an address format for this chain's explorer.
    fn validate_address(address: &str) -> Result<(), ExplorerError> {
        let trimmed = address.trim();
        if trimmed.len() != 42 || !trimmed.starts_with("0x") {
            return Err(ExplorerError::InvalidAddress(trimmed.to_string()));
        }
        if !trimmed[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ExplorerError::InvalidAddress(trimmed.to_string()));
        }
        Ok(())
    }
}

// ── Etherscan API response types ──────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EtherscanResponse {
    pub status: String,
    pub message: String,
    pub result: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EtherscanSourceResult {
    #[serde(default)]
    pub source_code: String,
    #[serde(default)]
    pub abi: String,
    #[serde(default)]
    pub contract_name: String,
    #[serde(default)]
    pub compiler_version: String,
    #[serde(default)]
    pub optimization_used: String,
    #[serde(default)]
    pub runs: String,
    #[serde(default)]
    pub implementation: String,
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub evm_version: String,
    #[serde(default)]
    pub license_type: String,
    #[serde(default)]
    pub method_identifiers: serde_json::Value,
}

/// Etherscan API client.
#[cfg(feature = "live-fetch")]
pub struct EtherscanClient {
    http_client: reqwest::blocking::Client,
}

#[cfg(feature = "live-fetch")]
impl EtherscanClient {
    pub fn new() -> Self {
        Self {
            http_client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new()),
        }
    }
}

#[cfg(feature = "live-fetch")]
impl Default for EtherscanClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "live-fetch")]
impl SourceFetcher for EtherscanClient {
    fn fetch_source(&self, chain: &Chain, address: &str) -> Result<FetchedSource, ExplorerError> {
        Self::validate_address(address)?;

        let api_key =
            std::env::var("ETHERSCAN_API_KEY").unwrap_or_else(|_| "YourApiKeyToken".into());

        let url = format!(
            "{}?module=contract&action=getsourcecode&address={}&apikey={}",
            chain.etherscan_api_url(),
            address,
            api_key
        );

        let display_url = digger_egress::redact_url(&url);
        digger_egress::authorize_global(&display_url, "fetch-contract-source")
            .map_err(|e| ExplorerError::NetworkError(e.to_string()))?;

        let resp = self
            .http_client
            .get(&url)
            .send()
            .map_err(|e| ExplorerError::NetworkError(e.to_string()))?;

        if resp.status().as_u16() == 429 {
            return Err(ExplorerError::RateLimited);
        }

        let body: EtherscanResponse = resp
            .json()
            .map_err(|e| ExplorerError::ApiError(e.to_string()))?;

        if body.status != "1" {
            return Err(ExplorerError::ApiError(format!(
                "{}: {}",
                body.status, body.message
            )));
        }

        let result: EtherscanSourceResult = serde_json::from_value(body.result)
            .map_err(|e| ExplorerError::ApiError(e.to_string()))?;

        let source = if result.source_code.is_empty() {
            return Err(ExplorerError::NotVerified(address.to_string()));
        } else {
            extract_source(&result.source_code)
        };

        let is_proxy = !result.implementation.is_empty() || result.proxy == "1";

        Ok(FetchedSource {
            verified: true,
            source,
            compiler_version: result.compiler_version,
            optimization: if result.optimization_used == "1" {
                format!("{} runs", result.runs)
            } else {
                "disabled".into()
            },
            contract_name: result.contract_name,
            abi: if result.abi.is_empty() || result.abi == "Contract source code not verified" {
                None
            } else {
                Some(result.abi)
            },
            implementation_address: if result.implementation.is_empty() {
                None
            } else {
                Some(result.implementation)
            },
            is_proxy,
            evm_version: if result.evm_version.is_empty() {
                None
            } else {
                Some(result.evm_version)
            },
        })
    }
}

/// Extract source code from Etherscan's SourceCode field.
///
/// Handles three formats:
/// 1. Standard-JSON: `{"language":"Solidity","sources":{"file.sol":{"content":"..."}}}`
///    Also handles Etherscan's double-brace wrapper: `{{ ... }}`
/// 2. Multi-file: `{{"file1.sol":"...","file2.sol":"..."}}` (key-value JSON after strip)
/// 3. Single-file: raw Solidity source
#[cfg(feature = "live-fetch")]
fn extract_source(raw_source: &str) -> String {
    let trimmed = raw_source.trim();

    // Step 1: Strip Etherscan's {{ }} wrapper if present
    let json_str = if trimmed.starts_with("{{") && trimmed.ends_with("}}") {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    };

    // Step 2: Try to parse as JSON
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json_str) {
        // Step 2a: Standard-JSON format (has "language" + "sources" keys)
        if let Some(sources) = parsed.get("sources").and_then(|s| s.as_object()) {
            if parsed.get("language").is_some() {
                return flatten_standard_json(sources);
            }
        }

        // Step 2b: Key-value multi-file format (each value has "content")
        if parsed.is_object() {
            let all_sol: Vec<String> = sources_to_sol_contents(&parsed);
            if !all_sol.is_empty() {
                return all_sol.join("\n\n");
            }
        }
    }

    // Step 3: Plain source text (single file)
    json_str
}

/// Flatten standard-JSON sources into concatenated Solidity source.
///
/// Each entry in `sources` is `"path": {"content": "// SPDX...\n..."}`.
/// We concatenate all .sol contents with a file-separator comment for debugging.
#[cfg(feature = "live-fetch")]
fn flatten_standard_json(sources: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Sort by key for deterministic output
    let mut sorted_keys: Vec<&String> = sources.keys().collect();
    sorted_keys.sort();

    for key in sorted_keys {
        if let Some(entry) = sources.get(key) {
            if let Some(content) = entry.get("content").and_then(|c| c.as_str()) {
                let trimmed = content.trim();
                if !trimmed.is_empty() {
                    parts.push(trimmed.to_string());
                }
            }
        }
    }

    if parts.is_empty() {
        // Fallback: return empty, caller will see NotVerified
        return String::new();
    }

    parts.join("\n\n")
}

/// Extract .sol file contents from a JSON object.
/// Used for key-value multi-file format: `{"file.sol": "content", ...}`
#[cfg(feature = "live-fetch")]
fn sources_to_sol_contents(obj: &serde_json::Value) -> Vec<String> {
    let mut result = Vec::new();
    if let Some(map) = obj.as_object() {
        let mut sorted_keys: Vec<&String> = map.keys().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            if key.ends_with(".sol") {
                if let Some(val) = map.get(key.as_str()) {
                    if let Some(content) = val.as_str() {
                        let trimmed = content.trim();
                        if !trimmed.is_empty() {
                            result.push(trimmed.to_string());
                        }
                    } else if let Some(content) = val.get("content").and_then(|c| c.as_str()) {
                        // Some formats wrap content in {"content": "..."}
                        let trimmed = content.trim();
                        if !trimmed.is_empty() {
                            result.push(trimmed.to_string());
                        }
                    }
                }
            }
        }
    }
    result
}
