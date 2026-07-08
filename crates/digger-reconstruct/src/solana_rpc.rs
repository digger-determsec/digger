use crate::explorer::ExplorerError;
use serde::{Deserialize, Serialize};

/// RPC endpoint configuration for Solana.
#[derive(Debug, Clone)]
pub struct SolanaRpcConfig {
    pub rpc_url: String,
}

impl Default for SolanaRpcConfig {
    fn default() -> Self {
        let rpc_url = std::env::var("DIGGER_SOLANA_RPC")
            .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".into());
        Self { rpc_url }
    }
}

/// Source provenance: where the analyzable source came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceProvenance {
    /// Actual Anchor source code available on-chain (rare).
    OnChainSource,
    /// Source resolved via verified-build / security.txt source_code URL.
    VerifiedBuildRepo(String),
    /// Local source file provided via --source.
    LocalSource(String),
    /// Only IDL available (interface, no handler bodies).
    IdlOnly,
    /// Only bytecode available (no source, no IDL).
    BytecodeOnly,
    /// Cloned from a git repository.
    GitRepo(String),
    /// Local Hardhat project.
    HardhatRepo(String),
    /// Local Anchor/Cargo workspace.
    AnchorRepo(String),
}

impl std::fmt::Display for SourceProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceProvenance::OnChainSource => write!(f, "on-chain source"),
            SourceProvenance::VerifiedBuildRepo(url) => {
                write!(f, "verified-build repo: {}", url)
            }
            SourceProvenance::LocalSource(path) => write!(f, "local source: {}", path),
            SourceProvenance::IdlOnly => write!(f, "IDL only (no handler source)"),
            SourceProvenance::BytecodeOnly => write!(f, "bytecode only (no source)"),
            SourceProvenance::GitRepo(url) => write!(f, "git repo: {}", url),
            SourceProvenance::HardhatRepo(path) => write!(f, "Hardhat project: {}", path),
            SourceProvenance::AnchorRepo(path) => write!(f, "Anchor project: {}", path),
        }
    }
}

/// What we fetched from a Solana program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchedSolanaProgram {
    /// The program address.
    pub program_id: String,
    /// Whether we could retrieve an IDL.
    pub has_idl: bool,
    /// The Anchor IDL JSON (if available).
    pub idl: Option<String>,
    /// The raw account data (always fetched for metadata).
    pub account_data: Option<String>,
    /// Program type description.
    pub program_type: String,
    /// Executor type (e.g. "bpf_loader_upgradeable").
    pub executor: String,
    /// Whether the program is deployed and upgradeable.
    pub is_deployed: bool,
    /// Where the analyzable source came from.
    pub provenance: SourceProvenance,
    /// Best-effort source link (e.g. from security.txt).
    pub source_link: Option<String>,
}

impl FetchedSolanaProgram {
    /// Whether this program has analyzable source code (not just IDL/bytecode).
    pub fn has_analyzable_source(&self) -> bool {
        matches!(
            self.provenance,
            SourceProvenance::OnChainSource
                | SourceProvenance::VerifiedBuildRepo(_)
                | SourceProvenance::LocalSource(_)
                | SourceProvenance::GitRepo(_)
                | SourceProvenance::HardhatRepo(_)
                | SourceProvenance::AnchorRepo(_)
        )
    }
}

/// Check if a string looks like a git URL (https, ssh, or .git suffix).
pub fn is_git_url(s: &str) -> bool {
    s.starts_with("https://github.com/")
        || s.starts_with("https://gitlab.com/")
        || s.starts_with("git@github.com:")
        || s.starts_with("git@gitlab.com:")
        || s.ends_with(".git")
}

/// Trait for fetching Solana program data via RPC.
///
/// All network access goes through this trait for testability.
pub trait SolanaSourceFetcher: Send + Sync {
    fn fetch_program(&self, program_id: &str) -> Result<FetchedSolanaProgram, ExplorerError>;
}

/// Solana RPC client.
#[cfg(feature = "live-fetch")]
pub struct SolanaRpcClient {
    http_client: reqwest::blocking::Client,
    config: SolanaRpcConfig,
}

#[cfg(feature = "live-fetch")]
impl SolanaRpcClient {
    pub fn new() -> Self {
        Self::with_config(SolanaRpcConfig::default())
    }

    pub fn with_config(config: SolanaRpcConfig) -> Self {
        Self {
            http_client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new()),
            config,
        }
    }

    /// Call a Solana RPC method.
    fn rpc_call(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, ExplorerError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        digger_egress::authorize_global(&self.config.rpc_url, "fetch-solana-source")
            .map_err(|e| ExplorerError::NetworkError(e.to_string()))?;

        let resp = self
            .http_client
            .post(&self.config.rpc_url)
            .json(&body)
            .send()
            .map_err(|e| ExplorerError::NetworkError(e.to_string()))?;

        if resp.status().as_u16() == 429 {
            return Err(ExplorerError::RateLimited);
        }

        let result: serde_json::Value = resp
            .json()
            .map_err(|e| ExplorerError::ApiError(e.to_string()))?;

        if let Some(error) = result.get("error") {
            return Err(ExplorerError::ApiError(format!("RPC error: {}", error)));
        }

        Ok(result
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }
}

#[cfg(feature = "live-fetch")]
impl Default for SolanaRpcClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "live-fetch")]
impl SolanaSourceFetcher for SolanaRpcClient {
    fn fetch_program(&self, program_id: &str) -> Result<FetchedSolanaProgram, ExplorerError> {
        let program_id = program_id.trim().to_string();

        // Validate program ID (base58, 32-44 chars)
        if program_id.len() < 32 || program_id.len() > 44 {
            return Err(ExplorerError::InvalidAddress(program_id));
        }

        // Step 1: Get account info to check if program exists
        let account_info = self.rpc_call(
            "getAccountInfo",
            &serde_json::json!([program_id, {"encoding": "jsonParsed"}]),
        )?;

        let account = account_info
            .get("value")
            .and_then(|v| v.as_object())
            .ok_or_else(|| ExplorerError::NotVerified(program_id.clone()))?;

        if account.get("data").is_none() || account.get("data").is_some_and(|d| d.is_null()) {
            return Err(ExplorerError::NotVerified(program_id.clone()));
        }

        let executor = account
            .get("owner")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let is_deployed = account
            .get("executable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Step 2: Try to fetch Anchor IDL
        let idl = self.try_fetch_idl(&program_id);
        let has_idl = idl.is_some();
        let program_type = if has_idl {
            "anchor".into()
        } else {
            "unknown".into()
        };

        Ok(FetchedSolanaProgram {
            program_id,
            has_idl,
            idl,
            account_data: None,
            program_type,
            executor,
            is_deployed,
            provenance: if has_idl {
                SourceProvenance::IdlOnly
            } else {
                SourceProvenance::BytecodeOnly
            },
            source_link: None,
        })
    }
}

#[cfg(feature = "live-fetch")]
impl SolanaRpcClient {
    /// Try to fetch Anchor IDL from the program's IDL account.
    fn try_fetch_idl(&self, _program_id: &str) -> Option<String> {
        // Anchor IDL is stored at a PDA: ["anchor:idl", program_id]
        // The IDL account address is derived from the program ID
        // For simplicity, we try the getAccountInfo with base58 address
        // In practice, the IDL address needs to be derived via PDA
        // This is a best-effort approach

        // Try fetching the IDL account directly
        // The actual IDL derivation is complex (requires base58 encoding)
        // For now, we return None if IDL is not directly available
        // A future pass could implement the full PDA derivation
        None
    }
}

/// Validate a Solana program ID (base58, 32-44 chars).
pub fn validate_program_id(program_id: &str) -> Result<(), ExplorerError> {
    let trimmed = program_id.trim();
    if trimmed.len() < 32 || trimmed.len() > 44 {
        return Err(ExplorerError::InvalidAddress(trimmed.to_string()));
    }
    // Base58 alphabet check (no 0, O, I, l)
    if !trimmed.chars().all(|c| {
        matches!(
            c,
            '1' | '2'
                | '3'
                | '4'
                | '5'
                | '6'
                | '7'
                | '8'
                | '9'
                | 'A'
                | 'B'
                | 'C'
                | 'D'
                | 'E'
                | 'F'
                | 'G'
                | 'H'
                | 'J'
                | 'K'
                | 'L'
                | 'M'
                | 'N'
                | 'P'
                | 'Q'
                | 'R'
                | 'S'
                | 'T'
                | 'U'
                | 'V'
                | 'W'
                | 'X'
                | 'Y'
                | 'Z'
                | 'a'
                | 'b'
                | 'c'
                | 'd'
                | 'e'
                | 'f'
                | 'g'
                | 'h'
                | 'i'
                | 'j'
                | 'k'
                | 'm'
                | 'n'
                | 'o'
                | 'p'
                | 'q'
                | 'r'
                | 's'
                | 't'
                | 'u'
                | 'v'
                | 'w'
                | 'x'
                | 'y'
                | 'z'
        )
    }) {
        return Err(ExplorerError::InvalidAddress(format!(
            "{} (contains non-base58 character)",
            trimmed
        )));
    }
    Ok(())
}
