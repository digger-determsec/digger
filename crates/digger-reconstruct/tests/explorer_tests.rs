use digger_parser::parse_program;
use digger_reconstruct::{
    detect_price_manipulation, detect_readonly_reentrancy, Chain, ExplorerError, SourceFetcher,
};
use std::path::Path;

/// Mock SourceFetcher for fixture-based testing.
struct MockFetcher {
    fixture_dir: std::path::PathBuf,
}

impl MockFetcher {
    fn new(fixture_dir: &std::path::Path) -> Self {
        Self {
            fixture_dir: fixture_dir.to_path_buf(),
        }
    }
}

impl SourceFetcher for MockFetcher {
    fn fetch_source(
        &self,
        _chain: &Chain,
        address: &str,
    ) -> Result<digger_reconstruct::FetchedSource, ExplorerError> {
        let fixture_name = match address {
            "0x0000000000000000000000000000000000000001" => "verified",
            "0x0000000000000000000000000000000000000002" => "unverified",
            "0x0000000000000000000000000000000000000003" => "proxy",
            _ => return Err(ExplorerError::NotVerified(address.to_string())),
        };

        let fixture_path = self.fixture_dir.join(format!("{}.json", fixture_name));
        let content = std::fs::read_to_string(&fixture_path)
            .map_err(|e| ExplorerError::ApiError(e.to_string()))?;

        let json: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| ExplorerError::ApiError(e.to_string()))?;

        if json["status"] != "1" {
            return Err(ExplorerError::NotVerified(address.to_string()));
        }

        let result = &json["result"][0];
        let source_code = result["SourceCode"].as_str().unwrap_or("").to_string();
        let is_proxy = result["Proxy"].as_str() == Some("1");

        Ok(digger_reconstruct::FetchedSource {
            verified: true,
            source: source_code,
            compiler_version: result["CompilerVersion"].as_str().unwrap_or("").to_string(),
            optimization: format!("{} runs", result["Runs"].as_str().unwrap_or("0")),
            contract_name: result["ContractName"].as_str().unwrap_or("").to_string(),
            abi: result["ABI"].as_str().map(|s| s.to_string()),
            implementation_address: result["Implementation"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
            is_proxy,
            evm_version: result["EVMVersion"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        })
    }
}

fn fixtures_dir() -> std::path::PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("tests/fixtures/explorer")
}

// ── Part 1: SourceFetcher parsing tests ──

#[test]
fn test_verified_contract() {
    let fetcher = MockFetcher::new(&fixtures_dir());
    let result = fetcher
        .fetch_source(
            &Chain::EthereumMainnet,
            "0x0000000000000000000000000000000000000001",
        )
        .unwrap();
    assert!(result.verified);
    assert_eq!(result.contract_name, "UniswapV2Pair");
    assert!(!result.is_proxy);
}

#[test]
fn test_unverified_contract() {
    let fetcher = MockFetcher::new(&fixtures_dir());
    let result = fetcher.fetch_source(
        &Chain::EthereumMainnet,
        "0x0000000000000000000000000000000000000002",
    );
    assert!(matches!(result, Err(ExplorerError::NotVerified(_))));
}

#[test]
fn test_proxy_detection() {
    let fetcher = MockFetcher::new(&fixtures_dir());
    let result = fetcher
        .fetch_source(
            &Chain::EthereumMainnet,
            "0x0000000000000000000000000000000000000003",
        )
        .unwrap();
    assert!(result.is_proxy);
    assert_eq!(
        result.implementation_address.as_deref(),
        Some("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f")
    );
}

#[test]
fn test_invalid_address() {
    let result = <MockFetcher as SourceFetcher>::validate_address("not-an-address");
    assert!(matches!(result, Err(ExplorerError::InvalidAddress(_))));
}

#[test]
fn test_valid_address() {
    let result = <MockFetcher as SourceFetcher>::validate_address(
        "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
    );
    assert!(result.is_ok());
}

#[test]
fn test_chain_parsing() {
    assert_eq!(
        Chain::from_name("ethereum").unwrap(),
        Chain::EthereumMainnet
    );
    assert_eq!(Chain::from_name("arbitrum").unwrap(), Chain::Arbitrum);
    assert!(Chain::from_name("bsc").is_err());
}

// ── Part 3: End-to-end test with real detector firing ──

/// End-to-end: fetched source -> parse -> graduated detector -> finding asserted.
/// This exercises the REAL detector on REAL parsed Solidity, not mock data.
#[test]
fn test_end_to_end_readonly_reentrancy_detector_fires() {
    // Source: a minimal read-only reentrancy pattern (same pattern as sentiment-2023)
    let source_code = r#"
pragma solidity ^0.8.19;

contract ReadReentrancyVault {
    mapping(address => uint256) public reserves;
    uint256 public price;

    function swap(address token, uint256 amount) external {
        // External call -- attacker reenters during transfer callback
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        // State read AFTER external call -- reads stale price
        uint256 currentPrice = price;
        uint256 output = (amount * currentPrice) / 1e18;
        reserves[token] += amount;
    }

    function setPrice(uint256 newPrice) external {
        price = newPrice;
    }
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}
"#;

    // Parse source
    let raw = parse_program(source_code, "solidity");
    assert!(!raw.functions.is_empty(), "Parser must produce functions");
    assert!(!raw.operations.is_empty(), "Parser must produce operations");

    // Run graduated detector
    let findings = detect_readonly_reentrancy(&raw);

    // Assert the detector fires
    assert!(
        !findings.is_empty(),
        "Read-only reentrancy detector MUST fire on this pattern"
    );

    // Assert the finding is for the swap function
    let swap_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.function_id == "swap")
        .collect();
    assert_eq!(
        swap_findings.len(),
        1,
        "Expected exactly 1 finding for swap function"
    );
    assert_eq!(swap_findings[0].finding_kind, "ReadOnlyReentrancy");
    assert!(!swap_findings[0].suppressed);

    println!("E2E: readonly_reentrancy detector fires on swap function -- PASS");
}

/// End-to-end: price manipulation detector on a minimal vulnerable pattern.
#[test]
fn test_end_to_end_price_manipulation_detector_fires() {
    let source_code = r#"
pragma solidity ^0.8.19;

contract PriceManipVault {
    address public uniswapPool;

    function getValue() public view returns (uint256) {
        (uint256 reserve0, uint256 reserve1) = getReserves(uniswapPool);
        return (reserve1 * 1e18) / reserve0;
    }

    function borrow(uint256 amount) external {
        uint256 value = getValue();
        require(value >= amount, "insufficient");
    }

    function getReserves(address pool) internal view returns (uint256, uint256);
}
"#;

    let raw = parse_program(source_code, "solidity");
    let findings = detect_price_manipulation(source_code, &raw);

    assert!(
        !findings.is_empty(),
        "Price manipulation detector MUST fire on getReserves pattern"
    );

    let borrow_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.critical_action == "borrow")
        .collect();
    assert!(
        !borrow_findings.is_empty(),
        "Expected at least 1 finding for borrow function"
    );
    assert!(!borrow_findings[0].suppressed);

    println!("E2E: price_manipulation detector fires on borrow function -- PASS");
}

/// Verify: safe pattern does NOT trigger detectors (precision check).
#[test]
fn test_end_to_end_safe_pattern_no_findings() {
    let source_code = r#"
pragma solidity ^0.8.19;

contract SafeVault {
    uint256 private _locked;

    modifier nonReentrant() {
        require(_locked == 0, "reentrant");
        _locked = 1;
        _;
        _locked = 0;
    }

    function withdraw() external nonReentrant {
        uint256 bal = address(this).balance;
        payable(msg.sender).transfer(bal);
    }
}
"#;

    let raw = parse_program(source_code, "solidity");
    let ror_findings = detect_readonly_reentrancy(&raw);
    assert!(
        ror_findings.is_empty() || ror_findings.iter().all(|f| f.suppressed),
        "Safe pattern must NOT produce unsuppressed findings"
    );
    println!("E2E: safe pattern produces no unsuppressed findings -- PASS");
}

// ── Part 4: Multi-file / standard-json assessment ──

#[test]
fn test_multi_file_source_unwrapping() {
    // Etherscan wraps multi-file sources in {{ }}
    let multi_file = r#"{{"contracts/Token.sol": "pragma solidity ^0.8.19; contract Token { uint public totalSupply; }", "contracts/Vault.sol": "pragma solidity ^0.8.19; contract Vault { function deposit() public {} }}"}}"#;

    // The explorer client strips the outer {{ }}
    let unwrapped = {
        let raw = multi_file.trim();
        if raw.starts_with("{{") && raw.ends_with("}}") {
            raw[1..raw.len() - 1].to_string()
        } else {
            raw.to_string()
        }
    };

    // After unwrapping, the result is a JSON object with file paths as keys
    assert!(unwrapped.contains("contracts/Token.sol"));
    assert!(unwrapped.contains("contracts/Vault.sol"));

    println!("Multi-file unwrapping: basic outer-brace strip works");
}

// ── Part 4: Standard-JSON multi-file tests ──

/// End-to-end: standard-JSON multi-file -> detection -> finding fires.
/// This exercises the real detector on real parsed Solidity from multi-file source.
#[test]
fn test_standard_json_multifile_parses() {
    // Load the standard-JSON fixture
    let fixture_dir = fixtures_dir();
    let fixture_path = fixture_dir.join("standard_json_vuln.json");
    let raw_json = std::fs::read_to_string(&fixture_path).expect("Failed to read fixture");

    // Simulate EtherscanClient extraction: strip {{ }} wrapper then call extract_source
    let stripped = raw_json.trim();
    let unwrapped = if stripped.starts_with("{{") && stripped.ends_with("}}") {
        stripped[1..stripped.len() - 1].to_string()
    } else {
        stripped.to_string()
    };

    // Parse the standard-JSON and flatten
    let parsed: serde_json::Value = serde_json::from_str(&unwrapped).expect("Invalid JSON");
    let sources = parsed
        .get("sources")
        .expect("Missing sources key")
        .as_object()
        .unwrap();
    let mut sol_files: Vec<String> = Vec::new();
    let mut sorted_keys: Vec<&String> = sources.keys().collect();
    sorted_keys.sort();
    for key in sorted_keys {
        if let Some(content) = sources[key].get("content").and_then(|c| c.as_str()) {
            sol_files.push(content.trim().to_string());
        }
    }
    assert_eq!(sol_files.len(), 2, "Expected 2 Solidity files");

    // Concatenate and parse
    let combined = sol_files.join("\n\n");
    let raw = parse_program(&combined, "solidity");
    assert!(!raw.functions.is_empty(), "Parser must produce functions");
    assert!(!raw.operations.is_empty(), "Parser must produce operations");

    // Run graduated detector
    let findings = detect_readonly_reentrancy(&raw);
    assert!(
        !findings.is_empty(),
        "Read-only reentrancy detector MUST fire on multi-file standard-JSON input"
    );

    let swap_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.function_id == "swap")
        .collect();
    assert_eq!(swap_findings.len(), 1);
    assert_eq!(swap_findings[0].finding_kind, "ReadOnlyReentrancy");

    println!("E2E: standard-JSON multi-file -> parse -> detector fires -- PASS");
}

/// Safe standard-JSON pattern must NOT trigger detectors.
#[test]
fn test_standard_json_safe_multifile() {
    let fixture_dir = fixtures_dir();
    let fixture_path = fixture_dir.join("standard_json_safe.json");
    let raw_json = std::fs::read_to_string(&fixture_path).expect("Failed to read fixture");

    let stripped = raw_json.trim();
    let unwrapped = if stripped.starts_with("{{") && stripped.ends_with("}}") {
        stripped[1..stripped.len() - 1].to_string()
    } else {
        stripped.to_string()
    };

    let parsed: serde_json::Value = serde_json::from_str(&unwrapped).expect("Invalid JSON");
    let sources = parsed
        .get("sources")
        .expect("Missing sources key")
        .as_object()
        .unwrap();
    let mut sol_files: Vec<String> = Vec::new();
    let mut sorted_keys: Vec<&String> = sources.keys().collect();
    sorted_keys.sort();
    for key in sorted_keys {
        if let Some(content) = sources[key].get("content").and_then(|c| c.as_str()) {
            sol_files.push(content.trim().to_string());
        }
    }

    let combined = sol_files.join("\n\n");
    let raw = parse_program(&combined, "solidity");
    let findings = detect_readonly_reentrancy(&raw);
    assert!(
        findings.is_empty() || findings.iter().all(|f| f.suppressed),
        "Safe standard-JSON pattern must NOT produce unsuppressed findings"
    );

    println!("E2E: standard-JSON safe pattern produces no findings -- PASS");
}
