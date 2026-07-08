use crate::models::*;
/// Gen 3.3d — Exporters for Foundry, Anvil, Hardhat, Solana, LiteSVM, Anchor.
///
/// Generates execution-ready export formats. Never executes code.
use crate::transaction_builders::*;

/// Export target format.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ExportFormat {
    Foundry,
    Anvil,
    Hardhat,
    SolanaTestValidator,
    LiteSvm,
    AnchorTest,
}

/// Complete export result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportResult {
    pub format: ExportFormat,
    pub package_id: String,
    pub files: Vec<ExportFile>,
    pub instructions: String,
    pub deterministic: bool,
}

/// A file in the export.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportFile {
    pub path: String,
    pub content: String,
    pub description: String,
}

/// Export to Foundry test format.
pub fn export_foundry(pkg: &ExecutionPackage) -> ExportResult {
    let evm_txns = build_evm_transactions(
        &ExploitChain {
            chain_id: pkg.chain_id.clone(),
            goal: pkg
                .context
                .required_assets
                .first()
                .map(|a| format!("Extract {}", a.asset_id))
                .unwrap_or_default(),
            steps: vec![],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 0.0,
            severity: digger_ir::Severity::High,
            historical_similarity: vec![],
            rank: None,
            explanation: String::new(),
        },
        &crate::engine::SynthesisInputs {
            ir: None,
            expansion: None,
            transitions: None,
            lifecycles: None,
            temporal: None,
            actors: None,
            economics: None,
            verification: None,
            adversarial: None,
            protocol: None,
            surface: None,
        },
    );

    let test_code = format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract ExploitTest is Test {{
    function testExploit() public {{
        // Setup: fork mainnet at block {}
        vm.createSelectFork("mainnet", {});
        
        // Attack sequence
        {}
        
        // Assertions
        {}
    }}
}}"#,
        pkg.environment.fork_block.unwrap_or(0),
        pkg.environment.fork_block.unwrap_or(0),
        evm_txns
            .iter()
            .enumerate()
            .map(|(i, tx)| format!(
                "        // Step {}: {}\n        vm.prank(address(0xATTACKER));\n        {}({});",
                i,
                pkg.transactions
                    .get(i)
                    .map(|t| t.expected_state_changes.join(", "))
                    .unwrap_or_default(),
                tx.function_signature,
                tx.data
            ))
            .collect::<Vec<_>>()
            .join("\n\n"),
        pkg.replay_bundle
            .expected_outputs
            .iter()
            .map(|o| format!("        // {}", o))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    ExportResult {
        format: ExportFormat::Foundry,
        package_id: pkg.package_id.clone(),
        files: vec![
            ExportFile {
                path: "test/Exploit.t.sol".into(),
                content: test_code,
                description: "Foundry exploit test".into(),
            },
            ExportFile {
                path: "script/Exploit.s.sol".into(),
                content: "// Deployment script placeholder".into(),
                description: "Foundry deployment script".into(),
            },
        ],
        instructions: "Run: forge test --match-test testExploit -vvvv".into(),
        deterministic: true,
    }
}

/// Export to Anvil format.
pub fn export_anvil(pkg: &ExecutionPackage) -> ExportResult {
    let mut result = export_foundry(pkg);
    result.format = ExportFormat::Anvil;
    result.instructions =
        "1. Start anvil: anvil\n2. Run: forge test --fork-url http://127.0.0.1:8545".into();
    result
}

/// Export to Hardhat format.
pub fn export_hardhat(pkg: &ExecutionPackage) -> ExportResult {
    let test_code = format!(
        r#"const {{ expect }} = require("chai");
const {{ ethers }} = require("hardhat");

describe("Exploit Test", function () {{
    it("Should execute exploit", async function () {{
        // Fork at block {}
        await hre.network.provider.request({{
            method: "hardhat_reset",
            params: [{{ forking: {{ jsonRpcUrl: process.env.MAINNET_RPC, blockNumber: {} }} }}]
        }});
        
        // Attack steps: {}
        // Expected outcomes: {}
    }});
}});
"#,
        pkg.environment.fork_block.unwrap_or(0),
        pkg.environment.fork_block.unwrap_or(0),
        pkg.transactions.len(),
        pkg.replay_bundle.expected_outputs.len(),
    );

    ExportResult {
        format: ExportFormat::Hardhat,
        package_id: pkg.package_id.clone(),
        files: vec![ExportFile {
            path: "test/Exploit.test.js".into(),
            content: test_code,
            description: "Hardhat exploit test".into(),
        }],
        instructions: "Run: npx hardhat test test/Exploit.test.js".into(),
        deterministic: true,
    }
}

/// Export to Solana test validator format.
pub fn export_solana_test_validator(pkg: &ExecutionPackage) -> ExportResult {
    let config = format!(
        r#"{{
  "cluster": "localnet",
  "clone": {{
    "url": "{}",
    "slot": {}
  }},
  "accounts": {},
  "programs": {}
}}"#,
        pkg.environment
            .rpc_url
            .as_deref()
            .unwrap_or("https://api.mainnet-beta.solana.com"),
        pkg.environment.fork_block.unwrap_or(0),
        serde_json::to_string_pretty(&pkg.context.required_accounts).unwrap_or("[]".into()),
        serde_json::to_string_pretty(&pkg.context.required_contracts).unwrap_or("[]".into()),
    );

    ExportResult {
        format: ExportFormat::SolanaTestValidator,
        package_id: pkg.package_id.clone(),
        files: vec![
            ExportFile {
                path: "test-validator-config.json".into(),
                content: config,
                description: "Solana test validator config".into(),
            },
            ExportFile {
                path: "tests/exploit_test.ts".into(),
                content: "// Anchor test placeholder".into(),
                description: "TypeScript test file".into(),
            },
        ],
        instructions: "Run: solana-test-validator --config test-validator-config.json".into(),
        deterministic: true,
    }
}

/// Export to LiteSVM format.
pub fn export_litesvm(pkg: &ExecutionPackage) -> ExportResult {
    let mut result = export_solana_test_validator(pkg);
    result.format = ExportFormat::LiteSvm;
    result.instructions = "Run with LiteSVM runtime for fast local testing".into();
    result
}

/// Export to Anchor test harness format.
pub fn export_anchor(pkg: &ExecutionPackage) -> ExportResult {
    let test_code = format!(
        r#"use anchor_lang::prelude::*;
use solana_program_test::*;

#[tokio::test]
async fn test_exploit() {{
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new("exploit_target", program_id, None);
    
    // Add required accounts
    {}
    
    let (mut banks_client, payer, recent_blockhash) = program_test.start().start().await;
    
    // Execute attack steps: {}
    // Assert expected outcomes
}}"#,
        pkg.context
            .required_accounts
            .iter()
            .map(|a| format!(
                "    program_test.add_account(\"{}\", /* balance */);",
                a.address
            ))
            .collect::<Vec<_>>()
            .join("\n"),
        pkg.transactions.len(),
    );

    ExportResult {
        format: ExportFormat::AnchorTest,
        package_id: pkg.package_id.clone(),
        files: vec![ExportFile {
            path: "tests/exploit.rs".into(),
            content: test_code,
            description: "Anchor test harness".into(),
        }],
        instructions: "Run: anchor test".into(),
        deterministic: true,
    }
}

/// Export to all formats.
pub fn export_all(pkg: &ExecutionPackage) -> Vec<ExportResult> {
    vec![
        export_foundry(pkg),
        export_anvil(pkg),
        export_hardhat(pkg),
        export_solana_test_validator(pkg),
        export_litesvm(pkg),
        export_anchor(pkg),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pkg() -> ExecutionPackage {
        ExecutionPackage {
            package_id: "test".into(),
            chain_id: "test".into(),
            protocol_id: "test".into(),
            chain_type: "evm".into(),
            context: ExecutionContext {
                required_contracts: vec![],
                required_accounts: vec![],
                required_authorities: vec![],
                required_assets: vec![AssetRequirement {
                    asset_id: "USDC".into(),
                    asset_type: "token".into(),
                    amount: 1000.0,
                    description: "test".into(),
                }],
                required_balances: vec![],
                required_approvals: vec![],
                required_signers: vec![SignerRequirement {
                    signer_id: "attacker".into(),
                    signer_type: "eoa".into(),
                    key_type: "secp256k1".into(),
                    description: "test".into(),
                }],
                required_pdas: vec![],
                required_storage: vec![],
                required_config: vec![],
            },
            transactions: vec![],
            environment: EnvironmentRequirements {
                fork_block: Some(18000000),
                chain_id: Some(1),
                rpc_url: None,
                deployed_contracts: vec![],
                token_balances: vec![],
                oracle_values: vec![],
                governance_state: vec![],
                validator_config: None,
                feature_gates: vec![],
                clock_requirements: None,
            },
            replay_bundle: ReplayBundle {
                bundle_id: "test".into(),
                version: "1.0.0".into(),
                chain_type: "evm".into(),
                metadata: BundleMetadata {
                    created_at: "test".into(),
                    chain_id: "1".into(),
                    protocol_id: "test".into(),
                    exploit_goal: "DrainAssets".into(),
                    total_steps: 0,
                    total_transactions: 0,
                    deterministic_hash: "abc".into(),
                },
                transaction_sequence: vec![],
                execution_dependencies: vec![],
                required_artifacts: vec![],
                expected_outputs: vec![],
                cleanup_instructions: vec![],
            },
            validation: PackageValidation {
                complete: true,
                missing_prerequisites: vec![],
                inconsistent_transactions: vec![],
                reproducible: true,
                explanation: "test".into(),
            },
            readiness_score: 0.8,
            blockers: vec![],
        }
    }

    #[test]
    fn test_foundry_export() {
        let pkg = test_pkg();
        let result = export_foundry(&pkg);
        assert_eq!(result.format, ExportFormat::Foundry);
        assert!(!result.files.is_empty());
        assert!(result.deterministic);
    }

    #[test]
    fn test_all_exports() {
        let pkg = test_pkg();
        let results = export_all(&pkg);
        assert_eq!(results.len(), 6);
        for r in &results {
            assert!(r.deterministic);
            assert!(!r.files.is_empty());
        }
    }

    #[test]
    fn test_export_anchor() {
        let pkg = test_pkg();
        let result = export_anchor(&pkg);
        assert_eq!(result.format, ExportFormat::AnchorTest);
        assert!(!result.files.is_empty());
        assert!(result.deterministic);
    }

    #[test]
    fn test_export_anvil() {
        let pkg = test_pkg();
        let result = export_anvil(&pkg);
        assert_eq!(result.format, ExportFormat::Anvil);
        assert!(!result.files.is_empty());
        assert!(result.deterministic);
    }

    #[test]
    fn test_export_hardhat() {
        let pkg = test_pkg();
        let result = export_hardhat(&pkg);
        assert_eq!(result.format, ExportFormat::Hardhat);
        assert!(!result.files.is_empty());
        assert!(result.deterministic);
    }

    #[test]
    fn test_export_litesvm() {
        let pkg = test_pkg();
        let result = export_litesvm(&pkg);
        assert_eq!(result.format, ExportFormat::LiteSvm);
        assert!(!result.files.is_empty());
        assert!(result.deterministic);
    }

    #[test]
    fn test_export_solana_test_validator() {
        let pkg = test_pkg();
        let result = export_solana_test_validator(&pkg);
        assert_eq!(result.format, ExportFormat::SolanaTestValidator);
        assert!(!result.files.is_empty());
        assert!(result.deterministic);
    }
}
