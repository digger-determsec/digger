#![allow(clippy::needless_update, clippy::useless_vec, clippy::len_zero)]
/// Example program tests — verify Digger finds known vulnerability patterns.
use std::fs;
use std::path::Path;

use digger_graph::build_system_ir;
use digger_hypothesis::analyze_compat as analyze;
use digger_parser::parse_program;

fn run_on_example(file: &str, lang: &str) -> Vec<String> {
    let path = Path::new("../../examples").join(file);
    let code = fs::read_to_string(&path).expect("Failed to read example");
    let raw = parse_program(&code, lang);
    let ir = build_system_ir(raw);
    let findings = analyze(&ir);
    findings.iter().map(|f| f.kind.clone()).collect()
}

#[test]
fn test_vulnerable_sol_finds_external_call_risk() {
    let kinds = run_on_example("vulnerable.sol", "solidity");
    assert!(
        kinds
            .iter()
            .any(|k| k.contains("External") || k.contains("Reentrancy")),
        "Should detect external call risk in vulnerable.sol. Found: {:?}",
        kinds
    );
}

#[test]
fn test_vulnerable_sol_finds_missing_auth() {
    let kinds = run_on_example("vulnerable.sol", "solidity");
    assert!(
        kinds
            .iter()
            .any(|k| k.contains("Authority") || k.contains("authority")),
        "Should detect missing authority in vulnerable.sol. Found: {:?}",
        kinds
    );
}

#[test]
fn test_vulnerable_evm_finds_multiple_issues() {
    let kinds = run_on_example("vulnerable_evm.sol", "solidity");
    assert!(
        kinds.len() >= 3,
        "Should find at least 3 issues in vulnerable_evm.sol. Found: {}",
        kinds.len()
    );
}

#[test]
fn test_vulnerable_anchor_finds_issues() {
    let kinds = run_on_example("vulnerable_anchor.rs", "anchor");
    assert!(
        kinds.len() >= 2,
        "Should find at least 2 issues in vulnerable_anchor.rs. Found: {}",
        kinds.len()
    );
}

#[test]
fn test_safe_vault_no_critical() {
    let kinds = run_on_example("vault.sol", "solidity");
    let critical: Vec<_> = kinds
        .iter()
        .filter(|k| k.contains("Critical") || k.contains("critical"))
        .collect();
    assert!(
        critical.is_empty(),
        "Safe vault should have no critical findings. Found: {:?}",
        kinds
    );
}

#[test]
fn test_anchor_vault_clean() {
    let kinds = run_on_example("anchor_vault.rs", "anchor");
    // Safe anchor vault should have minimal findings
    assert!(
        kinds.len() <= 5,
        "Safe anchor vault should have minimal findings. Found: {}",
        kinds.len()
    );
}
