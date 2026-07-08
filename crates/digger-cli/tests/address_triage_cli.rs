//! Fixture-backed tests for audit-triage --address and --path.
//! All tests use local fixtures. Zero network calls.

use std::process::Command;

fn digger_bin_path() -> std::path::PathBuf {
    let base = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join("digger");
    if base.exists() {
        base
    } else {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target")
            .join("debug")
            .join("digger.exe")
    }
}

fn fixture_path(name: &str) -> String {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(name)
        .to_string_lossy()
        .to_string()
}

fn run_triage(path: &str, chain: &str, extra_args: &[&str]) -> (bool, String) {
    let bin = digger_bin_path();
    let mut cmd = Command::new(&bin);
    cmd.arg("audit-triage")
        .arg("--path")
        .arg(path)
        .arg("--chain")
        .arg(chain)
        .arg("--json");
    for arg in extra_args {
        cmd.arg(arg);
    }
    let output = cmd.output().expect("failed to execute");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (output.status.success(), stdout)
}

// ── Existing test: evm triage packet shape ──

#[test]
fn evm_triage_packet_has_file_class() {
    let (ok, stdout) = run_triage(&fixture_path("examples/evm-basic"), "evm", &[]);
    assert!(ok, "triage must succeed");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(
        v["schema_version"].as_str().unwrap(),
        "digger.audit_triage_packet.v1"
    );
    // Verify file_class is present on surfaces
    if let Some(surfaces) = v["surfaces_scanned"].as_array() {
        for s in surfaces {
            assert!(
                s.get("file_class").is_some(),
                "Every surface must have file_class field: {:?}",
                s["name"]
            );
        }
    }
}

// ── --address validation tests (no network) ──

#[test]
fn address_requires_chain() {
    let bin = digger_bin_path();
    let output = Command::new(&bin)
        .args([
            "audit-triage",
            "--address",
            "0x1234567890123456789012345678901234567890",
        ])
        .output()
        .expect("failed");
    assert!(
        !output.status.success(),
        "Should fail without --chain or with invalid chain"
    );
}

#[test]
fn path_and_address_mutually_exclusive() {
    let bin = digger_bin_path();
    let output = Command::new(&bin)
        .args([
            "audit-triage",
            "--path",
            &fixture_path("examples/evm-basic"),
            "--address",
            "0x1234567890123456789012345678901234567890",
        ])
        .output()
        .expect("failed");
    assert!(
        !output.status.success(),
        "Should fail when both --path and --address given"
    );
}

// ── Solana triage packet shape ──

#[test]
fn solana_triage_packet_has_file_class() {
    let (ok, stdout) = run_triage(&fixture_path("examples/solana-basic"), "solana", &[]);
    assert!(ok, "triage must succeed");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(
        v["schema_version"].as_str().unwrap(),
        "digger.audit_triage_packet.v1"
    );
    assert_eq!(v["chain"].as_str().unwrap(), "solana");
    if let Some(surfaces) = v["surfaces_scanned"].as_array() {
        for s in surfaces {
            assert!(
                s.get("file_class").is_some(),
                "Every surface must have file_class: {:?}",
                s["name"]
            );
        }
    }
}

// ── Engine-derived hypotheses exist ──

#[test]
fn evm_triage_has_engine_hypotheses() {
    let (ok, stdout) = run_triage(&fixture_path("examples/evm-basic"), "evm", &[]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert!(
        !v["candidate_hypotheses"].as_array().unwrap().is_empty(),
        "Should have at least one candidate hypothesis"
    );
}

// ── Provenance field presence ──

#[test]
fn triage_packet_has_provenance_field() {
    let (ok, stdout) = run_triage(&fixture_path("examples/evm-basic"), "evm", &[]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    // provenance may be null for local path scans (only set for --address)
    // but the field must exist in the schema
    assert!(
        v.get("provenance").is_some(),
        "Packet must have provenance field"
    );
}

// ── Determinism test ──

#[test]
fn triage_packet_is_deterministic() {
    let (_, stdout1) = run_triage(&fixture_path("examples/evm-basic"), "evm", &[]);
    let (_, stdout2) = run_triage(&fixture_path("examples/evm-basic"), "evm", &[]);
    // Both should produce valid JSON
    let v1: serde_json::Value = serde_json::from_str(&stdout1).expect("invalid JSON run 1");
    let v2: serde_json::Value = serde_json::from_str(&stdout2).expect("invalid JSON run 2");
    // Correlation IDs should be identical for same input
    assert_eq!(
        v1["correlation_id"].as_str(),
        v2["correlation_id"].as_str(),
        "Same input must produce same correlation_id"
    );
    // Hypothesis counts should match
    assert_eq!(
        v1["candidate_hypotheses"].as_array().unwrap().len(),
        v2["candidate_hypotheses"].as_array().unwrap().len(),
        "Same input must produce same hypothesis count"
    );
}

// ── Oversized input guard: 65+ .sol files → clean error, no OOM ──

#[test]
fn oversized_input_returns_clean_error() {
    let tmp = std::env::temp_dir().join("digger_oversized_test");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create tmp dir");

    // Create 65 tiny .sol files
    for i in 0..65 {
        let path = tmp.join(format!("contract_{}.sol", i));
        std::fs::write(&path, "pragma solidity ^0.8.0; contract C{}").unwrap();
    }

    let bin = digger_bin_path();
    let output = Command::new(&bin)
        .args([
            "audit-triage",
            "--path",
            tmp.to_str().unwrap(),
            "--chain",
            "evm",
            "--json",
        ])
        .output()
        .expect("failed");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        !output.status.success(),
        "Should fail on oversized input, not OOM"
    );
    assert!(
        stderr.contains("too large to parse safely") || stderr.contains("65"),
        "Error message should explain why: got stderr: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
