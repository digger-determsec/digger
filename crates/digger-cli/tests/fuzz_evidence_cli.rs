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
        .join("crates")
        .join("digger-fuzz-maturity")
        .join("src")
        .join("fixtures")
        .join(name)
        .to_str()
        .unwrap()
        .to_string()
}

#[test]
fn cli_fuzz_evidence_foundry_failure() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "foundry",
            "--chain",
            "evm",
            "--artifact",
            &fixture_path("foundry_invariant_failure.txt"),
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(
        output.status.success(),
        "must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["report_type"], "fuzz_evidence");
    assert_eq!(json["tool"], "foundry");
    assert_eq!(json["chain"], "evm");
    assert_eq!(json["is_vulnerability_finding"], false);
    assert_eq!(json["confidence_ceiling"], "invariant_failed");
    assert!(json["invariant_name"].as_str().is_some());
    assert!(json["counterexample"].as_str().is_some());
}

#[test]
fn cli_fuzz_evidence_replay_fixture() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "foundry",
            "--chain",
            "evm",
            "--artifact",
            &fixture_path("foundry_invariant_replay.txt"),
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["confidence_ceiling"], "failure_replayed");
    assert!(json["replay_command"].as_str().is_some());
}

#[test]
fn cli_fuzz_evidence_unsupported_tool() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "mythril",
            "--chain",
            "evm",
            "--artifact",
            &fixture_path("foundry_invariant_failure.txt"),
        ])
        .output()
        .expect("run failed");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("foundry") || stderr.contains("echidna") || stderr.contains("medusa"));
}

#[test]
fn cli_fuzz_evidence_unsupported_chain() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "foundry",
            "--chain",
            "solana",
            "--artifact",
            &fixture_path("foundry_invariant_failure.txt"),
        ])
        .output()
        .expect("run failed");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("evm") || stderr.contains("not implemented"));
}

#[test]
fn cli_fuzz_evidence_nonexistent_path() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "foundry",
            "--chain",
            "evm",
            "--artifact",
            "/nonexistent/path/12345.txt",
        ])
        .output()
        .expect("run failed");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not found") || stderr.contains("Failed to read"));
}

#[test]
fn cli_fuzz_evidence_no_vulnerability_label() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "foundry",
            "--chain",
            "evm",
            "--artifact",
            &fixture_path("foundry_invariant_failure.txt"),
            "--json",
        ])
        .output()
        .expect("run failed");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["is_vulnerability_finding"], false);
    assert!(!json["confidence_ceiling"]
        .as_str()
        .unwrap()
        .contains("minimized"));
    assert!(!json["confidence_ceiling"]
        .as_str()
        .unwrap()
        .contains("poc_test"));
}

#[test]
fn cli_fuzz_evidence_echidna_failure() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "echidna",
            "--chain",
            "evm",
            "--artifact",
            &fixture_path("echidna_failure.txt"),
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(
        output.status.success(),
        "must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["report_type"], "fuzz_evidence");
    assert_eq!(json["tool"], "echidna");
    assert_eq!(json["chain"], "evm");
    assert_eq!(json["is_vulnerability_finding"], false);
    assert_eq!(json["confidence_ceiling"], "invariant_failed");
    assert!(json["invariant_name"].as_str().is_some());
    assert!(json["counterexample"].as_str().is_some());
}

#[test]
fn cli_fuzz_evidence_echidna_replay() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "echidna",
            "--chain",
            "evm",
            "--artifact",
            &fixture_path("echidna_replay.txt"),
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["confidence_ceiling"], "failure_replayed");
    assert!(json["replay_command"].as_str().is_some());
}

#[test]
fn cli_fuzz_evidence_medusa_failure() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "medusa",
            "--chain",
            "evm",
            "--artifact",
            &fixture_path("medusa_failure.txt"),
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(
        output.status.success(),
        "must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["report_type"], "fuzz_evidence");
    assert_eq!(json["tool"], "medusa");
    assert_eq!(json["chain"], "evm");
    assert_eq!(json["is_vulnerability_finding"], false);
    assert_eq!(json["confidence_ceiling"], "invariant_failed");
    assert!(json["invariant_name"].as_str().is_some());
    assert!(json["counterexample"].as_str().is_some());
}

#[test]
fn cli_fuzz_evidence_medusa_replay() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "medusa",
            "--chain",
            "evm",
            "--artifact",
            &fixture_path("medusa_replay.txt"),
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["confidence_ceiling"], "failure_replayed");
    assert!(json["replay_command"].as_str().is_some());
}

#[test]
fn cli_fuzz_evidence_cross_tool_schema_contract() {
    let tools = [
        ("foundry", "evm", "foundry_invariant_failure.txt"),
        ("echidna", "evm", "echidna_failure.txt"),
        ("medusa", "evm", "medusa_failure.txt"),
        ("crucible", "solana", "crucible_failure.json"),
    ];
    for (tool, chain, fixture) in tools {
        let output = Command::new(digger_bin_path())
            .args([
                "fuzz-evidence",
                "--tool",
                tool,
                "--chain",
                chain,
                "--artifact",
                &fixture_path(fixture),
                "--json",
            ])
            .output()
            .expect("run failed");

        assert!(
            output.status.success(),
            "{} must exit 0, stderr: {}",
            tool,
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
        assert_eq!(json["chain"], chain, "{} chain", tool);
        assert_eq!(json["tool"], tool, "{} tool label", tool);
        assert_eq!(json["report_type"], "fuzz_evidence", "{} report_type", tool);
        assert_eq!(
            json["is_vulnerability_finding"], false,
            "{} must not be vuln finding",
            tool
        );
        let cc = json["confidence_ceiling"].as_str().unwrap();
        assert!(
            cc == "invariant_failed" || cc == "failure_replayed",
            "{} confidence must be invariant_failed or failure_replayed, got: {}",
            tool,
            cc
        );
        assert!(
            !cc.contains("failure_minimized"),
            "{} no failure_minimized",
            tool
        );
        assert!(
            !cc.contains("poc_test_generated"),
            "{} no poc_test_generated",
            tool
        );
        assert!(!cc.contains("graduated"), "{} no graduated", tool);
        let has_name = json["invariant_name"]
            .as_str()
            .is_some_and(|s| !s.is_empty());
        let has_ce = json["counterexample"]
            .as_str()
            .is_some_and(|s| !s.is_empty());
        assert!(
            has_name || has_ce,
            "{} must extract invariant_name or counterexample",
            tool
        );
    }
}

#[test]
fn cli_fuzz_evidence_cross_tool_replay_downgrade() {
    let replay_fixtures = [
        ("foundry", "evm", "foundry_invariant_replay.txt"),
        ("echidna", "evm", "echidna_replay.txt"),
        ("medusa", "evm", "medusa_replay.txt"),
        ("crucible", "solana", "crucible_replay.json"),
    ];
    for (tool, chain, fixture) in replay_fixtures {
        let output = Command::new(digger_bin_path())
            .args([
                "fuzz-evidence",
                "--tool",
                tool,
                "--chain",
                chain,
                "--artifact",
                &fixture_path(fixture),
                "--json",
            ])
            .output()
            .expect("run failed");

        assert!(
            output.status.success(),
            "{} replay must exit 0, stderr: {}",
            tool,
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
        assert_eq!(
            json["confidence_ceiling"], "failure_replayed",
            "{} replay fixture must produce failure_replayed",
            tool
        );
        assert!(
            json["replay_command"].as_str().is_some(),
            "{} replay fixture must have replay_command",
            tool
        );
    }
}

#[test]
fn cli_fuzz_evidence_crucible_failure() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "crucible",
            "--chain",
            "solana",
            "--artifact",
            &fixture_path("crucible_failure.json"),
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(
        output.status.success(),
        "must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["report_type"], "fuzz_evidence");
    assert_eq!(json["tool"], "crucible");
    assert_eq!(json["chain"], "solana");
    assert_eq!(json["is_vulnerability_finding"], false);
    assert_eq!(json["confidence_ceiling"], "invariant_failed");
    assert!(json["invariant_name"].as_str().is_some());
    assert!(json["counterexample"].as_str().is_some());
}

#[test]
fn cli_fuzz_evidence_crucible_wrong_chain() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "crucible",
            "--chain",
            "evm",
            "--artifact",
            &fixture_path("crucible_failure.json"),
        ])
        .output()
        .expect("run failed");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("solana") || stderr.contains("chain"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn cli_fuzz_evidence_foundry_wrong_chain() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "foundry",
            "--chain",
            "solana",
            "--artifact",
            &fixture_path("foundry_invariant_failure.txt"),
        ])
        .output()
        .expect("run failed");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("evm") || stderr.contains("chain"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn cli_fuzz_evidence_foundry_smoke_name_not_in() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "foundry",
            "--chain",
            "evm",
            "--artifact",
            &fixture_path("foundry_smoke_failure.txt"),
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(
        output.status.success(),
        "must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let name = json["invariant_name"]
        .as_str()
        .expect("invariant_name must be present");
    assert!(
        name.contains("invariant_counter_never_negative"),
        "invariant_name should contain the real function name, got: {}",
        name
    );
    assert_ne!(name, "in", "invariant_name must not be the word 'in'");
}

#[test]
fn cli_fuzz_evidence_crucible_smoke_parses() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-evidence",
            "--tool",
            "crucible",
            "--chain",
            "solana",
            "--artifact",
            &fixture_path("crucible_smoke_failure.json"),
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(
        output.status.success(),
        "must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["tool"], "crucible");
    assert_eq!(json["chain"], "solana");
    assert_eq!(
        json["invariant_name"].as_str(),
        Some("staking_invariant_no_negative_balance")
    );
    assert_eq!(json["is_vulnerability_finding"], false);
    assert_eq!(json["confidence_ceiling"], "invariant_failed");
    let ce = json["counterexample"]
        .as_str()
        .expect("counterexample must be present");
    assert!(
        ce.contains("deposit"),
        "counterexample must contain actions"
    );
    assert!(ce.contains("withdraw"));
}
