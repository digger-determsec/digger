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
        .join("digger-repo-intelligence")
        .join("tests")
        .join("fixtures")
        .join(name)
        .to_str()
        .unwrap()
        .to_string()
}

#[test]
fn cli_repo_intel_evm_json_smoke() {
    let output = Command::new(digger_bin_path())
        .args([
            "repo-intelligence",
            "--path",
            &fixture_path("evm-basic"),
            "--chain",
            "evm",
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
    assert_eq!(json["schema_version"], "digger.repo_intelligence.v1");
    assert_eq!(json["report_kind"], "repo_intelligence");
    assert!(json["digger_version"].as_str().is_some());
    assert_eq!(json["chain"], "evm");
    assert!(json["surfaces"].is_array());
    assert!(json["unknowns"].is_array());
    assert!(!json["surfaces"].as_array().unwrap().is_empty());
}

#[test]
fn cli_repo_intel_solana_json_smoke() {
    let output = Command::new(digger_bin_path())
        .args([
            "repo-intelligence",
            "--path",
            &fixture_path("solana-basic"),
            "--chain",
            "solana",
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
    assert_eq!(json["schema_version"], "digger.repo_intelligence.v1");
    assert_eq!(json["report_kind"], "repo_intelligence");
    assert_eq!(json["chain"], "solana");
    assert!(json["surfaces"].is_array());
    assert!(!json["surfaces"].as_array().unwrap().is_empty());
}

#[test]
fn cli_repo_intel_no_vulnerability_fields() {
    let output = Command::new(digger_bin_path())
        .args([
            "repo-intelligence",
            "--path",
            &fixture_path("evm-basic"),
            "--chain",
            "evm",
            "--json",
        ])
        .output()
        .expect("run failed");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert!(json.get("severity").is_none());
    assert!(json.get("risk_score").is_none());
    assert!(json.get("is_vulnerability_finding").is_none());
    assert!(json.get("confidence_ceiling").is_none());
    assert!(json.get("generated_at").is_none());
}

#[test]
fn cli_repo_intel_invalid_path() {
    let output = Command::new(digger_bin_path())
        .args([
            "repo-intelligence",
            "--path",
            "/nonexistent/path/that/does/not/exist",
            "--chain",
            "evm",
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(
        !output.status.success(),
        "must exit nonzero for invalid path"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("Error"),
        "stderr must contain useful error: {}",
        stderr
    );
}

#[test]
fn cli_repo_intel_paths_are_relative() {
    let output = Command::new(digger_bin_path())
        .args([
            "repo-intelligence",
            "--path",
            &fixture_path("evm-basic"),
            "--chain",
            "evm",
            "--json",
        ])
        .output()
        .expect("run failed");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    for surface in json["surfaces"].as_array().unwrap() {
        let path = surface["path"].as_str().unwrap();
        assert!(!path.starts_with('/'), "path must be relative: {}", path);
        assert!(
            !path.contains('\\'),
            "path must use forward slashes: {}",
            path
        );
    }
}

#[test]
fn cli_repo_intel_deterministic_output() {
    let run_cli = || {
        let output = Command::new(digger_bin_path())
            .args([
                "repo-intelligence",
                "--path",
                &fixture_path("evm-basic"),
                "--chain",
                "evm",
                "--json",
            ])
            .output()
            .expect("run failed");
        String::from_utf8(output.stdout).unwrap()
    };

    let out1 = run_cli();
    let out2 = run_cli();
    assert_eq!(out1, out2, "CLI output must be deterministic");
}
