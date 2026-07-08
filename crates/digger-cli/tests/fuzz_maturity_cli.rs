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

fn tmpdir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("fuzz_maturity_cli_test_{}", name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn cli_fuzz_maturity_json_populated_repo() {
    let dir = tmpdir("populated");
    let tdir = dir.join("test");
    std::fs::create_dir_all(&tdir).unwrap();
    std::fs::write(
        tdir.join("InvariantCounter.t.sol"),
        "import StdInvariant; contract InvariantCounter is StdInvariant { function invariant_counter_never_negative() public view { assertGe(counter.value(), 0); } }",
    )
    .unwrap();
    std::fs::write(
        dir.join("CounterHandler.sol"),
        "contract CounterHandler { function doSomething() public {} }",
    )
    .unwrap();

    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-maturity",
            "--path",
            dir.to_str().unwrap(),
            "--chain",
            "evm",
            "--json",
        ])
        .output()
        .expect("failed to run digger fuzz-maturity");

    assert!(
        output.status.success(),
        "digger fuzz-maturity must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    assert_eq!(json["report_type"], "fuzzing_maturity");
    assert_eq!(json["is_vulnerability_finding"], false);
    assert_eq!(json["chain"], "evm");
    let score = json["maturity_score"]
        .as_u64()
        .expect("score must be a number");
    assert!(
        score > 30,
        "populated repo score must be >30, got {}",
        score
    );
    let signals = json["signals_present"]
        .as_array()
        .expect("signals_present must be array");
    assert!(
        !signals.is_empty(),
        "populated repo must have positive signals"
    );
    assert!(signals
        .iter()
        .any(|s| s.as_str().unwrap_or("").contains("invariant")));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_fuzz_maturity_flip_proof() {
    // Populated repo has signals
    let dir1 = tmpdir("flip_pop");
    let tdir = dir1.join("test");
    std::fs::create_dir_all(&tdir).unwrap();
    std::fs::write(
        tdir.join("Inv.t.sol"),
        "function invariant_x() public { assert(true); }",
    )
    .unwrap();

    let out1 = Command::new(digger_bin_path())
        .args([
            "fuzz-maturity",
            "--path",
            dir1.to_str().unwrap(),
            "--chain",
            "evm",
            "--json",
        ])
        .output()
        .expect("run failed");
    let json1: serde_json::Value = serde_json::from_slice(&out1.stdout).unwrap();
    let score1 = json1["maturity_score"].as_u64().unwrap();

    // Empty repo has no signals
    let dir2 = tmpdir("flip_empty");
    std::fs::write(dir2.join("Token.sol"), "contract Token {}").unwrap();

    let out2 = Command::new(digger_bin_path())
        .args([
            "fuzz-maturity",
            "--path",
            dir2.to_str().unwrap(),
            "--chain",
            "evm",
            "--json",
        ])
        .output()
        .expect("run failed");
    let json2: serde_json::Value = serde_json::from_slice(&out2.stdout).unwrap();
    let score2 = json2["maturity_score"].as_u64().unwrap();

    assert!(
        score1 > score2,
        "populated score ({}) must exceed empty score ({})",
        score1,
        score2
    );
    assert!(!json1["is_vulnerability_finding"].as_bool().unwrap());
    assert!(!json2["is_vulnerability_finding"].as_bool().unwrap());

    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn cli_fuzz_maturity_unsupported_chain() {
    let dir = tmpdir("chain_check");
    std::fs::write(dir.join("Token.sol"), "contract Token {}").unwrap();

    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-maturity",
            "--path",
            dir.to_str().unwrap(),
            "--chain",
            "solana",
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(
        !output.status.success(),
        "unsupported chain must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("evm") || stderr.contains("not supported"),
        "error message must mention unsupported chain"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_fuzz_maturity_nonexistent_path() {
    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-maturity",
            "--path",
            "/nonexistent/path/12345",
            "--chain",
            "evm",
        ])
        .output()
        .expect("run failed");

    assert!(
        !output.status.success(),
        "nonexistent path must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("not exist"),
        "error must mention path not found"
    );
}

#[test]
fn cli_fuzz_maturity_empty_repo_no_vulnerability() {
    let dir = tmpdir("empty");
    std::fs::write(dir.join("Token.sol"), "contract Token {}").unwrap();

    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-maturity",
            "--path",
            dir.to_str().unwrap(),
            "--chain",
            "evm",
            "--json",
        ])
        .output()
        .expect("run failed");

    assert!(output.status.success(), "empty repo must exit 0");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["report_type"], "fuzzing_maturity");
    assert_eq!(json["is_vulnerability_finding"], false);
    assert_eq!(json["maturity_score"], 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_fuzz_maturity_human_output() {
    let dir = tmpdir("human");
    let tdir = dir.join("test");
    std::fs::create_dir_all(&tdir).unwrap();
    std::fs::write(
        tdir.join("Inv.t.sol"),
        "function invariant_x() public { assert(true); }",
    )
    .unwrap();

    let output = Command::new(digger_bin_path())
        .args([
            "fuzz-maturity",
            "--path",
            dir.to_str().unwrap(),
            "--chain",
            "evm",
        ])
        .output()
        .expect("run failed");

    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("Fuzzing Maturity Report"),
        "human output must contain report title"
    );
    assert!(
        text.contains("is a static maturity report"),
        "must disclaim vulnerability finding"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
