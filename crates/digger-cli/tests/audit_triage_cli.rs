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

#[test]
fn evm_triage_succeeds() {
    let path = fixture_path("examples/evm-basic");
    let (ok, _) = run_triage(&path, "evm", &[]);
    assert!(ok);
}

#[test]
fn solana_triage_succeeds() {
    let path = fixture_path("examples/solana-basic");
    let (ok, _) = run_triage(&path, "solana", &[]);
    assert!(ok);
}

#[test]
fn evm_triage_json_schema_valid() {
    let path = fixture_path("examples/evm-basic");
    let (ok, stdout) = run_triage(&path, "evm", &[]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v["schema_version"].as_str().unwrap(),
        "digger.audit_triage_packet.v1"
    );
    assert_eq!(v["report_kind"].as_str().unwrap(), "audit_triage_packet");
    assert!(!v["is_finding"].as_bool().unwrap());
}

#[test]
fn solana_triage_json_schema_valid() {
    let path = fixture_path("examples/solana-basic");
    let (ok, stdout) = run_triage(&path, "solana", &[]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v["schema_version"].as_str().unwrap(),
        "digger.audit_triage_packet.v1"
    );
    assert!(!v["is_finding"].as_bool().unwrap());
}

#[test]
fn evm_triage_has_surfaces() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let surfaces = v["attack_surface_summary"]["total_functions"]
        .as_u64()
        .unwrap_or(0);
    assert!(surfaces > 0, "EVM triage should detect surfaces");
}

#[test]
fn evm_triage_has_hypotheses() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let hyps = v["candidate_hypotheses"].as_array().unwrap();
    assert!(!hyps.is_empty(), "EVM triage should generate hypotheses");
    for h in hyps {
        assert_eq!(h["status"].as_str().unwrap(), "requires_investigation");
    }
}

#[test]
fn evm_triage_has_proof_tasks() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let tasks = v["proof_tasks"].as_array().unwrap();
    assert!(!tasks.is_empty(), "EVM triage should generate proof tasks");
    for t in tasks {
        assert_eq!(t["status"].as_str().unwrap(), "pending");
    }
}

#[test]
fn evm_triage_has_limitations() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let lims = v["limitations"].as_array().unwrap();
    assert!(!lims.is_empty(), "Triage should list limitations");
}

#[test]
fn solana_triage_has_surfaces() {
    let path = fixture_path("examples/solana-basic");
    let (_, stdout) = run_triage(&path, "solana", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let surfaces = v["attack_surface_summary"]["total_functions"]
        .as_u64()
        .unwrap_or(0);
    assert!(surfaces > 0, "Solana triage should detect surfaces");
}

#[test]
fn invalid_path_fails() {
    let bin = digger_bin_path();
    let output = Command::new(&bin)
        .arg("audit-triage")
        .arg("--path")
        .arg("nonexistent_path_xyz")
        .arg("--chain")
        .arg("evm")
        .arg("--json")
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn invalid_chain_fails() {
    let bin = digger_bin_path();
    let path = fixture_path("examples/evm-basic");
    let output = Command::new(&bin)
        .arg("audit-triage")
        .arg("--path")
        .arg(&path)
        .arg("--chain")
        .arg("bitcoin")
        .arg("--json")
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn output_file_written() {
    let bin = digger_bin_path();
    let path = fixture_path("examples/evm-basic");
    let tmp = fixture_path("sample-output/test-triage-output.json");

    let output = Command::new(&bin)
        .arg("audit-triage")
        .arg("--path")
        .arg(&path)
        .arg("--chain")
        .arg("evm")
        .arg("--output")
        .arg(&tmp)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        std::path::Path::new(&tmp).exists(),
        "Output file should exist"
    );
    let content = std::fs::read_to_string(&tmp).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(!v["is_finding"].as_bool().unwrap());
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn human_summary_contains_disclaimer() {
    let bin = digger_bin_path();
    let path = fixture_path("examples/evm-basic");
    let output = Command::new(&bin)
        .arg("audit-triage")
        .arg("--path")
        .arg(&path)
        .arg("--chain")
        .arg("evm")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("audit triage, not a final finding"),
        "Human summary should contain non-finding disclaimer"
    );
}

#[test]
fn determinism_same_input_same_output() {
    let path = fixture_path("examples/evm-basic");
    let (_, out1) = run_triage(&path, "evm", &[]);
    let (_, out2) = run_triage(&path, "evm", &[]);
    assert_eq!(out1, out2, "Same input should produce same output");
}

#[test]
fn no_finding_terms_in_output() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    assert!(
        !stdout.contains("vulnerability confirmed"),
        "Should not claim vulnerability confirmed"
    );
    assert!(
        !stdout.contains("exploitable"),
        "Should not claim exploitable"
    );
}

#[test]
fn paths_are_repo_relative() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let ops = v["privileged_operations"].as_array().unwrap();
    for op in ops {
        let p = op["path"].as_str().unwrap_or("");
        assert!(
            !p.contains(":\\") && !p.contains("/Users/"),
            "Surface paths should be repo-relative, got: {}",
            p
        );
    }
}

#[test]
fn fuzz_maturity_flag_works() {
    let path = fixture_path("examples/evm-basic");
    let (ok, _) = run_triage(&path, "evm", &["--include-fuzz-maturity"]);
    assert!(ok);
}

#[test]
fn fuzz_artifact_invalid_path_warns() {
    let path = fixture_path("examples/evm-basic");
    let (ok, _) = run_triage(
        &path,
        "evm",
        &["--fuzz-artifact", "nonexistent_artifact.txt"],
    );
    assert!(ok);
}

#[test]
fn attack_surface_populated() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let total = v["attack_surface_summary"]["surfaces_scanned"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        total > 0,
        "EVM triage should scan surfaces from repo intelligence"
    );
}

#[test]
fn severity_requires_investigation_not_verdict() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let hyps = v["candidate_hypotheses"].as_array().unwrap();
    for h in hyps {
        if let Some(sev) = h.get("severity") {
            assert_eq!(
                h["status"].as_str().unwrap(),
                "requires_investigation",
                "severity field {} on hypothesis {} must have status requires_investigation, not a verdict",
                sev,
                h["hypothesis_id"].as_str().unwrap_or("unknown")
            );
            assert!(
                h.get("provenance").is_some(),
                "severity-bearing hypothesis {} must have a provenance label",
                h["hypothesis_id"].as_str().unwrap_or("unknown")
            );
        }
    }
    assert!(!v["is_finding"].as_bool().unwrap());
}

#[test]
fn evm_engine_derived_entries_exist() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["attack_surface_summary"]["engine_derived"]
        .as_bool()
        .unwrap());
    assert!(
        v["attack_surface_summary"]["engine_files_ok"]
            .as_u64()
            .unwrap()
            > 0
    );
    let surfaces = v["surfaces_scanned"].as_array().unwrap();
    let engine_surfaces: Vec<_> = surfaces
        .iter()
        .filter(|s| s["provenance"].as_str() == Some("engine"))
        .collect();
    assert!(
        !engine_surfaces.is_empty(),
        "EVM triage should have engine-derived surfaces"
    );
    for s in &engine_surfaces {
        assert_eq!(s["confidence"].as_str().unwrap(), "engine_verified");
    }
    let hyps = v["candidate_hypotheses"].as_array().unwrap();
    let engine_hyps: Vec<_> = hyps
        .iter()
        .filter(|h| h["engine_derived"].as_bool() == Some(true))
        .collect();
    assert!(
        !engine_hyps.is_empty(),
        "EVM triage should have engine-derived hypotheses"
    );
}

#[test]
fn solana_engine_derived_entries_exist() {
    let path = fixture_path("examples/solana-basic");
    let (_, stdout) = run_triage(&path, "solana", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["attack_surface_summary"]["engine_derived"]
        .as_bool()
        .unwrap());
    assert!(
        v["attack_surface_summary"]["engine_files_ok"]
            .as_u64()
            .unwrap()
            > 0
    );
    let hyps = v["candidate_hypotheses"].as_array().unwrap();
    let engine_hyps: Vec<_> = hyps
        .iter()
        .filter(|h| h["engine_derived"].as_bool() == Some(true))
        .collect();
    assert!(
        !engine_hyps.is_empty(),
        "Solana triage should have engine-derived hypotheses"
    );
}

#[test]
fn heuristic_entries_labeled() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let surfaces = v["surfaces_scanned"].as_array().unwrap();
    for s in surfaces {
        let prov = s["provenance"].as_str().unwrap_or("");
        assert!(
            prov == "engine"
                || prov == "heuristic"
                || prov == "repo_intelligence"
                || prov == "fuzz_maturity_scanner",
            "Surface {} has unknown provenance: {}",
            s["name"].as_str().unwrap_or("unknown"),
            prov
        );
    }
}

#[test]
fn dedup_engine_and_heuristic_no_double_count() {
    let path = fixture_path("examples/evm-basic");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let surfaces = v["surfaces_scanned"].as_array().unwrap();
    let mut seen = std::collections::HashSet::new();
    for s in surfaces {
        let key = (
            s["path"].as_str().unwrap_or("").to_string(),
            s["name"].as_str().unwrap_or("").to_string(),
        );
        assert!(
            seen.insert(key.clone()),
            "Duplicate surface (path={}, name={}) found after dedup",
            key.0,
            key.1
        );
    }
}

#[test]
fn report_draft_has_evidence_refs() {
    let path = fixture_path("examples/evm-basic");
    let (_, triage_stdout) = run_triage(&path, "evm", &[]);
    std::fs::write("_tmp_triage_evm.json", &triage_stdout).unwrap();
    std::fs::write(
        "_tmp_claim_evm.md",
        "The withdraw function has external calls",
    )
    .unwrap();
    let output = std::process::Command::new(digger_bin_path())
        .args([
            "verify-claim",
            "--triage",
            "_tmp_triage_evm.json",
            "--claim",
            "_tmp_claim_evm.md",
            "--json",
        ])
        .output()
        .unwrap();
    let verification = String::from_utf8(output.stdout).unwrap();
    std::fs::write("_tmp_verify_evm.json", &verification).unwrap();
    let output = std::process::Command::new(digger_bin_path())
        .args([
            "report-draft",
            "--triage",
            "_tmp_triage_evm.json",
            "--verification",
            "_tmp_verify_evm.json",
            "--json",
        ])
        .output()
        .unwrap();
    let report = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert!(
        !v["evidence_refs"].as_array().unwrap().is_empty(),
        "Report draft should have non-empty evidence_refs from surfaces_scanned"
    );
    assert!(
        !v["sections"].as_array().unwrap().is_empty(),
        "Report draft should have sections"
    );
    let _ = std::fs::remove_file("_tmp_triage_evm.json");
    let _ = std::fs::remove_file("_tmp_claim_evm.md");
    let _ = std::fs::remove_file("_tmp_verify_evm.json");
}

#[test]
fn is_finding_false_and_no_verdict_language() {
    let path = fixture_path("examples/solana-basic");
    let (_, stdout) = run_triage(&path, "solana", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(!v["is_finding"].as_bool().unwrap());
    assert!(!stdout.contains("confirmed_vulnerability"));
    assert!(!stdout.contains("exploitable"));
    assert!(!stdout.contains("guaranteed_safe"));
    assert!(!stdout.contains("final_finding"));
}

#[test]
fn verify_claim_statuses_on_real_triage() {
    let path = fixture_path("examples/evm-basic");
    let (_, triage_stdout) = run_triage(&path, "evm", &[]);
    std::fs::write("_tmp_triage_vc.json", &triage_stdout).unwrap();

    let run_claim = |claim: &str| -> String {
        std::fs::write("_tmp_claim_vc.md", claim).unwrap();
        let output = std::process::Command::new(digger_bin_path())
            .args([
                "verify-claim",
                "--triage",
                "_tmp_triage_vc.json",
                "--claim",
                "_tmp_claim_vc.md",
                "--json",
            ])
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    };

    // insufficient_evidence: claim about oracle (no oracle surface in Safe.sol triage)
    let out_insuff = run_claim("The oracle manipulation attack vector needs investigation");
    let v: serde_json::Value = serde_json::from_str(&out_insuff).unwrap();
    assert_eq!(v["status"].as_str().unwrap(), "insufficient_evidence");
    assert!(!v["is_finding"].as_bool().unwrap());
    assert!(v["evidence_satisfied"].as_array().unwrap().is_empty());

    // insufficient_evidence: deposit maps to a surface, but open missing evidence prevents valid
    let out_deposit = run_claim("The deposit function performs a state mutation");
    let v: serde_json::Value = serde_json::from_str(&out_deposit).unwrap();
    assert_eq!(v["status"].as_str().unwrap(), "insufficient_evidence");
    assert!(!v["is_finding"].as_bool().unwrap());
    assert!(!v["evidence_satisfied"].as_array().unwrap().is_empty());

    // invalid: claim denies guard on pause; engine shows pause has auth
    let out_invalid = run_claim("There is no guard on pause");
    let v: serde_json::Value = serde_json::from_str(&out_invalid).unwrap();
    assert_eq!(v["status"].as_str().unwrap(), "invalid");
    assert!(!v["is_finding"].as_bool().unwrap());
    assert!(!v["validation_failures"].as_array().unwrap().is_empty());
    let reason = v["status_reason"].as_str().unwrap();
    assert!(reason.contains("contradicts") || reason.contains("refutes"));

    // out_of_scope: claim references solana keywords not in EVM triage
    let out_oos = run_claim("The PDA seeds and CPI invocation are incorrect");
    let v: serde_json::Value = serde_json::from_str(&out_oos).unwrap();
    assert_eq!(v["status"].as_str().unwrap(), "out_of_scope");
    assert!(!v["is_finding"].as_bool().unwrap());

    // Note: needs_dynamic_proof and needs_chain_state_verification are
    // reachable only when proof_tasks carry runtime/chain-state evidence_type.
    // Current engine proof_tasks use evidence_type="engine_analysis".
    // These statuses will be exercised once Phase 5 wires evidence-run results.

    let _ = std::fs::remove_file("_tmp_triage_vc.json");
    let _ = std::fs::remove_file("_tmp_claim_vc.md");
}

#[test]
fn cross_file_same_name_retains_both_surfaces() {
    let path = fixture_path("crates/digger-cli/tests/fixtures/evm-multifile");
    let (_, stdout) = run_triage(&path, "evm", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let surfaces = v["surfaces_scanned"].as_array().unwrap();
    let withdraw_surfaces: Vec<_> = surfaces
        .iter()
        .filter(|s| s["name"].as_str() == Some("withdraw"))
        .collect();
    assert!(
        withdraw_surfaces.len() >= 2,
        "Both withdraw functions from different files must be retained, got {}",
        withdraw_surfaces.len()
    );
    let paths: Vec<String> = withdraw_surfaces
        .iter()
        .filter_map(|s| s["path"].as_str().map(|p| p.to_string()))
        .collect();
    assert!(paths.contains(&"Vault.sol".to_string()));
    assert!(paths.contains(&"Staking.sol".to_string()));
    for _ in &withdraw_surfaces {
        assert!(!v["is_finding"].as_bool().unwrap());
    }
}

#[test]
fn e2e_engine_derived_chain_with_shared_correlation_id() {
    let path = fixture_path("examples/evm-basic");
    let bin = digger_bin_path();

    // Stage 1: Triage
    let triage_out = Command::new(&bin)
        .args(["audit-triage", "--path", &path, "--chain", "evm", "--json"])
        .output()
        .unwrap();
    assert!(triage_out.status.success());
    let triage: serde_json::Value = serde_json::from_slice(&triage_out.stdout).unwrap();
    assert!(!triage["is_finding"].as_bool().unwrap());
    let cid = triage["correlation_id"].as_str().unwrap().to_string();

    // Verify engine-derived surfaces
    let surfaces = triage["surfaces_scanned"].as_array().unwrap();
    let engine_surfaces: Vec<_> = surfaces
        .iter()
        .filter(|s| s["provenance"].as_str() == Some("engine"))
        .collect();
    assert!(
        !engine_surfaces.is_empty(),
        "Triage must have engine-derived surfaces"
    );

    // Verify engine-derived hypotheses
    let hyps = triage["candidate_hypotheses"].as_array().unwrap();
    let engine_hyps: Vec<_> = hyps
        .iter()
        .filter(|h| h["engine_derived"].as_bool() == Some(true))
        .collect();
    assert!(
        !engine_hyps.is_empty(),
        "Triage must have engine-derived hypotheses"
    );
    for h in &engine_hyps {
        assert_eq!(h["provenance"].as_str().unwrap(), "engine");
    }

    std::fs::write("_tmp_e2e_triage.json", &triage_out.stdout).unwrap();

    // Stage 2: Hypothesis
    let hyp_out = Command::new(&bin)
        .args([
            "hypothesis-create",
            "--from-triage",
            "_tmp_e2e_triage.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(hyp_out.status.success());
    let hyp: serde_json::Value = serde_json::from_slice(&hyp_out.stdout).unwrap();
    assert_eq!(hyp["correlation_id"].as_str().unwrap(), cid);
    assert_eq!(hyp["audit_events"].as_array().unwrap().len(), 1);
    assert!(!hyp["is_finding"].as_bool().unwrap());
    std::fs::write("_tmp_e2e_hyp.json", &hyp_out.stdout).unwrap();

    // Stage 3: Proof task
    let pt_out = Command::new(&bin)
        .args([
            "proof-task-generate",
            "--from-hypothesis",
            "_tmp_e2e_hyp.json",
            "--triage",
            "_tmp_e2e_triage.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(pt_out.status.success());
    let pt: serde_json::Value = serde_json::from_slice(&pt_out.stdout).unwrap();
    assert_eq!(pt["correlation_id"].as_str().unwrap(), cid);
    assert!(!pt["is_finding"].as_bool().unwrap());
    std::fs::write("_tmp_e2e_pt.json", &pt_out.stdout).unwrap();

    // Stage 4: Verify claim
    std::fs::write(
        "_tmp_e2e_claim.md",
        "The deposit function performs a state mutation",
    )
    .unwrap();
    let vc_out = Command::new(&bin)
        .args([
            "verify-claim",
            "--triage",
            "_tmp_e2e_triage.json",
            "--claim",
            "_tmp_e2e_claim.md",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(vc_out.status.success());
    let vc: serde_json::Value = serde_json::from_slice(&vc_out.stdout).unwrap();
    assert_eq!(vc["correlation_id"].as_str().unwrap(), cid);
    assert!(!vc["is_finding"].as_bool().unwrap());
    std::fs::write("_tmp_e2e_verify.json", &vc_out.stdout).unwrap();

    // Stage 5: Report draft
    let rd_out = Command::new(&bin)
        .args([
            "report-draft",
            "--triage",
            "_tmp_e2e_triage.json",
            "--verification",
            "_tmp_e2e_verify.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(rd_out.status.success());
    let rd: serde_json::Value = serde_json::from_slice(&rd_out.stdout).unwrap();
    assert_eq!(rd["correlation_id"].as_str().unwrap(), cid);
    assert!(!rd["is_finding"].as_bool().unwrap());
    std::fs::write("_tmp_e2e_report.json", &rd_out.stdout).unwrap();

    // Stage 6: Evidence package (accumulates all events)
    let ep_out = Command::new(&bin)
        .args([
            "evidence-package",
            "--triage",
            "_tmp_e2e_triage.json",
            "--verification",
            "_tmp_e2e_verify.json",
            "--report-draft",
            "_tmp_e2e_report.json",
            "--hypothesis",
            "_tmp_e2e_hyp.json",
            "--proof-task",
            "_tmp_e2e_pt.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(ep_out.status.success());
    let ep: serde_json::Value = serde_json::from_slice(&ep_out.stdout).unwrap();
    assert_eq!(ep["correlation_id"].as_str().unwrap(), cid);
    assert!(!ep["is_finding"].as_bool().unwrap());

    // Verify event accumulation
    let events = ep["audit_events"].as_array().unwrap();
    assert!(
        events.len() >= 5,
        "Evidence package should accumulate events from at least 5 stages, got {}",
        events.len()
    );

    // Verify all events share the same correlation_id
    for evt in events {
        let refs = evt["output_refs"].as_array().unwrap();
        assert!(
            refs.iter().any(|r| r.as_str() == Some(&cid)),
            "Event output_refs should contain correlation_id"
        );
    }

    // Cleanup
    for f in &[
        "_tmp_e2e_triage.json",
        "_tmp_e2e_hyp.json",
        "_tmp_e2e_pt.json",
        "_tmp_e2e_claim.md",
        "_tmp_e2e_verify.json",
        "_tmp_e2e_report.json",
    ] {
        let _ = std::fs::remove_file(f);
    }
}

#[test]
fn solana_e2e_engine_derived() {
    let path = fixture_path("examples/solana-basic");
    let bin = digger_bin_path();

    let triage_out = Command::new(&bin)
        .args([
            "audit-triage",
            "--path",
            &path,
            "--chain",
            "solana",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(triage_out.status.success());
    let triage: serde_json::Value = serde_json::from_slice(&triage_out.stdout).unwrap();
    assert!(!triage["is_finding"].as_bool().unwrap());
    assert!(triage["attack_surface_summary"]["engine_derived"]
        .as_bool()
        .unwrap());

    let surfaces = triage["surfaces_scanned"].as_array().unwrap();
    let engine_surfaces: Vec<_> = surfaces
        .iter()
        .filter(|s| s["provenance"].as_str() == Some("engine"))
        .collect();
    assert!(
        !engine_surfaces.is_empty(),
        "Solana triage must have engine-derived surfaces"
    );

    let hyps = triage["candidate_hypotheses"].as_array().unwrap();
    let engine_hyps: Vec<_> = hyps
        .iter()
        .filter(|h| h["engine_derived"].as_bool() == Some(true))
        .collect();
    assert!(
        !engine_hyps.is_empty(),
        "Solana triage must have engine-derived hypotheses"
    );
    for h in &engine_hyps {
        assert_eq!(h["provenance"].as_str().unwrap(), "engine");
    }

    // Full chain smoke test
    std::fs::write("_tmp_sol_triage.json", &triage_out.stdout).unwrap();
    let cid = triage["correlation_id"].as_str().unwrap().to_string();

    let hyp_out = Command::new(&bin)
        .args([
            "hypothesis-create",
            "--from-triage",
            "_tmp_sol_triage.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(hyp_out.status.success());
    let hyp: serde_json::Value = serde_json::from_slice(&hyp_out.stdout).unwrap();
    assert_eq!(hyp["correlation_id"].as_str().unwrap(), cid);
    std::fs::write("_tmp_sol_hyp.json", &hyp_out.stdout).unwrap();

    let pt_out = Command::new(&bin)
        .args([
            "proof-task-generate",
            "--from-hypothesis",
            "_tmp_sol_hyp.json",
            "--triage",
            "_tmp_sol_triage.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(pt_out.status.success());
    std::fs::write("_tmp_sol_pt.json", &pt_out.stdout).unwrap();

    std::fs::write("_tmp_sol_claim.md", "The withdraw instruction has CPI").unwrap();
    let vc_out = Command::new(&bin)
        .args([
            "verify-claim",
            "--triage",
            "_tmp_sol_triage.json",
            "--claim",
            "_tmp_sol_claim.md",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(vc_out.status.success());
    let vc: serde_json::Value = serde_json::from_slice(&vc_out.stdout).unwrap();
    assert_eq!(vc["correlation_id"].as_str().unwrap(), cid);
    assert!(!vc["is_finding"].as_bool().unwrap());
    std::fs::write("_tmp_sol_verify.json", &vc_out.stdout).unwrap();

    let rd_out = Command::new(&bin)
        .args([
            "report-draft",
            "--triage",
            "_tmp_sol_triage.json",
            "--verification",
            "_tmp_sol_verify.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(rd_out.status.success());
    let rd: serde_json::Value = serde_json::from_slice(&rd_out.stdout).unwrap();
    assert_eq!(rd["correlation_id"].as_str().unwrap(), cid);
    std::fs::write("_tmp_sol_report.json", &rd_out.stdout).unwrap();

    let ep_out = Command::new(&bin)
        .args([
            "evidence-package",
            "--triage",
            "_tmp_sol_triage.json",
            "--verification",
            "_tmp_sol_verify.json",
            "--report-draft",
            "_tmp_sol_report.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(ep_out.status.success());
    let ep: serde_json::Value = serde_json::from_slice(&ep_out.stdout).unwrap();
    assert_eq!(ep["correlation_id"].as_str().unwrap(), cid);
    assert!(!ep["is_finding"].as_bool().unwrap());
    let events = ep["audit_events"].as_array().unwrap();
    assert!(events.len() >= 4);

    for f in &[
        "_tmp_sol_triage.json",
        "_tmp_sol_hyp.json",
        "_tmp_sol_pt.json",
        "_tmp_sol_claim.md",
        "_tmp_sol_verify.json",
        "_tmp_sol_report.json",
    ] {
        let _ = std::fs::remove_file(f);
    }
}

#[test]
fn surfaces_by_class_total_matches_surfaces_scanned() {
    let (ok, stdout) = run_triage(&fixture_path("examples/evm-basic"), "evm", &[]);
    assert!(ok, "triage must succeed");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");

    let surfaces_scanned = v["attack_surface_summary"]["surfaces_scanned"]
        .as_u64()
        .unwrap() as usize;
    let surfaces_by_class = v["attack_surface_summary"]["surfaces_by_class"]
        .as_object()
        .unwrap();
    let class_total: usize = surfaces_by_class
        .values()
        .map(|v| v.as_u64().unwrap() as usize)
        .sum();

    assert_eq!(
        class_total, surfaces_scanned,
        "surfaces_by_class total ({}) must equal surfaces_scanned ({})",
        class_total, surfaces_scanned
    );
}

#[test]
fn files_by_class_counts_distinct_files() {
    let (ok, stdout) = run_triage(&fixture_path("examples/evm-basic"), "evm", &[]);
    assert!(ok, "triage must succeed");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");

    // Collect distinct file paths from surfaces_scanned
    let mut seen = std::collections::BTreeSet::new();
    if let Some(arr) = v["surfaces_scanned"].as_array() {
        for item in arr {
            if let Some(p) = item["path"].as_str() {
                seen.insert(p.to_string());
            }
        }
    }
    let distinct_files = seen.len();

    let files_by_class = v["attack_surface_summary"]["files_by_class"]
        .as_object()
        .unwrap();
    let class_total: usize = files_by_class
        .values()
        .map(|v| v.as_u64().unwrap() as usize)
        .sum();

    assert_eq!(
        class_total, distinct_files,
        "files_by_class total ({}) must equal distinct file paths ({})",
        class_total, distinct_files
    );
    assert!(
        class_total > 0,
        "files_by_class must have at least one entry"
    );
}

#[test]
fn exclude_tests_filters_hypotheses_to_production() {
    let (_, json_stdout) = run_triage(&fixture_path("."), "evm", &["--exclude-tests"]);
    let v: serde_json::Value = serde_json::from_str(&json_stdout).expect("invalid JSON");

    let total = v["candidate_hypotheses_total"].as_u64().unwrap();
    let filtered = v["candidate_hypotheses"].as_array().unwrap().len();
    assert!(filtered <= total as usize, "filtered must be <= total");

    // Every filtered hypothesis must be production or missing file_class
    for h in v["candidate_hypotheses"].as_array().unwrap() {
        let fc = h
            .get("file_class")
            .and_then(|v| v.as_str())
            .unwrap_or("production");
        assert!(
            fc == "production",
            "exclude-tests should only include production hypotheses, got {}",
            fc
        );
    }
}
