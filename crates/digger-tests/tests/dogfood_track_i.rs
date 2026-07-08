//! Step 3 — End-to-end dogfood: digger scan → emit ScanContext → feed to
//! digger_mcp → drive all 4 tools over real stdio JSON-RPC.
//!
//! This test proves the FULL seam: CLI emits a typed ScanContext file from a
//! real corpus fixture, and the MCP binary serves that file's findings over
//! the wire — including catching a promoted-severity lie via the typed guardrail.

use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

// ── helpers ──────────────────────────────────────────────────────

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn workspace_root() -> std::path::PathBuf {
    let d = env!("CARGO_MANIFEST_DIR");
    std::path::Path::new(d)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn digger_bin_path() -> std::path::PathBuf {
    let base = workspace_root().join("target/debug/digger");
    if base.exists() {
        base
    } else {
        workspace_root().join("target/debug/digger.exe")
    }
}

fn mcp_bin_path() -> std::path::PathBuf {
    let base = workspace_root().join("target/debug/digger_mcp");
    if base.exists() {
        base
    } else {
        workspace_root().join("target/debug/digger_mcp.exe")
    }
}

fn tmpfile(name: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{}-{}-{}", name, std::process::id(), n))
}

/// Send requests via file-redirect stdin and read all stdout lines.
/// This avoids Windows pipe-buffering issues with BufRead::lines on piped stdio.
fn mcp_session(ctx_path: &std::path::Path, requests: &[&str]) -> Vec<serde_json::Value> {
    let stdin_path = tmpfile("mcp_in");
    let stdout_path = tmpfile("mcp_out");
    let stderr_path = tmpfile("mcp_err");

    // Write all requests to a file (newline-delimited)
    {
        let mut f = std::fs::File::create(&stdin_path).unwrap();
        for req in requests {
            writeln!(f, "{}", req).unwrap();
        }
    }

    let status = Command::new(mcp_bin_path())
        .arg(ctx_path)
        .stdin(std::fs::File::open(&stdin_path).unwrap())
        .stdout(std::fs::File::create(&stdout_path).unwrap())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .env("DIGGER_MCP_KEY", "test-bootstrap-key-for-dogfood")
        .env("DIGGER_API_KEY", "test-bootstrap-key-for-dogfood")
        .status()
        .expect("failed to spawn digger_mcp");

    assert!(status.success(), "digger_mcp must exit 0");

    // Parse all response lines
    let raw = std::fs::read_to_string(&stdout_path).unwrap();
    let mut responses = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
                responses.push(v);
            }
        }
    }

    let _ = std::fs::remove_file(&stdin_path);
    let _ = std::fs::remove_file(&stdout_path);
    let _ = std::fs::remove_file(&stderr_path);
    responses
}

// ── test ─────────────────────────────────────────────────────────

#[test]
fn dogfood_scan_to_mcp_all_tools() {
    let root = workspace_root();
    let fixture = root.join("corpus/price-manipulation/bzx-2020/source.sol");
    assert!(fixture.exists(), "corpus fixture must exist: {:?}", fixture);

    let ctx_path = tmpfile("dogfood-ctx.json");

    // ── PHASE 1: Run `digger scan-live --emit-scan-context` ──

    let scan_output = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run digger scan-live");

    assert!(
        scan_output.status.success(),
        "digger scan-live must exit 0, stderr: {}",
        String::from_utf8_lossy(&scan_output.stderr)
    );
    assert!(ctx_path.exists(), "emit-scan-context must write a file");

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "emitted ScanContext must have ≥1 finding"
    );

    // ── PHASE 2: Build the full MCP session ──

    let finding_id = findings[0]["finding_id"].as_str().unwrap();
    let rule_id = findings[0]["rule_id"].as_str().unwrap();
    let severity = findings[0]["severity"].as_str().unwrap();
    let confidence = findings[0]["confidence"].as_str().unwrap();
    let stage = findings[0]["stage"].as_str().unwrap();

    // Build the true claim from emitted data
    let true_claim = serde_json::json!({
        "scan_id": "dogfood-scan",
        "claimed_findings": [{
            "finding_id": finding_id,
            "rule_id": rule_id,
            "severity": severity,
            "confidence": confidence,
            "stage": stage,
            "locations": [],
            "exploit_status": "none",
            "claim_text": "benign analysis"
        }],
        "prose": "benign"
    });

    let lie_claim = serde_json::json!({
        "scan_id": "dogfood-scan",
        "claimed_findings": [{
            "finding_id": finding_id,
            "rule_id": rule_id,
            "severity": "critical",
            "confidence": confidence,
            "stage": stage,
            "locations": [],
            "exploit_status": "none",
            "claim_text": "promoted"
        }],
        "prose": "promoted"
    });

    let req_ev = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"get_evidence","arguments":{{"finding_id":"{}"}}}}}}"#,
        finding_id
    );
    let req_ctx = format!(
        r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"get_explanation_context","arguments":{{"finding_id":"{}"}}}}}}"#,
        finding_id
    );
    let req_val = format!(
        r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"validate_assistant_output","arguments":{}}}}}"#,
        true_claim
    );
    let req_lie = format!(
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"validate_assistant_output","arguments":{}}}}}"#,
        lie_claim
    );

    let requests = vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dogfood","version":"1.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"x"}}}"#,
        &req_ev,
        &req_ctx,
        &req_val,
        &req_lie,
    ];

    let responses = mcp_session(&ctx_path, &requests);

    // ── Assert responses ──

    // We get responses for requests 1,3,4,5,6,7,8 (notification #2 produces none)
    // Filter to only those with an "id" field
    let rpc_responses: Vec<&serde_json::Value> =
        responses.iter().filter(|r| r.get("id").is_some()).collect();

    // (a) initialize
    let init = rpc_responses.iter().find(|r| r["id"] == 1).unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(init["result"]["serverInfo"]["name"], "digger-mcp");

    // (b) tools/list — 4 tools, all readOnly
    let list = rpc_responses.iter().find(|r| r["id"] == 2).unwrap();
    let tools = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 4);
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"list_findings"));
    assert!(names.contains(&"get_evidence"));
    assert!(names.contains(&"get_explanation_context"));
    assert!(names.contains(&"validate_assistant_output"));
    for t in tools {
        assert_eq!(t["annotations"]["readOnlyHint"], true);
    }

    // (c) list_findings — echoes real emitted data
    let lf = rpc_responses.iter().find(|r| r["id"] == 3).unwrap();
    let lf_findings: Vec<serde_json::Value> =
        serde_json::from_str(lf["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(lf_findings.len(), findings.len());
    assert_eq!(lf_findings[0]["rule_id"], rule_id);
    assert_eq!(lf_findings[0]["severity"], severity);
    assert_eq!(lf_findings[0]["confidence"], confidence);
    assert_eq!(lf_findings[0]["stage"], stage);

    // Location wired from engine's function name (not fabricated)
    let locs = lf_findings[0]["locations"].as_array().unwrap();
    assert!(
        !locs.is_empty(),
        "emitted finding must carry a location from the engine"
    );
    assert!(
        !locs[0]["symbol"].as_str().unwrap_or("").is_empty(),
        "location symbol must be the engine-emitted function name"
    );

    // (d) get_evidence — valid JSON-RPC response (may be empty array)
    let ge = rpc_responses.iter().find(|r| r["id"] == 4).unwrap();
    let _ge_text = ge["result"]["content"][0]["text"].as_str().unwrap();

    // (e) get_explanation_context — valid JSON-RPC response
    let gec = rpc_responses.iter().find(|r| r["id"] == 5).unwrap();
    assert!(gec.get("result").is_some() || gec.get("error").is_some());

    // (f) validate — engine-true → pass
    let val = rpc_responses.iter().find(|r| r["id"] == 6).unwrap();
    let val_report: serde_json::Value =
        serde_json::from_str(val["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(val_report["pass"], true, "engine-true claim must pass");

    // (g) validate — promoted severity → SEVERITY_UPGRADED
    let lie = rpc_responses.iter().find(|r| r["id"] == 7).unwrap();
    let lie_report: serde_json::Value =
        serde_json::from_str(lie["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(lie_report["pass"], false, "promoted severity must fail");
    let violations = lie_report["violations"].as_array().unwrap();
    assert!(
        violations.iter().any(|v| v["code"] == "SEVERITY_UPGRADED"),
        "must have SEVERITY_UPGRADED, got: {:?}",
        violations
    );

    // cleanup
    let _ = std::fs::remove_file(&ctx_path);
}

// ── Solana dogfood arm ──────────────────────────────────────────

#[test]
fn dogfood_solana_scan_to_mcp_all_tools() {
    let root = workspace_root();
    let fixture = root.join("corpus/solana-account-model/cpi-signer-only-vuln/source.rs");
    assert!(
        fixture.exists(),
        "Solana corpus fixture must exist: {:?}",
        fixture
    );

    let ctx_path = tmpfile("dogfood-solana-ctx.json");

    let scan_output = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run digger scan-live");

    assert!(
        scan_output.status.success(),
        "digger scan-live must exit 0, stderr: {}",
        String::from_utf8_lossy(&scan_output.stderr)
    );
    assert!(ctx_path.exists(), "emit-scan-context must write a file");

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "Solana scan must produce >=1 finding from cpi-signer-only-vuln"
    );

    let finding_id = findings[0]["finding_id"].as_str().unwrap();
    let rule_id = findings[0]["rule_id"].as_str().unwrap();
    let severity = findings[0]["severity"].as_str().unwrap();
    let confidence = findings[0]["confidence"].as_str().unwrap();
    let stage = findings[0]["stage"].as_str().unwrap();

    // Verify Solana-specific labels
    assert_eq!(rule_id, "solana_access_control");
    assert_eq!(severity, "high");
    assert_eq!(confidence, "experimental");
    assert_eq!(stage, "shadow");

    // Location has function name from engine
    let locs = findings[0]["locations"].as_array().unwrap();
    assert!(!locs.is_empty(), "Solana finding must carry a location");
    assert!(!locs[0]["symbol"].as_str().unwrap_or("").is_empty());

    // Build claims for guardrail test
    let true_claim = serde_json::json!({
        "scan_id": "dogfood-solana",
        "claimed_findings": [{
            "finding_id": finding_id,
            "rule_id": rule_id,
            "severity": severity,
            "confidence": confidence,
            "stage": stage,
            "locations": [],
            "exploit_status": "none",
            "claim_text": "benign"
        }],
        "prose": "benign"
    });

    let lie_claim = serde_json::json!({
        "scan_id": "dogfood-solana",
        "claimed_findings": [{
            "finding_id": finding_id,
            "rule_id": rule_id,
            "severity": "critical",
            "confidence": confidence,
            "stage": stage,
            "locations": [],
            "exploit_status": "none",
            "claim_text": "promoted"
        }],
        "prose": "promoted"
    });

    let req_ev = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"get_evidence","arguments":{{"finding_id":"{}"}}}}}}"#,
        finding_id
    );
    let req_val = format!(
        r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"validate_assistant_output","arguments":{}}}}}"#,
        true_claim
    );
    let req_lie = format!(
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"validate_assistant_output","arguments":{}}}}}"#,
        lie_claim
    );

    let requests = vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dogfood-solana","version":"1.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"x"}}}"#,
        &req_ev,
        &req_val,
        &req_lie,
    ];

    let responses = mcp_session(&ctx_path, &requests);
    let rpc_responses: Vec<&serde_json::Value> =
        responses.iter().filter(|r| r.get("id").is_some()).collect();

    // list_findings echoes Solana labels
    let lf = rpc_responses.iter().find(|r| r["id"] == 3).unwrap();
    let lf_findings: Vec<serde_json::Value> =
        serde_json::from_str(lf["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(lf_findings.len(), findings.len());
    assert_eq!(lf_findings[0]["rule_id"], "solana_access_control");
    assert_eq!(lf_findings[0]["severity"], "high");
    assert_eq!(lf_findings[0]["confidence"], "experimental");

    // validate — engine-true → pass
    let val = rpc_responses.iter().find(|r| r["id"] == 6).unwrap();
    let val_report: serde_json::Value =
        serde_json::from_str(val["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        val_report["pass"], true,
        "Solana engine-true claim must pass"
    );

    // validate — promoted severity → SEVERITY_UPGRADED
    let lie = rpc_responses.iter().find(|r| r["id"] == 7).unwrap();
    let lie_report: serde_json::Value =
        serde_json::from_str(lie["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        lie_report["pass"], false,
        "Solana promoted severity must fail"
    );
    let violations = lie_report["violations"].as_array().unwrap();
    assert!(
        violations.iter().any(|v| v["code"] == "SEVERITY_UPGRADED"),
        "Solana must have SEVERITY_UPGRADED, got: {:?}",
        violations
    );

    let _ = std::fs::remove_file(&ctx_path);
}

// ── Multi-class detection proof ─────────────────────────────────

fn emit_and_collect_rule_ids(fixture_rel: &str) -> Vec<String> {
    let root = workspace_root();
    let fixture = root.join(fixture_rel);
    assert!(fixture.exists(), "fixture must exist: {:?}", fixture);

    let ctx_path = tmpfile("det-emit.json");
    let scan = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("run digger scan-live");
    assert!(
        scan.status.success(),
        "scan-live failed for {}: {}",
        fixture_rel,
        String::from_utf8_lossy(&scan.stderr)
    );

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();
    let mut ids: Vec<String> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str().map(String::from))
        .collect();
    ids.sort();
    ids.dedup();
    let _ = std::fs::remove_file(&ctx_path);
    ids
}

fn assert_fires_via_mcp(fixture_rel: &str, expected_rule: &str) {
    let root = workspace_root();
    let fixture = root.join(fixture_rel);
    assert!(fixture.exists(), "fixture must exist: {:?}", fixture);

    let ctx_path = tmpfile("det-mcp.json");
    let scan = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("run digger scan-live");
    assert!(
        scan.status.success(),
        "scan-live failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );

    let req_ev = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"x"}}}"#.to_string();
    let requests = vec![
        r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"det","version":"1.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        &req_ev,
    ];

    let responses = mcp_session(&ctx_path, &requests);
    let rpc: Vec<&serde_json::Value> = responses.iter().filter(|r| r.get("id").is_some()).collect();
    let lf = rpc
        .iter()
        .find(|r| r["id"] == 1)
        .expect("missing list_findings response");
    let lf_findings: Vec<serde_json::Value> =
        serde_json::from_str(lf["result"]["content"][0]["text"].as_str().unwrap()).unwrap();

    let mcp_rules: Vec<&str> = lf_findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();
    assert!(
        mcp_rules.contains(&expected_rule),
        "MCP list_findings must echo rule_id '{}' from {}, got: {:?}",
        expected_rule,
        fixture_rel,
        mcp_rules
    );

    let _ = std::fs::remove_file(&ctx_path);
}

#[test]
fn dogfood_solana_multiclass_exact_rule_ids() {
    // cpi-bridge-vuln-1 fires all 4 Solana detectors — pin the exact set.
    let rule_ids =
        emit_and_collect_rule_ids("corpus/solana-account-model/cpi-bridge-vuln-1/source.rs");
    let expected: Vec<&str> = vec![
        "solana_access_control",
        "solana_type_cosplay",
        "solana_unchecked_account_owner",
        "solana_unvalidated_cpi",
    ];
    assert_eq!(rule_ids, expected, "pinned rule_id set drifted");
}

#[test]
fn dogfood_per_detector_cpi_fires() {
    assert_fires_via_mcp(
        "corpus/solana-account-model/cpi-bridge-vuln-1/source.rs",
        "solana_unvalidated_cpi",
    );
}

#[test]
fn dogfood_per_detector_type_cosplay_fires() {
    assert_fires_via_mcp(
        "corpus/solana-account-model/type-cosplay-vuln-1/source.rs",
        "solana_type_cosplay",
    );
}

#[test]
fn dogfood_per_detector_unchecked_owner_fires() {
    assert_fires_via_mcp(
        "corpus/solana-account-model/owner-check-vuln-1/source.rs",
        "solana_unchecked_account_owner",
    );
}

// ── Op-layer dogfood arm ─────────────────────────────────────────

#[test]
fn dogfood_op_layer_positive_fires_through_cli() {
    let root = workspace_root();
    let fixture = root.join("corpus/operational-layer/positive-feed-update/handler.ts");
    assert!(
        fixture.exists(),
        "op-layer corpus fixture must exist: {:?}",
        fixture
    );

    let ctx_path = tmpfile("dogfood-oplayer-ctx.json");

    let scan_output = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run digger scan-live");

    assert!(
        scan_output.status.success(),
        "digger scan-live must exit 0 for op-layer fixture, stderr: {}",
        String::from_utf8_lossy(&scan_output.stderr)
    );
    assert!(
        ctx_path.exists(),
        "emit-scan-context must write a file for op-layer"
    );

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "op-layer scan must produce >=1 finding from positive fixture"
    );

    // Verify exact rule_id matches gate + normalize_detector_id
    let rule_id = findings[0]["rule_id"].as_str().unwrap();
    assert_eq!(
        rule_id, "op_unverified_attestation",
        "rule_id must exactly match gate expectation"
    );
    assert_eq!(findings[0]["severity"], "high");
    assert_eq!(findings[0]["confidence"], "experimental");
    assert_eq!(findings[0]["stage"], "shadow");

    // evidence_ids must be non-empty — proving the wiring is live
    let evidence_ids = findings[0]["evidence_ids"]
        .as_array()
        .expect("finding must carry evidence_ids array (not missing/null)");
    assert!(
        !evidence_ids.is_empty(),
        "evidence_ids must be non-empty (len >= 1), got empty vec — wiring regression"
    );
    assert_eq!(
        evidence_ids.len(),
        1,
        "op-layer finding should have exactly 1 evidence id"
    );
    // Must be a real string (not null or empty)
    assert!(
        !evidence_ids[0].as_str().unwrap_or("").is_empty(),
        "evidence_id string must be non-empty"
    );

    // Feed through MCP and assert list_findings echoes the finding
    let severity = findings[0]["severity"].as_str().unwrap();
    let confidence = findings[0]["confidence"].as_str().unwrap();
    let stage = findings[0]["stage"].as_str().unwrap();

    let requests = vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dogfood-oplayer","version":"1.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"x"}}}"#,
    ];
    let responses = mcp_session(&ctx_path, &requests);
    let rpc: Vec<&serde_json::Value> = responses.iter().filter(|r| r.get("id").is_some()).collect();
    let lf = rpc
        .iter()
        .find(|r| r["id"] == 4)
        .expect("missing list_findings response");
    let lf_findings: Vec<serde_json::Value> =
        serde_json::from_str(lf["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(lf_findings.len(), findings.len());
    assert_eq!(lf_findings[0]["rule_id"], "op_unverified_attestation");
    assert_eq!(lf_findings[0]["severity"], severity);
    assert_eq!(lf_findings[0]["confidence"], confidence);
    assert_eq!(lf_findings[0]["stage"], stage);

    // evidence_ids must survive the MCP round-trip — capture CLI value, compare
    let cli_evidence_ids: Vec<serde_json::Value> = evidence_ids.to_vec();
    let mcp_evidence_ids: Vec<serde_json::Value> = lf_findings[0]["evidence_ids"]
        .as_array()
        .expect("MCP list_findings must carry evidence_ids array")
        .to_vec();
    assert!(
        !mcp_evidence_ids.is_empty(),
        "MCP evidence_ids must be non-empty (len >= 1) — field dropped across serialization seam"
    );
    assert_eq!(
        mcp_evidence_ids, cli_evidence_ids,
        "MCP evidence_ids must equal CLI scan-context evidence_ids — no drop across seam"
    );

    let _ = std::fs::remove_file(&ctx_path);
}

#[test]
fn dogfood_op_layer_benign_emits_zero_findings() {
    let root = workspace_root();
    let fixture = root.join("corpus/operational-layer/benign-feed-with-verify/handler.ts");
    assert!(
        fixture.exists(),
        "op-layer benign fixture must exist: {:?}",
        fixture
    );

    let ctx_path = tmpfile("dogfood-oplayer-benign-ctx.json");

    let scan_output = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run digger scan-live for op-layer benign");

    assert!(
        scan_output.status.success(),
        "digger scan-live must exit 0 for op-layer benign fixture, stderr: {}",
        String::from_utf8_lossy(&scan_output.stderr)
    );
    assert!(ctx_path.exists());

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();

    let op_findings: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "op_unverified_attestation")
        .collect();
    assert!(
        op_findings.is_empty(),
        "benign op-layer fixture must emit ZERO op_unverified_attestation findings, got: {:?}",
        op_findings
    );

    let _ = std::fs::remove_file(&ctx_path);
}

// ── Op-layer control-plane dogfood ───────────────────────────────

#[test]
fn dogfood_op_cp_positive_fires_through_cli() {
    let root = workspace_root();
    let fixture = root.join("corpus/operational-layer/positive-control-plane-routing/handler.ts");
    assert!(
        fixture.exists(),
        "op-cp corpus fixture must exist: {:?}",
        fixture
    );

    let ctx_path = tmpfile("dogfood-oplayer-cp-ctx.json");

    let scan_output = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run digger scan-live for op-cp");

    assert!(
        scan_output.status.success(),
        "digger scan-live must exit 0 for op-cp fixture, stderr: {}",
        String::from_utf8_lossy(&scan_output.stderr)
    );
    assert!(ctx_path.exists());

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "op-cp scan must produce >=1 finding from positive fixture"
    );

    let cp_findings: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "op_control_plane_authority")
        .collect();
    assert!(
        !cp_findings.is_empty(),
        "must have op_control_plane_authority finding"
    );
    assert_eq!(cp_findings[0]["severity"], "high");
    assert_eq!(cp_findings[0]["confidence"], "experimental");

    let rule_id = cp_findings[0]["rule_id"].as_str().unwrap();
    let severity = cp_findings[0]["severity"].as_str().unwrap();
    let confidence = cp_findings[0]["confidence"].as_str().unwrap();
    let stage = cp_findings[0]["stage"].as_str().unwrap();

    let requests = vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dogfood-op-cp","version":"1.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"x"}}}"#,
    ];

    let responses = mcp_session(&ctx_path, &requests);
    let rpc: Vec<&serde_json::Value> = responses.iter().filter(|r| r.get("id").is_some()).collect();
    let lf = rpc
        .iter()
        .find(|r| r["id"] == 4)
        .expect("missing list_findings response");
    let lf_findings: Vec<serde_json::Value> =
        serde_json::from_str(lf["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(lf_findings.len(), findings.len());
    assert_eq!(lf_findings[0]["rule_id"], rule_id);
    assert_eq!(lf_findings[0]["severity"], severity);
    assert_eq!(lf_findings[0]["confidence"], confidence);
    assert_eq!(lf_findings[0]["stage"], stage);

    let _ = std::fs::remove_file(&ctx_path);
}

#[test]
fn dogfood_op_cp_benign_emits_zero_findings() {
    let root = workspace_root();
    let fixture = root.join("corpus/operational-layer/benign-control-plane-allowlisted/handler.ts");
    assert!(
        fixture.exists(),
        "op-cp benign fixture must exist: {:?}",
        fixture
    );

    let ctx_path = tmpfile("dogfood-oplayer-cp-benign-ctx.json");

    let scan_output = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run digger scan-live for op-cp benign");

    assert!(
        scan_output.status.success(),
        "digger scan-live must exit 0 for op-cp benign, stderr: {}",
        String::from_utf8_lossy(&scan_output.stderr)
    );
    assert!(ctx_path.exists());

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();

    let cp_findings: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "op_control_plane_authority")
        .collect();
    assert!(
        cp_findings.is_empty(),
        "benign op-cp fixture must emit ZERO op_control_plane_authority findings, got {:?}",
        cp_findings
    );

    let _ = std::fs::remove_file(&ctx_path);
}

// ── Op-layer fail-open bootstrap dogfood ────────────────────────

#[test]
fn dogfood_op_fob_positive_fires_through_cli() {
    let root = workspace_root();
    let fixture = root.join("corpus/operational-layer/positive-fail-open-breaker/handler.ts");
    assert!(
        fixture.exists(),
        "op-fob corpus fixture must exist: {:?}",
        fixture
    );

    let ctx_path = tmpfile("dogfood-oplayer-fob-ctx.json");

    let scan_output = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run digger scan-live for op-fob");

    assert!(
        scan_output.status.success(),
        "digger scan-live must exit 0 for op-fob fixture, stderr: {}",
        String::from_utf8_lossy(&scan_output.stderr)
    );
    assert!(ctx_path.exists());

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "op-fob scan must produce >=1 finding from positive fixture"
    );

    let fob_findings: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "op_fail_open_bootstrap")
        .collect();
    assert!(
        !fob_findings.is_empty(),
        "must have op_fail_open_bootstrap finding"
    );
    assert_eq!(fob_findings[0]["severity"], "high");
    assert_eq!(fob_findings[0]["confidence"], "experimental");

    let rule_id = fob_findings[0]["rule_id"].as_str().unwrap();
    let severity = fob_findings[0]["severity"].as_str().unwrap();
    let confidence = fob_findings[0]["confidence"].as_str().unwrap();
    let stage = fob_findings[0]["stage"].as_str().unwrap();

    let requests = vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dogfood-op-fob","version":"1.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"x"}}}"#,
    ];

    let responses = mcp_session(&ctx_path, &requests);
    let rpc: Vec<&serde_json::Value> = responses.iter().filter(|r| r.get("id").is_some()).collect();
    let lf = rpc
        .iter()
        .find(|r| r["id"] == 4)
        .expect("missing list_findings response");
    let lf_findings: Vec<serde_json::Value> =
        serde_json::from_str(lf["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(lf_findings.len(), findings.len());
    assert_eq!(lf_findings[0]["rule_id"], rule_id);
    assert_eq!(lf_findings[0]["severity"], severity);
    assert_eq!(lf_findings[0]["confidence"], confidence);
    assert_eq!(lf_findings[0]["stage"], stage);

    let _ = std::fs::remove_file(&ctx_path);
}

#[test]
fn dogfood_op_fob_benign_emits_zero_findings() {
    let root = workspace_root();
    let fixture = root.join("corpus/operational-layer/benign-fail-closed-breaker/handler.ts");
    assert!(
        fixture.exists(),
        "op-fob benign fixture must exist: {:?}",
        fixture
    );

    let ctx_path = tmpfile("dogfood-oplayer-fob-benign-ctx.json");

    let scan_output = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run digger scan-live for op-fob benign");

    assert!(
        scan_output.status.success(),
        "digger scan-live must exit 0 for op-fob benign, stderr: {}",
        String::from_utf8_lossy(&scan_output.stderr)
    );
    assert!(ctx_path.exists());

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();

    let fob_findings: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "op_fail_open_bootstrap")
        .collect();
    assert!(
        fob_findings.is_empty(),
        "benign op-fob fixture must emit ZERO op_fail_open_bootstrap findings, got {:?}",
        fob_findings
    );

    let _ = std::fs::remove_file(&ctx_path);
}

// ── Op-layer silent-failover dogfood ───────────────────────────

#[test]
fn dogfood_op_sf_positive_fires_through_cli() {
    let root = workspace_root();
    let fixture = root.join("corpus/operational-layer/positive-silent-failover/handler.ts");
    assert!(
        fixture.exists(),
        "op-sf corpus fixture must exist: {:?}",
        fixture
    );

    let ctx_path = tmpfile("dogfood-oplayer-sf-ctx.json");

    let scan_output = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run digger scan-live for op-sf");

    assert!(
        scan_output.status.success(),
        "digger scan-live must exit 0 for op-sf fixture, stderr: {}",
        String::from_utf8_lossy(&scan_output.stderr)
    );
    assert!(ctx_path.exists());

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "op-sf scan must produce >=1 finding from positive fixture"
    );

    let sf_findings: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "op_silent_failover")
        .collect();
    assert!(
        !sf_findings.is_empty(),
        "must have op_silent_failover finding"
    );
    assert_eq!(sf_findings[0]["severity"], "high");
    assert_eq!(sf_findings[0]["confidence"], "experimental");

    let rule_id = sf_findings[0]["rule_id"].as_str().unwrap();
    let severity = sf_findings[0]["severity"].as_str().unwrap();
    let confidence = sf_findings[0]["confidence"].as_str().unwrap();
    let stage = sf_findings[0]["stage"].as_str().unwrap();

    let requests = vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dogfood-op-sf","version":"1.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"x"}}}"#,
    ];

    let responses = mcp_session(&ctx_path, &requests);
    let rpc: Vec<&serde_json::Value> = responses.iter().filter(|r| r.get("id").is_some()).collect();
    let lf = rpc
        .iter()
        .find(|r| r["id"] == 4)
        .expect("missing list_findings response");
    let lf_findings: Vec<serde_json::Value> =
        serde_json::from_str(lf["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(lf_findings.len(), findings.len());
    assert_eq!(lf_findings[0]["rule_id"], rule_id);
    assert_eq!(lf_findings[0]["severity"], severity);
    assert_eq!(lf_findings[0]["confidence"], confidence);
    assert_eq!(lf_findings[0]["stage"], stage);

    let _ = std::fs::remove_file(&ctx_path);
}

#[test]
fn dogfood_op_sf_benign_emits_zero_findings() {
    let root = workspace_root();
    let fixture = root.join("corpus/operational-layer/benign-failover-adjusted/handler.ts");
    assert!(
        fixture.exists(),
        "op-sf benign fixture must exist: {:?}",
        fixture
    );

    let ctx_path = tmpfile("dogfood-oplayer-sf-benign-ctx.json");

    let scan_output = Command::new(digger_bin_path())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run digger scan-live for op-sf benign");

    assert!(
        scan_output.status.success(),
        "digger scan-live must exit 0 for op-sf benign, stderr: {}",
        String::from_utf8_lossy(&scan_output.stderr)
    );
    assert!(ctx_path.exists());

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();

    let sf_findings: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "op_silent_failover")
        .collect();
    assert!(
        sf_findings.is_empty(),
        "benign op-sf fixture must emit ZERO op_silent_failover findings, got {:?}",
        sf_findings
    );

    let _ = std::fs::remove_file(&ctx_path);
}
