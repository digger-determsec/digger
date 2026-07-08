use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use digger_agent::contract::*;
use digger_agent::guardrails::*;
use digger_platform::storage::Storage;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

const READ_TIMEOUT: Duration = Duration::from_secs(10);

fn test_scan_ctx() -> ScanContext {
    ScanContext {
        scan_id: "scan-test".into(),
        findings: vec![FindingView {
            finding_id: "f-1".into(),
            rule_id: "access_control".into(),
            severity: Severity::High,
            confidence: Confidence::Experimental,
            stage: Stage::Shadow,
            summary: "migrateStake lacks auth check".into(),
            locations: vec![LocationView {
                file: "StaxLPStaking.sol".into(),
                line_start: Some(42),
                line_end: Some(60),
                symbol: Some("migrateStake".into()),
            }],
            evidence_ids: vec!["ev-1".into()],
        }],
        predicate_states: vec![PredicateState {
            predicate_id: "pred-access-control-1".into(),
            outcome: PredicateOutcomeState::Undetermined,
            missing_facts: vec!["account_owner_mismatch".into()],
            resolved_facts: BTreeMap::new(),
            stage: Stage::Shadow,
            tier: "TierA".into(),
        }],
    }
}

fn write_context_file() -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("digger-mcp-test-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("scan_context.json");
    let ctx = test_scan_ctx();
    let json = serde_json::to_string_pretty(&ctx).unwrap();
    std::fs::write(&path, json).unwrap();
    path
}

fn spawn_mcp(ctx_path: &std::path::Path) -> std::process::Child {
    let bin = env!("CARGO_BIN_EXE_digger_mcp");
    Command::new(bin)
        .arg(ctx_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("DIGGER_MCP_KEY", "test-bootstrap-key-for-mcp-tests")
        .env("DIGGER_API_KEY", "test-bootstrap-key-for-mcp-tests")
        .spawn()
        .unwrap()
}

fn close_stdin(child: &mut std::process::Child) {
    if let Some(stdin) = child.stdin.take() {
        drop(stdin);
    }
}

fn read_stdout_lines(mut stdout: Box<dyn Read + Send>, tx: mpsc::Sender<Result<String, String>>) {
    let mut one_line = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        match stdout.read(&mut buf) {
            Ok(0) => {
                if !one_line.is_empty() {
                    let s = String::from_utf8_lossy(&one_line).to_string();
                    let _ = tx.send(Ok(s));
                }
                break;
            }
            Ok(n) => {
                for &b in &buf[..n] {
                    if b == b'\n' {
                        if !one_line.is_empty() {
                            let s = String::from_utf8_lossy(&one_line).to_string();
                            if !s.trim().is_empty() {
                                let _ = tx.send(Ok(s));
                            }
                            one_line.clear();
                        }
                    } else {
                        one_line.push(b);
                    }
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e.to_string()));
                break;
            }
        }
    }
}

fn rpc_roundtrip(child: &mut std::process::Child, request: &str) -> serde_json::Value {
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(request.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    read_one_response_from_child(child)
}

fn read_one_response_from_child(child: &mut std::process::Child) -> serde_json::Value {
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        read_stdout_lines(Box::new(stdout), tx);
    });

    match rx.recv_timeout(READ_TIMEOUT) {
        Ok(Ok(line)) => serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!("parse response {}: {}", line, e);
        }),
        Ok(Err(e)) => panic!("stdout read error: {}", e),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("timeout waiting for MCP response after {:?}", READ_TIMEOUT);
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("stdout channel disconnected without response");
        }
    }
}

fn read_two_responses_from_child(
    child: &mut std::process::Child,
) -> (serde_json::Value, serde_json::Value) {
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        read_stdout_lines(Box::new(stdout), tx);
    });

    let deadline = Instant::now() + READ_TIMEOUT;

    let resp1 = match rx.recv_timeout(READ_TIMEOUT) {
        Ok(Ok(line)) => serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!("parse response 1 {}: {}", line, e);
        }),
        Ok(Err(e)) => panic!("stdout read error on response 1: {}", e),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("timeout waiting for MCP response 1");
        }
    };

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("timeout waiting for MCP response 2");
    }

    let resp2 = match rx.recv_timeout(remaining) {
        Ok(Ok(line)) => serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!("parse response 2 {}: {}", line, e);
        }),
        Ok(Err(e)) => panic!("stdout read error on response 2: {}", e),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("timeout waiting for MCP response 2");
        }
    };

    (resp1, resp2)
}

fn kill_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn cleanup(ctx_path: &std::path::Path) {
    if let Some(parent) = ctx_path.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
}

#[test]
fn stdio_tools_list_returns_4_readonly() {
    let ctx_path = write_context_file();
    let mut child = spawn_mcp(&ctx_path);

    let resp = rpc_roundtrip(
        &mut child,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
    );

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);

    let tools = resp["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 4, "must expose exactly 4 tools");

    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"list_findings"));
    assert!(names.contains(&"get_evidence"));
    assert!(names.contains(&"get_explanation_context"));
    assert!(names.contains(&"validate_assistant_output"));

    for t in tools {
        assert_eq!(
            t["annotations"]["readOnlyHint"], true,
            "tool {} must be readOnlyHint",
            t["name"]
        );
    }

    kill_child(&mut child);
    cleanup(&ctx_path);
}

#[test]
fn stdio_list_findings_echoes_engine_labels() {
    let ctx_path = write_context_file();
    let mut child = spawn_mcp(&ctx_path);

    let resp = rpc_roundtrip(
        &mut child,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"scan-test"}}}"#,
    );

    let text = &resp["result"]["content"][0]["text"];
    let findings: Vec<serde_json::Value> = serde_json::from_str(text.as_str().unwrap()).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["severity"], "high");
    assert_eq!(findings[0]["confidence"], "experimental");
    assert_eq!(findings[0]["stage"], "shadow");

    kill_child(&mut child);
    cleanup(&ctx_path);
}

#[test]
fn stdio_validate_rejects_promoted_severity() {
    let ctx_path = write_context_file();
    let mut child = spawn_mcp(&ctx_path);

    let true_claim = serde_json::json!({
        "scan_id": "scan-test",
        "claimed_findings": [{
            "finding_id": "f-1",
            "rule_id": "access_control",
            "severity": "high",
            "confidence": "experimental",
            "stage": "shadow",
            "locations": [{"file": "StaxLPStaking.sol", "line_start": 42, "line_end": 60, "symbol": "migrateStake"}],
            "exploit_status": "none",
            "claim_text": "benign"
        }],
        "prose": "benign"
    });

    let bad_claim = serde_json::json!({
        "scan_id": "scan-test",
        "claimed_findings": [{
            "finding_id": "f-1",
            "rule_id": "access_control",
            "severity": "critical",
            "confidence": "experimental",
            "stage": "shadow",
            "locations": [{"file": "StaxLPStaking.sol", "line_start": 42, "line_end": 60, "symbol": "migrateStake"}],
            "exploit_status": "none",
            "claim_text": "promoted"
        }],
        "prose": "promoted"
    });

    let req1 = format!(
        r#"{{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{{"name":"validate_assistant_output","arguments":{}}}}}"#,
        true_claim
    );
    let req2 = format!(
        r#"{{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{{"name":"validate_assistant_output","arguments":{}}}}}"#,
        bad_claim
    );

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(req1.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.write_all(req2.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    close_stdin(&mut child);

    let (resp1, resp2) = read_two_responses_from_child(&mut child);

    let report: serde_json::Value =
        serde_json::from_str(resp1["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(report["pass"], true, "engine-true claim must pass");

    let report2: serde_json::Value =
        serde_json::from_str(resp2["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(report2["pass"], false, "promoted severity must fail");
    let violations = report2["violations"].as_array().unwrap();
    assert!(
        violations.iter().any(|v| v["code"] == "SEVERITY_UPGRADED"),
        "must have SEVERITY_UPGRADED violation, got: {:?}",
        violations
    );

    kill_child(&mut child);
    cleanup(&ctx_path);
}

#[test]
fn stdio_bridge_scan_context_list_findings() {
    let scan_ctx = ScanContext {
        scan_id: "scan-solana-corpus".into(),
        findings: vec![FindingView {
            finding_id: "f-abc123".into(),
            rule_id: "solana_access_control".into(),
            severity: Severity::High,
            confidence: Confidence::Experimental,
            stage: Stage::Shadow,
            summary: "missing_authority_check".into(),
            locations: vec![],
            evidence_ids: vec![],
        }],
        predicate_states: vec![],
    };

    let dir = std::env::temp_dir().join(format!(
        "digger-mcp-bridge-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ctx_path = dir.join("scan_ctx.json");
    std::fs::write(&ctx_path, serde_json::to_string_pretty(&scan_ctx).unwrap()).unwrap();

    let mut child = spawn_mcp(&ctx_path);

    let resp = rpc_roundtrip(
        &mut child,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"scan-test"}}}"#,
    );

    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let findings: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["rule_id"], "solana_access_control");
    assert_eq!(findings[0]["severity"], "high");
    assert_eq!(findings[0]["confidence"], "experimental");
    assert_eq!(findings[0]["stage"], "shadow");

    kill_child(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
}

// ── MCP negative tests: auth rejection ──────────────────────────

fn write_temp_ctx() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "digger-mcp-neg-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ctx_path = dir.join("scan_ctx.json");
    let scan_ctx = test_scan_ctx();
    std::fs::write(&ctx_path, serde_json::to_string_pretty(&scan_ctx).unwrap()).unwrap();
    ctx_path
}

fn spawn_mcp_with_keys(ctx: &std::path::Path, mcp_key: &str, api_key: &str) -> std::process::Child {
    let bin = env!("CARGO_BIN_EXE_digger_mcp");
    Command::new(bin)
        .arg(ctx)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("DIGGER_MCP_KEY", mcp_key)
        .env("DIGGER_API_KEY", api_key)
        .spawn()
        .unwrap()
}

#[test]
fn test_mcp_rejects_bogus_key_with_different_bootstrap() {
    let ctx = write_temp_ctx();
    // Bogus key ≠ bootstrap → should exit non-zero
    let mut child = spawn_mcp_with_keys(&ctx, "bogus-garbage-key", "different-bootstrap-value");
    let exit = child.wait().unwrap();
    assert!(
        !exit.success(),
        "bogus key with different bootstrap must be rejected"
    );
}

#[test]
fn test_mcp_rejects_empty_key() {
    let ctx = write_temp_ctx();
    // Empty DIGGER_MCP_KEY → should exit non-zero
    let mut child = spawn_mcp_with_keys(&ctx, "", "some-bootstrap");
    let exit = child.wait().unwrap();
    assert!(!exit.success(), "empty key must be rejected");
}

#[test]
fn test_mcp_accepts_bootstrap_key_match() {
    let ctx = write_temp_ctx();
    // Bootstrap key matches DIGGER_MCP_KEY → auth must NOT reject.
    // The binary may panic during ScanContext loading on CI (env difference),
    // but any exit code other than 1 means auth passed.
    let bin = env!("CARGO_BIN_EXE_digger_mcp");
    let output = Command::new(bin)
        .arg(&ctx)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env("DIGGER_MCP_KEY", "my-bootstrap-secret-123")
        .env("DIGGER_API_KEY", "my-bootstrap-secret-123")
        .output()
        .unwrap();
    let code = output.status.code().unwrap_or(1);
    assert_ne!(
        code,
        1,
        "bootstrap key should be accepted, not rejected (exit: {}, stderr: {})",
        code,
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── Live ScanContext from store test ────────────────────────────

#[test]
fn test_mcp_loads_scan_context_from_store() {
    // Set up a temporary platform store and write a ScanContext into it
    let dir = std::env::temp_dir().join(format!(
        "digger-mcp-store-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let store = digger_platform::json_storage::JsonStorage::new(&dir);
    digger_platform::storage::Storage::init(&store).unwrap();

    let scan_ctx = test_scan_ctx();
    let scan_id = scan_ctx.scan_id.clone();
    let value = serde_json::to_value(&scan_ctx).unwrap();
    store.write_json("scan_contexts", &scan_id, &value).unwrap();

    // Spawn MCP with DIGGER_SCAN_CONTEXT_ID and DIGGER_STORAGE_DIR pointing to the same store
    let bin = env!("CARGO_BIN_EXE_digger_mcp");
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("DIGGER_MCP_KEY", "test-bootstrap-key-for-store")
        .env("DIGGER_API_KEY", "test-bootstrap-key-for-store")
        .env("DIGGER_SCAN_CONTEXT_ID", &scan_id)
        .env("DIGGER_STORAGE_DIR", &dir)
        .spawn()
        .unwrap();

    // Call list_findings via tools/call
    let resp = rpc_roundtrip(
        &mut child,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"scan-test"}}}"#,
    );

    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let findings: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
    assert_eq!(findings.len(), 1, "should find the stored finding");
    assert_eq!(findings[0]["rule_id"], "access_control");

    kill_child(&mut child);
}
