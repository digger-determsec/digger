//! Quickstart smoke test — proves the skill's documented flow works end-to-end.
//! Mirrors quickstart.sh logic in pure Rust to avoid bash availability issues on Windows.

use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

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

fn digger_bin() -> std::path::PathBuf {
    let base = workspace_root().join("target/debug/digger");
    if base.exists() {
        base
    } else {
        workspace_root().join("target/debug/digger.exe")
    }
}

fn mcp_bin() -> std::path::PathBuf {
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

fn mcp_session(ctx: &std::path::Path, requests: &[&str]) -> Vec<serde_json::Value> {
    let inp = tmpfile("qs_in");
    let out = tmpfile("qs_out");
    let err = tmpfile("qs_err");
    {
        let mut f = std::fs::File::create(&inp).unwrap();
        for r in requests {
            writeln!(f, "{}", r).unwrap();
        }
    }
    let status = Command::new(mcp_bin())
        .arg(ctx)
        .stdin(std::fs::File::open(&inp).unwrap())
        .stdout(std::fs::File::create(&out).unwrap())
        .stderr(std::fs::File::create(&err).unwrap())
        .env("DIGGER_MCP_KEY", "test-bootstrap-key-for-quickstart")
        .env("DIGGER_API_KEY", "test-bootstrap-key-for-quickstart")
        .status()
        .expect("spawn mcp");
    assert!(status.success(), "digger_mcp exited nonzero");
    let raw = std::fs::read_to_string(&out).unwrap();
    let mut resps = Vec::new();
    for line in raw.lines() {
        let t = line.trim();
        if !t.is_empty() {
            if let Ok(v) = serde_json::from_str(t) {
                resps.push(v);
            }
        }
    }
    let _ = std::fs::remove_file(&inp);
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&err);
    resps
}

#[test]
fn quickstart_smoke_passes() {
    let root = workspace_root();
    let fixture = root.join("corpus/price-manipulation/bzx-2020/source.sol");
    assert!(fixture.exists(), "corpus fixture missing: {:?}", fixture);

    let ctx_path = tmpfile("qs-ctx.json");

    // Phase 1: scan-live
    let scan = Command::new(digger_bin())
        .args([
            "scan-live",
            "--source-file",
            fixture.to_str().unwrap(),
            "--emit-scan-context",
            ctx_path.to_str().unwrap(),
        ])
        .output()
        .expect("run digger");
    assert!(
        scan.status.success(),
        "scan-live failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );

    let ctx_json = std::fs::read_to_string(&ctx_path).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&ctx_json).unwrap();
    let findings = ctx["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "emitted >=1 finding");

    // Phase 2: MCP handshake
    let fid = findings[0]["finding_id"].as_str().unwrap();
    let rid = findings[0]["rule_id"].as_str().unwrap();
    let sev = findings[0]["severity"].as_str().unwrap();
    let conf = findings[0]["confidence"].as_str().unwrap();
    let stg = findings[0]["stage"].as_str().unwrap();

    let true_claim = serde_json::json!({"scan_id":"qs","claimed_findings":[{"finding_id":fid,"rule_id":rid,"severity":sev,"confidence":conf,"stage":stg,"locations":[],"exploit_status":"none","claim_text":"benign"}],"prose":"benign"});
    let lie_claim = serde_json::json!({"scan_id":"qs","claimed_findings":[{"finding_id":fid,"rule_id":rid,"severity":"critical","confidence":conf,"stage":stg,"locations":[],"exploit_status":"none","claim_text":"promoted"}],"prose":"promoted"});

    let r_ev = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"get_evidence","arguments":{{"finding_id":"{}"}}}}}}"#,
        fid
    );
    let r_val = format!(
        r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"validate_assistant_output","arguments":{}}}}}"#,
        true_claim
    );
    let r_lie = format!(
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"validate_assistant_output","arguments":{}}}}}"#,
        lie_claim
    );

    let requests = vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"qs","version":"1.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"x"}}}"#,
        &r_ev,
        &r_val,
        &r_lie,
    ];

    let responses = mcp_session(&ctx_path, &requests);
    let rpc: Vec<&serde_json::Value> = responses.iter().filter(|r| r.get("id").is_some()).collect();

    // 1) initialize OK
    let init = rpc.iter().find(|r| r["id"] == 1).unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");

    // 2) tools/list — 4 readOnly
    let tl = rpc.iter().find(|r| r["id"] == 2).unwrap();
    let tools = tl["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 4);
    for t in tools {
        assert_eq!(t["annotations"]["readOnlyHint"], true);
    }

    // 3) list_findings echoes engine labels
    let lf = rpc.iter().find(|r| r["id"] == 3).unwrap();
    let lf_findings: Vec<serde_json::Value> =
        serde_json::from_str(lf["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(lf_findings[0]["rule_id"], rid);
    assert_eq!(lf_findings[0]["severity"], sev);
    assert_eq!(lf_findings[0]["confidence"], conf);
    assert_eq!(lf_findings[0]["stage"], stg);

    // 4) validate — engine-true → pass
    let vr = rpc.iter().find(|r| r["id"] == 6).unwrap();
    let vrep: serde_json::Value =
        serde_json::from_str(vr["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(vrep["pass"], true);

    // 5) validate — severity promoted → SEVERITY_UPGRADED
    let lr = rpc.iter().find(|r| r["id"] == 7).unwrap();
    let lrep: serde_json::Value =
        serde_json::from_str(lr["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(lrep["pass"], false);
    assert!(lrep["violations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["code"] == "SEVERITY_UPGRADED"));

    let _ = std::fs::remove_file(&ctx_path);
}
