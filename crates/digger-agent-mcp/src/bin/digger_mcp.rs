use digger_agent::guardrails::ScanContext;
use std::io::{BufRead, Write};

fn main() {
    // ── API key validation (FIX A) ──
    // DIGGER_MCP_KEY: the key presented by the connecting agent/client
    // DIGGER_API_KEY: the bootstrap/admin secret (for local dev only)
    let presented_key = match std::env::var("DIGGER_MCP_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!("FATAL: DIGGER_MCP_KEY not set. Provide the API key via DIGGER_MCP_KEY.");
            std::process::exit(1);
        }
    };

    // Tier 1: Validate against stored hashed keys
    let store = digger_platform::config::create_storage();
    let _ = store.init();
    let stored_valid = digger_platform::api_keys::validate_key(&*store, &presented_key).is_ok();

    // Tier 2: Bootstrap secret (constant-time compare)
    let bootstrap_valid = match std::env::var("DIGGER_API_KEY") {
        Ok(bootstrap) if !bootstrap.is_empty() && bootstrap.len() == presented_key.len() => {
            digger_platform::timing::timing_safe_eq(&presented_key, &bootstrap)
        }
        _ => false,
    };

    if !stored_valid && !bootstrap_valid {
        eprintln!(
            "FATAL: The provided API key is invalid, revoked, or does not match bootstrap. \
             DIGGER_MCP_KEY must be a valid stored key or match DIGGER_API_KEY exactly."
        );
        std::process::exit(1);
    }

    // ── Load ScanContext: store lookup (by scan_id) → file → error ──
    // Precedence:
    // 1. DIGGER_SCAN_CONTEXT_ID or first arg starting with "scan:" → store lookup
    // 2. File path (first arg or DIGGER_SCAN_CONTEXT env) → file read
    // 3. Neither → clear error

    let ctx = load_scan_context(&*store);

    eprintln!("Digger MCP Server v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("API key validated. Listening on stdin...");

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line_result in stdin.lock().lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("stdin read error: {}", e);
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                let resp = jsonrpc_error(None, -32602, "Parse error");
                write_response(&mut out, &resp);
                continue;
            }
        };

        let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let id = request.get("id");

        // Notifications (no id) → no response
        if method.starts_with("notifications/") || id.is_none() {
            continue;
        }

        let id = id.cloned().unwrap_or(serde_json::Value::Null);

        let resp = match method {
            "initialize" => {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "digger-mcp", "version": env!("CARGO_PKG_VERSION")}
                    }
                })
            }
            "tools/list" => {
                let tools: Vec<serde_json::Value> = digger_agent_mcp::tools::list_tools()
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                            "annotations": {"readOnlyHint": t.read_only_hint}
                        })
                    })
                    .collect();
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"tools": tools}
                })
            }
            "tools/call" => {
                let params = request
                    .get("params")
                    .cloned()
                    .unwrap_or(serde_json::json!({}));
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or(serde_json::json!({}));

                match dispatch_tool(tool_name, &arguments, &ctx) {
                    Ok(text) => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{"type": "text", "text": text}],
                            "isError": false
                        }
                    }),
                    Err(e) => jsonrpc_error(Some(id), -32603, &e),
                }
            }
            _ => jsonrpc_error(Some(id), -32601, &format!("Unknown method: {}", method)),
        };

        write_response(&mut out, &resp);
    }
}

fn dispatch_tool(
    name: &str,
    args: &serde_json::Value,
    ctx: &ScanContext,
) -> Result<String, String> {
    match name {
        "list_findings" => {
            let scan_id = args.get("scan_id").and_then(|v| v.as_str()).unwrap_or("");
            let findings = digger_agent_mcp::tools::tool_list_findings(ctx, scan_id);
            serde_json::to_string(&findings).map_err(|e| e.to_string())
        }
        "get_evidence" => {
            let finding_id = args
                .get("finding_id")
                .and_then(|v| v.as_str())
                .ok_or("missing finding_id")?;
            let evidence = digger_agent_mcp::tools::tool_get_evidence(ctx, finding_id);
            serde_json::to_string(&evidence).map_err(|e| e.to_string())
        }
        "get_explanation_context" => {
            let finding_id = args
                .get("finding_id")
                .and_then(|v| v.as_str())
                .ok_or("missing finding_id")?;
            match digger_agent_mcp::tools::tool_get_explanation_context(ctx, finding_id) {
                Some(context) => serde_json::to_string(&context).map_err(|e| e.to_string()),
                None => Err(format!("finding not found: {}", finding_id)),
            }
        }
        "validate_assistant_output" => {
            let claim: digger_agent::guardrails::AssistantClaim =
                serde_json::from_value(args.clone()).map_err(|e| e.to_string())?;
            let report = digger_agent_mcp::tools::tool_validate_assistant_output(&claim, ctx);
            serde_json::to_string(&report).map_err(|e| e.to_string())
        }
        _ => Err(format!("unknown tool: {}", name)),
    }
}

fn jsonrpc_error(id: Option<serde_json::Value>, code: i32, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(serde_json::Value::Null),
        "error": {"code": code, "message": message}
    })
}

fn write_response(out: &mut impl Write, resp: &serde_json::Value) {
    let line = serde_json::to_string(resp).unwrap_or_default();
    let _ = writeln!(out, "{}", line);
    let _ = out.flush();
}

const SCAN_CONTEXTS: &str = "scan_contexts";

fn load_scan_context(store: &dyn digger_platform::storage::Storage) -> ScanContext {
    // Try store lookup by scan_id first
    if let Ok(scan_id) = std::env::var("DIGGER_SCAN_CONTEXT_ID") {
        if !scan_id.is_empty() {
            if let Ok(val) = store.read_json(SCAN_CONTEXTS, &scan_id) {
                match serde_json::from_value::<ScanContext>(val) {
                    Ok(ctx) => {
                        eprintln!("Loaded ScanContext from store (scan_id={})", scan_id);
                        return ctx;
                    }
                    Err(e) => {
                        eprintln!(
                            "WARNING: stored ScanContext for '{}' is malformed: {}",
                            scan_id, e
                        );
                    }
                }
            } else {
                eprintln!(
                    "WARNING: ScanContext '{}' not found in store, trying file fallback",
                    scan_id
                );
            }
        }
    }

    // Try first arg as file path
    let ctx_path = match std::env::args()
        .nth(1)
        .or_else(|| std::env::var("DIGGER_SCAN_CONTEXT").ok())
    {
        Some(p) => p,
        None => {
            eprintln!(
                "No ScanContext source found. Provide either:\n\
                 - DIGGER_SCAN_CONTEXT_ID=<scan_id> to load from platform store, or\n\
                 - A file path as the first argument or via DIGGER_SCAN_CONTEXT=<path>"
            );
            std::process::exit(1);
        }
    };

    let ctx_data = match std::fs::read_to_string(&ctx_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "Error: failed to read scan context file {}: {}",
                ctx_path, e
            );
            std::process::exit(1);
        }
    };
    match serde_json::from_str(&ctx_data) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Error: failed to parse scan context: {}", e);
            std::process::exit(1);
        }
    }
}
