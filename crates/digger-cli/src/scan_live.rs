use digger_reconstruct::{
    detect_price_manipulation, detect_readonly_reentrancy, detect_solana_access_violations,
    detect_type_cosplay, detect_unchecked_owner, detect_unvalidated_cpi, recover_source_body_graph,
    Chain, EtherscanClient, ExplorerError, SolanaRpcClient, SolanaSourceFetcher, SourceFetcher,
};

use digger_agent::contract::{FindingView, PredicateState};
use digger_agent::guardrails::ScanContext;
use std::hash::{DefaultHasher, Hash, Hasher};

/// Check if a string looks like a git URL (https, ssh, or .git suffix).
fn is_git_url(s: &str) -> bool {
    digger_reconstruct::is_git_url(s)
}

const EXIT_OK: i32 = 0;
const EXIT_ERROR: i32 = 1;

/// Analysis result produced by scan.
#[derive(Debug)]
pub struct ScanResult {
    pub contract_name: String,
    pub metadata: serde_json::Value,
    pub graduated_findings: Vec<serde_json::Value>,
    pub experimental_hypotheses: Vec<serde_json::Value>,
    pub exploit_chain_count: usize,
    pub verified: bool,
    pub source_provenance: String,
    pub source_link: Option<String>,
}

/// Analyze source and return structured result.
fn analyze(
    source_text: &str,
    contract_name: &str,
    metadata: serde_json::Value,
    chain: &str,
) -> ScanResult {
    let raw = digger_parser::parse_program(source_text, "solidity");

    let mut graduated_findings: Vec<serde_json::Value> = Vec::new();
    let mut experimental_findings: Vec<serde_json::Value> = Vec::new();

    let is_solana = chain == "solana";
    let is_oplayer = chain == "op-layer";

    if is_oplayer {
        let program = digger_oplayer::parse_op_program(source_text);
        for v in digger_oplayer::detect_unverified_attestation(&program) {
            experimental_findings.push(serde_json::json!({
                "detector": "op_unverified_attestation",
                "function": v.function_id,
                "kind": v.violation_kind,
                "severity": "high",
                "confidence": "experimental",
                "evidence_refs": [v.id],
            }));
        }
        for v in digger_oplayer::detect_control_plane_authority(&program) {
            experimental_findings.push(serde_json::json!({
                "detector": "op_control_plane_authority",
                "function": v.function_id,
                "kind": v.violation_kind,
                "severity": "high",
                "confidence": "experimental",
                "evidence_refs": [v.id],
            }));
        }
        for v in digger_oplayer::detect_fail_open_bootstrap(&program) {
            experimental_findings.push(serde_json::json!({
                "detector": "op_fail_open_bootstrap",
                "function": v.function_id,
                "kind": v.violation_kind,
                "severity": "high",
                "confidence": "experimental",
                "evidence_refs": [v.id],
            }));
        }
        for v in digger_oplayer::detect_silent_failover(&program) {
            experimental_findings.push(serde_json::json!({
                "detector": "op_silent_failover",
                "function": v.function_id,
                "kind": v.violation_kind,
                "severity": "high",
                "confidence": "experimental",
                "evidence_refs": [v.id],
            }));
        }
    } else if is_solana {
        // Solana access-control detector (EXPERIMENTAL: 100% precision, 50% recall)
        let lang = "anchor";
        let raw_sol = digger_parser::parse_program(source_text, lang);
        if let Some(body) = recover_source_body_graph(&raw_sol) {
            for v in detect_solana_access_violations(&body) {
                experimental_findings.push(serde_json::json!({
                    "detector": "solana_access_control",
                    "function": v.function_id,
                    "kind": v.violation_kind,
                    "severity": "high",
                    "confidence": "experimental",
                    "precision_note": "100% precision, 50% recall (C6.6)",
                    "evidence_refs": [v.provenance.id],
                }));
            }
            for v in detect_unvalidated_cpi(&body) {
                experimental_findings.push(serde_json::json!({
                    "detector": "solana_unvalidated_cpi",
                    "function": v.function_id,
                    "kind": v.violation_kind,
                    "severity": "high",
                    "confidence": "experimental",
                    "evidence_refs": [v.provenance.id],
                }));
            }
            for v in detect_type_cosplay(&body) {
                experimental_findings.push(serde_json::json!({
                    "detector": "solana_type_cosplay",
                    "function": v.function_id,
                    "kind": v.violation_kind,
                    "severity": "high",
                    "confidence": "experimental",
                    "evidence_refs": [v.provenance.id],
                }));
            }
            for v in detect_unchecked_owner(&body) {
                experimental_findings.push(serde_json::json!({
                    "detector": "solana_unchecked_account_owner",
                    "function": v.function_id,
                    "kind": v.violation_kind,
                    "severity": "high",
                    "confidence": "experimental",
                    "evidence_refs": [v.provenance.id],
                }));
            }
        }
    } else {
        // EVM detectors (GRADUATED)
        for f in detect_price_manipulation(source_text, &raw) {
            if !f.suppressed {
                graduated_findings.push(serde_json::json!({
                    "detector": "price_manipulation",
                    "function": f.function_name,
                    "kind": "PriceOracleManipulation",
                    "severity": "high",
                    "confidence": "graduated",
                    "price_source": f.price_source,
                    "critical_action": f.critical_action,
                    "evidence_refs": [f.function_name],
                }));
            }
        }
        for f in detect_readonly_reentrancy(&raw) {
            if !f.suppressed {
                graduated_findings.push(serde_json::json!({
                    "detector": "readonly_reentrancy",
                    "function": f.function_id,
                    "kind": f.finding_kind,
                    "severity": "high",
                    "confidence": "graduated",
                    "evidence_refs": [f.provenance.id],
                }));
            }
        }
    }

    // Gen2+Gen3 pipeline (EVM only for now)
    let gen2_chain_count;
    if is_solana || is_oplayer {
        gen2_chain_count = 0;
    } else {
        let outcome = digger_pipeline::investigate_source(source_text, "solidity");
        if let Some(sys) = outcome.systems.first() {
            for h in &sys.hypotheses.hypotheses {
                experimental_findings.push(serde_json::json!({
                    "id": h.id.0,
                    "type": format!("{}", h.hypothesis_type),
                    "severity": format!("{}", h.severity),
                    "primary_function": h.primary_function,
                    "confidence": "experimental",
                }));
            }
            gen2_chain_count = sys.exploits.total_chains;
        } else {
            gen2_chain_count = 0;
        }
    }

    let provenance = metadata
        .get("source_provenance")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let source_link = metadata
        .get("source_link")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    ScanResult {
        contract_name: contract_name.to_string(),
        metadata,
        graduated_findings,
        experimental_hypotheses: experimental_findings,
        exploit_chain_count: gen2_chain_count,
        verified: true,
        source_provenance: provenance,
        source_link,
    }
}

/// Format result as JSON string.
fn to_json(result: &ScanResult) -> String {
    serde_json::json!({
        "contract": {
            "name": result.contract_name,
            "verified": result.verified,
            "source_provenance": result.source_provenance,
            "source_link": result.source_link,
        },
        "graduated_findings": result.graduated_findings,
        "experimental_hypotheses": result.experimental_hypotheses,
        "exploit_chains": result.exploit_chain_count,
        "summary": {
            "graduated_count": result.graduated_findings.len(),
            "experimental_count": result.experimental_hypotheses.len(),
        },
    })
    .to_string()
}

/// Format result for human-readable output.
fn to_human(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("\n  digger scan\n");
    out.push_str("  ==========\n");
    let chain = result
        .metadata
        .get("chain")
        .and_then(|v| v.as_str())
        .unwrap_or("local");
    let addr = result
        .metadata
        .get("address")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !addr.is_empty() {
        out.push_str(&format!("  address:  {}\n", addr));
    }
    out.push_str(&format!("  chain:    {}\n", chain));
    out.push_str(&format!("  contract: {}\n", result.contract_name));
    let compiler = result
        .metadata
        .get("compiler_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !compiler.is_empty() {
        out.push_str(&format!("  compiler: {}\n", compiler));
    }
    if result
        .metadata
        .get("is_proxy")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let impl_a = result
            .metadata
            .get("implementation_address")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        out.push_str(&format!("  proxy:    YES (implementation: {})\n", impl_a));
    }
    if !result.source_provenance.is_empty() {
        out.push_str(&format!("  source:   {}\n", &result.source_provenance));
    }
    if let Some(ref link) = result.source_link {
        out.push_str(&format!("  source link: {}\n", link));
    }
    out.push('\n');

    if result.graduated_findings.is_empty() {
        out.push_str("  graduated findings: 0 (no known-vulnerability patterns detected)\n");
    } else {
        out.push_str(&format!(
            "  graduated findings: {} (known precision/recall per detector)\n",
            result.graduated_findings.len()
        ));
        for (i, f) in result.graduated_findings.iter().enumerate() {
            let kind = f["kind"].as_str().unwrap_or("?");
            let sev = f["severity"].as_str().unwrap_or("?");
            let func = f["function"].as_str().unwrap_or("?");
            out.push_str(&format!(
                "    {}. [{}] {} -- {} [confidence: graduated]\n",
                i + 1,
                sev,
                kind,
                func
            ));
        }
    }
    out.push('\n');

    if result.experimental_hypotheses.is_empty() {
        out.push_str("  experimental hypotheses: 0\n");
    } else {
        out.push_str(&format!(
            "  experimental hypotheses: {} (structural observations, not confirmed findings)\n",
            result.experimental_hypotheses.len()
        ));
        for h in &result.experimental_hypotheses {
            let htype = h["type"].as_str().unwrap_or("?");
            let sev = h["severity"].as_str().unwrap_or("?");
            let func = h["primary_function"].as_str().unwrap_or("?");
            out.push_str(&format!("    [{}] {} ({})\n", sev, htype, func));
        }
    }
    out.push('\n');
    out.push_str(&format!(
        "  exploit chains: {} (Gen3)\n",
        result.exploit_chain_count
    ));
    out
}

/// Deterministic finding ID from detector + function.
fn finding_id_for(detector: &str, function: &str) -> String {
    let mut hasher = DefaultHasher::new();
    detector.hash(&mut hasher);
    function.hash(&mut hasher);
    format!("f-{:016x}", hasher.finish())
}

/// Build a typed ScanContext from scan findings.
///
/// Maps engine-emitted JSON findings into `FindingView` via
/// `FindingView::from_engine` (the blessed constructor). Severity and
/// confidence are taken verbatim from the engine output — never up-labelled.
/// Stage is always `Shadow` (the scan path emits no stage data).
/// predicate_states is empty — the engine produces no predicate state today.
fn build_scan_context(result: &ScanResult, chain: &str) -> ScanContext {
    let mut findings = Vec::new();

    for f in &result.graduated_findings {
        if let Some(view) = finding_json_to_view(f) {
            findings.push(view);
        }
    }
    for f in &result.experimental_hypotheses {
        if let Some(view) = finding_json_to_view(f) {
            findings.push(view);
        }
    }

    let scan_id = format!(
        "scan-{}-{}",
        chain,
        finding_id_for(&result.contract_name, &result.source_provenance)
    );

    ScanContext {
        scan_id,
        findings,
        predicate_states: Vec::<PredicateState>::new(),
    }
}

/// Map a single engine-emitted JSON finding into a typed FindingView.
///
/// Returns None if the JSON lacks required fields or if the severity/confidence
/// values are not recognized by the contract enums (no silent coercion).
fn finding_json_to_view(f: &serde_json::Value) -> Option<FindingView> {
    let detector = f.get("detector").and_then(|v| v.as_str())?;
    let function = f
        .get("function")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let severity = f.get("severity").and_then(|v| v.as_str()).unwrap_or("high");
    let confidence = f
        .get("confidence")
        .and_then(|v| v.as_str())
        .unwrap_or("experimental");
    let kind = f.get("kind").and_then(|v| v.as_str()).unwrap_or(detector);

    // Wire the function name as a location symbol — the engine's best effort
    // at a source address. file/line are empty (engine doesn't carry them);
    // evidence_ids are empty (engine doesn't produce them).
    // This is honest: the function name is the only locatable entity the
    // engine emits per finding.
    let locations = if function != "unknown" {
        vec![digger_evidence::Location {
            file: String::new(),
            line_start: None,
            line_end: None,
            symbol: Some(function.to_string()),
        }]
    } else {
        vec![]
    };

    // evidence_refs may or may not be present in the JSON.
    // When present, the detector/CLI included provenance data.
    // When absent, the finding carries no evidence — we default to empty.
    let evidence_refs: Vec<String> = f
        .get("evidence_refs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Build a digger_evidence::Finding to route through the blessed constructor
    let evidence_finding = digger_evidence::Finding {
        finding_id: finding_id_for(detector, function),
        rule_id: detector.to_string(),
        severity: severity.to_string(),
        confidence_label: confidence.to_string(),
        locations,
        evidence_refs,
        repro_ref: None,
    };

    // from_engine returns Err if severity/confidence are unrecognized —
    // we propagate None to skip malformed findings silently.
    FindingView::from_engine(&evidence_finding, "shadow", kind).ok()
}

/// Public entry point (exits process)
#[allow(clippy::too_many_arguments)]
pub fn run_scan(
    address: Option<String>,
    chain_name: Option<String>,
    source_file: Option<String>,
    use_stdin: bool,
    repo_path: Option<String>,
    format_json: bool,
    impl_address: Option<String>,
    emit_scan_context: Option<String>,
) {
    let input = resolve_input(
        &address,
        &chain_name,
        &source_file,
        use_stdin,
        &repo_path,
        &impl_address,
        format_json,
    );
    let (source_text, contract_name, metadata) = match input {
        Ok(v) => v,
        Err(code) => std::process::exit(code),
    };

    let chain_name_str = metadata
        .get("chain")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let result = analyze(&source_text, &contract_name, metadata, &chain_name_str);

    if format_json {
        println!("{}", to_json(&result));
    } else {
        eprint!("{}", to_human(&result));
    }

    if let Some(ref path) = emit_scan_context {
        let ctx = build_scan_context(&result, &chain_name_str);
        let json = serde_json::to_string_pretty(&ctx).unwrap_or_else(|e| {
            eprintln!("error: failed to serialize ScanContext: {}", e);
            std::process::exit(EXIT_ERROR);
        });
        if let Err(e) = std::fs::write(path, json) {
            eprintln!("error: failed to write {}: {}", path, e);
            std::process::exit(EXIT_ERROR);
        }
    }

    std::process::exit(EXIT_OK);
}

// ── Input resolution ──

fn resolve_input(
    address: &Option<String>,
    chain_name: &Option<String>,
    source_file: &Option<String>,
    use_stdin: bool,
    repo_path: &Option<String>,
    impl_address: &Option<String>,
    format_json: bool,
) -> Result<(String, String, serde_json::Value), i32> {
    match (
        address.as_ref(),
        chain_name.as_ref(),
        source_file.as_ref(),
        use_stdin,
        repo_path.as_ref(),
    ) {
        (Some(addr), Some(chain), _, _, _) => {
            fetch_live(addr, chain, impl_address.clone(), format_json)
        }
        (None, None, Some(path), false, None) => read_file(path),
        (None, None, None, true, None) => read_stdin(),
        (None, None, None, false, Some(repo)) => read_repo(repo),
        _ => {
            eprintln!(
                "error: specify --address + --chain, --source <file>, --stdin, or --repo <path>"
            );
            eprintln!("usage: digger scan --address 0x... --chain ethereum");
            eprintln!("       digger scan --source contract.sol");
            eprintln!("       digger scan --stdin < contract.sol");
            eprintln!("       digger scan --repo /path/to/foundry-project");
            Err(EXIT_ERROR)
        }
    }
}

pub(crate) fn fetch_live(
    address: &str,
    chain_name: &str,
    impl_address: Option<String>,
    format_json: bool,
) -> Result<(String, String, serde_json::Value), i32> {
    // Detect Solana chain
    let is_solana = matches!(
        chain_name.to_lowercase().as_str(),
        "solana" | "sol" | "sol-mainnet" | "mainnet-solana"
    );

    if is_solana {
        return fetch_solana(address, format_json);
    }

    // EVM path
    let chain = Chain::from_name(chain_name).map_err(|e| {
        eprintln!("error: {}", e);
        EXIT_ERROR
    })?;
    EtherscanClient::validate_address(address).map_err(|e| {
        eprintln!("error: {}", e);
        EXIT_ERROR
    })?;
    let client = EtherscanClient::new();
    let target = impl_address.unwrap_or_else(|| address.to_string());
    let source = match client.fetch_source(&chain, &target) {
        Ok(s) => s,
        Err(ExplorerError::NotVerified(addr)) => {
            // Genuinely unverified — NOT a fetch failure
            let meta = serde_json::json!({
                "chain": chain.name(),
                "address": addr,
                "source_provenance": "unverified",
                "source_available": false,
            });
            return Ok((String::new(), addr, meta));
        }
        Err(ExplorerError::RateLimited) => {
            eprintln!("error: rate limited by explorer API -- try again later");
            return Err(EXIT_ERROR);
        }
        Err(e) => {
            eprintln!("error: fetch failed: {e}");
            return Err(EXIT_ERROR);
        }
    };
    let meta = serde_json::json!({
        "chain": chain.name(),
        "address": address,
        "compiler_version": source.compiler_version,
        "optimization": source.optimization,
        "is_proxy": source.is_proxy,
        "implementation_address": source.implementation_address,
    });
    Ok((source.source, source.contract_name, meta))
}

pub fn read_file(path: &str) -> Result<(String, String, serde_json::Value), i32> {
    let p = std::path::Path::new(path);
    if !p.exists() {
        eprintln!("error: path not found: {}", path);
        return Err(EXIT_ERROR);
    }

    if p.is_dir() {
        read_directory(path)
    } else {
        let code = std::fs::read_to_string(p).map_err(|e| {
            eprintln!("error: cannot read '{}': {}", path, e);
            EXIT_ERROR
        })?;
        if code.trim().is_empty() {
            eprintln!("error: file '{}' is empty", path);
            return Err(EXIT_ERROR);
        }
        let name = p
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Infer chain from file extension: .rs → Solana, .ts/.js → op-layer, else local/EVM
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        let chain = if ext == "rs" {
            "solana"
        } else if ext == "ts" || ext == "js" || ext == "mjs" || ext == "mts" {
            "op-layer"
        } else {
            "local"
        };

        let meta = serde_json::json!({
            "chain": chain,
            "source_file": path,
            "source_provenance": "local source",
        });
        Ok((code, name, meta))
    }
}

/// Read a directory of source files, concatenate with import tracking.
pub fn read_directory(dir_path: &str) -> Result<(String, String, serde_json::Value), i32> {
    let dir = std::path::Path::new(dir_path);
    let mut files: Vec<(std::path::PathBuf, String)> = Vec::new();

    collect_source_files(dir, &mut files).map_err(|e| {
        eprintln!("error reading directory '{}': {}", dir_path, e);
        EXIT_ERROR
    })?;

    if files.is_empty() {
        eprintln!("error: no .sol or .rs files found in '{}'", dir_path);
        return Err(EXIT_ERROR);
    }

    // Sort by path for deterministic output
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut all_source = String::new();
    let mut all_imports: Vec<String> = Vec::new();
    let mut unresolved_imports: Vec<String> = Vec::new();

    for (file_path, content) in &files {
        // Track imports in this file
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("import ") {
                let import_path = trimmed
                    .strip_prefix("import ")
                    .unwrap_or(trimmed)
                    .trim()
                    .trim_matches(';')
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                if !import_path.is_empty() {
                    all_imports.push(import_path.clone());
                    // Check if the import resolves to a provided file
                    let import_file = file_path.parent().unwrap_or(dir).join(&import_path);
                    if !import_file.exists() {
                        unresolved_imports.push(import_path);
                    }
                }
            }
        }

        if !all_source.is_empty() {
            all_source.push_str("\n\n");
        }
        all_source.push_str(content);
    }

    // Warn about unresolved imports (do NOT silently analyze partial source)
    if !unresolved_imports.is_empty() {
        eprintln!(
            "  WARNING: {} import(s) could not be resolved from provided files:",
            unresolved_imports.len()
        );
        for imp in &unresolved_imports {
            eprintln!("    - {}", imp);
        }
        eprintln!("  Analysis will proceed on partial source. Findings are labeled accordingly.");
    }

    let name = dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let meta = serde_json::json!({
        "chain": "local",
        "source_file": dir_path,
        "source_provenance": "local source",
        "file_count": files.len(),
        "import_count": all_imports.len(),
        "unresolved_import_count": unresolved_imports.len(),
        "unresolved_imports": unresolved_imports,
    });

    Ok((all_source, name, meta))
}

/// Recursively collect .sol and .rs files from a directory.
fn collect_source_files(
    dir: &std::path::Path,
    files: &mut Vec<(std::path::PathBuf, String)>,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_source_files(&path, files)?;
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext == "sol" || ext == "rs" {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    files.push((path, content));
                }
            }
        }
    }
    Ok(())
}

fn read_stdin() -> Result<(String, String, serde_json::Value), i32> {
    let mut code = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut code).map_err(|e| {
        eprintln!("error: failed to read stdin: {}", e);
        EXIT_ERROR
    })?;
    if code.trim().is_empty() {
        eprintln!("error: stdin is empty");
        return Err(EXIT_ERROR);
    }
    let meta = serde_json::json!({"chain": "stdin", "source_provenance": "local source"});
    Ok((code, "<stdin>".into(), meta))
}

// ── Solana live fetch ──

fn fetch_solana(
    program_id: &str,
    _format_json: bool,
) -> Result<(String, String, serde_json::Value), i32> {
    digger_reconstruct::validate_program_id(program_id).map_err(|e| {
        eprintln!("error: {}", e);
        EXIT_ERROR
    })?;

    let client = SolanaRpcClient::new();
    let program = client.fetch_program(program_id).map_err(|e| {
        eprintln!("error: {}", e);
        EXIT_ERROR
    })?;

    let (source_text, source_type) = if let Some(ref idl) = program.idl {
        (idl.clone(), "anchor_idl")
    } else if let Some(ref data) = program.account_data {
        (data.clone(), "raw_account_data")
    } else {
        // No analyzable source available — return Ok with no-source provenance
        let meta = serde_json::json!({
            "program_id": program_id,
            "chain": "solana",
            "source_provenance": program.provenance.to_string(),
            "has_idl": program.has_idl,
            "is_deployed": program.is_deployed,
            "source_available": false,
        });
        return Ok((String::new(), program_id.to_string(), meta));
    };

    let meta = serde_json::json!({
        "chain": "solana",
        "address": program_id,
        "program_type": program.program_type,
        "executor": program.executor,
        "has_idl": program.has_idl,
        "source_type": source_type,
        "is_deployed": program.is_deployed,
        "source_provenance": program.provenance.to_string(),
        "source_link": program.source_link,
    });

    Ok((source_text, program.program_id, meta))
}

// ── Foundry repo ingestion ──

fn read_repo(repo_path: &str) -> Result<(String, String, serde_json::Value), i32> {
    if is_git_url(repo_path) {
        return clone_and_scan(repo_path);
    }

    let path = std::path::Path::new(repo_path);
    if !path.exists() {
        eprintln!("error: path not found: {}", repo_path);
        return Err(EXIT_ERROR);
    }

    // Detect project type: prefer Foundry > Hardhat > Anchor
    let foundry = digger_reconstruct::FoundryProject::detect(path);
    let hardhat = digger_reconstruct::HardhatProject::detect(path);
    let anchor = digger_reconstruct::AnchorProject::detect(path);

    let (source, unresolved, framework, src_dir, provenance_label) = if let Some(project) = foundry
    {
        let (s, u) = project.resolve_source().map_err(|e| {
            eprintln!("error: {}", e);
            EXIT_ERROR
        })?;
        if hardhat.is_some() || anchor.is_some() {
            eprintln!("  note: multiple frameworks detected; using Foundry");
        }
        (
            s,
            u,
            "foundry".to_string(),
            project.src_dir.to_string_lossy().to_string(),
            "Foundry repo".to_string(),
        )
    } else if let Some(project) = hardhat {
        let (s, u) = project.resolve_source().map_err(|e| {
            eprintln!("error: {}", e);
            EXIT_ERROR
        })?;
        (
            s,
            u,
            "hardhat".to_string(),
            project.contracts_dir.to_string_lossy().to_string(),
            "Hardhat project".to_string(),
        )
    } else if let Some(project) = anchor {
        let (s, u) = project.resolve_source().map_err(|e| {
            eprintln!("error: {}", e);
            EXIT_ERROR
        })?;
        (
            s,
            u,
            "anchor".to_string(),
            project.programs_dir.to_string_lossy().to_string(),
            "Anchor project".to_string(),
        )
    } else {
        eprintln!(
            "error: no Foundry, Hardhat, or Anchor project found in '{}'.",
            repo_path
        );
        eprintln!("  Supported frameworks: Foundry, Hardhat, Anchor.");
        return Err(EXIT_ERROR);
    };

    if source.trim().is_empty() {
        eprintln!("error: no source files found in '{}'", repo_path);
        return Err(EXIT_ERROR);
    }

    if !unresolved.is_empty() {
        eprintln!(
            "  WARNING: {} import(s) unresolved from provided files:",
            unresolved.len()
        );
        for imp in &unresolved {
            eprintln!("    - {}", imp);
        }
    }

    let meta = serde_json::json!({
        "chain": "local",
        "source_provenance": provenance_label,
        "repo_path": repo_path,
        "framework": framework,
        "src_dir": src_dir,
        "unresolved_imports": unresolved.len(),
    });

    Ok((
        source,
        path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        meta,
    ))
}

/// Clone a git URL to a temp dir and scan it as a Foundry project.
fn clone_and_scan(url: &str) -> Result<(String, String, serde_json::Value), i32> {
    let temp_dir = std::env::temp_dir().join(format!("digger_scan_{}", std::process::id()));

    // Clean up on exit (success or failure)
    let cleanup = |dir: &std::path::Path| {
        let _ = std::fs::remove_dir_all(dir);
    };

    // Parse URL and optional ref
    let (repo_url, ref_name) = if let Some(hash_pos) = url.rfind('#') {
        (
            url[..hash_pos].to_string(),
            Some(url[hash_pos + 1..].to_string()),
        )
    } else {
        (url.to_string(), None)
    };

    // Clone
    if let Err(e) = digger_egress::authorize_global(&repo_url, "clone-git-repo") {
        eprintln!("Error: {e}");
        return Err(1);
    }
    eprintln!("  cloning {} ...", repo_url);
    let mut cmd = std::process::Command::new("git");
    cmd.arg("clone").arg("--depth").arg("1");
    if let Some(ref r) = ref_name {
        cmd.arg("--branch").arg(r);
    }
    cmd.arg(&repo_url).arg(&temp_dir);

    let output = cmd.output().map_err(|e| {
        eprintln!("error: failed to run git: {}", e);
        cleanup(&temp_dir);
        EXIT_ERROR
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("error: git clone failed: {}", stderr.trim());
        cleanup(&temp_dir);
        return Err(EXIT_ERROR);
    }

    // Detect Foundry project
    let project = digger_reconstruct::FoundryProject::detect(&temp_dir).ok_or_else(|| {
        eprintln!("error: cloned repo has no foundry.toml. Unsupported project layout.");
        eprintln!("  digger scan --repo currently supports Foundry projects only.");
        cleanup(&temp_dir);
        EXIT_ERROR
    })?;

    // Resolve source
    let (source, unresolved) = project.resolve_source().map_err(|e| {
        eprintln!("error: {}", e);
        cleanup(&temp_dir);
        EXIT_ERROR
    })?;

    // Cleanup temp dir
    cleanup(&temp_dir);

    if source.trim().is_empty() {
        eprintln!("error: no source files found in cloned repo");
        return Err(EXIT_ERROR);
    }

    if !unresolved.is_empty() {
        eprintln!(
            "  WARNING: {} import(s) unresolved after clone:",
            unresolved.len()
        );
        for imp in &unresolved {
            eprintln!("    - {}", imp);
        }
    }

    let meta = serde_json::json!({
        "chain": "local",
        "source_provenance": "git repo",
        "repo_url": url,
        "framework": "foundry",
        "src_dir": project.src_dir.to_string_lossy(),
        "unresolved_imports": unresolved.len(),
    });

    let name = std::path::Path::new(&repo_url)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    Ok((source, name, meta))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_scan_context_from_real_solana_fixture() {
        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("corpus/solana-account-model/cpi-signer-only-vuln/source.rs");
        assert!(fixture.exists(), "{:?} must be git-tracked", fixture);

        let source = std::fs::read_to_string(&fixture).unwrap();
        let raw = digger_parser::parse_program(&source, "anchor");
        let metadata = serde_json::json!({
            "source_provenance": "corpus",
            "chain": "solana",
        });

        // Run the same detection path the CLI uses
        let mut experimental = Vec::new();
        if let Some(body) = recover_source_body_graph(&raw) {
            for v in detect_solana_access_violations(&body) {
                experimental.push(serde_json::json!({
                    "detector": "solana_access_control",
                    "function": v.function_id,
                    "kind": v.violation_kind,
                    "severity": "high",
                    "confidence": "experimental",
                }));
            }
        }

        let result = ScanResult {
            contract_name: "owner-check-vuln-1".into(),
            metadata,
            graduated_findings: Vec::new(),
            experimental_hypotheses: experimental,
            exploit_chain_count: 0,
            verified: true,
            source_provenance: "corpus".into(),
            source_link: None,
        };

        let ctx = build_scan_context(&result, "solana");

        // Non-vacuity: must produce ≥1 finding
        assert!(
            !ctx.findings.is_empty(),
            "real fixture must produce ≥1 FindingView"
        );

        // Typed labels must match engine output exactly
        let f = &ctx.findings[0];
        assert_eq!(f.rule_id, "solana_access_control");
        assert_eq!(f.severity, digger_agent::contract::Severity::High);
        assert_eq!(
            f.confidence,
            digger_agent::contract::Confidence::Experimental
        );
        assert_eq!(f.stage, digger_agent::contract::Stage::Shadow);

        // Prove inflation fails: from_engine rejects unrecognized severity
        let bogus = digger_evidence::Finding {
            finding_id: "test".into(),
            rule_id: "test".into(),
            severity: "banana".into(),
            confidence_label: "experimental".into(),
            locations: vec![],
            evidence_refs: vec![],
            repro_ref: None,
        };
        let bogus_result = FindingView::from_engine(&bogus, "shadow", "test");
        assert!(
            bogus_result.is_err(),
            "unrecognized severity must be rejected by from_engine"
        );

        // Serialize round-trip
        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: ScanContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.findings.len(), ctx.findings.len());
        assert_eq!(deserialized.findings[0].rule_id, "solana_access_control");
    }

    #[test]
    fn finding_json_to_view_evidence_ids_wiring() {
        // WITH evidence_refs → evidence_ids is populated
        let with_refs = serde_json::json!({
            "detector": "op_unverified_attestation",
            "function": "handleFeed",
            "kind": "UnverifiedAttestation",
            "severity": "high",
            "confidence": "experimental",
            "evidence_refs": ["op:abc123"],
        });
        let view = super::finding_json_to_view(&with_refs).expect("should parse");
        assert_eq!(view.evidence_ids, vec!["op:abc123"]);
        assert!(
            !view.evidence_ids.is_empty(),
            "wiring is live when refs present"
        );

        // WITHOUT evidence_refs → evidence_ids is empty (flip-proof)
        let without_refs = serde_json::json!({
            "detector": "solana_access_control",
            "function": "mint",
            "kind": "MissingSigner",
            "severity": "high",
            "confidence": "experimental",
        });
        let view_no = super::finding_json_to_view(&without_refs).expect("should parse");
        assert!(
            view_no.evidence_ids.is_empty(),
            "absent refs yield empty vec"
        );

        // The two prove the field is threaded, not constant
        assert_ne!(
            view.evidence_ids.len(),
            view_no.evidence_ids.len(),
            "non-empty vs empty must differ — field is genuinely wired"
        );
    }

    #[test]
    fn build_scan_context_predicate_states_is_documented_empty_gap() {
        // Track J inc-2 (DOCUMENTED GAP, not a silent stub): no production
        // predicate evaluator is wired into the scan path. The hypothesis engine
        // emits structural `Hypothesis` observations (graph-fact backed), NOT
        // `PredicateOutcome` evaluations. The only `PredicateContext` impl in the
        // tree is the test-only `TestCtx`; `ExploitPredicate::evaluate` is never
        // called in production. Therefore `predicate_states` is intentionally empty.
        // This test pins the invariant so no future change silently fabricates
        // predicate reasoning traces (which `guardrails::validate` consumes for the
        // UNDETERMINED_AS_POSITIVE check). Flip-proof: populating predicate_states
        // without a real producer breaks this test.
        let result = ScanResult {
            contract_name: "x".into(),
            metadata: serde_json::json!({ "chain": "local" }),
            graduated_findings: Vec::new(),
            experimental_hypotheses: Vec::new(),
            exploit_chain_count: 0,
            verified: true,
            source_provenance: "local source".into(),
            source_link: None,
        };
        let ctx = build_scan_context(&result, "local");
        assert!(
            ctx.predicate_states.is_empty(),
            "predicate_states must remain empty until a real PredicateContext + \
             ExploitPredicate registry is wired (documented gap, not a silent stub)"
        );
    }
}
