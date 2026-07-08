use crate::engine_triage::collect_engine_evidence;
use crate::scan_live::fetch_live;
use crate::source_triage::triage_source_files;
use digger_fuzz_maturity::scan_fuzzing_maturity;
use digger_ingestion::file_class::classify_path;
use digger_repo_intelligence::{scan_repo, Chain, RepoIntelligenceInput};
use std::path::Path;

/// Run audit triage on a local path or live contract address.
/// Merges the address path (fetch live) and local path (read files) into
/// the same analysis pipeline. Live fetch requires the live-fetch feature.
#[allow(clippy::too_many_arguments)]
pub fn run(
    path: Option<&str>,
    address: Option<&str>,
    impl_address: Option<&str>,
    chain: &str,
    json: bool,
    output: Option<&str>,
    include_fuzz_maturity: bool,
    fuzz_artifact: Option<&str>,
    exclude_tests: bool,
    egress: &mut digger_egress::EgressPolicy,
) {
    // ── Input validation: exactly one of --path or --address ──
    if path.is_some() && address.is_some() {
        eprintln!("Error: use --path OR --address, not both");
        std::process::exit(1);
    }
    if path.is_none() && address.is_none() {
        eprintln!("Error: specify --path <local-repo> or --address <contract-on-chain>");
        eprintln!("  digger audit-triage --path /path/to/contract.sol --chain evm");
        eprintln!("  digger audit-triage --address 0x... --chain ethereum");
        std::process::exit(1);
    }

    // ── Resolve path: fetch live if --address, otherwise use --path ──
    let (repo_path, live_provenance) = if let Some(addr) = address {
        // Egress gate: authorize before any network request
        let chain_for_url = match chain {
            "solana" => "api.mainnet-beta.solana.com",
            _ => "etherscan.io",
        };
        let url = format!("https://{chain_for_url}/");
        if let Err(e) = egress.authorize(&url, "fetch-contract-source") {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        // Live-fetch path
        eprintln!("digger: contacting explorer for {addr} on {chain} (live-fetch)");
        let (source, contract_name, meta) =
            match fetch_live(addr, chain, impl_address.map(String::from), json) {
                Ok(r) => r,
                Err(_) => std::process::exit(1),
            };
        let temp_dir = std::env::temp_dir().join(format!("digger-triage-{addr}"));
        let _ = std::fs::create_dir_all(&temp_dir);
        let source_path = temp_dir.join(format!("{contract_name}.sol"));
        if let Err(e) = std::fs::write(&source_path, &source) {
            eprintln!("Error writing temp source: {e}");
            std::process::exit(1);
        }
        let provenance = if meta
            .get("is_proxy")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            "verified-source-proxied"
        } else if source.trim().is_empty() {
            "bytecode-only"
        } else {
            "verified-source"
        };
        (
            temp_dir.to_string_lossy().to_string(),
            Some((
                addr.to_string(),
                chain.to_string(),
                provenance.to_string(),
                meta,
            )),
        )
    } else if let Some(p) = path {
        if !Path::new(p).exists() {
            eprintln!("Error: path '{}' does not exist", p);
            std::process::exit(1);
        }
        (p.to_string(), None)
    } else {
        eprintln!("Error: specify --path or --address");
        std::process::exit(1);
    };

    if chain != "evm"
        && chain != "solana"
        && chain != "ethereum"
        && chain != "arbitrum"
        && chain != "optimism"
        && chain != "polygon"
        && chain != "base"
    {
        eprintln!("Error: unsupported chain '{chain}'");
        std::process::exit(1);
    }

    let chain_enum = match chain {
        "evm" => Chain::Evm,
        "solana" => Chain::Solana,
        _ => unreachable!(),
    };

    let mut limitations: Vec<serde_json::Value> = Vec::new();
    let mut missing_evidence: Vec<serde_json::Value> = Vec::new();

    // ── Size guard: prevent OOM on oversized inputs ──
    let repo_path_obj = std::path::Path::new(&repo_path);
    if repo_path_obj.is_dir() {
        let sol_count = repo_path_obj
            .read_dir()
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .and_then(|ext| ext.to_str())
                            .map(|ext| ext == "sol")
                            .unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0);
        if sol_count > 64 {
            eprintln!(
                "Error: directory contains {sol_count} .sol files — \
                 too large to parse safely (solang parser limit). \
                 Use --source-file to analyze individual contracts."
            );
            std::process::exit(1);
        }
    }

    // ── Repo Intelligence (file-level classification — always runs) ──
    let ri_map = match scan_repo(RepoIntelligenceInput {
        root: std::path::PathBuf::from(&repo_path),
        chain: chain_enum,
    }) {
        Ok(m) => Some(m),
        Err(e) => {
            limitations.push(serde_json::json!({
                "limitation_id": "lim-ri-failed",
                "description": format!("Repo intelligence scan failed: {}", e),
                "category": "scanner_error",
            }));
            None
        }
    };

    // ── Fuzz maturity (optional flag) ──
    let fuzz_report = if include_fuzz_maturity {
        Some(scan_fuzzing_maturity(std::path::Path::new(&repo_path)))
    } else {
        None
    };

    if include_fuzz_maturity && fuzz_report.is_none() {
        limitations.push(serde_json::json!({
            "limitation_id": "lim-fuzz-maturity",
            "description": "Fuzz maturity scan requested but produced no report",
            "category": "scanner_error",
        }));
    }

    // ═══════════════════════════════════════════════════════════════════
    // ENGINE-BACKED PATH (PRIMARY): deterministic parser → IR → graph → hypothesis
    // ═══════════════════════════════════════════════════════════════════
    let engine_evidence = collect_engine_evidence(std::path::Path::new(&repo_path), chain);
    let engine_derived = !engine_evidence.hypotheses.is_empty();

    for lim in &engine_evidence.limitations {
        limitations.push(serde_json::json!({
            "limitation_id": "lim-engine",
            "description": lim,
            "category": "engine",
        }));
    }

    // Build a set of functions already covered by the engine (for dedup)
    // Key on (path, function_name) so two files sharing a function name don't collide
    let engine_function_keys: std::collections::BTreeSet<(String, String)> = engine_evidence
        .surfaces
        .iter()
        .map(|s| (s.file.clone(), s.function_name.clone()))
        .collect();

    let mut surfaces_scanned: Vec<serde_json::Value> = Vec::new();
    let mut privileged_ops: Vec<serde_json::Value> = Vec::new();
    let mut state_mutations: Vec<serde_json::Value> = Vec::new();
    let mut external_calls: Vec<serde_json::Value> = Vec::new();
    let mut candidate_hypotheses: Vec<serde_json::Value> = Vec::new();
    let mut proof_tasks: Vec<serde_json::Value> = Vec::new();

    // ── Engine surfaces (PRIMARY) ──
    for es in &engine_evidence.surfaces {
        surfaces_scanned.push(serde_json::json!({
            "id": format!("engine-{}", es.function_name),
            "path": es.file,
            "file_class": classify_path(&es.file).to_string(),
            "category": "engine_derived",
            "name": es.function_name,
            "kind": "engine_surface",
            "confidence": "engine_verified",
            "has_authority": es.has_authority,
            "writes_state": es.writes_state,
            "makes_external_calls": es.makes_external_calls,
            "provenance": "engine",
        }));
        // Engine surfaces also contribute to privileged_ops/state_mutations/external_calls
        if es.has_authority || es.writes_state || es.makes_external_calls {
            let mut reasons: Vec<String> = Vec::new();
            if es.has_authority {
                reasons.push("authority_required".into());
            }
            if es.writes_state {
                reasons.push("state_mutation".into());
            }
            if es.makes_external_calls {
                reasons.push("external_call".into());
            }
            privileged_ops.push(serde_json::json!({
                "path": es.file,
                "name": es.function_name,
                "kind": "engine_surface",
                "reason": format!("[engine] {}", reasons.join(", ")),
                "needs_review": true,
                "provenance": "engine",
                "engine_derived": true,
            }));
            if es.writes_state {
                state_mutations.push(serde_json::json!({
                    "path": es.file,
                    "name": es.function_name,
                    "kind": "engine_surface",
                    "reason": "[engine] state mutation signal",
                    "needs_review": true,
                    "provenance": "engine",
                    "engine_derived": true,
                }));
            }
            if es.makes_external_calls {
                external_calls.push(serde_json::json!({
                    "path": es.file,
                    "name": es.function_name,
                    "kind": "engine_surface",
                    "reason": "[engine] external call signal",
                    "needs_review": true,
                    "provenance": "engine",
                    "engine_derived": true,
                }));
            }
        }
    }

    // ── Engine hypotheses (PRIMARY) ──
    for eh in &engine_evidence.hypotheses {
        candidate_hypotheses.push(serde_json::json!({
            "hypothesis_id": format!("engine-{}", eh.id),
            "description": format!("[engine-derived] {} — {}", eh.kind, eh.description),
            "affected_component": eh.affected_function,
            "evidence_requirements": ["graph evidence", "IR verification"],
            "confidence": "engine-verified",
            "status": "requires_investigation",
            "severity": eh.severity,
            "source_file": eh.source_file,
            "file_class": classify_path(&eh.source_file).to_string(),
            "provenance": "engine",
            "engine_derived": true,
        }));
        proof_tasks.push(serde_json::json!({
            "task_id": format!("pt-engine-{}", eh.id),
            "hypothesis_ref": format!("engine-{}", eh.id),
            "description": format!("Verify engine-derived {}: {}", eh.kind, eh.description),
            "evidence_type": "engine_analysis",
            "priority": "high",
            "status": "pending",
            "source_ref": eh.source_file,
            "file_class": classify_path(&eh.source_file).to_string(),
            "provenance": "engine",
            "engine_derived": true,
        }));
    }

    // ═══════════════════════════════════════════════════════════════════
    // HEURISTIC FALLBACK: only for surfaces the engine could not lift
    // ═══════════════════════════════════════════════════════════════════
    let source_triage = triage_source_files(std::path::Path::new(&repo_path), chain);
    limitations.extend(source_triage.limitations.iter().map(|l| {
        serde_json::json!({
            "limitation_id": "lim-source-triage",
            "description": l,
            "category": "source_triage",
        })
    }));

    // Source_triage account structs — engine does not produce these, always include
    // (Anchor #[derive(Accounts)] field analysis is heuristic-only)
    let func_surfaces: Vec<serde_json::Value> = Vec::new();

    for func in &source_triage.functions {
        // Only emit heuristic surfaces for functions NOT already covered by engine
        let is_engine_covered =
            engine_function_keys.contains(&(func.path.clone(), func.name.clone()));

        if is_engine_covered {
            // Engine already covers this function — skip heuristic duplicate
            continue;
        }

        // This is a heuristic fallback entry — label it honestly
        let mut surface = serde_json::json!({
            "name": func.name,
            "path": func.path,
            "file_class": classify_path(&func.path).to_string(),
            "line_start": func.line_start,
            "line_end": func.line_end,
            "kind": func.kind,
            "visibility": func.visibility,
            "is_payable": func.is_payable,
            "has_auth_signal": func.has_auth_signal,
            "auth_signals": func.auth_signals,
            "has_state_mutation": func.has_state_mutation,
            "mutation_signals": func.mutation_signals,
            "has_external_call": func.has_external_call,
            "external_call_signals": func.external_call_signals,
            "has_cpi": func.has_cpi,
            "cpi_signals": func.cpi_signals,
            "provenance": "heuristic",
            "heuristic": true,
        });
        if func.is_payable {
            surface["is_payable"] = serde_json::json!(true);
        }
        surfaces_scanned.push(surface);

        if func.has_auth_signal
            || func.visibility.as_deref() == Some("public")
            || func.visibility.as_deref() == Some("external")
        {
            let reason = if func.has_auth_signal {
                format!("Has auth signals: {}", func.auth_signals.join(", "))
            } else {
                format!("Public/external function: {}", func.kind)
            };
            privileged_ops.push(serde_json::json!({
                "path": func.path,
                "name": func.name,
                "file_class": classify_path(&func.path).to_string(),
                "line": func.line_start,
                "kind": func.kind,
                "reason": reason,
                "needs_review": true,
                "provenance": "heuristic",
                "heuristic": true,
            }));
        }

        if func.has_state_mutation {
            state_mutations.push(serde_json::json!({
                "path": func.path,
                "name": func.name,
                "file_class": classify_path(&func.path).to_string(),
                "line": func.line_start,
                "kind": func.kind,
                "reason": format!("Mutation signals: {}", func.mutation_signals.join(", ")),
                "needs_review": true,
                "provenance": "heuristic",
                "heuristic": true,
            }));
        }

        if func.has_external_call || func.has_cpi {
            let signals = if func.has_cpi {
                &func.cpi_signals
            } else {
                &func.external_call_signals
            };
            external_calls.push(serde_json::json!({
                "path": func.path,
                "name": func.name,
                "file_class": classify_path(&func.path).to_string(),
                "line": func.line_start,
                "kind": func.kind,
                "reason": format!("Call/CPI signals: {}", signals.join(", ")),
                "needs_review": true,
                "provenance": "heuristic",
                "heuristic": true,
            }));
        }
    }

    // ── Repo-level metadata (heuristic: file counts, unknowns) ──
    if let Some(ref ri) = ri_map {
        for node in &ri.surfaces {
            // Skip surfaces already covered by engine
            if engine_function_keys.contains(&(node.path.clone(), node.name.clone())) {
                continue;
            }
            surfaces_scanned.push(serde_json::json!({
                "id": node.id,
                "path": node.path,
                "file_class": classify_path(&node.path).to_string(),
                "category": node.category,
                "name": node.name,
                "kind": node.kind,
                "confidence": node.confidence.classification,
                "provenance": "repo_intelligence",
                "heuristic": true,
            }));
        }
    }

    if let Some(ref fuzz) = fuzz_report {
        for signal in &fuzz.signals_present {
            surfaces_scanned.push(serde_json::json!({
                "id": format!("fuzz-{}", signal),
                "path": fuzz.scanned_path,
                "file_class": classify_path(&fuzz.scanned_path).to_string(),
                "category": "fuzz_infrastructure",
                "name": signal,
                "kind": "fuzz_signal",
                "confidence": "high",
                "provenance": "fuzz_maturity_scanner",
                "heuristic": true,
            }));
        }
    }

    // ── Source_triage account structs (heuristic-only, engine does not produce these) ──
    if !source_triage.account_structs.is_empty() {
        limitations.push(serde_json::json!({
            "limitation_id": "lim-account-structs-heuristic",
            "description": format!("{} Anchor account structs detected via heuristic analysis (not engine-derived)", source_triage.account_structs.len()),
            "category": "heuristic_fallback",
        }));
    }

    if !include_fuzz_maturity {
        limitations.push(serde_json::json!({
            "limitation_id": "lim-fuzz-not-requested",
            "description": "Fuzz maturity scan not requested (pass --include-fuzz-maturity to enable)",
            "category": "user_flag",
        }));
    }

    if let Some(artifact) = fuzz_artifact {
        let artifact_path = Path::new(artifact);
        if artifact_path.exists() {
            if chain == "evm" {
                match digger_fuzz_maturity::parse_foundry_failure_file(artifact_path) {
                    Ok(report) => {
                        missing_evidence.push(serde_json::json!({
                            "evidence_id": "me-fuzz-artifact",
                            "description": format!("Fuzz artifact parsed: invariant='{}', confidence_ceiling='{}'", report.invariant_name.as_deref().unwrap_or("unknown"), report.confidence_ceiling),
                            "category": "fuzz_evidence",
                            "impact": "Fuzz evidence available for review",
                        }));
                    }
                    Err(e) => {
                        limitations.push(serde_json::json!({
                            "limitation_id": "lim-fuzz-artifact-parse",
                            "description": format!("Failed to parse fuzz artifact: {}", e),
                            "category": "parser_error",
                        }));
                    }
                }
            } else {
                limitations.push(serde_json::json!({
                    "limitation_id": "lim-fuzz-artifact-chain",
                    "description": format!("Fuzz artifact parsing for {} is not yet supported", chain),
                    "category": "unsupported_chain",
                }));
            }
        } else {
            eprintln!(
                "Warning: fuzz artifact '{}' does not exist, skipping",
                artifact
            );
        }
    }

    // ── Missing evidence from source_triage ──
    for src_ev in &source_triage.missing_evidence {
        missing_evidence.push(serde_json::json!({
            "evidence_id": src_ev.evidence_id,
            "description": src_ev.description,
            "category": src_ev.category,
            "affected_component": src_ev.affected_component,
            "source_ref": src_ev.source_ref,
        }));
    }

    // ── Engine-derived missing evidence ──
    for hyp in &engine_evidence.hypotheses {
        missing_evidence.push(serde_json::json!({
            "evidence_id": format!("me-engine-{}", hyp.id),
            "description": format!("Evidence for engine hypothesis '{}' requires verification against IR/graph", hyp.kind),
            "category": "engine_evidence_gap",
            "affected_component": hyp.affected_function,
            "source_ref": hyp.source_file,
        }));
    }

    limitations.push(serde_json::json!({
        "limitation_id": "lim-static-triage",
        "description": "Surface mapping uses deterministic engine (parser/IR/graph) as primary source, with conservative text heuristics as fallback. No compilation, no runtime analysis, no execution.",
        "category": "methodology",
    }));

    // ── Build summaries ──
    let ri_summary = ri_map.as_ref().map(|m| {
        serde_json::json!({
            "schema_version": m.schema_version,
            "chain": m.chain,
            "surface_count": m.summary.surface_count,
            "unknown_count": m.summary.unknown_count,
        })
    });

    let fuzz_summary = fuzz_report.as_ref().map(|m| {
        serde_json::json!({
            "maturity_score": m.maturity_score,
            "signals_present": m.signals_present,
            "signals_missing": m.signals_missing,
            "confidence_ceiling": m.confidence_ceiling,
            "limitations": m.limitations,
        })
    });

    let total_functions = privileged_ops.len();
    let total_state = state_mutations.len();
    let total_external = external_calls.len();

    let packet_id = format!(
        "atp-{}",
        &format!("{:x}", djbx33a(repo_path.replace('\\', "/").as_bytes()))
    );
    let correlation_id = format!("run-{}", packet_id);
    let provenance_info = live_provenance.as_ref().map(|(addr, chain, prov, _meta)| {
        serde_json::json!({
            "source_provenance": prov,
            "resolved_address": addr,
            "chain_id": chain,
        })
    });

    // ── Compute per-class breakdowns from all tagged objects ──
    let class_counts =
        |items: &[serde_json::Value], key: &str| -> std::collections::BTreeMap<String, usize> {
            let mut counts = std::collections::BTreeMap::new();
            for item in items {
                if let Some(cls) = item.get(key).and_then(|v| v.as_str()) {
                    *counts.entry(cls.to_string()).or_insert(0) += 1;
                }
            }
            counts
        };

    let surfaces_by_class = class_counts(&surfaces_scanned, "file_class");
    let hypotheses_by_class = class_counts(&candidate_hypotheses, "file_class");

    let files_by_class: std::collections::BTreeMap<String, usize> = {
        let mut seen = std::collections::BTreeSet::new();
        let mut counts = std::collections::BTreeMap::new();

        // Count distinct file paths from surfaces_scanned
        for item in &surfaces_scanned {
            if let (Some(path), Some(cls)) = (
                item.get("path").and_then(|v| v.as_str()),
                item.get("file_class").and_then(|v| v.as_str()),
            ) {
                if seen.insert(path.to_string()) {
                    *counts.entry(cls.to_string()).or_insert(0) += 1;
                }
            }
        }
        // Count distinct file paths from privileged_ops not already seen
        for item in &privileged_ops {
            if let (Some(path), Some(cls)) = (
                item.get("path").and_then(|v| v.as_str()),
                item.get("file_class").and_then(|v| v.as_str()),
            ) {
                if seen.insert(path.to_string()) {
                    *counts.entry(cls.to_string()).or_insert(0) += 1;
                }
            }
        }
        counts
    };

    // ── Apply --exclude-tests filter (display-only: scan is complete) ──
    let filtered_hypotheses: Vec<serde_json::Value> = if exclude_tests {
        candidate_hypotheses
            .iter()
            .filter(|h| {
                h.get("file_class").and_then(|v| v.as_str()) == Some("production")
                    || h.get("file_class").and_then(|v| v.as_str()).is_none()
            })
            .cloned()
            .collect()
    } else {
        candidate_hypotheses.clone()
    };

    let filtered_tasks: Vec<serde_json::Value> = if exclude_tests {
        proof_tasks
            .iter()
            .filter(|t| {
                t.get("file_class").and_then(|v| v.as_str()) == Some("production")
                    || t.get("file_class").and_then(|v| v.as_str()).is_none()
            })
            .cloned()
            .collect()
    } else {
        proof_tasks.clone()
    };

    let packet = serde_json::json!({
        "schema_version": "digger.audit_triage_packet.v1",
        "digger_version": env!("CARGO_PKG_VERSION"),
        "report_kind": "audit_triage_packet",
        "correlation_id": correlation_id,
        "packet_id": packet_id,
        "target_repository": repo_path.replace('\\', "/"),
        "chain": chain,
        "provenance": provenance_info,
        "repo_intelligence_ref": ri_summary,
        "attack_surface_summary": {
            "total_functions": total_functions,
            "privileged_functions": total_functions,
            "external_call_sites": total_external,
            "state_mutation_sites": total_state,
            "surfaces_scanned": surfaces_scanned.len(),
            "function_level_surfaces": func_surfaces.len(),
            "account_structs": source_triage.account_structs.len(),
            "engine_files_ok": engine_evidence.files_ok,
            "engine_files_failed": engine_evidence.files_err,
            "engine_derived": engine_derived,
            "heuristic_fallback_count": func_surfaces.len(),
            "files_by_class": files_by_class,
            "surfaces_by_class": surfaces_by_class,
            "hypotheses_by_class": hypotheses_by_class,
        },
        "privileged_operations": privileged_ops,
        "state_mutations": state_mutations,
        "external_calls_or_cpi": external_calls,
        "function_surfaces": func_surfaces,
        "surfaces_scanned": surfaces_scanned,
        "account_structs": source_triage.account_structs.iter().map(|a| {
            serde_json::json!({
                "name": a.name,
                "path": a.path,
                "file_class": classify_path(&a.path).to_string(),
                "line_start": a.line_start,
                "line_end": a.line_end,
                "fields": a.fields.iter().map(|f| {
                    serde_json::json!({
                        "name": f.name,
                        "field_type": f.field_type,
                        "is_signer": f.is_signer,
                        "is_mutable": f.is_mutable,
                        "has_constraint": f.has_constraint,
                        "constraint_signals": f.constraint_signals,
                    })
                }).collect::<Vec<_>>(),
                "provenance": "heuristic",
                "heuristic": true,
            })
        }).collect::<Vec<_>>(),
        "fuzz_maturity_ref": fuzz_summary,
        "candidate_hypotheses": filtered_hypotheses,
        "candidate_hypotheses_total": candidate_hypotheses.len(),
        "proof_tasks": filtered_tasks,
        "proof_tasks_total": proof_tasks.len(),
        "missing_evidence": missing_evidence,
        "evidence_runs": [],
        "report_draft_ref": null,
        "audit_events": [serde_json::json!({
            "event_id": format!("ae-triage-{}", &format!("{:x}", djbx33a(repo_path.replace('\\', "/").as_bytes()))),
            "event_type": "triage_completed",
            "actor": "digger-cli",
            "action_summary": format!(
                "Audit triage completed for {} ({} chain, {} surfaces, {} hypotheses, {} proof tasks)",
                repo_path,
                chain,
                surfaces_scanned.len(),
                candidate_hypotheses.len(),
                proof_tasks.len()
            ),
            "input_refs": [repo_path.clone()],
            "output_refs": [correlation_id.clone()],
            "approval_required": false,
            "approval_status": "not_required".to_string(),
            "policy_decision": "allowed".to_string(),
            "is_mutating": false,
            "is_finding": false,
        })],
        "limitations": limitations,
        "is_finding": false,
    });

    let output_json = match serde_json::to_string_pretty(&packet) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error serializing packet: {}", e);
            std::process::exit(1);
        }
    };

    if json && output.is_none() {
        println!("{}", output_json);
    }

    if let Some(out_path) = output {
        if let Err(e) = std::fs::write(out_path, &output_json) {
            eprintln!("Error writing output: {}", e);
            std::process::exit(1);
        }
        println!("Written to: {}", out_path);
    } else if !json {
        println!("Digger Audit Triage — v{}", env!("CARGO_PKG_VERSION"));
        println!("Path: {}", repo_path);
        println!("Chain: {}", chain);
        println!();
        println!("Files scanned: {}", source_triage.files_scanned);
        println!("Engine files: {}", engine_evidence.files_ok);
        println!("Function-level surfaces: {}", func_surfaces.len());
        if !source_triage.account_structs.is_empty() {
            println!("Account structs: {}", source_triage.account_structs.len());
        }
        println!("Privileged operations: {}", total_functions);
        println!("State mutations: {}", total_state);
        println!("External calls/CPI: {}", total_external);
        if let Some(ref fuzz) = fuzz_report {
            println!("Fuzz maturity score: {}/100", fuzz.maturity_score);
        }
        println!("Candidate hypotheses: {}", candidate_hypotheses.len());
        println!("Proof tasks: {}", proof_tasks.len());
        println!("Missing evidence: {}", missing_evidence.len());
        println!("Limitations: {}", limitations.len());
        if exclude_tests {
            println!(
                "  (--exclude-tests: showing {} hypotheses, {} proof tasks — production only)",
                filtered_hypotheses.len(),
                filtered_tasks.len()
            );
        }
        println!();
        // Per-class breakdown
        if !surfaces_by_class.is_empty() {
            println!("Surfaces by class:");
            for (cls, count) in &surfaces_by_class {
                println!("  {}: {}", cls, count);
            }
        }
        println!();
        println!("This is audit triage, not a final finding report.");
        println!(
            "Run with --json for the full AuditTriagePacket, or --output <path> to write JSON."
        );
    }
}

fn djbx33a(data: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    for &byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}
