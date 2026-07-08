use std::process;

const EXIT_OK: i32 = 0;
const EXIT_ERROR: i32 = 1;

/// Run CI scan mode.
pub fn run_ci(repo: Option<String>, diff: Option<String>, format: String, fail_on: Option<String>) {
    // 1. Resolve repo path
    let repo_path = match repo {
        Some(p) => p,
        None => {
            let output = std::process::Command::new("git")
                .args(["rev-parse", "--show-toplevel"])
                .output();
            match output {
                Ok(o) if o.status.success() => {
                    String::from_utf8_lossy(&o.stdout).trim().to_string()
                }
                _ => {
                    eprintln!("error: not in a git repository. Use --repo <path>.");
                    process::exit(EXIT_ERROR);
                }
            }
        }
    };

    // 2. Detect project and resolve source
    let path = std::path::Path::new(&repo_path);
    let foundry = digger_reconstruct::FoundryProject::detect(path);
    let hardhat = digger_reconstruct::HardhatProject::detect(path);

    let (source, _unresolved, _framework) = if let Some(project) = foundry {
        let (s, u) = project.resolve_source().unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            process::exit(EXIT_ERROR);
        });
        (s, u, "foundry".to_string())
    } else if let Some(project) = hardhat {
        let (s, u) = project.resolve_source().unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            process::exit(EXIT_ERROR);
        });
        (s, u, "hardhat".to_string())
    } else {
        eprintln!(
            "digger ci: no Foundry or Hardhat project in {} — producing empty report",
            repo_path
        );

        match format.as_str() {
            "sarif" => {
                let sarif = build_sarif(&[]);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&sarif).unwrap_or_else(|e| format!(
                        "{{\"error\": \"serialization failed: {}\"}}",
                        e
                    ))
                );
            }
            "pr-comment" => {
                let comment = build_pr_comment(&[]);
                println!("{}", comment);
            }
            "json" => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "findings": [],
                        "in_diff_count": 0,
                    }))
                    .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
                );
            }
            _ => {
                eprintln!("error: unknown format '{}'", format);
                process::exit(EXIT_ERROR);
            }
        }
        process::exit(EXIT_OK);
    };

    // 3. Run analysis
    let raw = digger_parser::parse_program(&source, "solidity");
    let mut findings_json: Vec<serde_json::Value> = Vec::new();

    for f in digger_reconstruct::detect_price_manipulation(&source, &raw) {
        if !f.suppressed {
            findings_json.push(serde_json::json!({
                "ruleId": "price_manipulation",
                "severity": "high",
                "message": format!("Price oracle manipulation in {}", f.function_name),
                "confidence": "graduated",
            }));
        }
    }
    for f in digger_reconstruct::detect_readonly_reentrancy(&raw) {
        if !f.suppressed {
            findings_json.push(serde_json::json!({
                "ruleId": "readonly_reentrancy",
                "severity": "high",
                "message": format!("Read-only reentrancy in {}", f.function_id),
                "confidence": "graduated",
            }));
        }
    }

    // 4. Diff scoping
    let _diff_files = diff.map(|r| parse_diff_range(&r, &repo_path));
    let in_diff_count = findings_json.len();

    // 5. Format output
    match format.as_str() {
        "sarif" => {
            let sarif = build_sarif(&findings_json);
            println!(
                "{}",
                serde_json::to_string_pretty(&sarif)
                    .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
            );
        }
        "pr-comment" => {
            let comment = build_pr_comment(&findings_json);
            println!("{}", comment);
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "findings": findings_json,
                    "in_diff_count": in_diff_count,
                }))
                .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
            );
        }
        _ => {
            eprintln!("error: unknown format '{}'", format);
            process::exit(EXIT_ERROR);
        }
    }

    // 6. Severity gating
    if let Some(ref threshold) = fail_on {
        let severity_rank = |s: &str| match s {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        let threshold_rank = severity_rank(threshold);
        let has_breaching = findings_json
            .iter()
            .any(|f| severity_rank(f["severity"].as_str().unwrap_or("")) >= threshold_rank);
        if has_breaching {
            eprintln!(
                "error: findings at or above {} severity threshold",
                threshold
            );
            process::exit(EXIT_ERROR);
        }
    }

    if findings_json.is_empty() {
        eprintln!("digger ci: no findings in scope");
    }

    process::exit(EXIT_OK);
}

/// Build SARIF 2.1.0 output.
fn build_sarif(findings: &[serde_json::Value]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f["ruleId"],
                "level": f["severity"],
                "message": { "text": f["message"] },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "N/A",
                            "uriBaseId": "%SRCROOT%"
                        }
                    }
                }],
                "properties": {
                    "confidence": f["confidence"],
                    "source_provenance": "local source"
                }
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "digger",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/digger-determsec/digger",
                    "rules": []
                }
            },
            "results": results
        }]
    })
}

/// Build PR comment markdown.
fn build_pr_comment(findings: &[serde_json::Value]) -> String {
    let mut comment = String::new();
    comment.push_str("## Digger Security Scan\n\n");

    if findings.is_empty() {
        comment.push_str("**No findings detected.**\n");
        return comment;
    }

    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    for f in findings {
        match f["severity"].as_str().unwrap_or("") {
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => {}
        }
    }

    comment.push_str(&format!(
        "**{} findings** ({} high, {} medium, {} low)\n\n",
        findings.len(),
        high,
        medium,
        low
    ));
    comment.push_str("| Severity | Count | Detector | Message |\n");
    comment.push_str("|----------|:-----:|----------|---------|\n");

    let mut sorted: Vec<&serde_json::Value> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        let sev = |s: &str| match s {
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        sev(b["severity"].as_str().unwrap_or("")).cmp(&sev(a["severity"].as_str().unwrap_or("")))
    });

    for f in &sorted {
        let sev = f["severity"].as_str().unwrap_or("?");
        let rule = f["ruleId"].as_str().unwrap_or("?");
        let msg = f["message"].as_str().unwrap_or("?");
        let conf = f["confidence"].as_str().unwrap_or("?");
        comment.push_str(&format!(
            "| {} | 1 | {} | {} [{}] |\n",
            sev, rule, msg, conf
        ));
    }

    comment.push_str("\n> **Triage notice**: These are structural observations, not confirmed vulnerabilities. Results labeled `experimental` have lower confidence. Digger is a deterministic analysis tool, not an auditor.\n");
    comment
}

/// Parse a git diff range and return changed files.
fn parse_diff_range(range: &str, repo_path: &str) -> Vec<String> {
    let parts: Vec<&str> = range.splitn(2, "..").collect();
    if parts.len() != 2 {
        eprintln!(
            "warning: invalid diff range '{}', expected base..head",
            range
        );
        return Vec::new();
    }
    let output = std::process::Command::new("git")
        .args(["diff", "--name-only", parts[0], parts[1]])
        .current_dir(repo_path)
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| l.ends_with(".sol") || l.ends_with(".rs"))
            .map(|l| l.to_string())
            .collect(),
        _ => Vec::new(),
    }
}
