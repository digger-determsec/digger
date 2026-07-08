use digger_benchmark::normalize_finding;
use digger_graph::build_system_ir;
use digger_hypothesis::analyze_compat as analyze;
use digger_parser::parse_program;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub detection_rate: f64,
    pub categories: Vec<CategoryResult>,
    pub cases: Vec<CaseResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CategoryResult {
    pub category: String,
    pub total: usize,
    pub passed: usize,
    pub detection_rate: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseResult {
    pub file: String,
    pub category: String,
    pub passed: bool,
    pub expected_findings: Vec<String>,
    pub actual_findings: Vec<String>,
    pub matched: Vec<String>,
    pub missed: Vec<String>,
    pub unexpected: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BugMeta {
    #[allow(dead_code)] // serde-populated; retained for JSON schema round-trip
    category: String,
    expected_findings: Vec<String>,
    #[allow(dead_code)]
    expected_path_type: String,
    #[allow(dead_code)]
    severity: String,
    #[allow(dead_code)]
    functions_affected: Vec<String>,
}

pub fn run(corpus_dir: &str, json_output: bool) {
    let bugs_dir = Path::new(corpus_dir).join("bugs");
    let exploits_dir = Path::new(corpus_dir).join("known-exploits");

    let mut cases = vec![];
    let mut categories: std::collections::HashMap<String, (usize, usize)> =
        std::collections::HashMap::new();

    if bugs_dir.exists() {
        load_from_bugs_dir(&bugs_dir, &mut cases, &mut categories);
    }
    if exploits_dir.exists() {
        load_from_exploits_dir(&exploits_dir, &mut cases, &mut categories);
    }

    let total_cases = cases.len();
    let passed = cases.iter().filter(|c| c.passed).count();
    let failed = total_cases - passed;
    let detection_rate = if total_cases > 0 {
        passed as f64 / total_cases as f64
    } else {
        0.0
    };

    let mut category_results: Vec<CategoryResult> = categories
        .iter()
        .map(|(name, (total, pass))| CategoryResult {
            category: name.clone(),
            total: *total,
            passed: *pass,
            detection_rate: if *total > 0 {
                *pass as f64 / *total as f64
            } else {
                0.0
            },
        })
        .collect();
    category_results.sort_by(|a, b| a.category.cmp(&b.category));

    let report = BenchmarkReport {
        total_cases,
        passed,
        failed,
        detection_rate,
        categories: category_results,
        cases,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
        );
    } else {
        print_report(&report);
    }
}

fn load_from_bugs_dir(
    bugs_dir: &Path,
    cases: &mut Vec<CaseResult>,
    categories: &mut std::collections::HashMap<String, (usize, usize)>,
) {
    for entry in fs::read_dir(bugs_dir).into_iter().flatten().flatten() {
        let category_dir = entry.path();
        if !category_dir.is_dir() {
            continue;
        }

        let category_name = category_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let meta_path = category_dir.join("meta.json");
        let meta: BugMeta = if meta_path.exists() {
            match fs::read_to_string(&meta_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
            {
                Some(m) => m,
                None => continue,
            }
        } else {
            continue;
        };

        for source_entry in fs::read_dir(&category_dir).into_iter().flatten().flatten() {
            let source_path = source_entry.path();
            let ext = source_path.extension().and_then(|e| e.to_str());
            if ext != Some("sol") && ext != Some("rs") {
                continue;
            }

            let lang = match ext {
                Some("sol") => "solidity",
                Some("rs") => {
                    let code = fs::read_to_string(&source_path).unwrap_or_default();
                    if code.contains("#[program]")
                        || code.contains("anchor_lang")
                        || code.contains("declare_id!")
                        || code.contains("#[account]")
                    {
                        "anchor"
                    } else {
                        "rust"
                    }
                }
                _ => continue,
            };

            let code = match fs::read_to_string(&source_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Solana (anchor/rust) fixtures are NOT scored by this command.
            // analyze_compat emits identical MissingAuthorityCheck@0.60 for
            // every Anchor fixture regardless of vuln/safe — zero discrimination.
            // Authoritative Solana measurement lives in the eval-gate
            // (cargo test -p digger-benchmark, measure.rs detect_* detectors).
            if matches!(lang, "anchor" | "rust") {
                eprintln!(
                    "  SKIPPED (Solana): {} — measured by eval-gate, not this command",
                    source_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                );
                continue;
            }

            let raw = parse_program(&code, lang);
            let ir = build_system_ir(raw);
            let findings = analyze(&ir);

            let actual_findings: Vec<String> = findings.iter().map(|f| f.kind.clone()).collect();

            let matched: Vec<String> = meta
                .expected_findings
                .iter()
                .filter(|ef| {
                    actual_findings
                        .iter()
                        .any(|af| normalize_finding(af) == normalize_finding(ef))
                })
                .cloned()
                .collect();

            let missed: Vec<String> = meta
                .expected_findings
                .iter()
                .filter(|ef| {
                    !actual_findings
                        .iter()
                        .any(|af| normalize_finding(af) == normalize_finding(ef))
                })
                .cloned()
                .collect();

            let unexpected: Vec<String> = actual_findings
                .iter()
                .filter(|af| {
                    !meta
                        .expected_findings
                        .iter()
                        .any(|ef| normalize_finding(af) == normalize_finding(ef))
                })
                .cloned()
                .collect();

            let passed = missed.is_empty();

            let category_entry = categories.entry(category_name.clone()).or_insert((0, 0));
            category_entry.0 += 1;
            if passed {
                category_entry.1 += 1;
            }

            cases.push(CaseResult {
                file: source_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                category: category_name.clone(),
                passed,
                expected_findings: meta.expected_findings.clone(),
                actual_findings,
                matched,
                missed,
                unexpected,
            });
        }
    }
}

fn load_from_exploits_dir(
    exploits_dir: &Path,
    cases: &mut Vec<CaseResult>,
    categories: &mut std::collections::HashMap<String, (usize, usize)>,
) {
    // Walk class directories (e.g., reentrancy/, oracle-manipulation/)
    for class_entry in fs::read_dir(exploits_dir).into_iter().flatten().flatten() {
        let class_path = class_entry.path();
        if !class_path.is_dir() {
            continue;
        }

        // Walk exploit directories within each class
        for exploit_entry in fs::read_dir(&class_path).into_iter().flatten().flatten() {
            let exploit_path = exploit_entry.path();
            if !exploit_path.is_dir() {
                continue;
            }

            let meta_path = exploit_path.join("meta.json");
            if !meta_path.exists() {
                continue;
            }

            let meta_str = match fs::read_to_string(&meta_path) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let meta: serde_json::Value = match serde_json::from_str(&meta_str) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let expected_findings: Vec<String> = meta
                .get("expected_findings")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let vulnerability_class = meta
                .get("vulnerability_class")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            if expected_findings.is_empty() {
                continue;
            }

            // Find source file
            let source_path = find_source_file(&exploit_path);
            if let Some(source_path) = source_path {
                let lang = classify_language(&source_path);
                let code = match fs::read_to_string(&source_path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                // Solana (anchor/rust) fixtures are NOT scored by this command.
                // analyze_compat emits identical MissingAuthorityCheck@0.60 for
                // every Anchor fixture regardless of vuln/safe — zero discrimination.
                // Authoritative Solana measurement lives in the eval-gate
                // (cargo test -p digger-benchmark, measure.rs detect_* detectors).
                if matches!(lang, "anchor" | "rust") {
                    eprintln!(
                        "  SKIPPED (Solana): {} — measured by eval-gate, not this command",
                        source_path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                    );
                    continue;
                }

                let raw = parse_program(&code, lang);
                let ir = build_system_ir(raw);
                let findings = analyze(&ir);

                let actual_findings: Vec<String> =
                    findings.iter().map(|f| f.kind.clone()).collect();

                let matched: Vec<String> = expected_findings
                    .iter()
                    .filter(|ef| {
                        actual_findings
                            .iter()
                            .any(|af| normalize_finding(af) == normalize_finding(ef))
                    })
                    .cloned()
                    .collect();

                let missed: Vec<String> = expected_findings
                    .iter()
                    .filter(|ef| {
                        !actual_findings
                            .iter()
                            .any(|af| normalize_finding(af) == normalize_finding(ef))
                    })
                    .cloned()
                    .collect();

                let unexpected: Vec<String> = actual_findings
                    .iter()
                    .filter(|af| {
                        !expected_findings
                            .iter()
                            .any(|ef| normalize_finding(af) == normalize_finding(ef))
                    })
                    .cloned()
                    .collect();

                let passed = missed.is_empty();

                let category_entry = categories
                    .entry(vulnerability_class.clone())
                    .or_insert((0, 0));
                category_entry.0 += 1;
                if passed {
                    category_entry.1 += 1;
                }

                cases.push(CaseResult {
                    file: source_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    category: vulnerability_class,
                    passed,
                    expected_findings,
                    actual_findings,
                    matched,
                    missed,
                    unexpected,
                });
            }
        }
    }
}

fn find_source_file(dir: &Path) -> Option<PathBuf> {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if ext == Some("sol") || ext == Some("rs") {
            return Some(path);
        }
    }
    None
}

fn classify_language(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "sol" => "solidity",
        "rs" => "anchor",
        _ => "unknown",
    }
}

fn print_report(report: &BenchmarkReport) {
    println!();
    println!("==============================");
    println!("    DIGGER BENCHMARK REPORT   ");
    println!("==============================");
    println!();
    println!("Total Cases: {}", report.total_cases);
    println!("Passed:      {}", report.passed);
    println!("Failed:      {}", report.failed);
    println!("Detection:   {:.1}%", report.detection_rate * 100.0);
    println!();

    println!("--- By Category ---");
    for cat in &report.categories {
        println!(
            "  {}: {}/{} ({:.1}%)",
            cat.category,
            cat.passed,
            cat.total,
            cat.detection_rate * 100.0
        );
    }
    println!();

    println!("--- Case Details ---");
    for case in &report.cases {
        let status = if case.passed { "PASS" } else { "FAIL" };
        println!("  [{}] {} ({})", status, case.file, case.category);
        if !case.missed.is_empty() {
            println!("      Missed: {:?}", case.missed);
        }
        if !case.unexpected.is_empty() {
            println!("      Unexpected: {:?}", case.unexpected);
        }
    }
    println!();

    if report.failed > 0 {
        println!("RESULT: {} failures detected", report.failed);
    } else {
        println!("RESULT: ALL CASES PASSED");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn solana_rs_fixture_is_skipped_not_scored() {
        // Create a temporary corpus with a single .rs anchor fixture
        let tmp = std::env::temp_dir().join(format!("digger-bench-test-{}", std::process::id()));
        let bugs = tmp.join("bugs").join("test-category");
        fs::create_dir_all(&bugs).unwrap();

        // Write a minimal anchor source file
        fs::write(
            bugs.join("vuln.rs"),
            "#[program]\npub mod test_prog {\n    use super::*;\n    pub fn do_thing(_ctx: Context<DoThing>) -> Result<()> { Ok(()) }\n}\n#[derive(Accounts)]\npub struct DoThing<'info> {\n    pub signer: Signer<'info>,\n}\n",
        )
        .unwrap();

        // Write meta.json with expected findings
        fs::write(
            bugs.join("meta.json"),
            r#"{"category":"test","expected_findings":["MissingAuthorityCheck"],"expected_path_type":"missing_signer","severity":"high","functions_affected":["do_thing"]}"#,
        )
        .unwrap();

        let mut cases = vec![];
        let mut categories = std::collections::HashMap::new();
        load_from_bugs_dir(&tmp.join("bugs"), &mut cases, &mut categories);

        // The .rs fixture must NOT appear in cases (skipped, not scored)
        assert!(
            cases.is_empty(),
            "Solana .rs fixture must be skipped — got {} scored cases",
            cases.len()
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn evm_sol_fixture_is_still_scored() {
        let tmp = std::env::temp_dir().join(format!("digger-bench-evm-{}", std::process::id()));
        let bugs = tmp.join("bugs").join("evm-cat");
        fs::create_dir_all(&bugs).unwrap();

        fs::write(
            bugs.join("vuln.sol"),
            "pragma solidity ^0.8.0;\ncontract Test { uint public x; function set(uint v) external { x = v; } }\n",
        )
        .unwrap();
        fs::write(
            bugs.join("meta.json"),
            r#"{"category":"evm-cat","expected_findings":["PriceOracleManipulation"],"expected_path_type":"oracle","severity":"high","functions_affected":["set"]}"#,
        )
        .unwrap();

        let mut cases = vec![];
        let mut categories = std::collections::HashMap::new();
        load_from_bugs_dir(&tmp.join("bugs"), &mut cases, &mut categories);

        // The .sol fixture IS scored (even if it misses — that's expected)
        assert_eq!(cases.len(), 1, "EVM .sol fixture must be scored");

        let _ = fs::remove_dir_all(&tmp);
    }
}
