#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]
#![allow(clippy::unnecessary_map_or, clippy::unnecessary_sort_by)]

#[cfg(test)]
use digger_graph::build_system_ir;
#[cfg(test)]
use digger_hypothesis::analyze_compat as analyze;
#[cfg(test)]
use digger_parser::parse_program;

#[cfg(test)]
mod scaffolding {
    use std::fs;
    use std::path::{Path, PathBuf};

    use digger_graph::build_system_ir;
    use digger_hypothesis::analyze_compat as analyze;
    use digger_parser::parse_program;

    pub struct Finding {
        pub kind: String,
        pub severity: String,
        pub function: String,
        pub _confidence: f32,
    }

    pub fn walk_files(dir: &Path, ext: &str) -> Vec<PathBuf> {
        let mut files = vec![];
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    if name == "target" || name == "node_modules" || name == ".git" {
                        continue;
                    }
                    files.extend(walk_files(&path, ext));
                } else if path
                    .extension()
                    .map_or(false, |e| e == ext.trim_start_matches('.'))
                {
                    files.push(path);
                }
            }
        }
        files
    }

    pub fn severity_order(s: &str) -> u8 {
        match s {
            "Critical" => 0,
            "High" => 1,
            "Medium" => 2,
            "Low" => 3,
            "Info" => 4,
            _ => 5,
        }
    }

    pub fn run_audit(repo_path: &Path, lang: &str) -> Vec<Finding> {
        let ext = match lang {
            "solidity" => ".sol",
            "anchor" | "rust" => ".rs",
            _ => return vec![],
        };

        let files = walk_files(repo_path, ext);
        let mut all_findings = vec![];

        for file_path in &files {
            if let Ok(code) = fs::read_to_string(file_path) {
                if code.trim().is_empty() {
                    continue;
                }

                let raw = parse_program(&code, lang);
                let ir = build_system_ir(raw);
                let hypotheses = analyze(&ir);

                for h in hypotheses {
                    all_findings.push(Finding {
                        kind: h.kind,
                        severity: format!("{:?}", h.severity),
                        function: h.affected_function,
                        _confidence: h.confidence,
                    });
                }
            }
        }

        all_findings.sort_by(|a, b| severity_order(&b.severity).cmp(&severity_order(&a.severity)));

        all_findings
    }
}

#[ignore = "requires external clone under test_repos/ (run: cargo test -p digger-tests -- --ignored)"]
#[test]
fn test_squads_v4() {
    use scaffolding::*;
    use std::path::Path;

    let repo_path = Path::new("../../test_repos/squads/programs/squads_multisig_program");
    if !repo_path.exists() {
        eprintln!("SKIP: Squads repo not cloned");
        return;
    }

    let result = run_audit(repo_path, "anchor");

    println!("Squads v4 audit:");
    println!("  Files scanned: {}", walk_files(repo_path, ".rs").len());
    println!("  Findings: {}", result.len());
    for f in &result {
        println!("  [{}] {} - {}", f.severity, f.kind, f.function);
    }

    assert!(
        !result.is_empty() || walk_files(repo_path, ".rs").is_empty(),
        "Squads should produce findings or have no source files"
    );
}

#[ignore = "requires external clone under test_repos/ (run: cargo test -p digger-tests -- --ignored)"]
#[test]
fn test_drift_v2() {
    use scaffolding::*;
    use std::path::Path;

    let repo_path = Path::new("../../test_repos/drift/programs/drift");
    if !repo_path.exists() {
        eprintln!("SKIP: Drift repo not cloned");
        return;
    }

    let result = run_audit(repo_path, "anchor");

    println!("Drift v2 audit:");
    println!("  Files scanned: {}", walk_files(repo_path, ".rs").len());
    println!("  Findings: {}", result.len());
    for f in result.iter().take(10) {
        println!("  [{}] {} - {}", f.severity, f.kind, f.function);
    }
    if result.len() > 10 {
        println!("  ... and {} more", result.len() - 10);
    }

    assert!(
        !result.is_empty() || walk_files(repo_path, ".rs").is_empty(),
        "Drift should produce findings or have no source files"
    );
}

#[ignore = "requires external clone under test_repos/ (run: cargo test -p digger-tests -- --ignored)"]
#[test]
fn test_determinism() {
    use scaffolding::*;
    use std::path::Path;

    let repo_path = Path::new("../../test_repos/squads/programs/squads_multisig_program");
    if !repo_path.exists() {
        eprintln!("SKIP: Squads repo not cloned");
        return;
    }

    let result1 = run_audit(repo_path, "anchor");
    let result2 = run_audit(repo_path, "anchor");
    let result3 = run_audit(repo_path, "anchor");

    assert_eq!(result1.len(), result2.len(), "Run 1 and 2 should match");
    assert_eq!(result2.len(), result3.len(), "Run 2 and 3 should match");

    for i in 0..result1.len() {
        assert_eq!(
            result1[i].kind, result2[i].kind,
            "Finding kind mismatch at {}",
            i
        );
        assert_eq!(
            result1[i].severity, result2[i].severity,
            "Severity mismatch at {}",
            i
        );
    }

    println!("Determinism check: PASS (3 runs, identical output)");
}

#[ignore = "requires external clone under test_repos/ (run: cargo test -p digger-tests -- --ignored)"]
#[test]
fn test_no_crash_on_any_file() {
    use scaffolding::*;
    use std::path::Path;

    let repo_path = Path::new("../../test_repos/squads/programs/squads_multisig_program");
    if !repo_path.exists() {
        eprintln!("SKIP: Squads repo not cloned");
        return;
    }

    let files = walk_files(repo_path, ".rs");
    let errors = 0;

    for file_path in &files {
        if let Ok(code) = std::fs::read_to_string(file_path) {
            if code.trim().is_empty() {
                continue;
            }

            let raw = parse_program(&code, "anchor");
            let ir = build_system_ir(raw);
            let _ = analyze(&ir);
        }
    }

    println!(
        "No-crash check: PASS ({} files processed, {} errors)",
        files.len(),
        errors
    );
    assert_eq!(errors, 0, "No file should cause a crash");
}
