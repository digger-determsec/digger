//! EVM fuzzing maturity scanner.
//!
//! Static filesystem analysis of a local repository path. Reports whether
//! the project has real invariant-fuzzing infrastructure. This is a maturity
//! signal, NOT a vulnerability detector and NOT fuzz failure ingestion.
//!
//! Per ADR-0038: harness presence is not evidence of a bug, clean fuzz runs
//! are not proof of absence, and no replayable failure means no high-confidence
//! fuzz finding.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VacuityWarning {
    pub category: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaturityReport {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub chain: String,
    pub report_type: String,
    pub is_vulnerability_finding: bool,
    pub maturity_score: u8,
    pub signals_present: Vec<String>,
    pub signals_missing: Vec<String>,
    pub vacuity_warnings: Vec<VacuityWarning>,
    pub recommended_next_steps: Vec<String>,
    pub limitations: Vec<String>,
    pub confidence_ceiling: String,
    pub scanned_path: String,
}

pub fn scan_fuzzing_maturity(path: &Path) -> MaturityReport {
    if !path.exists() {
        return MaturityReport {
            schema_version: "digger.fuzz_maturity.v1".into(),
            digger_version: env!("CARGO_PKG_VERSION").into(),
            report_kind: "fuzz_maturity".into(),
            chain: "evm".into(),
            report_type: "fuzzing_maturity".into(),
            is_vulnerability_finding: false,
            maturity_score: 0,
            signals_present: vec![],
            signals_missing: all_signal_names(),
            vacuity_warnings: vec![VacuityWarning {
                category: "empty_invariant".into(),
                message: format!("Path does not exist: {}", path.display()),
            }],
            recommended_next_steps: vec!["Provide a valid EVM project path.".into()],
            limitations: vec!["Path does not exist.".into()],
            confidence_ceiling: "suggested_invariant".into(),
            scanned_path: path.display().to_string(),
        };
    }

    let mut signals_present = Vec::new();
    let mut signals_missing = Vec::new();
    let mut vacuity_warnings = Vec::new();
    let mut score: u8 = 0;

    let files = collect_solidity_files(path);
    let fuzz_files = collect_fuzz_invariant_files(&files);
    let configs = collect_fuzz_configs(path);
    let ci_configs = collect_ci_configs(path);

    // 1. Foundry invariant tests
    if has_foundry_invariant_signals(&fuzz_files) {
        signals_present.push("foundry_invariant_tests".into());
        score += 20;
    } else {
        signals_missing.push("foundry_invariant_tests".into());
    }

    // 2. Echidna presence
    if has_echidna_signals(&configs, &files) {
        signals_present.push("echidna_present".into());
        score += 20;
    } else {
        signals_missing.push("echidna_present".into());
    }

    // 3. Medusa presence
    if has_medusa_signals(&configs, &files) {
        signals_present.push("medusa_present".into());
        score += 20;
    } else {
        signals_missing.push("medusa_present".into());
    }

    // 4. Handler contracts
    if has_handler_contracts(&files) {
        signals_present.push("handler_contracts".into());
        score += 10;
    } else {
        signals_missing.push("handler_contracts".into());
    }

    // 5. Target selector/config hints
    if has_target_config_signals(&configs, &files) {
        signals_present.push("target_config".into());
        score += 10;
    } else {
        signals_missing.push("target_config".into());
    }

    // 6. Meaningful assertions
    if has_assertion_signals(&fuzz_files) {
        signals_present.push("meaningful_assertions".into());
        score += 15;
    } else if !fuzz_files.is_empty() {
        vacuity_warnings.push(VacuityWarning {
            category: "empty_invariant".into(),
            message: "Invariant/fuzz functions found but appear to lack meaningful assertions."
                .into(),
        });
        signals_missing.push("meaningful_assertions".into());
    } else {
        signals_missing.push("meaningful_assertions".into());
    }

    // 7. Setup/state hints
    if has_setup_signals(&fuzz_files) {
        signals_present.push("setup_state".into());
        score += 10;
    } else if !fuzz_files.is_empty() {
        vacuity_warnings.push(VacuityWarning {
            category: "no_setup".into(),
            message: "Invariant/fuzz files found but no setUp or state initialization signals."
                .into(),
        });
        signals_missing.push("setup_state".into());
    } else {
        signals_missing.push("setup_state".into());
    }

    // 8. CI fuzz job hints
    if has_ci_fuzz_signals(&ci_configs) {
        signals_present.push("ci_fuzz_jobs".into());
        score += 5;
    } else {
        signals_missing.push("ci_fuzz_jobs".into());
    }

    // 9. Corpus/reproducer hints
    if has_corpus_signals(path) {
        signals_present.push("corpus_reproducer".into());
        score += 5;
    } else {
        signals_missing.push("corpus_reproducer".into());
    }

    // 10. Reusable property hints
    if has_property_hints(&files) {
        signals_present.push("property_hints".into());
        score += 5;
    } else {
        signals_missing.push("property_hints".into());
    }

    // Vacuity checks
    if !fuzz_files.is_empty() && has_all_empty_invariants(&fuzz_files) {
        vacuity_warnings.push(VacuityWarning {
            category: "all_empty".into(),
            message: "All invariant/fuzz candidates appear empty or trivial.".into(),
        });
        score = score.saturating_sub(20);
    }

    if signals_present.is_empty() {
        vacuity_warnings.push(VacuityWarning {
            category: "empty_invariant".into(),
            message: "No fuzzing infrastructure detected in this repository.".into(),
        });
    }

    if configs.is_empty() && !fuzz_files.is_empty() {
        vacuity_warnings.push(VacuityWarning {
            category: "config_no_test".into(),
            message: "Fuzz config files found but no matching invariant/test files.".into(),
        });
    }

    if !configs.is_empty() && fuzz_files.is_empty() {
        vacuity_warnings.push(VacuityWarning {
            category: "tests_no_ci".into(),
            message: "Fuzz configuration present but no test/harness files found.".into(),
        });
    }

    if fuzz_files.is_empty() && configs.is_empty() && ci_configs.is_empty() {
        vacuity_warnings.push(VacuityWarning {
            category: "no_corpus".into(),
            message: "No fuzz corpus, reproducers, or call-sequence artifacts found.".into(),
        });
    }

    let mut steps = Vec::new();
    if signals_present.is_empty() {
        steps.push(
            "Add Foundry invariant tests with StdInvariant and meaningful assertions.".into(),
        );
    }
    if signals_missing.contains(&"handler_contracts".to_string()) {
        steps.push("Add handler contracts that exercise privileged state transitions.".into());
    }
    if signals_missing.contains(&"target_config".to_string()) {
        steps.push("Configure target contracts/selectors for invariant campaigns.".into());
    }
    if signals_missing.contains(&"ci_fuzz_jobs".to_string()) {
        steps.push(
            "Add CI jobs for forge test --match-contract invariant_ / echidna / medusa.".into(),
        );
    }
    if signals_missing.contains(&"setup_state".to_string()) {
        steps.push("Add setUp() with meaningful state initialization in invariant tests.".into());
    }

    let ceiling = if score >= 25 {
        "harness/config_present"
    } else {
        "suggested_invariant"
    };

    let limits = vec![
        "Static filesystem analysis only — no code execution, no compilation, no network.".into(),
        "Cannot detect runtime-only fuzz harnesses that don't match naming conventions.".into(),
        "Cannot assess fuzz coverage quality or campaign effectiveness.".into(),
        "No replayable failure ingestion in K.1 — confidence ceiling is harness/config present."
            .into(),
    ];

    MaturityReport {
        schema_version: "digger.fuzz_maturity.v1".into(),
        digger_version: env!("CARGO_PKG_VERSION").into(),
        report_kind: "fuzz_maturity".into(),
        chain: "evm".into(),
        report_type: "fuzzing_maturity".into(),
        is_vulnerability_finding: false,
        maturity_score: score.min(100),
        signals_present,
        signals_missing,
        vacuity_warnings,
        recommended_next_steps: steps,
        limitations: limits,
        confidence_ceiling: ceiling.into(),
        scanned_path: path.display().to_string(),
    }
}

// ── File collection ──

fn collect_solidity_files(root: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    walk_dir(root, &mut results, &["sol"]);
    results
}

fn collect_fuzz_invariant_files(all_sol: &[PathBuf]) -> Vec<PathBuf> {
    all_sol
        .iter()
        .filter(|p| is_fuzz_invariant_file(p))
        .cloned()
        .collect()
}

fn is_fuzz_invariant_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    let content = std::fs::read_to_string(path)
        .ok()
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    name.contains("invariant")
        || name.contains("fuzz")
        || name.contains("echidna")
        || content.contains("invariant_")
        || content.contains("stdinvariant")
        || content.contains("echidna_")
}

fn collect_fuzz_configs(root: &Path) -> Vec<PathBuf> {
    let mut configs = Vec::new();
    for name in &[
        "echidna.yaml",
        "echidna.yml",
        "medusa.json",
        "medusa.yaml",
        "foundry.toml",
    ] {
        let p = root.join(name);
        if p.exists() {
            configs.push(p);
        }
    }
    for entry in walk_and_filter(root, &["yaml", "yml", "json", "toml"]) {
        let fname = entry
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if fname.contains("echidna") || fname.contains("medusa") || fname.contains("fuzz") {
            configs.push(entry);
        }
    }
    configs
}

fn collect_ci_configs(root: &Path) -> Vec<PathBuf> {
    let mut configs = Vec::new();
    for ci_dir in &[
        ".github/workflows",
        ".gitlab-ci.yml",
        ".circleci",
        ".github/actions",
    ] {
        let p = root.join(ci_dir);
        if p.exists() && p.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&p) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                            if ext == "yml" || ext == "yaml" {
                                configs.push(path);
                            }
                        }
                    }
                }
            }
        } else if p.exists() && p.is_file() {
            configs.push(p);
        }
    }
    configs
}

fn walk_and_filter(root: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut results = Vec::new();
    walk_dir(root, &mut results, extensions);
    results
}

fn walk_dir(dir: &Path, results: &mut Vec<PathBuf>, extensions: &[&str]) {
    let entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(e) => e.flatten().collect(),
        Err(_) => return,
    };
    for entry in &entries {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "node_modules" || name == "lib" || name == "out" {
                continue;
            }
            walk_dir(&path, results, extensions);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if extensions.contains(&ext) {
                results.push(path);
            }
        }
    }
}

// ── Signal detection ──

fn has_foundry_invariant_signals(fuzz_files: &[PathBuf]) -> bool {
    for f in fuzz_files {
        if let Ok(content) = std::fs::read_to_string(f) {
            let lc = content.to_lowercase();
            if lc.contains("stdinvariant") || lc.contains("invariant_") {
                return true;
            }
        }
    }
    false
}

fn has_echidna_signals(configs: &[PathBuf], files: &[PathBuf]) -> bool {
    for c in configs {
        let name = c
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if name.contains("echidna") {
            return true;
        }
    }
    for f in files {
        let name = f
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if name.contains("echidna") {
            return true;
        }
        if let Ok(content) = std::fs::read_to_string(f) {
            if content.to_lowercase().contains("echidna_") {
                return true;
            }
        }
    }
    false
}

fn has_medusa_signals(configs: &[PathBuf], files: &[PathBuf]) -> bool {
    for c in configs {
        let name = c
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if name.contains("medusa") {
            return true;
        }
    }
    for f in files {
        if let Ok(content) = std::fs::read_to_string(f) {
            let lc = content.to_lowercase();
            if lc.contains("medusa") && lc.contains("test") {
                return true;
            }
        }
    }
    false
}

fn has_handler_contracts(files: &[PathBuf]) -> bool {
    for f in files {
        let name = f
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if name.contains("handler") {
            return true;
        }
        if let Ok(content) = std::fs::read_to_string(f) {
            let lc = content.to_lowercase();
            if lc.contains("contract handler") || lc.contains("contract fuzzhandler") {
                return true;
            }
        }
    }
    false
}

fn has_target_config_signals(configs: &[PathBuf], files: &[PathBuf]) -> bool {
    let targets = [
        "targetcontract",
        "targetselector",
        "targetartifact",
        "targetcontracts",
    ];
    for c in configs {
        if let Ok(content) = std::fs::read_to_string(c) {
            let lc = content.to_lowercase();
            if targets.iter().any(|t| lc.contains(t)) {
                return true;
            }
        }
    }
    for f in files {
        if let Ok(content) = std::fs::read_to_string(f) {
            let lc = content.to_lowercase();
            if targets.iter().any(|t| lc.contains(t)) {
                return true;
            }
        }
    }
    false
}

fn has_assertion_signals(fuzz_files: &[PathBuf]) -> bool {
    let terms = ["assert", "asserteq", "assertge", "assertle", "require"];
    for f in fuzz_files {
        if let Ok(content) = std::fs::read_to_string(f) {
            let lc = content.to_lowercase();
            if terms.iter().any(|t| lc.contains(t)) {
                return true;
            }
        }
    }
    false
}

fn has_setup_signals(fuzz_files: &[PathBuf]) -> bool {
    let terms = [
        "setup(",
        "mint(",
        "deposit(",
        "borrow(",
        "liquidate(",
        "swap(",
        "transfer(",
    ];
    for f in fuzz_files {
        if let Ok(content) = std::fs::read_to_string(f) {
            let lc = content.to_lowercase();
            if terms.iter().any(|t| lc.contains(t)) {
                return true;
            }
        }
    }
    false
}

fn has_ci_fuzz_signals(ci_configs: &[PathBuf]) -> bool {
    let terms = ["forge test", "echidna", "medusa", "invariant"];
    for c in ci_configs {
        if let Ok(content) = std::fs::read_to_string(c) {
            let lc = content.to_lowercase();
            if terms.iter().any(|t| lc.contains(t)) {
                return true;
            }
        }
    }
    false
}

fn has_corpus_signals(root: &Path) -> bool {
    for hint in &[
        "corpus",
        "reproducer",
        "call-sequence",
        "minimized",
        "trace",
    ] {
        if root.join(hint).exists() {
            return true;
        }
    }
    for f in walk_and_filter(root, &["txt", "bin", "json"]) {
        let name = f
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if [
            "corpus",
            "reproducer",
            "call-sequence",
            "minimized",
            "trace",
        ]
        .iter()
        .any(|h| name.contains(h))
        {
            return true;
        }
    }
    false
}

fn has_property_hints(files: &[PathBuf]) -> bool {
    let terms = [
        "erc20", "erc721", "erc4626", "erc7540", "proptest", "property",
    ];
    for f in files {
        let name = f
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if terms.iter().any(|t| name.contains(t)) {
            return true;
        }
        if let Ok(content) = std::fs::read_to_string(f) {
            let lc = content.to_lowercase();
            if terms.iter().any(|t| lc.contains(t)) {
                return true;
            }
        }
    }
    false
}

fn has_all_empty_invariants(fuzz_files: &[PathBuf]) -> bool {
    if fuzz_files.is_empty() {
        return false;
    }
    fuzz_files.iter().all(|f| {
        std::fs::read_to_string(f)
            .map(|c| {
                let lc = c.to_lowercase();
                !lc.contains("assert")
                    && !lc.contains("require")
                    && !lc.contains("transfer")
                    && !lc.contains("mint")
                    && !lc.contains("deposit")
            })
            .unwrap_or(true)
    })
}

fn all_signal_names() -> Vec<String> {
    vec![
        "foundry_invariant_tests".into(),
        "echidna_present".into(),
        "medusa_present".into(),
        "handler_contracts".into(),
        "target_config".into(),
        "meaningful_assertions".into(),
        "setup_state".into(),
        "ci_fuzz_jobs".into(),
        "corpus_reproducer".into(),
        "property_hints".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fuzz_maturity_test_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_foundry_invariant_project() {
        let dir = tmpdir("foundry_inv");
        let tdir = dir.join("test");
        fs::create_dir_all(&tdir).unwrap();
        fs::write(
            tdir.join("InvariantCounter.t.sol"),
            "import StdInvariant; contract InvariantCounter is StdInvariant { function invariant_counter_never_negative() public view { assertGe(counter.value(), 0); } }",
        )
        .unwrap();
        fs::write(
            dir.join("CounterHandler.sol"),
            "contract CounterHandler { function doSomething() public {} }",
        )
        .unwrap();

        let report = scan_fuzzing_maturity(&dir);
        assert!(
            report.maturity_score > 30,
            "score={}",
            report.maturity_score
        );
        assert!(report
            .signals_present
            .contains(&"foundry_invariant_tests".into()));
        assert!(report
            .signals_present
            .contains(&"meaningful_assertions".into()));
        assert!(!report.is_vulnerability_finding);
        assert_eq!(report.chain, "evm");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_empty_invariants_vacuity() {
        let dir = tmpdir("empty_inv");
        fs::write(
            dir.join("EmptyFuzz.t.sol"),
            "contract EmptyFuzz { function invariant_something() public view {} }",
        )
        .unwrap();
        let report = scan_fuzzing_maturity(&dir);
        assert!(report
            .vacuity_warnings
            .iter()
            .any(|w| w.category == "empty_invariant"));
        assert!(report.maturity_score < 50);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_echidna_detection() {
        let dir = tmpdir("echidna");
        fs::write(dir.join("echidna.yaml"), "testMode: assertion").unwrap();
        fs::write(
            dir.join("EchidnaTest.sol"),
            "function echidna_test_something() returns (bool) { return true; }",
        )
        .unwrap();
        let report = scan_fuzzing_maturity(&dir);
        assert!(report.signals_present.contains(&"echidna_present".into()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_medusa_detection() {
        let dir = tmpdir("medusa");
        fs::write(dir.join("medusa.json"), "{}").unwrap();
        fs::write(
            dir.join("MedusaTest.sol"),
            "contract MedusaTest is Test { }",
        )
        .unwrap();
        let report = scan_fuzzing_maturity(&dir);
        assert!(report.signals_present.contains(&"medusa_present".into()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ci_fuzz_job_detection() {
        let dir = tmpdir("ci_fuzz");
        let ci = dir.join(".github").join("workflows");
        fs::create_dir_all(&ci).unwrap();
        fs::write(
            ci.join("fuzz.yml"),
            "name: Fuzz\njobs:\n  fuzz:\n    run: forge test --match-contract invariant_",
        )
        .unwrap();
        let report = scan_fuzzing_maturity(&dir);
        assert!(report.signals_present.contains(&"ci_fuzz_jobs".into()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_no_fuzzing_infrastructure() {
        let dir = tmpdir("no_fuzz");
        fs::write(dir.join("Token.sol"), "contract Token {}").unwrap();
        let report = scan_fuzzing_maturity(&dir);
        assert_eq!(report.maturity_score, 0);
        assert!(report.signals_present.is_empty());
        assert!(!report.is_vulnerability_finding);
        assert_eq!(report.confidence_ceiling, "suggested_invariant");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_no_vulnerability_labels() {
        let dir = tmpdir("no_vuln");
        let tdir = dir.join("test");
        fs::create_dir_all(&tdir).unwrap();
        fs::write(
            tdir.join("Invariant.t.sol"),
            "function invariant_x() public { assertEq(1, 1); }",
        )
        .unwrap();
        let report = scan_fuzzing_maturity(&dir);
        assert!(!report.is_vulnerability_finding);
        assert!(!report.report_type.contains("finding"));
        assert!(report.confidence_ceiling != "graduated");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_corpus_detection() {
        let dir = tmpdir("corpus_test");
        fs::create_dir_all(dir.join("corpus")).unwrap();
        fs::write(dir.join("corpus").join("call_1.bin"), "").unwrap();
        let report = scan_fuzzing_maturity(&dir);
        assert!(report.signals_present.contains(&"corpus_reproducer".into()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_flip_proof_no_fuzzing() {
        let dir = tmpdir("flip_a");
        let tdir = dir.join("test");
        fs::create_dir_all(&tdir).unwrap();
        fs::write(
            tdir.join("Inv.t.sol"),
            "function invariant_x() public { assert(true); }",
        )
        .unwrap();
        let report_with = scan_fuzzing_maturity(&dir);
        let score_with = report_with.maturity_score;

        let dir2 = tmpdir("flip_b");
        fs::write(dir2.join("Token.sol"), "contract Token {}").unwrap();
        let report_without = scan_fuzzing_maturity(&dir2);

        assert!(score_with > report_without.maturity_score);
        assert!(!report_with.is_vulnerability_finding);
        assert!(!report_without.is_vulnerability_finding);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn test_ceiling_empty_repo_is_lowest() {
        let dir = tmpdir("ceiling_empty");
        fs::write(dir.join("Token.sol"), "contract Token {}").unwrap();
        let report = scan_fuzzing_maturity(&dir);
        assert_eq!(report.confidence_ceiling, "suggested_invariant");
        assert_eq!(report.maturity_score, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ceiling_populated_harness_is_harness_present() {
        let dir = tmpdir("ceiling_harness");
        let tdir = dir.join("test");
        fs::create_dir_all(&tdir).unwrap();
        fs::write(
            tdir.join("InvariantCounter.t.sol"),
            "import StdInvariant; contract InvariantCounter is StdInvariant { function invariant_counter_never_negative() public view { assertGe(counter.value(), 0); } }",
        )
        .unwrap();
        fs::write(
            dir.join("CounterHandler.sol"),
            "contract CounterHandler { function doSomething() public {} }",
        )
        .unwrap();
        let report = scan_fuzzing_maturity(&dir);
        assert_eq!(
            report.confidence_ceiling, "harness/config_present",
            "real harness config must reach harness/config_present ceiling"
        );
        assert!(report.maturity_score >= 25);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ceiling_never_exceeds_harness_present() {
        // No matter how many signals, ceiling never goes above harness/config_present
        // because K.1 does not execute fuzzers or ingest failures.
        let dir = tmpdir("ceiling_max");
        let tdir = dir.join("test");
        fs::create_dir_all(&tdir).unwrap();
        fs::write(
            tdir.join("InvariantCounter.t.sol"),
            "import StdInvariant; contract InvariantCounter is StdInvariant { function invariant_counter_never_negative() public view { assertGe(counter.value(), 0); } }",
        )
        .unwrap();
        fs::write(
            dir.join("CounterHandler.sol"),
            "contract CounterHandler { function doSomething() public {} }",
        )
        .unwrap();
        fs::write(dir.join("echidna.yaml"), "testMode: assertion").unwrap();
        fs::create_dir_all(dir.join("corpus")).unwrap();
        fs::write(dir.join("corpus").join("call_1.bin"), "").unwrap();
        let ci = dir.join(".github").join("workflows");
        fs::create_dir_all(&ci).unwrap();
        fs::write(
            ci.join("fuzz.yml"),
            "run: forge test --match-contract invariant_",
        )
        .unwrap();

        let report = scan_fuzzing_maturity(&dir);
        assert!(
            report.confidence_ceiling == "harness/config_present",
            "ceiling must never exceed harness/config_present in K.1, got: {}",
            report.confidence_ceiling
        );
        // Verify higher fuzz-execution levels are never emitted
        assert!(!report.confidence_ceiling.contains("campaign_ran_clean"));
        assert!(!report.confidence_ceiling.contains("invariant_failed"));
        assert!(!report.confidence_ceiling.contains("failure_replayed"));
        assert!(!report.confidence_ceiling.contains("failure_minimized"));
        assert!(!report.confidence_ceiling.contains("poc_test_generated"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_maturity_report_schema_contract() {
        let dir = tmpdir("schema_contract");
        fs::write(
            dir.join("Test.t.sol"),
            "contract Test { function test_x() public {} }",
        )
        .unwrap();
        let report = scan_fuzzing_maturity(&dir);
        let json = serde_json::to_value(&report).unwrap();

        // Required top-level fields must exist and have correct types
        assert!(json["chain"].is_string(), "chain must be string");
        assert!(
            json["report_type"].is_string(),
            "report_type must be string"
        );
        assert!(
            json["is_vulnerability_finding"].is_boolean(),
            "is_vulnerability_finding must be boolean"
        );
        assert!(
            json["maturity_score"].is_number(),
            "maturity_score must be number"
        );
        assert!(
            json["signals_present"].is_array(),
            "signals_present must be array"
        );
        assert!(
            json["signals_missing"].is_array(),
            "signals_missing must be array"
        );
        assert!(
            json["vacuity_warnings"].is_array(),
            "vacuity_warnings must be array"
        );
        assert!(
            json["recommended_next_steps"].is_array(),
            "recommended_next_steps must be array"
        );
        assert!(json["limitations"].is_array(), "limitations must be array");
        assert!(
            json["confidence_ceiling"].is_string(),
            "confidence_ceiling must be string"
        );
        assert!(
            json["scanned_path"].is_string(),
            "scanned_path must be string"
        );

        // Invariants pinned by schema
        assert_eq!(json["schema_version"], "digger.fuzz_maturity.v1");
        assert!(
            json["digger_version"].is_string(),
            "digger_version must be string"
        );
        assert_eq!(json["report_kind"], "fuzz_maturity");
        assert_eq!(json["report_type"], "fuzzing_maturity");
        assert_eq!(json["is_vulnerability_finding"], false);
        assert_eq!(json["chain"], "evm");

        let cc = json["confidence_ceiling"].as_str().unwrap();
        assert!(
            cc == "suggested_invariant" || cc == "harness/config_present",
            "confidence_ceiling must be suggested_invariant or harness/config_present, got: {}",
            cc
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
