/// End-to-end tests: run real detectors over real corpus, feed the real gate.
use digger_benchmark::evaluate_gate;
use digger_benchmark::measure::{
    case_target_detectors, measure_detectors, measure_detectors_multi, normalize_detector_id,
};
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let d = env!("CARGO_MANIFEST_DIR");
    Path::new(d)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn labeled_dirs() -> Vec<PathBuf> {
    let root = workspace_root();
    vec![
        root.join("corpus").join("solana-account-model"),
        root.join("corpus").join("price-manipulation"),
        root.join("corpus").join("operational-layer"),
    ]
}

#[test]
fn test_gate_e2e_pass_on_current_corpus() {
    let root = workspace_root();
    let held_out_dir = root.join("corpus/held-out-fp");

    let measurements = measure_detectors_multi(&labeled_dirs(), &held_out_dir);
    assert!(
        !measurements.is_empty(),
        "measure_detectors should return measurements"
    );

    let labeled: Vec<_> = measurements
        .iter()
        .filter(|m| m.corpus_type == "labeled")
        .cloned()
        .collect();
    let held_out: Vec<_> = measurements
        .iter()
        .filter(|m| m.corpus_type == "held-out")
        .cloned()
        .collect();

    assert!(
        !labeled.is_empty(),
        "should have labeled measurements from solana + EVM corpus"
    );

    eprintln!();
    eprintln!("===== E2E MEASUREMENTS =====");
    for m in &measurements {
        eprintln!(
            "  {:<30} {:<10} TP={} FP={} FN={} TN={} recall={:.1}% precision={:.1}% floor={:.1}%",
            m.detector,
            m.corpus_type,
            m.tp,
            m.fp,
            m.fn_count,
            m.tn,
            m.recall * 100.0,
            m.precision * 100.0,
            m.recall_floor * 100.0
        );
    }
    eprintln!();

    let report = evaluate_gate(&labeled, &held_out);

    assert!(
        report.gate_passed,
        "gate must pass. FP: {:?}, recall: {:?}",
        report.held_out_fp_violations, report.recall_violations
    );

    // Verify evm_price_oracle has a labeled measurement with real TP
    let evm_labeled: Vec<_> = labeled
        .iter()
        .filter(|m| m.detector == "evm_price_oracle")
        .collect();
    assert_eq!(
        evm_labeled.len(),
        1,
        "must have exactly 1 evm_price_oracle labeled measurement"
    );
    assert!(
        evm_labeled[0].tp > 0,
        "evm_price_oracle must have TP > 0 from price-manipulation corpus"
    );
    assert!(
        evm_labeled[0].recall >= evm_labeled[0].recall_floor,
        "evm_price_oracle recall must clear its floor"
    );

    // Verify held-out corpus has expected TN counts (locks the committed corpus size)
    let solana_held_out_tn: usize = held_out
        .iter()
        .filter(|m| m.detector == "solana_access_control")
        .map(|m| m.tn)
        .sum();
    assert!(
        solana_held_out_tn >= 7,
        "solana held-out must have >= 7 TN (got {}) — missing fixtures?",
        solana_held_out_tn
    );

    // Verify labeled corpus has grown (new per-class fixtures added)
    let solana_labeled_tn: usize = labeled
        .iter()
        .filter(|m| m.detector == "solana_access_control")
        .map(|m| m.tn)
        .sum();
    assert!(
        solana_labeled_tn >= 14,
        "solana labeled must have >= 14 TN after corpus growth (got {})",
        solana_labeled_tn
    );

    // Lock per-class labeled positive counts (tp + fn) so a dropped or
    // unlabeled fixture trips the gate — TN counts alone do not catch this.
    let labeled_pos = |det: &str| -> usize {
        labeled
            .iter()
            .filter(|m| m.detector == det)
            .map(|m| m.tp + m.fn_count)
            .sum()
    };
    assert_eq!(
        labeled_pos("solana_unvalidated_cpi"),
        5,
        "expected 5 labeled CPI positives (got {})",
        labeled_pos("solana_unvalidated_cpi")
    );
    assert_eq!(
        labeled_pos("solana_type_cosplay"),
        4,
        "expected 4 labeled type-cosplay positives (got {})",
        labeled_pos("solana_type_cosplay")
    );
    assert_eq!(
        labeled_pos("solana_unchecked_account_owner"),
        6,
        "expected 6 labeled unchecked-owner positives (got {})",
        labeled_pos("solana_unchecked_account_owner")
    );
    assert_eq!(
        labeled_pos("solana_access_control"),
        10,
        "expected 10 labeled access-control positives (got {})",
        labeled_pos("solana_access_control")
    );

    let evm_held_out_tn: usize = held_out
        .iter()
        .filter(|m| m.detector == "evm_price_oracle")
        .map(|m| m.tn)
        .sum();
    assert!(
        evm_held_out_tn >= 3,
        "evm held-out must have >= 3 TN (got {}) — missing fixtures?",
        evm_held_out_tn
    );

    // Verify op-layer corpus is measured (not skipped by extension routing)
    let op_labeled: Vec<_> = labeled
        .iter()
        .filter(|m| m.detector == "op_unverified_attestation")
        .collect();
    assert_eq!(
        op_labeled.len(),
        1,
        "must have exactly 1 op_unverified_attestation labeled measurement"
    );
    assert!(
        op_labeled[0].tp >= 2,
        "op_unverified_attestation must have tp >= 2 (grew past n=1)"
    );
    assert!(
        op_labeled[0].recall >= op_labeled[0].recall_floor,
        "op_unverified_attestation recall must clear its floor"
    );

    // Verify op-layer held-out has no FP (real held-out benigns, not vacuous)
    let op_held_out: Vec<_> = held_out
        .iter()
        .filter(|m| m.detector == "op_unverified_attestation")
        .collect();
    assert!(
        !op_held_out.is_empty(),
        "op_unverified_attestation must have held-out measurements (real benigns)"
    );
    let op_fp: usize = op_held_out.iter().map(|m| m.fp).sum();
    assert_eq!(
        op_fp, 0,
        "op_unverified_attestation held-out must have 0 FP on real benigns"
    );

    // Verify op_control_plane_authority is measured with tp > 0
    let cp_labeled: Vec<_> = labeled
        .iter()
        .filter(|m| m.detector == "op_control_plane_authority")
        .collect();
    assert_eq!(
        cp_labeled.len(),
        1,
        "must have exactly 1 op_control_plane_authority labeled measurement"
    );
    assert!(
        cp_labeled[0].tp >= 2,
        "op_control_plane_authority must have tp >= 2 (grew past n=1)"
    );
    assert!(
        cp_labeled[0].recall >= cp_labeled[0].recall_floor,
        "op_control_plane_authority recall must clear its floor"
    );

    let cp_held_out: Vec<_> = held_out
        .iter()
        .filter(|m| m.detector == "op_control_plane_authority")
        .collect();
    assert!(
        !cp_held_out.is_empty(),
        "op_control_plane_authority must have held-out measurements (real benigns)"
    );
    let cp_fp: usize = cp_held_out.iter().map(|m| m.fp).sum();
    assert_eq!(
        cp_fp, 0,
        "op_control_plane_authority held-out must have 0 FP on real benigns"
    );

    // Verify op_fail_open_bootstrap is measured with tp > 0
    let fob_labeled: Vec<_> = labeled
        .iter()
        .filter(|m| m.detector == "op_fail_open_bootstrap")
        .collect();
    assert_eq!(
        fob_labeled.len(),
        1,
        "must have exactly 1 op_fail_open_bootstrap labeled measurement"
    );
    assert!(
        fob_labeled[0].tp >= 2,
        "op_fail_open_bootstrap must have tp >= 2 (grew past n=1)"
    );
    assert!(
        fob_labeled[0].recall >= fob_labeled[0].recall_floor,
        "op_fail_open_bootstrap recall must clear its floor"
    );

    let fob_held_out: Vec<_> = held_out
        .iter()
        .filter(|m| m.detector == "op_fail_open_bootstrap")
        .collect();
    assert!(
        !fob_held_out.is_empty(),
        "op_fail_open_bootstrap must have held-out measurements (real benigns)"
    );
    let fob_fp: usize = fob_held_out.iter().map(|m| m.fp).sum();
    assert_eq!(
        fob_fp, 0,
        "op_fail_open_bootstrap held-out must have 0 FP on real benigns"
    );

    // Verify op_silent_failover is measured with tp > 0
    let sf_labeled: Vec<_> = labeled
        .iter()
        .filter(|m| m.detector == "op_silent_failover")
        .collect();
    assert_eq!(
        sf_labeled.len(),
        1,
        "must have exactly 1 op_silent_failover labeled measurement"
    );
    assert!(
        sf_labeled[0].tp >= 2,
        "op_silent_failover must have tp >= 2 (grew past n=1)"
    );
    assert!(
        sf_labeled[0].recall >= sf_labeled[0].recall_floor,
        "op_silent_failover recall must clear its floor"
    );

    let sf_held_out: Vec<_> = held_out
        .iter()
        .filter(|m| m.detector == "op_silent_failover")
        .collect();
    assert!(
        !sf_held_out.is_empty(),
        "op_silent_failover must have held-out measurements (real benigns)"
    );
    let sf_fp: usize = sf_held_out.iter().map(|m| m.fp).sum();
    assert_eq!(
        sf_fp, 0,
        "op_silent_failover held-out must have 0 FP on real benigns"
    );
}

#[test]
fn test_gate_e2e_catches_recall_regression() {
    let measurements = measure_detectors_multi(&labeled_dirs(), &PathBuf::new());
    let labeled: Vec<_> = measurements
        .iter()
        .filter(|m| m.corpus_type == "labeled")
        .cloned()
        .collect();

    let modified_labeled: Vec<_> = labeled
        .iter()
        .map(|m| {
            if m.detector == "solana_access_control" {
                let mut m = m.clone();
                m.recall_floor = 0.99;
                m
            } else {
                m.clone()
            }
        })
        .collect();

    let report = evaluate_gate(&modified_labeled, &[]);

    assert!(
        !report.gate_passed,
        "gate should FAIL when recall_floor is artificially raised above actual recall"
    );
    assert!(
        !report.recall_violations.is_empty(),
        "should have recall violations for solana_access_control"
    );
}

#[test]
fn test_gate_e2e_real_pipeline_fp_detection() {
    let tmp = std::env::temp_dir().join(format!("digger-gate-fp-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);

    // Vulnerable case: state mutation, no authority check — real detector flags this
    let vuln_dir = tmp.join("vuln-case");
    std::fs::create_dir_all(&vuln_dir).unwrap();
    std::fs::write(
        vuln_dir.join("source.rs"),
        "use anchor_lang::prelude::*;\n\
#[program]\n\
pub mod vulnerable_program {\n\
    use super::*;\n\
    pub fn mint_tokens(ctx: Context<Mint>, amount: u64) -> Result<()> {\n\
        ctx.accounts.token.mint_authority = ctx.accounts.user.key();\n\
        ctx.accounts.token.amount += amount;\n\
        Ok(())\n\
    }\n\
}\n\
#[derive(Accounts)]\n\
pub struct Mint<'info> {\n\
    #[account(mut)]\n\
    pub token: Account<'info, TokenAccount>,\n\
    pub user: Signer<'info>,\n\
}\n\
#[account]\n\
pub struct TokenAccount { pub mint_authority: Pubkey, pub amount: u64 }\n",
    )
    .unwrap();
    std::fs::write(
        vuln_dir.join("meta.json"),
        r#"{"exploit_id": "fp-test", "vulnerability_class": "NEGATIVE", "expected_findings": [], "known_limitations": "NEGATIVE"}"#,
    )
    .unwrap();

    // Safe case 1: read-only
    let safe1 = tmp.join("safe-readonly");
    std::fs::create_dir_all(&safe1).unwrap();
    std::fs::write(
        safe1.join("source.rs"),
        "use anchor_lang::prelude::*;\n\
#[program]\n\
pub mod safe_prog {\n\
    use super::*;\n\
    pub fn get_data(ctx: Context<Get>) -> Result<u64> { Ok(ctx.accounts.vault.amount) }\n\
}\n\
#[derive(Accounts)]\n\
pub struct Get<'info> { pub vault: Account<'info, Vault> }\n\
#[account]\n\
pub struct Vault { pub amount: u64 }\n",
    )
    .unwrap();
    std::fs::write(
        safe1.join("meta.json"),
        r#"{"exploit_id": "TN-1", "vulnerability_class": "NEGATIVE", "expected_findings": [], "known_limitations": "NEGATIVE"}"#,
    )
    .unwrap();

    // Safe case 2: guarded
    let safe2 = tmp.join("safe-guarded");
    std::fs::create_dir_all(&safe2).unwrap();
    std::fs::write(
        safe2.join("source.rs"),
        "use anchor_lang::prelude::*;\n\
#[program]\n\
pub mod guarded {\n\
    use super::*;\n\
    pub fn deposit(ctx: Context<Dep>, amt: u64) -> Result<()> { require!(amt > 0, ErrorCode::Zero); Ok(()) }\n\
}\n\
#[derive(Accounts)]\n\
pub struct Dep<'info> { #[account(mut)] pub vault: Account<'info, V>, pub signer: Signer<'info> }\n\
#[account]\n\
pub struct V { pub amount: u64 }\n",
    )
    .unwrap();
    std::fs::write(
        safe2.join("meta.json"),
        r#"{"exploit_id": "TN-2", "vulnerability_class": "NEGATIVE", "expected_findings": [], "known_limitations": "NEGATIVE"}"#,
    )
    .unwrap();

    // Run real detectors — feed as held_out to exercise FP-check path
    let measurements = measure_detectors(&std::path::PathBuf::new(), &tmp);
    let access: Vec<_> = measurements
        .iter()
        .filter(|m| m.detector == "solana_access_control")
        .cloned()
        .collect();

    assert!(!access.is_empty(), "must have access_control measurement");
    assert!(
        access[0].fp > 0,
        "real detector must flag the vulnerable case"
    );

    // Gate must FAIL on real FP
    let gate = evaluate_gate(&[], &access);
    assert!(!gate.gate_passed, "gate must FAIL on real held-out FP");
    assert!(
        !gate.held_out_fp_violations.is_empty(),
        "must record the FP"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

fn all_corpus_dirs() -> Vec<PathBuf> {
    let root = workspace_root();
    vec![
        root.join("corpus/solana-account-model"),
        root.join("corpus/price-manipulation"),
        root.join("corpus/held-out-fp"),
        root.join("corpus/operational-layer"),
    ]
}

#[test]
fn test_corpus_integrity_no_orphan_or_unmapped_fixtures() {
    let mut checked = 0usize;
    let mut problems: Vec<String> = Vec::new();

    for corpus in all_corpus_dirs() {
        if !corpus.exists() {
            continue;
        }
        for entry in std::fs::read_dir(&corpus).unwrap().flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let meta_path = path.join("meta.json");

            let has_src = std::fs::read_dir(&path).unwrap().flatten().any(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| x == "rs" || x == "sol" || x == "ts")
                    .unwrap_or(false)
            });

            if meta_path.exists() && !has_src {
                problems.push(format!("{}: has meta.json but NO source file", name));
                continue;
            }
            if has_src && !meta_path.exists() {
                problems.push(format!(
                    "{}: has a source file but NO meta.json (orphan)",
                    name
                ));
                continue;
            }
            if !meta_path.exists() {
                continue;
            }

            let meta_str = std::fs::read_to_string(&meta_path).unwrap();
            let meta: serde_json::Value = match serde_json::from_str(&meta_str) {
                Ok(v) => v,
                Err(e) => {
                    problems.push(format!("{}: meta.json parse error: {}", name, e));
                    continue;
                }
            };

            let is_negative = meta
                .get("known_limitations")
                .and_then(|v| v.as_str())
                .map(|s| s.contains("NEGATIVE"))
                .or_else(|| {
                    meta.get("expected_findings")
                        .and_then(|v| v.as_array())
                        .map(|a| a.is_empty())
                })
                .unwrap_or(false);

            if is_negative {
                checked += 1;
                continue;
            }

            let findings = meta
                .get("expected_findings")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if findings.is_empty() {
                problems.push(format!(
                    "{}: positive case but expected_findings is empty",
                    name
                ));
                continue;
            }
            for f in &findings {
                if let Some(s) = f.as_str() {
                    if normalize_detector_id(s).is_none() {
                        problems.push(format!(
                            "{}: expected_finding {:?} maps to NO known detector",
                            name, s
                        ));
                    }
                }
            }
            if case_target_detectors(&meta).is_empty() {
                problems.push(format!(
                    "{}: positive maps to EMPTY detector target set (invisible to recall)",
                    name
                ));
            }
            checked += 1;
        }
    }

    assert!(checked > 0, "integrity scan must check >= 1 case");
    assert!(
        problems.is_empty(),
        "corpus integrity violations:\n  {}",
        problems.join("\n  ")
    );
}
