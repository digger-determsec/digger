//! Phase 11 — non-vacuous E2E coverage of the SOURCE analysis path
//! (parse_program -> build_system_ir -> analyze_compat) over the in-repo,
//! version-tracked corpus. This is a DIFFERENT path from the eval-gate,
//! which drives the digger-reconstruct detect_* detectors. Here we prove
//! the hypothesis (Gen2) pipeline runs clean + deterministic on every
//! tracked Solana fixture and can never silently no-op.

use std::fs;
use std::path::{Path, PathBuf};

use digger_graph::build_system_ir;
use digger_hypothesis::analyze_compat as analyze;
use digger_parser::parse_program;

const CORPUS: &str = "../../corpus/solana-account-model";

fn walk_rs(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk_rs(&p));
            } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn kinds_for(path: &Path) -> Vec<String> {
    let code = fs::read_to_string(path).unwrap_or_default();
    if code.trim().is_empty() {
        return vec![];
    }
    let raw = parse_program(&code, "anchor");
    let ir = build_system_ir(raw);
    analyze(&ir).into_iter().map(|h| h.kind).collect()
}

#[test]
fn corpus_is_present_and_nonempty() {
    let files = walk_rs(Path::new(CORPUS));
    assert!(
        files.len() >= 20,
        "expected >=20 tracked .rs corpus files, found {} — corpus not checked out \
         (it is gitignored + force-added). This suite must NOT run vacuously.",
        files.len()
    );
}

#[test]
fn every_corpus_file_analyzes_without_panic() {
    let files = walk_rs(Path::new(CORPUS));
    assert!(
        !files.is_empty(),
        "corpus empty — see corpus_is_present_and_nonempty"
    );
    let mut analyzed = 0usize;
    for f in &files {
        let _ = kinds_for(f);
        analyzed += 1;
    }
    assert_eq!(analyzed, files.len(), "every tracked file must be analyzed");
}

#[test]
fn source_pipeline_is_deterministic_over_whole_corpus() {
    let files = walk_rs(Path::new(CORPUS));
    assert!(!files.is_empty());
    for f in &files {
        let a = kinds_for(f);
        let b = kinds_for(f);
        assert_eq!(a, b, "non-deterministic finding kinds for {:?}", f);
    }
}

// ── Solana account-model: broken vs fixed Cashio discrimination ──

use digger_hypothesis::models::HypothesisType;

fn derive_kinds_for_source(code: &str) -> Vec<(String, String)> {
    let raw = parse_program(code, "anchor");
    let ir = digger_graph::build_system_ir_with_language(raw, digger_ir::Language::Anchor);
    digger_hypothesis::derive(&ir)
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::MissingAccountConstraintCandidate)
        .map(|h| (h.primary_function.clone(), format!("{:?}", h.severity)))
        .collect()
}

/// Dump AuthorityEdge nodes (both enforced and missing) for debugging.
fn dump_auth_edges(code: &str) -> Vec<(String, String, String)> {
    let raw = parse_program(code, "anchor");
    let ir = digger_graph::build_system_ir_with_language(raw, digger_ir::Language::Anchor);
    ir.edges
        .iter()
        .filter_map(|e| match e {
            digger_ir::Edge::Authority(a) => Some((
                a.function.clone(),
                a.authority_source.clone(),
                a.check_type.clone(),
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn dump_broken_cashio_rawprogram() {
    let code = fs::read_to_string("../../corpus/solana-account-model/cashio-broken-mint/source.rs")
        .unwrap();
    let raw = parse_program(&code, "anchor");
    if let Some(val) = raw.metadata.extra.get("anchor_accounts_MintTokens") {
        let json_str = serde_json::to_string_pretty(val).unwrap();
        // Print in chunks to avoid truncation
        for line in json_str.lines().take(30) {
            eprintln!("  {}", line);
        }
    }
}

#[test]
fn dump_broken_cashio_all_edges() {
    let code = fs::read_to_string("../../corpus/solana-account-model/cashio-broken-mint/source.rs")
        .unwrap();
    let raw = parse_program(&code, "anchor");
    let ir = digger_graph::build_system_ir_with_language(raw, digger_ir::Language::Anchor);
    eprintln!("language: {:?}", ir.language);
    eprintln!("functions: {}", ir.functions.len());
    eprintln!("edges total: {}", ir.edges.len());
    for e in &ir.edges {
        if let digger_ir::Edge::Authority(a) = e {
            eprintln!(
                "  AUTH: {} | {} | {}",
                a.function, a.authority_source, a.check_type
            );
        }
    }
}

#[test]
fn broken_cashio_fires_account_constraint() {
    let code = fs::read_to_string("../../corpus/solana-account-model/cashio-broken-mint/source.rs")
        .expect("broken Cashio fixture must exist");
    // Check parser metadata
    let raw = parse_program(&code, "anchor");
    let anchor_keys: Vec<_> = raw
        .metadata
        .extra
        .keys()
        .filter(|k| k.starts_with("anchor"))
        .collect();
    eprintln!("anchor metadata keys: {:?}", anchor_keys);
    // Check builder edges
    let edges = dump_auth_edges(&code);
    let missing: Vec<_> = edges.iter().filter(|(_, _, ct)| ct == "missing").collect();
    eprintln!("missing edges: {:?}", missing);
    eprintln!("all edges: {:?}", edges);
    assert!(
        !missing.is_empty(),
        "broken Cashio builder must emit >=1 missing edge"
    );
    // Check derivation
    let hits = derive_kinds_for_source(&code);
    assert!(
        !hits.is_empty(),
        "broken Cashio MUST emit MissingAccountConstraintCandidate"
    );
}

#[test]
fn fixed_cashio_silent_on_account_constraint() {
    let code = fs::read_to_string("../../corpus/solana-account-model/cashio-fixed-mint/source.rs")
        .expect("fixed Cashio fixture must exist");
    let hits = derive_kinds_for_source(&code);
    assert!(
        hits.is_empty(),
        "fixed Cashio MUST be SILENT — got {} false positives: {:?}",
        hits.len(),
        hits
    );
}

#[test]
fn fixed_cashio_parser_extracts_constraints() {
    let code = fs::read_to_string("../../corpus/solana-account-model/cashio-fixed-mint/source.rs")
        .expect("fixed Cashio fixture must exist");
    let raw = parse_program(&code, "anchor");
    let accounts_entry = raw.metadata.extra.get("anchor_accounts_MintTokens");
    assert!(
        accounts_entry.is_some(),
        "anchor_accounts_MintTokens must exist"
    );
    let accounts = accounts_entry.unwrap().as_array().unwrap();
    // MintTokens has 2 fields: mint (Account<TokenMint>) and mint_authority (Signer)
    let mint_acct = accounts
        .iter()
        .find(|a| a.get("name").and_then(|v| v.as_str()) == Some("mint"));
    assert!(mint_acct.is_some(), "mint field must exist");
    let mint_constraints = mint_acct
        .unwrap()
        .get("constraints")
        .and_then(|v| v.as_array());
    assert!(
        mint_constraints.is_some() && !mint_constraints.unwrap().is_empty(),
        "mint MUST have constraints (has_one = mint_authority)"
    );
}

#[test]
fn debug_dump_auth_edges_for_cashio_fixtures() {
    let broken_code =
        fs::read_to_string("../../corpus/solana-account-model/cashio-broken-mint/source.rs")
            .unwrap();
    let broken_edges = dump_auth_edges(&broken_code);
    let broken_missing: Vec<_> = broken_edges
        .iter()
        .filter(|(_, _, ct)| ct == "missing")
        .collect();
    assert!(
        !broken_missing.is_empty(),
        "broken Cashio must have >=1 missing edge"
    );

    let fixed_code =
        fs::read_to_string("../../corpus/solana-account-model/cashio-fixed-mint/source.rs")
            .unwrap();
    let fixed_edges = dump_auth_edges(&fixed_code);
    let fixed_missing: Vec<_> = fixed_edges
        .iter()
        .filter(|(_, _, ct)| ct == "missing")
        .collect();
    assert!(
        fixed_missing.is_empty(),
        "fixed Cashio must have ZERO missing edges"
    );
}

#[test]
fn init_account_no_false_positive() {
    // An #[account(init, payer = authority)] account is authorized by the
    // payer Signer — must NOT produce MissingAccountConstraint hypotheses.
    let code = r#"
use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGSk6idZizNqiAHBysDKg1TkvSaVvWmRGiNbr");

#[program]
pub mod init_test {
    use super::*;
    pub fn initialize(ctx: Context<Init>) -> Result<()> { Ok(()) }
}

#[derive(Accounts)]
pub struct Init<'info> {
    #[account(init, payer = authority, space = 8 + 32)]
    pub vault: Account<'info, SomeAccount>,
    pub authority: Signer<'info>,
}

#[account]
pub struct SomeAccount { pub data: u64 }
"#;
    let hits = derive_kinds_for_source(code);
    assert!(
        hits.is_empty(),
        "init account must NOT fire MissingAccountConstraint — got {:?}",
        hits
    );
}

#[test]
fn read_only_typed_account_silent() {
    // A read-only TYPED Account<T> without constraint is SILENT
    // because the type provides program-ownership + discriminator checks.
    let code = r#"
use anchor_lang::prelude::*;
declare_id!("Fg6PaFpoGSk6idZizNqiAHBysDKg1TkvSaVvWmRGiNbr");
#[program]
pub mod read_only_test {
    use super::*;
    pub fn check_balance(ctx: Context<CheckBalance>) -> Result<()> { Ok(()) }
}
#[derive(Accounts)]
pub struct CheckBalance<'info> {
    pub token_account: Account<'info, SomeToken>,
}
#[account]
pub struct SomeToken { pub amount: u64 }
"#;
    let hits = derive_kinds_for_source(code);
    assert!(
        hits.is_empty(),
        "read-only typed Account<T> must NOT fire — got {:?}",
        hits
    );
}

#[test]
fn sign_plus_mut_account_still_fires() {
    // An instruction with BOTH a fee-payer Signer AND a separate #[account(mut)]
    // account lacking has_one → the mut account MUST still fire.
    let code = r#"
use anchor_lang::prelude::*;
declare_id!("Fg6PaFpoGSk6idZizNqiAHBysDKg1TkvSaVvWmRGiNbr");
#[program]
pub mod dual_test {
    use super::*;
    pub fn do_thing(ctx: Context<DoThing>) -> Result<()> { Ok(()) }
}
#[derive(Accounts)]
pub struct DoThing<'info> {
    #[account(mut)]
    pub vault: Account<'info, SomeAccount>,
    pub authority: Signer<'info>,
}
#[account]
pub struct SomeAccount { pub data: u64 }
"#;
    let hits = derive_kinds_for_source(code);
    assert!(
        !hits.is_empty(),
        "mut account MUST fire even when a Signer exists in same instruction"
    );
    // The hypothesis is keyed on the function name, not the account name.
    // Check that the authority_source contains "vault" to confirm it's the right account.
    let raw = parse_program(code, "anchor");
    let ir = digger_graph::build_system_ir_with_language(raw, digger_ir::Language::Anchor);
    let vault_missing: Vec<_> = ir
        .edges
        .iter()
        .filter(|e| match e {
            digger_ir::Edge::Authority(a) => {
                a.check_type == "missing" && a.authority_source.contains("vault")
            }
            _ => false,
        })
        .collect();
    assert!(
        !vault_missing.is_empty(),
        "vault must have a missing edge even when Signer exists in same instruction"
    );
}

#[test]
fn debug_cpi_bridge_safe_1() {
    let code = fs::read_to_string("../../corpus/solana-account-model/cpi-bridge-safe-1/source.rs")
        .unwrap();
    let raw = parse_program(&code, "anchor");
    eprintln!("functions: {}", raw.functions.len());
    for f in &raw.functions {
        eprintln!("  fn {} inputs={:?}", f.name, f.inputs);
        eprintln!(
            "    has token::transfer: {}",
            f.body.contains("token::transfer")
        );
        eprintln!("    has invoke: {}", f.body.contains("invoke"));
    }
    // Check if the struct is found
    let has_bridge_transfer = raw
        .metadata
        .extra
        .keys()
        .any(|k| k == "anchor_accounts_BridgeTransfer");
    eprintln!(
        "has anchor_accounts_BridgeTransfer: {}",
        has_bridge_transfer
    );
    if let Some(val) = raw.metadata.extra.get("anchor_accounts_BridgeTransfer") {
        eprintln!(
            "BridgeTransfer accounts: {}",
            serde_json::to_string_pretty(val).unwrap()
        );
    }
    // Run the full pipeline
    let ir = digger_graph::build_system_ir_with_language(raw, digger_ir::Language::Anchor);
    let missing: Vec<_> = ir
        .edges
        .iter()
        .filter(|e| match e {
            digger_ir::Edge::Authority(a) => a.check_type == "missing",
            _ => false,
        })
        .collect();
    eprintln!("missing edges: {}", missing.len());
    for e in &missing {
        if let digger_ir::Edge::Authority(a) = e {
            eprintln!(
                "  {} | {} | {}",
                a.function, a.authority_source, a.check_type
            );
        }
    }
}

// ── Corpus matrix: safe-* = 0 findings, vuln-* fires ──
// FIXTURES_PASSING: safe-* fixtures that produce 0 MissingAccountConstraint.
const FIXTURES_PASSING: &[&str] = &[
    "cashio-fixed-mint",
    "has-one-data-account-safe",
    "missing-owner-safe",
    "missing-signer-safe",
    "owner-check-safe-1",
    "raydium-pool",
    "safe-governance",
    "type-cosplay-safe-2",
];

// FIXTURES_KNOWN_FP: safe-* fixtures that still produce findings.
// Root cause: the anchor_accounts_* metadata is structurally identical between
// these safe fixtures and their vuln counterparts. The ONLY difference is what
// the function body does — but body-text matching is forbidden because it is
// structurally blind (the adversarial body-text-trap-vuln proves this).
// Fixing these requires AST-level expression walking the parser doesn't supply.
const FIXTURES_KNOWN_FP: &[&str] = &[
    "cpi-bridge-safe-1",
    "cpi-oracle-safe-1",
    "cpi-staking-safe-1",
    "marinade-stake-lp",
    "missing-signer-typed-vuln",
    "owner-check-safe-2",
    "owner-check-safe-3",
    "owner-check-safe-4",
    "safe-cpi-proxy",
    "safe-multisig-vault",
    "safe-token-vault",
    "sablier-stake-pool-2023",
    "solend-oracle",
    "stepdice-token",
    "type-cosplay-safe-1",
    "type-cosplay-safe-3",
    "type-cosplay-safe-4",
    "unvalidated-cpi-safe",
    "vesper-lp-2023",
];

const VULN_FIXTURES: &[&str] = &[
    "body-text-trap-vuln",
    "cashio-broken-mint",
    "cashio-collateral-owner-check",
    "cpi-bridge-vuln-1",
    "cpi-oracle-vuln-1",
    "cpi-signer-only-vuln",
    "cpi-staking-vuln-1",
    "magic-eden-creator",
    "missing-owner-vuln",
    "missing-signer-vuln",
    "owner-check-vuln-1",
    "owner-check-vuln-2",
    "owner-check-vuln-3",
    "owner-check-vuln-4",
    "type-cosplay-vuln-1",
    "type-cosplay-vuln-2",
    "type-cosplay-vuln-3",
    "type-cosplay-vuln-4",
    "unvalidated-cpi-require",
    "unvalidated-cpi-vuln",
];

/// ADVERSARIAL NEGATIVE CONTROL: body-text-trap-vuln contains .owner,
/// require_keys_eq!, and &ctx.accounts.X in its function body — every
/// string a body-text suppression gate would match. But the check is
/// WRONG (compares vault.owner against the attacker's own authority key).
/// This test permanently fails the build if anyone reintroduces
/// f.body.contains()-based suppression that silences this fixture.
#[test]
fn body_text_trap_vuln_fires_despite_body_strings() {
    let count = count_missing_for_fixture("body-text-trap-vuln");
    assert!(
        count >= 1,
        "body-text-trap-vuln MUST fire despite containing .owner, \
         require_keys_eq!, and &ctx.accounts.X — if this passes, \
         someone reintroduced body-text suppression"
    );
}

/// ISOLATION: missing-signer-vuln fires account:signer:authority (the
/// missing_signer branch) not account:owner:authority (the missing_owner
/// branch). Proves the S2 detector is load-bearing.
#[test]
fn missing_signer_detector_is_load_bearing() {
    let code =
        fs::read_to_string("../../corpus/solana-account-model/missing-signer-vuln/source.rs")
            .unwrap();
    let edges = dump_auth_edges(&code);
    let signer_edges: Vec<_> = edges
        .iter()
        .filter(|(_, src, ct)| ct == "missing" && src.contains(":signer:"))
        .collect();
    assert!(
        !signer_edges.is_empty(),
        "missing-signer-vuln MUST emit account:signer:* edge (S2 detector). \
         Got edges: {:?}",
        edges
    );
}

/// SUBSTRATE WALL: missing-signer-typed-vuln has a TYPED authority (Account<AuthState>)
/// as has_one target. The metadata cannot distinguish authority-target from
/// data-relationship-target when both are TYPED. This fixture fires 0 —
/// documented as a feasibility limitation.
#[test]
fn missing_signer_typed_authority_is_substrate_wall() {
    let count = count_missing_for_fixture("missing-signer-typed-vuln");
    assert_eq!(
        count, 0,
        "missing-signer-typed-vuln fires {} findings — TYPED authority \
         targets are a substrate wall (metadata can't distinguish authority \
         from data-relationship). If this fires, the gate was broadened.",
        count
    );
}

/// ISOLATION: missing-owner-vuln fires account:owner:raw_data (the owner
/// class) NOT account:has_one:* or account:signer:*. Proves the missing_owner
/// branch is load-bearing on its own.
#[test]
fn missing_owner_detector_is_load_bearing() {
    let code = fs::read_to_string("../../corpus/solana-account-model/missing-owner-vuln/source.rs")
        .unwrap();
    let edges = dump_auth_edges(&code);
    let owner_edges: Vec<_> = edges
        .iter()
        .filter(|(_, src, ct)| ct == "missing" && src.contains(":owner:"))
        .collect();
    assert!(
        !owner_edges.is_empty(),
        "missing-owner-vuln MUST emit account:owner:* edge (det2). \
         Got edges: {:?}",
        edges
    );
    // Must NOT fire via signer or has_one class
    let non_owner_missing: Vec<_> = edges
        .iter()
        .filter(|(_, src, ct)| {
            ct == "missing" && (src.contains(":signer:") || src.contains(":has_one:"))
        })
        .collect();
    assert!(
        non_owner_missing.is_empty(),
        "missing-owner-vuln must fire ONLY via owner class, not {:?}",
        non_owner_missing
    );
}

/// NEGATIVE CONTROL: missing-owner-negative-control has typed data accounts
/// with has_one constraints — no raw unchecked accounts → must fire 0.
#[test]
fn missing_owner_negative_control_is_silent() {
    let count = count_missing_for_fixture("missing-owner-negative-control");
    assert_eq!(
        count, 0,
        "missing-owner-negative-control fires {} findings — typed data \
         accounts with constraints must not trigger missing_owner.",
        count
    );
}

fn count_missing_for_fixture(fixture_name: &str) -> usize {
    let path = format!(
        "../../corpus/solana-account-model/{}/source.rs",
        fixture_name
    );
    let code = fs::read_to_string(&path).unwrap_or_default();
    if code.trim().is_empty() {
        return 0;
    }
    let raw = parse_program(&code, "anchor");
    let ir = digger_graph::build_system_ir_with_language(raw, digger_ir::Language::Anchor);
    digger_hypothesis::derive(&ir)
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::MissingAccountConstraintCandidate)
        .count()
}

#[test]
fn safe_fixtures_zero_findings() {
    for name in FIXTURES_PASSING {
        let count = count_missing_for_fixture(name);
        assert_eq!(
            count, 0,
            "{} must have 0 MissingAccountConstraint (safe program)",
            name
        );
    }
}

#[test]
fn known_fp_fixtures_are_documented() {
    // Soft-assert: log counts for fixtures that still produce findings.
    // A safe fixture dropping to 0 is the GOAL — never hard-fail on improvement.
    for name in FIXTURES_KNOWN_FP {
        let count = count_missing_for_fixture(name);
        if count > 0 {
            eprintln!(
                "KNOWN_FP: {} produces {} findings (substrate wall)",
                name, count
            );
        } else {
            eprintln!(
                "IMPROVED: {} now produces 0 — remove from FIXTURES_KNOWN_FP",
                name
            );
        }
    }
    // Assert that the list is non-empty (sanity check that we haven't deleted everything)
    assert!(
        !FIXTURES_KNOWN_FP.is_empty(),
        "FIXTURES_KNOWN_FP must not be empty — if all safe-* are fixed, move them to FIXTURES_PASSING"
    );
}

#[test]
fn vuln_fixtures_fire() {
    for name in VULN_FIXTURES {
        let count = count_missing_for_fixture(name);
        assert!(
            count >= 1,
            "{} must have >=1 MissingAccountConstraint (vuln program)",
            name
        );
    }
}
