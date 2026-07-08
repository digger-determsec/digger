use crate::types::*;
use std::fs;
use std::io::Read;
use std::path::Path;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".cache",
    ".cargo",
    ".mypy_cache",
    ".pytest_cache",
    "venv",
    ".venv",
];

const EVM_EXTENSIONS: &[&str] = &["sol"];
const SOLANA_EXTENSIONS: &[&str] = &["rs", "toml"];

/// Scan a repository and produce a repo intelligence map.
pub fn scan_repo(input: RepoIntelligenceInput) -> anyhow::Result<RepoIntelligenceMap> {
    if !input.root.exists() {
        return Err(anyhow::anyhow!(
            "Path does not exist: {}",
            input.root.display()
        ));
    }

    let mut surfaces = Vec::new();
    let mut unknowns = Vec::new();
    let mut surface_id = 0usize;

    walk_dir(
        &input.root,
        &input.root,
        input.chain,
        &mut surfaces,
        &mut unknowns,
        &mut surface_id,
    );

    surfaces.sort_by(|a, b| a.path.cmp(&b.path).then(a.id.cmp(&b.id)));

    let summary = RepoIntelligenceSummary {
        surface_count: surfaces.len(),
        unknown_count: unknowns.len(),
    };

    Ok(RepoIntelligenceMap {
        schema_version: "digger.repo_intelligence.v1".into(),
        digger_version: env!("CARGO_PKG_VERSION").into(),
        report_kind: "repo_intelligence".into(),
        chain: input.chain.as_str().into(),
        generated_from: GeneratedFrom {
            mode: "read_only_static_inventory".into(),
        },
        surfaces,
        unknowns,
        summary,
    })
}

fn walk_dir(
    root: &Path,
    current: &Path,
    chain: Chain,
    surfaces: &mut Vec<SurfaceNode>,
    unknowns: &mut Vec<UnknownItem>,
    id_counter: &mut usize,
) {
    let entries = match fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if SKIP_DIRS.contains(&name_str.as_ref()) {
            continue;
        }

        if path.is_dir() {
            walk_dir(root, &path, chain, surfaces, unknowns, id_counter);
            continue;
        }

        let rel = relative_path(root, &path);
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match chain {
            Chain::Evm => {
                if EVM_EXTENSIONS.contains(&ext) {
                    scan_evm_file(&path, &rel, surfaces, unknowns, id_counter);
                }
            }
            Chain::Solana => {
                if SOLANA_EXTENSIONS.contains(&ext) || name_str == "Anchor.toml" {
                    scan_solana_file(&path, &rel, surfaces, unknowns, id_counter);
                }
            }
        }
    }
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn read_file_safe(path: &Path) -> Option<String> {
    let mut content = String::new();
    let mut file = fs::File::open(path).ok()?;
    file.read_to_string(&mut content).ok()?;
    Some(content)
}

fn scan_evm_file(
    path: &Path,
    rel: &str,
    surfaces: &mut Vec<SurfaceNode>,
    unknowns: &mut Vec<UnknownItem>,
    id_counter: &mut usize,
) {
    let content = match read_file_safe(path) {
        Some(c) => c,
        None => {
            unknowns.push(UnknownItem {
                path: rel.to_string(),
                reason: "unreadable file".into(),
            });
            return;
        }
    };

    let lower = content.to_lowercase();

    // Contract/interface/library declarations
    for line in content.lines() {
        let trimmed = line.trim();
        let lower_trimmed = trimmed.to_lowercase();
        if lower_trimmed.starts_with("contract ")
            || lower_trimmed.starts_with("interface ")
            || lower_trimmed.starts_with("library ")
        {
            let name = trimmed
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .trim_matches('{')
                .to_string();
            if !name.is_empty() {
                surfaces.push(make_surface(
                    id_counter,
                    rel,
                    "evm",
                    "entrypoint",
                    &name,
                    "contract_declaration",
                    "high",
                ));
            }
        }
    }

    // Function detection
    for line in content.lines() {
        let trimmed = line.trim();
        let lower_trimmed = trimmed.to_lowercase();
        if lower_trimmed.contains("function ") && trimmed.contains('(') {
            let cat = classify_evm_function(trimmed, &lower, &lower_trimmed);
            let name = extract_function_name(trimmed);
            if !name.is_empty() {
                surfaces.push(make_surface(
                    id_counter, rel, "evm", &cat, &name, "function", "medium",
                ));
            }
        }
    }

    // Test/fuzz detection by path
    if rel.contains("test") || rel.contains("fuzz") || rel.contains("invariant") {
        surfaces.push(make_surface(
            id_counter,
            rel,
            "evm",
            "test_or_fuzz_harness",
            &path.file_stem().unwrap_or_default().to_string_lossy(),
            "test_file",
            "high",
        ));
    }

    // Config detection
    let fname = path.file_name().unwrap_or_default().to_string_lossy();
    if fname == "foundry.toml"
        || fname == "hardhat.config.js"
        || fname == "hardhat.config.ts"
        || fname == "remappings.txt"
    {
        surfaces.push(make_surface(
            id_counter,
            rel,
            "evm",
            "config_or_deployment",
            &fname,
            "config_file",
            "high",
        ));
    }
}

fn classify_evm_function(_line: &str, _full_lower: &str, line_lower: &str) -> String {
    if line_lower.contains("payable")
        || line_lower.contains("transfer(")
        || line_lower.contains(".call{")
        || line_lower.contains("msg.value")
    {
        "value_transfer".into()
    } else if line_lower.contains("onlyowner")
        || line_lower.contains("onlyadmin")
        || line_lower.contains("onlygovernor")
        || line_lower.contains("onlyrole")
    {
        "privileged_operation".into()
    } else if line_lower.contains("oracle")
        || line_lower.contains("price")
        || line_lower.contains("feed")
        || line_lower.contains("chainlink")
    {
        "oracle_or_external_data".into()
    } else if line_lower.contains("delegatecall")
        || line_lower.contains(".call(")
        || line_lower.contains(".staticcall(")
    {
        "external_call".into()
    } else if line_lower.contains("mapping(")
        || line_lower.contains("=>")
        || line_lower.contains("storage")
    {
        "state_mutation".into()
    } else if line_lower.contains("onlyowner")
        || line_lower.contains("require(msg.sender")
        || line_lower.contains("require(signer")
    {
        "authorization_or_access_control".into()
    } else {
        "entrypoint".into()
    }
}

fn extract_function_name(line: &str) -> String {
    if let Some(pos) = line.find("function ") {
        let after = &line[pos + 9..];
        after.split('(').next().unwrap_or("").trim().to_string()
    } else {
        String::new()
    }
}

fn scan_solana_file(
    path: &Path,
    rel: &str,
    surfaces: &mut Vec<SurfaceNode>,
    unknowns: &mut Vec<UnknownItem>,
    id_counter: &mut usize,
) {
    let content = match read_file_safe(path) {
        Some(c) => c,
        None => {
            unknowns.push(UnknownItem {
                path: rel.to_string(),
                reason: "unreadable file".into(),
            });
            return;
        }
    };

    let lower = content.to_lowercase();

    // Anchor program detection
    if lower.contains("#[program]") {
        surfaces.push(make_surface(
            id_counter,
            rel,
            "solana",
            "entrypoint",
            &path.file_stem().unwrap_or_default().to_string_lossy(),
            "program_entry",
            "high",
        ));
    }

    // Account struct detection
    if lower.contains("#[derive(Accounts)]") || lower.contains("derive(accounts)") {
        surfaces.push(make_surface(
            id_counter,
            rel,
            "solana",
            "state_mutation",
            "AccountStruct",
            "account_struct",
            "high",
        ));
    }

    // CPI detection
    if lower.contains("invoke_signed") || lower.contains("cpicontext") || lower.contains("invoke(")
    {
        surfaces.push(make_surface(
            id_counter,
            rel,
            "solana",
            "external_call",
            "CPI",
            "cpi_call",
            "high",
        ));
    }

    // Authority/signer detection
    if lower.contains("signer") || lower.contains("has_one") || lower.contains("constraint") {
        surfaces.push(make_surface(
            id_counter,
            rel,
            "solana",
            "authorization_or_access_control",
            "AuthorityCheck",
            "authority_pattern",
            "medium",
        ));
    }

    // Oracle detection
    if lower.contains("oracle") || lower.contains("pyth") || lower.contains("switchboard") {
        surfaces.push(make_surface(
            id_counter,
            rel,
            "solana",
            "oracle_or_external_data",
            "Oracle",
            "oracle_pattern",
            "medium",
        ));
    }

    // Test/fuzz detection
    if rel.contains("test") || rel.contains("fuzz") {
        surfaces.push(make_surface(
            id_counter,
            rel,
            "solana",
            "test_or_fuzz_harness",
            &path.file_stem().unwrap_or_default().to_string_lossy(),
            "test_file",
            "high",
        ));
    }

    // Config detection
    let fname = path.file_name().unwrap_or_default().to_string_lossy();
    if fname == "Anchor.toml" || fname == "Cargo.toml" {
        surfaces.push(make_surface(
            id_counter,
            rel,
            "solana",
            "config_or_deployment",
            &fname,
            "config_file",
            "high",
        ));
    }
}

fn make_surface(
    id_counter: &mut usize,
    path: &str,
    chain: &str,
    category: &str,
    name: &str,
    kind: &str,
    confidence: &str,
) -> SurfaceNode {
    let id = format!("s-{}", id_counter);
    *id_counter += 1;
    SurfaceNode {
        id,
        path: path.to_string(),
        chain: chain.to_string(),
        category: category.to_string(),
        name: name.to_string(),
        kind: kind.to_string(),
        evidence: vec![EvidencePointer {
            path: path.to_string(),
            line_start: None,
            line_end: None,
            excerpt: None,
            reason: "Detected by static inventory scan".into(),
        }],
        confidence: ConfidenceLevel {
            inventory: confidence.to_string(),
            classification: "medium".into(),
        },
    }
}
