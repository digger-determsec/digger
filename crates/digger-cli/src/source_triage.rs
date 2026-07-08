use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSurface {
    pub name: String,
    pub path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub kind: String,
    pub visibility: Option<String>,
    pub is_payable: bool,
    pub has_auth_signal: bool,
    pub auth_signals: Vec<String>,
    pub has_state_mutation: bool,
    pub mutation_signals: Vec<String>,
    pub has_external_call: bool,
    pub external_call_signals: Vec<String>,
    pub has_cpi: bool,
    pub cpi_signals: Vec<String>,
    pub context_type: Option<String>,
    pub account_struct: Option<String>,
    pub source_snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStructInfo {
    pub name: String,
    pub path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub fields: Vec<AccountField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountField {
    pub name: String,
    pub field_type: String,
    pub is_signer: bool,
    pub is_mutable: bool,
    pub has_constraint: bool,
    pub constraint_signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingEvidence {
    pub evidence_id: String,
    pub description: String,
    pub category: String,
    pub affected_component: String,
    pub source_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceTriageResult {
    pub chain: String,
    pub files_scanned: usize,
    pub functions: Vec<FunctionSurface>,
    pub account_structs: Vec<AccountStructInfo>,
    pub missing_evidence: Vec<MissingEvidence>,
    pub limitations: Vec<String>,
}

pub fn triage_source_files(root: &Path, chain: &str) -> SourceTriageResult {
    let mut functions = Vec::new();
    let mut account_structs = Vec::new();
    let mut files_scanned = 0;
    let mut limitations = Vec::new();

    match chain {
        "evm" => {
            collect_evm_functions(root, root, &mut functions, &mut files_scanned);
        }
        "solana" => {
            collect_solana_files(
                root,
                root,
                &mut functions,
                &mut account_structs,
                &mut files_scanned,
            );
        }
        _ => {
            limitations.push(format!(
                "Source triage not implemented for chain '{}'",
                chain
            ));
        }
    }

    let missing_evidence = generate_missing_evidence(&functions, &account_structs, chain);

    if functions.is_empty() {
        limitations.push("No function-level surfaces detected by source triage".into());
    }

    limitations.push(
        "Source triage uses conservative text heuristics. No AST parsing, no compilation, no execution."
            .into(),
    );

    SourceTriageResult {
        chain: chain.to_string(),
        files_scanned,
        functions,
        account_structs,
        missing_evidence,
        limitations,
    }
}

fn generate_missing_evidence(
    functions: &[FunctionSurface],
    account_structs: &[AccountStructInfo],
    chain: &str,
) -> Vec<MissingEvidence> {
    let mut evidence = Vec::new();
    let mut id_counter = 0;

    for func in functions {
        id_counter += 1;
        let source_ref = format!("{}:L{}-L{}", func.path, func.line_start, func.line_end);

        if func.has_auth_signal {
            evidence.push(MissingEvidence {
                evidence_id: format!("me-auth-{}", id_counter),
                description: format!(
                    "Authority/modifier enforcement evidence needs review for {} `{}` at {}",
                    func.kind, func.name, source_ref
                ),
                category: "authority_verification".into(),
                affected_component: func.name.clone(),
                source_ref: Some(source_ref.clone()),
            });
        }

        if func.has_state_mutation && func.has_external_call {
            evidence.push(MissingEvidence {
                evidence_id: format!("me-cei-{}", id_counter),
                description: format!(
                    "CEI ordering and reentrancy evidence missing for {} `{}` at {} — external call and state mutation signals both present",
                    func.kind, func.name, source_ref
                ),
                category: "reentrancy_cei".into(),
                affected_component: func.name.clone(),
                source_ref: Some(source_ref.clone()),
            });
        }

        if func.has_external_call {
            evidence.push(MissingEvidence {
                evidence_id: format!("me-call-{}", id_counter),
                description: format!(
                    "External call target and failure-handling evidence missing for {} `{}` at {}",
                    func.kind, func.name, source_ref
                ),
                category: "external_call_target".into(),
                affected_component: func.name.clone(),
                source_ref: Some(source_ref.clone()),
            });
        }

        if func.has_cpi {
            evidence.push(MissingEvidence {
                evidence_id: format!("me-cpi-{}", id_counter),
                description: format!(
                    "CPI target/account validation evidence missing for {} `{}` at {}",
                    func.kind, func.name, source_ref
                ),
                category: "cpi_validation".into(),
                affected_component: func.name.clone(),
                source_ref: Some(source_ref.clone()),
            });
        }

        if chain == "solana" && func.has_state_mutation {
            evidence.push(MissingEvidence {
                evidence_id: format!("me-acc-{}", id_counter),
                description: format!(
                    "Operation-level authority-to-account mapping not proven for instruction `{}` at {}",
                    func.name, source_ref
                ),
                category: "authority_account_mapping".into(),
                affected_component: func.name.clone(),
                source_ref: Some(source_ref),
            });
        }
    }

    for acct in account_structs {
        id_counter += 1;
        let source_ref = format!("{}:L{}-L{}", acct.path, acct.line_start, acct.line_end);

        for field in &acct.fields {
            if field.is_signer {
                evidence.push(MissingEvidence {
                    evidence_id: format!("me-signer-{}", id_counter),
                    description: format!(
                        "Verify signer `{}` in account struct `{}` protects the intended operation at {}",
                        field.name, acct.name, source_ref
                    ),
                    category: "signer_account_binding".into(),
                    affected_component: format!("{}.{}", acct.name, field.name),
                    source_ref: Some(source_ref.clone()),
                });
            }

            if field.is_mutable && !field.has_constraint {
                evidence.push(MissingEvidence {
                    evidence_id: format!("me-mut-{}", id_counter),
                    description: format!(
                        "Mutable field `{}` in `{}` lacks constraint verification at {}",
                        field.name, acct.name, source_ref
                    ),
                    category: "mutable_account_constraint".into(),
                    affected_component: format!("{}.{}", acct.name, field.name),
                    source_ref: Some(source_ref.clone()),
                });
            }

            if field.has_constraint {
                evidence.push(MissingEvidence {
                    evidence_id: format!("me-constraint-{}", id_counter),
                    description: format!(
                        "Constraint enforcement for field `{}` in `{}` needs verification at {}",
                        field.name, acct.name, source_ref
                    ),
                    category: "constraint_verification".into(),
                    affected_component: format!("{}.{}", acct.name, field.name),
                    source_ref: Some(source_ref.clone()),
                });
            }
        }
    }

    evidence
}

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
    "venv",
    ".venv",
];

fn collect_evm_functions(
    dir: &Path,
    root: &Path,
    functions: &mut Vec<FunctionSurface>,
    files_scanned: &mut usize,
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            collect_evm_functions(&path, root, functions, files_scanned);
        } else if path.extension().and_then(|e| e.to_str()) == Some("sol") {
            if let Ok(content) = fs::read_to_string(&path) {
                *files_scanned += 1;
                let rel = rel_path(&path, root);
                parse_solidity_functions(&content, &rel, functions);
            }
        }
    }
}

fn collect_solana_files(
    dir: &Path,
    root: &Path,
    functions: &mut Vec<FunctionSurface>,
    account_structs: &mut Vec<AccountStructInfo>,
    files_scanned: &mut usize,
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            collect_solana_files(&path, root, functions, account_structs, files_scanned);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(content) = fs::read_to_string(&path) {
                *files_scanned += 1;
                let rel = rel_path(&path, root);
                parse_solana_file(&content, &rel, functions, account_structs);
            }
        }
    }
}

fn rel_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
        .replace('\\', "/")
}

fn parse_solidity_functions(content: &str, rel_path: &str, functions: &mut Vec<FunctionSurface>) {
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    let mut brace_depth = 0;
    let mut in_function = false;
    let mut func_start = 0;
    let mut func_name = String::new();
    let mut func_visibility = String::new();
    let mut func_payable = false;
    let mut func_auth_signals = Vec::new();
    let mut func_mutation_signals = Vec::new();
    let mut func_call_signals = Vec::new();

    while i < lines.len() {
        let line = lines[i].trim();

        if !in_function {
            if line.contains("function ") {
                let mut decl_lines = Vec::new();
                let mut j = i;
                while j < lines.len() {
                    decl_lines.push(lines[j]);
                    if lines[j].contains('{') {
                        break;
                    }
                    j += 1;
                }
                let full_decl = decl_lines.join(" ");
                let (name, vis, payable) = parse_function_signature(&full_decl);
                if !name.is_empty() {
                    in_function = true;
                    func_start = i + 1;
                    func_name = name;
                    func_visibility = vis;
                    func_payable = payable;
                    func_auth_signals = Vec::new();
                    func_mutation_signals = Vec::new();
                    func_call_signals = Vec::new();
                    brace_depth = 0;
                    for dl in &decl_lines {
                        check_evm_auth_signals(dl.trim(), &mut func_auth_signals);
                    }
                    if lines[i].contains('{') {
                        brace_depth += lines[i].matches('{').count() as i32
                            - lines[i].matches('}').count() as i32;
                        if brace_depth <= 0 {
                            let snippet = lines
                                .get(func_start - 1..=(func_start).min(lines.len() - 1))
                                .map(|l| l.join("\n"));
                            functions.push(FunctionSurface {
                                name: func_name.clone(),
                                path: rel_path.to_string(),
                                line_start: func_start,
                                line_end: i + 1,
                                kind: "function".into(),
                                visibility: Some(func_visibility.clone()),
                                is_payable: func_payable,
                                has_auth_signal: !func_auth_signals.is_empty(),
                                auth_signals: func_auth_signals.clone(),
                                has_state_mutation: false,
                                mutation_signals: Vec::new(),
                                has_external_call: false,
                                external_call_signals: Vec::new(),
                                has_cpi: false,
                                cpi_signals: Vec::new(),
                                context_type: None,
                                account_struct: None,
                                source_snippet: snippet,
                            });
                            in_function = false;
                        }
                    }
                }
            }
        } else {
            if line.contains('{') {
                brace_depth += line.matches('{').count() as i32;
            }
            if line.contains('}') {
                brace_depth -= line.matches('}').count() as i32;
            }

            check_evm_auth_signals(line, &mut func_auth_signals);
            check_evm_mutation_signals(line, &mut func_mutation_signals);
            check_evm_call_signals(line, &mut func_call_signals);

            if brace_depth <= 0 {
                let snippet = lines
                    .get(func_start - 1..=i.min(lines.len() - 1))
                    .map(|l| l.join("\n"));
                functions.push(FunctionSurface {
                    name: func_name.clone(),
                    path: rel_path.to_string(),
                    line_start: func_start,
                    line_end: i + 1,
                    kind: "function".into(),
                    visibility: Some(func_visibility.clone()),
                    is_payable: func_payable,
                    has_auth_signal: !func_auth_signals.is_empty(),
                    auth_signals: func_auth_signals.clone(),
                    has_state_mutation: !func_mutation_signals.is_empty(),
                    mutation_signals: func_mutation_signals.clone(),
                    has_external_call: !func_call_signals.is_empty(),
                    external_call_signals: func_call_signals.clone(),
                    has_cpi: false,
                    cpi_signals: Vec::new(),
                    context_type: None,
                    account_struct: None,
                    source_snippet: snippet,
                });
                in_function = false;
            }
        }
        i += 1;
    }
}

fn parse_function_signature(line: &str) -> (String, String, bool) {
    let mut name = String::new();
    let mut payable = false;

    if let Some(rest) = line.strip_prefix("function ") {
        let rest = rest.trim_start();
        if let Some(paren_idx) = rest.find('(') {
            name = rest[..paren_idx].trim().to_string();
        }
    } else if let Some(idx) = line.find("function ") {
        let rest = line[idx + 9..].trim_start();
        if let Some(paren_idx) = rest.find('(') {
            name = rest[..paren_idx].trim().to_string();
        }
    }

    let vis = if line.contains("public") {
        "public".to_string()
    } else if line.contains("external") {
        "external".to_string()
    } else if line.contains("internal") {
        "internal".to_string()
    } else if line.contains("private") {
        "private".to_string()
    } else {
        "unknown".to_string()
    };

    if line.contains("payable") {
        payable = true;
    }

    (name, vis, payable)
}

fn check_evm_auth_signals(line: &str, signals: &mut Vec<String>) {
    let checks = [
        ("onlyOwner", "onlyOwner modifier"),
        ("onlyAdmin", "onlyAdmin modifier"),
        ("onlyRole", "onlyRole modifier"),
        ("hasRole", "hasRole check"),
        ("AccessControl", "AccessControl pattern"),
        ("governance", "governance reference"),
        ("upgrade", "upgrade reference"),
        ("whenNotPaused", "whenNotPaused guard"),
        ("whenPaused", "whenPaused guard"),
        ("pause", "pause reference"),
        ("unpause", "unpause reference"),
        ("guardian", "guardian reference"),
        ("authority", "authority reference"),
        ("require(msg.sender", "msg.sender require"),
        ("msg.sender ==", "msg.sender comparison"),
    ];
    for (pattern, desc) in checks {
        if line.contains(pattern) && !signals.contains(&desc.to_string()) {
            signals.push(desc.into());
        }
    }
}

fn check_evm_mutation_signals(line: &str, signals: &mut Vec<String>) {
    let trimmed = line.trim();
    if (trimmed.contains("= ")
        || trimmed.ends_with('=')
        || trimmed.contains("+= ")
        || trimmed.contains("-= ")
        || trimmed.contains("++")
        || trimmed.contains("--"))
        && !trimmed.starts_with("//")
        && !trimmed.starts_with("*")
        && !signals.contains(&"state_assignment".to_string())
    {
        signals.push("state_assignment".into());
    }
    if (trimmed.contains("balances[")
        || trimmed.contains("allowances[")
        || trimmed.contains("[msg.sender]"))
        && !signals.contains(&"mapping_write".to_string())
    {
        signals.push("mapping_write".into());
    }
    if (trimmed.starts_with("emit ") || trimmed.contains(" emit "))
        && !signals.contains(&"event_emission".to_string())
    {
        signals.push("event_emission".into());
    }
}

fn check_evm_call_signals(line: &str, signals: &mut Vec<String>) {
    let checks = [
        (".call{", "low_level_call"),
        (".call(", "low_level_call"),
        (".delegatecall(", "delegatecall"),
        (".staticcall(", "staticcall"),
        (".transfer(", "value_transfer"),
        (".send(", "value_send"),
        ("transferFrom", "token_transferFrom"),
        ("transfer(", "token_transfer"),
    ];
    for (pattern, desc) in checks {
        if line.contains(pattern) && !signals.contains(&desc.to_string()) {
            signals.push(desc.into());
        }
    }
}

fn parse_solana_file(
    content: &str,
    rel_path: &str,
    functions: &mut Vec<FunctionSurface>,
    account_structs: &mut Vec<AccountStructInfo>,
) {
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    let mut brace_depth = 0;
    let mut in_function = false;
    let mut func_start = 0;
    let mut func_name = String::new();
    let mut func_auth_signals = Vec::new();
    let mut func_mutation_signals = Vec::new();
    let mut func_cpi_signals = Vec::new();

    while i < lines.len() {
        let line = lines[i].trim();

        if !in_function {
            if line.starts_with("pub fn ") || line.contains("pub fn ") {
                if let Some(name) = extract_fn_name(line) {
                    in_function = true;
                    func_start = i + 1;
                    func_name = name;
                    func_auth_signals = Vec::new();
                    func_mutation_signals = Vec::new();
                    func_cpi_signals = Vec::new();
                    brace_depth = 0;
                    check_solana_auth_signals(line, &mut func_auth_signals);
                    if line.contains('{') {
                        brace_depth +=
                            line.matches('{').count() as i32 - line.matches('}').count() as i32;
                        if brace_depth <= 0 {
                            let snippet = lines
                                .get(func_start - 1..=(func_start).min(lines.len() - 1))
                                .map(|l| l.join("\n"));
                            functions.push(FunctionSurface {
                                name: func_name.clone(),
                                path: rel_path.to_string(),
                                line_start: func_start,
                                line_end: i + 1,
                                kind: "instruction".into(),
                                visibility: Some("public".into()),
                                is_payable: false,
                                has_auth_signal: false,
                                auth_signals: Vec::new(),
                                has_state_mutation: false,
                                mutation_signals: Vec::new(),
                                has_external_call: false,
                                external_call_signals: Vec::new(),
                                has_cpi: false,
                                cpi_signals: Vec::new(),
                                context_type: extract_ctx_type(line),
                                account_struct: None,
                                source_snippet: snippet,
                            });
                            in_function = false;
                        }
                    }
                }
            } else if line.contains("#[derive(Accounts)]") {
                if let Some(struct_info) = parse_account_struct(&lines, i, rel_path) {
                    account_structs.push(struct_info);
                }
            }
        } else {
            if line.contains('{') {
                brace_depth += line.matches('{').count() as i32;
            }
            if line.contains('}') {
                brace_depth -= line.matches('}').count() as i32;
            }

            check_solana_auth_signals(line, &mut func_auth_signals);
            check_solana_mutation_signals(line, &mut func_mutation_signals);
            check_solana_cpi_signals(line, &mut func_cpi_signals);

            if brace_depth <= 0 {
                let snippet = lines
                    .get(func_start - 1..=i.min(lines.len() - 1))
                    .map(|l| l.join("\n"));
                functions.push(FunctionSurface {
                    name: func_name.clone(),
                    path: rel_path.to_string(),
                    line_start: func_start,
                    line_end: i + 1,
                    kind: "instruction".into(),
                    visibility: Some("public".into()),
                    is_payable: false,
                    has_auth_signal: !func_auth_signals.is_empty(),
                    auth_signals: func_auth_signals.clone(),
                    has_state_mutation: !func_mutation_signals.is_empty(),
                    mutation_signals: func_mutation_signals.clone(),
                    has_external_call: false,
                    external_call_signals: Vec::new(),
                    has_cpi: !func_cpi_signals.is_empty(),
                    cpi_signals: func_cpi_signals.clone(),
                    context_type: None,
                    account_struct: None,
                    source_snippet: snippet,
                });
                in_function = false;
            }
        }
        i += 1;
    }
}

fn extract_fn_name(line: &str) -> Option<String> {
    if let Some(rest) = line.strip_prefix("pub fn ") {
        let rest = rest.trim_start();
        if let Some(paren_idx) = rest.find('(') {
            let name = rest[..paren_idx].trim();
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn extract_ctx_type(line: &str) -> Option<String> {
    if let Some(start) = line.find("Context<") {
        let rest = &line[start + 8..];
        if let Some(end) = rest.find('>') {
            let ctx = rest[..end].trim();
            if !ctx.is_empty() {
                return Some(ctx.to_string());
            }
        }
    }
    None
}

fn parse_account_struct(
    lines: &[&str],
    derive_line: usize,
    rel_path: &str,
) -> Option<AccountStructInfo> {
    let mut struct_name = String::new();
    let mut struct_start = derive_line;
    let mut struct_end = derive_line;
    let mut brace_depth = 0;
    let mut in_struct = false;

    for (i, line_raw) in lines.iter().enumerate().skip(derive_line).take(20) {
        let line = line_raw.trim();
        if line.starts_with("pub struct ") || line.contains("pub struct ") {
            if let Some(name) = extract_struct_name(line) {
                struct_name = name;
                struct_start = i;
                in_struct = true;
            }
        }
        if in_struct {
            if line.contains('{') {
                brace_depth += line.matches('{').count() as i32;
            }
            if line.contains('}') {
                brace_depth -= line.matches('}').count() as i32;
                if brace_depth <= 0 {
                    struct_end = i;
                    break;
                }
            }
        }
    }

    if struct_name.is_empty() {
        return None;
    }

    let mut fields = Vec::new();
    for line_raw in lines
        .iter()
        .skip(derive_line + 1)
        .take(struct_end + 1 - derive_line - 1)
    {
        let line = line_raw.trim();
        if let Some(field) = parse_account_field(line) {
            fields.push(field);
        }
    }

    Some(AccountStructInfo {
        name: struct_name,
        path: rel_path.to_string(),
        line_start: struct_start + 1,
        line_end: struct_end + 1,
        fields,
    })
}

fn extract_struct_name(line: &str) -> Option<String> {
    if let Some(rest) = line.strip_prefix("pub struct ") {
        let rest = rest.trim_start();
        if let Some(brace_idx) = rest.find('{') {
            let name = rest[..brace_idx].trim();
            let name = name.split('<').next().unwrap_or(name).trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    } else if let Some(idx) = line.find("pub struct ") {
        let rest = line[idx + 11..].trim_start();
        if let Some(brace_idx) = rest.find('{') {
            let name = rest[..brace_idx].trim();
            let name = name.split('<').next().unwrap_or(name).trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn parse_account_field(line: &str) -> Option<AccountField> {
    if !line.starts_with("pub ") && !line.contains("pub ") {
        return None;
    }
    if line.contains("struct ") || line.contains("impl ") || line.contains("fn ") {
        return None;
    }

    let is_signer = line.contains("Signer<");
    let is_mutable = line.contains("#[account(mut)]") || line.contains("account(mut)");
    let has_constraint = line.contains("constraint")
        || line.contains("has_one")
        || line.contains("seeds")
        || line.contains("bump");

    let mut constraint_signals = Vec::new();
    if line.contains("has_one") {
        constraint_signals.push("has_one".into());
    }
    if line.contains("constraint") {
        constraint_signals.push("constraint".into());
    }
    if line.contains("seeds") {
        constraint_signals.push("seeds".into());
    }
    if line.contains("bump") {
        constraint_signals.push("bump".into());
    }

    let field_name = extract_field_name(line)?;
    let field_type = extract_field_type(line);

    Some(AccountField {
        name: field_name,
        field_type,
        is_signer,
        is_mutable,
        has_constraint,
        constraint_signals,
    })
}

fn extract_field_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let after_pub = if let Some(idx) = trimmed.find("pub ") {
        &trimmed[idx + 4..]
    } else {
        return None;
    };
    if let Some(colon_idx) = after_pub.find(':') {
        let name = after_pub[..colon_idx].trim();
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Some(name.to_string());
        }
    }
    None
}

fn extract_field_type(line: &str) -> String {
    if let Some(idx) = line.find(':') {
        let rest = &line[idx + 1..];
        if let Some(comma_idx) = rest.find(',') {
            rest[..comma_idx].trim().to_string()
        } else {
            rest.trim().trim_end_matches(',').trim().to_string()
        }
    } else {
        "unknown".into()
    }
}

fn check_solana_auth_signals(line: &str, signals: &mut Vec<String>) {
    let checks = [
        ("Signer<'info>", "Signer account"),
        ("has_one", "has_one constraint"),
        ("constraint", "constraint check"),
        ("seeds", "PDA seeds"),
        ("bump", "PDA bump"),
        ("authority", "authority reference"),
        ("admin", "admin reference"),
        ("payer", "payer reference"),
        ("require!", "require macro"),
        ("require_keys_eq!", "require_keys_eq macro"),
        ("owner", "owner check"),
    ];
    for (pattern, desc) in checks {
        if line.contains(pattern) && !signals.contains(&desc.to_string()) {
            signals.push(desc.into());
        }
    }
}

fn check_solana_mutation_signals(line: &str, signals: &mut Vec<String>) {
    if (line.contains("#[account(mut)]") || line.contains("account(mut)"))
        && !signals.contains(&"mutable_account".to_string())
    {
        signals.push("mutable_account".into());
    }
    if (line.contains("load_mut") || line.contains("try_borrow_mut_data"))
        && !signals.contains(&"mut_data_access".to_string())
    {
        signals.push("mut_data_access".into());
    }
    if line.contains("ctx.accounts") && !signals.contains(&"accounts_mutation".to_string()) {
        signals.push("accounts_mutation".into());
    }
}

fn check_solana_cpi_signals(line: &str, signals: &mut Vec<String>) {
    let checks = [
        ("invoke(", "invoke"),
        ("invoke_signed(", "invoke_signed"),
        ("CpiContext", "CpiContext"),
        ("token::transfer", "token_transfer"),
        ("token::mint_to", "token_mint"),
        ("token::burn", "token_burn"),
        ("system_program::transfer", "system_transfer"),
        ("::cpi::", "cpi_module"),
    ];
    for (pattern, desc) in checks {
        if line.contains(pattern) && !signals.contains(&desc.to_string()) {
            signals.push(desc.into());
        }
    }
}
