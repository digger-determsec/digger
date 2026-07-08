use digger_pipeline::investigate_source;
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
    "venv",
    ".venv",
];

#[derive(Debug, Clone)]
pub struct EngineHypothesis {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub affected_function: String,
    pub description: String,
    pub source_file: String,
}

#[derive(Debug, Clone)]
pub struct EngineSurface {
    pub function_name: String,
    pub file: String,
    pub has_authority: bool,
    pub writes_state: bool,
    pub makes_external_calls: bool,
}

pub struct EngineEvidence {
    pub hypotheses: Vec<EngineHypothesis>,
    pub surfaces: Vec<EngineSurface>,
    pub limitations: Vec<String>,
    pub files_ok: usize,
    pub files_err: usize,
}

pub fn collect_engine_evidence(root: &Path, chain: &str) -> EngineEvidence {
    let mut evidence = EngineEvidence {
        hypotheses: Vec::new(),
        surfaces: Vec::new(),
        limitations: Vec::new(),
        files_ok: 0,
        files_err: 0,
    };
    let lang = match chain {
        "evm" => "solidity",
        "solana" => "rust",
        _ => "unknown",
    };
    let exts: Vec<&str> = match chain {
        "evm" => vec!["sol"],
        "solana" => vec!["rs"],
        _ => vec![],
    };
    let root = root.to_path_buf();
    collect_recursive(&root, &root, lang, &exts, &mut evidence);
    evidence
}

fn rel_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
        .replace('\\', "/")
}

fn collect_recursive(
    dir: &Path,
    root: &Path,
    lang: &str,
    exts: &[&str],
    evidence: &mut EngineEvidence,
) {
    let entries = match std::fs::read_dir(dir) {
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
            collect_recursive(&path, root, lang, exts, evidence);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if exts.contains(&ext) {
                process_file(&path, root, lang, evidence);
            }
        }
    }
}

fn process_file(path: &Path, root: &Path, lang: &str, evidence: &mut EngineEvidence) {
    let code = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            evidence.files_err += 1;
            return;
        }
    };
    let file_str = rel_path(path, root);
    let outcome = investigate_source(&code, lang);
    evidence.files_ok += 1;
    for sys in &outcome.systems {
        for h in &sys.hypotheses.hypotheses {
            evidence.hypotheses.push(EngineHypothesis {
                id: h.id.0.clone(),
                kind: format!("{}", h.hypothesis_type),
                severity: format!("{:?}", h.severity),
                affected_function: h.primary_function.clone(),
                description: h.description.clone(),
                source_file: file_str.clone(),
            });
        }
        for ep in &sys.surface.attack_surface.entry_points {
            evidence.surfaces.push(EngineSurface {
                function_name: ep.function.clone(),
                file: file_str.clone(),
                has_authority: ep.has_authority,
                writes_state: ep.writes_state,
                makes_external_calls: ep.makes_external_calls,
            });
        }
    }
}
