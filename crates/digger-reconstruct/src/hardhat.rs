use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Detected Hardhat project layout.
#[derive(Debug, Clone)]
pub struct HardhatProject {
    pub root: PathBuf,
    pub contracts_dir: PathBuf,
    pub node_modules: PathBuf,
}

impl HardhatProject {
    /// Detect a Hardhat project at the given path.
    pub fn detect(path: &Path) -> Option<Self> {
        // Check for hardhat config files
        let has_config = path.join("hardhat.config.js").exists()
            || path.join("hardhat.config.ts").exists()
            || path.join("hardhat.config.cjs").exists();

        // Check for hardhat in package.json (backup detection)
        let has_pkg_hardhat = path.join("package.json").exists()
            && std::fs::read_to_string(path.join("package.json"))
                .unwrap_or_default()
                .contains("hardhat");

        if !has_config && !has_pkg_hardhat {
            return None;
        }

        let contracts_dir = path.join("contracts");
        let node_modules = path.join("node_modules");

        Some(Self {
            root: path.to_path_buf(),
            contracts_dir,
            node_modules,
        })
    }

    /// Resolve all imports and return dependency-closed source + unresolved list.
    pub fn resolve_source(&self) -> Result<(String, Vec<String>), String> {
        let mut resolved_files: BTreeMap<PathBuf, String> = BTreeMap::new();
        let mut unresolved: Vec<String> = Vec::new();
        let mut to_process: Vec<PathBuf> = Vec::new();
        let mut processed = std::collections::HashSet::new();

        self.collect_source_files(&self.contracts_dir, &mut to_process);

        // Also check node_modules for direct imports
        // (but don't scan all of node_modules — only resolve specific imports)

        while let Some(file) = to_process.pop() {
            if processed.contains(&file) {
                continue;
            }
            processed.insert(file.clone());
            let content = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("import ") {
                    let import_path = trimmed
                        .strip_prefix("import ")
                        .unwrap_or(trimmed)
                        .trim()
                        .trim_matches(';')
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    // Strip named imports: import {X} from "path" -> "path"
                    let import_path = if let Some(from_pos) = import_path.find(" from ") {
                        import_path[from_pos + 6..]
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'')
                            .to_string()
                    } else {
                        import_path
                    };
                    if !import_path.is_empty() {
                        if let Some(resolved) = self.resolve_import(&import_path, &file) {
                            if !processed.contains(&resolved) {
                                to_process.push(resolved);
                            }
                        } else if !unresolved.contains(&import_path) {
                            unresolved.push(import_path);
                        }
                    }
                }
            }
            resolved_files.insert(file, content);
        }

        let mut source = String::new();
        let mut sorted_keys: Vec<&PathBuf> = resolved_files.keys().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            if !source.is_empty() {
                source.push_str("\n\n");
            }
            source.push_str(&resolved_files[key]);
        }
        Ok((source, unresolved))
    }

    /// Resolve an import path to a file.
    pub fn resolve_import(&self, import_path: &str, from_file: &Path) -> Option<PathBuf> {
        // Try node_modules for @-scoped and bare imports
        if import_path.starts_with('@') || !import_path.starts_with('.') {
            let nm_path = self.node_modules.join(import_path);
            if nm_path.exists() {
                return Some(nm_path);
            }
            // Try with .sol extension
            let nm_with_sol = self.node_modules.join(format!("{}.sol", import_path));
            if nm_with_sol.exists() {
                return Some(nm_with_sol);
            }
        }

        // Try relative to the importing file's directory
        if let Some(parent) = from_file.parent() {
            let resolved = parent.join(import_path);
            if resolved.exists() {
                return Some(resolved);
            }
        }

        // Try relative to contracts/
        let resolved = self.contracts_dir.join(import_path);
        if resolved.exists() {
            return Some(resolved);
        }

        None
    }

    fn collect_source_files(&self, dir: &Path, files: &mut Vec<PathBuf>) {
        if !dir.exists() {
            return;
        }
        if let Ok(entries) = dir.read_dir() {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Skip node_modules subdirectories
                    if path.file_name().and_then(|n| n.to_str()) == Some("node_modules") {
                        continue;
                    }
                    self.collect_source_files(&path, files);
                } else if path.extension().and_then(|e| e.to_str()) == Some("sol") {
                    files.push(path);
                }
            }
        }
    }
}
