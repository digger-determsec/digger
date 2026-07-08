use std::path::{Path, PathBuf};

/// Detected Anchor/Cargo workspace layout.
#[derive(Debug, Clone)]
pub struct AnchorProject {
    pub root: PathBuf,
    pub programs_dir: PathBuf,
}

impl AnchorProject {
    /// Detect an Anchor project at the given path.
    pub fn detect(path: &Path) -> Option<Self> {
        // Primary: Anchor.toml
        if path.join("Anchor.toml").exists() {
            let programs_dir = path.join("programs");
            if programs_dir.exists() {
                return Some(Self {
                    root: path.to_path_buf(),
                    programs_dir,
                });
            }
        }
        // Secondary: Cargo.toml with anchor-lang dependency
        let cargo_toml = path.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml).unwrap_or_default();
            if content.contains("anchor-lang") {
                let programs_dir = path.join("programs");
                if programs_dir.exists() {
                    return Some(Self {
                        root: path.to_path_buf(),
                        programs_dir,
                    });
                }
            }
        }
        None
    }

    /// Gather program source files (lib.rs + mod-referenced files).
    pub fn resolve_source(&self) -> Result<(String, Vec<String>), String> {
        let mut source_files = Vec::new();
        let mut unresolved = Vec::new();

        // Find all program crates under programs/
        for entry in std::fs::read_dir(&self.programs_dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let crate_dir = entry.path();
            if !crate_dir.is_dir() {
                continue;
            }
            let src_dir = crate_dir.join("src");
            if !src_dir.exists() {
                continue;
            }
            // Collect lib.rs and all .rs files in src/
            self.collect_rust_files(&src_dir, &mut source_files);
        }

        if source_files.is_empty() {
            return Err("No Rust source files found in programs/*/src/".into());
        }

        // Scan for unresolved mod references and external crate imports
        for file in &source_files {
            if let Ok(content) = std::fs::read_to_string(file) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    // External crate imports (anchor-lang, spl-token, etc.)
                    if trimmed.starts_with("use ") && !trimmed.starts_with("use super::") {
                        let import = trimmed
                            .strip_prefix("use ")
                            .unwrap_or(trimmed)
                            .trim()
                            .trim_matches(';')
                            .to_string();
                        // Check if the first segment is an external crate
                        if let Some(crate_name) = import.split("::").next() {
                            if !crate_name.starts_with("super")
                                && !crate_name.starts_with("self")
                                && !crate_name.starts_with("crate")
                                && crate_name != "_"
                            {
                                // External crate - report as unresolved (deps not analyzed)
                                if !unresolved.contains(&import) {
                                    unresolved.push(import);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Concatenate all source files
        let mut source = String::new();
        let mut sorted_files = source_files;
        sorted_files.sort();
        for file in &sorted_files {
            if let Ok(content) = std::fs::read_to_string(file) {
                if !source.is_empty() {
                    source.push_str("\n\n");
                }
                source.push_str(&content);
            }
        }

        Ok((source, unresolved))
    }

    /// Collect all .rs files in a directory recursively.
    fn collect_rust_files(&self, dir: &Path, files: &mut Vec<PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    self.collect_rust_files(&path, files);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    files.push(path);
                }
            }
        }
    }
}
