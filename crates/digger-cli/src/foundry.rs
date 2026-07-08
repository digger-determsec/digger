use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Detected Foundry project layout.
#[derive(Debug, Clone)]
pub struct FoundryProject {
    pub root: PathBuf,
    pub src_dir: PathBuf,
    pub lib_dir: PathBuf,
    pub remappings: BTreeMap<String, String>,
}

impl FoundryProject {
    /// Detect a Foundry project at the given path.
    /// Returns None if no foundry.toml is found.
    pub fn detect(path: &Path) -> Option<Self> {
        let toml_path = path.join("foundry.toml");
        if !toml_path.exists() {
            return None;
        }

        let toml_content = std::fs::read_to_string(&toml_path).ok()?;

        // Parse foundry.toml for src, libs, remappings
        let mut src = path.join("src");
        let mut libs = vec![path.join("lib")];
        let mut remappings: BTreeMap<String, String> = BTreeMap::new();

        // Simple TOML parsing (avoid adding toml dependency)
        for line in toml_content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("src") && trimmed.contains('=') {
                if let Some(val) = trimmed.split('=').nth(1) {
                    let val = val.trim().trim_matches('"');
                    src = path.join(val);
                }
            }
            if trimmed.starts_with("libs") && trimmed.contains('=') {
                // Parse libs array like ["lib"]
                if let Some(start) = trimmed.find('[') {
                    if let Some(end) = trimmed.find(']') {
                        let inner = &trimmed[start + 1..end];
                        libs = inner
                            .split(',')
                            .map(|s| path.join(s.trim().trim_matches('"')))
                            .collect();
                    }
                }
            }
        }

        // Parse remappings from foundry.toml
        Self::parse_toml_remappings(&toml_content, path, &mut remappings);

        // Also parse remappings.txt if present
        let remappings_txt = path.join("remappings.txt");
        if remappings_txt.exists() {
            Self::parse_remappings_txt(&remappings_txt, &mut remappings);
        }

        // Add implicit lib/ remappings (forge style: lib/name/src/ -> name/)
        for lib in &libs {
            if lib.is_dir() {
                if let Ok(entries) = std::fs::read_dir(lib) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let src = entry.path().join("src");
                        if src.exists() {
                            remappings.insert(
                                format!("{}/", name),
                                format!("{}/src/", entry.path().display()),
                            );
                        }
                    }
                }
            }
        }

        Some(Self {
            root: path.to_path_buf(),
            src_dir: src,
            lib_dir: libs.first().cloned().unwrap_or_else(|| path.join("lib")),
            remappings,
        })
    }

    /// Parse remappings from foundry.toml content.
    fn parse_toml_remappings(
        toml_content: &str,
        root: &Path,
        remappings: &mut BTreeMap<String, String>,
    ) {
        // Look for remappings = [...] block
        let mut in_remappings = false;
        let mut bracket_depth = 0;

        for line in toml_content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("remappings") && trimmed.contains('[') {
                in_remappings = true;
                bracket_depth = 1;
                // Check if the entire array is on one line
                if let Some(end) = trimmed.find(']') {
                    let inner = &trimmed[trimmed.find('[').map_or(0, |i| i + 1)..end];
                    for entry in inner.split(',') {
                        let entry = entry.trim().trim_matches('"');
                        Self::add_remapping(entry, root, remappings);
                    }
                    in_remappings = false;
                }
                continue;
            }
            if in_remappings {
                if trimmed.contains(']') {
                    in_remappings = false;
                    // Handle last entry before ]
                    if let Some(start) = trimmed.find('"') {
                        let entry = trimmed[start..].trim_matches('"').trim_matches(',');
                        if !entry.is_empty() {
                            Self::add_remapping(entry, root, remappings);
                        }
                    }
                    continue;
                }
                let entry = trimmed.trim_matches(',').trim_matches('"');
                if !entry.is_empty() {
                    Self::add_remapping(entry, root, remappings);
                }
            }
        }
    }

    /// Parse remappings from remappings.txt.
    fn parse_remappings_txt(path: &Path, remappings: &mut BTreeMap<String, String>) {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with("//") {
                    Self::add_remapping(line, path.parent().unwrap_or(path), remappings);
                }
            }
        }
    }

    /// Add a single remapping entry.
    fn add_remapping(entry: &str, root: &Path, remappings: &mut BTreeMap<String, String>) {
        if let Some(eq_pos) = entry.find('=') {
            let key = entry[..eq_pos].trim().to_string();
            let val = entry[eq_pos + 1..].trim().to_string();
            if !key.is_empty() && !val.is_empty() {
                // Resolve relative paths
                let resolved = if val.starts_with('.') || val.starts_with('/') {
                    root.join(&val).to_string_lossy().to_string()
                } else {
                    val
                };
                remappings.insert(key, resolved);
            }
        }
    }

    /// Resolve an import path to an actual file path.
    pub fn resolve_import(&self, import_path: &str, from_file: &Path) -> Option<PathBuf> {
        // Try each remapping prefix
        for (prefix, target) in &self.remappings {
            if import_path.starts_with(prefix) {
                let relative = &import_path[prefix.len()..];
                let resolved = Path::new(target).join(relative);
                if resolved.exists() {
                    return Some(resolved);
                }
            }
        }

        // Try relative to the importing file's directory
        if let Some(parent) = from_file.parent() {
            let resolved = parent.join(import_path);
            if resolved.exists() {
                return Some(resolved);
            }
        }

        // Try relative to src/
        let resolved = self.src_dir.join(import_path);
        if resolved.exists() {
            return Some(resolved);
        }

        // Try relative to each lib dir
        if let Ok(entries) = self.root.read_dir() {
            for lib in entries.flatten() {
                if lib.path().is_dir() {
                    let resolved = lib.path().join("src").join(import_path);
                    if resolved.exists() {
                        return Some(resolved);
                    }
                }
            }
        }

        None
    }

    /// Resolve all imports across the source files and return dependency-closed source.
    pub fn resolve_source(&self) -> (String, Vec<String>) {
        let mut resolved_files: BTreeMap<PathBuf, String> = BTreeMap::new();
        let mut unresolved: Vec<String> = Vec::new();

        // Collect all source files
        let mut source_files = Vec::new();
        self.collect_source_files(&self.src_dir, &mut source_files);
        for lib in &self.libs() {
            self.collect_source_files(lib, &mut source_files);
        }

        // Process each file and its imports
        let mut to_process: Vec<PathBuf> = source_files;
        let mut processed = std::collections::HashSet::new();

        while let Some(file) = to_process.pop() {
            if processed.contains(&file) {
                continue;
            }
            processed.insert(file.clone());

            let content = match std::fs::read_to_string(&file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Track imports and resolve
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

                    if let Some(resolved) = self.resolve_import(&import_path, &file) {
                        if !processed.contains(&resolved) {
                            to_process.push(resolved);
                        }
                    } else if !unresolved.contains(&import_path) {
                        unresolved.push(import_path);
                    }
                }
            }

            resolved_files.insert(file, content);
        }

        // Concatenate all resolved files in order
        let mut source = String::new();
        let mut sorted_keys: Vec<&PathBuf> = resolved_files.keys().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            if !source.is_empty() {
                source.push_str("\n\n");
            }
            source.push_str(&resolved_files[key]);
        }

        (source, unresolved)
    }

    /// Collect .sol files from a directory recursively.
    fn collect_source_files(&self, dir: &Path, files: &mut Vec<PathBuf>) {
        if let Ok(entries) = dir.read_dir() {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    self.collect_source_files(&path, files);
                } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if ext == "sol" {
                        files.push(path);
                    }
                }
            }
        }
    }

    /// Get lib directories.
    fn libs(&self) -> Vec<PathBuf> {
        if self.lib_dir.exists() {
            vec![self.lib_dir.clone()]
        } else {
            vec![]
        }
    }
}
