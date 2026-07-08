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
    pub fn detect(path: &Path) -> Option<Self> {
        let toml_path = path.join("foundry.toml");
        if !toml_path.exists() {
            return None;
        }
        let toml_content = std::fs::read_to_string(&toml_path).ok()?;
        let mut src = path.join("src");
        let mut libs = vec![path.join("lib")];
        let mut remappings: BTreeMap<String, String> = BTreeMap::new();

        for line in toml_content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("src") && trimmed.contains('=') {
                if let Some(val) = trimmed.split('=').nth(1) {
                    src = path.join(val.trim().trim_matches('"'));
                }
            }
            if trimmed.starts_with("libs") && trimmed.contains('[') {
                if let (Some(start), Some(end)) = (trimmed.find('['), trimmed.find(']')) {
                    let inner = &trimmed[start + 1..end];
                    libs = inner
                        .split(',')
                        .map(|s| path.join(s.trim().trim_matches('"')))
                        .collect();
                }
            }
        }

        Self::parse_toml_remappings(&toml_content, path, &mut remappings);
        let remappings_txt = path.join("remappings.txt");
        if remappings_txt.exists() {
            Self::parse_remappings_txt(&remappings_txt, &mut remappings);
        }
        for lib in &libs {
            if let Ok(entries) = std::fs::read_dir(lib) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let src_dir = entry.path().join("src");
                    if src_dir.exists() {
                        remappings.insert(
                            format!("{}/", name),
                            format!("{}/src/", entry.path().display()),
                        );
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

    pub fn resolve_import(&self, import_path: &str, from_file: &Path) -> Option<PathBuf> {
        for (prefix, target) in &self.remappings {
            if import_path.starts_with(prefix) {
                let relative = &import_path[prefix.len()..];
                let resolved = Path::new(target).join(relative);
                if resolved.exists() {
                    return Some(resolved);
                }
            }
        }
        if let Some(parent) = from_file.parent() {
            let resolved = parent.join(import_path);
            if resolved.exists() {
                return Some(resolved);
            }
        }
        let resolved = self.src_dir.join(import_path);
        if resolved.exists() {
            return Some(resolved);
        }
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

    pub fn resolve_source(&self) -> Result<(String, Vec<String>), String> {
        let mut resolved_files: BTreeMap<PathBuf, String> = BTreeMap::new();
        let mut unresolved: Vec<String> = Vec::new();
        let mut to_process: Vec<PathBuf> = Vec::new();
        let mut processed = std::collections::HashSet::new();
        self.collect_source_files(&self.src_dir, &mut to_process);
        for lib in self.libs() {
            self.collect_source_files(&lib, &mut to_process);
        }
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

    fn collect_source_files(&self, dir: &Path, files: &mut Vec<PathBuf>) {
        if let Ok(entries) = dir.read_dir() {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    self.collect_source_files(&path, files);
                } else if path.extension().and_then(|e| e.to_str()) == Some("sol") {
                    files.push(path);
                }
            }
        }
    }

    fn libs(&self) -> Vec<PathBuf> {
        if self.lib_dir.exists() {
            vec![self.lib_dir.clone()]
        } else {
            vec![]
        }
    }

    fn parse_toml_remappings(
        toml_content: &str,
        root: &Path,
        remappings: &mut BTreeMap<String, String>,
    ) {
        let mut in_remappings = false;
        for line in toml_content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("remappings") && trimmed.contains('[') {
                in_remappings = true;
                if let (Some(start), Some(end)) = (trimmed.find('['), trimmed.find(']')) {
                    let inner = &trimmed[start + 1..end];
                    for entry in inner.split(',') {
                        Self::add_remapping(entry.trim().trim_matches('"'), root, remappings);
                    }
                    in_remappings = false;
                }
                continue;
            }
            if in_remappings {
                if trimmed.contains(']') {
                    in_remappings = false;
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

    fn add_remapping(entry: &str, root: &Path, remappings: &mut BTreeMap<String, String>) {
        if let Some(eq_pos) = entry.find('=') {
            let key = entry[..eq_pos].trim().to_string();
            let val = entry[eq_pos + 1..].trim().to_string();
            if !key.is_empty() && !val.is_empty() {
                let resolved = if val.starts_with('.') || val.starts_with('/') {
                    root.join(&val).to_string_lossy().to_string()
                } else {
                    val
                };
                remappings.insert(key, resolved);
            }
        }
    }
}
