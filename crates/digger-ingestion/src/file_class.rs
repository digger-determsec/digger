use serde::{Deserialize, Serialize};

/// Classification of a source file's role in a project.
///
/// This is additive metadata only — it does not affect scanning or detection.
/// The classifier is a heuristic; edge cases exist (e.g. production code in a
/// `test/` folder, or real protocol code under `lib/`). Display filtering only,
/// never scan filtering. Full counts always appear in summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileClass {
    /// Contract source, protocol logic, libraries.
    Production,
    /// Test harness, mocks, fixtures, specs.
    Test,
    /// Example contracts, demos, samples.
    Example,
    /// Vendored dependencies (node_modules, forge-std, etc.).
    Dependency,
}

impl std::fmt::Display for FileClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileClass::Production => write!(f, "production"),
            FileClass::Test => write!(f, "test"),
            FileClass::Example => write!(f, "example"),
            FileClass::Dependency => write!(f, "dependency"),
        }
    }
}

/// Classify a file path into a [`FileClass`].
///
/// Pure and deterministic — no I/O, no filesystem stat. Uses only the
/// path string (split into segments, compared case-insensitively).
///
/// # Classification rules (checked in order)
///
/// 1. **Dependency** — any path segment matches: `node_modules`, `lib`, `vendor`,
///    `.deps`, `dependencies`
/// 2. **Test** — any path segment matches: `test`, `tests`, `mock`, `mocks`,
///    `fixture`, `fixtures`, `spec`, `specs`; OR filename matches `*.t.sol`,
///    `*Test.sol`, `*Mock*.sol`, `*.test.*`, `*.spec.*`, `*Echidna*`, `*Invariant*`
/// 3. **Example** — any path segment matches: `example`, `examples`, `demo`, `sample`
/// 4. **Production** — everything else
pub fn classify_path(path: &str) -> FileClass {
    // Normalize separators to forward slash for cross-platform consistency
    let normalized = path.replace('\\', "/");
    let segments: Vec<&str> = normalized.split('/').collect();
    let filename = normalized.rsplit('/').next().unwrap_or(&normalized);
    let filename_lower = filename.to_lowercase();

    // Check dependency segments first (most specific)
    for seg in &segments {
        let s = seg.to_lowercase();
        if s == "node_modules" || s == "lib" || s == "vendor" || s == ".deps" || s == "dependencies"
        {
            return FileClass::Dependency;
        }
    }

    // Check test segments and filename patterns
    for seg in &segments {
        let s = seg.to_lowercase();
        if s == "test"
            || s == "tests"
            || s == "mock"
            || s == "mocks"
            || s == "fixture"
            || s == "fixtures"
            || s == "spec"
            || s == "specs"
        {
            return FileClass::Test;
        }
    }

    // Filename-based test detection
    if filename_lower.ends_with(".t.sol")
        || filename_lower.ends_with("test.sol")
        || filename_lower.contains("mock") && filename_lower.ends_with(".sol")
        || filename_lower.ends_with(".test.js")
        || filename_lower.ends_with(".test.ts")
        || filename_lower.ends_with(".spec.js")
        || filename_lower.ends_with(".spec.ts")
        || filename_lower.contains("echidna")
        || filename_lower.contains("invariant")
    {
        return FileClass::Test;
    }

    // Check example segments
    for seg in &segments {
        let s = seg.to_lowercase();
        if s == "example"
            || s == "examples"
            || s == "demo"
            || s == "demos"
            || s == "sample"
            || s == "samples"
        {
            return FileClass::Example;
        }
    }

    FileClass::Production
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_contract() {
        assert_eq!(classify_path("contracts/Vault.sol"), FileClass::Production);
    }

    #[test]
    fn test_by_segment() {
        assert_eq!(classify_path("test/Vault.t.sol"), FileClass::Test);
        assert_eq!(classify_path("tests/mock_vault.rs"), FileClass::Test);
        assert_eq!(classify_path("src/mocks/helper.rs"), FileClass::Test);
        assert_eq!(classify_path("fixtures/input.json"), FileClass::Test);
    }

    #[test]
    fn test_by_filename_pattern() {
        assert_eq!(classify_path("src/MyTest.sol"), FileClass::Test);
        assert_eq!(classify_path("src/MockToken.sol"), FileClass::Test);
        assert_eq!(classify_path("src/vault.test.ts"), FileClass::Test);
        assert_eq!(classify_path("src/vault.spec.js"), FileClass::Test);
        assert_eq!(classify_path("src/EchidnaVuln.sol"), FileClass::Test);
        assert_eq!(classify_path("src/InvariantCheck.sol"), FileClass::Test);
    }

    #[test]
    fn example_files() {
        assert_eq!(classify_path("examples/vault.sol"), FileClass::Example);
        assert_eq!(classify_path("example/demo.sol"), FileClass::Example);
        assert_eq!(classify_path("samples/ERC20.sol"), FileClass::Example);
    }

    #[test]
    fn dependency_files() {
        assert_eq!(
            classify_path("node_modules/@openzeppelin/contracts/ERC20.sol"),
            FileClass::Dependency
        );
        assert_eq!(
            classify_path("lib/forge-std/src/Test.sol"),
            FileClass::Dependency
        );
        assert_eq!(
            classify_path("vendor/safe-contracts/Safe.sol"),
            FileClass::Dependency
        );
    }

    #[test]
    fn v4_core_style_paths() {
        // Uniswap v4-core style: test/MockHooks.sol
        assert_eq!(classify_path("test/MockHooks.sol"), FileClass::Test);
        // Protocol source
        assert_eq!(classify_path("src/PoolManager.sol"), FileClass::Production);
        // Library in src — "libraries" must NOT match "lib" (exact segment equality)
        assert_eq!(
            classify_path("src/libraries/TickMath.sol"),
            FileClass::Production
        );
        assert_eq!(
            classify_path("src/libraries/Hooks.sol"),
            FileClass::Production
        );
        // forge-std under lib — "lib" IS a dependency segment
        assert_eq!(
            classify_path("lib/forge-std/src/StdCheats.sol"),
            FileClass::Dependency
        );
        // OpenZeppelin under node_modules
        assert_eq!(
            classify_path("node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol"),
            FileClass::Dependency
        );
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(classify_path("TEST/Vault.sol"), FileClass::Test);
        assert_eq!(
            classify_path("node_modules/Package/Mod.sol"),
            FileClass::Dependency
        );
        assert_eq!(classify_path("EXAMPLES/demo.sol"), FileClass::Example);
    }

    #[test]
    fn nested_segments() {
        assert_eq!(
            classify_path("src/contracts/deep/nested/MockHelper.sol"),
            FileClass::Test
        );
        assert_eq!(
            classify_path("packages/core/test/unit/vault.rs"),
            FileClass::Test
        );
    }

    #[test]
    fn deterministic() {
        let path = "src/contracts/Vault.sol";
        assert_eq!(classify_path(path), classify_path(path));
    }
}
