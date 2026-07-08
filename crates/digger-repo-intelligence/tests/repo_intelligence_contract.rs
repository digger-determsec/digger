use digger_repo_intelligence::*;
use std::path::PathBuf;

fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn test_metadata_contract_evm() {
    let input = RepoIntelligenceInput {
        root: fixture_dir("evm-basic"),
        chain: Chain::Evm,
    };
    let map = scan_repo(input).unwrap();

    assert_eq!(map.schema_version, "digger.repo_intelligence.v1");
    assert_eq!(map.report_kind, "repo_intelligence");
    assert_eq!(map.chain, "evm");
    assert_eq!(map.generated_from.mode, "read_only_static_inventory");
    assert!(!map.surfaces.is_empty());
}

#[test]
fn test_metadata_contract_solana() {
    let input = RepoIntelligenceInput {
        root: fixture_dir("solana-basic"),
        chain: Chain::Solana,
    };
    let map = scan_repo(input).unwrap();

    assert_eq!(map.schema_version, "digger.repo_intelligence.v1");
    assert_eq!(map.report_kind, "repo_intelligence");
    assert_eq!(map.chain, "solana");
}

#[test]
fn test_no_vulnerability_fields() {
    let input = RepoIntelligenceInput {
        root: fixture_dir("evm-basic"),
        chain: Chain::Evm,
    };
    let map = scan_repo(input).unwrap();
    let json = serde_json::to_value(&map).unwrap();

    // Must not contain vulnerability/risk/severity/finding fields
    assert!(json.get("severity").is_none());
    assert!(json.get("risk_score").is_none());
    assert!(json.get("is_vulnerability_finding").is_none());
    assert!(json.get("confidence_ceiling").is_none());
    assert!(json.get("finding_id").is_none());

    // Each surface must not contain vulnerability fields
    for surface in &map.surfaces {
        let sj = serde_json::to_value(surface).unwrap();
        assert!(sj.get("severity").is_none());
        assert!(sj.get("risk_score").is_none());
        assert!(sj.get("is_vulnerability_finding").is_none());
    }
}

#[test]
fn test_deterministic_output() {
    let make_input = || RepoIntelligenceInput {
        root: fixture_dir("evm-basic"),
        chain: Chain::Evm,
    };

    let map1 = scan_repo(make_input()).unwrap();
    let map2 = scan_repo(make_input()).unwrap();

    let json1 = serde_json::to_string(&map1).unwrap();
    let json2 = serde_json::to_string(&map2).unwrap();
    assert_eq!(json1, json2, "output must be deterministic");
}

#[test]
fn test_evm_classification() {
    let input = RepoIntelligenceInput {
        root: fixture_dir("evm-basic"),
        chain: Chain::Evm,
    };
    let map = scan_repo(input).unwrap();

    let categories: Vec<&str> = map.surfaces.iter().map(|s| s.category.as_str()).collect();
    assert!(
        categories.contains(&"entrypoint"),
        "should detect contract/entrypoint"
    );
    assert!(
        categories.contains(&"value_transfer")
            || categories.contains(&"privileged_operation")
            || categories.contains(&"external_call"),
        "should detect function-level surfaces"
    );
}

#[test]
fn test_solana_classification() {
    let input = RepoIntelligenceInput {
        root: fixture_dir("solana-basic"),
        chain: Chain::Solana,
    };
    let map = scan_repo(input).unwrap();

    let categories: Vec<&str> = map.surfaces.iter().map(|s| s.category.as_str()).collect();
    assert!(
        categories.contains(&"entrypoint"),
        "should detect program entry"
    );
}

#[test]
fn test_path_normalization() {
    let input = RepoIntelligenceInput {
        root: fixture_dir("evm-basic"),
        chain: Chain::Evm,
    };
    let map = scan_repo(input).unwrap();

    for surface in &map.surfaces {
        assert!(
            !surface.path.starts_with('/'),
            "path must be relative: {}",
            surface.path
        );
        assert!(
            !surface.path.contains('\\'),
            "path must use forward slashes: {}",
            surface.path
        );
    }
}

#[test]
fn test_nonexistent_path() {
    let input = RepoIntelligenceInput {
        root: PathBuf::from("/nonexistent/path/that/does/not/exist"),
        chain: Chain::Evm,
    };
    assert!(scan_repo(input).is_err());
}
