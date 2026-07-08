//! Phase 1 completion gate — Storage Consolidation + Artifact Integrity Audit.
//!
//! Verifies that:
//!   - the default workspace seeds deterministically and idempotently
//!   - every ArtifactKind can be created, persisted, and reloaded
//!   - every artifact has single, resolvable ownership (scan -> project -> org)
//!   - a whole-store audit reports no orphans and no ownership mismatches
use digger_platform::json_storage::JsonStorage;
use digger_platform::storage::Storage;
use digger_platform::{integrity, seed};

#[test]
fn phase1_storage_consolidation_gate() {
    let dir = std::env::temp_dir().join(format!("digger-integrity-{}", uuid::Uuid::new_v4()));
    let store = JsonStorage::new(&dir);
    store.init().expect("init storage");

    // Seeding is idempotent and deterministic.
    seed::seed_defaults(&store).expect("seed defaults");
    seed::seed_defaults(&store).expect("seed defaults idempotent");
    assert!(
        store.exists("orgs", seed::DEFAULT_ORG_ID),
        "default org seeded"
    );
    assert!(
        store.exists("projects", seed::DEFAULT_PROJECT_ID),
        "default project seeded"
    );

    // Every ArtifactKind round-trips with single ownership.
    let checks = integrity::verify_all_artifact_kinds(&store).expect("verify kinds");
    assert_eq!(checks.len(), 9, "nine ArtifactKinds verified");
    for c in &checks {
        assert!(c.created, "{} created", c.kind);
        assert!(c.persisted, "{} persisted", c.kind);
        assert!(c.reloaded, "{} reloaded", c.kind);
        assert!(c.ownership_ok, "{} single-ownership", c.kind);
    }

    // Whole-store ownership audit passes with no orphans.
    let report = integrity::audit(&store);
    assert!(
        report.orphan_artifacts.is_empty(),
        "no orphan artifacts: {:?}",
        report.orphan_artifacts
    );
    assert!(report.orphan_reports.is_empty(), "no orphan reports");
    assert!(
        report.ownership_mismatches.is_empty(),
        "no ownership mismatches: {:?}",
        report.ownership_mismatches
    );
    assert!(report.passed, "integrity audit passes");

    let _ = std::fs::remove_dir_all(&dir);
}
