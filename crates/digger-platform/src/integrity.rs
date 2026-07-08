/// Artifact integrity audit.
///
/// Enforces the ownership invariants frozen in
/// `docs/architecture/01-platform-ownership.md` and
/// `docs/architecture/02-artifact-lifecycle.md`:
///
///   - every artifact belongs to exactly one scan_id, project, and organization
///   - ownership is deterministic and fully resolvable (no orphans)
///   - persistence flows through the Storage trait only (single path to disk)
///
/// This module is the programmatic completion gate for Phase 1.
use crate::models::*;
use crate::storage::{Storage, StorageError};
use std::collections::{BTreeMap, BTreeSet};

/// Result of a whole-store ownership audit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct IntegrityReport {
    pub total_orgs: usize,
    pub total_projects: usize,
    pub total_scans: usize,
    pub total_artifacts: usize,
    pub total_reports: usize,
    /// Count of persisted artifacts per ArtifactKind.
    pub artifacts_by_kind: BTreeMap<String, usize>,
    /// Artifact ids whose scan_id does not resolve to a persisted scan.
    pub orphan_artifacts: Vec<String>,
    /// Report ids whose scan_id does not resolve to a persisted scan.
    pub orphan_reports: Vec<String>,
    /// Human-readable ownership-chain inconsistencies.
    pub ownership_mismatches: Vec<String>,
    /// True iff there are no orphans and no mismatches.
    pub passed: bool,
}

fn kind_name(kind: &ArtifactKind) -> String {
    format!("{:?}", kind)
}

/// Audit every persisted artifact and report against the ownership hierarchy.
pub fn audit(store: &dyn Storage) -> IntegrityReport {
    let orgs: Vec<Organization> = store
        .list_all_json("orgs")
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();
    let projects: Vec<Project> = store
        .list_all_json("projects")
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();
    let scans: Vec<ScanRecord> = store
        .list_all_json("scans")
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();
    let artifacts: Vec<Artifact> = store
        .list_all_json("artifacts")
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();
    let reports: Vec<Report> = store
        .list_all_json("reports")
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();

    let org_ids: BTreeSet<String> = orgs.iter().map(|o| o.id.clone()).collect();
    let project_org: BTreeMap<String, String> = projects
        .iter()
        .map(|p| (p.id.clone(), p.org_id.clone()))
        .collect();
    let scan_owner: BTreeMap<String, (String, String)> = scans
        .iter()
        .map(|s| (s.id.clone(), (s.project_id.clone(), s.org_id.clone())))
        .collect();

    let mut report = IntegrityReport {
        total_orgs: orgs.len(),
        total_projects: projects.len(),
        total_scans: scans.len(),
        total_artifacts: artifacts.len(),
        total_reports: reports.len(),
        ..Default::default()
    };

    for a in &artifacts {
        *report
            .artifacts_by_kind
            .entry(kind_name(&a.kind))
            .or_insert(0) += 1;

        if a.scan_id.is_empty() {
            report.orphan_artifacts.push(a.id.clone());
            continue;
        }
        match scan_owner.get(&a.scan_id) {
            None => report.orphan_artifacts.push(a.id.clone()),
            Some((proj, scan_org)) => {
                if a.project_id != *proj {
                    report.ownership_mismatches.push(format!(
                        "artifact {} project_id '{}' != scan {} project_id '{}'",
                        a.id, a.project_id, a.scan_id, proj
                    ));
                }
                match project_org.get(&a.project_id) {
                    None => report.ownership_mismatches.push(format!(
                        "artifact {} references unknown project '{}'",
                        a.id, a.project_id
                    )),
                    Some(org) => {
                        if !org_ids.contains(org) {
                            report.ownership_mismatches.push(format!(
                                "artifact {} -> project '{}' -> unknown org '{}'",
                                a.id, a.project_id, org
                            ));
                        }
                        if org != scan_org {
                            report.ownership_mismatches.push(format!(
                                "artifact {} project org '{}' != scan org '{}'",
                                a.id, org, scan_org
                            ));
                        }
                    }
                }
            }
        }
    }

    for r in &reports {
        if r.scan_id.is_empty() {
            report.orphan_reports.push(r.id.clone());
            continue;
        }
        match scan_owner.get(&r.scan_id) {
            None => report.orphan_reports.push(r.id.clone()),
            Some((proj, org)) => {
                if r.project_id != *proj {
                    report.ownership_mismatches.push(format!(
                        "report {} project_id '{}' != scan project_id '{}'",
                        r.id, r.project_id, proj
                    ));
                }
                if r.org_id != *org {
                    report.ownership_mismatches.push(format!(
                        "report {} org_id '{}' != scan org_id '{}'",
                        r.id, r.org_id, org
                    ));
                }
            }
        }
    }

    report.passed = report.orphan_artifacts.is_empty()
        && report.orphan_reports.is_empty()
        && report.ownership_mismatches.is_empty();
    report
}

/// Every ArtifactKind that must round-trip cleanly through storage.
pub fn all_artifact_kinds() -> Vec<ArtifactKind> {
    vec![
        ArtifactKind::SourceCode,
        ArtifactKind::ParsedIr,
        ArtifactKind::SystemGraph,
        ArtifactKind::KnowledgeReferences,
        ArtifactKind::Hypothesis,
        ArtifactKind::ExploitChain,
        ArtifactKind::ValidationReport,
        ArtifactKind::ExecutionTranscript,
        ArtifactKind::EvaluationReport,
    ]
}

/// Per-kind round-trip verification result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct KindCheck {
    pub kind: String,
    pub created: bool,
    pub persisted: bool,
    pub reloaded: bool,
    pub ownership_ok: bool,
}

/// Create, persist, and reload one artifact of every ArtifactKind under a
/// throwaway scan, verifying single, deterministic ownership and a clean
/// round-trip. Probe artifacts are deleted before returning.
pub fn verify_all_artifact_kinds(store: &dyn Storage) -> Result<Vec<KindCheck>, StorageError> {
    use crate::artifacts::ArtifactManager;
    let mgr = ArtifactManager::new(store);
    let scan_id = format!("integrity-scan-{}", uuid::Uuid::new_v4());
    let project_id = crate::seed::DEFAULT_PROJECT_ID;

    let mut checks = Vec::new();
    let mut created_ids = Vec::new();

    for kind in all_artifact_kinds() {
        let mut check = KindCheck {
            kind: kind_name(&kind),
            ..Default::default()
        };
        let content = serde_json::json!({ "probe": kind_name(&kind) });
        match mgr.store(
            &scan_id,
            project_id,
            kind.clone(),
            "integrity-probe",
            content,
        ) {
            Ok(artifact) => {
                check.created = true;
                check.persisted = store.exists("artifacts", &artifact.id);
                if let Ok(loaded) = mgr.get(&artifact.id) {
                    check.reloaded = true;
                    check.ownership_ok = loaded.scan_id == scan_id
                        && loaded.project_id == project_id
                        && loaded.kind == kind;
                }
                created_ids.push(artifact.id);
            }
            Err(e) => return Err(format!("failed to create {}: {}", check.kind, e).into()),
        }
        checks.push(check);
    }

    for id in created_ids {
        let _ = mgr.delete(&id);
    }
    Ok(checks)
}
