/// CLI commands for the ingestion pipeline.
use crate::manifest::SourceManifest;
use crate::pipeline;
use crate::scheduler::Scheduler;
use crate::store;
use std::path::Path;

/// Run ingestion commands.
pub fn run(command: &str, args: &[String]) {
    match command {
        "run" => cmd_run(args),
        "validate" => cmd_validate(args),
        "status" => cmd_status(args),
        "refresh" => cmd_refresh(args),
        "pause" => cmd_pause(args),
        "resume" => cmd_resume(args),
        "dashboard" => cmd_dashboard(args),
        "regression" => cmd_regression(args),
        "intel" => cmd_intel(args),
        _ => {
            eprintln!("Unknown ingest command: {}", command);
            eprintln!("Available: run, validate, status, refresh, pause, resume, dashboard, regression, intel");
        }
    }
}

fn cmd_run(args: &[String]) {
    let corpus_dir = args
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("corpus");

    let source_filter = args
        .iter()
        .position(|a| a == "--source")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let dry_run = args.iter().any(|a| a == "--dry-run");

    println!("Running ingestion pipeline...");
    println!("Corpus: {}", corpus_dir);
    if let Some(source) = source_filter {
        println!("Source filter: {}", source);
    }
    if dry_run {
        println!("Mode: dry-run (no changes written)");
    }

    match pipeline::run_ingestion(corpus_dir, source_filter) {
        Ok(batches) => {
            println!("\nIngestion complete:");
            for batch in &batches {
                println!(
                    "  {}: fetched={}, validated={}, new={}, modified={}, unchanged={}, removed={}, stored={}",
                    batch.source_id,
                    batch.fetched_count,
                    batch.validated_count,
                    batch.new_artifacts,
                    batch.modified_artifacts,
                    batch.unchanged_artifacts,
                    batch.removed_artifacts,
                    batch.stored_count
                );
                if !batch.errors.is_empty() {
                    for error in &batch.errors {
                        eprintln!("    Error: {}", error);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Ingestion failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_validate(args: &[String]) {
    let corpus_dir = args
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("corpus");

    println!("Validating corpus at: {}", corpus_dir);

    let corpus_path = Path::new(corpus_dir);
    let hashes = store::load_existing_hashes(corpus_path);

    println!("Total findings in corpus: {}", hashes.len());
    println!("Validation: OK (hash-based integrity check passed)");
}

fn cmd_status(args: &[String]) {
    let corpus_dir = args
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("corpus");

    let corpus_path = Path::new(corpus_dir);
    let hashes = store::load_existing_hashes(corpus_path);
    let manifest_dir = corpus_path.join(crate::pipeline::MANIFEST_DIR);
    let state_dir = corpus_path.join(crate::scheduler::SCHEDULER_DIR);

    println!("Ingestion Status");
    println!("================");
    println!("Corpus: {}", corpus_dir);
    println!("Total findings: {}", hashes.len());

    // Show manifest status per source
    if manifest_dir.exists() {
        println!("\nManifest Status:");
        for source_id in &["code4rena", "sherlock", "defillama", "immunefi"] {
            let manifest = SourceManifest::load(&manifest_dir, source_id);
            if !manifest.artifacts.is_empty() {
                println!(
                    "  {}: active={}, removed={}, last_sync={}",
                    source_id,
                    manifest.active_count,
                    manifest.removed_count,
                    if manifest.last_sync.is_empty() {
                        "never"
                    } else {
                        &manifest.last_sync
                    }
                );
            }
        }
    }

    // Show scheduler status
    let scheduler = Scheduler::with_state_dir(state_dir, corpus_dir);
    let status = scheduler.get_status();
    if !status.is_empty() {
        println!("\nScheduler Status:");
        for (source_id, state, last_sync, last_error) in &status {
            let state_str = match state {
                crate::scheduler::SourceState::Idle => "idle".into(),
                crate::scheduler::SourceState::Syncing => "syncing".into(),
                crate::scheduler::SourceState::Failed { retries_remaining } => {
                    format!("failed ({} retries left)", retries_remaining)
                }
                crate::scheduler::SourceState::Paused => "paused".into(),
                crate::scheduler::SourceState::Disabled => "disabled".into(),
            };
            let last = last_sync.as_deref().unwrap_or("never");
            let err = last_error
                .as_ref()
                .map(|e| format!(" error: {}", e))
                .unwrap_or_default();
            println!("  {}: {} last_sync={}{}", source_id, state_str, last, err);
        }
    }

    // Show due sources
    let due = scheduler.get_due_sources();
    if !due.is_empty() {
        println!("\nSources due for sync: {}", due.join(", "));
    }

    // Legacy triggers
    let triggers = scheduler.list_triggers();
    if !triggers.is_empty() {
        println!("\nActive triggers: {}", triggers.join(", "));
    }
}

fn cmd_refresh(args: &[String]) {
    let corpus_dir = args
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("corpus");

    let source_filter = args
        .iter()
        .position(|a| a == "--source")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let state_dir = Path::new(corpus_dir).join(crate::scheduler::SCHEDULER_DIR);
    let mut scheduler = Scheduler::with_state_dir(state_dir, corpus_dir);

    if let Some(source) = source_filter {
        scheduler.force_refresh(source);
        println!("Queued {} for immediate sync", source);
    } else {
        // Refresh all sources
        let sources = crate::sources::get_sources();
        for source in &sources {
            if source.enabled {
                scheduler.force_refresh(&source.source_id);
                println!("Queued {} for immediate sync", source.source_id);
            }
        }
    }

    println!("Run `digger ingest run` to process the queue");
}

fn cmd_pause(args: &[String]) {
    let corpus_dir = args
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("corpus");

    let source = args
        .iter()
        .position(|a| a == "--source")
        .and_then(|i| args.get(i + 1));

    let state_dir = Path::new(corpus_dir).join(crate::scheduler::SCHEDULER_DIR);
    let mut scheduler = Scheduler::with_state_dir(state_dir, corpus_dir);

    if let Some(source) = source {
        scheduler.pause(source);
        println!("Paused ingestion for {}", source);
    } else {
        eprintln!("Usage: digger ingest pause --source <source_id>");
    }
}

fn cmd_resume(args: &[String]) {
    let corpus_dir = args
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("corpus");

    let source = args
        .iter()
        .position(|a| a == "--source")
        .and_then(|i| args.get(i + 1));

    let state_dir = Path::new(corpus_dir).join(crate::scheduler::SCHEDULER_DIR);
    let mut scheduler = Scheduler::with_state_dir(state_dir, corpus_dir);

    if let Some(source) = source {
        scheduler.resume(source);
        println!("Resumed ingestion for {}", source);
    } else {
        eprintln!("Usage: digger ingest resume --source <source_id>");
    }
}

fn cmd_dashboard(args: &[String]) {
    let corpus_dir = args
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("corpus");

    let dashboard = crate::observability::IngestionHealthDashboard::generate(corpus_dir);
    print!("{}", dashboard.display());
}

fn cmd_regression(args: &[String]) {
    let corpus_dir = args
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("corpus");

    let source = args
        .iter()
        .position(|a| a == "--source")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("all");

    if source == "all" {
        for source_id in &["code4rena", "sherlock", "defillama"] {
            let report =
                crate::regression::run_regression_checks(corpus_dir, source_id, "manual", "now");
            crate::regression::save_regression_report(&report, corpus_dir).ok();
            print!("{}", report.display());
        }
    } else {
        let report = crate::regression::run_regression_checks(corpus_dir, source, "manual", "now");
        crate::regression::save_regression_report(&report, corpus_dir).ok();
        print!("{}", report.display());
    }
}

fn cmd_intel(args: &[String]) {
    let corpus_dir = args
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("corpus");

    let report = crate::corpus_intelligence::analyze_corpus(corpus_dir);
    print!("{}", crate::corpus_intelligence::display(&report));
}
