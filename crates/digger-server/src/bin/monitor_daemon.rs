#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::sync::Arc;

#[tokio::main]
async fn main() {
    let db_path = std::env::var("DIGGER_DB_PATH").unwrap_or_else(|_| "digger.db".into());
    let poll_secs: u64 = std::env::var("DIGGER_MONITOR_POLL_SECS")
        .unwrap_or_else(|_| "60".into())
        .parse()
        .unwrap_or(60);

    println!(
        "digger-monitor-daemon starting, DB: {}, poll: {}s",
        db_path, poll_secs
    );

    let _conn = match digger_server::auth::init_db(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to init DB: {e}");
            std::process::exit(1);
        }
    };
    let evidence: Arc<dyn digger_evidence::EvidenceStore> =
        Arc::new(digger_evidence::InMemoryStore::new());
    let audit = Arc::new(digger_runtime::InMemoryAuditStore::new());
    let approvals = Arc::new(digger_runtime::ApprovalService::new(3600));
    let broker = Arc::new(digger_runtime::CredentialBroker::new(300));
    let connectors = std::collections::BTreeMap::new();

    let source = digger_monitor::source::MockMonitorSource::new(vec![]);
    let store = Arc::new(digger_monitor::store::InMemoryMonitorStore::new());
    let gw = Arc::new(digger_runtime::ActionGateway::new(
        digger_runtime::Policy::default(),
        evidence.clone(),
        audit,
        approvals,
        broker,
        connectors,
    ));

    let clock = Arc::new(digger_monitor::clock::RealClock);
    let history = Arc::new(digger_monitor::history::InMemoryHistoryStore::new());
    let mon = digger_monitor::monitor::Monitor::new(source, store, gw, evidence);
    let mut daemon = digger_monitor::daemon::MonitorDaemon::new(mon, clock, history);

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx.send(());
    });

    println!("digger-monitor-daemon running. Press Ctrl+C to stop.");

    let mut shutdown_rx = shutdown_rx;
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                println!("Shutting down daemon...");
                break;
            }
            _ = async {
                let _summary = daemon.run_once();
                tokio::time::sleep(tokio::time::Duration::from_secs(poll_secs)).await;
            } => {}
        }
    }

    println!("digger-monitor-daemon stopped.");
}
