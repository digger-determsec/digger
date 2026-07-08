use digger_api::Config;

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    let app = digger_api::create_app(&config);

    match std::env::var("DIGGER_API_KEY") {
        Ok(k) if !k.is_empty() => {
            println!("Auth: API key configured (all requests require X-API-Key header)");
        }
        _ => {
            eprintln!(
                "FATAL: DIGGER_API_KEY is not set or empty.\n\
                 All API requests will be DENIED (fail-closed).\n\
                 Set DIGGER_API_KEY to a strong secret to start the server."
            );
            std::process::exit(1);
        }
    }

    println!("Digger API listening on {}", config.bind_addr);
    println!("Health: http://{}/api/v1/health", config.bind_addr);
    println!("Version: http://{}/api/v1/version", config.bind_addr);
    println!("Press Ctrl+C to shut down gracefully");

    let listener = match tokio::net::TcpListener::bind(&config.bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {}: {}", config.bind_addr, e);
            std::process::exit(1);
        }
    };

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );
    let graceful = server.with_graceful_shutdown(shutdown_signal());

    if let Err(e) = graceful.await {
        eprintln!("Server error: {}", e);
    }
    println!("Server shut down gracefully");
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Warning: failed to install SIGTERM handler: {}", e);
                    ctrl_c.await.ok();
                    return;
                }
            };
        tokio::select! {
            _ = ctrl_c => { println!("\nReceived Ctrl+C"); }
            _ = sigterm.recv() => { println!("\nReceived SIGTERM"); }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        println!("\nReceived Ctrl+C");
    }
}
