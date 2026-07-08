#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

#[tokio::main]
async fn main() {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:3000").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind: {e}");
            std::process::exit(1);
        }
    };
    println!("digger-server listening on 127.0.0.1:3000");
    let app = digger_server::app_defaults();
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("server failed: {e}");
        std::process::exit(1);
    }
}
