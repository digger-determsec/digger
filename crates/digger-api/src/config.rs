/// API server configuration.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub cors_origins: Vec<String>,
    pub enable_logging: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let host = std::env::var("DIGGER_API_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port = std::env::var("DIGGER_API_PORT").unwrap_or_else(|_| "3000".into());
        let bind_addr: SocketAddr = match format!("{}:{}", host, port).parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!(
                    "WARNING: Invalid DIGGER_API_PORT '{}', falling back to 127.0.0.1:3000 ({})",
                    port, e
                );
                DEFAULT_BIND
            }
        };

        Self {
            bind_addr,
            cors_origins: vec!["*".into()],
            enable_logging: true,
        }
    }
}
