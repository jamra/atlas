use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub mode: ProxyMode,
    /// Number of worker threads (defaults to number of CPU cores)
    pub workers: Option<usize>,
    /// Document root for static file serving
    pub root: Option<String>,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file (PEM format)
    pub cert: String,
    /// Path to private key file (PEM format)
    pub key: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// Raw TCP proxying - one upstream connection per client connection
    Tcp,
    /// HTTP/1.1 aware - multiplexes requests over pooled connections
    #[default]
    Http,
    /// Static file serving with sendfile() zero-copy
    Static,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Upstream {
    pub name: String,
    pub address: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheck {
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RoutingConfig {
    #[serde(default = "default_strategy")]
    pub strategy: Strategy,
    #[cfg(feature = "lua")]
    pub lua_script: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    Random,
    IpHash,
    #[cfg(feature = "lua")]
    Lua,
}

fn default_weight() -> u32 {
    1
}

fn default_strategy() -> Strategy {
    Strategy::RoundRobin
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
