use std::time::Duration;
use serde::{Deserialize, Serialize};
use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(name = "pulsar-kepler-demo")]
#[command(about = "Real-Time Vulnerable Process Detection Demo")]
pub struct Args {
    /// Kepler API base URL
    #[arg(long, default_value = "http://localhost:8000")]
    pub kepler_url: String,

    /// Web server host
    #[arg(long, default_value = "localhost")]
    pub host: String,

    /// Web server port
    #[arg(short, long, default_value = "3000")]
    pub port: u16,

    /// Minimum CVSS score for alerts
    #[arg(long, default_value = "7.0")]
    pub min_cvss_score: f64,

    /// Cache TTL in seconds
    #[arg(long, default_value = "3600")]
    pub cache_ttl: u64,

    /// Log level
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Run test mode
    #[arg(long)]
    pub test: bool,

    /// Disable caching for demo purposes
    #[arg(long)]
    pub no_cache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub kepler: KeplerConfig,
    pub server: ServerConfig,
    pub detection: DetectionConfig,
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeplerConfig {
    pub base_url: String,
    pub timeout: Duration,
    pub retry_attempts: u32,
    pub retry_delay: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub min_cvss_score: f64,
    pub cache_ttl: Duration,
    pub max_cache_size: u64,
    pub monitored_processes: Vec<String>,
    pub enable_cache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub scan_interval: Duration,
    pub max_recent_events: usize,
    pub enable_process_scan: bool,
    pub enable_mock_events: bool,
}

impl From<Args> for Config {
    fn from(args: Args) -> Self {
        Self {
            kepler: KeplerConfig {
                base_url: args.kepler_url,
                timeout: Duration::from_secs(10),
                retry_attempts: 3,
                retry_delay: Duration::from_millis(500),
            },
            server: ServerConfig {
                host: args.host,
                port: args.port,
                max_connections: 100,
            },
            detection: DetectionConfig {
                min_cvss_score: args.min_cvss_score,
                cache_ttl: Duration::from_secs(args.cache_ttl),
                max_cache_size: 1000,
                enable_cache: !args.no_cache,
                monitored_processes: vec![
                    "nginx".to_string(),
                    "apache".to_string(),
                    "apache2".to_string(),
                    "sshd".to_string(),
                    "mysqld".to_string(),
                    "postgres".to_string(),
                    "node".to_string(),
                    "python".to_string(),
                    "python3".to_string(),
                    "java".to_string(),
                ],
            },
            monitoring: MonitoringConfig {
                scan_interval: Duration::from_secs(5),
                max_recent_events: 100,
                enable_process_scan: true,
                enable_mock_events: true,
            },
        }
    }
}

impl Config {
    pub fn should_monitor_process(&self, process_name: &str) -> bool {
        if self.detection.monitored_processes.is_empty() {
            return true;
        }
        
        self.detection.monitored_processes
            .iter()
            .any(|pattern| process_name.contains(pattern))
    }
}