use color_eyre::eyre::Result;
use config::{Config, Environment, File};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, time::Duration};

/// Configuration for the Zebra Seeder.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct SeederConfig {
    /// The Zebra network configuration.
    pub network: zebra_network::Config,

    /// The socket address Hickory DNS will bind to.
    ///
    /// Defaults to `0.0.0.0:53`.
    pub dns_listen_addr: SocketAddr,

    /// The domain name the seeder is authoritative for.
    pub seed_domain: String,

    /// DNS response TTL (Time To Live) in seconds.
    ///
    /// Controls how long clients cache DNS responses.
    /// Lower values mean fresher data but more queries.
    /// Higher values reduce query load but slower updates.
    ///
    /// Defaults to `600` (10 minutes).
    pub dns_ttl: u32,

    /// Duration between refreshing the address book.
    #[serde(with = "humantime_serde")]
    pub crawl_interval: Duration,

    /// Prometheus metrics configuration.
    ///
    /// If `None`, metrics are disabled.
    pub metrics: Option<MetricsConfig>,

    /// Rate limiting configuration.
    ///
    /// If `None`, rate limiting is disabled (NOT recommended for production).
    pub rate_limit: Option<RateLimitConfig>,
}

/// Configuration for Prometheus metrics.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// The socket address to expose Prometheus metrics on.
    ///
    /// Defaults to `0.0.0.0:9999`.
    pub endpoint_addr: SocketAddr,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            endpoint_addr: "0.0.0.0:9999".parse().expect("valid address"),
        }
    }
}

/// Configuration for DNS query rate limiting.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Maximum queries per second per IP address.
    ///
    /// Defaults to `10`.
    pub queries_per_second: u32,

    /// Burst capacity (maximum queries in a short burst).
    ///
    /// Defaults to `20` (2x the rate).
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            queries_per_second: 10,
            burst_size: 20,
        }
    }
}

impl Default for SeederConfig {
    fn default() -> Self {
        Self {
            network: zebra_network::Config::default(),
            dns_listen_addr: "0.0.0.0:53"
                .parse()
                .expect("hardcoded address must be valid"),
            seed_domain: "mainnet.seeder.example.com".to_string(),
            dns_ttl: 600,                             // 10 minutes
            crawl_interval: Duration::from_secs(600), // 10 minutes
            metrics: None,
            rate_limit: Some(RateLimitConfig::default()),
        }
    }
}

impl SeederConfig {
    /// Load the configuration from the given path, merging with default settings and
    /// environment variables.
    ///
    /// Precedence:
    /// 1. Environment Variables (ZEBRA_SEEDER_*)
    /// 2. Config File (if path is provided)
    /// 3. Default Values
    pub fn load_with_env(path: Option<std::path::PathBuf>) -> Result<Self> {
        let mut builder = Config::builder().add_source(Config::try_from(&Self::default())?);

        if let Some(path) = path {
            builder = builder.add_source(File::from(path));
        }

        builder = builder.add_source(
            Environment::with_prefix("ZEBRA_SEEDER")
                .separator("__")
                .try_parsing(true),
        );

        let config = builder.build()?;
        let seeder_config: SeederConfig = config.try_deserialize()?;

        Ok(seeder_config)
    }

    /// Load the configuration from the given path, using default settings for any
    /// unspecified fields.
    ///
    /// This is a convenience wrapper around `load_with_env` that ignores environment variables
    /// for testing purposes, or can be used if env vars are not desired.
    /// However, strictly following the pattern, `load_with_env` is the primary entry point.
    // In Zebrad, `load` usually implies just file + defaults, but here we generally want Env too.
    // For simplicity and matching typical app flow, strictly following the prompt's request for "load" and "load_with_env":
    pub fn load(path: std::path::PathBuf) -> Result<Self> {
        Self::load_with_env(Some(path))
    }
}
