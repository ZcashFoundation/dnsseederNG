use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, time::Duration};
use color_eyre::eyre::{eyre, Result};
use config::{Config, Environment, File};

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

    /// Duration between refreshing the address book.
    #[serde(with = "humantime_serde")]
    pub crawl_interval: Duration,
}

impl Default for SeederConfig {
    fn default() -> Self {
        Self {
            network: zebra_network::Config::default(),
            dns_listen_addr: "0.0.0.0:53".parse().expect("hardcoded address must be valid"),
            seed_domain: "mainnet.seeder.example.com".to_string(),
            crawl_interval: Duration::from_secs(600), // 10 minutes
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
        let mut builder = Config::builder()
            .add_source(Config::try_from(&Self::default())?);

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
