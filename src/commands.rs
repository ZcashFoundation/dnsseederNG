use crate::config::SeederConfig;
use clap::{Parser, Subcommand};
use color_eyre::eyre::{Context, Result};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(author, version, about = "Zcash DNS Seeder", long_about = None)]
pub struct SeederApp {
    /// Path to configuration file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Filter for tracing events (e.g. "info", "debug")
    #[arg(short, long, default_value = "info", global = true)]
    pub verbose: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the DNS seeder
    Start,
}

impl SeederApp {
    pub async fn run() -> Result<()> {
        let app = SeederApp::parse();

        // Initialize tracing
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(&app.verbose))
            .with(tracing_subscriber::fmt::layer())
            .init();

        match app.command {
            Commands::Start => {
                let config = SeederConfig::load_with_env(app.config)
                    .wrap_err("failed to load configuration")?;

                info!("Starting zebra-seeder with config: {:?}", config);

                // TODO: Initialize Async Skeleton & DNS Handler in next step
                // For now, just keep the process alive or exit
                crate::server::spawn(config).await?;
            }
        }

        Ok(())
    }
}
