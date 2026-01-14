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

                if let Some(ref metrics_config) = config.metrics {
                    crate::metrics::init(metrics_config.endpoint_addr)?;
                }

                crate::server::spawn(config).await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_structure() {
        // Verify the CLI can be built without errors
        let cmd = SeederApp::command();
        assert_eq!(cmd.get_name(), "zebra-seeder");
    }

    #[test]
    fn test_start_command_exists() {
        let cmd = SeederApp::command();
        let subcommands: Vec<_> = cmd.get_subcommands().map(|s| s.get_name()).collect();
        assert!(
            subcommands.contains(&"start"),
            "Should have 'start' subcommand"
        );
    }

    #[test]
    fn test_config_option_exists() {
        let cmd = SeederApp::command();
        let config_arg = cmd.get_arguments().find(|a| a.get_id() == "config");
        assert!(config_arg.is_some(), "Should have --config option");
    }

    #[test]
    fn test_verbose_option_default() {
        let cmd = SeederApp::command();
        let verbose_arg = cmd.get_arguments().find(|a| a.get_id() == "verbose");
        assert!(verbose_arg.is_some(), "Should have --verbose option");
    }

    #[test]
    fn test_parse_start_command() {
        // Test parsing the start command
        let result = SeederApp::try_parse_from(&["zebra-seeder", "start"]);
        assert!(result.is_ok(), "Should parse 'start' command successfully");

        if let Ok(app) = result {
            assert!(matches!(app.command, Commands::Start));
        }
    }

    #[test]
    fn test_parse_with_config_path() {
        let result = SeederApp::try_parse_from(&[
            "zebra-seeder",
            "--config",
            "/path/to/config.toml",
            "start",
        ]);
        assert!(result.is_ok(), "Should parse with --config option");

        if let Ok(app) = result {
            assert!(app.config.is_some());
            assert_eq!(
                app.config.unwrap().to_str().unwrap(),
                "/path/to/config.toml"
            );
        }
    }

    #[test]
    fn test_parse_with_verbose() {
        let result = SeederApp::try_parse_from(&["zebra-seeder", "--verbose", "debug", "start"]);
        assert!(result.is_ok(), "Should parse with --verbose option");

        if let Ok(app) = result {
            assert_eq!(app.verbose, "debug");
        }
    }
}
