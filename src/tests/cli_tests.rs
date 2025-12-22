use crate::commands::SeederApp;
use clap::Parser;

#[test]
fn test_cli_parsing_default() {
    let args = vec!["zebra-seeder", "start"];
    let app = SeederApp::try_parse_from(args).expect("should parse");
    match app.command {
        crate::commands::Commands::Start => {}
    }
    assert_eq!(app.verbose, "info");
    assert!(app.config.is_none());
}

#[test]
fn test_cli_parsing_with_config() {
    let args = vec![
        "zebra-seeder",
        "--config",
        "/path/to/config.toml",
        "--verbose",
        "debug",
        "start",
    ];
    let app = SeederApp::try_parse_from(args).expect("should parse");
    assert_eq!(
        app.config.unwrap().to_str().unwrap(),
        "/path/to/config.toml"
    );
    assert_eq!(app.verbose, "debug");
}

#[test]
fn test_cli_parsing_args_after_subcommand() {
    let args = vec!["zebra-seeder", "start", "--verbose", "debug"];
    let app = SeederApp::try_parse_from(args).expect("should parse");
    assert_eq!(app.verbose, "debug");
}
