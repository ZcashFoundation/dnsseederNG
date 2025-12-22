use crate::config::SeederConfig;
use std::env;
use std::time::Duration;

#[test]
fn test_default_config() {
    let config = SeederConfig::default();
    assert_eq!(config.dns_listen_addr.to_string(), "0.0.0.0:53");
    assert_eq!(config.seed_domain, "mainnet.seeder.example.com");
    assert_eq!(config.crawl_interval, Duration::from_secs(600));
}

#[test]
fn test_env_overrides() {
    // Save original env to restore later (though tests run in parallel, this is flaky if not careful. 
    // Ideally use `figment` or just run this test in isolation, but standard rust `env::set_var` is process global.)
    // For this scaffolding, we'll try to use a unique prefix or just set and unset.
    
    env::set_var("ZEBRA_SEEDER__SEED_DOMAIN", "test.example.com");
    env::set_var("ZEBRA_SEEDER__CRAWL_INTERVAL", "30s");
    
    // We can't really pass "None" path to `load_with_env` if we want JUST env, 
    std::env::set_var("ZEBRA_SEEDER__CRAWL_INTERVAL", "5m");
    
    let config = SeederConfig::load_with_env(None).expect("should load");
    
    assert_eq!(config.seed_domain, "test.example.com");
    assert_eq!(config.crawl_interval, std::time::Duration::from_secs(300));
    
    // Clean up
    env::remove_var("ZEBRA_SEEDER__SEED_DOMAIN");
    env::remove_var("ZEBRA_SEEDER__CRAWL_INTERVAL");
}

#[test]
fn test_config_loading_from_env_overrides_network() {
    // Set environment variables
    std::env::set_var("ZEBRA_SEEDER__NETWORK__NETWORK", "Testnet");
    std::env::set_var("ZEBRA_SEEDER__DNS_LISTEN_ADDR", "0.0.0.0:1053");
    
    let config = SeederConfig::load_with_env(None).expect("should load");
    
    assert_eq!(config.network.network.to_string(), "Testnet");
    assert_eq!(config.dns_listen_addr.port(), 1053);
}
