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
    // but `load_with_env(None)` loads defaults + env.
    let config = SeederConfig::load_with_env(None).expect("should load");
    
    assert_eq!(config.seed_domain, "test.example.com");
    // "30s" string is parsed by humantime-serde
    assert_eq!(config.crawl_interval, Duration::from_secs(30)); 
    
    // Clean up
    env::remove_var("ZEBRA_SEEDER__SEED_DOMAIN");
    env::remove_var("ZEBRA_SEEDER__CRAWL_INTERVAL");
}
