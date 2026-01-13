use crate::config::SeederConfig;
use config::FileFormat;
use std::env;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_env_lock<F>(f: F)
where
    F: FnOnce(),
{
    let mutex = ENV_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = mutex.lock().unwrap_or_else(|e| e.into_inner());
    f();
}

#[test]
fn test_default_config() {
    let config = SeederConfig::default();
    assert_eq!(config.dns_listen_addr.to_string(), "0.0.0.0:53");
    assert_eq!(config.seed_domain, "mainnet.seeder.example.com");
    assert_eq!(config.dns_ttl, 600);
    assert_eq!(config.crawl_interval, Duration::from_secs(600));
}

#[test]
fn test_env_overrides() {
    with_env_lock(|| {
        env::set_var("ZEBRA_SEEDER__SEED_DOMAIN", "test.example.com");
        env::set_var("ZEBRA_SEEDER__CRAWL_INTERVAL", "5m");

        let config = SeederConfig::load_with_env(None).expect("should load");

        assert_eq!(config.seed_domain, "test.example.com");
        assert_eq!(config.crawl_interval, std::time::Duration::from_secs(300));

        // Clean up
        env::remove_var("ZEBRA_SEEDER__SEED_DOMAIN");
        env::remove_var("ZEBRA_SEEDER__CRAWL_INTERVAL");
    });
}

#[test]
fn test_config_loading_from_env_overrides_network() {
    with_env_lock(|| {
        // Set environment variables
        std::env::set_var("ZEBRA_SEEDER__NETWORK__NETWORK", "Testnet");
        std::env::set_var("ZEBRA_SEEDER__DNS_LISTEN_ADDR", "0.0.0.0:1053");

        let config = SeederConfig::load_with_env(None).expect("should load");

        assert_eq!(config.network.network.to_string(), "Testnet");
        assert_eq!(config.dns_listen_addr.port(), 1053);

        // Clean up
        env::remove_var("ZEBRA_SEEDER__NETWORK__NETWORK");
        env::remove_var("ZEBRA_SEEDER__DNS_LISTEN_ADDR");
    });
}

#[test]
fn test_crawl_interval_parsing() {
    // Determine parsing logic without relying on Env Vars (avoiding races)
    // We demonstrate that humantime_serde works via TOML source string

    // We can't easily load partial config into SeederConfig without valid structure,
    // but SeederConfig::load_with_env loads defaults first.
    // Let's mimic what we want: override just command interval using a File source.

    let config_res = config::Config::builder()
        .add_source(config::Config::try_from(&SeederConfig::default()).unwrap())
        .add_source(config::File::from_str(
            "crawl_interval = '1h 30m'",
            FileFormat::Toml,
        ))
        .build();

    let config: SeederConfig = config_res
        .expect("build")
        .try_deserialize()
        .expect("deserialize");
    assert_eq!(config.crawl_interval, Duration::from_secs(5400));

    let config_res2 = config::Config::builder()
        .add_source(config::Config::try_from(&SeederConfig::default()).unwrap())
        .add_source(config::File::from_str(
            "crawl_interval = '10s'",
            FileFormat::Toml,
        ))
        .build();
    let config2: SeederConfig = config_res2
        .expect("build")
        .try_deserialize()
        .expect("deserialize");
    assert_eq!(config2.crawl_interval, Duration::from_secs(10));
}

#[test]
fn test_network_config_defaults() {
    // Verify default network config logic through SeederConfig
    let config = SeederConfig::default();
    // Zebra network default listening port depends on network, but here we check our config wrapper defaults
    // basic checks
    assert_eq!(config.network.network.to_string(), "Mainnet");
}

#[test]
fn test_dns_ttl_from_env() {
    with_env_lock(|| {
        env::set_var("ZEBRA_SEEDER__DNS_TTL", "300");

        let config = SeederConfig::load_with_env(None).expect("should load");

        assert_eq!(config.dns_ttl, 300);

        // Clean up
        env::remove_var("ZEBRA_SEEDER__DNS_TTL");
    });
}
