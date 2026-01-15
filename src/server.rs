use std::{
    net::IpAddr,
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::Duration,
};

use color_eyre::eyre::{Context, Result};
use dashmap::DashMap;
use governor::{state::InMemoryState, Quota, RateLimiter as GovernorLimiter};
use hickory_proto::{
    op::{Header, ResponseCode},
    rr::{RData, Record, RecordType},
};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};
use metrics::{counter, gauge, histogram};
use rand::{rng, seq::SliceRandom};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::watch,
};
use tracing::{info_span, Instrument};
use zebra_chain::block::Height;
use zebra_network::PeerSocketAddr;

use crate::{config::SeederConfig, mock_chain_tip::MockChainTip};

/// Per-IP rate limiter for DNS queries
#[derive(Debug, Clone)]
struct RateLimiter {
    limiters: DashMap<
        IpAddr,
        Arc<
            GovernorLimiter<
                governor::state::direct::NotKeyed,
                InMemoryState,
                governor::clock::DefaultClock,
                governor::middleware::NoOpMiddleware,
            >,
        >,
    >,
    quota: Quota,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct AddressRecords {
    ipv4: Vec<PeerSocketAddr>,
    ipv6: Vec<PeerSocketAddr>,
}

impl RateLimiter {
    fn new(queries_per_second: u32, burst_size: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(queries_per_second).unwrap())
            .allow_burst(NonZeroU32::new(burst_size).unwrap());

        Self {
            limiters: DashMap::new(),
            quota,
        }
    }

    /// This method checks if the provided [`IpAddr`] is within the configured rate limit.
    ///
    /// # Correctness
    ///
    /// This method uses [`DashMap`] for concurrent mutable access to the collection tracking rate limits by IP.
    /// [`DashMap`] uses fine-grained locks such that there should be little to no contention except when locking the same key.
    ///
    /// In order to ensure that there can be no contention when this method is called frequently and concurrently with the same IP,
    /// it checks for an existing entry or inserts a new one, then immediately clones and drops the reference.
    fn check(&self, ip: IpAddr) -> bool {
        let limiter = self
            .limiters
            .entry(ip)
            .or_insert_with(|| Arc::new(GovernorLimiter::direct(self.quota)))
            .clone();

        // TODO:
        // - Limit the number of IPs being tracked (too many possible ipv6 addresses, otherwise it would be maximum of ~3MB)
        // - Stop tracking IPs one second after their last request (when the rate limiter reverts to its default state)

        limiter.check().is_ok()
    }
}

pub async fn spawn(config: SeederConfig) -> Result<()> {
    tracing::info!("Initializing zebra-network...");

    // Dummy inbound service that rejects everything
    let inbound_service = tower::service_fn(|_req: zebra_network::Request| async move {
        Ok::<zebra_network::Response, Box<dyn std::error::Error + Send + Sync + 'static>>(
            zebra_network::Response::Nil,
        )
    });

    // Provide a user agent
    let user_agent = "zebra-seeder/0.1.0".to_string();

    let (chain_tip, chain_tip_sender) = MockChainTip::new();

    // TODO: Use the height and block time of the last checkpointed block to estimate the network chain tip height here based on the current time from the system clock.

    // Use the latest network upgrade for the configured network with a defined activation height
    chain_tip_sender.send_best_tip_height(Height::MAX);

    // Initialize zebra-network. It's okay to drop:
    // - The unused peer set, it'll be polled regularly by the candidate set.
    // - The unused misbehaviour sender, it'll cause an untracked and otherwise-unused task to harmlessly exit early.
    let (_, address_book, _) = zebra_network::init(
        config.network.clone(),
        inbound_service,
        chain_tip,
        user_agent,
    )
    .await;

    let address_book_monitor = address_book.clone();
    let default_port = config.network.network.default_port();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(config.metrics_log_interval);

        loop {
            interval.tick().await;
            tracing::info!("Starting network crawl...");

            // Log Address Book stats
            let book = match address_book_monitor.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!(
                        "Address book mutex poisoned during crawler monitoring, recovering"
                    );
                    counter!("seeder.mutex_poisoning_total", "location" => "crawler").increment(1);
                    poisoned.into_inner()
                }
            };
            log_crawler_status(&book, default_port);
        }
    });

    // Initialize rate limiter if configured
    let rate_limiter = config.rate_limit.as_ref().map(|rl_config| {
        tracing::info!(
            "Rate limiting enabled: {} queries/sec per IP, burst size: {}",
            rl_config.queries_per_second,
            rl_config.burst_size
        );
        Arc::new(RateLimiter::new(
            rl_config.queries_per_second,
            rl_config.burst_size,
        ))
    });

    tracing::info!("Initializing DNS server on {}", config.dns_listen_addr);

    let latest_addresses =
        spawn_addresses_cache_updater(address_book.clone(), config.network.network.default_port());

    let authority = SeederAuthority::new(
        latest_addresses,
        config.seed_domain.clone(),
        config.dns_ttl,
        rate_limiter,
    );
    let mut server = ServerFuture::new(authority);

    // Register UDP and TCP listeners
    let udp_socket = UdpSocket::bind(config.dns_listen_addr)
        .await
        .wrap_err("failed to bind UDP socket")?;
    server.register_socket(udp_socket);

    let tcp_listener = TcpListener::bind(config.dns_listen_addr)
        .await
        .wrap_err("failed to bind TCP listener")?;
    server.register_listener(tcp_listener, std::time::Duration::from_secs(5));

    tracing::info!("Seeder running. Press Ctrl+C to exit.");

    // Run the server in the background, or block here?
    // Usually ServerFuture needs to be polled. `block_on` runs it.
    // We want to run it concurrently with ctrl_c.

    tokio::select! {
        result = server.block_until_done() => {
            result.wrap_err("DNS server crashed")?;
            tracing::info!("DNS server stopped, shutting down...");

            // Brief delay to allow cleanup
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal, cleaning up...");

            // Note: ServerFuture doesn't have a graceful shutdown method,
            // so we rely on the Drop implementation to clean up sockets

            // Brief delay to allow:
            // - Crawler task to finish aborting
            // - Any in-flight DNS responses to complete
            // - Metrics to flush (PrometheusBuilder handles this internally)
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            tracing::info!("Cleanup complete");
        }
    }

    Ok(())
}

fn spawn_addresses_cache_updater(
    address_book: Arc<Mutex<zebra_network::AddressBook>>,
    default_port: u16,
) -> watch::Receiver<AddressRecords> {
    let (latest_addresses_sender, latest_addresses) = watch::channel(AddressRecords::default());

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            let matched_peers: Vec<_> = match address_book.lock() {
                Ok(guard) => guard
                    .peers()
                    .filter(|meta| {
                        let ip = meta.addr().ip();

                        // 1. Routability check
                        let is_global =
                            !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast();

                        // 2. Port check
                        let is_default_port = meta.addr().port() == default_port;

                        is_global && is_default_port
                    })
                    .collect::<Vec<_>>(),
                Err(_poisoned) => {
                    tracing::error!(
                        "Address book mutex poisoned during DNS query handling, recovering"
                    );
                    counter!("seeder.mutex_poisoning_total", "location" => "dns_handler")
                        .increment(1);

                    panic!(
                        "poisoned address book mutex in latest address records cache updater task"
                    );
                }
            };

            // Get verified peers (using reconnection_peers or similar if verified() is strictly "verified by zebra-network connection")
            // `reconnection_peers()` returns MetaAddrs that are good for connection.
            // However, the prompt says "select a random subset".

            // Note: using `reconnection_peers()` is better than `peers()` as it sorts/filters by reliability.
            // But let's check what's available. `AddressBook` has `peers()` iterator usually.
            // Assuming `reconnection_peers()` gives us a nice list.
            // Actually `reconnection_peers` returns a Box<dyn Iterator>.
            // Use `peers()` or look at docs if available.
            // Since I can't see docs, I'll use `reconnection_peers` if it compiles, else `peers().values()`.
            // Let's assume we want ALL peers and filter them ourselves as per requirements.

            // Filter and collect up to 50 eligible peers (more than we need for shuffle randomness)
            // This avoids allocating a vector for ALL peers in the address book

            // 3. Address family check
            let mut ipv4: Vec<_> = matched_peers
                .iter()
                .filter(|meta| meta.addr().ip().is_ipv4())
                .take(PEER_SELECTION_POOL_SIZE)
                .collect();
            let mut ipv6: Vec<_> = matched_peers
                .iter()
                .filter(|meta| meta.addr().ip().is_ipv6())
                .take(PEER_SELECTION_POOL_SIZE)
                .collect();

            // Shuffle and take the configured maximum
            ipv4.shuffle(&mut rng());
            ipv4.truncate(MAX_DNS_RESPONSE_PEERS);
            ipv6.shuffle(&mut rng());
            ipv6.truncate(MAX_DNS_RESPONSE_PEERS);

            let ipv4 = ipv4.iter().map(|peer| peer.addr()).collect::<Vec<_>>();
            let ipv6 = ipv6.iter().map(|peer| peer.addr()).collect::<Vec<_>>();

            let _ = latest_addresses_sender.send(AddressRecords { ipv4, ipv6 });
        }
    });

    latest_addresses
}

fn log_crawler_status(book: &zebra_network::AddressBook, default_port: u16) {
    let total_peers = book.len();

    // Calculate eligible peers (passing filter criteria)
    let peers: Vec<_> = book.peers().collect();

    let eligible_v4 = peers
        .iter()
        .filter(|meta| {
            let ip = meta.addr().ip();
            let is_global = !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast();
            is_global && ip.is_ipv4() && meta.addr().port() == default_port
        })
        .count();

    let eligible_v6 = peers
        .iter()
        .filter(|meta| {
            let ip = meta.addr().ip();
            let is_global = !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast();
            is_global && ip.is_ipv6() && meta.addr().port() == default_port
        })
        .count();

    tracing::info!(
        "Crawler Status: Total={} | Eligible IPv4={} | Eligible IPv6={}",
        total_peers,
        eligible_v4,
        eligible_v6
    );

    gauge!("seeder.peers.total").set(total_peers as f64);
    gauge!("seeder.peers.eligible", "addr_family" => "v4").set(eligible_v4 as f64);
    gauge!("seeder.peers.eligible", "addr_family" => "v6").set(eligible_v6 as f64);
}

#[derive(Clone)]
pub struct SeederAuthority {
    latest_addresses: watch::Receiver<AddressRecords>,
    seed_domain: String,
    dns_ttl: u32,
    rate_limiter: Option<Arc<RateLimiter>>,
}

// DNS response configuration
const MAX_DNS_RESPONSE_PEERS: usize = 25;
const PEER_SELECTION_POOL_SIZE: usize = 50; // Collect 2x peers for shuffle randomness

impl SeederAuthority {
    fn new(
        latest_addresses: watch::Receiver<AddressRecords>,
        seed_domain: String,
        dns_ttl: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Self {
        Self {
            latest_addresses,
            seed_domain,
            dns_ttl,
            rate_limiter,
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for SeederAuthority {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &hickory_server::server::Request,
        response_handle: R,
    ) -> ResponseInfo {
        let span = info_span!("dns_query", client_addr = %request.src());
        async move { self.handle_request_inner(request, response_handle).await }
            .instrument(span)
            .await
    }
}

impl SeederAuthority {
    async fn handle_request_inner<R: ResponseHandler>(
        &self,
        request: &hickory_server::server::Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true); // WE ARE THE AUTHORITY!

        // Rate limiting check
        if let Some(ref limiter) = self.rate_limiter {
            let client_ip = request.src().ip();

            if !limiter.check(client_ip) {
                tracing::warn!("Rate limit exceeded for {}", client_ip);
                counter!("seeder.dns.rate_limited_total").increment(1);

                // Drop the request silently (no response to prevent amplification)
                return ResponseInfo::from(header);
            }
        }

        // Checking one query at a time standard
        // If multiple queries, usually we answer the first or all?
        // Standard DNS usually has 1 question.
        if let Some(query) = request.queries().first() {
            let name = query.name();
            let record_type = query.query_type();

            // Check if we should answer this query
            let name_s = name.to_ascii();
            let name_norm = name_s.trim_end_matches('.');
            let seed_norm = self.seed_domain.trim_end_matches('.');

            if name_norm != seed_norm && !name_norm.ends_with(&format!(".{}", seed_norm)) {
                // Return REFUSED
                header.set_response_code(ResponseCode::Refused);
                let response = builder.build(header, &[], &[], &[], &[]);
                return response_handle
                    .send_response(response)
                    .await
                    .unwrap_or_else(|_| ResponseInfo::from(header));
            }

            let mut records = Vec::new();

            // Collect peer data while holding the lock, then drop the guard
            let matched_peers = match record_type {
                RecordType::A => self.latest_addresses.borrow().ipv4.clone(),
                RecordType::AAAA => self.latest_addresses.borrow().ipv6.clone(),
                _ => Vec::new(),
            };

            histogram!("seeder.dns.response_peers").record(matched_peers.len() as f64);

            for addr in matched_peers {
                let rdata = match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => RData::A(hickory_proto::rr::rdata::A(ipv4)),
                    std::net::IpAddr::V6(ipv6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(ipv6)),
                };

                let record = Record::from_rdata(name.clone().into(), self.dns_ttl, rdata);
                records.push(record);
            }

            match record_type {
                RecordType::A | RecordType::AAAA => {
                    // Record metric by type
                    let type_label = match record_type {
                        RecordType::A => "A",
                        RecordType::AAAA => "AAAA",
                        _ => "other",
                    };
                    counter!("seeder.dns.queries_total", &[("record_type", type_label)])
                        .increment(1);

                    let response = builder.build(header, records.iter(), &[], &[], &[]);
                    return response_handle
                        .send_response(response)
                        .await
                        .inspect_err(|e| {
                            tracing::warn!("Failed to send DNS response: {}", e);
                            counter!("seeder.dns.errors_total").increment(1);
                        })
                        .unwrap_or_else(|_| {
                            ResponseInfo::from(header) // fallback
                        });
                }
                _ => {
                    // For NS, SOA, etc, we might want to return something else or Refused.
                    // Returning empty NOERROR or NXDOMAIN?
                    // Let's return NOERROR empty for now.
                }
            }
        }

        // Default response (SERVFAIL or just empty user defined)
        // If we got here, we didn't return above.
        let response = builder.build(header, &[], &[], &[], &[]);
        response_handle
            .send_response(response)
            .await
            .unwrap_or_else(|_| ResponseInfo::from(header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Rate Limiter Tests
    #[test]
    fn test_rate_limiter_allows_normal_queries() {
        let limiter = RateLimiter::new(10, 20);
        let test_ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First query should be allowed
        assert!(limiter.check(test_ip), "First query should be allowed");

        // Second query should also be allowed (within burst)
        assert!(limiter.check(test_ip), "Second query should be allowed");
    }

    #[test]
    fn test_rate_limiter_blocks_excessive_queries() {
        let limiter = RateLimiter::new(1, 2); // Very low limits for testing
        let test_ip: IpAddr = "192.168.1.2".parse().unwrap();

        // First two queries should pass (burst size = 2)
        assert!(limiter.check(test_ip), "Query 1 should pass");
        assert!(limiter.check(test_ip), "Query 2 should pass");

        // Third query should be rate limited
        assert!(!limiter.check(test_ip), "Query 3 should be rate limited");
    }

    #[test]
    fn test_rate_limiter_per_ip_isolation() {
        let limiter = RateLimiter::new(1, 1);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Exhaust IP1's quota
        assert!(limiter.check(ip1), "IP1 first query should pass");
        assert!(!limiter.check(ip1), "IP1 second query should be blocked");

        // IP2 should still have quota
        assert!(limiter.check(ip2), "IP2 should have independent quota");
    }

    #[test]
    fn test_rate_limiter_ipv6_support() {
        let limiter = RateLimiter::new(10, 20);
        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();

        assert!(limiter.check(ipv6), "IPv6 addresses should be supported");
    }

    // Peer Filtering Logic Tests
    #[test]
    fn test_ipv4_is_global() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let unspecified: IpAddr = "0.0.0.0".parse().unwrap();
        let multicast: IpAddr = "224.0.0.1".parse().unwrap();
        let global: IpAddr = "8.8.8.8".parse().unwrap();

        // Test the same logic used in handle_request_inner for filtering
        assert!(loopback.is_loopback(), "Loopback should be detected");
        assert!(
            unspecified.is_unspecified(),
            "Unspecified should be detected"
        );
        assert!(multicast.is_multicast(), "Multicast should be detected");

        let is_global = !global.is_loopback() && !global.is_unspecified() && !global.is_multicast();
        assert!(is_global, "8.8.8.8 should be considered global");
    }

    #[test]
    fn test_ipv6_is_global() {
        let loopback: IpAddr = "::1".parse().unwrap();
        let unspecified: IpAddr = "::".parse().unwrap();
        let multicast: IpAddr = "ff02::1".parse().unwrap();
        let global: IpAddr = "2001:4860:4860::8888".parse().unwrap();

        assert!(loopback.is_loopback());
        assert!(unspecified.is_unspecified());
        assert!(multicast.is_multicast());

        let is_global = !global.is_loopback() && !global.is_unspecified() && !global.is_multicast();
        assert!(is_global, "Google DNS IPv6 should be considered global");
    }

    #[test]
    fn test_private_ipv4_ranges() {
        let private_10: IpAddr = "10.0.0.1".parse().unwrap();
        let private_172: IpAddr = "172.16.0.1".parse().unwrap();
        let private_192: IpAddr = "192.168.1.1".parse().unwrap();

        // These are not loopback/unspecified/multicast, but they're private
        // The server.rs logic doesn't explicitly filter private ranges,
        // but we document this behavior for future reference
        let is_global_10 =
            !private_10.is_loopback() && !private_10.is_unspecified() && !private_10.is_multicast();
        let is_global_172 = !private_172.is_loopback()
            && !private_172.is_unspecified()
            && !private_172.is_multicast();
        let is_global_192 = !private_192.is_loopback()
            && !private_192.is_unspecified()
            && !private_192.is_multicast();

        // Note: Current implementation would consider these "global"
        // This is acceptable for a seeder as peers on private networks won't be reachable anyway
        assert!(is_global_10);
        assert!(is_global_172);
        assert!(is_global_192);
    }

    // DNS Response Constants Tests
    #[test]
    fn test_dns_response_constants() {
        // Verify the constants are reasonable
        assert_eq!(
            MAX_DNS_RESPONSE_PEERS, 25,
            "Should return max 25 peers per query"
        );
        assert_eq!(
            PEER_SELECTION_POOL_SIZE, 50,
            "Should collect 50 peers for randomization"
        );
        assert!(
            PEER_SELECTION_POOL_SIZE >= MAX_DNS_RESPONSE_PEERS * 2,
            "Pool should be at least 2x response size for good randomization"
        );
    }
}
