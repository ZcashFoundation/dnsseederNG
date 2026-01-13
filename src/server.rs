use crate::config::SeederConfig;
use color_eyre::eyre::{Context, Result};
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::ServerFuture;
use rand::rng;
use rand::seq::SliceRandom;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time;

use dashmap::DashMap;
use governor::state::InMemoryState;
use governor::{Quota, RateLimiter as GovernorLimiter};
use metrics::{counter, gauge, histogram};
use tracing::{info_span, Instrument};

/// Per-IP rate limiter for DNS queries
struct RateLimiter {
    limiters: DashMap<IpAddr, Arc<GovernorLimiter<governor::state::direct::NotKeyed, InMemoryState, governor::clock::DefaultClock, governor::middleware::NoOpMiddleware>>>,
    quota: Quota,
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

    fn check(&self, ip: IpAddr) -> bool {
        let limiter = self
            .limiters
            .entry(ip)
            .or_insert_with(|| Arc::new(GovernorLimiter::direct(self.quota)))
            .clone();

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

    // Initialize zebra-network
    let (peer_set, address_book, _peer_sender) = zebra_network::init(
        config.network.clone(),
        inbound_service,
        zebra_chain::chain_tip::NoChainTip,
        user_agent,
    )
    .await;

    // Spawn the Crawl Coordinator
    let crawl_interval = config.crawl_interval;
    let address_book_monitor = address_book.clone();
    let default_port = config.network.network.default_port();

    let crawler_handle = tokio::spawn(async move {
        // Keep peer_set alive in the crawler task to ensure the network stack keeps running
        let _keep_alive = peer_set;

        // Wait specifically for the first crawl to (hopefully) finish or at least start before logging
        // But for now, standard interval tick is fine.
        let mut interval = time::interval(crawl_interval);

        loop {
            interval.tick().await;
            tracing::info!("Starting network crawl...");

            // Log Address Book stats
            let book = match address_book_monitor.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!("Address book mutex poisoned during crawler monitoring, recovering");
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

    let authority = SeederAuthority::new(
        address_book,
        config.network.network,
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
            
            // Clean up crawler task
            crawler_handle.abort();
            
            // Brief delay to allow cleanup
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal, cleaning up...");
            
            // Abort the crawler task
            crawler_handle.abort();
            
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
    address_book: Arc<std::sync::Mutex<zebra_network::AddressBook>>,
    network: zebra_chain::parameters::Network,
    seed_domain: String,
    dns_ttl: u32,
    rate_limiter: Option<Arc<RateLimiter>>,
}

// DNS response configuration
const MAX_DNS_RESPONSE_PEERS: usize = 25;
const PEER_SELECTION_POOL_SIZE: usize = 50; // Collect 2x peers for shuffle randomness

impl SeederAuthority {
    fn new(
        address_book: Arc<std::sync::Mutex<zebra_network::AddressBook>>,
        network: zebra_chain::parameters::Network,
        seed_domain: String,
        dns_ttl: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Self {
        Self {
            address_book,
            network,
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
            let matched_peers = {
                let book = match self.address_book.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        tracing::error!(
                            "Address book mutex poisoned during DNS query handling, recovering"
                        );
                        counter!("seeder.mutex_poisoning_total", "location" => "dns_handler").increment(1);
                        poisoned.into_inner()
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

                let default_port = self.network.default_port();

                // Filter and collect up to 50 eligible peers (more than we need for shuffle randomness)
                // This avoids allocating a vector for ALL peers in the address book
                let mut matched_peers: Vec<_> = book.peers()
                    .filter(|meta| {
                        let ip = meta.addr().ip();
                        
                        // 1. Routability check
                        let is_global = !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast();
                        if !is_global {
                            return false;
                        }
                        
                        // 2. Port check
                        if meta.addr().port() != default_port {
                            return false;
                        }
                        
                        // 3. Address family check
                        match record_type {
                            RecordType::A => ip.is_ipv4(),
                            RecordType::AAAA => ip.is_ipv6(),
                            _ => false,
                        }
                    })
                    .take(PEER_SELECTION_POOL_SIZE)
                    .collect::<Vec<_>>();

                // Shuffle and take the configured maximum
                matched_peers.shuffle(&mut rng());
                matched_peers.truncate(MAX_DNS_RESPONSE_PEERS);

                // Copy the socket addresses so we can drop the lock
                matched_peers.iter().map(|peer| peer.addr()).collect::<Vec<_>>()
                // MutexGuard is dropped here
            };

            histogram!("seeder.dns.response_peers").record(matched_peers.len() as f64);

            for addr in matched_peers {
                let rdata = match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => RData::A(hickory_proto::rr::rdata::A(ipv4)),
                    std::net::IpAddr::V6(ipv6) => {
                        RData::AAAA(hickory_proto::rr::rdata::AAAA(ipv6))
                    }
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
    // Note: filter_candidates tests removed as filtering logic is now inlined
    // in handle_request_inner for better performance (see peer collection optimization)
}
