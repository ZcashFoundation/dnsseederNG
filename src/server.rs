use crate::config::SeederConfig;
use color_eyre::eyre::{Context, Result};
use hickory_proto::op::Header;
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::ServerFuture;
use rand::rng;
use rand::seq::SliceRandom;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time;

use metrics::{counter, gauge, histogram};
use tracing::{info_span, Instrument};

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

    let _crawler_handle = tokio::spawn(async move {
        // Keep peer_set alive in the crawler task to ensure the network stack keeps running
        let _keep_alive = peer_set;

        // Wait specifically for the first crawl to (hopefully) finish or at least start before logging
        // But for now, standard interval tick is fine.
        let mut interval = time::interval(crawl_interval);

        loop {
            interval.tick().await;
            tracing::info!("Starting network crawl...");

            // Log Address Book stats
            if let Ok(book) = address_book_monitor.lock() {
                log_crawler_status(&book, default_port);
            } else {
                tracing::warn!("Failed to lock address book for monitoring");
            }
        }
    });

    tracing::info!("Initializing DNS server on {}", config.dns_listen_addr);

    let authority = SeederAuthority::new(address_book, config.network.network);
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
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutting down...");
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
}

impl SeederAuthority {
    fn new(
        address_book: Arc<std::sync::Mutex<zebra_network::AddressBook>>,
        network: zebra_chain::parameters::Network,
    ) -> Self {
        Self {
            address_book,
            network,
        }
    }

    fn filter_candidates<P: PeerAddress>(
        candidates: Vec<&P>,
        record_type: RecordType,
        default_port: u16,
    ) -> Vec<&P> {
        candidates
            .into_iter()
            .filter(|meta| {
                // 1. Routability
                let ip = meta.addr().ip();

                // Basic globality check
                // (We can assume zebra-network filters out private IPs mostly, but good to check)
                let is_global = !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast();
                // TODO: Add proper bogon filtering if strictness required

                if !is_global {
                    return false;
                }

                // 2. Port check
                if meta.addr().port() != default_port {
                    return false;
                }

                // 3. Address Family check
                match record_type {
                    RecordType::A => ip.is_ipv4(),
                    RecordType::AAAA => ip.is_ipv6(),
                    _ => false,
                }
            })
            .collect()
    }
}

trait PeerAddress {
    fn addr(&self) -> std::net::SocketAddr;
}

impl PeerAddress for zebra_network::types::MetaAddr {
    fn addr(&self) -> std::net::SocketAddr {
        *self.addr()
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

        // Checking one query at a time standard
        // If multiple queries, usually we answer the first or all?
        // Standard DNS usually has 1 question.
        if let Some(query) = request.queries().first() {
            let name = query.name();
            let record_type = query.query_type();

            // Check if we should answer this query
            // Ideally we check if `name` matches our seed domain, but for a dedicated seeder
            // running on a specific IP, we might just answer everything or filter.
            // For now, let's assume we answer for any domain routed to us,
            // OR we could check config.seed_domain if passed in.
            // Given the prompt didn't specify strict domain filtering, we'll answer.

            let mut records = Vec::new();

            if let Ok(book) = self.address_book.lock() {
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

                // Collecting all peers (this can be expensive if large, but efficient enough for a seeder)
                // Collecting all peers (this can be expensive if large, but efficient enough for a seeder)
                // Using `peers()` which likely returns `impl Iterator<Item = &MetaAddr>`.
                let candidates: Vec<_> = book.peers().collect();

                let default_port = self.network.default_port();

                let candidate_refs: Vec<_> = candidates.iter().collect();
                let mut matched_peers: Vec<&zebra_network::types::MetaAddr> =
                    Self::filter_candidates(candidate_refs, record_type, default_port);

                // Shuffle and take 25
                matched_peers.shuffle(&mut rng());
                matched_peers.truncate(25);

                histogram!("seeder.dns.response_peers").record(matched_peers.len() as f64);

                for peer in matched_peers {
                    let rdata = match peer.addr().ip() {
                        std::net::IpAddr::V4(ipv4) => RData::A(hickory_proto::rr::rdata::A(ipv4)),
                        std::net::IpAddr::V6(ipv6) => {
                            RData::AAAA(hickory_proto::rr::rdata::AAAA(ipv6))
                        }
                    };

                    let record = Record::from_rdata(name.clone().into(), 600, rdata); // 600s TTL default
                    records.push(record);
                }
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
                        .map_err(|e| {
                            counter!("seeder.dns.errors_total").increment(1);
                            e
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    struct MockPeer {
        addr: SocketAddr,
    }

    impl PeerAddress for MockPeer {
        fn addr(&self) -> SocketAddr {
            self.addr
        }
    }

    fn mock_peer(ip: IpAddr, port: u16) -> MockPeer {
        MockPeer {
            addr: SocketAddr::new(ip, port),
        }
    }

    #[test]
    fn test_filter_candidates_a_record() {
        let v4_good = mock_peer(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8233);
        let v6_good = mock_peer(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8233,
        );
        let candidates = vec![&v4_good, &v6_good];

        let filtered = SeederAuthority::filter_candidates(candidates, RecordType::A, 8233);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].addr().ip(), v4_good.addr.ip());
    }

    #[test]
    fn test_filter_candidates_aaaa_record() {
        let v4_good = mock_peer(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8233);
        let v6_good = mock_peer(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8233,
        );
        let candidates = vec![&v4_good, &v6_good];

        let filtered = SeederAuthority::filter_candidates(candidates, RecordType::AAAA, 8233);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].addr().ip(), v6_good.addr.ip());
    }

    #[test]
    fn test_filter_candidates_port_mismatch() {
        let good = mock_peer(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8233);
        let bad_port = mock_peer(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)), 9999);
        let candidates = vec![&good, &bad_port];

        let filtered = SeederAuthority::filter_candidates(candidates, RecordType::A, 8233);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].addr().ip(), good.addr.ip());
    }

    #[test]
    fn test_filter_candidates_non_global() {
        let global = mock_peer(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 8233);
        let loopback = mock_peer(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8233);
        let unspecified = mock_peer(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8233);

        let candidates = vec![&global, &loopback, &unspecified];

        let filtered = SeederAuthority::filter_candidates(candidates, RecordType::A, 8233);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].addr().ip(), global.addr.ip());
    }
}
