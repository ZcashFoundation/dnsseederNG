# Architecture

## Overview

zebra-seeder is a DNS seeder for Zcash that crawls the network and serves DNS records pointing to healthy peers.

```mermaid
graph TD
    A[DNS Client] -->|UDP Query| B[hickory-dns Server]
    B --> C[Rate Limiter]
    C -->|Check IP| D{Allow?}
    D -->|Yes| E[SeederAuthority]
    D -->|No| F[Drop Packet]
    E --> G[Address Book]
    G --> H[zebra-network]
    H -->|Peer Discovery| I[Zcash Network]
    E --> J[Filter & Shuffle]
    J --> K[Return A/AAAA Records]
```

### Core Components

- **zebra-network**: Handles Zcash P2P networking and peer discovery
- **hickory-dns**: DNS server framework
- **Rate Limiter**: Per-IP rate limiting using governor crate
- **Address Book**: Thread-safe peer storage with mutex protection
- **Metrics**: Prometheus metrics via metrics-exporter-prometheus

## Data Flow

### Startup Sequence

1. Load configuration (env vars → TOML → defaults)
2. Initialize metrics endpoint (if enabled)
3. Initialize zebra-network with address book
4. Create rate limiter (if enabled)
5. Start DNS server on configured port
6. Launch crawler task (monitors address book periodically)

### DNS Query Handling

```mermaid
sequenceDiagram
    Client->>DNS Server: Query A record
    DNS Server->>Rate Limiter: Check IP limit
    alt Rate limit OK
        Rate Limiter->>Authority: Process query
        Authority->>Authority: Validate domain
        alt Domain valid
            Authority->>Address Book: Get peers
            Address Book-->>Authority: Peer list
            Authority->>Authority: Filter (IPv4, global, correct port)
            Authority->>Authority: Shuffle & take 25
            Authority-->>DNS Server: A records
            DNS Server-->>Client: Response (25 IPs)
        else Domain invalid
            Authority-->>DNS Server: REFUSED
            DNS Server-->>Client: REFUSED
        end
    else Rate limited
        Rate Limiter-->>DNS Server: Drop
        Note over Client,DNS Server: No response (silent drop)
    end
```

**Steps:**
1. Client sends DNS query
2. Rate limiter checks if IP is within limits
3. If rate-limited: packet dropped silently (no amplification)
4. If allowed: validate domain matches `seed_domain`
5. Lock address book mutex (with poisoning recovery)
6. Filter peers: IPv4/IPv6, global IPs, correct port
7. Collect up to 50 eligible peers (early limiting optimization)
8. Shuffle and take 25 peers
9. Return DNS response

### Network Crawling

```mermaid
sequenceDiagram
    participant Crawler
    participant AddressBook
    participant zebra-network
    participant Metrics
    
    loop Every crawl_interval (default 10min)
        Crawler->>AddressBook: Lock & read stats
        AddressBook-->>Crawler: Peer counts
        Crawler->>Metrics: Update gauges
        Note over zebra-network,AddressBook: Continuous background updates
    end
```

**How it works:**
- zebra-network continuously discovers peers
- Crawler task periodically logs Address Book stats
- Metrics updated with peer counts (total, eligible IPv4/IPv6)

## Components Deep Dive

### zebra-network Integration

**What:** Zcash P2P networking library from the Zebra project

**Responsibilities:**
- Peer discovery via DNS seeds and peer exchange
- Connection management
- Protocol message handling
- Address book maintenance

**Our usage:**
- Initialize with config and dummy inbound service (reject all)
- Access Address Book for peer list
- Never send blockchain data (we're not a full node)

**Files:** `src/server.rs` (initialization)

---

### hickory-dns Server

**What:** Async DNS server framework (formerly trust-dns)

**Responsibilities:**
- DNS protocol handling (UDP/TCP)
- Query parsing
- Response building

**Our usage:**
- Implement `RequestHandler` trait via `SeederAuthority`
- Handle A and AAAA queries
- Return REFUSED for unauthorized domains

**Files:** `src/server.rs` (authority implementation)

---

### Rate Limiter

**What:** Per-IP rate limiting to prevent DDoS amplification

**Implementation:**
- `governor` crate with token bucket algorithm
- `DashMap` for concurrent IP tracking
- Each IP gets isolated rate limiter instance

**Configuration:**
- Default: 10 queries/second per IP
- Burst: 20 queries (2x rate)
- Configurable via `rate_limit` config section

**Behavior:**
- Rate-limited requests: dropped silently (no response)
- Metric: `seeder.dns.rate_limited_total`

**Files:** `src/server.rs` (`RateLimiter` struct), `src/config.rs` (`RateLimitConfig`)

---

### Address Book & Mutex Handling

**Mutex Strategy:**
- Address Book protected by `std::sync::Mutex`
- Shared via `Arc` between crawler and DNS handler

**Poisoning Recovery:**
- If thread panics while holding lock, mutex becomes "poisoned"
- We recover by calling `poisoned.into_inner()`
- Log error + increment metric
- Continue serving (availability over strict correctness)

**Peer Filtering:**
- Global IPs only (no loopback, unspecified, multicast)
- Match requested record type (A→IPv4, AAAA→IPv6)
- Correct port (network default, usually 8233)

---

### Configuration System

**Layered priority:**
1. Environment variables (`ZEBRA_SEEDER__*`)
2. TOML config file
3. Hardcoded defaults

**Implementation:**
- `config` crate for loading
- `serde` for deserialization
- `.env` file support via `dotenvy`

**Files:** `src/config.rs`, `src/commands.rs`

---

### Metrics

**Prometheus metrics exposed on configurable endpoint (default `:9999/metrics`)**

**Key metrics:**
- `seeder.peers.total` - Total peers in address book
- `seeder.peers.eligible` - Eligible peers (by address family)
- `seeder.dns.queries_total` - DNS queries (by record type)
- `seeder.dns.response_peers` - Histogram of peer count per response
- `seeder.dns.rate_limited_total` - Rate-limited queries
- `seeder.dns.errors_total` - DNS errors
- `seeder.mutex_poisoning_total` - Mutex poisoning events

**Files:** `src/metrics.rs`, `src/server.rs`

## Architecture Decision Records

### ADR 001: Use zebra-network for Peer Discovery

**Status:** Accepted

**Context:**  
We need to crawl the Zcash network to discover and maintain a list of healthy peers.

**Decision:**  
Use the `zebra-network` crate instead of implementing custom P2P networking.

**Rationale:**
- **Proven**: Battle-tested in Zebra full node
- **Avoids duplication**: Complex P2P logic already implemented
- **Protocol compatibility**: Follows Zcash protocol exactly
- **Maintenance**: Benefits from ongoing Zebra improvements
- **Reduced bugs**: Don't recreate peer discovery, connection management, etc.

**Consequences:**
- ✅ Faster development
- ✅ Reduced bug surface
- ✅ Protocol compliance guaranteed
- ⚠️ Dependency on zebra-network versions
- ⚠️ Must track Zebra releases for updates

**Alternatives Considered:**
- Custom P2P implementation - Rejected (too complex, high bug risk)
- libp2p - Rejected (incompatible with Zcash protocol)

---

### ADR 002: Use hickory-dns for DNS Server

**Status:** Accepted

**Context:**  
We need to serve DNS A/AAAA records to clients querying for Zcash peers.

**Decision:**  
Use the `hickory-dns` crate (formerly trust-dns) for DNS serving.

**Rationale:**
- **Mature**: Industry-standard Rust DNS implementation
- **RFC compliant**: Handles DNS protocol complexities correctly
- **Async native**: Works with tokio ecosystem
- **Feature-rich**: Supports all DNS record types we need
- **Tower integration**: Modern request/response abstraction

**Consequences:**
- ✅ Correct DNS protocol handling
- ✅ Good performance
- ✅ Well-maintained
- ⚠️ Additional dependency
- ⚠️ Learning curve for API

**Alternatives Considered:**
- Custom DNS parser - Rejected (too complex, error-prone, RFC compliance burden)
- trust-dns (old name) - N/A (hickory-dns is the successor)

---

### ADR 003: Implement Per-IP Rate Limiting

**Status:** Accepted

**Context:**  
DNS seeders on UDP port 53 are vulnerable to DNS amplification attacks where:
- Attackers forge source IP addresses
- Small queries trigger large responses
- Our seeder becomes a DDoS weapon

**Decision:**  
Implement per-IP rate limiting using `governor` crate:
- 10 queries/second per IP (default, configurable)
- Burst capacity of 20
- Silent packet dropping (no REFUSED response)

**Rationale:**
- **Security**: Prevents amplification attacks
- **Fairness**: No single IP can monopolize resources
- **Performance**: <1ms overhead with DashMap
- **Configurability**: Operators can tune based on traffic
- **Silent drops**: Avoid amplification (no error responses)

**Implementation:**
- `governor` crate for token bucket algorithm (GCRA)
- `DashMap` for per-IP tracking across threads in a single map
- Each IP gets isolated rate limiter instance
- Metrics track rate-limited requests

**Consequences:**
- ✅ Cannot be weaponized for DDoS
- ✅ Fair resource allocation
- ✅ Minimal performance impact
- ⚠️ Legitimate high-volume clients may be rate-limited
- ⚠️ Memory grows with unique IPs (acceptable: ~200 bytes/IP)

**Alternatives Considered:**
- No rate limiting - Rejected (unacceptable security risk)
- Global rate limit - Rejected (single client could DoS all others)
- Response size limiting - Rejected (insufficient, still allows amplification)

## Design Principles

1. **Security First**: Rate limiting and domain validation prevent abuse
2. **Availability**: Mutex poisoning recovery ensures continued operation
3. **Performance**: Concurrent data structures, early limiting, minimal allocations
4. **Observability**: Comprehensive metrics for monitoring
5. **Simplicity**: Leverage proven libraries (zebra-network, hickory-dns)
6. **Configurability**: All key parameters are configurable
