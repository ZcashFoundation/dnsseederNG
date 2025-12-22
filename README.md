# zebra-seeder

A Rust-based DNS seeder for the Zcash network, mirroring patterns from the [Zebra](https://github.com/zcashfoundation/zebra) project.

## Objective
To create a standalone binary that crawls the Zcash network using `zebra-network` and serves A/AAAA records using `hickory-dns`.

## Status
**Current State**: DNS Server Active

### Completed Features
- **Project Structure**: Initialized with `tokio`, `zebra-network`, `zebra-chain`, and `hickory-dns`.
- **Configuration**: Layered configuration system (Env Vars > Config File > Defaults) mirroring `zebrad`.
- **Dotenv Support**: Automatically loads configuration from a `.env` file if present.
- **CLI**: `clap`-based command line interface with `start` command.
- **Async Runtime**: Basic `tokio` orchestration with `tracing` for logging.
- **Crawler**: Active network crawler with address book monitoring.
- **DNS Server**: Authoritative DNS server serving A/AAAA records from filtered peers.
- **Testing**: Unit tests for configuration loading and CLI argument parsing.

## Usage

### Running the Seeder
```bash
cargo run start
```

### Verifying DNS Responses
Once the server is running, you can verify it using `dig`:

**IPv4 (A Record):**
```bash
dig @127.0.0.1 -p 1053 testnet.seeder.example.com A
```

**IPv6 (AAAA Record):**
```bash
dig @127.0.0.1 -p 1053 testnet.seeder.example.com AAAA
```

### Configuration
Configuration can be provided via a TOML file, environment variables, or a `.env` file.

**Environment Variables:**
Prefix with `ZEBRA_SEEDER__` (double underscore separator). 

**Using `.env` file:**
You can create a `.env` file in the project root to persist environment variables. See [`.env-example.txt`](.env-example.txt) for a template.

```bash
# Example .env content
ZEBRA_SEEDER__NETWORK__NETWORK="Mainnet"
ZEBRA_SEEDER__DNS_LISTEN_ADDR="0.0.0.0:1053"
ZEBRA_SEEDER__SEED_DOMAIN="mainnet.seeder.example.com"
ZEBRA_SEEDER__METRICS__ENDPOINT_ADDR="0.0.0.0:9999"
```

## Architecture
- **Networking**: Uses `zebra-network` for peer discovery and management.
- **DNS Server**: Uses `hickory-dns` (formerly `trust-dns`) to serve DNS records.
- **Service Pattern**: Implements `tower::Service` for modular request handling.

## Metrics (Observability)

The seeder can expose Prometheus metrics. To enable them, uncomment this line in .env:

```bash
ZEBRA_SEEDER__METRICS__ENDPOINT_ADDR="0.0.0.0:9999"
```

Once enabled, metrics are available at `http://localhost:9999/metrics`.

### Key Metrics for Operators
Monitor these metrics to ensure the seeder is healthy and serving useful data:

-   **`seeder.peers.eligible`** (Gauge, labels: `v4`, `v6`): **Critical**. The number of peers that are currently reachable, routable, and listening on the default zcash port. If this drops to 0, the seeder is effectively returning empty or bad lists.
-   **`seeder.dns.queries_total`** (Counter, labels: `A`, `AAAA`): Traffic volume.
-   **`seeder.dns.errors_total`** (Counter): Should be near zero. Spikes indicate socket handling issues.
-   **`seeder.dns.response_peers`** (Histogram): Tracks how many peers are returned per query. A healthy seeder should consistently return near 25 peers. A shift to lower numbers indicates the address book is running dry of eligible peers.
-   **`seeder.peers.total`** (Gauge): Raw size of the address book (includes unresponsive/unverified peers).

## Deployment

### Docker (Recommended)
The project includes a `Dockerfile` and `docker-compose.yml` for easy deployment. The container uses a `rust` builder and a `distroless` runtime, minimal distroless image (Debian 13 "Trixie" based).

**Quick Start:**
```bash
docker-compose up -d
```
This starts the seeder on port `1053` (UDP/TCP).

**Production Best Practices:**

1.  **Persistence**: Mount a volume for the address book cache to ensure peer data is retained across restarts.
    ```yaml
    volumes:
      - ./data:/root/.cache/zebra/network
    ```
2.  **Resource Limits**: The seeder is lightweight, but it is good practice to set limits.
    ```yaml
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 512M
    ```
3.  **Metrics**: Enable metrics in production for monitoring (see Metrics section).

**Manual Docker Build:**
```bash
docker build -t zebra-seeder .
docker run -d -p 1053:1053/udp -p 1053:1053/tcp zebra-seeder
```

**Configuration with Docker:**
Pass environment variables to the container. See `docker-compose.yml` for examples.

## Roadmap
- [x] Initial Scaffolding (Project setup, basic dependencies)
- [x] Configuration System (Env vars, TOML, Defaults, Dotenv)
- [x] CLI Entry Point
- [x] Implement DNS Request Handler (Connect `AddressBook` to DNS responses)
- [x] Implement Crawler Logic (Active peer discovery loop & monitoring)
- [x] Metrics & Observability (Basic Prometheus exporter and tracing)
- [x] CI/CD (GitHub Actions)
- [x] Deployment (Containerization)
- [ ] Improve bootstrapping (Resilience against seed failures) 

## Known Issues
- [ ] DNS server not accessible over udp/1053 when running in docker.  May be distroless related.
