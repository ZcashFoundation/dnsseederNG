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
cargo run -- start --verbose debug
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
You can create a `.env` file in the project root to persit environment variables. See `[.env-example.txt](.env-example.txt)` for a template.

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

The seeder can expose Prometheus metrics. To enable them, add a `[metrics]` section to your configuration file:

```toml
[metrics]
endpoint_addr = "0.0.0.0:9999"
```

Or set the environment variable: `ZEBRA_SEEDER__METRICS__ENDPOINT_ADDR="0.0.0.0:9999"`.

Once enabled, metrics are available at `http://localhost:9999/metrics`.

### Key Metrics for Operators
Monitor these metrics to ensure the seeder is healthy and serving useful data:

-   **`seeder.peers.eligible`** (Gauge, labels: `v4`, `v6`): **Critical**. The number of peers that are currently reachable, routable, and listening on the default zcash port. If this drops to 0, the seeder is effectively returning empty or bad lists.
-   **`seeder.dns.queries_total`** (Counter, labels: `A`, `AAAA`): Traffic volume.
-   **`seeder.dns.errors_total`** (Counter): Should be near zero. Spikes indicate socket handling issues.
-   **`seeder.dns.response_peers`** (Histogram): Tracks how many peers are returned per query. A healthy seeder should consistently return near 25 peers. A shift to lower numbers indicates the address book is running dry of eligible peers.
-   **`seeder.peers.total`** (Gauge): Raw size of the address book (includes unresponsive/unverified peers).

## Roadmap
- [x] Initial Scaffolding (Project setup, basic dependencies)
- [x] Configuration System (Env vars, TOML, Defaults, Dotenv)
- [x] CLI Entry Point
- [x] Implement DNS Request Handler (Connect `AddressBook` to DNS responses)
- [x] Implement Crawler Logic (Active peer discovery loop & monitoring)
- [x] Metrics & Observability (Basic Prometheus exporter and tracing)
- [x] CI/CD (GitHub Actions)
- [ ] Deployment (Containerization)
- [ ] Improve bootstrapping.  Add mechanism for seeder to be resilient in the face of failure of all other seeders, which is how the Zcash network bootstraps.  Perhaps allow a list of known good long lived peers to be specified in the config, and the seeder will try to connect to them in order to bootstrap. 


