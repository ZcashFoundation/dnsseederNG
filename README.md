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
```

## Architecture
- **Networking**: Uses `zebra-network` for peer discovery and management.
- **DNS Server**: Uses `hickory-dns` (formerly `trust-dns`) to serve DNS records.
- **Service Pattern**: Implements `tower::Service` for modular request handling.

## Roadmap
- [x] Initial Scaffolding (Project setup, basic dependencies)
- [x] Configuration System (Env vars, TOML, Defaults, Dotenv)
- [x] CLI Entry Point
- [x] Implement DNS Request Handler (Connect `AddressBook` to DNS responses)
- [x] Implement Crawler Logic (Active peer discovery loop & monitoring)
- [ ] Metrics & Observability
- [ ] Deployment & CI/CD
