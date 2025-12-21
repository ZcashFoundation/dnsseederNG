# zebra-seeder

A Rust-based DNS seeder for the Zcash network, mirroring patterns from the [Zebra](https://github.com/zcashfoundation/zebra) project.

## Objective
To create a standalone binary that crawls the Zcash network using `zebra-network` and serves A/AAAA records using `hickory-dns`.

## Status
**Current State**: Initial Scaffolding

### Completed Features
- **Project Structure**: Initialized with `tokio`, `zebra-network`, `zebra-chain`, and `hickory-dns`.
- **Configuration**: Layered configuration system (Env Vars > Config File > Defaults) mirroring `zebrad`.
- **CLI**: `clap`-based command line interface with `start` command.
- **Async Runtime**: Basic `tokio` orchestration with `tracing` for logging.
- **Testing**: Unit tests for configuration loading and CLI argument parsing.

## Usage

### Running the Seeder
```bash
cargo run -- start --verbose debug
```

### Configuration
Configuration can be provided via a TOML file or environment variables.

**Environment Variables:**
Prefix with `ZEBRA_SEEDER__` (double underscore separator). Example:
```bash
ZEBRA_SEEDER__NETWORK__NETWORK=Mainnet cargo run -- start
```

## Architecture
- **Networking**: Uses `zebra-network` for peer discovery and management.
- **DNS Server**: Uses `hickory-dns` (formerly `trust-dns`) to serve DNS records.
- **Service Pattern**: Implements `tower::Service` for modular request handling.

## Roadmap
- [x] Initial Scaffolding (Project setup, basic dependencies)
- [x] Configuration System (Env vars, TOML, Defaults)
- [x] CLI Entry Point
- [ ] Implement DNS Request Handler (Connect `AddressBook` to DNS responses)
- [ ] Implement Crawler Logic (Active peer discovery loop)
- [ ] Metrics & Observability
- [ ] Deployment & CI/CD
