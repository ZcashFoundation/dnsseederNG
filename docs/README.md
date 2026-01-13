# zebra-seeder Documentation

Documentation for the Zcash DNS seeder.

## Quick Navigation

- **[Architecture](architecture.md)** - System design, components, and key decisions (ADRs)
- **[Operations](operations.md)** - Configuration, deployment, and monitoring
- **[Development](development.md)** - Contributing and development guide

## Start Here

**👨‍💼 Operators:** Read [Operations](operations.md)  
**👨‍💻 Developers:** Read [Architecture](architecture.md) → [Development](development.md)  
**👀 Code Reviewers:** Read [Architecture](architecture.md)

## What is zebra-seeder?

A DNS seeder for Zcash that:
- Crawls the network to discover healthy peers
- Serves DNS A/AAAA records to clients
- Implements rate limiting to prevent DDoS abuse
- Provides Prometheus metrics

Built with Rust using `zebra-network` and `hickory-dns`.
