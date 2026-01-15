# Testing Strategy

This directory is currently reserved for future black-box integration tests.

## Where are the tests?
- **DNS Server Integration Tests**: Located inline in `src/server.rs` (in `mod tests`). This allows tests to access internal types like `RateLimiter` and `SeederAuthority` without making them public.
- **Unit Tests**: Located in `src/tests/` (e.g., `cli_tests.rs`, `config_tests.rs`).
- **Property-Based Tests**: Located inline in `src/server.rs`.

Run all tests with:
```bash
cargo nextest run
```

