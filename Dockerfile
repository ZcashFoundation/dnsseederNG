# Builder stage
FROM rust:1-trixie as builder

WORKDIR /app

# Copy source code
COPY . .

# Build the release binary
RUN cargo build --release

# Runtime stage
# User requested Trixie (Debian 13) to match builder's glibc version.
FROM gcr.io/distroless/cc-debian13

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/zebra-seeder /app/zebra-seeder

# Documentation for exposed ports
# 1053: DNS (UDP/TCP)
# 9999: Metrics (TCP) - optional, disabled by default
EXPOSE 1053/udp 1053/tcp 9999/tcp

# Set the entrypoint
ENTRYPOINT ["/app/zebra-seeder", "start"]
