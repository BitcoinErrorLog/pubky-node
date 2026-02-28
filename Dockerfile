# Stage 1: Build both binaries
FROM rust:1.82-bookworm AS builder
WORKDIR /build

# Copy all workspace sources (pubky-node depends on local pkarr + pkdns)
COPY pkarr/ pkarr/
COPY pkdns/ pkdns/
COPY pubky-node/ pubky-node/

# Build pkdns
RUN cargo build --release --manifest-path pkdns/server/Cargo.toml

# Build pubky-node
RUN cargo build --release --manifest-path pubky-node/Cargo.toml

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/pubky-node/target/release/pubky-node /usr/local/bin/
COPY --from=builder /build/pkdns/target/release/pkdns /usr/local/bin/

# Dashboard (HTTP), Relay (HTTP), DHT (UDP)
EXPOSE 9090 6881/tcp 6881/udp

VOLUME /data

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

ENTRYPOINT ["pubky-node"]
CMD ["--data-dir", "/data", "--dashboard-bind", "0.0.0.0", "--dashboard-port", "9090"]
