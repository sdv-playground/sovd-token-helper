# Container image for sovd-token-helper — the offboard workshop JWT minter.
#
# Runs in the sumo-provision tower stack (compose.towers.yml) as a DELEGATE of
# Tower 1: at startup docker-entrypoint.sh asks sumo-ca to sign it a short leaf
# cert, then starts the minter signing with that key. So the runtime image needs
# curl + jq (the bootstrap) alongside the binary.
#
#   docker build -t sumo-provision/minter .
#   docker run -e CA_URL=http://sumo-ca:8080 -e SOVD_MINTER_OPERATOR_TOKEN=… … sumo-provision/minter

# ---- builder ---------------------------------------------------------------
# Pinned to rust-toolchain.toml (1.96). No git deps — self-contained crate.
FROM rust:1.96-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin sovd-token-helper \
    && cp target/release/sovd-token-helper /usr/local/bin/sovd-token-helper.out

# ---- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
# curl + jq: the entrypoint mints the delegate cert from Tower 1 and splits the
# PEM response. ca-certificates: outbound TLS if Tower 1 is https.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/sovd-token-helper.out /usr/local/bin/sovd-token-helper
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Non-root; /state (the minted key/chain) is a volume mount point.
RUN useradd --system --uid 10002 --create-home --home-dir /home/minter minter \
    && mkdir -p /state && chown -R minter:minter /state
USER minter
WORKDIR /home/minter

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
