# Builds and runs `bh-push-relay` — the opaque wake-notification relay
# (crates/bh-push-relay, see that crate's own module doc for the full
# design). Build from the repo root:
#
#   docker build -f infra/push-relay/Dockerfile -t blackhole-push-relay .
#
# Unlike the bootstrap-node image, this binary has no bh-storage/bh-crypto/
# bh-calls dependency at all (just axum/tokio/serde/tower_governor), so
# the builder needs nothing beyond a plain Rust toolchain and the runtime
# image needs no shared codec/D-Bus libraries.

# ---- builder -----------------------------------------------------------
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked -p bh-push-relay

# ---- runtime ------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin blackhole

COPY --from=builder /build/target/release/bh-push-relay /usr/local/bin/bh-push-relay

# In-memory only by design (crates/bh-push-relay/src/lib.rs's own module
# doc: "Not durable" — losing registration state on restart is a liveness
# gap, not a confidentiality one). No volume needed, nothing to persist.
ENV BLACKHOLE_PUSH_RELAY_PORT=47900
EXPOSE 47900/tcp

USER blackhole
ENTRYPOINT ["/usr/local/bin/bh-push-relay"]
