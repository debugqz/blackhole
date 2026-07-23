# Builds and runs `daemon` (package `bh-daemon`, binary `blackhole-daemon`)
# configured as a public DHT bootstrap node — see ../README.md for what
# that means and how to actually run this image. Build from the repo
# root so the whole Cargo workspace is in context:
#
#   docker build -f infra/bootstrap-node/Dockerfile -t blackhole-bootstrap-node .
#
# There is no "bootstrap-only" binary in this codebase — a bootstrap node
# is just an ordinary `daemon` whose only real job is staying reachable at
# a stable address (see BLACKHOLE_PERSISTENT_NETWORK_IDENTITY below). It
# still runs the full localhost HTTP API; nothing in this image exposes
# that beyond localhost, so it's inert for a node nobody uses as a chat
# client.

# ---- builder -----------------------------------------------------------
FROM rust:1-bookworm AS builder

# Same list CI installs (.github/workflows/ci.yml) — `daemon` pulls in
# `bh-calls` transitively (daemon -> bh-api -> bh-calls), so it needs the
# codec/bindgen/screen-capture headers even though a bootstrap node never
# places a call. `libasound2-dev` is NOT in CI's own list — it's needed
# here too (bh-calls's `cpal` dependency, ALSA on Linux) but CI's
# ubuntu-latest runner happens to ship it preinstalled, silently masking
# the gap; a minimal `rust:1-bookworm` image doesn't have it, and building
# this image is what surfaced that CI's documented dependency list is
# incomplete for a from-scratch environment.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev pkg-config libopus-dev libvpx-dev libclang-dev clang \
    libpipewire-0.3-dev libdbus-1-dev libasound2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release --locked -p bh-daemon

# ---- runtime ------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Runtime counterparts of the builder's -dev packages (shared libs only,
# no headers/compiler) plus ca-certificates for the push-relay/TURN HTTP
# calls `bh-api` itself would make if this image is ever repurposed as a
# full user-facing daemon rather than a bootstrap-only node.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 libopus0 libvpx7 libpipewire-0.3-0 libdbus-1-3 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/blackhole --shell /usr/sbin/nologin blackhole

COPY --from=builder /build/target/release/blackhole-daemon /usr/local/bin/blackhole-daemon

# Persisted across restarts: the SQLCipher profile data, and — when
# BLACKHOLE_PERSISTENT_NETWORK_IDENTITY=1 — the libp2p keypair that keeps
# this node's PeerId (and therefore its multiaddr) stable. Mount a real
# volume here; losing this directory means generating a new identity next
# start, which silently breaks every other node's BLACKHOLE_BOOTSTRAP_PEERS
# entry pointing at the old one (docs/THREAT_MODEL.md §3.5).
ENV BLACKHOLE_DATA_DIR=/var/lib/blackhole/data
RUN mkdir -p "$BLACKHOLE_DATA_DIR" && chown -R blackhole:blackhole /var/lib/blackhole
VOLUME ["/var/lib/blackhole/data"]

# A bootstrap node's whole point is a stable, publicly reachable identity —
# opt into both fixes that exist for exactly that (see ../README.md and
# docs/THREAT_MODEL.md §3.5/§3.7 for why each is off by default elsewhere).
ENV BLACKHOLE_PERSISTENT_NETWORK_IDENTITY=1
ENV BLACKHOLE_KEYSTORE_BACKEND=file
# Fixed port so the multiaddr operators publish doesn't change on its own —
# override the host-side mapping in docker-compose.yml / your own `docker
# run -p`, not this value, unless you also update every advertised address.
ENV BLACKHOLE_NETWORK_LISTEN_ADDR=/ip4/0.0.0.0/tcp/4001
# The localhost-only HTTP API (SPEC.md §6) — never exposed outside this
# container/host; nothing needs to reach it on a bootstrap node. Left at
# its default rather than disabled since there's no supported way to turn
# it off, and it costs nothing unreachable.
EXPOSE 4001/tcp

USER blackhole
WORKDIR /var/lib/blackhole
ENTRYPOINT ["/usr/local/bin/blackhole-daemon"]
