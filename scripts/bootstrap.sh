#!/usr/bin/env bash
# One-shot dev environment setup for Blackhole. Installs the system
# packages `bh-storage` (SQLCipher/OpenSSL), the WebAuthn stack, and
# `bh-calls` (opus/libvpx, plus scap's PipeWire/D-Bus backend on Linux)
# need to build, points Cargo at OpenSSL where the linker can't find it
# on its own (Apple Silicon Homebrew), then warms the Rust and pnpm
# caches so the first `cargo build`/`pnpm tauri dev` isn't also a cold
# dependency fetch. Safe to re-run — every step checks before installing.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

log() { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$1" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

os="$(uname -s)"
pkg_manager=""
if [[ "$os" == "Darwin" ]]; then
  pkg_manager="brew"
elif [[ "$os" == "Linux" ]]; then
  if have apt-get; then pkg_manager="apt"
  elif have pacman; then pkg_manager="pacman"
  elif have dnf; then pkg_manager="dnf"
  fi
fi

log "Detected OS: $os (package manager: ${pkg_manager:-none detected})"

# --- Rust toolchain ---------------------------------------------------
if ! have rustup; then
  warn "rustup not found. Install it from https://rustup.rs and re-run this script."
  exit 1
fi
log "rustup $(rustup --version | head -1)"
rustup component add rustfmt clippy >/dev/null
log "rustfmt/clippy components present"

# --- Node / pnpm --------------------------------------------------------
if ! have node; then
  warn "Node.js not found. Install Node 20+ (e.g. via nvm/fnm) and re-run."
  exit 1
fi
if ! have pnpm; then
  warn "pnpm not found. Install it (https://pnpm.io/installation), e.g.:"
  warn "  corepack enable pnpm"
  exit 1
fi
log "node $(node --version), pnpm $(pnpm --version)"

# --- System dependencies (bh-storage's SQLCipher/OpenSSL link, ---------
# --- bh-calls' opus/libvpx codecs, scap's Linux screen-capture deps) ---
case "$pkg_manager" in
  brew)
    pkgs=(openssl@3 opus libvpx pkg-config)
    missing=()
    for p in "${pkgs[@]}"; do
      brew list --versions "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
      log "Installing via Homebrew: ${missing[*]}"
      brew install "${missing[@]}"
    else
      log "Homebrew packages already present: ${pkgs[*]}"
    fi
    ;;
  apt)
    log "Installing via apt (sudo required): libssl-dev pkg-config libopus-dev libvpx-dev libclang-dev clang libpipewire-0.3-dev libdbus-1-dev"
    sudo apt-get update
    sudo apt-get install -y libssl-dev pkg-config libopus-dev libvpx-dev libclang-dev clang libpipewire-0.3-dev libdbus-1-dev
    ;;
  pacman)
    log "Installing via pacman (sudo required): openssl pkgconf opus libvpx clang pipewire dbus"
    sudo pacman -Sy --needed openssl pkgconf opus libvpx clang pipewire dbus
    ;;
  dnf)
    log "Installing via dnf (sudo required): openssl-devel pkgconf-pkg-config opus-devel libvpx-devel clang-devel pipewire-devel dbus-devel"
    sudo dnf install -y openssl-devel pkgconf-pkg-config opus-devel libvpx-devel clang-devel pipewire-devel dbus-devel
    ;;
  *)
    warn "No known package manager detected — install OpenSSL, opus, libvpx, pkg-config"
    warn "(and on Linux: libclang, libpipewire, libdbus) yourself; see README.md's"
    warn "'Building & running' section for the exact package names per distro."
    ;;
esac

# Apple Silicon Homebrew installs OpenSSL outside the default linker
# search path; point OPENSSL_DIR at it so openssl-sys/rusqlite's
# bundled-sqlcipher feature can find it without a manual export.
env_file="$repo_root/.env.bootstrap"
: > "$env_file"
if [[ "$os" == "Darwin" ]] && have brew; then
  openssl_prefix="$(brew --prefix openssl@3 2>/dev/null || true)"
  if [[ -n "$openssl_prefix" ]]; then
    echo "export OPENSSL_DIR=\"$openssl_prefix\"" >> "$env_file"
    log "OPENSSL_DIR resolved to $openssl_prefix (written to .env.bootstrap)"
  fi
fi

# --- Warm caches ---------------------------------------------------------
log "Fetching Cargo dependencies (cargo fetch)..."
cargo fetch --locked

log "Installing pnpm dependencies (client/desktop)..."
(cd client/desktop && pnpm install --frozen-lockfile)

cat <<EOF

Setup complete. If OPENSSL_DIR was written above, load it into your shell:

  source .env.bootstrap

Now, in separate terminals:

  cargo run -p bh-daemon                        # daemon (binds 127.0.0.1:47853)
  cd client/desktop && pnpm tauri dev            # desktop client
  cargo run -p bh-push-relay                     # opt-in wake-push relay

EOF
