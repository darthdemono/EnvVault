# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:1.85-bookworm AS builder

# mold: faster linking (matches .cargo/config.toml)
# libsqlcipher-dev: rusqlite sqlcipher feature links against system SQLCipher
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libsqlcipher-dev \
    mold \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY vault-core/Cargo.toml vault-core/
COPY apiv-server/Cargo.toml apiv-server/
COPY apiv-cli/Cargo.toml apiv-cli/
COPY src-tauri/Cargo.toml src-tauri/

# Stub all crate entry points so `cargo fetch` resolves the workspace without full source
RUN mkdir -p vault-core/src apiv-server/src apiv-cli/src src-tauri/src && \
    printf 'pub fn placeholder() {}' > vault-core/src/lib.rs && \
    printf 'fn main() {}' > apiv-server/src/main.rs && \
    printf 'fn main() {}' > apiv-cli/src/main.rs && \
    printf 'pub fn placeholder() {}' > src-tauri/src/lib.rs && \
    printf 'fn main() {}' > src-tauri/src/main.rs

# Pre-fetch and compile deps (cached as long as Cargo.toml/Cargo.lock unchanged)
RUN cargo build --release -p apiv-server 2>&1 | grep -v "^warning" || true

# Copy real source and rebuild only the changed crates
COPY vault-core/src vault-core/src
COPY apiv-server/src apiv-server/src

# Touch to force rebuild after stub replacement
RUN touch vault-core/src/lib.rs apiv-server/src/main.rs && \
    cargo build --release -p apiv-server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -r -u 1001 -s /bin/false apiv
RUN mkdir /data && chown apiv:apiv /data

COPY --from=builder /build/target/release/apiv-server /usr/local/bin/apiv-server

USER apiv
VOLUME ["/data"]
EXPOSE 8743

ENTRYPOINT [ \
    "apiv-server", \
    "--host", "0.0.0.0", \
    "--db-path",   "/data/vault.db", \
    "--salt-path", "/data/vault.salt" \
]
