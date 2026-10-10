# ── Build stage ───────────────────────────────────────────────────────────────
# 1.85 stopped building once the lockfile moved to crates needing rustc 1.88 (found by actually building the image, 2026-10-09).
FROM rust:1.99-bookworm AS builder

# mold: faster linking (matches .cargo/config.toml)
# SQLCipher is compiled in (`vault-core/bundled`), the same engine the releases
# ship, instead of Debian's libsqlcipher. The vendored OpenSSL it builds needs
# perl and make, which the rust image already carries.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    mold \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY vault-core/Cargo.toml vault-core/
COPY unv-server/Cargo.toml unv-server/
COPY unv-cli/Cargo.toml unv-cli/
COPY src-tauri/Cargo.toml src-tauri/

# Stub all crate entry points so `cargo fetch` resolves the workspace without full source
RUN mkdir -p vault-core/src unv-server/src unv-cli/src src-tauri/src && \
    printf 'pub fn placeholder() {}' > vault-core/src/lib.rs && \
    printf 'pub fn placeholder() {}' > unv-server/src/lib.rs && \
    printf 'fn main() {}' > unv-server/src/main.rs && \
    printf 'pub fn placeholder() {}' > unv-cli/src/lib.rs && \
    printf 'fn main() {}' > unv-cli/src/main.rs && \
    printf 'pub fn placeholder() {}' > src-tauri/src/lib.rs && \
    printf 'fn main() {}' > src-tauri/src/main.rs

# Pre-fetch and compile deps (cached as long as Cargo.toml/Cargo.lock unchanged)
RUN cargo build --release -p unv-server --features vault-core/bundled 2>&1 | grep -v "^warning" || true

# Copy real source and rebuild only the changed crates
# secret-types.json (Phase 24.5) is `include_str!`'d from vault-core/src at a
# repo-root-relative path — without it here the build fails past the stub
# stage with "couldn't read vault-core/src/../../secret-types.json".
#
# Phase 31/33 added two more: secret-templates.json (templates.rs) and the BIP39
# wordlist under vault-core/data (type_emit.rs), both `include_str!`'d.
COPY secret-types.json secret-templates.json ./
COPY vault-core/data vault-core/data
COPY vault-core/src vault-core/src
# Phase 34: the hub renders node targets with the CLI's exporters, so unv-server
# depends on the unv-cli library.
COPY unv-cli/src unv-cli/src
COPY unv-server/src unv-server/src

# Touch to force rebuild after stub replacement
RUN touch vault-core/src/lib.rs unv-server/src/lib.rs unv-server/src/main.rs && \
    cargo build --release -p unv-server --features vault-core/bundled

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Memory ────────────────────────────────────────────────────────────────────
#
# Two settings do most of the work in a container this small.
#
# MALLOC_ARENA_MAX: glibc gives each thread its own arena, up to 8 per core, and
# each arena reserves a 64 MB heap it never fully returns. On a many-core host
# that alone accounts for most of the resident memory of an otherwise idle
# server. Two arenas is plenty for two worker threads.
#
# UNV_WORKER_THREADS: tokio would otherwise start one worker per host CPU —
# threads this workload has no use for, each carrying a stack and an arena.
# MALLOC_TRIM/MMAP_THRESHOLD_ return freed memory to the OS more eagerly. The
# server allocates in bursts (a vault decrypt, a JSON round trip) and then sits
# idle; without these the peak stays resident for the life of the process.
# (A comment cannot live inside a continued ENV line — Docker does not allow it.)
ENV MALLOC_ARENA_MAX=2 \
    UNV_WORKER_THREADS=2 \
    MALLOC_TRIM_THRESHOLD_=131072 \
    MALLOC_MMAP_THRESHOLD_=131072

# Non-root user
RUN useradd -r -u 1001 -s /bin/false unv
RUN mkdir /data && chown unv:unv /data

COPY --from=builder /build/target/release/unv-server /usr/local/bin/unv-server

USER unv
VOLUME ["/data"]
EXPOSE 8743

ENTRYPOINT [ \
    "unv-server", \
    "--host", "0.0.0.0", \
    "--db-path",   "/data/vault.db", \
    "--salt-path", "/data/vault.salt" \
]
