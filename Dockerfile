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
COPY envv-server/Cargo.toml envv-server/
COPY envv-cli/Cargo.toml envv-cli/
COPY src-tauri/Cargo.toml src-tauri/

# Stub all crate entry points so `cargo fetch` resolves the workspace without full source
RUN mkdir -p vault-core/src envv-server/src envv-cli/src src-tauri/src && \
    printf 'pub fn placeholder() {}' > vault-core/src/lib.rs && \
    printf 'pub fn placeholder() {}' > envv-server/src/lib.rs && \
    printf 'fn main() {}' > envv-server/src/main.rs && \
    printf 'fn main() {}' > envv-cli/src/main.rs && \
    printf 'pub fn placeholder() {}' > src-tauri/src/lib.rs && \
    printf 'fn main() {}' > src-tauri/src/main.rs

# Pre-fetch and compile deps (cached as long as Cargo.toml/Cargo.lock unchanged)
RUN cargo build --release -p envv-server 2>&1 | grep -v "^warning" || true

# Copy real source and rebuild only the changed crates
COPY vault-core/src vault-core/src
COPY envv-server/src envv-server/src

# Touch to force rebuild after stub replacement
RUN touch vault-core/src/lib.rs envv-server/src/lib.rs envv-server/src/main.rs && \
    cargo build --release -p envv-server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher0 \
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
# ENVV_WORKER_THREADS: tokio would otherwise start one worker per host CPU —
# threads this workload has no use for, each carrying a stack and an arena.
# MALLOC_TRIM/MMAP_THRESHOLD_ return freed memory to the OS more eagerly. The
# server allocates in bursts (a vault decrypt, a JSON round trip) and then sits
# idle; without these the peak stays resident for the life of the process.
# (A comment cannot live inside a continued ENV line — Docker does not allow it.)
ENV MALLOC_ARENA_MAX=2 \
    ENVV_WORKER_THREADS=2 \
    MALLOC_TRIM_THRESHOLD_=131072 \
    MALLOC_MMAP_THRESHOLD_=131072

# Non-root user
RUN useradd -r -u 1001 -s /bin/false envv
RUN mkdir /data && chown envv:envv /data

COPY --from=builder /build/target/release/envv-server /usr/local/bin/envv-server

USER envv
VOLUME ["/data"]
EXPOSE 8743

ENTRYPOINT [ \
    "envv-server", \
    "--host", "0.0.0.0", \
    "--db-path",   "/data/vault.db", \
    "--salt-path", "/data/vault.salt" \
]
