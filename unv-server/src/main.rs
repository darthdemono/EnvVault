//! `unv-server` binary — CLI wrapper around the [`unv_server`] library.
//!
//! Everything substantive lives in the library so the desktop app can host the
//! identical router in-process for "Open to LAN". This file only parses argv,
//! resolves paths, and reports failures to the terminal.

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

use unv_server::{
    auto_unlock, cert_fingerprint, ensure_self_signed_cert, serve, AppState, TlsFiles,
};

#[derive(Parser)]
#[command(name = "unv-server", version, about = "UnENVerse remote vault server")]
struct Args {
    #[arg(long, default_value_t = 8743)]
    port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long)]
    db_path: Option<PathBuf>,
    #[arg(long)]
    salt_path: Option<PathBuf>,
    /// Enable TLS (HTTPS).  A self-signed cert is auto-generated if --cert/--key are absent.
    #[arg(long)]
    tls: bool,
    /// Path to PEM-encoded TLS certificate (requires --tls).
    #[arg(long)]
    cert: Option<PathBuf>,
    /// Path to PEM-encoded TLS private key (requires --tls).
    #[arg(long)]
    key: Option<PathBuf>,
    /// Idle minutes before a session token expires. Any authenticated request
    /// resets the clock; `GET /api/ping` exists to do exactly that. 0 disables expiry.
    #[arg(long, default_value_t = 480)]
    session_ttl_mins: u64,
    /// Absolute hours a session may live, counted from when it was issued and
    /// never extended by activity. `--session-ttl-mins` alone bounds only
    /// *abandoned* sessions: a token that keeps being used slides its own idle
    /// deadline forward forever, so a leaked one would never expire. 0 disables
    /// the ceiling.
    #[arg(long, default_value_t = 24)]
    session_max_hours: u64,
    /// Enable the unique-ID registry (Phase 24.4). Off by default: it is a
    /// second SQLCipher file with its own storage-growth and rate-limiting
    /// profile, and a deployment that never asked for it should never find
    /// `registry.db` on disk.
    #[arg(long)]
    uid_registry: bool,
    /// Refuse further `uid` registrations once `registry.db` exceeds this many
    /// bytes. Default 10 GiB ≈ 160M ids at the measured 61 bytes/row.
    #[arg(long, default_value_t = 10 * 1024 * 1024 * 1024)]
    uid_max_bytes: i64,
    /// Override a unique-ID rate limit: `BUCKET=A_REFILL:A_BURST:S_REFILL:S_BURST`
    /// for `mint`, `check` or `lookup` — per-actor then server-wide, refill in
    /// values per second, counted per value. Repeatable.
    #[arg(long = "uid-rate")]
    uid_rate: Vec<String>,
    /// Enable Nodes (Phase 34): enrollment, heartbeats and push/pull for agents
    /// on other hosts. Off by default; every `/api/nodes/*` route answers 404
    /// until it is on, and `nodes.json` is never created.
    #[arg(long)]
    nodes: bool,
    /// Where the node registry lives. Default: `nodes.json` beside the vault.
    #[arg(long)]
    nodes_file: Option<std::path::PathBuf>,
}

fn main() {
    // Variables set before the rename (`ENVV_*`) keep working.
    vault_core::compat::adopt_legacy_env();
    // Pick the crypto provider explicitly. The workspace enables both `ring`
    // (axum-server) and `aws_lc_rs` (vault-core's `tls` feature) on one rustls;
    // cargo unifies features across a build, so rustls sees two candidates,
    // refuses to guess, and panics inside the first TLS handshake — after the
    // startup banner has already printed a URL and a fingerprint, which is a
    // maximally confusing place to fail.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Tokio defaults to one worker thread per CPU. On a 16-core host that is 16
    // threads for a server whose entire job is a handful of small JSON requests,
    // and each one brings its own stack and its own glibc malloc arena — which
    // is what actually shows up as resident memory in a container.
    //
    // Two workers is ample: the work here is IO-bound, and the one CPU-heavy
    // step (Argon2id at 64 MB per unlock) is rare and deliberately serialised by
    // its own cost. `UNV_WORKER_THREADS` raises it for anyone who needs more.
    let workers = std::env::var("UNV_WORKER_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(2);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        // 1 MB rather than the 2 MB default: nothing here recurses deeply, and
        // the saving is per thread.
        .thread_stack_size(1024 * 1024)
        .enable_all()
        .build()
        .expect("build tokio runtime");
    runtime.block_on(async_main());
}

async fn async_main() {
    let args = Args::parse();

    // Structured logging before anything that can fail, so a bad path or a
    // refused bind is reported through the same channel as everything else.
    // `info` by default: a long-lived server should say what it did, unlike the
    // CLI, which must stay silent to keep its stdout envelope clean.
    vault_core::telemetry::init("unv-server", "info");
    // Where the vault lives when the operator has not said. There is no
    // hardcoded fallback path on purpose: `/var/lib` is meaningless on Windows,
    // where it resolves to `\var\lib` on whatever the current drive happens to
    // be — and a server that quietly creates an empty vault in an unexpected
    // directory looks exactly like one that lost every secret. If the platform
    // cannot say where application data belongs, say so and stop.
    //
    // Resolved lazily so that passing both --db-path and --salt-path works even
    // on a machine where it cannot be resolved at all.
    let resolve_data_dir = || -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| {
                eprintln!(
                    "unv-server: cannot determine this platform's data directory \
                     (no $XDG_DATA_HOME or $HOME on Unix, no %APPDATA% on Windows).\n\
                     Pass --db-path and --salt-path explicitly."
                );
                std::process::exit(2);
            })
            .join("envv-server")
    };

    let db_path = args
        .db_path
        .unwrap_or_else(|| resolve_data_dir().join("vault.db"));
    let salt_path = args
        .salt_path
        .unwrap_or_else(|| resolve_data_dir().join("vault.salt"));

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).expect("create data dir");
    }

    let (tls, fingerprint) = if args.tls {
        match (args.cert, args.key) {
            (Some(cert), Some(key)) => {
                let fp = cert_fingerprint(&cert).unwrap_or_else(|e| {
                    eprintln!("Cannot read TLS cert fingerprint: {e}");
                    std::process::exit(1);
                });
                (Some(TlsFiles { cert, key }), Some(fp))
            }
            (None, None) => {
                let (files, fp) =
                    ensure_self_signed_cert(&resolve_data_dir()).unwrap_or_else(|e| {
                        eprintln!("TLS cert generation failed: {e}");
                        std::process::exit(1);
                    });
                println!("TLS cert → {}", files.cert.display());
                (Some(files), Some(fp))
            }
            _ => {
                eprintln!("--cert and --key must both be provided (or neither)");
                std::process::exit(1);
            }
        }
    } else {
        (None, None)
    };

    let state = AppState::new(
        db_path,
        salt_path,
        fingerprint.clone(),
        args.session_ttl_mins,
        args.session_max_hours,
        /* lan_mode */ false,
    )
    .with_uid_registry(args.uid_registry, Some(args.uid_max_bytes))
    .with_nodes(args.nodes, args.nodes_file.clone())
    .with_uid_rates({
        let mut rates = unv_server::UidRates::default();
        for spec in &args.uid_rate {
            if let Err(e) = rates.set(spec) {
                eprintln!("--uid-rate: {e}");
                std::process::exit(1);
            }
        }
        rates
    });
    if args.nodes {
        tracing::info!("nodes enabled");
        state.start_node_poller();
    }
    if args.uid_registry {
        tracing::info!(max_bytes = args.uid_max_bytes, "uid registry enabled");
    }

    // Unattended deployments (Docker) unlock from the environment.
    if let Ok(pw) = std::env::var("UNV_PASSWORD") {
        if !pw.is_empty() {
            match auto_unlock(&state, &pw) {
                Ok(()) => {
                    tracing::info!("vault auto-unlocked from UNV_PASSWORD");
                    println!("Vault auto-unlocked (UNV_PASSWORD)");
                }
                // The password itself never reaches the log; `e` is a reason,
                // not an echo of the input.
                Err(e) => {
                    tracing::error!(error = %e, "auto-unlock failed");
                    eprintln!("Auto-unlock failed: {e}");
                }
            }
        }
    }

    let scheme = if args.tls { "https" } else { "http" };
    let addr_str = format!("{}:{}", args.host, args.port);
    tracing::info!(
        %scheme,
        addr = %addr_str,
        tls = args.tls,
        session_ttl_mins = args.session_ttl_mins,
        session_max_hours = args.session_max_hours,
        "starting"
    );
    println!("unv-server  →  {scheme}://{addr_str}");
    println!("OpenAPI JSON →  {scheme}://{addr_str}/api/openapi.json");
    if let Some(fp) = &fingerprint {
        println!("TLS fingerprint (SHA-256) → {fp}");
    }

    let addr: SocketAddr = addr_str.parse().expect("invalid bind address");
    // The binary runs until killed; nothing ever fires this.
    let (_tx, rx) = tokio::sync::oneshot::channel();

    if let Err(e) = serve(state, addr, tls, rx).await {
        tracing::error!(error = %e, "server stopped");
        eprintln!("{e}");
        std::process::exit(1);
    }
}
