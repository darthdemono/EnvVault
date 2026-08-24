//! `envv-server` binary — CLI wrapper around the [`envv_server`] library.
//!
//! Everything substantive lives in the library so the desktop app can host the
//! identical router in-process for "Open to LAN". This file only parses argv,
//! resolves paths, and reports failures to the terminal.

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

use envv_server::{
    auto_unlock, cert_fingerprint, ensure_self_signed_cert, serve, AppState, TlsFiles,
};

#[derive(Parser)]
#[command(name = "envv-server", version, about = "EnvVault remote vault server")]
struct Args {
    #[arg(long, default_value_t = 8743)] port:      u16,
    #[arg(long, default_value = "127.0.0.1")] host: String,
    #[arg(long)] db_path:   Option<PathBuf>,
    #[arg(long)] salt_path: Option<PathBuf>,
    /// Enable TLS (HTTPS).  A self-signed cert is auto-generated if --cert/--key are absent.
    #[arg(long)] tls:       bool,
    /// Path to PEM-encoded TLS certificate (requires --tls).
    #[arg(long)] cert:      Option<PathBuf>,
    /// Path to PEM-encoded TLS private key (requires --tls).
    #[arg(long)] key:       Option<PathBuf>,
    /// Idle minutes before a session token expires. Any authenticated request
    /// resets the clock; `GET /api/ping` exists to do exactly that. 0 disables expiry.
    #[arg(long, default_value_t = 480)] session_ttl_mins: u64,
}

fn main() {
    // Tokio defaults to one worker thread per CPU. On a 16-core host that is 16
    // threads for a server whose entire job is a handful of small JSON requests,
    // and each one brings its own stack and its own glibc malloc arena — which
    // is what actually shows up as resident memory in a container.
    //
    // Two workers is ample: the work here is IO-bound, and the one CPU-heavy
    // step (Argon2id at 64 MB per unlock) is rare and deliberately serialised by
    // its own cost. `ENVV_WORKER_THREADS` raises it for anyone who needs more.
    let workers = std::env::var("ENVV_WORKER_THREADS")
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
                    "envv-server: cannot determine this platform's data directory \
                     (no $XDG_DATA_HOME or $HOME on Unix, no %APPDATA% on Windows).\n\
                     Pass --db-path and --salt-path explicitly."
                );
                std::process::exit(2);
            })
            .join("envv-server")
    };

    let db_path   = args.db_path.unwrap_or_else(|| resolve_data_dir().join("vault.db"));
    let salt_path = args.salt_path.unwrap_or_else(|| resolve_data_dir().join("vault.salt"));

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
                let (files, fp) = ensure_self_signed_cert(&resolve_data_dir()).unwrap_or_else(|e| {
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
        /* lan_mode */ false,
    );

    // Unattended deployments (Docker) unlock from the environment.
    if let Ok(pw) = std::env::var("ENVV_PASSWORD") {
        if !pw.is_empty() {
            match auto_unlock(&state, &pw) {
                Ok(()) => println!("Vault auto-unlocked (ENVV_PASSWORD)"),
                Err(e) => eprintln!("Auto-unlock failed: {e}"),
            }
        }
    }

    let scheme   = if args.tls { "https" } else { "http" };
    let addr_str = format!("{}:{}", args.host, args.port);
    println!("envv-server  →  {scheme}://{addr_str}");
    println!("OpenAPI JSON →  {scheme}://{addr_str}/api/openapi.json");
    if let Some(fp) = &fingerprint {
        println!("TLS fingerprint (SHA-256) → {fp}");
    }

    let addr: SocketAddr = addr_str.parse().expect("invalid bind address");
    // The binary runs until killed; nothing ever fires this.
    let (_tx, rx) = tokio::sync::oneshot::channel();

    if let Err(e) = serve(state, addr, tls, rx).await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
