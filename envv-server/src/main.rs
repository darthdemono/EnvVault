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

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/var/lib"))
        .join("envv-server");

    let db_path   = args.db_path.unwrap_or_else(|| data_dir.join("vault.db"));
    let salt_path = args.salt_path.unwrap_or_else(|| data_dir.join("vault.salt"));

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
                let (files, fp) = ensure_self_signed_cert(&data_dir).unwrap_or_else(|e| {
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
