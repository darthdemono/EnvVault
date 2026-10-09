//! `unv catalogue` — the signed provider catalogue (Phase 31).
//!
//! The format, signature and cache rules live in `vault_core::catalogue`; this
//! file is I/O. Nothing here touches the vault, so none of it asks for a
//! password. The catalogue is public reference data, so unlike the credential
//! emitters its output may go to stdout.

use crate::enrich::bundled_providers;
use crate::error::{CliError, CliResult};
use crate::out;
use clap::Subcommand;
use serde_json::json;
use std::path::PathBuf;
use vault_core::catalogue as cat;

pub use vault_core::catalogue::DEFAULT_URL;
const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Subcommand)]
pub enum CatalogueCmd {
    /// Fetch the whole catalogue, verify it against the pinned key and cache it.
    ///
    /// One file is fetched, never one provider, so the host cannot learn which
    /// issuers your vault holds credentials for.
    Update {
        #[arg(long, default_value = DEFAULT_URL)]
        url: String,
        /// Install a catalogue from disk instead (air-gapped machines). Verified
        /// exactly like a downloaded one.
        #[arg(long, conflicts_with = "url")]
        file: Option<PathBuf>,
    },
    /// Which table enrich is using: the cached catalogue or the compiled one.
    Show,
    /// What the cached catalogue adds to, or changes in, the compiled table.
    Diff,
    /// Publisher: dump the compiled table as providers JSON, to seed a source file.
    Export,
    /// Publisher: stamp and sign a providers JSON file with an Ed25519 seed.
    Sign {
        /// JSON array of providers.
        input: PathBuf,
        /// File holding the 32-byte seed as 64 hex digits.
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
}

fn now_utc() -> String {
    let t = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn invalid(e: impl ToString) -> CliError {
    CliError::invalid(e.to_string())
}

fn fetch(url: &str) -> CliResult<Vec<u8>> {
    if !url.starts_with("https://") {
        return Err(invalid("the catalogue is only fetched over https"));
    }
    let client =
        crate::tls::build_public_client(std::time::Duration::from_secs(20), "envv-catalogue")?;
    let resp = client
        .get(url)
        .send()
        .and_then(|r| r.error_for_status())
        .map_err(|e| CliError::unavailable(format!("Cannot fetch {url}: {e}")))?;
    let bytes = resp
        .bytes()
        .map_err(|e| CliError::unavailable(format!("Cannot read {url}: {e}")))?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid("catalogue is over 4 MiB; refusing"));
    }
    Ok(bytes.to_vec())
}

pub fn run(cmd: &CatalogueCmd) -> CliResult {
    match cmd {
        CatalogueCmd::Update { url, file } => {
            let raw = match file {
                Some(p) => std::fs::read(p)
                    .map_err(|e| CliError::from(format!("Cannot read {}: {e}", p.display())))?,
                None => fetch(url)?,
            };
            let c = cat::store(&raw).map_err(invalid)?;
            out::ok(
                "catalogue.update",
                json!({ "generated_at": c.generated_at, "providers": c.providers.len() }),
                || {
                    println!(
                        "Catalogue {} cached ({} providers).",
                        c.generated_at,
                        c.providers.len()
                    )
                },
            );
        }
        CatalogueCmd::Show => {
            let cached = cat::load_cached();
            let data = match &cached {
                Some(c) => json!({
                    "source": "catalogue", "generated_at": c.generated_at,
                    "providers": c.providers.len(), "bundled": bundled_providers().len(),
                }),
                None => json!({ "source": "bundled", "providers": bundled_providers().len() }),
            };
            out::ok("catalogue.show", data, || match &cached {
                Some(c) => println!(
                    "Using catalogue {} ({} providers) over the compiled table ({}).",
                    c.generated_at,
                    c.providers.len(),
                    bundled_providers().len()
                ),
                None => println!(
                    "No verified catalogue cached; using the compiled table ({} providers). \
                     Run `unv catalogue update`.",
                    bundled_providers().len()
                ),
            });
        }
        CatalogueCmd::Diff => {
            let c = cat::load_cached().ok_or_else(|| {
                CliError::not_found("No verified catalogue cached; run `unv catalogue update`.")
            })?;
            let built = bundled_providers();
            let mut added = Vec::new();
            let mut changed = Vec::new();
            for p in &c.providers {
                match built.iter().find(|b| b.prefix == p.prefix) {
                    None => added.push(p.prefix.clone()),
                    Some(b) if b != p => changed.push(p.prefix.clone()),
                    _ => {}
                }
            }
            let dropped: Vec<_> = built
                .iter()
                .filter(|b| !c.providers.iter().any(|p| p.prefix == b.prefix))
                .map(|b| b.prefix.clone())
                .collect();
            out::ok(
                "catalogue.diff",
                json!({ "added": added, "changed": changed, "not_in_catalogue": dropped }),
                || {
                    println!("added: {}", added.join(" "));
                    println!("changed: {}", changed.join(" "));
                    println!("compiled only (still used): {}", dropped.join(" "));
                },
            );
        }
        CatalogueCmd::Export => {
            let doc = serde_json::to_string_pretty(&bundled_providers()).map_err(invalid)?;
            println!("{doc}");
        }
        CatalogueCmd::Sign {
            input,
            key_file,
            out: out_path,
        } => {
            let providers =
                serde_json::from_slice(&std::fs::read(input).map_err(|e| {
                    CliError::from(format!("Cannot read {}: {e}", input.display()))
                })?)
                .map_err(invalid)?;
            let mut seed = [0u8; 32];
            let hexed = std::fs::read_to_string(key_file)
                .map_err(|e| CliError::from(format!("Cannot read key file: {e}")))?;
            hex::decode_to_slice(hexed.trim(), &mut seed)
                .map_err(|_| invalid("key file must hold 64 hex digits"))?;
            let c = cat::Catalogue {
                schema: cat::SCHEMA,
                generated_at: now_utc(),
                providers,
            };
            let signed = cat::sign(&c, &seed).map_err(invalid)?;
            match out_path {
                Some(p) => {
                    std::fs::write(p, signed).map_err(|e| {
                        CliError::from(format!("Cannot write {}: {e}", p.display()))
                    })?;
                    out::ok(
                        "catalogue.sign",
                        json!({ "written": p.display().to_string() }),
                        || println!("Wrote {}", p.display()),
                    );
                }
                None => println!("{signed}"),
            }
        }
    }
    Ok(())
}
