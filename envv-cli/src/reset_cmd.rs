//! `envv reset-vault` — delete the local vault, what the app's Settings -> Reset
//! does (Phase 33.5). Local only, and it never asks for the master password: the
//! point is the case where it is lost. Hence the guard rails the app's version
//! gets from a confirmation dialog: `--yes` or a terminal answer, a non-tty
//! refusal (`confirm`), `--dry-run` support, and the path printed before and
//! after. A `.v1.bak` left by the schema migration is *not* removed: it is a
//! backup, and a reset that silently deleted the only other copy would be worse
//! than the vault it replaces.

use crate::access::{default_db_path, default_salt_path};
use crate::error::{CliError, CliResult};
use crate::{fmt, out};
use serde_json::json;
use std::path::PathBuf;

pub fn run(yes: bool, dry_run: bool) -> CliResult {
    let db = default_db_path();
    let salt = default_salt_path();
    let mut targets: Vec<PathBuf> = vec![db.clone(), salt];
    for suffix in ["-wal", "-shm"] {
        let mut s = db.clone().into_os_string();
        s.push(suffix);
        targets.push(PathBuf::from(s));
    }
    let existing: Vec<&PathBuf> = targets.iter().filter(|p| p.exists()).collect();
    if existing.is_empty() {
        return Err(CliError::not_found(format!(
            "No local vault at {}",
            db.display()
        )));
    }
    if dry_run {
        out::ok(
            "reset-vault",
            json!({ "dry_run": true, "would_remove": existing.iter().map(|p| p.display().to_string()).collect::<Vec<_>>() }),
            || {
                for p in &existing {
                    println!("would remove {}", p.display());
                }
            },
        );
        return Ok(());
    }
    let question = format!(
        "Permanently delete the local vault at {} and its salt? This cannot be undone.",
        db.display()
    );
    if !fmt::confirm(&question, yes)? {
        return Err(CliError::new(
            crate::error::Code::NeedsConfirmation,
            "Reset cancelled",
        ));
    }
    let mut removed = Vec::new();
    for p in existing {
        std::fs::remove_file(p)
            .map_err(|e| CliError::from(format!("Cannot remove {}: {e}", p.display())))?;
        removed.push(p.display().to_string());
    }
    out::ok("reset-vault", json!({ "removed": removed }), || {
        for p in &removed {
            println!("removed {p}");
        }
    });
    Ok(())
}
