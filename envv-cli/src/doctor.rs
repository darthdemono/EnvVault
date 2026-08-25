//! `envv doctor` — everything that can be checked about a vault without
//! changing it.
//!
//! One command, several independent checks, each reporting on its own. The
//! design rule is that **a check either proves something or says it could not
//! run** — a check that quietly passes because it did not execute is worse than
//! no check, because it converts "unknown" into "fine".
//!
//! Deliberately absent: any repair for a missing salt. The salt is 16 bytes of
//! CSPRNG output, written once, derived from nothing and duplicated nowhere. No
//! command can reconstruct it. `doctor` reports the condition and says the vault
//! is unrecoverable, because the alternative — a `--repair` flag that appears to
//! offer recovery — would be discovered as a lie at the worst possible moment.

use serde_json::{json, Value};

use crate::access::Access;
use crate::error::{CliError, CliResult};

/// How bad a finding is. Determines the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    /// Worth knowing, nothing is broken.
    Note,
    /// Something is wrong but the vault still works.
    Warn,
    /// The vault is damaged or unopenable.
    Fail,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Note => "note",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }
}

pub struct Finding {
    pub check: &'static str,
    pub level: Level,
    pub message: String,
    /// What to do about it. Empty when there is nothing to do.
    pub remedy: String,
}

impl Finding {
    fn ok(check: &'static str, message: impl Into<String>) -> Self {
        Self {
            check,
            level: Level::Ok,
            message: message.into(),
            remedy: String::new(),
        }
    }
    fn at(
        check: &'static str,
        level: Level,
        message: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self {
            check,
            level,
            message: message.into(),
            remedy: remedy.into(),
        }
    }
    fn to_json(&self) -> Value {
        json!({
            "check": self.check,
            "level": self.level.as_str(),
            "message": self.message,
            "remedy": self.remedy,
        })
    }
}

/// SQLCipher integrity check.
///
/// Runs `PRAGMA integrity_check`, which walks the b-trees rather than merely
/// opening the file — a database can open cleanly and still be corrupt in a page
/// nothing has read yet.
fn check_integrity(access: &Access) -> Finding {
    match access {
        Access::Remote(_) => Finding::at(
            "integrity",
            Level::Note,
            "Skipped: the database lives on the server",
            "Run `envv doctor` on the machine hosting the vault.",
        ),
        Access::Local(_) => {
            let conn = match access.conn() {
                Ok(c) => c,
                Err(e) => return Finding::at("integrity", Level::Fail, e.to_string(), ""),
            };
            let result: Result<String, _> =
                conn.query_row("PRAGMA integrity_check", [], |r| r.get(0));
            match result {
                Ok(s) if s == "ok" => Finding::ok("integrity", "Database structure is intact"),
                Ok(s) => Finding::at(
                    "integrity",
                    Level::Fail,
                    format!("SQLCipher reports: {s}"),
                    "Restore from `envv backup restore-archive` or a .vaultbak.",
                ),
                Err(e) => Finding::at(
                    "integrity",
                    Level::Fail,
                    format!("Integrity check failed to run: {e}"),
                    "",
                ),
            }
        }
    }
}

/// The salt is present and paired with the database.
fn check_salt(access: Option<&Access>) -> Finding {
    if matches!(access, Some(Access::Remote(_))) {
        return Finding::at("salt", Level::Note, "Skipped: remote vault", "");
    }
    let salt_path = crate::access::default_salt_path();
    let db_path = crate::access::default_db_path();
    if !salt_path.exists() {
        return Finding::at(
            "salt",
            Level::Fail,
            format!(
                "{} is missing — this vault cannot be opened",
                salt_path.display()
            ),
            "There is no repair for this. The salt is random bytes written once and \
             stored nowhere else; nothing can recompute it. Restore from an archive \
             (`envv backup restore-archive`), which carries both files.",
        );
    }
    match std::fs::metadata(&salt_path) {
        Ok(m) if m.len() != 16 => Finding::at(
            "salt",
            Level::Fail,
            format!("{} is {} bytes, expected 16", salt_path.display(), m.len()),
            "The file is damaged. Restore from an archive.",
        ),
        Ok(_) => Finding::ok(
            "salt",
            format!(
                "Present beside {} — back both up together (`envv backup archive`)",
                db_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default()
            ),
        ),
        Err(e) => Finding::at("salt", Level::Warn, format!("Cannot stat salt: {e}"), ""),
    }
}

/// File permissions on everything that holds or unlocks a secret.
///
/// Reports "not enforceable" on Windows rather than passing: NTFS inherits the
/// directory ACL and there is no chmod equivalent, so claiming 0600 there would
/// be a check that always passes and proves nothing.
fn check_permissions() -> Vec<Finding> {
    let paths = [
        ("vault database", crate::access::default_db_path()),
        ("vault salt", crate::access::default_salt_path()),
        ("session file", crate::session::session_path()),
    ];
    let pool = vault_core::pool::state_path();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut out = Vec::new();
        let mut all: Vec<(&str, std::path::PathBuf)> = paths.to_vec();
        if let Some(p) = pool {
            all.push(("pool state", p));
        }
        for (label, path) in all {
            if !path.exists() {
                continue;
            }
            match std::fs::metadata(&path) {
                Ok(m) => {
                    let mode = m.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        out.push(Finding::at(
                            "permissions",
                            Level::Warn,
                            format!("{label} is mode {mode:o} — readable by other users"),
                            format!("chmod 600 {}", path.display()),
                        ));
                    }
                }
                Err(e) => out.push(Finding::at(
                    "permissions",
                    Level::Warn,
                    format!("Cannot stat {label}: {e}"),
                    "",
                )),
            }
        }
        if out.is_empty() {
            out.push(Finding::ok(
                "permissions",
                "Vault, salt, session and pool files are owner-only",
            ));
        }
        out
    }
    #[cfg(not(unix))]
    {
        let _ = (paths, pool);
        vec![Finding::at(
            "permissions",
            Level::Note,
            "Not enforceable on this platform — files inherit the directory ACL",
            "Keep the EnvVault data directory out of shared locations.",
        )]
    }
}

/// Pool state parses, and every member still names an entry that exists.
///
/// The dangling-member check is invariant 2 applied to a file outside the vault:
/// `pools.json` holds entry keys, and nothing tells it when an entry is renamed
/// or deleted.
fn check_pools(vault: &Value) -> Finding {
    let Some(path) = vault_core::pool::state_path() else {
        return Finding::at("pools", Level::Note, "No pool state directory", "");
    };
    if !path.exists() {
        return Finding::ok("pools", "No pool state yet");
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            return Finding::at(
                "pools",
                Level::Warn,
                format!("Cannot read {}: {e}", path.display()),
                "",
            )
        }
    };
    let parsed: Result<Value, _> = serde_json::from_str(&raw);
    let Ok(state) = parsed else {
        return Finding::at(
            "pools",
            Level::Warn,
            format!("{} is not valid JSON", path.display()),
            "Delete it — cursors and cooldowns rebuild themselves; nothing in it is a secret.",
        );
    };

    let known: std::collections::HashSet<String> = crate::data::entries(vault)
        .iter()
        .map(vault_core::entry_ck)
        .collect();
    let mut dangling = Vec::new();
    if let Some(pools) = state.get("pools").and_then(|p| p.as_object()) {
        for (name, p) in pools {
            for m in p
                .get("members")
                .and_then(|m| m.as_array())
                .unwrap_or(&vec![])
            {
                if let Some(ck) = m.as_str() {
                    if !known.contains(ck) {
                        dangling.push(format!("{name}: {ck}"));
                    }
                }
            }
        }
    }
    if dangling.is_empty() {
        Finding::ok("pools", "Pool state parses and every member exists")
    } else {
        Finding::at(
            "pools",
            Level::Warn,
            format!(
                "{} pool member(s) name entries that no longer exist: {}",
                dangling.len(),
                dangling.join(", ")
            ),
            "Run `envv pool reset <pool>`, or re-add the entries.",
        )
    }
}

/// The audit hash chain still verifies.
fn check_audit(access: &Access) -> Finding {
    // Reuse the existing verifier rather than reimplementing the hash formula —
    // two implementations of a tamper check is one too many.
    match crate::scan::verify_chain(access) {
        Ok(0) => Finding::ok("audit", "No hash-chained rows yet"),
        Ok(n) => Finding::ok("audit", format!("Hash chain intact across {n} rows")),
        Err(e) => Finding::at(
            "audit",
            Level::Fail,
            e.to_string(),
            "Rows were altered or removed. The vault data is unaffected, but the log \
             can no longer prove what happened.",
        ),
    }
}

/// The vault loads and its top-level shape is what every reader assumes.
fn check_schema(vault: &Value) -> Finding {
    let mut missing = Vec::new();
    for key in ["api_keys", "projects", "user_categories"] {
        if !vault.get(key).map(|v| v.is_array()).unwrap_or(false) {
            missing.push(key);
        }
    }
    if missing.is_empty() {
        Finding::ok(
            "schema",
            format!(
                "{} entries, {} projects",
                crate::data::entries(vault).len(),
                crate::data::projects(vault).len()
            ),
        )
    } else {
        Finding::at(
            "schema",
            Level::Warn,
            format!(
                "Vault is missing top-level array(s): {}",
                missing.join(", ")
            ),
            "An import may have written a partial document. Restore from a backup.",
        )
    }
}

/// Run every check.
///
/// `access` is `None` when the vault could not be opened — which is precisely
/// when someone runs this command, so the file-level checks still run and the
/// reason is reported as a finding. An earlier version took `&Access` and
/// therefore failed with "no vault found" on a vault with a missing salt: the
/// one condition it most needed to diagnose.
pub fn run(access: Option<&Access>, open_error: Option<String>) -> CliResult {
    let mut findings = Vec::new();

    // These need no key and no database — they are what is left to say when
    // nothing opens.
    findings.push(check_salt(access));
    findings.extend(check_permissions());

    let Some(access) = access else {
        findings.push(Finding::at(
            "open",
            Level::Fail,
            open_error.unwrap_or_else(|| "The vault could not be opened".into()),
            "Checks needing the vault contents were skipped.",
        ));
        return report(findings);
    };

    let vault = match access.load_vault_or_empty() {
        Ok(v) => v,
        Err(e) => {
            findings.push(Finding::at("open", Level::Fail, e.to_string(), ""));
            return report(findings);
        }
    };

    findings.insert(0, check_integrity(access));
    findings.push(check_schema(&vault));
    findings.push(check_pools(&vault));
    findings.push(check_audit(access));
    report(findings)
}

fn report(findings: Vec<Finding>) -> CliResult {
    let worst = findings.iter().map(|f| f.level).max().unwrap_or(Level::Ok);
    let payload = json!({
        "status": worst.as_str(),
        "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
    });

    crate::out::ok("doctor", payload, || {
        for f in &findings {
            let tag = match f.level {
                Level::Ok => "  ok  ",
                Level::Note => " note ",
                Level::Warn => " warn ",
                Level::Fail => " FAIL ",
            };
            println!("[{tag}] {:<12} {}", f.check, f.message);
            if !f.remedy.is_empty() {
                for line in f.remedy.split('\n') {
                    println!("               → {}", line.trim());
                }
            }
        }
    });

    // The exit code is the point: a script runs `envv doctor` and branches on
    // it. `fail` is a broken vault, which is `invalid` rather than `unavailable`
    // because retrying will not help.
    match worst {
        Level::Fail => Err(CliError::invalid(
            "Vault has failing checks — see the findings above",
        )),
        _ => Ok(()),
    }
}
