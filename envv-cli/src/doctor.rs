//! `unv doctor` — everything that can be checked about a vault without
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
            "Run `unv doctor` on the machine hosting the vault.",
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
                    "Restore from `unv backup restore-archive` or a .vaultbak.",
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

/// Row-per-entry storage (Phase 30): the schema is current, every row still
/// hashes to its recorded content hash, and no pre-conversion backup is left
/// lying around.
fn check_storage(access: &Access) -> Finding {
    if matches!(access, Access::Remote(_)) {
        return Finding::at(
            "storage",
            Level::Note,
            "Skipped: the database lives on the server",
            "",
        );
    }
    let conn = match access.conn() {
        Ok(c) => c,
        Err(e) => return Finding::at("storage", Level::Fail, e.to_string(), ""),
    };
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
    match vault_core::verify_vault_integrity(&conn) {
        Ok(true) => {}
        Ok(false) => {
            return Finding::at(
                "storage",
                Level::Fail,
                "A stored row no longer matches its content hash, or the rows no longer match the vault version",
                "Something wrote to the database outside UnENVerse. Restore from `unv backup restore-archive` or a .vaultbak.",
            )
        }
        Err(e) => return Finding::at("storage", Level::Fail, e, ""),
    }
    let rows = count("SELECT COUNT(*) FROM vault_rows WHERE kind = 'entry'");
    // Phase 30.2: say how stale a writer can be and still be merged.
    let window = match vault_core::storage::merge_window(&conn) {
        Ok(Some((since, n))) => format!("; a writer that last read the vault after {since} can still be merged ({n} saves kept)"),
        _ => String::new(),
    };
    let hist = count("SELECT COUNT(*) FROM vault_history");
    let mut bak = crate::access::default_db_path().into_os_string();
    bak.push(".v1.bak");
    if std::path::Path::new(&bak).exists() {
        Finding::at(
            "storage",
            Level::Note,
            format!("{rows} entry rows, {hist} with history{window}. A pre-conversion backup still exists"),
            "Once you are satisfied the vault opens correctly, delete the `.v1.bak` file beside it: it holds the same secrets in the old format.",
        )
    } else {
        Finding::ok(
            "storage",
            format!("{rows} entry rows, {hist} with history; every row verifies{window}"),
        )
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
             (`unv backup restore-archive`), which carries both files.",
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
                "Present beside {} — back both up together (`unv backup archive`)",
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
            "Keep the UnENVerse data directory out of shared locations.",
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
            "Run `unv pool reset <pool>`, or re-add the entries.",
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

/// Entries with no stable `id` (Phase 23, E12).
///
/// `entry_ck` falls back to `provider|account_name|key_id` for an entry without
/// one, and that tuple is what RBAC scoped writes, `unv entry rm` and the
/// merge path all match on. Two entries differing only by their `label` would
/// collide there — so a scoped write meant for one would act on the other.
///
/// The fix is **not** to add `label` to the tuple: that would change every
/// existing `entry_ck` and silently re-target scoping on every pre-id vault.
/// It is to backfill the id, which the desktop app already does in
/// `finishInit()`. This check exists for the entries an older CLI wrote.
fn check_entry_ids(vault: &Value) -> Finding {
    let n = count_idless(vault);
    if n == 0 {
        Finding::ok("entry-ids", "every entry has a stable id")
    } else {
        Finding::at(
            "entry-ids",
            Level::Warn,
            format!(
                "{n} entr{} no stable id",
                if n == 1 { "y has" } else { "ies have" }
            ),
            "Such an entry is identified by provider|account|key_id, which two entries \
             can share. Run `unv doctor --fix` to backfill; the app does it on unlock.",
        )
    }
}

/// Membership that names a non-bundle or missing parent is safely read as
/// unbundled, but should be surfaced and repairable after an older-build edit.
fn check_bundle_membership(vault: &Value) -> Finding {
    let bundle_ids: std::collections::HashSet<String> = crate::data::entries(vault)
        .iter()
        .filter(|entry| entry.get("secretType").and_then(Value::as_str) == Some("bundle"))
        .filter_map(|entry| entry.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let dangling: Vec<String> = crate::data::entries(vault)
        .iter()
        .filter(|entry| {
            entry
                .get("bundle_id")
                .and_then(Value::as_str)
                .is_some_and(|id| !bundle_ids.contains(id))
        })
        .map(|entry| {
            entry
                .get("provider")
                .and_then(Value::as_str)
                .unwrap_or("unnamed")
                .to_owned()
        })
        .collect();
    if dangling.is_empty() {
        Finding::ok("bundle-membership", "every bundle member has a bundle")
    } else {
        Finding::at(
            "bundle-membership",
            Level::Warn,
            format!(
                "{} entr{} point to a missing bundle: {}",
                dangling.len(),
                if dangling.len() == 1 { "y" } else { "ies" },
                dangling.join(", ")
            ),
            "Run `unv doctor --fix` to make these entries standalone.",
        )
    }
}

fn clear_dangling_bundle_memberships(vault: &mut Value) -> usize {
    let bundle_ids: std::collections::HashSet<String> = crate::data::entries(vault)
        .iter()
        .filter(|entry| entry.get("secretType").and_then(Value::as_str) == Some("bundle"))
        .filter_map(|entry| entry.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let mut fixed = 0;
    for entry in crate::data::entries_mut(vault) {
        let dangling = entry
            .get("bundle_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !bundle_ids.contains(id));
        if dangling {
            for key in ["bundle_id", "bundle_slot", "bundle_order"] {
                if let Some(object) = entry.as_object_mut() {
                    let _ = object.remove(key);
                }
            }
            fixed += 1;
        }
    }
    fixed
}

fn count_idless(vault: &Value) -> usize {
    crate::data::entries(vault)
        .iter()
        .filter(|e| {
            e.get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().is_empty())
                .unwrap_or(true)
        })
        .count()
}

/// Backfill the ids `check_entry_ids` reports.
///
/// Deliberately the *only* thing `--fix` does. Every other finding this command
/// reports is either informational or needs a decision — there is no `--repair`
/// for a missing salt, because nothing can reconstruct 16 bytes of CSPRNG output
/// and a flag that appeared to offer it would be discovered as a lie during a
/// restore.
fn fix_entry_ids(access: &Access) -> CliResult<(usize, usize)> {
    let mut vault = access.load_vault_or_empty()?;
    let mut fixed = 0usize;
    for e in crate::data::entries_mut(&mut vault) {
        let missing = e
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);
        if missing {
            e["id"] = json!(vault_core::new_uuid());
            fixed += 1;
        }
    }
    let bundles_fixed = clear_dangling_bundle_memberships(&mut vault);
    if fixed > 0 || bundles_fixed > 0 {
        access.save(&vault)?;
    }
    Ok((fixed, bundles_fixed))
}

/// Run every check.
///
/// `access` is `None` when the vault could not be opened — which is precisely
/// when someone runs this command, so the file-level checks still run and the
/// reason is reported as a finding. An earlier version took `&Access` and
/// therefore failed with "no vault found" on a vault with a missing salt: the
/// one condition it most needed to diagnose.
/// The checks that need the database file: structure, row hashes, the salt pairing,
/// file permissions and the audit chain. The desktop app builds an `Access::Local`
/// from the key it holds and calls this (Phase 33.2b); `unv doctor` runs the same
/// functions.
pub fn file_findings(access: &Access) -> Vec<Value> {
    let mut all = vec![
        check_integrity(access),
        check_storage(access),
        check_salt(Some(access)),
    ];
    all.extend(check_permissions());
    all.push(check_audit(access));
    all.iter().map(Finding::to_json).collect()
}

/// The checks that read only the vault document: schema, ids, bundle membership
/// and pools. Pure, so the desktop app can run them over whichever vault it holds
/// (local or remote, the A1 rule). The database-level checks (integrity, storage,
/// salt, permissions, audit) need the file and remain `unv doctor`'s alone.
pub fn document_findings(vault: &Value) -> Vec<Value> {
    [
        check_schema(vault),
        check_entry_ids(vault),
        check_bundle_membership(vault),
        check_pools(vault),
    ]
    .iter()
    .map(Finding::to_json)
    .collect()
}

pub fn run(access: Option<&Access>, open_error: Option<String>, fix: bool) -> CliResult {
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

    // Repair before reporting, so the report describes the vault as it is when
    // the command exits rather than as it was when it started — a `--fix` run
    // that still printed the warning it had just repaired would be read as a
    // failed repair.
    if fix {
        let (ids_fixed, bundles_fixed) = fix_entry_ids(access)?;
        let total = ids_fixed + bundles_fixed;
        findings.push(Finding::ok(
            "fix",
            if total == 0 {
                "nothing to repair".to_string()
            } else {
                format!("backfilled {ids_fixed} id(s), cleared {bundles_fixed} dangling bundle membership(s)")
            },
        ));
    }
    let vault = if fix {
        access.load_vault_or_empty()?
    } else {
        vault
    };

    findings.insert(0, check_integrity(access));
    findings.insert(1, check_storage(access));
    findings.push(check_schema(&vault));
    findings.push(check_entry_ids(&vault));
    findings.push(check_bundle_membership(&vault));
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

    // The exit code is the point: a script runs `unv doctor` and branches on
    // it. `fail` is a broken vault, which is `invalid` rather than `unavailable`
    // because retrying will not help.
    match worst {
        Level::Fail => Err(CliError::invalid(
            "Vault has failing checks — see the findings above",
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dangling_membership_is_reported_and_repaired_as_standalone() {
        let mut vault = json!({
            "api_keys": [
                {"id": "member", "provider": "Orphan", "bundle_id": "deleted", "bundle_slot": "slot", "bundle_order": 10},
                {"id": "bundle", "provider": "Valid", "secretType": "bundle"},
                {"id": "child", "provider": "Child", "bundle_id": "bundle", "bundle_slot": "child"}
            ]
        });

        let finding = check_bundle_membership(&vault);
        assert_eq!(finding.level, Level::Warn);
        assert!(finding.message.contains("Orphan"));
        assert_eq!(clear_dangling_bundle_memberships(&mut vault), 1);
        assert_eq!(check_bundle_membership(&vault).level, Level::Ok);
        assert!(vault["api_keys"][0].get("bundle_id").is_none());
        assert!(vault["api_keys"][0].get("bundle_slot").is_none());
        assert_eq!(vault["api_keys"][2]["bundle_id"], "bundle");
    }
}
