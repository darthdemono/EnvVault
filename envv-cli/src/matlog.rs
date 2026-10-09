//! Phase 36 — the materialisation log (ADR-0142).
//!
//! Local `unv exec`, `--out` and revealed output are deliberately not in the
//! vault's audit chain: every read used to write a row, and a chain that grows
//! with reads cannot be pruned without breaking the chain that makes it worth
//! having. Blast radius still needs to know what reached *this* machine, so
//! those events go to a separate, bounded, ring-buffered file beside
//! `sessions.json`, outside any hash chain.
//!
//! What a record holds: when, how (`exec`, `file`, `stdout`), which vault, and
//! which secrets' exact values were in what was written, as entry, field and
//! fingerprint, never the values. A record with no vault secret in it is not
//! written. The file is 0600 and keeps the newest [`MAX_RECORDS`].
//!
//! Covered: `exec`, anything written with `--out` (a pulled node file included),
//! anything printed with `--reveal` by any command, and the desktop app's
//! clipboard writes (`matlog_note`). **Not covered:** a value read by anything
//! that opened the vault directly. The log is evidence of what the CLI did here, not of what a
//! compromised user could have done.

use crate::exposure::Matcher;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use vault_core::blast::Exposed;

#[cfg(not(test))]
pub const MAX_RECORDS: usize = 5000;
/// Small under test so the ring is exercised without thousands of appends.
#[cfg(test)]
pub const MAX_RECORDS: usize = 50;
/// Compact when the file holds this many records, so the rewrite happens once per
/// 20% of growth rather than on every append.
const COMPACT_AT: usize = MAX_RECORDS + MAX_RECORDS / 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub at: String,
    pub kind: String,
    pub host: String,
    pub vault: String,
    pub note: String,
    pub exposed: Vec<Exposed>,
}

pub fn path() -> PathBuf {
    crate::session::state_file("materialisations.jsonl")
}

/// The vault this process last loaded, so a writer deep in a command can tell
/// what it just wrote without every call site passing the vault down.
static VAULT: Mutex<Option<(Value, String)>> = Mutex::new(None);

pub fn remember(vault: &Value, label: &str) {
    if let Ok(mut g) = VAULT.lock() {
        *g = Some((vault.clone(), label.to_string()));
    }
}

fn read_records(path: &Path) -> Vec<Record> {
    std::fs::read_to_string(path)
        .map(|t| {
            t.lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        })
        .unwrap_or_default()
}

pub fn read(path: &Path) -> Vec<Record> {
    read_records(path)
}

/// Appends one record, compacting to the newest [`MAX_RECORDS`] when the file
/// has grown by a fifth past that.
pub fn append(path: &Path, rec: &Record) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| e.to_string())?;
    let line = serde_json::to_string(rec).map_err(|e| e.to_string())?;
    writeln!(f, "{line}").map_err(|e| e.to_string())?;
    drop(f);
    // Counting newlines is a byte scan; parsing every line on every append is not.
    let lines = std::fs::read(path)
        .map(|b| b.iter().filter(|c| **c == b'\n').count())
        .unwrap_or(0);
    if lines >= COMPACT_AT {
        let all = read_records(path);
        let keep = &all[all.len() - MAX_RECORDS..];
        let tmp = path.with_extension("jsonl.tmp");
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut out = o.open(&tmp).map_err(|e| e.to_string())?;
        for r in keep {
            writeln!(
                out,
                "{}",
                serde_json::to_string(r).map_err(|e| e.to_string())?
            )
            .map_err(|e| e.to_string())?;
        }
        out.sync_all().map_err(|e| e.to_string())?;
        drop(out);
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Notes that `text` was just handed to something outside the vault. Never
/// fails the command: a log that cannot be written is reported, not fatal.
pub fn note(kind: &str, note: &str, text: &str) {
    note_to(&path(), kind, note, text);
}

pub fn note_to(path: &Path, kind: &str, note: &str, text: &str) {
    let Some((vault, label)) = VAULT.lock().ok().and_then(|g| g.clone()) else {
        return;
    };
    let exposed = Matcher::from_vault(&vault).find(text);
    if exposed.is_empty() {
        return;
    }
    let rec = Record {
        at: vault_core::iso_now(),
        kind: kind.to_string(),
        host: crate::node_agent::hostname(),
        vault: label,
        note: note.to_string(),
        exposed,
    };
    if let Err(e) = append(path, &rec) {
        tracing::warn!(error = %e, "could not write the materialisation log");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scratch() -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("envv-matlog-{n}"));
        std::fs::create_dir_all(&d).unwrap();
        d.join("materialisations.jsonl")
    }

    fn rec(i: usize) -> Record {
        Record {
            at: format!("2026-10-{:02}T00:00:00Z", (i % 28) + 1),
            kind: "exec".into(),
            host: "h".into(),
            vault: "local".into(),
            note: i.to_string(),
            exposed: vec![],
        }
    }

    #[test]
    fn the_log_is_a_ring_that_keeps_the_newest_records() {
        let p = scratch();
        for i in 0..(COMPACT_AT + 10) {
            append(&p, &rec(i)).unwrap();
        }
        let all = read(&p);
        assert!(all.len() <= COMPACT_AT, "{} records", all.len());
        assert_eq!(
            all.last().unwrap().note,
            (COMPACT_AT + 9).to_string(),
            "the newest survived"
        );
        assert!(all.len() >= MAX_RECORDS);
        assert_ne!(all[0].note, "0", "the oldest were dropped");
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let p = scratch();
        append(&p, &rec(1)).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_record_names_the_secret_and_never_holds_its_value() {
        let p = scratch();
        remember(
            &json!({ "api_keys": [{ "id": "e1", "provider": "Stripe", "api_key": "sk_live_SECRETVALUE1" }] }),
            "local",
        );
        note_to(
            &p,
            "exec",
            "project=web",
            "A=1\nSTRIPE=sk_live_SECRETVALUE1\n",
        );
        note_to(&p, "file", "/tmp/x", "nothing secret in here");
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            !text.contains("sk_live_SECRETVALUE1"),
            "the log holds a value"
        );
        let all = read(&p);
        assert_eq!(all.len(), 1, "a write with no secret in it is not logged");
        assert_eq!(all[0].exposed[0].entry_id, "e1");
        assert_eq!(all[0].kind, "exec");
    }

    #[test]
    fn a_garbled_line_is_skipped_not_fatal() {
        let p = scratch();
        append(&p, &rec(1)).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .unwrap()
            .write_all(b"not json\n")
            .unwrap();
        append(&p, &rec(2)).unwrap();
        assert_eq!(read(&p).len(), 2);
    }
}
