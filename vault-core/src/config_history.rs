//! Phase 35 — the config time machine (ADR-0141).
//!
//! Config lives in git and its secrets live elsewhere, and the two drift: the
//! copy in git is redacted, so it is not the file that runs, and the file that
//! runs is versioned by nobody. The vault is the one place that holds both, so
//! it keeps a snapshot of every rendered config whenever that config changes.
//!
//! # Two copies of each snapshot, on purpose
//!
//! `content` is the file exactly as it would be deployed, secrets included.
//! `masked` is the same render with every resolved secret replaced by its
//! fingerprint, which is what `unv project export` already prints to a
//! terminal. Every default view (list, show, diff, the app) reads `masked`, so
//! "this key changed" is visible without the key ever being read; `content`
//! is reached only with `--reveal`/`--out` or the app's Reveal. Masking the
//! stored text afterwards would not work: a rotated-away secret is no longer in
//! the vault, so nothing would know to mask it in an old snapshot.
//!
//! # Tamper evidence and retention
//!
//! Each stream (project and exporter) is a hash chain: `chain = sha256(prev ‖
//! project ‖ exporter ‖ sha(content) ‖ sha(masked) ‖ at)`. Old secrets living
//! forever is a liability, so history is pruned by policy (`keep` newest and
//! everything younger than `days`), and pruning a prefix would normally break
//! the chain. A **checkpoint** row records the chain value at the pruned
//! boundary so the remainder still verifies, and the prune also appends a row
//! to the vault's own audit chain naming that value; [`verify`] requires the two
//! to agree, so forging a checkpoint means forging the audit chain too.

use crate::textdiff;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const DEFAULT_KEEP: i64 = 50;
pub const DEFAULT_DAYS: i64 = 90;
/// A snapshot larger than this is not stored. A rendered config is kilobytes;
/// anything bigger is a file this feature was not built for.
pub const MAX_BYTES: usize = 2 * 1024 * 1024;

pub fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS config_snapshots (
             seq          INTEGER PRIMARY KEY AUTOINCREMENT,
             project      TEXT NOT NULL,
             project_name TEXT NOT NULL,
             exporter     TEXT NOT NULL,
             at           TEXT NOT NULL,
             sha256       TEXT NOT NULL,
             bytes        INTEGER NOT NULL,
             content      TEXT NOT NULL,
             masked       TEXT NOT NULL,
             exposed      TEXT NOT NULL DEFAULT '[]',
             cause        TEXT NOT NULL,
             actor        TEXT,
             chain        TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS config_snapshots_stream
             ON config_snapshots(project, exporter, seq);
         CREATE INDEX IF NOT EXISTS config_snapshots_sha ON config_snapshots(sha256);
         CREATE TABLE IF NOT EXISTS config_checkpoints (
             id                 INTEGER PRIMARY KEY AUTOINCREMENT,
             project            TEXT NOT NULL,
             exporter           TEXT NOT NULL,
             pruned_through_seq INTEGER NOT NULL,
             chain_at           TEXT NOT NULL,
             pruned_count       INTEGER NOT NULL,
             at                 TEXT NOT NULL
         );",
    )
    .map_err(|e| e.to_string())?;
    // A history created before blast radius (Phase 36) lacks the column.
    let _ = conn.execute_batch(
        "ALTER TABLE config_snapshots ADD COLUMN exposed TEXT NOT NULL DEFAULT '[]';",
    );
    Ok(())
}

fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn chain_of(
    prev: &str,
    project: &str,
    exporter: &str,
    content: &str,
    masked: &str,
    exposed: &str,
    at: &str,
) -> String {
    // `exposed` is derived data, but it is what blast radius is answered from, so
    // editing it to hide an entry must break the chain like editing the text does.
    sha(&format!(
        "envv-history-v2|{prev}|{project}|{exporter}|{}|{}|{}|{at}",
        sha(content),
        sha(masked),
        sha(exposed)
    ))
}

// ── Policy ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Policy {
    pub enabled: bool,
    pub keep: i64,
    pub days: i64,
}

fn meta_get(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM vault_meta WHERE key = ?1", [key], |r| {
        r.get(0)
    })
    .optional()
    .ok()
    .flatten()
}

fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
        params![key, value],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

pub fn policy(conn: &Connection) -> Policy {
    let num = |k: &str, d: i64| {
        meta_get(conn, k)
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|n| *n >= 0)
            .unwrap_or(d)
    };
    Policy {
        enabled: meta_get(conn, "history_enabled").as_deref() != Some("0"),
        keep: num("history_keep", DEFAULT_KEEP),
        days: num("history_days", DEFAULT_DAYS),
    }
}

pub fn set_policy(
    conn: &Connection,
    enabled: Option<bool>,
    keep: Option<i64>,
    days: Option<i64>,
) -> Result<Policy, String> {
    if let Some(k) = keep {
        if !(1..=100_000).contains(&k) {
            return Err(
                "keep must be between 1 and 100000 (a stream always keeps its newest snapshot)"
                    .into(),
            );
        }
        meta_set(conn, "history_keep", &k.to_string())?;
    }
    if let Some(d) = days {
        if !(0..=36_500).contains(&d) {
            return Err("days must be between 0 and 36500".into());
        }
        meta_set(conn, "history_days", &d.to_string())?;
    }
    if let Some(e) = enabled {
        meta_set(conn, "history_enabled", if e { "1" } else { "0" })?;
    }
    Ok(policy(conn))
}

// ── Recording ─────────────────────────────────────────────────────────────────

/// One rendered stream: which project and which exporter produced the text.
pub struct Stream<'a> {
    pub project: &'a str,
    pub project_name: &'a str,
    pub exporter: &'a str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SnapMeta {
    pub seq: i64,
    pub project: String,
    pub project_name: String,
    pub exporter: String,
    pub at: String,
    pub sha256: String,
    pub bytes: i64,
    pub cause: String,
    pub actor: Option<String>,
}

const META_COLS: &str = "seq, project, project_name, exporter, at, sha256, bytes, cause, actor";

fn meta_row(r: &rusqlite::Row) -> rusqlite::Result<SnapMeta> {
    Ok(SnapMeta {
        seq: r.get(0)?,
        project: r.get(1)?,
        project_name: r.get(2)?,
        exporter: r.get(3)?,
        at: r.get(4)?,
        sha256: r.get(5)?,
        bytes: r.get(6)?,
        cause: r.get(7)?,
        actor: r.get(8)?,
    })
}

/// Records a snapshot when `content` differs from the stream's latest. Returns
/// the new sequence number, or `None` when nothing changed (or history is off).
pub fn record(
    conn: &Connection,
    s: &Stream,
    content: &str,
    masked: &str,
    exposed: &str,
    cause: &str,
    actor: Option<&str>,
) -> Result<Option<i64>, String> {
    if !policy(conn).enabled {
        return Ok(None);
    }
    if content.len() > MAX_BYTES {
        return Err(format!(
            "{} {} renders to {} bytes; history keeps files up to {} bytes",
            s.project_name,
            s.exporter,
            content.len(),
            MAX_BYTES
        ));
    }
    // IMMEDIATE: two writers (a save's background snapshot and a push's) must not
    // both read the same tail and each extend it, or the chain forks and the
    // stream can never verify again.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let last: Option<(String, String)> = tx
        .query_row(
            "SELECT sha256, chain FROM config_snapshots WHERE project = ?1 AND exporter = ?2 \
             ORDER BY seq DESC LIMIT 1",
            params![s.project, s.exporter],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let new_sha = sha(content);
    if last.as_ref().is_some_and(|(h, _)| *h == new_sha) {
        return Ok(None);
    }
    // After a prune the newest row may be the only link back to a checkpoint;
    // either way the previous chain value is the latest row's, or genesis.
    let prev = last.map_or_else(|| genesis_for(&tx, s.project, s.exporter), |(_, c)| c);
    let at = crate::iso_now();
    let chain = chain_of(&prev, s.project, s.exporter, content, masked, exposed, &at);
    tx.execute(
        "INSERT INTO config_snapshots \
         (project, project_name, exporter, at, sha256, bytes, content, masked, exposed, cause, actor, chain) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            s.project,
            s.project_name,
            s.exporter,
            at,
            new_sha,
            content.len() as i64,
            content,
            masked,
            exposed,
            cause,
            actor,
            chain
        ],
    )
    .map_err(|e| e.to_string())?;
    let seq = tx.last_insert_rowid();
    tx.commit().map_err(|e| e.to_string())?;
    Ok(Some(seq))
}

/// The chain value a stream's first remaining snapshot extends: the newest
/// checkpoint's, or genesis when nothing was ever pruned.
fn genesis_for(conn: &Connection, project: &str, exporter: &str) -> String {
    conn.query_row(
        "SELECT chain_at FROM config_checkpoints WHERE project = ?1 AND exporter = ?2 \
         ORDER BY pruned_through_seq DESC LIMIT 1",
        params![project, exporter],
        |r| r.get(0),
    )
    .optional()
    .ok()
    .flatten()
    .unwrap_or_else(|| "genesis".to_string())
}

// ── Reading ───────────────────────────────────────────────────────────────────

pub fn list(
    conn: &Connection,
    project: Option<&str>,
    exporter: Option<&str>,
    since: Option<&str>,
    limit: i64,
) -> Result<Vec<SnapMeta>, String> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {META_COLS} FROM config_snapshots \
             WHERE (?1 IS NULL OR project = ?1 OR project_name = ?1) \
               AND (?2 IS NULL OR exporter = ?2) AND (?3 IS NULL OR at >= ?3) \
             ORDER BY seq DESC LIMIT ?4"
        ))
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(
            params![project, exporter, since, limit.clamp(1, 10_000)],
            meta_row,
        )
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

pub struct Snapshot {
    pub meta: SnapMeta,
    pub content: String,
    pub masked: String,
    /// JSON array of the vault secrets whose exact value appears in `content`.
    pub exposed: String,
}

pub fn get(conn: &Connection, seq: i64) -> Result<Option<Snapshot>, String> {
    conn.query_row(
        &format!(
            "SELECT {META_COLS}, content, masked, exposed FROM config_snapshots WHERE seq = ?1"
        ),
        [seq],
        |r| {
            Ok(Snapshot {
                meta: meta_row(r)?,
                content: r.get(9)?,
                masked: r.get(10)?,
                exposed: r.get(11)?,
            })
        },
    )
    .optional()
    .map_err(|e| e.to_string())
}

/// Snapshots whose content has this hash, newest first. This is how a hub says
/// "the file on that host is the one rendered on 3 October".
pub fn find_by_sha(conn: &Connection, sha256: &str, limit: i64) -> Result<Vec<SnapMeta>, String> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {META_COLS} FROM config_snapshots WHERE sha256 = ?1 ORDER BY seq DESC LIMIT ?2"
        ))
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![sha256, limit.clamp(1, 100)], meta_row)
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

/// What the files with this hash contained: the union over every snapshot that
/// recorded it (the same text can be recorded again after a revert), or `None`
/// when no snapshot has it, so a caller can tell "nothing exposed" from "unknown".
pub fn exposed_by_sha(
    conn: &Connection,
    sha256: &str,
) -> Result<Option<Vec<crate::blast::Exposed>>, String> {
    let mut stmt = conn
        .prepare("SELECT exposed FROM config_snapshots WHERE sha256 = ?1")
        .map_err(|e| e.to_string())?;
    let rows: Vec<String> = stmt
        .query_map([sha256], |r| r.get(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut all: Vec<crate::blast::Exposed> = Vec::new();
    for json in rows {
        let list: Vec<crate::blast::Exposed> =
            serde_json::from_str(&json).map_err(|e| e.to_string())?;
        for e in list {
            if !all.contains(&e) {
                all.push(e);
            }
        }
    }
    Ok(Some(all))
}

/// The newest snapshot of a stream.
pub fn latest(
    conn: &Connection,
    project: &str,
    exporter: &str,
) -> Result<Option<Snapshot>, String> {
    let seq: Option<i64> = conn
        .query_row(
            "SELECT seq FROM config_snapshots WHERE project = ?1 AND exporter = ?2 \
             ORDER BY seq DESC LIMIT 1",
            params![project, exporter],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    match seq {
        Some(s) => get(conn, s),
        None => Ok(None),
    }
}

/// A unified diff between two snapshots of the same stream. `masked` picks the
/// fingerprinted text (the default everywhere) or the real one.
pub fn diff(
    conn: &Connection,
    a: i64,
    b: i64,
    masked: bool,
    context: usize,
) -> Result<String, String> {
    let sa = get(conn, a)?.ok_or_else(|| format!("No snapshot #{a}"))?;
    let sb = get(conn, b)?.ok_or_else(|| format!("No snapshot #{b}"))?;
    if (&sa.meta.project, &sa.meta.exporter) != (&sb.meta.project, &sb.meta.exporter) {
        return Err(
            "Those snapshots belong to different configs; compare two of one stream".into(),
        );
    }
    let pick = |s: &Snapshot| {
        if masked {
            s.masked.clone()
        } else {
            s.content.clone()
        }
    };
    Ok(textdiff::unified(
        &format!("#{a} {}", sa.meta.at),
        &format!("#{b} {}", sb.meta.at),
        &pick(&sa),
        &pick(&sb),
        context,
    ))
}

/// Picks the two snapshots a diff should compare. With `from`/`to` unset, the two
/// newest of the stream named by `project` (and `exporter`, which is required
/// when the project has more than one stream, such as Compose and its `.env`).
pub fn resolve_pair(
    conn: &Connection,
    project: Option<&str>,
    exporter: Option<&str>,
    from: Option<i64>,
    to: Option<i64>,
) -> Result<(i64, i64), String> {
    if let (Some(a), Some(b)) = (from, to) {
        return Ok((a, b));
    }
    let project = project.ok_or("Name a project, or give both --from and --to")?;
    let rows = list(conn, Some(project), exporter, None, 1000)?;
    let mut exporters: Vec<&str> = rows.iter().map(|m| m.exporter.as_str()).collect();
    exporters.sort_unstable();
    exporters.dedup();
    if exporters.len() > 1 {
        return Err(format!(
            "'{project}' has several configs ({}); say which with --exporter",
            exporters.join(", ")
        ));
    }
    // `rows` is newest first.
    let newest = rows
        .first()
        .ok_or_else(|| format!("No snapshots of '{project}' yet"))?;
    let b = to.unwrap_or(newest.seq);
    let a = match from {
        Some(a) => a,
        None => rows
            .iter()
            .find(|m| m.seq < b)
            .map(|m| m.seq)
            .ok_or_else(|| {
                format!("'{project}' has only one snapshot, so there is nothing to compare")
            })?,
    };
    Ok((a, b))
}

// ── Retention ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, PartialEq)]
pub struct PruneReport {
    pub would_delete: i64,
    pub deleted: i64,
    pub streams_touched: i64,
    pub bytes_freed: i64,
}

/// Deletes, per stream, every snapshot that is both beyond the newest `keep` and
/// older than `days` days, leaving a checkpoint so the rest still verifies.
/// `dry_run` counts without touching anything.
pub fn prune(
    conn: &Connection,
    keep: i64,
    days: i64,
    dry_run: bool,
    actor: Option<&str>,
) -> Result<PruneReport, String> {
    let cutoff = cutoff_iso(days)?;
    let streams: Vec<(String, String)> = {
        let mut st = conn
            .prepare("SELECT DISTINCT project, exporter FROM config_snapshots")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
    };
    let mut rep = PruneReport {
        would_delete: 0,
        deleted: 0,
        streams_touched: 0,
        bytes_freed: 0,
    };
    // IMMEDIATE: two writers (a save's background snapshot and a push's) must not
    // both read the same tail and each extend it, or the chain forks and the
    // stream can never verify again.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    for (project, exporter) in streams {
        // Rows to delete: older than the cutoff AND not among the newest `keep`.
        // `keep >= 1` is enforced by the policy, so a stream never empties.
        let doomed: Vec<(i64, String, i64)> = {
            let mut st = tx
                .prepare(
                    "SELECT seq, chain, bytes FROM config_snapshots \
                     WHERE project = ?1 AND exporter = ?2 AND at < ?3 \
                       AND seq NOT IN (SELECT seq FROM config_snapshots \
                                       WHERE project = ?1 AND exporter = ?2 \
                                       ORDER BY seq DESC LIMIT ?4) \
                     ORDER BY seq ASC",
                )
                .map_err(|e| e.to_string())?;
            let rows = st
                .query_map(params![project, exporter, cutoff, keep.max(1)], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
        };
        // The doomed rows are always a prefix of the stream: older than the
        // cutoff and older than the kept window, both of which are monotone in seq.
        let Some((last_seq, last_chain, _)) = doomed.last().cloned() else {
            continue;
        };
        rep.would_delete += doomed.len() as i64;
        rep.bytes_freed += doomed.iter().map(|d| d.2).sum::<i64>();
        rep.streams_touched += 1;
        if dry_run {
            continue;
        }
        tx.execute(
            "DELETE FROM config_snapshots WHERE project = ?1 AND exporter = ?2 AND seq <= ?3",
            params![project, exporter, last_seq],
        )
        .map_err(|e| e.to_string())?;
        let at = crate::iso_now();
        tx.execute(
            "INSERT INTO config_checkpoints \
             (project, exporter, pruned_through_seq, chain_at, pruned_count, at) \
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                project,
                exporter,
                last_seq,
                last_chain,
                doomed.len() as i64,
                at
            ],
        )
        .map_err(|e| e.to_string())?;
        rep.deleted += doomed.len() as i64;
        // The audit chain is the other half of the attestation: verify() demands a
        // row naming this chain value for every checkpoint.
        crate::record_event(
            &tx,
            "config.prune",
            &project,
            Some(
                &serde_json::json!({
                    "exporter": exporter, "through_seq": last_seq,
                    "chain_at": last_chain, "count": doomed.len()
                })
                .to_string(),
            ),
            actor,
        )?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(rep)
}

fn cutoff_iso(days: i64) -> Result<String, String> {
    let now = time::OffsetDateTime::now_utc();
    let then = now
        .checked_sub(time::Duration::days(days))
        .ok_or("days is out of range")?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        then.year(),
        u8::from(then.month()),
        then.day(),
        then.hour(),
        then.minute(),
        then.second()
    ))
}

// ── Verification ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, PartialEq)]
pub struct VerifyReport {
    pub streams: i64,
    pub snapshots: i64,
    pub checkpoints: i64,
    pub problems: Vec<String>,
}

/// Recomputes every hash and every chain, and checks each checkpoint against the
/// audit chain.
pub fn verify(conn: &Connection) -> Result<VerifyReport, String> {
    let mut rep = VerifyReport {
        streams: 0,
        snapshots: 0,
        checkpoints: 0,
        problems: vec![],
    };
    let streams: Vec<(String, String)> = {
        let mut st = conn
            .prepare(
                "SELECT project, exporter FROM config_snapshots \
                 UNION SELECT project, exporter FROM config_checkpoints",
            )
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
    };
    let audit: Vec<String> = {
        let mut st = conn
            .prepare("SELECT COALESCE(details,'') FROM vault_audit WHERE action = 'config.prune'")
            .map_err(|e| e.to_string())?;
        let rows = st.query_map([], |r| r.get(0)).map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
    };
    for (project, exporter) in streams {
        rep.streams += 1;
        let label = format!("{project}/{exporter}");
        let cps: Vec<(i64, String)> = {
            let mut st = conn
                .prepare(
                    "SELECT pruned_through_seq, chain_at FROM config_checkpoints \
                     WHERE project = ?1 AND exporter = ?2 ORDER BY pruned_through_seq ASC",
                )
                .map_err(|e| e.to_string())?;
            let rows = st
                .query_map(params![project, exporter], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
        };
        for (through, chain_at) in &cps {
            rep.checkpoints += 1;
            if !audit.iter().any(|d| d.contains(chain_at.as_str())) {
                rep.problems.push(format!(
                    "{label}: checkpoint through #{through} has no matching row in the audit chain"
                ));
            }
        }
        let mut prev = cps
            .last()
            .map_or_else(|| "genesis".to_string(), |c| c.1.clone());
        let mut st = conn
            .prepare(
                "SELECT seq, at, content, masked, sha256, bytes, chain, exposed FROM config_snapshots \
                 WHERE project = ?1 AND exporter = ?2 ORDER BY seq ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(params![project, exporter], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (seq, at, content, masked, stored_sha, bytes, chain, exposed) =
                row.map_err(|e| e.to_string())?;
            rep.snapshots += 1;
            if sha(&content) != stored_sha || content.len() as i64 != bytes {
                rep.problems
                    .push(format!("{label}: #{seq} content does not match its hash"));
            }
            let want = chain_of(&prev, &project, &exporter, &content, &masked, &exposed, &at);
            if want != chain {
                rep.problems
                    .push(format!("{label}: #{seq} breaks the chain"));
            }
            prev = chain;
        }
    }
    Ok(rep)
}

#[derive(Debug, Serialize)]
pub struct Stats {
    pub snapshots: i64,
    pub streams: i64,
    pub bytes: i64,
    pub oldest: Option<String>,
}

pub fn stats(conn: &Connection) -> Result<Stats, String> {
    conn.query_row(
        "SELECT COUNT(*), COUNT(DISTINCT project || '/' || exporter), COALESCE(SUM(bytes),0), MIN(at) \
         FROM config_snapshots",
        [],
        |r| {
            Ok(Stats {
                snapshots: r.get(0)?,
                streams: r.get(1)?,
                bytes: r.get(2)?,
                oldest: r.get(3)?,
            })
        },
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::init_schema(&c).unwrap();
        c
    }

    const S: Stream = Stream {
        project: "p1",
        project_name: "edge",
        exporter: "nginx",
    };

    fn rec(c: &Connection, body: &str) -> Option<i64> {
        record(c, &S, body, &masked_of(body), "[]", "save", Some("owner")).unwrap()
    }

    /// Stands in for the fingerprinted render: derived from the body but not
    /// containing it, as a real masked render does not contain the secret.
    fn masked_of(body: &str) -> String {
        format!("m:{}", &sha(body)[..8])
    }

    /// Rewrites `at` so a snapshot looks older, keeping the chain valid the way
    /// a real older snapshot would be: recompute from the start of the stream.
    fn age(c: &Connection, seq: i64, at: &str) {
        c.execute(
            "UPDATE config_snapshots SET at = ?1 WHERE seq = ?2",
            params![at, seq],
        )
        .unwrap();
        rechain(c);
    }

    fn rechain(c: &Connection) {
        let rows: Vec<(i64, String, String, String, String)> = {
            let mut st = c
                .prepare(
                    "SELECT seq, at, content, masked, exposed FROM config_snapshots ORDER BY seq",
                )
                .unwrap();
            st.query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
        };
        let mut prev = genesis_for(c, "p1", "nginx");
        for (seq, at, content, masked, exposed) in rows {
            prev = chain_of(&prev, "p1", "nginx", &content, &masked, &exposed, &at);
            c.execute(
                "UPDATE config_snapshots SET chain = ?1 WHERE seq = ?2",
                params![prev, seq],
            )
            .unwrap();
        }
    }

    #[test]
    fn concurrent_writers_never_fork_the_chain() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("envv-hist-conc-{n}.db"));
        {
            let c = Connection::open(&path).unwrap();
            crate::init_schema(&c).unwrap();
        }
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let c = Connection::open(&path).unwrap();
                    for i in 0..25 {
                        let body = format!("thread {t} version {i}");
                        record(&c, &S, &body, &masked_of(&body), "[]", "save", None).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let c = Connection::open(&path).unwrap();
        let v = verify(&c).unwrap();
        assert_eq!(v.snapshots, 100);
        assert!(v.problems.is_empty(), "{:?}", v.problems);
    }

    #[test]
    fn a_change_is_recorded_and_an_identical_render_is_not() {
        let c = db();
        assert!(rec(&c, "a").is_some());
        assert!(rec(&c, "a").is_none());
        assert!(rec(&c, "b").is_some());
        assert_eq!(list(&c, Some("edge"), None, None, 10).unwrap().len(), 2);
    }

    #[test]
    fn going_back_to_an_earlier_text_is_a_new_snapshot() {
        let c = db();
        rec(&c, "a");
        rec(&c, "b");
        assert!(rec(&c, "a").is_some(), "reverting a change is a change");
    }

    #[test]
    fn a_stream_is_per_project_and_exporter() {
        let c = db();
        rec(&c, "a");
        let other = Stream {
            project: "p1",
            project_name: "edge",
            exporter: "compose",
        };
        assert!(record(&c, &other, "a", "m", "[]", "save", None)
            .unwrap()
            .is_some());
    }

    #[test]
    fn disabled_history_records_nothing() {
        let c = db();
        set_policy(&c, Some(false), None, None).unwrap();
        assert!(rec(&c, "a").is_none());
        set_policy(&c, Some(true), None, None).unwrap();
        assert!(rec(&c, "a").is_some());
    }

    #[test]
    fn default_views_read_the_masked_text_and_only_get_returns_the_real_one() {
        let c = db();
        let s1 = rec(&c, "key=REAL1").unwrap();
        let s2 = rec(&c, "key=REAL2").unwrap();
        let d = diff(&c, s1, s2, true, 3).unwrap();
        assert!(d.contains(&format!("-{}", masked_of("key=REAL1"))));
        assert!(d.contains(&format!("+{}", masked_of("key=REAL2"))));
        assert!(
            !d.contains("REAL"),
            "a masked diff carried the real value: {d}"
        );
        let real = diff(&c, s1, s2, false, 3).unwrap();
        assert!(real.contains("-key=REAL1") && real.contains("+key=REAL2"));
    }

    #[test]
    fn the_default_diff_compares_the_two_newest_and_asks_when_a_project_has_two_configs() {
        let c = db();
        let a = rec(&c, "a").unwrap();
        let b = rec(&c, "b").unwrap();
        assert_eq!(
            resolve_pair(&c, Some("edge"), None, None, None).unwrap(),
            (a, b)
        );
        assert_eq!(
            resolve_pair(&c, Some("edge"), None, Some(a), None).unwrap(),
            (a, b)
        );
        assert_eq!(
            resolve_pair(&c, None, None, Some(1), Some(2)).unwrap(),
            (1, 2)
        );
        assert!(resolve_pair(&c, None, None, None, None).is_err());
        let other = Stream {
            project: "p1",
            project_name: "edge",
            exporter: "compose",
        };
        record(&c, &other, "x", "m", "[]", "save", None).unwrap();
        let e = resolve_pair(&c, Some("edge"), None, None, None).unwrap_err();
        assert!(e.contains("--exporter"), "{e}");
        assert!(resolve_pair(&c, Some("edge"), Some("nginx"), None, None).is_ok());
    }

    #[test]
    fn one_snapshot_has_nothing_to_compare_with() {
        let c = db();
        rec(&c, "a");
        assert!(resolve_pair(&c, Some("edge"), None, None, None)
            .unwrap_err()
            .contains("only one"));
    }

    #[test]
    fn a_diff_of_two_different_streams_is_refused() {
        let c = db();
        let a = rec(&c, "a").unwrap();
        let other = Stream {
            project: "p2",
            project_name: "x",
            exporter: "nginx",
        };
        let b = record(&c, &other, "b", "m", "[]", "save", None)
            .unwrap()
            .unwrap();
        assert!(diff(&c, a, b, true, 3)
            .unwrap_err()
            .contains("different configs"));
    }

    fn ex(id: &str, fp: &str) -> String {
        serde_json::to_string(&vec![crate::blast::Exposed {
            entry_id: id.into(),
            provider: "P".into(),
            key_id: String::new(),
            field: "api_key".into(),
            fp: fp.into(),
            short: false,
        }])
        .unwrap()
    }

    #[test]
    fn what_a_file_contained_is_the_union_over_every_snapshot_with_that_hash_and_none_when_unknown()
    {
        let c = db();
        record(&c, &S, "same", "m1", &ex("e1", "f1"), "save", None).unwrap();
        record(&c, &S, "other", "m2", "[]", "save", None).unwrap();
        // The same text again after a revert, now also matching a second entry.
        record(&c, &S, "same", "m1", &ex("e2", "f2"), "save", None).unwrap();
        let got = exposed_by_sha(&c, &sha("same")).unwrap().unwrap();
        let ids: Vec<&str> = got.iter().map(|e| e.entry_id.as_str()).collect();
        assert_eq!(ids, vec!["e1", "e2"]);
        assert_eq!(exposed_by_sha(&c, &sha("other")).unwrap().unwrap().len(), 0);
        assert!(exposed_by_sha(&c, &sha("never recorded"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn hiding_an_entry_from_the_exposed_list_breaks_the_chain() {
        let c = db();
        record(&c, &S, "t", "m", &ex("e1", "f1"), "save", None).unwrap();
        assert!(verify(&c).unwrap().problems.is_empty());
        c.execute(
            "UPDATE config_snapshots SET exposed = '[]' WHERE seq = 1",
            [],
        )
        .unwrap();
        assert!(
            verify(&c)
                .unwrap()
                .problems
                .iter()
                .any(|p| p.contains("#1 breaks the chain")),
            "an edited exposed list went unnoticed"
        );
    }

    #[test]
    fn the_file_on_a_host_is_matched_to_the_snapshot_it_came_from() {
        let c = db();
        let first = rec(&c, "one").unwrap();
        rec(&c, "two");
        let hits = find_by_sha(&c, &sha("one"), 5).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].seq, first);
        assert!(find_by_sha(&c, &sha("never rendered"), 5)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn verify_passes_on_an_untouched_history_and_catches_each_kind_of_tampering() {
        let c = db();
        rec(&c, "a");
        rec(&c, "b");
        rec(&c, "c");
        let ok = verify(&c).unwrap();
        assert_eq!((ok.snapshots, ok.problems.len()), (3, 0));

        // Edited content.
        c.execute(
            "UPDATE config_snapshots SET content = 'evil' WHERE seq = 2",
            [],
        )
        .unwrap();
        assert!(verify(&c)
            .unwrap()
            .problems
            .iter()
            .any(|p| p.contains("#2 content")));
        c.execute(
            "UPDATE config_snapshots SET content = 'b' WHERE seq = 2",
            [],
        )
        .unwrap();
        assert!(verify(&c).unwrap().problems.is_empty());

        // Edited masked text: covered by the chain, not by the content hash.
        c.execute("UPDATE config_snapshots SET masked = 'x' WHERE seq = 2", [])
            .unwrap();
        assert!(verify(&c)
            .unwrap()
            .problems
            .iter()
            .any(|p| p.contains("#2 breaks the chain")));
        c.execute(
            "UPDATE config_snapshots SET masked = ?1 WHERE seq = 2",
            [masked_of("b")],
        )
        .unwrap();

        // A deleted middle snapshot.
        c.execute("DELETE FROM config_snapshots WHERE seq = 2", [])
            .unwrap();
        assert!(!verify(&c).unwrap().problems.is_empty());
    }

    #[test]
    fn deleting_the_oldest_snapshots_without_a_checkpoint_is_detected() {
        let c = db();
        rec(&c, "a");
        rec(&c, "b");
        c.execute("DELETE FROM config_snapshots WHERE seq = 1", [])
            .unwrap();
        assert!(verify(&c)
            .unwrap()
            .problems
            .iter()
            .any(|p| p.contains("breaks the chain")));
    }

    #[test]
    fn prune_keeps_the_newest_and_the_recent_and_leaves_a_verifiable_chain() {
        let c = db();
        for i in 0..6 {
            rec(&c, &format!("v{i}"));
        }
        // Make the first four old; the last two stay recent.
        for seq in 1..=4 {
            age(&c, seq, "2020-01-01T00:00:00Z");
        }
        let dry = prune(&c, 3, 30, true, None).unwrap();
        assert_eq!(
            (dry.would_delete, dry.deleted),
            (3, 0),
            "keep 3 newest: only #1..#3 are old and beyond"
        );
        assert_eq!(
            stats(&c).unwrap().snapshots,
            6,
            "a dry run deleted something"
        );
        let real = prune(&c, 3, 30, false, Some("owner")).unwrap();
        assert_eq!((real.deleted, real.streams_touched), (3, 1));
        let left: Vec<i64> = list(&c, None, None, None, 10)
            .unwrap()
            .iter()
            .map(|m| m.seq)
            .collect();
        assert_eq!(left, vec![6, 5, 4]);
        let v = verify(&c).unwrap();
        assert!(v.problems.is_empty(), "{:?}", v.problems);
        assert_eq!(v.checkpoints, 1);

        // New snapshots extend the chain from the checkpoint and still verify.
        rec(&c, "v6");
        assert!(verify(&c).unwrap().problems.is_empty());
        // And a second prune stacks a second checkpoint.
        for seq in 4..=7 {
            age(&c, seq, "2020-02-01T00:00:00Z");
        }
        prune(&c, 1, 30, false, None).unwrap();
        let v = verify(&c).unwrap();
        assert!(v.problems.is_empty(), "{:?}", v.problems);
        assert_eq!(list(&c, None, None, None, 10).unwrap().len(), 1);
    }

    #[test]
    fn a_stream_that_lost_every_row_after_a_prune_restarts_from_its_checkpoint() {
        // Not reachable through prune (it always keeps the newest), but reachable
        // by an operator deleting rows by hand; the next snapshot must extend the
        // checkpoint or the stream can never verify again.
        let c = db();
        rec(&c, "a");
        rec(&c, "b");
        age(&c, 1, "2000-01-01T00:00:00Z");
        prune(&c, 1, 30, false, Some("owner")).unwrap();
        c.execute("DELETE FROM config_snapshots", []).unwrap();
        rec(&c, "c");
        assert!(verify(&c).unwrap().problems.is_empty());
    }

    #[test]
    fn prune_never_empties_a_stream() {
        let c = db();
        rec(&c, "a");
        age(&c, 1, "2000-01-01T00:00:00Z");
        let r = prune(&c, 1, 0, false, None).unwrap();
        assert_eq!(r.deleted, 0);
        assert_eq!(stats(&c).unwrap().snapshots, 1);
    }

    #[test]
    fn a_forged_checkpoint_with_no_audit_row_is_caught() {
        let c = db();
        rec(&c, "a");
        rec(&c, "b");
        rec(&c, "c");
        // An attacker drops the first snapshot and writes a checkpoint to cover it.
        let chain1: String = c
            .query_row(
                "SELECT chain FROM config_snapshots WHERE seq = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        c.execute("DELETE FROM config_snapshots WHERE seq = 1", [])
            .unwrap();
        c.execute(
            "INSERT INTO config_checkpoints (project, exporter, pruned_through_seq, chain_at, pruned_count, at) \
             VALUES ('p1','nginx',1,?1,1,'t')",
            [chain1],
        )
        .unwrap();
        let v = verify(&c).unwrap();
        assert!(
            v.problems
                .iter()
                .any(|p| p.contains("no matching row in the audit chain")),
            "{:?}",
            v.problems
        );
    }

    #[test]
    fn a_real_prune_writes_the_audit_row_the_checkpoint_is_checked_against() {
        let c = db();
        rec(&c, "a");
        rec(&c, "b");
        age(&c, 1, "2000-01-01T00:00:00Z");
        prune(&c, 1, 30, false, Some("owner")).unwrap();
        let n: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM vault_audit WHERE action = 'config.prune'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn policy_has_defaults_and_refuses_nonsense() {
        let c = db();
        assert_eq!(
            policy(&c),
            Policy {
                enabled: true,
                keep: DEFAULT_KEEP,
                days: DEFAULT_DAYS
            }
        );
        assert!(set_policy(&c, None, Some(0), None).is_err());
        assert!(set_policy(&c, None, None, Some(-1)).is_err());
        let p = set_policy(&c, None, Some(5), Some(7)).unwrap();
        assert_eq!((p.keep, p.days), (5, 7));
    }

    #[test]
    fn an_oversized_render_is_refused_not_truncated() {
        let c = db();
        let big = "x".repeat(MAX_BYTES + 1);
        assert!(record(&c, &S, &big, "m", "[]", "save", None)
            .unwrap_err()
            .contains("history keeps files up to"));
    }
}
