//! The unique-ID registry — Phase 24.4.
//!
//! A server-side record of every identifier this deployment has issued, so a
//! new one can be checked for uniqueness before it is handed out and a
//! presented one can be checked for provenance. **Keyed hash only, never the
//! value**: a database of every API key ever minted would be the best single
//! target an attacker could find, so what is stored is
//! `HMAC-SHA256(pepper, normalise(value))` truncated to 16 bytes — enough to be
//! collision-free at any size this will reach, and useless if stolen.
//!
//! Lives in its own SQLCipher file, `registry.db`, beside `vault.db`. Its key
//! and pepper are random 32-byte values held in the **vault's** `vault_meta`
//! table: the registry only opens while the vault is unlocked, travels with
//! vault backups, and survives a master-password change without needing its
//! own KDF.
//!
//! Storage shape and pragmas are exactly what was measured on 2026-09-14
//! (`CLAUDE.md`, Phase 24.4): `WITHOUT ROWID`, a date index, a 32 MB page
//! cache, and pruning in 10,000-row chunks rather than one statement — the
//! single-statement prune held the writer lock for 45.7s at 10M rows in that
//! benchmark, which would stall every mint and register behind it.

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use sha2::Sha256;
use std::fs;
use std::path::Path;

/// A value is registered by an `INSERT` that fails on the primary key, never a
/// `SELECT` then `INSERT` — so two concurrent mints of one value cannot both
/// succeed. `check` is therefore advisory ("unique right now"); `register` is
/// authoritative.
const PRUNE_CHUNK: usize = 10_000;

// ── Registry secrets, held in the vault's own vault_meta ──────────────────────

const META_KEY: &str = "uid_registry_key";
const META_PEPPER: &str = "uid_registry_pepper";

fn rand32() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// Reads the registry's SQLCipher key and HMAC pepper from `vault_meta`,
/// generating and persisting both the first time the registry is used. Callers
/// never see the values live anywhere but here and inside the open registry
/// connection.
pub fn ensure_registry_secrets(vault_conn: &Connection) -> Result<([u8; 32], [u8; 32]), String> {
    let read = |key: &str| -> Result<Option<String>, String> {
        vault_conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    };
    let write = |key: &str, value: &str| -> Result<(), String> {
        vault_conn
            .execute(
                "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    };

    let key = match read(META_KEY)? {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).map_err(|e| e.to_string())?;
            bytes
                .try_into()
                .map_err(|_| "uid_registry_key is corrupt (wrong length)".to_string())?
        }
        None => {
            let k = rand32();
            write(META_KEY, &hex::encode(k))?;
            k
        }
    };
    let pepper = match read(META_PEPPER)? {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).map_err(|e| e.to_string())?;
            bytes
                .try_into()
                .map_err(|_| "uid_registry_pepper is corrupt (wrong length)".to_string())?
        }
        None => {
            let p = rand32();
            write(META_PEPPER, &hex::encode(p))?;
            p
        }
    };
    Ok((key, pepper))
}

// ── Opening the registry file ──────────────────────────────────────────────────

/// Opens (creating if absent) `registry.db` at `path` with the measured pragmas.
pub fn open_registry(path: &Path, key: &[u8; 32]) -> Result<Connection, String> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .map_err(|e| e.to_string())?;
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key)))
        .map_err(|e| e.to_string())?;
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|_| "Wrong registry key".to_string())?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-32000;",
    )
    .map_err(|e| e.to_string())?;
    crate::restrict_to_owner(path)?;
    for suffix in ["-wal", "-shm"] {
        let mut side = path.as_os_str().to_owned();
        side.push(suffix);
        let side = std::path::PathBuf::from(side);
        if side.exists() {
            crate::restrict_to_owner(&side)?;
        }
    }
    init_schema(&conn)?;
    Ok(conn)
}

pub fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS uid (
             h BLOB PRIMARY KEY,
             t INTEGER NOT NULL,
             m INTEGER
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS uid_t ON uid(t);
         CREATE TABLE IF NOT EXISTS uid_meta (
             id        INTEGER PRIMARY KEY,
             namespace TEXT,
             generator TEXT,
             params    TEXT,
             normalise TEXT,
             actor     TEXT,
             source    TEXT,
             entry_ck  TEXT,
             note      TEXT,
             created_at INTEGER NOT NULL
         );",
    )
    .map_err(|e| e.to_string())
}

// ── Normalisation ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Normalise {
    Uuid,
    Ulid,
    Lower,
    None,
}

impl Normalise {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "uuid" => Some(Normalise::Uuid),
            "ulid" => Some(Normalise::Ulid),
            "lower" => Some(Normalise::Lower),
            "none" => Some(Normalise::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Normalise::Uuid => "uuid",
            Normalise::Ulid => "ulid",
            Normalise::Lower => "lower",
            Normalise::None => "none",
        }
    }
}

/// Decides what "the same ID" means. Getting this wrong makes two spellings of
/// one identifier both look unique.
pub fn normalise(value: &str, mode: Normalise) -> String {
    match mode {
        Normalise::Uuid => {
            let hex_only: String = value
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect::<String>()
                .to_ascii_lowercase();
            if hex_only.len() == 32 {
                format!(
                    "{}-{}-{}-{}-{}",
                    &hex_only[0..8],
                    &hex_only[8..12],
                    &hex_only[12..16],
                    &hex_only[16..20],
                    &hex_only[20..32]
                )
            } else {
                value.to_ascii_lowercase()
            }
        }
        Normalise::Ulid => value
            .to_ascii_uppercase()
            .chars()
            .map(|c| match c {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            })
            .collect(),
        Normalise::Lower => value.to_ascii_lowercase(),
        Normalise::None => value.to_string(),
    }
}

/// `HMAC-SHA256(pepper, normalise(value))`, truncated to 16 bytes. The
/// namespace is **not** part of the input — that is what "unique across
/// everything" means: the same string minted under two namespaces is one
/// collision, not two independent slots.
pub fn hash_value(pepper: &[u8; 32], value: &str, mode: Normalise) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let normalised = normalise(value, mode);
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(normalised.as_bytes());
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Batch metadata ────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct BatchMeta<'a> {
    pub namespace: Option<&'a str>,
    pub generator: Option<&'a str>,
    pub params: Option<&'a str>,
    pub actor: Option<&'a str>,
    pub source: Option<&'a str>,
    pub entry_ck: Option<&'a str>,
    pub note: Option<&'a str>,
}

fn insert_meta_row(
    conn: &Connection,
    meta: &BatchMeta,
    normalise_mode: Normalise,
) -> Result<i64, String> {
    conn.execute(
        "INSERT INTO uid_meta (namespace, generator, params, normalise, actor, source, entry_ck, note, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            meta.namespace,
            meta.generator,
            meta.params,
            normalise_mode.as_str(),
            meta.actor,
            meta.source,
            meta.entry_ck,
            meta.note,
            now_ts(),
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(conn.last_insert_rowid())
}

// ── Check / register / lookup ─────────────────────────────────────────────────

/// Advisory only — "unique right now". Never authoritative: `register` is the
/// only operation that actually reserves a value.
pub fn check(
    conn: &Connection,
    pepper: &[u8; 32],
    values: &[String],
    mode: Normalise,
) -> Result<Vec<(String, bool)>, String> {
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        let h = hash_value(pepper, v, mode);
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM uid WHERE h = ?1)",
                params![h.as_slice()],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        out.push((v.clone(), !exists));
    }
    Ok(out)
}

pub struct RegisterOutcome {
    pub value: String,
    pub registered: bool,
}

/// Registers every value as one batch. Each is an `INSERT` that fails on the
/// primary key — never a read-then-write — so two concurrent registrations of
/// one value cannot both succeed; the loser is reported as a conflict, not an
/// error.
pub fn register(
    conn: &Connection,
    pepper: &[u8; 32],
    values: &[String],
    mode: Normalise,
    meta: &BatchMeta,
) -> Result<Vec<RegisterOutcome>, String> {
    let meta_id = insert_meta_row(conn, meta, mode)?;
    let t = now_ts();
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        let h = hash_value(pepper, v, mode);
        let res = conn.execute(
            "INSERT INTO uid (h, t, m) VALUES (?1, ?2, ?3)",
            params![h.as_slice(), t, meta_id],
        );
        out.push(RegisterOutcome {
            value: v.clone(),
            registered: res.is_ok(),
        });
    }
    Ok(out)
}

/// Generate-check-register in one call, retrying up to `max_attempts` times on
/// collision. `generate` is supplied by the caller (`envv-server`), which owns
/// the id-shape decision this module has no opinion about.
pub fn mint(
    conn: &Connection,
    pepper: &[u8; 32],
    mode: Normalise,
    meta: &BatchMeta,
    max_attempts: u32,
    mut generate: impl FnMut() -> String,
) -> Result<Option<String>, String> {
    for _ in 0..max_attempts.max(1) {
        let candidate = generate();
        let outcome = register(conn, pepper, std::slice::from_ref(&candidate), mode, meta)?;
        if outcome.first().is_some_and(|o| o.registered) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

#[derive(Serialize)]
pub struct LookupResult {
    pub issued: bool,
    pub namespace: Option<String>,
    pub generator: Option<String>,
    pub actor: Option<String>,
    pub source: Option<String>,
    pub created_at: Option<i64>,
}

/// One value → provenance the caller may see. `check`/`lookup` are the
/// enumeration oracle for a low-entropy namespace — the rate limiter is the
/// control, not this function.
pub fn lookup(
    conn: &Connection,
    pepper: &[u8; 32],
    value: &str,
    mode: Normalise,
) -> Result<LookupResult, String> {
    let h = hash_value(pepper, value, mode);
    let row = conn
        .query_row(
            "SELECT u.t, m.namespace, m.generator, m.actor, m.source \
             FROM uid u LEFT JOIN uid_meta m ON u.m = m.id \
             WHERE u.h = ?1",
            params![h.as_slice()],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(match row {
        Some((t, namespace, generator, actor, source)) => LookupResult {
            issued: true,
            namespace,
            generator,
            actor,
            source,
            created_at: Some(t),
        },
        None => LookupResult {
            issued: false,
            namespace: None,
            generator: None,
            actor: None,
            source: None,
            created_at: None,
        },
    })
}

/// Registers an ID that was minted **elsewhere** — the provenance-recording
/// half, distinct from `mint` which generates in-process.
pub fn register_external(
    conn: &Connection,
    pepper: &[u8; 32],
    values: &[String],
    mode: Normalise,
    meta: &BatchMeta,
) -> Result<Vec<RegisterOutcome>, String> {
    register(conn, pepper, values, mode, meta)
}

// ── Prune ──────────────────────────────────────────────────────────────────────

#[derive(Serialize, Default)]
pub struct PruneReport {
    pub matched: u64,
    pub deleted: u64,
    pub chunks: u64,
    pub dry_run: bool,
}

/// Deletes rows older than `before_ts`, optionally narrowed by namespace,
/// generator or actor (all resolved through `uid_meta`). Runs in chunks of
/// `PRUNE_CHUNK` rows in **separate transactions**, so registration and
/// minting are never blocked behind one long-held writer lock — the measured
/// reason a single `DELETE` was rejected (45.7s at 10M rows vs. a 0.38s worst
/// chunk).
///
/// This deletes the only evidence an ID was issued: a pruned ID can be issued
/// again without a collision being detected, and `lookup` answers `unknown`
/// for an ID that was real. Callers must say so before confirming — see
/// `envv-cli/src/uid_cmd.rs` and the `/api/uid/prune` handler.
pub fn prune(
    conn: &mut Connection,
    before_ts: i64,
    namespace: Option<&str>,
    generator: Option<&str>,
    actor: Option<&str>,
    dry_run: bool,
) -> Result<PruneReport, String> {
    // One clause used unconditionally, rather than a fast path for "no meta
    // filter": with every filter `NULL` the subquery matches every batch, so
    // correctness does not depend on which branch ran — only the query plan
    // would differ, and this table is small enough that it does not matter.
    let where_clause = "u.t < ?1 AND u.m IN (SELECT id FROM uid_meta m WHERE \
         (?2 IS NULL OR m.namespace = ?2) AND \
         (?3 IS NULL OR m.generator = ?3) AND \
         (?4 IS NULL OR m.actor = ?4))";

    let matched: u64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM uid u WHERE {where_clause}"),
            params![before_ts, namespace, generator, actor],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;

    if dry_run {
        return Ok(PruneReport {
            matched,
            deleted: 0,
            chunks: 0,
            dry_run: true,
        });
    }

    let mut deleted: u64 = 0;
    let mut chunks: u64 = 0;
    loop {
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let n = tx
            .execute(
                &format!(
                    "DELETE FROM uid WHERE h IN (SELECT h FROM uid u WHERE {where_clause} LIMIT {PRUNE_CHUNK})"
                ),
                params![before_ts, namespace, generator, actor],
            )
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        deleted += n as u64;
        chunks += 1;
        if n == 0 {
            break;
        }
    }
    Ok(PruneReport {
        matched,
        deleted,
        chunks,
        dry_run: false,
    })
}

// ── Stats ──────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RegistryStats {
    pub count: i64,
    pub size_bytes: i64,
    pub oldest_ts: Option<i64>,
}

pub fn stats(conn: &Connection) -> Result<RegistryStats, String> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM uid", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let oldest_ts: Option<i64> = conn
        .query_row("SELECT MIN(t) FROM uid", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let page_count: i64 = conn
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap_or(0);
    let page_size: i64 = conn
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .unwrap_or(4096);
    Ok(RegistryStats {
        count,
        size_bytes: page_count * page_size,
        oldest_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn uuid_normalisation_folds_case_and_dashes() {
        let a = normalise("550E8400-E29B-41D4-A716-446655440000", Normalise::Uuid);
        let b = normalise("550e8400e29b41d4a716446655440000", Normalise::Uuid);
        assert_eq!(a, b);
        assert_eq!(a, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn ulid_normalisation_maps_ambiguous_letters() {
        // I/L -> 1, O -> 0, per Crockford base32.
        assert_eq!(normalise("01ILOabc", Normalise::Ulid), "01110ABC");
    }

    #[test]
    fn registering_the_same_value_twice_reports_a_conflict_not_two_rows() {
        let conn = mem();
        let pepper = [7u8; 32];
        let meta = BatchMeta::default();
        let first = register(&conn, &pepper, &["abc".to_string()], Normalise::None, &meta).unwrap();
        assert!(first[0].registered);
        let second =
            register(&conn, &pepper, &["abc".to_string()], Normalise::None, &meta).unwrap();
        assert!(!second[0].registered);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM uid", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn check_is_advisory_and_never_reserves() {
        let conn = mem();
        let pepper = [1u8; 32];
        let r1 = check(&conn, &pepper, &["x".to_string()], Normalise::None).unwrap();
        assert!(r1[0].1, "unique before anything is registered");
        let r2 = check(&conn, &pepper, &["x".to_string()], Normalise::None).unwrap();
        assert!(r2[0].1, "check alone must not have reserved it");
    }

    #[test]
    fn lookup_reports_provenance_for_a_registered_value() {
        let conn = mem();
        let pepper = [3u8; 32];
        let meta = BatchMeta {
            namespace: Some("ci"),
            generator: Some("uuidv4"),
            actor: Some("runner-1"),
            ..Default::default()
        };
        register(&conn, &pepper, &["v1".to_string()], Normalise::None, &meta).unwrap();
        let found = lookup(&conn, &pepper, "v1", Normalise::None).unwrap();
        assert!(found.issued);
        assert_eq!(found.namespace.as_deref(), Some("ci"));
        let missing = lookup(&conn, &pepper, "v2", Normalise::None).unwrap();
        assert!(!missing.issued);
    }

    #[test]
    fn prune_deletes_only_rows_older_than_the_cutoff() {
        let mut conn = mem();
        let pepper = [9u8; 32];
        let meta = BatchMeta::default();
        register(&conn, &pepper, &["old".to_string()], Normalise::None, &meta).unwrap();
        conn.execute("UPDATE uid SET t = 100", []).unwrap();
        register(&conn, &pepper, &["new".to_string()], Normalise::None, &meta).unwrap();
        conn.execute("UPDATE uid SET t = 999999999 WHERE t != 100", [])
            .unwrap();

        let dry = prune(&mut conn, 500, None, None, None, true).unwrap();
        assert_eq!(dry.matched, 1);
        assert_eq!(dry.deleted, 0);

        let real = prune(&mut conn, 500, None, None, None, false).unwrap();
        assert_eq!(real.deleted, 1);
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM uid", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn a_pruned_value_can_be_registered_again() {
        // Written down as a consequence, not a bug: pruning deletes the only
        // evidence an ID was issued.
        let mut conn = mem();
        let pepper = [4u8; 32];
        let meta = BatchMeta::default();
        register(
            &conn,
            &pepper,
            &["gone".to_string()],
            Normalise::None,
            &meta,
        )
        .unwrap();
        conn.execute("UPDATE uid SET t = 1", []).unwrap();
        prune(&mut conn, 1000, None, None, None, false).unwrap();
        let again = register(
            &conn,
            &pepper,
            &["gone".to_string()],
            Normalise::None,
            &meta,
        )
        .unwrap();
        assert!(again[0].registered);
    }
}
