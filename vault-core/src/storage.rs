//! Row-per-entry storage, schema v2 (Phase 30, review-01 section 2.1; ADR-0138).
//!
//! Schema v1 kept the whole vault as one JSON string in one row, so every write
//! parsed and re-serialised the lot, the compare-and-swap token was a hash of the
//! blob (two people editing *different* entries conflicted, and both branches of
//! the conflict prompt discarded someone's changeset), `version_history` grew
//! inside the thing written most often, and nothing could be indexed.
//!
//! v2 stores one row per entry and per project, a row for the category list and a
//! row for every other top-level key. The public document API is unchanged
//! (`load_vault` returns the same JSON, `save_vault` takes it), so the desktop app,
//! `envv-server` and `envv` need no change; what changes is what a save *does*:
//!
//! * only rows whose content changed are written;
//! * `version_history` lives in its own table and is attached on load;
//! * every save records which rows it changed in `vault_changes`, and a writer who
//!   read an older version is **merged**, not refused: entries it left untouched
//!   keep whatever the other writer did, and only an entry both sides changed (or
//!   one side changed and the other deleted) is a conflict, named in the error.
//!
//! ## The version token
//!
//! `"<seq>.<state hash>"`. The hash is over every row's `(kind, key, position,
//! content hash)`; the sequence number says *when*, so a stale token can be turned
//! into "which rows changed since" instead of "something changed". The token is
//! opaque to callers, as before; a token in the old bare-hex form fails the merge
//! lookup and is a whole-vault conflict, which is what it always was.
//!
//! ## What a merge can and cannot know
//!
//! A row's content hash (`rev`) is the identity of its content. For each row the
//! writer sends back, the changes since its base version tell us what that row
//! looked like when it read it (`prev_rev` of the first later change). If the
//! writer's copy still has that hash, the writer did not touch it and the stored
//! row wins; if the writer's copy matches the stored row, there is nothing to
//! decide; otherwise both sides edited it. History is bounded (the newest
//! [`KEEP_SAVES`] saves); a token older than that is a whole-vault conflict.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// How many saves of change history to keep for merging stale writers.
pub const KEEP_SAVES: i64 = 2000;

const KIND_ENTRY: &str = "entry";
const KIND_PROJECT: &str = "project";
const KIND_CATEGORIES: &str = "categories";
const KIND_DOC: &str = "doc";

/// The three top-level keys that get their own rows; everything else rides in `doc`.
const SPLIT_KEYS: [&str; 3] = ["api_keys", "projects", "user_categories"];

pub fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vault_rows (
             kind TEXT NOT NULL,
             key  TEXT NOT NULL,
             pos  INTEGER NOT NULL,
             data TEXT NOT NULL,
             rev  TEXT NOT NULL,
             PRIMARY KEY (kind, key)
         );
         CREATE INDEX IF NOT EXISTS vault_rows_pos ON vault_rows (kind, pos);
         CREATE TABLE IF NOT EXISTS vault_history (
             key  TEXT PRIMARY KEY,
             data TEXT NOT NULL,
             rev  TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS vault_saves (
             seq        INTEGER PRIMARY KEY AUTOINCREMENT,
             state_hash TEXT NOT NULL,
             at         TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS vault_changes (
             seq      INTEGER NOT NULL,
             kind     TEXT NOT NULL,
             key      TEXT NOT NULL,
             prev_rev TEXT,
             new_rev  TEXT
         );
         CREATE INDEX IF NOT EXISTS vault_changes_seq ON vault_changes (seq);",
    )
    .map_err(|e| e.to_string())
}

fn sha(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

/// SHA-256 of a value's compact JSON, without building the string. Identical to
/// `sha(&v.to_string())`, which is what `verify` recomputes from the stored text.
struct HashWriter(Sha256);

impl std::io::Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn rev_of(v: &Value) -> String {
    let mut w = HashWriter(Sha256::new());
    let _ = serde_json::to_writer(&mut w, v);
    format!("{:x}", w.0.finalize())
}

/// One storable unit of the document.
#[derive(Clone)]
pub struct Ent {
    pub kind: &'static str,
    /// Unique within `kind`.
    pub key: String,
    /// The JSON stored in the row (for entries, without `version_history`).
    pub data: Value,
    pub rev: String,
    /// An entry's `version_history`, kept apart from its row.
    pub history: Option<Value>,
}

impl Ent {
    fn new(kind: &'static str, key: String, data: Value, history: Option<Value>) -> Self {
        let rev = rev_of(&data);
        Self {
            kind,
            key,
            data,
            rev,
            history,
        }
    }

    /// The entry as the rest of the code sees it: row plus `version_history`.
    pub fn full(&self) -> Value {
        let mut v = self.data.clone();
        if let (Some(h), Some(o)) = (&self.history, v.as_object_mut()) {
            o.insert("version_history".into(), h.clone());
        }
        v
    }

    pub fn provider(&self) -> String {
        self.data
            .get("provider")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }
}

/// A row key unique within the incoming list. Duplicate cks (legacy entries with
/// no `id` and identical provider/account/key_id) get an ordinal so they do not
/// collapse into one row.
fn unique_keys(cks: Vec<String>) -> Vec<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    cks.into_iter()
        .map(|ck| {
            let n = seen.entry(ck.clone()).or_insert(0);
            *n += 1;
            if *n == 1 {
                ck
            } else {
                format!("{ck}\u{2}{n}")
            }
        })
        .collect()
}

fn project_ck(p: &Value) -> String {
    let id = p.get("id").and_then(Value::as_str).unwrap_or("");
    if !id.is_empty() {
        return format!("id\u{1}{id}");
    }
    format!(
        "name\u{1}{}",
        p.get("name").and_then(Value::as_str).unwrap_or("")
    )
}

/// Split a vault document into storable units, in document order. Consumes the
/// document so a large vault is moved, not cloned.
pub fn split(mut doc: Value) -> Vec<Ent> {
    let mut out = Vec::new();
    let mut take = |k: &str| -> Vec<Value> {
        match doc.get_mut(k).map(Value::take) {
            Some(Value::Array(a)) => a,
            _ => Vec::new(),
        }
    };

    let entries = take("api_keys");
    let keys = unique_keys(entries.iter().map(crate::entry_ck).collect());
    for (e, key) in entries.into_iter().zip(keys) {
        let mut data = e;
        let history = data
            .as_object_mut()
            .and_then(|o| o.remove("version_history"));
        out.push(Ent::new(KIND_ENTRY, key, data, history));
    }
    let projects = take("projects");
    let keys = unique_keys(projects.iter().map(project_ck).collect());
    for (p, key) in projects.into_iter().zip(keys) {
        out.push(Ent::new(KIND_PROJECT, key, p, None));
    }
    let cats = take("user_categories");
    out.push(Ent::new(
        KIND_CATEGORIES,
        String::new(),
        Value::Array(cats),
        None,
    ));
    let mut extra = Map::new();
    if let Value::Object(o) = doc {
        for (k, v) in o {
            if !SPLIT_KEYS.contains(&k.as_str()) {
                extra.insert(k, v);
            }
        }
    }
    out.push(Ent::new(
        KIND_DOC,
        String::new(),
        Value::Object(extra),
        None,
    ));
    out
}

/// Reassemble the document from units in order, consuming them.
pub fn join(ents: Vec<Ent>) -> Value {
    let mut doc = Map::new();
    let mut entries = Vec::new();
    let mut projects = Vec::new();
    let mut cats = Value::Array(vec![]);
    for e in ents {
        match e.kind {
            KIND_ENTRY => {
                let mut v = e.data;
                if let (Some(h), Some(o)) = (e.history, v.as_object_mut()) {
                    o.insert("version_history".into(), h);
                }
                entries.push(v);
            }
            KIND_PROJECT => projects.push(e.data),
            KIND_CATEGORIES => cats = e.data,
            KIND_DOC => {
                if let Value::Object(o) = e.data {
                    for (k, v) in o {
                        doc.insert(k, v);
                    }
                }
            }
            _ => {}
        }
    }
    doc.insert("api_keys".into(), Value::Array(entries));
    doc.insert("projects".into(), Value::Array(projects));
    doc.insert("user_categories".into(), cats);
    Value::Object(doc)
}

// ── Reading ──────────────────────────────────────────────────────────────────

fn history_map(conn: &Connection) -> Result<HashMap<String, Value>, String> {
    let mut stmt = conn
        .prepare("SELECT key, data FROM vault_history")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| e.to_string())?;
    let mut m = HashMap::new();
    for r in rows {
        let (k, d) = r.map_err(|e| e.to_string())?;
        if let Ok(v) = serde_json::from_str(&d) {
            m.insert(k, v);
        }
    }
    Ok(m)
}

fn ent_from_row(
    kind: &'static str,
    key: String,
    data: &str,
    rev: String,
    history: Option<Value>,
) -> Result<Ent, String> {
    Ok(Ent {
        kind,
        key,
        data: serde_json::from_str(data).map_err(|e| e.to_string())?,
        rev,
        history,
    })
}

fn kind_static(k: &str) -> &'static str {
    match k {
        KIND_ENTRY => KIND_ENTRY,
        KIND_PROJECT => KIND_PROJECT,
        KIND_CATEGORIES => KIND_CATEGORIES,
        _ => KIND_DOC,
    }
}

/// Every stored unit in document order, or `None` when nothing has been saved.
pub fn load_ents(conn: &Connection) -> Result<Option<Vec<Ent>>, String> {
    load_ents_opts(conn, true)
}

/// As [`load_ents`], optionally leaving out each entry's `version_history`, which
/// is up to 50 revisions of secret material per entry and is not wanted by a
/// selective read.
pub fn load_ents_opts(conn: &Connection, with_history: bool) -> Result<Option<Vec<Ent>>, String> {
    let mut stmt = conn
        .prepare("SELECT kind, key, data, rev FROM vault_rows ORDER BY kind, pos")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let hist = if with_history {
        history_map(conn)?
    } else {
        HashMap::new()
    };
    let mut by_kind: HashMap<&'static str, Vec<Ent>> = HashMap::new();
    for r in rows {
        let (kind, key, data, rev) = r.map_err(|e| e.to_string())?;
        let k = kind_static(&kind);
        let h = if k == KIND_ENTRY {
            hist.get(&key).cloned()
        } else {
            None
        };
        by_kind
            .entry(k)
            .or_default()
            .push(ent_from_row(k, key, &data, rev, h)?);
    }
    if !by_kind.contains_key(KIND_DOC) {
        return Ok(None); // the doc row exists iff something was ever saved
    }
    let mut out = Vec::new();
    for k in [KIND_ENTRY, KIND_PROJECT, KIND_CATEGORIES, KIND_DOC] {
        out.extend(by_kind.remove(k).unwrap_or_default());
    }
    Ok(Some(out))
}

pub fn load(conn: &Connection) -> Result<Option<Value>, String> {
    Ok(load_ents(conn)?.map(join))
}

/// The document without any entry's `version_history`.
pub fn load_lite(conn: &Connection) -> Result<Option<Value>, String> {
    Ok(load_ents_opts(conn, false)?.map(join))
}

/// Every row's `(rev, pos)`, read once per save.
pub type Snapshot = HashMap<(String, String), (String, i64)>;

pub fn snapshot(conn: &Connection) -> Result<Snapshot, String> {
    let mut stmt = conn
        .prepare("SELECT kind, key, pos, rev FROM vault_rows")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut m = HashMap::new();
    for r in rows {
        let (k, key, pos, rev) = r.map_err(|e| e.to_string())?;
        m.insert((k, key), (rev, pos));
    }
    Ok(m)
}

/// One stored row by key, with its history attached for entries.
pub fn load_ent(conn: &Connection, kind: &'static str, key: &str) -> Result<Option<Ent>, String> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT data, rev FROM vault_rows WHERE kind = ?1 AND key = ?2",
            params![kind, key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let Some((data, rev)) = row else {
        return Ok(None);
    };
    let history: Option<Value> = if kind == KIND_ENTRY {
        conn.query_row(
            "SELECT data FROM vault_history WHERE key = ?1",
            params![key],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    };
    Ok(Some(ent_from_row(
        kind,
        key.to_string(),
        &data,
        rev,
        history,
    )?))
}

/// Entries only (no projects, no history) matching `keep`, parsed individually.
/// Used for selective reads: the server no longer has to materialise the whole
/// document to answer "which entries mention X".
pub fn load_entries_where(
    conn: &Connection,
    keep: impl Fn(&Value) -> bool,
) -> Result<Vec<Value>, String> {
    let mut stmt = conn
        .prepare("SELECT data FROM vault_rows WHERE kind = 'entry' ORDER BY pos")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        let v: Value =
            serde_json::from_str(&r.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        if keep(&v) {
            out.push(v);
        }
    }
    Ok(out)
}

// ── Version token ────────────────────────────────────────────────────────────

/// The state hash is the XOR of a hash of every row's `(kind, key, pos, rev)`.
/// XOR is order-independent and every row is unique, so a save can update it by
/// removing the old row's hash and adding the new one: O(changed), not O(vault).
/// `verify` recomputes it from the rows and compares.
type Acc = [u8; 32];

fn row_hash(kind: &str, key: &str, pos: i64, rev: &str) -> Acc {
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update([1]);
    h.update(key.as_bytes());
    h.update([1]);
    h.update(pos.to_string().as_bytes());
    h.update([1]);
    h.update(rev.as_bytes());
    h.finalize().into()
}

fn xor(acc: &mut Acc, other: &Acc) {
    for (a, b) in acc.iter_mut().zip(other) {
        *a ^= b;
    }
}

fn acc_from_rows(snap: &Snapshot) -> Acc {
    let mut acc = [0u8; 32];
    for ((k, key), (rev, pos)) in snap {
        xor(&mut acc, &row_hash(k, key, *pos, rev));
    }
    acc
}

fn acc_hex(acc: &Acc) -> String {
    acc.iter().map(|b| format!("{b:02x}")).collect()
}

fn acc_parse(s: &str) -> Option<Acc> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn stored_acc(conn: &Connection) -> Result<Option<Acc>, String> {
    Ok(conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'state_acc'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .and_then(|s| acc_parse(&s)))
}

fn token(seq: i64, hash: &str) -> String {
    format!("{seq}.{hash}")
}

fn parse_token(t: &str) -> Option<(i64, &str)> {
    let (s, h) = t.split_once('.')?;
    Some((s.parse().ok()?, h))
}

/// The current version token, or `None` for an empty vault.
pub fn version(conn: &Connection) -> Result<Option<String>, String> {
    conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'data_hash'",
        [],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| e.to_string())
}

/// Integrity: every row hashes to its `rev`, and the rows hash to the stored token.
pub fn verify(conn: &Connection) -> Result<bool, String> {
    let mut stmt = conn
        .prepare("SELECT data, rev FROM vault_rows")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| e.to_string())?;
    let mut any = false;
    for r in rows {
        let (data, rev) = r.map_err(|e| e.to_string())?;
        any = true;
        if sha(&data) != rev {
            return Ok(false);
        }
    }
    if !any {
        return Ok(true);
    }
    let Some(stored) = version(conn)? else {
        return Ok(true);
    };
    let fresh = acc_hex(&acc_from_rows(&snapshot(conn)?));
    let recorded = stored_acc(conn)?.map(|a| acc_hex(&a));
    Ok(parse_token(&stored)
        .map(|(_, h)| h == fresh)
        .unwrap_or(false)
        && recorded.as_deref().map(|r| r == fresh).unwrap_or(true))
}

// ── Merge ────────────────────────────────────────────────────────────────────

type Id = (String, String);

/// Resolve the writer's units against what is stored. Returns the units to
/// persist, or the conflicting row labels.
///
/// `expect` is the version the writer read. `None` writes unconditionally.
pub fn merge(
    conn: &Connection,
    stored: &Snapshot,
    incoming: Vec<Ent>,
    expect: Option<&str>,
) -> Result<(Vec<Ent>, bool), String> {
    let cur_version = version(conn)?;
    let expect = expect.map(|e| e.strip_suffix(crate::MERGED_SUFFIX).unwrap_or(e));
    // Rows changed since the writer's base, by the first prior revision they had.
    let mut touched: HashMap<Id, Option<String>> = HashMap::new();
    match expect {
        None => {}
        Some(e) if cur_version.as_deref() == Some(e) => {}
        Some(e) => {
            let ok = parse_token(e).and_then(|(seq, hash)| {
                let found: Option<String> = conn
                    .query_row(
                        "SELECT state_hash FROM vault_saves WHERE seq = ?1",
                        params![seq],
                        |r| r.get(0),
                    )
                    .optional()
                    .ok()
                    .flatten();
                (found.as_deref() == Some(hash)).then_some(seq)
            });
            let Some(base) = ok else {
                return Err(conflict(&[]));
            };
            let mut stmt = conn
                .prepare("SELECT kind, key, prev_rev FROM vault_changes WHERE seq > ?1 ORDER BY seq ASC, rowid ASC")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![base], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            for r in rows {
                let (k, key, prev) = r.map_err(|e| e.to_string())?;
                touched.entry((k, key)).or_insert(prev);
            }
        }
    }
    if touched.is_empty() {
        return Ok((incoming, false)); // nothing concurrent: the writer's document wins as written
    }

    let mut conflicts: Vec<String> = Vec::new();
    let mut out: Vec<Ent> = Vec::new();
    let mut seen: HashSet<Id> = HashSet::new();
    // True when the result differs from the writer's own view of the vault, so the
    // writer must not adopt the new version as its base (see `save_vault_txn`).
    let mut adopted_theirs = false;

    for ent in incoming {
        let id: Id = (ent.kind.to_string(), ent.key.clone());
        seen.insert(id.clone());
        let Some(base_prev) = touched.get(&id) else {
            out.push(ent);
            continue;
        };
        let cur = stored.get(&id).map(|(rev, _)| rev);
        if cur == Some(&ent.rev) {
            out.push(ent); // both sides arrived at the same content
            continue;
        }
        match base_prev {
            // The writer did not touch it: whatever the other side did stands.
            Some(b) if *b == ent.rev => {
                adopted_theirs = true;
                if cur.is_some() {
                    if let Some(theirs) = load_ent(conn, ent.kind, &ent.key)? {
                        out.push(theirs);
                    }
                } // else the other side deleted it and the writer left it alone
            }
            _ => conflicts.push(label(&ent)),
        }
    }
    // Rows the writer does not have, in a stable order.
    let mut leftovers: Vec<&Id> = stored.keys().filter(|id| !seen.contains(*id)).collect();
    leftovers.sort();
    for id in leftovers {
        let kind = kind_static(&id.0);
        match touched.get(id) {
            None => {} // existed at the base, untouched: the writer deleted it
            Some(None) => {
                // Created after the writer read: not theirs to delete.
                adopted_theirs = true;
                if let Some(theirs) = load_ent(conn, kind, &id.1)? {
                    out.push(theirs);
                }
            }
            Some(Some(_)) => conflicts.push(
                load_ent(conn, kind, &id.1)?
                    .map(|e| label(&e))
                    .unwrap_or_else(|| id.1.clone()),
            ),
        }
    }
    if !conflicts.is_empty() {
        conflicts.sort();
        conflicts.dedup();
        return Err(conflict(&conflicts));
    }
    // Keep the writer's order, with rows they did not have after their own kind.
    let order = |k: &str| match k {
        KIND_ENTRY => 0,
        KIND_PROJECT => 1,
        KIND_CATEGORIES => 2,
        _ => 3,
    };
    out.sort_by_key(|e| order(e.kind)); // stable: preserves relative order within a kind
    Ok((out, adopted_theirs))
}

fn label(e: &Ent) -> String {
    match e.kind {
        KIND_ENTRY => {
            let p = e.provider();
            if p.is_empty() {
                e.key.replace('\u{1}', ":")
            } else {
                p
            }
        }
        KIND_PROJECT => e
            .data
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&e.key)
            .to_string(),
        KIND_CATEGORIES => "categories".into(),
        _ => "vault settings".into(),
    }
}

fn conflict(names: &[String]) -> String {
    if names.is_empty() {
        format!(
            "{}: the vault changed since you last read it — reload and retry",
            crate::CONFLICT_ERR
        )
    } else {
        format!(
            "{}: the vault changed since you last read it — you and another writer both changed: {}",
            crate::CONFLICT_ERR,
            names.join(", ")
        )
    }
}

// ── Writing ──────────────────────────────────────────────────────────────────

/// Persist `ents` as the new state. Must run inside a write transaction. Only rows
/// whose content, position or history changed are touched. Returns the new token
/// (the current one, unchanged, when nothing differs).
pub fn write(
    conn: &Connection,
    stored: &Snapshot,
    ents: &[Ent],
    now: &str,
) -> Result<String, String> {
    // The state accumulator before any row moves; updated row by row below.
    let mut acc = match stored_acc(conn)? {
        Some(a) => a,
        None => acc_from_rows(stored),
    };
    let stored_hist: HashMap<String, String> = {
        let mut stmt = conn
            .prepare("SELECT key, rev FROM vault_history")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| e.to_string())?;
        let mut m = HashMap::new();
        for r in rows {
            let (k, v) = r.map_err(|e| e.to_string())?;
            m.insert(k, v);
        }
        m
    };

    let mut changes: Vec<(String, String, Option<String>, Option<String>)> = Vec::new();
    let mut dirty = false;
    let mut pos_by_kind: HashMap<&str, i64> = HashMap::new();
    let mut keep: HashSet<Id> = HashSet::new();
    let mut keep_hist: HashSet<String> = HashSet::new();

    for e in ents {
        let p = pos_by_kind.entry(e.kind).or_insert(0);
        let pos = *p;
        *p += 1;
        let id: Id = (e.kind.to_string(), e.key.clone());
        keep.insert(id.clone());
        match stored.get(&id) {
            None => {
                conn.execute(
                    "INSERT INTO vault_rows (kind, key, pos, data, rev) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![e.kind, e.key, pos, e.data.to_string(), e.rev],
                )
                .map_err(|x| x.to_string())?;
                xor(&mut acc, &row_hash(e.kind, &e.key, pos, &e.rev));
                changes.push((e.kind.into(), e.key.clone(), None, Some(e.rev.clone())));
                dirty = true;
            }
            Some((rev, old_pos)) if *rev != e.rev => {
                xor(&mut acc, &row_hash(e.kind, &e.key, *old_pos, rev));
                xor(&mut acc, &row_hash(e.kind, &e.key, pos, &e.rev));
                conn.execute(
                    "UPDATE vault_rows SET pos = ?3, data = ?4, rev = ?5 WHERE kind = ?1 AND key = ?2",
                    params![e.kind, e.key, pos, e.data.to_string(), e.rev],
                )
                .map_err(|x| x.to_string())?;
                changes.push((
                    e.kind.into(),
                    e.key.clone(),
                    Some(rev.clone()),
                    Some(e.rev.clone()),
                ));
                dirty = true;
            }
            Some((rev, old_pos)) => {
                if *old_pos != pos {
                    xor(&mut acc, &row_hash(e.kind, &e.key, *old_pos, rev));
                    xor(&mut acc, &row_hash(e.kind, &e.key, pos, rev));
                    conn.execute(
                        "UPDATE vault_rows SET pos = ?3 WHERE kind = ?1 AND key = ?2",
                        params![e.kind, e.key, pos],
                    )
                    .map_err(|x| x.to_string())?;
                    dirty = true;
                }
            }
        }
        if e.kind == KIND_ENTRY {
            if let Some(h) = e
                .history
                .as_ref()
                .filter(|h| h.as_array().map(|a| !a.is_empty()).unwrap_or(false))
            {
                keep_hist.insert(e.key.clone());
                let hrev = rev_of(h);
                if stored_hist.get(&e.key) != Some(&hrev) {
                    conn.execute(
                        "INSERT OR REPLACE INTO vault_history (key, data, rev) VALUES (?1, ?2, ?3)",
                        params![e.key, h.to_string(), hrev],
                    )
                    .map_err(|x| x.to_string())?;
                    dirty = true;
                }
            }
        }
    }
    for (id, (rev, old_pos)) in stored {
        if !keep.contains(id) {
            xor(&mut acc, &row_hash(&id.0, &id.1, *old_pos, rev));
            conn.execute(
                "DELETE FROM vault_rows WHERE kind = ?1 AND key = ?2",
                params![id.0, id.1],
            )
            .map_err(|x| x.to_string())?;
            changes.push((id.0.clone(), id.1.clone(), Some(rev.clone()), None));
            dirty = true;
        }
    }
    for k in stored_hist.keys() {
        if !keep_hist.contains(k) {
            conn.execute("DELETE FROM vault_history WHERE key = ?1", params![k])
                .map_err(|x| x.to_string())?;
            dirty = true;
        }
    }

    if !dirty {
        if let Some(v) = version(conn)? {
            return Ok(v);
        }
    }
    let hash = acc_hex(&acc);
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('state_acc', ?1)",
        params![hash],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO vault_saves (state_hash, at) VALUES (?1, ?2)",
        params![hash, now],
    )
    .map_err(|e| e.to_string())?;
    let seq = conn.last_insert_rowid();
    for (k, key, prev, new) in changes {
        conn.execute(
            "INSERT INTO vault_changes (seq, kind, key, prev_rev, new_rev) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![seq, k, key, prev, new],
        )
        .map_err(|e| e.to_string())?;
    }
    // Bounded history: a writer older than this gets a whole-vault conflict.
    conn.execute(
        "DELETE FROM vault_saves WHERE seq <= ?1",
        params![seq - KEEP_SAVES],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM vault_changes WHERE seq <= ?1",
        params![seq - KEEP_SAVES],
    )
    .map_err(|e| e.to_string())?;
    let tok = token(seq, &hash);
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('data_hash', ?1)",
        params![tok],
    )
    .map_err(|e| e.to_string())?;
    Ok(tok)
}

// ── Migration from v1 ────────────────────────────────────────────────────────

fn legacy_blob(conn: &Connection) -> Result<Option<String>, String> {
    conn.query_row("SELECT data FROM vault WHERE id = 1", [], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())
}

/// True when a v1 blob is waiting to be converted.
pub fn needs_migration(conn: &Connection) -> Result<bool, String> {
    Ok(legacy_blob(conn)?.is_some())
}

/// Copy `vault.db` to `vault.db.v1.bak` (owner-only) before the one-way conversion.
fn backup_v1(conn: &Connection) {
    let Some(path) = conn.path().map(std::path::PathBuf::from) else {
        return;
    };
    if path.as_os_str().is_empty() {
        return;
    }
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    let mut bak = path.as_os_str().to_owned();
    bak.push(".v1.bak");
    let bak = std::path::PathBuf::from(bak);
    if !bak.exists() && std::fs::copy(&path, &bak).is_ok() {
        let _ = crate::restrict_to_owner(&bak);
    }
}

/// Convert the v1 blob into rows. Must run inside a write transaction. No audit
/// rows are written: nothing about the data changed, only where it lives.
pub fn migrate_in_txn(conn: &Connection, now: &str) -> Result<bool, String> {
    let Some(raw) = legacy_blob(conn)? else {
        return Ok(false);
    };
    let doc: Value =
        serde_json::from_str(&raw).map_err(|e| format!("legacy vault is unreadable: {e}"))?;
    conn.execute("DELETE FROM vault_rows", [])
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM vault_history", [])
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM vault_meta WHERE key = 'state_acc'", [])
        .map_err(|e| e.to_string())?;
    write(conn, &snapshot(conn)?, &split(doc), now)?;
    conn.execute("DELETE FROM vault WHERE id = 1", [])
        .map_err(|e| e.to_string())?;
    Ok(true)
}

/// Migrate on its own transaction (the read path). Cheap when nothing is pending.
pub fn migrate_if_needed(conn: &Connection, now: &str) -> Result<(), String> {
    if !needs_migration(conn)? {
        return Ok(());
    }
    backup_v1(conn);
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| e.to_string())?;
    let r = migrate_in_txn(conn, now).and_then(|_| {
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?1)",
            params![crate::VAULT_SCHEMA_VERSION.to_string()],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    });
    match r {
        Ok(()) => conn.execute_batch("COMMIT").map_err(|e| e.to_string()),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{load_vault, save_vault, vault_version, SaveCtx, CONFLICT_ERR};
    use serde_json::json;

    fn open(tag: &str) -> (Connection, std::path::PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("vc-storage-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = crate::derive_key("correct horse battery staple", b"0123456789abcdef").unwrap();
        let conn = crate::open_db(&dir.join("vault.db"), &key).unwrap();
        crate::init_schema(&conn).unwrap();
        (conn, dir)
    }

    fn e(id: &str, provider: &str) -> Value {
        json!({ "id": id, "provider": provider, "api_key": format!("key-{id}") })
    }

    fn save(conn: &Connection, doc: Value, base: Option<&str>) -> Result<String, String> {
        save_vault(
            conn,
            doc,
            SaveCtx {
                actor: None,
                expect_version: base,
            },
        )
    }

    fn names(conn: &Connection) -> Vec<String> {
        load_vault(conn).unwrap().unwrap()["api_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["provider"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn the_document_round_trips_including_unknown_top_level_keys_and_order() {
        let (conn, _d) = open("roundtrip");
        let doc = json!({
            "api_keys": [e("b", "B"), e("a", "A"), e("c", "C")],
            "projects": [{ "id": "p2", "name": "Two" }, { "id": "p1", "name": "One" }],
            "user_categories": ["x", "a/b"],
            "someFutureKey": { "nested": [1, 2, 3] }
        });
        save(&conn, doc.clone(), None).unwrap();
        let got = load_vault(&conn).unwrap().unwrap();
        assert_eq!(got, doc);
    }

    #[test]
    fn a_save_writes_only_the_rows_that_changed() {
        let (conn, _d) = open("minimal");
        let v1 = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B"), e("3", "C")] }),
            None,
        )
        .unwrap();
        save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B-edited"), e("3", "C")] }),
            Some(&v1),
        )
        .unwrap();
        let last: i64 = conn
            .query_row("SELECT MAX(seq) FROM vault_saves", [], |r| r.get(0))
            .unwrap();
        let changed: Vec<(String, String)> = conn
            .prepare("SELECT kind, key FROM vault_changes WHERE seq = ?1")
            .unwrap()
            .query_map(params![last], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|x| x.unwrap())
            .collect();
        assert_eq!(changed, vec![("entry".to_string(), "id\u{1}2".to_string())]);
    }

    #[test]
    fn an_identical_save_creates_no_new_version() {
        let (conn, _d) = open("noop");
        let doc = json!({ "api_keys": [e("1", "A")] });
        let v1 = save(&conn, doc.clone(), None).unwrap();
        let v2 = save(&conn, doc, Some(&v1)).unwrap();
        assert_eq!(v1, v2);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM vault_saves", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn two_writers_editing_different_entries_both_land() {
        let (conn, _d) = open("disjoint");
        let base = json!({ "api_keys": [e("1", "A"), e("2", "B")] });
        let v1 = save(&conn, base, None).unwrap();
        // Writer one edits entry 1 and saves.
        save(
            &conn,
            json!({ "api_keys": [e("1", "A-one"), e("2", "B")] }),
            Some(&v1),
        )
        .unwrap();
        // Writer two, still holding v1, edits entry 2. Their copy of entry 1 is stale.
        let out = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B-two")] }),
            Some(&v1),
        );
        assert!(out.is_ok(), "{out:?}");
        assert_eq!(names(&conn), vec!["A-one", "B-two"]);
    }

    #[test]
    fn a_stale_writer_neither_deletes_nor_overwrites_what_it_never_saw() {
        let (conn, _d) = open("unseen");
        let v1 = save(&conn, json!({ "api_keys": [e("1", "A")] }), None).unwrap();
        // Someone else adds entry 2.
        save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "Added")] }),
            Some(&v1),
        )
        .unwrap();
        // The stale writer edits entry 1 and does not have entry 2.
        save(&conn, json!({ "api_keys": [e("1", "A-edit")] }), Some(&v1)).unwrap();
        assert_eq!(names(&conn), vec!["A-edit", "Added"]);
    }

    #[test]
    fn deleting_an_untouched_entry_while_another_is_added_applies_both() {
        let (conn, _d) = open("delete-add");
        let v1 = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B")] }),
            None,
        )
        .unwrap();
        save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B"), e("3", "C")] }),
            Some(&v1),
        )
        .unwrap();
        save(&conn, json!({ "api_keys": [e("1", "A")] }), Some(&v1)).unwrap();
        assert_eq!(names(&conn), vec!["A", "C"]);
    }

    #[test]
    fn a_merged_save_says_so_and_a_writer_that_reloads_carries_on() {
        let (conn, _d) = open("merged-token");
        let v1 = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B")] }),
            None,
        )
        .unwrap();
        // Someone else edits entry 1.
        save(
            &conn,
            json!({ "api_keys": [e("1", "A-theirs"), e("2", "B")] }),
            Some(&v1),
        )
        .unwrap();
        // The stale writer edits entry 2; entry 1 in its copy is behind.
        let t = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B-mine")] }),
            Some(&v1),
        )
        .unwrap();
        let bare = t
            .strip_suffix(crate::MERGED_SUFFIX)
            .expect("a merge is marked");
        assert_eq!(vault_version(&conn).unwrap().as_deref(), Some(bare));
        // Reloading gives the merged document, and its token is a valid base.
        assert_eq!(names(&conn), vec!["A-theirs", "B-mine"]);
        let mut doc = load_vault(&conn).unwrap().unwrap();
        doc["api_keys"][1]["provider"] = json!("B-mine-2");
        save(&conn, doc, Some(bare)).unwrap();
        assert_eq!(names(&conn), vec!["A-theirs", "B-mine-2"]);
    }

    #[test]
    fn the_marked_token_is_accepted_as_a_base() {
        let (conn, _d) = open("marked");
        let v1 = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B")] }),
            None,
        )
        .unwrap();
        save(
            &conn,
            json!({ "api_keys": [e("1", "A-theirs"), e("2", "B")] }),
            Some(&v1),
        )
        .unwrap();
        let t = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B-mine")] }),
            Some(&v1),
        )
        .unwrap();
        assert!(t.ends_with(crate::MERGED_SUFFIX));
        let mut doc = load_vault(&conn).unwrap().unwrap();
        doc["api_keys"][0]["api_key"] = json!("changed");
        assert!(save(&conn, doc, Some(&t)).is_ok());
    }

    #[test]
    fn a_save_with_nothing_to_merge_returns_the_new_version() {
        let (conn, _d) = open("clean-token");
        let v1 = save(&conn, json!({ "api_keys": [e("1", "A")] }), None).unwrap();
        let v2 = save(&conn, json!({ "api_keys": [e("1", "A2")] }), Some(&v1)).unwrap();
        assert_ne!(v1, v2);
        assert!(!v2.contains('+'), "no merge happened: {v2}");
        assert_eq!(vault_version(&conn).unwrap().as_deref(), Some(v2.as_str()));
    }

    #[test]
    fn deleting_an_entry_someone_else_edited_is_a_conflict_that_names_it() {
        let (conn, _d) = open("delete-edited");
        let v1 = save(
            &conn,
            json!({ "api_keys": [e("1", "Keep"), e("2", "Contested")] }),
            None,
        )
        .unwrap();
        save(
            &conn,
            json!({ "api_keys": [e("1", "Keep"), e("2", "Contested-edited")] }),
            Some(&v1),
        )
        .unwrap();
        let err = save(&conn, json!({ "api_keys": [e("1", "Keep")] }), Some(&v1)).unwrap_err();
        assert!(err.starts_with(CONFLICT_ERR));
        assert!(err.contains("Contested-edited"), "{err}");
        assert_eq!(names(&conn), vec!["Keep", "Contested-edited"]);
    }

    #[test]
    fn editing_an_entry_someone_else_deleted_is_a_conflict() {
        let (conn, _d) = open("edit-deleted");
        let v1 = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B")] }),
            None,
        )
        .unwrap();
        save(&conn, json!({ "api_keys": [e("1", "A")] }), Some(&v1)).unwrap();
        let err = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B-edit")] }),
            Some(&v1),
        )
        .unwrap_err();
        assert!(err.starts_with(CONFLICT_ERR), "{err}");
    }

    #[test]
    fn two_writers_arriving_at_the_same_content_do_not_conflict() {
        let (conn, _d) = open("same");
        let v1 = save(&conn, json!({ "api_keys": [e("1", "A")] }), None).unwrap();
        save(&conn, json!({ "api_keys": [e("1", "Same")] }), Some(&v1)).unwrap();
        assert!(save(&conn, json!({ "api_keys": [e("1", "Same")] }), Some(&v1)).is_ok());
    }

    #[test]
    fn projects_and_categories_merge_like_entries() {
        let (conn, _d) = open("projects");
        let v1 = save(
            &conn,
            json!({ "api_keys": [], "projects": [{ "id": "p1", "name": "One" }, { "id": "p2", "name": "Two" }], "user_categories": ["a"] }),
            None,
        )
        .unwrap();
        save(
            &conn,
            json!({ "api_keys": [], "projects": [{ "id": "p1", "name": "One-renamed" }, { "id": "p2", "name": "Two" }], "user_categories": ["a"] }),
            Some(&v1),
        )
        .unwrap();
        save(
            &conn,
            json!({ "api_keys": [], "projects": [{ "id": "p1", "name": "One" }, { "id": "p2", "name": "Two-renamed" }], "user_categories": ["a", "b"] }),
            Some(&v1),
        )
        .unwrap();
        let got = load_vault(&conn).unwrap().unwrap();
        assert_eq!(got["projects"][0]["name"], "One-renamed");
        assert_eq!(got["projects"][1]["name"], "Two-renamed");
        assert_eq!(got["user_categories"], json!(["a", "b"]));
    }

    #[test]
    fn a_token_in_the_old_form_or_from_a_pruned_save_is_a_whole_vault_conflict() {
        let (conn, _d) = open("oldtoken");
        let v1 = save(&conn, json!({ "api_keys": [e("1", "A")] }), None).unwrap();
        save(&conn, json!({ "api_keys": [e("1", "A2")] }), Some(&v1)).unwrap();
        for bad in [
            "deadbeef".to_string(),
            "1.0000".to_string(),
            "x.y".to_string(),
        ] {
            let err = save(&conn, json!({ "api_keys": [e("9", "Z")] }), Some(&bad)).unwrap_err();
            assert!(err.starts_with(CONFLICT_ERR), "{bad}: {err}");
        }
        // The base save has aged out of the retained history.
        conn.execute("DELETE FROM vault_saves WHERE seq = 1", [])
            .unwrap();
        let err = save(&conn, json!({ "api_keys": [e("1", "mine")] }), Some(&v1)).unwrap_err();
        assert!(err.starts_with(CONFLICT_ERR), "{err}");
    }

    #[test]
    fn history_lives_in_its_own_table_and_not_in_the_row() {
        let (conn, _d) = open("history");
        let v1 = save(&conn, json!({ "api_keys": [e("1", "A")] }), None).unwrap();
        let mut changed = e("1", "A");
        changed["api_key"] = json!("rotated");
        save(&conn, json!({ "api_keys": [changed] }), Some(&v1)).unwrap();
        let row: String = conn
            .query_row(
                "SELECT data FROM vault_rows WHERE kind = 'entry'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!row.contains("version_history"), "{row}");
        assert!(
            !row.contains("key-1"),
            "the old key belongs in the history table only"
        );
        let hist: String = conn
            .query_row("SELECT data FROM vault_history", [], |r| r.get(0))
            .unwrap();
        assert!(hist.contains("key-1"));
        // And it comes back attached to the entry.
        let doc = load_vault(&conn).unwrap().unwrap();
        assert_eq!(doc["api_keys"][0]["version_history"][0]["value"], "key-1");
    }

    #[test]
    fn deleting_an_entry_deletes_its_history() {
        let (conn, _d) = open("history-delete");
        let v1 = save(&conn, json!({ "api_keys": [e("1", "A")] }), None).unwrap();
        let mut changed = e("1", "A");
        changed["api_key"] = json!("rotated");
        let v2 = save(&conn, json!({ "api_keys": [changed] }), Some(&v1)).unwrap();
        save(&conn, json!({ "api_keys": [] }), Some(&v2)).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM vault_history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn legacy_entries_with_the_same_identity_both_survive() {
        let (conn, _d) = open("dupes");
        let doc = json!({ "api_keys": [
            { "provider": "Same", "api_key": "one" },
            { "provider": "Same", "api_key": "two" }
        ] });
        save(&conn, doc, None).unwrap();
        let got = load_vault(&conn).unwrap().unwrap();
        let keys: Vec<&str> = got["api_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["api_key"].as_str().unwrap())
            .collect();
        assert_eq!(keys, vec!["one", "two"]);
    }

    #[test]
    fn reordering_is_a_change_but_not_a_content_conflict() {
        let (conn, _d) = open("reorder");
        let v1 = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B")] }),
            None,
        )
        .unwrap();
        let v2 = save(
            &conn,
            json!({ "api_keys": [e("2", "B"), e("1", "A")] }),
            Some(&v1),
        )
        .unwrap();
        assert_ne!(v1, v2);
        assert_eq!(names(&conn), vec!["B", "A"]);
    }

    #[test]
    fn tampering_with_a_row_or_with_the_token_fails_integrity() {
        let (conn, _d) = open("verify");
        save(&conn, json!({ "api_keys": [e("1", "A")] }), None).unwrap();
        assert!(crate::verify_vault_integrity(&conn).unwrap());
        conn.execute("UPDATE vault_rows SET pos = 7 WHERE kind = 'entry'", [])
            .unwrap();
        assert!(
            !crate::verify_vault_integrity(&conn).unwrap(),
            "a moved row changes the state hash"
        );
    }

    // ── v1 -> v2 ───────────────────────────────────────────────────────────────

    fn plant_v1(conn: &Connection, doc: &Value) {
        conn.execute(
            "INSERT OR REPLACE INTO vault (id, data) VALUES (1, ?1)",
            params![doc.to_string()],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', '1')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('data_hash', 'abc')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn a_v1_vault_is_converted_on_first_open_with_a_backup_and_nothing_lost() {
        let (conn, dir) = open("migrate");
        let doc = json!({
            "api_keys": [
                { "id": "1", "provider": "A", "api_key": "k", "version_history": [{ "value": "old", "saved_at": "2026-01-01T00:00:00Z" }] },
                { "id": "2", "provider": "B", "api_key": "k2" }
            ],
            "projects": [{ "id": "p", "name": "P", "chunks": [] }],
            "user_categories": ["c"],
            "extra": 1
        });
        plant_v1(&conn, &doc);
        let audit_before = crate::load_audit(&conn).unwrap().len();

        let got = load_vault(&conn).unwrap().unwrap();
        assert_eq!(got, doc, "same document, new storage");
        assert_eq!(crate::vault_schema_version(&conn).unwrap(), Some(2));
        assert!(
            dir.join("vault.db.v1.bak").exists(),
            "the one-way conversion is backed up first"
        );
        let blob: i64 = conn
            .query_row("SELECT COUNT(*) FROM vault", [], |r| r.get(0))
            .unwrap();
        assert_eq!(blob, 0, "no second copy of every secret is left behind");
        assert_eq!(
            crate::load_audit(&conn).unwrap().len(),
            audit_before,
            "a move is not an edit"
        );
        assert!(crate::verify_vault_integrity(&conn).unwrap());
        // The old history is where history now lives.
        let h: i64 = conn
            .query_row("SELECT COUNT(*) FROM vault_history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(h, 1);
        // Idempotent.
        assert_eq!(load_vault(&conn).unwrap().unwrap(), doc);
    }

    #[test]
    fn the_version_read_before_the_data_is_valid_after_a_conversion() {
        let (conn, _d) = open("v1-version-order");
        plant_v1(&conn, &json!({ "api_keys": [e("1", "A")] }));
        crate::ensure_current_schema(&conn).unwrap();
        let v = vault_version(&conn).unwrap().unwrap();
        let doc = load_vault(&conn).unwrap().unwrap();
        let mut edited = doc;
        edited["api_keys"][0]["provider"] = json!("A2");
        assert!(
            save(&conn, edited, Some(&v)).is_ok(),
            "the first save after an upgrade must not conflict"
        );
    }

    #[test]
    fn saving_a_v1_vault_converts_it_in_the_same_transaction() {
        let (conn, _d) = open("migrate-save");
        plant_v1(&conn, &json!({ "api_keys": [e("1", "A")] }));
        let v = vault_version(&conn).unwrap().unwrap();
        assert_eq!(
            v, "abc",
            "before conversion the old token is still what is stored"
        );
        let out = save(
            &conn,
            json!({ "api_keys": [e("1", "A"), e("2", "B")] }),
            None,
        )
        .unwrap();
        assert_ne!(out, "abc");
        assert_eq!(names(&conn), vec!["A", "B"]);
        let blob: i64 = conn
            .query_row("SELECT COUNT(*) FROM vault", [], |r| r.get(0))
            .unwrap();
        assert_eq!(blob, 0);
    }

    #[test]
    fn a_vault_with_rows_but_a_v1_stamp_and_no_blob_is_left_alone() {
        let (conn, _d) = open("stamp-only");
        save(&conn, json!({ "api_keys": [e("1", "A")] }), None).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', '1')",
            [],
        )
        .unwrap();
        assert_eq!(names(&conn), vec!["A"]);
    }

    /// Not a test: a measurement, run with `--ignored --nocapture`. Nothing here
    /// should be optimised before it is instrumented, and the claim behind schema
    /// v2 is that one edit costs O(1) rows instead of O(vault).
    #[test]
    #[ignore]
    fn measure_one_edit_against_the_blob() {
        use std::time::Instant;
        let (conn, _d) = open("bench");
        let n = 5000;
        let entries: Vec<Value> = (0..n)
            .map(|i| {
                json!({
                    "id": format!("id-{i}"), "provider": format!("Provider {i}"),
                    "api_key": "x".repeat(48), "description": "d".repeat(200),
                    "tags": ["a", "b"], "extra_vars": [{"key": "K", "value": "v".repeat(64)}],
                    "version_history": (0..3).map(|j| json!({"value": "o".repeat(48), "saved_at": format!("2026-01-0{}T00:00:00Z", j + 1)})).collect::<Vec<_>>()
                })
            })
            .collect();
        let mut doc = json!({ "api_keys": entries, "projects": [], "user_categories": [] });
        let t = Instant::now();
        let mut base = save(&conn, doc.clone(), None).unwrap();
        println!("first save of {n} entries: {:?}", t.elapsed());

        // One edit, v2.
        doc["api_keys"][2500]["description"] = json!("edited");
        let t = Instant::now();
        base = save(&conn, doc.clone(), Some(&base)).unwrap();
        let v2 = t.elapsed();
        println!("v2: one edit in {n}: {v2:?}");
        let t = Instant::now();
        let _parts = split(doc.clone());
        println!("  split: {:?}", t.elapsed());
        // What v1 did for the same edit: read the blob, parse it, index every entry
        // (cloning, as the old code did), serialise the new document, hash it and
        // rewrite the one row.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS old_blob (id INTEGER PRIMARY KEY, data TEXT)",
        )
        .unwrap();
        let first = serde_json::to_string(&doc).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO old_blob (id, data) VALUES (1, ?1)",
            params![first],
        )
        .unwrap();
        let t = Instant::now();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let old: String = conn
            .query_row("SELECT data FROM old_blob WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        let old_doc: Value = serde_json::from_str(&old).unwrap();
        let old_map: HashMap<String, Value> = old_doc["api_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (crate::entry_ck(e), e.clone()))
            .collect();
        let _same = doc["api_keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| old_map.contains_key(&crate::entry_ck(e)))
            .count();
        let raw = serde_json::to_string(&doc).unwrap();
        let _h = sha(&raw);
        conn.execute(
            "INSERT OR REPLACE INTO old_blob (id, data) VALUES (1, ?1)",
            params![raw],
        )
        .unwrap();
        conn.execute_batch("COMMIT").unwrap();
        let v1 = t.elapsed();
        println!(
            "v1 (read blob, parse, index, serialise, hash, rewrite; {} KB): {v1:?}",
            raw.len() / 1024
        );

        let t = Instant::now();
        let loaded = load_vault(&conn).unwrap().unwrap();
        println!("load of {n} entries with history: {:?}", t.elapsed());
        let t = Instant::now();
        let lite = load_lite(&conn).unwrap().unwrap();
        println!("selective load without history: {:?}", t.elapsed());
        assert_eq!(
            loaded["api_keys"].as_array().unwrap().len(),
            lite["api_keys"].as_array().unwrap().len()
        );
        let _ = base;
    }
}
