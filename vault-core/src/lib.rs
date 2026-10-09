//! vault-core — shared encryption, storage, and tooling for UnENVerse.
//!
//! Used by the Tauri desktop app, the HTTP server (`unv-server`), and the CLI
//! (`unv-cli`).  Has no dependency on Tauri; accepts `&Path` for all I/O.

use argon2::{Algorithm, Argon2, Params, Version};
pub use rusqlite::Connection as SqlConnection;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::fs;
use std::path::Path;
pub use zeroize::Zeroize;

pub mod generators;
pub mod jwks;
pub use generators::{generate_certificate, generate_ssh_keypair};

// Phase 24.3: the one Rust builder for the .ics feed — moved here from
// unv-cli so `unv-server` can serve it too. See the module doc for why the
// TypeScript twin was deleted rather than kept as a second answer.
pub mod calendar;
// Phase 24.3: the ics_feeds table (token issuance/lookup/revocation). Storage
// only — rate limiting and RBAC filtering live in unv-server, same split as
// `users`.
pub mod ics_feeds;
// Phase 24.4: the unique-ID registry — a separate SQLCipher file keyed from a
// secret stored in this vault's vault_meta. Storage and hashing only; rate
// limiting lives in unv-server.
pub mod uid_registry;

// Phase 34: nodes. The protocol, the hub registry and the node config (`nodes`),
// and the transactional file apply a node performs (`nodes_apply`).
pub mod nodes;
pub mod nodes_apply;

// Phase 35: the config time machine, and the line diff it shares with the CLI,
// the server and the app.
pub mod blast;
pub mod config_history;

// Phase 38: stack integrations (Prometheus, Grafana, Homepage) as descriptors in
// data/stack-adapters.json, interpreted here and in src/ts/stack.ts.
pub mod stack;
pub mod textdiff;
// Phase 24.5: the secret-type registry — one JSON descriptor file, read here
// and imported as plain JSON by the TypeScript side.
pub mod secret_types;
// Phase 24.5: FIDO CXF import/export.
pub mod cxf;
// Phase 24.1: bundle-local and sibling-value template resolution.
pub mod bundle_import;
pub mod bundle_scope;
pub mod catalogue;
pub mod config_check;
pub mod oauth;
pub mod pgp;
pub mod php_config;
pub mod session_import;
pub mod storage;
pub mod templates;
pub mod toml_import;
pub mod type_emit;

pub mod permex;
pub mod pool;

// No outer `///` here either — same reason as `totp` and `totp_import` below:
// this module's own `//!` block would merge with one and break intra-doc links.
pub mod composite;

// Both modules carry their own `//!` docs. Adding an outer `///` here as well
// makes rustdoc merge the two and resolve the *combined* text in this file's
// scope, so every intra-doc link written inside the module — `[`Source::Os`]`,
// `[`TlsPolicy::Pin`]` — fails with "no item named … in scope" and
// `-D warnings` turns that into a failed docs build.
pub mod entropy;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "telemetry")]
pub mod telemetry;
pub use permex::{
    eval as eval_perm_expr, parse as parse_perm_expr, EntryView, Expr as PermExpr,
    Field as PermField,
};

pub mod users;

// `totp` carries its own `//!` docs. No outer `///` here, for the same reason
// as `entropy` above: rustdoc merges the two and resolves the combined text in
// *this* file's scope, so `[`verify`]` written inside the module fails with
// "no item named `verify` in module `vault_core`" and `-D warnings` turns that
// into a failed docs build.
pub mod totp;

// Reading and writing the export files other authenticator apps produce.
// Documented inside the module: an outer `///` here would merge with its own
// `//!` block and resolve every intra-doc link in *this* file's scope, which is
// how `entropy` and `totp` have each broken the docs build before.
pub mod totp_import;
pub use users::{
    assign_user_class, authority_tier, class_authority_tier, create_user, create_user_class,
    create_user_token, delete_user, delete_user_class, effective_permission_expr,
    ensure_owner_user, filter_vault_for_user, get_class_permissions, get_permission_expr,
    get_user_capabilities, get_user_permissions, glob_matches, init_users_schema,
    list_user_classes, list_user_tokens, list_users, merge_user_vault_write, rename_user,
    revoke_user_token, seed_default_admin, set_class_permissions, set_permission_expr,
    set_user_password, set_user_permissions, token_user_id, update_user_class, user_authority_tier,
    verify_user_password, verify_user_token, AdminSeed, ClassPermission, PermissionRecord,
    TokenRecord, UserClass, UserRecord,
};

// ── Constants ──────────────────────────────────────────────────────────────────

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

const A2_M_COST: u32 = 65_536;
const A2_T_COST: u32 = 3;
const A2_P_COST: u32 = 1;

/// In-memory AES-256 vault key.
pub type VaultKey = [u8; KEY_LEN];

// ── KDF ────────────────────────────────────────────────────────────────────────

/// Derives a 32-byte AES-256 key from `password` and `salt` using Argon2id
/// (m=65536 KiB, t=3, p=1 — OWASP 2023 recommendation).
pub fn derive_key(password: &str, salt: &[u8]) -> Result<VaultKey, String> {
    let params =
        Params::new(A2_M_COST, A2_T_COST, A2_P_COST, Some(KEY_LEN)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

/// Restrict a file to its owner where the platform can express that.
///
/// Windows has no chmod equivalent — files inherit the directory ACL — so this
/// is a no-op there and `unv doctor` reports the check as *not enforceable*
/// rather than passing. A check that always passes proves nothing.
pub fn restrict_to_owner(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Refuse to derive a key when a database exists but its salt does not.
///
/// [`read_or_create_salt`] generates a salt when the file is absent, which is
/// right for a first run and catastrophic for an existing vault: the new salt
/// derives a different key, every unlock reports **"Wrong master password"**,
/// and the user spends the afternoon convinced they have forgotten it. The
/// evidence that anything else happened is gone by then, because the missing
/// file has been silently replaced.
///
/// Called before key derivation by every path that opens an existing vault.
pub fn check_salt_pairing(db_path: &Path, salt_path: &Path) -> Result<(), String> {
    let db_exists = fs::metadata(db_path).map(|m| m.len() > 0).unwrap_or(false);
    if db_exists && !salt_path.exists() {
        return Err(format!(
            "{} exists but {} is missing.\n\
             The salt is 16 random bytes written once and stored nowhere else — without \n\
             it this database cannot be opened by anyone, and nothing can recompute it.\n\
             Restore both from an archive (`unv backup restore-archive`), or restore the \n\
             vault contents from a .vaultbak (`unv backup import`), which does not need \n\
             the original salt.",
            db_path.display(),
            salt_path.display()
        ));
    }
    Ok(())
}

/// Reads salt from `salt_path`; generates and writes a fresh 16-byte salt if absent.
pub fn read_or_create_salt(salt_path: &Path) -> Result<[u8; SALT_LEN], String> {
    if salt_path.exists() {
        let raw = fs::read(salt_path).map_err(|e| e.to_string())?;
        raw.try_into()
            .map_err(|_| "vault.salt is corrupt (wrong length)".to_string())
    } else {
        use rand::RngCore;
        let mut s = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut s);
        if let Some(parent) = salt_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(salt_path, s).map_err(|e| e.to_string())?;
        // The salt is half of what opens the vault. It was written with whatever
        // the umask gave it — 0644 on a default Linux install, which `unv
        // doctor` is what finally noticed.
        restrict_to_owner(salt_path)?;
        Ok(s)
    }
}

// ── Database ───────────────────────────────────────────────────────────────────

/// Opens (or creates) the SQLCipher database at `db_path` using the 32-byte `key`.
///
/// Executes a verification query; returns `Err("Wrong master password")` on
/// decryption failure so callers can distinguish auth errors from I/O errors.
pub fn open_db(db_path: &Path, key: &VaultKey) -> Result<Connection, String> {
    if let Some(p) = db_path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .map_err(|e| e.to_string())?;
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key)))
        .map_err(|e| e.to_string())?;
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|_| "Wrong master password".to_string())?;
    // WAL mode: allows concurrent reads + one writer, avoids full locks (item 17)
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .map_err(|e| e.to_string())?;
    // SQLCipher creates the file with the process umask — 0644 on a default
    // Linux install. The contents are encrypted, so this is not a disclosure of
    // secrets; it is a disclosure of the ciphertext to anyone with a login on
    // the box, which is an offline-attack head start nobody asked to give.
    // WAL mode means two sidecars carry the same data.
    restrict_to_owner(db_path)?;
    for suffix in ["-wal", "-shm"] {
        let mut side = db_path.as_os_str().to_owned();
        side.push(suffix);
        let side = std::path::PathBuf::from(side);
        if side.exists() {
            restrict_to_owner(&side)?;
        }
    }
    Ok(conn)
}

/// Creates the `vault` and `vault_audit` tables if absent; adds hash-chain
/// columns to `vault_audit` via idempotent ALTER TABLE (errors silently ignored
/// on existing columns).
pub fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vault (
             id   INTEGER PRIMARY KEY CHECK (id = 1),
             data TEXT    NOT NULL
         );
         CREATE TABLE IF NOT EXISTS vault_audit (
             id             INTEGER PRIMARY KEY AUTOINCREMENT,
             action         TEXT    NOT NULL,
             entry_provider TEXT,
             timestamp      TEXT    NOT NULL,
             details        TEXT
         );
         CREATE TABLE IF NOT EXISTS vault_meta (
             key   TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );",
    )
    .map_err(|e| e.to_string())?;
    // Idempotent migration: add hash-chain columns if absent.
    let _ = conn.execute_batch("ALTER TABLE vault_audit ADD COLUMN entry_hash TEXT;");
    let _ = conn.execute_batch("ALTER TABLE vault_audit ADD COLUMN prev_hash  TEXT;");
    // Who performed the action. Rows written before this column exists stay NULL
    // and verify against the v1 hash formula (see `compute_audit_hash`).
    let _ = conn.execute_batch("ALTER TABLE vault_audit ADD COLUMN actor TEXT;");
    // Audit lookups by entry and by time were full scans of the only table in the
    // schema that could have been indexed from the start.
    let _ = conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS vault_audit_provider ON vault_audit (entry_provider);
         CREATE INDEX IF NOT EXISTS vault_audit_time ON vault_audit (timestamp);",
    );
    // Row-per-entry storage (Phase 30).
    storage::init_schema(conn)?;
    // Multi-user tables (Phase 5)
    users::init_users_schema(conn)?;
    // Calendar feed tokens (Phase 24.3)
    ics_feeds::init_schema(conn)?;
    config_history::init_schema(conn)?;
    Ok(())
}

// ── Entry identity ────────────────────────────────────────────────────────────

/// Canonical identity key for a vault entry.
///
/// Prefers the stable `id` (a UUID the frontend assigns on creation and never
/// mutates). Falls back to `provider|account_name|key_id` for entries written
/// before `id` existed.
///
/// Every consumer must use this one function. `save_vault` and
/// [`merge_user_vault_write`] previously disagreed — the former ignored
/// `key_id`, so two entries sharing provider+account collapsed into one key and
/// `version_history` / audit rows landed on the wrong entry, while the RBAC
/// merge treated them as distinct.
pub fn entry_ck(entry: &serde_json::Value) -> String {
    if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
        if !id.is_empty() {
            return format!("id\u{1}{id}");
        }
    }
    let field = |k: &str| entry.get(k).and_then(|v| v.as_str()).unwrap_or("");
    format!(
        "legacy\u{1}{}\u{1}{}\u{1}{}",
        field("provider"),
        field("account_name"),
        field("key_id"),
    )
}

// ── Schema versioning ─────────────────────────────────────────────────────────

/// The vault-document schema this build writes.
///
/// Three binaries — the desktop app, `unv-server` and `unv` — read and write
/// one untyped JSON blob, and until this existed nothing recorded which shape it
/// was in. The problem had already been hit once and solved by convention: the
/// legacy `rate_limit` string is dual-written so a vault edited by a current
/// build stays readable to an older one. The next field that skips that
/// convention breaks old readers with no way to detect it and no way to refuse.
///
/// Bump this when a change makes a document unreadable to the previous build —
/// not for an added optional field, which older readers ignore harmlessly.
///
/// Version 1 is the document shape as of 0.8.1: the whole vault as one JSON
/// string in one row. Vaults written before this constant existed carry no
/// version at all; that is treated as 1, because it is.
///
/// **Version 2 (Phase 30) is row-per-entry storage** (see [`storage`]). A v1 vault
/// is converted on first open, after a `vault.db.v1.bak` copy; a v1 build then
/// refuses the file with [`SCHEMA_ERR`] instead of reading an empty blob.
///
/// **Version 3 (Phase 30.2) gives every chunk of a project a row of its own.** A v2
/// vault loads unchanged (a project row with inline chunks is understood) and is
/// rewritten into chunk rows by its first save; a v2 build then refuses the file,
/// because it would read a project with no chunks and delete the chunk rows.
pub const VAULT_SCHEMA_VERSION: u32 = 3;

/// Marker prefix on the error returned when the stored vault was written by a
/// newer build than this one. Callers match on it to tell "upgrade me" from a
/// real failure.
pub const SCHEMA_ERR: &str = "VAULT_SCHEMA_TOO_NEW";

/// The schema version stamped on the stored vault, or `None` for a vault
/// written before versioning existed (or an empty database).
pub fn vault_schema_version(conn: &Connection) -> Result<Option<u32>, String> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    match raw {
        None => Ok(None),
        // An unparseable stamp is not "no stamp": something wrote a value this
        // build cannot interpret, which is the same situation as a future
        // version and gets the same refusal.
        Some(s) => s
            .trim()
            .parse::<u32>()
            .map(Some)
            .map_err(|_| format!("{SCHEMA_ERR}: unreadable schema_version {s:?}")),
    }
}

/// Refuses to touch a vault written by a newer build.
///
/// Refuse-with-a-message beats corrupt-on-round-trip: an old binary that reads a
/// future document, drops the fields it does not know and writes it back has
/// silently destroyed data, which is this project's worst bug class.
pub fn check_schema_version(conn: &Connection) -> Result<(), String> {
    match vault_schema_version(conn)? {
        Some(v) if v > VAULT_SCHEMA_VERSION => Err(format!(
            "{SCHEMA_ERR}: this vault was written by a newer version of UnENVerse \
             (vault schema v{v}, this build understands v{VAULT_SCHEMA_VERSION}). \
             Upgrade UnENVerse to open it — writing it with this build would drop \
             the fields it does not understand."
        )),
        _ => Ok(()),
    }
}

// ── Vault I/O ─────────────────────────────────────────────────────────────────

/// Loads the raw vault JSON from an open connection.
///
/// Refuses a vault stamped with a schema this build does not understand, rather
/// than handing back a document it would silently truncate on the next save.
pub fn load_vault(conn: &Connection) -> Result<Option<serde_json::Value>, String> {
    check_schema_version(conn)?;
    // A v1 vault is converted the first time anything opens it.
    storage::migrate_if_needed(conn, &iso_now())?;
    storage::load(conn)
}

/// Appended to the version returned by a save that folded in other writers'
/// changes (Phase 30). The part before it is the current version token; a writer
/// that sends the whole thing back as `expect_version` is understood.
pub const MERGED_SUFFIX: &str = "+merged";

/// Refuse a newer schema and convert a v1 vault, so that a version read *after*
/// this is a version of the converted vault. A caller that reads the version
/// before the data (the safe order, see the server's PUT handler) must call this
/// first, or it pairs a v1 hash with a v2 document and its first save conflicts.
pub fn ensure_current_schema(conn: &Connection) -> Result<(), String> {
    check_schema_version(conn)?;
    storage::migrate_if_needed(conn, &iso_now())
}

/// The vault document without any entry's `version_history`: what a selective
/// read needs, without the 50-revision secret trail per entry that a full read
/// carries (Phase 30).
pub fn load_vault_lite(conn: &Connection) -> Result<Option<serde_json::Value>, String> {
    check_schema_version(conn)?;
    storage::migrate_if_needed(conn, &iso_now())?;
    storage::load_lite(conn)
}

/// Marker prefix on the error returned when a compare-and-swap write is refused.
/// Callers match on this to tell "someone else wrote first" from a real failure.
pub const CONFLICT_ERR: &str = "VAULT_CONFLICT";

/// Who is writing, and what they believe the vault currently is.
///
/// A struct rather than two positional `Option<&str>` arguments: silently
/// swapping an actor id for a version hash would disable the concurrency check
/// while still compiling and still passing tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct SaveCtx<'a> {
    /// User id responsible for the change, recorded in the audit log.
    /// `None` for contexts where the owner is implicit.
    pub actor: Option<&'a str>,
    /// The version the caller last read. When set, the write is refused unless
    /// the stored vault is *still* at that version. `None` writes unconditionally
    /// — only correct when nothing else can be writing.
    pub expect_version: Option<&'a str>,
}

/// Current version of the stored vault, or `None` when the vault is empty.
///
/// This is the `data_hash` that `save_vault` writes, so it is by construction
/// the hash of exactly the bytes on disk — no re-serialisation, no assumptions
/// about map ordering.
pub fn vault_version(conn: &Connection) -> Result<Option<String>, String> {
    storage::version(conn)
}

/// Entry fields whose change is worth a `version_history` snapshot.
///
/// The pair is (JSON field, the word the audit row uses). `api_key` is first and
/// is the one that writes no `field` discriminator into the record — see
/// `save_vault_with_actor`.
const HISTORIED_SECRET_FIELDS: [(&str, &str); 3] = [
    ("api_key", "api_key"),
    ("api_secret", "api_secret"),
    ("totp_secret", "totp_secret"),
];

/// Previous values of an entry's `extra_vars`, keyed by var name.
///
/// Phase 23, E8. A named variable is where the real payload of an `env_var`
/// entry lives, and for an AWS or Twilio credential it is where *all* of it
/// lives — so before this, the only entries whose secrets were versioned were
/// the ones that happened to use the primary slot. An `env_var` entry had **no
/// history at all**, which E8 itself calls the one unacceptable option.
///
/// A var marked `public` is skipped: it is a region or a client id by
/// declaration, and filling a 50-record history with them evicts the values
/// that cannot be recovered any other way.
fn historied_extra_vars(entry: &serde_json::Value) -> Vec<(String, String)> {
    entry
        .get("extra_vars")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|xv| !xv.get("public").and_then(|p| p.as_bool()).unwrap_or(false))
                .filter_map(|xv| {
                    let k = xv.get("key").and_then(|v| v.as_str())?;
                    let v = xv.get("value").and_then(|v| v.as_str())?;
                    if k.is_empty() {
                        return None;
                    }
                    Some((k.to_string(), v.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Phase 30.1: apply a delta to a stored vault document. Shared by `PATCH
/// /api/vault` and the desktop's `save_vault_rows` so they cannot differ.
///
/// `{ put, delete }` change `api_keys` by `id`; `projects_put`/`projects_delete`
/// change `projects` by `id`; `categories`, when present, replaces
/// `user_categories` (a flat list of strings, small). Every put needs a
/// non-empty string `id`. Unknown keys are ignored.
pub fn apply_row_patch(
    mut doc: serde_json::Value,
    patch: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    use serde_json::Value;
    fn ids(v: Option<&Value>, what: &str) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for d in v.and_then(Value::as_array).into_iter().flatten() {
            match d.as_str() {
                Some(id) if !id.is_empty() => out.push(id.to_string()),
                _ => return Err(format!("{what} takes a list of ids")),
            }
        }
        Ok(out)
    }
    fn puts(v: Option<&Value>, what: &str) -> Result<Vec<(String, Value)>, String> {
        let mut out = Vec::new();
        for e in v.and_then(Value::as_array).into_iter().flatten() {
            match e.get("id").and_then(Value::as_str) {
                Some(id) if !id.is_empty() => out.push((id.to_string(), e.clone())),
                _ => return Err(format!("Every {what} needs a string id")),
            }
        }
        Ok(out)
    }
    fn apply(
        doc: &mut Value,
        key: &str,
        put: Vec<(String, Value)>,
        del: Vec<String>,
    ) -> Result<(), String> {
        let list = doc
            .get_mut(key)
            .and_then(Value::as_array_mut)
            .ok_or_else(|| format!("stored vault has no {key}"))?;
        let id_of = |e: &Value| e.get("id").and_then(Value::as_str).map(str::to_string);
        list.retain(|e| id_of(e).is_none_or(|id| !del.contains(&id)));
        for (id, entry) in put {
            match list
                .iter()
                .position(|e| id_of(e).as_deref() == Some(id.as_str()))
            {
                Some(i) => list[i] = entry,
                None => list.push(entry),
            }
        }
        Ok(())
    }
    let (ep, ed) = (
        puts(patch.get("put"), "put entry")?,
        ids(patch.get("delete"), "delete")?,
    );
    let (pp, pd) = (
        puts(patch.get("projects_put"), "put project")?,
        ids(patch.get("projects_delete"), "projects_delete")?,
    );
    let cats = match patch.get("categories") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) if a.iter().all(Value::is_string) => Some(Value::Array(a.clone())),
        Some(_) => return Err("categories takes a list of strings".into()),
    };
    apply(&mut doc, "api_keys", ep, ed)?;
    if !pp.is_empty() || !pd.is_empty() {
        if doc.get("projects").is_none() {
            doc["projects"] = Value::Array(Vec::new());
        }
        apply(&mut doc, "projects", pp, pd)?;
    }
    if let Some(c) = cats {
        doc["user_categories"] = c;
    }
    Ok(doc)
}

/// Serialises `data` to the vault, updating `version_history` on key changes
/// and appending to the `vault_audit` hash chain. Returns the new version.
///
/// # Concurrency
///
/// When `ctx.expect_version` is set this is a **compare-and-swap**: the whole
/// operation runs inside one `BEGIN IMMEDIATE` transaction, and if another
/// writer has changed the vault since the caller read it, nothing is written and
/// [`CONFLICT_ERR`] is returned.
///
/// Doing the check here rather than in each caller matters for two reasons.
/// A caller that reads, compares, then writes has a race between the compare and
/// the write — which is what the server's `If-Match` handling used to be. And a
/// caller that simply forgets is silently unprotected, which is how the desktop
/// could clobber a LAN peer's edit.
///
/// The audit appends are inside the same transaction. They used to run before it,
/// so a rejected or failed write still left audit rows describing changes that
/// never happened.
pub fn save_vault(
    conn: &Connection,
    data: serde_json::Value,
    ctx: SaveCtx<'_>,
) -> Result<String, String> {
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| e.to_string())?;
    match save_vault_txn(conn, data, ctx) {
        Ok(hash) => {
            conn.execute_batch("COMMIT").map_err(|e| e.to_string())?;
            Ok(hash)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Body of [`save_vault`]. Must only be called inside a write transaction.
///
/// Phase 30: the document is split into rows, a stale writer is merged with what
/// others saved since (see [`storage`]), and only rows whose content changed are
/// written, audited and given history.
fn save_vault_txn(
    conn: &Connection,
    data: serde_json::Value,
    ctx: SaveCtx<'_>,
) -> Result<String, String> {
    let actor = ctx.actor;
    let now_str = iso_now();

    // Refuse before doing any work: a newer document read by this build would
    // lose every field this build does not know about.
    check_schema_version(conn)?;
    // A v1 blob still waiting is converted inside this same transaction.
    storage::migrate_in_txn(conn, &now_str)?;

    // Compare-and-swap, now per row: inside the transaction, so no writer can slip
    // between this check and the write below. An absent version means an empty
    // vault; a caller expecting a specific version against one is out of date.
    let snap = storage::snapshot(conn)?;
    let (mut ents, merged) = storage::merge(conn, &snap, storage::split(data), ctx.expect_version)?;

    let stored: std::collections::HashMap<&str, &str> = snap
        .iter()
        .filter(|((kind, _), _)| kind == "entry")
        .map(|((_, key), (rev, _))| (key.as_str(), rev.as_str()))
        .collect();
    let kept: std::collections::HashSet<&str> = ents
        .iter()
        .filter(|e| e.kind == "entry")
        .map(|e| e.key.as_str())
        .collect();
    for key in stored.keys() {
        if !kept.contains(*key) {
            if let Some(old) = storage::load_ent(conn, "entry", key)? {
                append_audit(conn, "delete", &old.provider(), &now_str, None, actor)?;
            }
        }
    }

    for ent in ents.iter_mut().filter(|e| e.kind == "entry") {
        match stored.get(ent.key.as_str()) {
            // Content unchanged: no history, no audit, no write.
            Some(rev) if *rev == ent.rev => continue,
            Some(_) => {
                let Some(old) = storage::load_ent(conn, "entry", &ent.key)? else {
                    continue;
                };
                let old_e = old.full();
                let mut entry = ent.full();
                let provider = ent.provider();
                let entry = &mut entry;
                // Every secret-carrying value the entry holds, snapshot into one
                // history. `api_key` writes no `field` discriminator so a vault
                // stays readable to a build that predates the others — an
                // absent `field` means `api_key`, and always has.
                //
                // `totp_secret` is here because a re-enrolled authenticator seed
                // is exactly as unrecoverable as a replaced API key, and losing
                // it silently is how a user finds out at the login screen.
                for (field, label) in HISTORIED_SECRET_FIELDS {
                    let new_val = entry.get(field).and_then(|v| v.as_str()).unwrap_or("");
                    let old_val = old_e.get(field).and_then(|v| v.as_str()).unwrap_or("");
                    if new_val == old_val || old_val.is_empty() {
                        continue;
                    }
                    let mut history: Vec<serde_json::Value> = entry
                        .get("version_history")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_else(|| {
                            old_e
                                .get("version_history")
                                .and_then(|v| v.as_array())
                                .cloned()
                                .unwrap_or_default()
                        });
                    let mut record = serde_json::json!({ "value": old_val, "saved_at": now_str });
                    if field != "api_key" {
                        record["field"] = serde_json::json!(field);
                    }
                    history.insert(0, record);
                    // The cap is per entry, not per field, so a chatty seed
                    // cannot evict an API key's history — which is why they all
                    // share one list rather than getting one each.
                    history.truncate(50);
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert(
                            "version_history".to_string(),
                            serde_json::Value::Array(history),
                        );
                    }
                    append_audit(
                        conn,
                        "update",
                        &provider,
                        &now_str,
                        Some(&format!("{label} rotated")),
                        actor,
                    )?;
                }

                // The same, for named variables (E8). Matched by **name**, not
                // by position: `extra_vars` is an array the form rebuilds on
                // every save, so an index captured across an edit points at
                // whatever took its place — invariant 1, in the one place where
                // getting it wrong writes the wrong secret into history.
                //
                // A var that is *removed* leaves its last value in history: the
                // user deleting a row is exactly as unable to recover it as the
                // user overwriting one, and the row's absence is not evidence
                // that they meant to lose it.
                let old_vars = historied_extra_vars(&old_e);
                if !old_vars.is_empty() {
                    let new_vars: std::collections::HashMap<String, String> =
                        historied_extra_vars(entry).into_iter().collect();
                    for (key, old_val) in old_vars {
                        if old_val.is_empty() {
                            continue;
                        }
                        if new_vars.get(&key).map(String::as_str) == Some(old_val.as_str()) {
                            continue;
                        }
                        let mut history: Vec<serde_json::Value> = entry
                            .get("version_history")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        history.insert(
                            0,
                            serde_json::json!({
                                "value": old_val,
                                "saved_at": now_str,
                                // Namespaced so a restore can tell a var called
                                // `api_key` from the field of that name.
                                "field": format!("extra_vars/{key}"),
                            }),
                        );
                        history.truncate(50);
                        if let Some(obj) = entry.as_object_mut() {
                            obj.insert(
                                "version_history".to_string(),
                                serde_json::Value::Array(history),
                            );
                        }
                        append_audit(
                            conn,
                            "update",
                            &provider,
                            &now_str,
                            Some(&format!("{key} rotated")),
                            actor,
                        )?;
                    }
                }
                // Split the (possibly extended) history back off the row.
                if let Some(h) = entry
                    .as_object_mut()
                    .and_then(|o| o.remove("version_history"))
                {
                    ent.history = Some(h);
                }
            }
            None => {
                append_audit(conn, "add", &ent.provider(), &now_str, None, actor)?;
            }
        }
    }

    // Data and token move together, so the integrity check never sees a mismatch.
    let token = storage::write(conn, &snap, &ents, &now_str)?;
    // Stamp the shape alongside the data, in the same transaction. A vault that
    // has been written by this build is by definition in this build's schema,
    // so there is no separate migration step to forget to run.
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?1)",
        rusqlite::params![VAULT_SCHEMA_VERSION.to_string()],
    )
    .map_err(|e| e.to_string())?;

    // When other writers' changes were folded in, the caller's copy of the vault
    // is *behind* what was just stored. Treating the new token as its base would
    // let it overwrite those changes on its next save, and keeping its old base
    // would make that save conflict with its own previous one. So the token comes
    // back marked [`MERGED_SUFFIX`]: a client that holds a document reloads it; a
    // one-shot client (the CLI) never looks.
    if merged {
        Ok(format!("{token}{MERGED_SUFFIX}"))
    } else {
        Ok(token)
    }
}

/// Verifies the stored vault data against its SHA-256 integrity hash.
/// Returns `Ok(true)` if hash matches, `Ok(false)` if tampered or hash absent, `Err` on I/O.
pub fn verify_vault_integrity(conn: &Connection) -> Result<bool, String> {
    storage::verify(conn)
}

/// Returns vault entries whose `expires_at` date falls within `within_days` days
/// from today (inclusive of today, exclusive of entries already expired).
///
/// Uses lexicographic YYYY-MM-DD comparison — no parsing feature required.
pub fn get_expiring_entries(
    conn: &Connection,
    within_days: u32,
) -> Result<Vec<serde_json::Value>, String> {
    let data = load_vault(conn)?.unwrap_or_else(|| serde_json::json!({ "api_keys": [] }));
    Ok(expiring_from_value(&data, within_days))
}

/// Like [`get_expiring_entries`] but first filters the vault to the entries the
/// user is permitted to read.  Prevents non-owner sessions from learning about
/// the expiry (and full contents) of secrets outside their RBAC scope.
pub fn get_expiring_entries_for_user(
    conn: &Connection,
    within_days: u32,
    read: Option<&permex::Expr>,
) -> Result<Vec<serde_json::Value>, String> {
    let data = load_vault(conn)?.unwrap_or_else(|| serde_json::json!({ "api_keys": [] }));
    let filtered = filter_vault_for_user(data, read);
    Ok(expiring_from_value(&filtered, within_days))
}

/// Extracts the `api_keys` whose `expires_at` falls within `within_days` of today.
fn expiring_from_value(data: &serde_json::Value, within_days: u32) -> Vec<serde_json::Value> {
    let now = time::OffsetDateTime::now_utc();
    let cutoff = now + time::Duration::days(within_days as i64);
    let today_str = fmt_date(&now);
    let cutoff_str = fmt_date(&cutoff);

    data.get("api_keys")
        .and_then(|k| k.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| {
            entry
                .get("expires_at")
                .and_then(|v| v.as_str())
                .is_some_and(|s| {
                    let d = &s[..s.len().min(10)];
                    d >= today_str.as_str() && d <= cutoff_str.as_str()
                })
        })
        .collect()
}

fn fmt_date(dt: &time::OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day())
}

// ── Audit log ─────────────────────────────────────────────────────────────────

/// A single audit log row, including the hash-chain fields.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditRow {
    pub id: i64,
    pub action: String,
    pub entry_provider: Option<String>,
    pub timestamp: String,
    pub details: Option<String>,
    pub entry_hash: Option<String>,
    pub prev_hash: Option<String>,
    /// User id that performed the action. `None` for rows written before actor
    /// tracking, and for local desktop edits where the owner is implicit.
    pub actor: Option<String>,
}

/// Appends an audit entry and computes `entry_hash = SHA256(action|provider|ts|prev_hash)`.
fn append_audit(
    conn: &Connection,
    action: &str,
    provider: &str,
    timestamp: &str,
    details: Option<&str>,
    actor: Option<&str>,
) -> Result<(), String> {
    let prev_hash: Option<String> = conn
        .query_row(
            "SELECT entry_hash FROM vault_audit ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .flatten();

    let entry_hash = compute_audit_hash(
        action,
        provider,
        timestamp,
        actor,
        prev_hash.as_deref().unwrap_or("genesis"),
    );

    conn.execute(
        "INSERT INTO vault_audit \
         (action, entry_provider, timestamp, details, entry_hash, prev_hash, actor) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![action, provider, timestamp, details, entry_hash, prev_hash, actor],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Records a hash-chained audit event with the current timestamp.
pub fn record_event(
    conn: &Connection,
    action: &str,
    provider: &str,
    details: Option<&str>,
    actor: Option<&str>,
) -> Result<(), String> {
    append_audit(conn, action, provider, &iso_now(), details, actor)
}

/// Hash for one audit row, binding it to its predecessor.
///
/// Two formats coexist:
/// - **v1** `action|provider|timestamp|prev` — rows written before actor tracking.
/// - **v2** `action|provider|timestamp|actor|prev` — includes the acting user, so
///   attribution is covered by the chain and cannot be rewritten undetected.
///
/// A row with no actor keeps using v1 so existing chains stay verifiable; the
/// verifier tries v2 first and falls back to v1.
fn compute_audit_hash(
    action: &str,
    provider: &str,
    timestamp: &str,
    actor: Option<&str>,
    prev_hash: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    match actor {
        Some(a) => {
            for part in [
                action, "|", provider, "|", timestamp, "|", a, "|", prev_hash,
            ] {
                h.update(part.as_bytes());
            }
        }
        None => {
            for part in [action, "|", provider, "|", timestamp, "|", prev_hash] {
                h.update(part.as_bytes());
            }
        }
    }
    hex::encode(h.finalize())
}

/// Returns all audit rows ordered newest-first.
pub fn load_audit(conn: &Connection) -> Result<Vec<AuditRow>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, action, entry_provider, timestamp, details, entry_hash, prev_hash, actor \
         FROM vault_audit ORDER BY id DESC",
        )
        .map_err(|e| e.to_string())?;

    let rows: Vec<Result<AuditRow, _>> = stmt
        .query_map([], |row| {
            Ok(AuditRow {
                id: row.get(0)?,
                action: row.get(1)?,
                entry_provider: row.get(2)?,
                timestamp: row.get(3)?,
                details: row.get(4)?,
                entry_hash: row.get(5)?,
                prev_hash: row.get(6)?,
                actor: row.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect();
    rows.into_iter()
        .map(|r| r.map_err(|e| e.to_string()))
        .collect()
}

// ── Migration helpers ─────────────────────────────────────────────────────────

/// Inserts raw JSON from a legacy `vault.json` into the `vault` table.
/// Called once on first unlock after a Phase 1 → Phase 2 upgrade.
pub fn migrate_legacy_json(conn: &Connection, raw_json: &str) -> Result<(), String> {
    let doc: serde_json::Value = serde_json::from_str(raw_json).map_err(|e| e.to_string())?;
    save_vault(conn, doc, SaveCtx::default()).map(|_| ())
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Returns the current UTC time as an ISO-8601 string (`YYYY-MM-DDTHH:MM:SSZ`).
/// A random UUID v4, with the version and variant bits set.
///
/// Hand-rolled rather than pulled in as a crate for the same reason base32 is:
/// it is eleven lines, and `rand` is already here. `users.rs` and the TOTP
/// importer both call it, so an entry created by the desktop app's import gets
/// an id shaped exactly like one created anywhere else — which matters because
/// `entry_ck` falls back to a legacy tuple for entries that have none.
pub fn new_uuid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&b[0..4]),
        hex::encode(&b[4..6]),
        hex::encode(&b[6..8]),
        hex::encode(&b[8..10]),
        hex::encode(&b[10..16]),
    )
}

pub fn iso_now() -> String {
    let t = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[test]
    fn a_row_patch_replaces_by_id_appends_deletes_and_refuses_bad_input() {
        use serde_json::json;
        let doc = json!({
            "api_keys": [{"id":"a","provider":"A"},{"id":"b","provider":"B"}],
            "user_categories": ["x"],
            "projects": [{"id":"p","name":"P"}]
        });
        let out = apply_row_patch(
            doc.clone(),
            &json!({
                "put": [{"id":"b","provider":"B2"},{"id":"c","provider":"C"}],
                "delete": ["a"],
                "projects_put": [{"id":"q","name":"Q"}],
                "projects_delete": ["p"],
                "categories": ["y","z"]
            }),
        )
        .unwrap();
        assert_eq!(
            out,
            json!({
                "api_keys": [{"id":"b","provider":"B2"},{"id":"c","provider":"C"}],
                "user_categories": ["y","z"],
                "projects": [{"id":"q","name":"Q"}]
            })
        );
        // An empty patch changes nothing.
        assert_eq!(apply_row_patch(doc.clone(), &json!({})).unwrap(), doc);
        for bad in [
            json!({"put": [{"provider":"no id"}]}),
            json!({"delete": [1]}),
            json!({"projects_put": [{"name":"no id"}]}),
            json!({"categories": [1]}),
        ] {
            assert!(apply_row_patch(doc.clone(), &bad).is_err(), "{bad}");
        }
    }

    use super::*;
    use serde_json::json;

    /// Unique scratch path per test; SQLCipher needs a real file, not `:memory:`.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("unenverse-test-{tag}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open_scratch(tag: &str) -> (Connection, std::path::PathBuf) {
        let dir = scratch(tag);
        let key = derive_key("correct horse battery staple", b"0123456789abcdef").unwrap();
        let conn = open_db(&dir.join("vault.db"), &key).unwrap();
        init_schema(&conn).unwrap();
        (conn, dir)
    }

    // ── version_history (Phase 23, E8) ─────────────────────────────────────────

    fn history_of(conn: &Connection) -> Vec<serde_json::Value> {
        let raw = load_vault(conn).unwrap().unwrap_or(json!({}));
        raw["api_keys"][0]["version_history"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    /// Every secret-carrying value is versioned, not just `api_key`.
    ///
    /// Before Phase 23 a refresh-token swap, a replaced client secret and every
    /// `extra_vars` edit left no history at all — and for an `env_var` entry,
    /// whose entire payload lives in named variables, *nothing* was versioned.
    /// E8 calls leaving a secret silently unversioned the one unacceptable
    /// option.
    #[test]
    fn every_secret_carrying_value_is_versioned() {
        let (conn, _d) = open_scratch("historyfields");
        let base = json!({ "api_keys": [{
            "id": "e1", "provider": "Aws",
            "api_key": "key-v1", "api_secret": "secret-v1",
            "extra_vars": [
                { "key": "SESSION_TOKEN", "value": "tok-v1" },
                { "key": "REGION", "value": "eu-west-1", "public": true },
            ],
        }]});
        save_vault(&conn, base.clone(), SaveCtx::default()).unwrap();
        assert!(history_of(&conn).is_empty(), "nothing changed yet");

        let mut next = base.clone();
        next["api_keys"][0]["api_key"] = json!("key-v2");
        next["api_keys"][0]["api_secret"] = json!("secret-v2");
        next["api_keys"][0]["extra_vars"][0]["value"] = json!("tok-v2");
        next["api_keys"][0]["extra_vars"][1]["value"] = json!("us-east-1");
        save_vault(&conn, next.clone(), SaveCtx::default()).unwrap();

        let hist = history_of(&conn);
        let found: Vec<(String, String)> = hist
            .iter()
            .map(|h| {
                (
                    h.get("field")
                        .and_then(|v| v.as_str())
                        .unwrap_or("api_key")
                        .to_string(),
                    h["value"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect();

        assert!(
            found.contains(&("api_key".into(), "key-v1".into())),
            "api_key still writes no discriminator — every pre-Phase-22 vault relies on that: {found:?}"
        );
        assert!(
            found.contains(&("api_secret".into(), "secret-v1".into())),
            "a replaced client secret is as unrecoverable as a replaced key: {found:?}"
        );
        assert!(
            found.contains(&("extra_vars/SESSION_TOKEN".into(), "tok-v1".into())),
            "a named variable is where an env_var entry's whole payload lives: {found:?}"
        );
        assert!(
            !found.iter().any(|(f, _)| f == "extra_vars/REGION"),
            "a var marked public is a region by declaration; filling a 50-record \
             history with them evicts the values that cannot be recovered: {found:?}"
        );
    }

    /// A deleted variable leaves its last value behind.
    ///
    /// Deleting a row makes its value exactly as unrecoverable as overwriting
    /// one, and the row's absence is not evidence that the user meant to lose it.
    #[test]
    fn deleting_a_variable_still_versions_it() {
        let (conn, _d) = open_scratch("historydelete");
        let base = json!({ "api_keys": [{
            "id": "e1", "provider": "Aws", "api_key": "k",
            "extra_vars": [{ "key": "SESSION_TOKEN", "value": "tok-v1" }],
        }]});
        save_vault(&conn, base.clone(), SaveCtx::default()).unwrap();

        let mut next = base.clone();
        next["api_keys"][0]["extra_vars"] = json!([]);
        save_vault(&conn, next, SaveCtx::default()).unwrap();

        let hist = history_of(&conn);
        assert_eq!(hist.len(), 1, "{hist:?}");
        assert_eq!(hist[0]["field"], json!("extra_vars/SESSION_TOKEN"));
        assert_eq!(hist[0]["value"], json!("tok-v1"));
    }

    /// Variables are matched by **name**, never by position.
    ///
    /// `extra_vars` is an array the form rebuilds on every save, so an index
    /// captured across an edit points at whatever took its place — invariant 1,
    /// in the one place where getting it wrong writes the wrong secret into
    /// history.
    #[test]
    fn variables_are_matched_by_name_not_position() {
        let (conn, _d) = open_scratch("historyreorder");
        let base = json!({ "api_keys": [{
            "id": "e1", "provider": "Aws", "api_key": "k",
            "extra_vars": [
                { "key": "A", "value": "a1" },
                { "key": "B", "value": "b1" },
            ],
        }]});
        save_vault(&conn, base, SaveCtx::default()).unwrap();

        // Reordered, and only B changed.
        let next = json!({ "api_keys": [{
            "id": "e1", "provider": "Aws", "api_key": "k",
            "extra_vars": [
                { "key": "B", "value": "b2" },
                { "key": "A", "value": "a1" },
            ],
        }]});
        save_vault(&conn, next, SaveCtx::default()).unwrap();

        let hist = history_of(&conn);
        assert_eq!(hist.len(), 1, "only B changed: {hist:?}");
        assert_eq!(hist[0]["field"], json!("extra_vars/B"));
        assert_eq!(hist[0]["value"], json!("b1"));
    }

    // ── Schema version ─────────────────────────────────────────────────────────

    #[test]
    fn saving_stamps_the_schema_version() {
        let (conn, _d) = open_scratch("schemastamp");
        assert_eq!(
            vault_schema_version(&conn).unwrap(),
            None,
            "a fresh database carries no stamp until something is written"
        );
        save_vault(
            &conn,
            serde_json::json!({ "api_keys": [] }),
            SaveCtx::default(),
        )
        .unwrap();
        assert_eq!(
            vault_schema_version(&conn).unwrap(),
            Some(VAULT_SCHEMA_VERSION)
        );
    }

    #[test]
    fn an_unstamped_vault_still_opens() {
        // Every vault written before this constant existed has no stamp. Treating
        // "absent" as a failure would refuse to open every vault in the field.
        let (conn, _d) = open_scratch("schemalegacy");
        save_vault(
            &conn,
            serde_json::json!({ "api_keys": [] }),
            SaveCtx::default(),
        )
        .unwrap();
        conn.execute("DELETE FROM vault_meta WHERE key = 'schema_version'", [])
            .unwrap();
        assert!(load_vault(&conn).unwrap().is_some());
    }

    #[test]
    fn a_future_schema_is_refused_for_both_read_and_write() {
        // Refuse-with-a-message beats corrupt-on-round-trip. An old binary that
        // reads a newer document, drops the fields it does not know and saves it
        // back has silently destroyed data — the exact failure mode this project
        // hunts everywhere else.
        let (conn, _d) = open_scratch("schemafuture");
        save_vault(
            &conn,
            serde_json::json!({ "api_keys": [], "projects": [] }),
            SaveCtx::default(),
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?1)",
            rusqlite::params![(VAULT_SCHEMA_VERSION + 1).to_string()],
        )
        .unwrap();

        let read = load_vault(&conn).unwrap_err();
        assert!(read.starts_with(SCHEMA_ERR), "load said: {read}");
        let write = save_vault(
            &conn,
            serde_json::json!({ "api_keys": [] }),
            SaveCtx::default(),
        )
        .unwrap_err();
        assert!(write.starts_with(SCHEMA_ERR), "save said: {write}");

        // And the refusal must not have been a partial write.
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', '1')",
            [],
        )
        .unwrap();
        let v = load_vault(&conn).unwrap().unwrap();
        assert!(
            v.get("projects").is_some(),
            "the refused save wrote nothing"
        );
    }

    #[test]
    fn an_unparseable_stamp_is_treated_as_unknown_not_as_absent() {
        let (conn, _d) = open_scratch("schemajunk");
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', 'tomorrow')",
            [],
        )
        .unwrap();
        let e = load_vault(&conn).unwrap_err();
        assert!(e.starts_with(SCHEMA_ERR), "said: {e}");
    }

    // ── KDF ────────────────────────────────────────────────────────────────────

    #[test]
    fn derive_key_is_deterministic_and_salt_sensitive() {
        let a = derive_key("hunter2", b"0123456789abcdef").unwrap();
        let b = derive_key("hunter2", b"0123456789abcdef").unwrap();
        let c = derive_key("hunter2", b"fedcba9876543210").unwrap();
        let d = derive_key("hunter3", b"0123456789abcdef").unwrap();
        assert_eq!(a, b, "same password + salt must derive the same key");
        assert_ne!(a, c, "different salt must derive a different key");
        assert_ne!(a, d, "different password must derive a different key");
    }

    #[test]
    fn salt_is_persisted_and_reused() {
        let dir = scratch("salt");
        let path = dir.join("vault.salt");
        let first = read_or_create_salt(&path).unwrap();
        let second = read_or_create_salt(&path).unwrap();
        assert_eq!(first, second, "salt must be stable across reads");
        assert_eq!(first.len(), SALT_LEN);
    }

    // ── Entry identity ─────────────────────────────────────────────────────────

    #[test]
    fn entry_ck_prefers_stable_id() {
        let a = json!({ "id": "abc", "provider": "GitHub", "account_name": "x" });
        let b = json!({ "id": "abc", "provider": "Renamed", "account_name": "y" });
        assert_eq!(entry_ck(&a), entry_ck(&b), "id must dominate other fields");
    }

    #[test]
    fn entry_ck_legacy_distinguishes_key_id() {
        // The historic save_vault key ignored key_id and collapsed these two into
        // one entry, misattributing version_history between them.
        let a = json!({ "provider": "AWS", "account_name": "prod", "key_id": "one" });
        let b = json!({ "provider": "AWS", "account_name": "prod", "key_id": "two" });
        assert_ne!(entry_ck(&a), entry_ck(&b));
    }

    #[test]
    fn entry_ck_ignores_empty_id() {
        let with_empty = json!({ "id": "", "provider": "P" });
        let without = json!({ "provider": "P" });
        assert_eq!(entry_ck(&with_empty), entry_ck(&without));
    }

    // ── Vault I/O ──────────────────────────────────────────────────────────────

    #[test]
    fn save_then_load_roundtrips() {
        let (conn, _dir) = open_scratch("roundtrip");
        let data = json!({
            "api_keys": [{ "id": "1", "provider": "GitHub", "api_key": "ghp_aaa" }],
            "user_categories": ["dev"],
            "projects": [{ "id": "Universal", "name": "Universal" }],
        });
        save_vault(&conn, data.clone(), SaveCtx::default()).unwrap();
        let loaded = load_vault(&conn).unwrap().expect("vault should exist");
        assert_eq!(loaded["api_keys"][0]["provider"], "GitHub");
        assert_eq!(loaded["user_categories"][0], "dev");
    }

    #[test]
    fn load_returns_none_for_fresh_vault() {
        let (conn, _dir) = open_scratch("fresh");
        assert!(load_vault(&conn).unwrap().is_none());
    }

    #[test]
    fn changing_a_key_records_previous_value_in_history() {
        let (conn, _dir) = open_scratch("history");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "GitHub", "api_key": "old_value" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "GitHub", "api_key": "new_value" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();

        let loaded = load_vault(&conn).unwrap().unwrap();
        let history = loaded["api_keys"][0]["version_history"].as_array().unwrap();
        assert_eq!(
            history.len(),
            1,
            "one rotation should append one history entry"
        );
        assert_eq!(history[0]["value"], "old_value");
    }

    #[test]
    fn a_replaced_totp_seed_is_versioned_and_labelled() {
        // A re-enrolled authenticator seed is as unrecoverable as a replaced API
        // key. Before Phase 22 only `api_key` was snapshot, so swapping a seed
        // left no record at all — and the user would find out at a login screen.
        let (conn, _dir) = open_scratch("totp-history");
        save_vault(
            &conn,
            json!({
                "api_keys": [{
                    "id": "1", "provider": "GitHub",
                    "api_key": "k1", "totp_secret": "JBSWY3DPEHPK3PXP",
                }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [{
                    "id": "1", "provider": "GitHub",
                    "api_key": "k1", "totp_secret": "MZXW6YTBOI======",
                }]
            }),
            SaveCtx::default(),
        )
        .unwrap();

        let loaded = load_vault(&conn).unwrap().unwrap();
        let history = loaded["api_keys"][0]["version_history"].as_array().unwrap();
        assert_eq!(history.len(), 1, "the seed change is one revision");
        assert_eq!(history[0]["value"], "JBSWY3DPEHPK3PXP");
        // The discriminator is what tells a restore which field it is restoring.
        assert_eq!(history[0]["field"], "totp_secret");
    }

    #[test]
    fn an_api_key_revision_still_carries_no_field_discriminator() {
        // Absent `field` means `api_key`, and every vault written before Phase 22
        // relies on that. Stamping it now would make an older build's history
        // viewer show a field name it has never heard of.
        let (conn, _dir) = open_scratch("legacy-history-shape");
        save_vault(
            &conn,
            json!({ "api_keys": [{ "id": "1", "provider": "GitHub", "api_key": "v1" }] }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(
            &conn,
            json!({ "api_keys": [{ "id": "1", "provider": "GitHub", "api_key": "v2" }] }),
            SaveCtx::default(),
        )
        .unwrap();

        let loaded = load_vault(&conn).unwrap().unwrap();
        let history = loaded["api_keys"][0]["version_history"].as_array().unwrap();
        assert!(history[0].get("field").is_none(), "{:?}", history[0]);
    }

    #[test]
    fn history_follows_the_id_not_the_provider_name() {
        // Renaming an entry must not look like "delete + create", which would
        // lose its history. This is exactly what the old provider|account key broke.
        let (conn, _dir) = open_scratch("rename");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "OldName", "api_key": "v1" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "NewName", "api_key": "v2" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();

        let loaded = load_vault(&conn).unwrap().unwrap();
        let history = loaded["api_keys"][0]["version_history"].as_array().unwrap();
        assert_eq!(history[0]["value"], "v1", "history must survive a rename");
    }

    #[test]
    fn integrity_hash_matches_after_save() {
        let (conn, _dir) = open_scratch("integrity");
        save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        assert!(verify_vault_integrity(&conn).unwrap());
    }

    #[test]
    fn integrity_check_detects_tampering() {
        let (conn, _dir) = open_scratch("tamper");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "P", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        // Rewrite the row behind save_vault's back, leaving the stored hash stale.
        conn.execute(
            "UPDATE vault_rows SET data = ?1 WHERE kind = 'entry'",
            rusqlite::params![r#"{"id":"1","provider":"EVIL","api_key":"k"}"#],
        )
        .unwrap();
        assert!(
            !verify_vault_integrity(&conn).unwrap(),
            "tampered data must fail the hash check"
        );
    }

    #[test]
    fn empty_vault_is_trivially_intact() {
        let (conn, _dir) = open_scratch("empty-integrity");
        assert!(verify_vault_integrity(&conn).unwrap());
    }

    // ── Optimistic concurrency ────────────────────────────────────────────────

    #[test]
    fn version_changes_with_every_write() {
        let (conn, _dir) = open_scratch("version");
        assert!(
            vault_version(&conn).unwrap().is_none(),
            "empty vault has no version"
        );
        let v1 = save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        let v2 = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        assert_ne!(v1, v2);
        assert_eq!(vault_version(&conn).unwrap().as_deref(), Some(v2.as_str()));
    }

    #[test]
    fn returned_version_is_the_stored_version() {
        // The value save_vault hands back must be exactly what a later
        // compare-and-swap will be checked against, or every write would conflict.
        let (conn, _dir) = open_scratch("version-match");
        let v = save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        assert_eq!(vault_version(&conn).unwrap().unwrap(), v);
    }

    #[test]
    fn writing_at_the_expected_version_succeeds() {
        let (conn, _dir) = open_scratch("cas-ok");
        let v1 = save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        let res = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx {
                actor: None,
                expect_version: Some(&v1),
            },
        );
        assert!(res.is_ok());
    }

    #[test]
    fn writing_at_a_stale_version_is_refused() {
        // The lost-update scenario: two writers read v1, one saves, the other
        // must not be allowed to overwrite it.
        let (conn, _dir) = open_scratch("cas-stale");
        let v1 = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "original", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();

        // Writer A lands first.
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "written-by-A", "api_key": "k" }]
            }),
            SaveCtx {
                actor: None,
                expect_version: Some(&v1),
            },
        )
        .unwrap();

        // Writer B still holds v1.
        let err = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "written-by-B", "api_key": "k" }]
            }),
            SaveCtx {
                actor: None,
                expect_version: Some(&v1),
            },
        )
        .expect_err("a stale write must be refused");
        assert!(
            err.starts_with(CONFLICT_ERR),
            "callers match on this prefix, got: {err}"
        );

        // A's data survived intact.
        let stored = load_vault(&conn).unwrap().unwrap();
        assert_eq!(stored["api_keys"][0]["provider"], "written-by-A");
    }

    #[test]
    fn a_refused_write_leaves_no_trace() {
        // The audit appends used to run before the transaction, so a rejected
        // write still logged changes that never happened.
        let (conn, _dir) = open_scratch("cas-clean");
        let v1 = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        // Another writer edits the same entry.
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A-theirs", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();

        let audit_before = load_audit(&conn).unwrap().len();
        let version_before = vault_version(&conn).unwrap();

        let err = save_vault(
            &conn,
            json!({
                "api_keys": [
                    { "id": "1", "provider": "A-mine", "api_key": "k" },
                    { "id": "9", "provider": "GHOST", "api_key": "k" }
                ]
            }),
            SaveCtx {
                actor: None,
                expect_version: Some(&v1),
            },
        )
        .expect_err("both sides edited entry 1");
        assert!(err.starts_with(CONFLICT_ERR), "{err}");
        assert!(
            err.contains("A-mine"),
            "the conflict names the entry: {err}"
        );

        assert_eq!(
            load_audit(&conn).unwrap().len(),
            audit_before,
            "a refused write must not append audit rows"
        );
        assert_eq!(vault_version(&conn).unwrap(), version_before);
        assert!(!load_audit(&conn)
            .unwrap()
            .iter()
            .any(|r| r.entry_provider.as_deref() == Some("GHOST")));
        let stored = load_vault(&conn).unwrap().unwrap();
        assert_eq!(stored["api_keys"].as_array().unwrap().len(), 1);
        assert_eq!(stored["api_keys"][0]["provider"], "A-theirs");
    }

    #[test]
    fn expecting_a_version_against_an_empty_vault_is_refused() {
        let (conn, _dir) = open_scratch("cas-empty");
        let err = save_vault(
            &conn,
            json!({ "api_keys": [] }),
            SaveCtx {
                actor: None,
                expect_version: Some("deadbeef"),
            },
        )
        .expect_err("nothing is stored, so no version can match");
        assert!(err.starts_with(CONFLICT_ERR));
    }

    #[test]
    fn omitting_the_version_writes_unconditionally() {
        // The explicit escape hatch, used when the user chooses to overwrite.
        let (conn, _dir) = open_scratch("cas-force");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "first", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "forced", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        let stored = load_vault(&conn).unwrap().unwrap();
        assert_eq!(stored["api_keys"][0]["provider"], "forced");
    }

    #[test]
    fn integrity_still_holds_after_a_refused_write() {
        let (conn, _dir) = open_scratch("cas-integrity");
        let v1 = save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        let _ = save_vault(
            &conn,
            json!({ "api_keys": [] }),
            SaveCtx {
                actor: None,
                expect_version: Some(&v1),
            },
        );
        assert!(
            verify_vault_integrity(&conn).unwrap(),
            "a rolled-back write must not desync data from its hash"
        );
    }

    // ── Audit chain ────────────────────────────────────────────────────────────

    #[test]
    fn audit_rows_form_a_hash_chain() {
        let (conn, _dir) = open_scratch("audit");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [
                    { "id": "1", "provider": "A", "api_key": "k" },
                    { "id": "2", "provider": "B", "api_key": "k2" }
                ]
            }),
            SaveCtx::default(),
        )
        .unwrap();

        let mut rows = load_audit(&conn).unwrap();
        assert!(rows.len() >= 2, "expected an audit row per added entry");
        rows.sort_by_key(|r| r.id); // load_audit returns newest-first
        assert!(rows[0].entry_hash.is_some());
        // Each row must link to its predecessor.
        for pair in rows.windows(2) {
            assert_eq!(
                pair[1].prev_hash, pair[0].entry_hash,
                "row {} must chain to row {}",
                pair[1].id, pair[0].id
            );
        }
    }

    #[test]
    fn deleting_an_entry_is_audited() {
        let (conn, _dir) = open_scratch("audit-delete");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "Doomed", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        let rows = load_audit(&conn).unwrap();
        assert!(rows
            .iter()
            .any(|r| r.action == "delete" && r.entry_provider.as_deref() == Some("Doomed")));
    }

    #[test]
    fn audit_rows_record_the_acting_user() {
        let (conn, _dir) = open_scratch("audit-actor");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx {
                actor: Some("user-123"),
                ..Default::default()
            },
        )
        .unwrap();
        let rows = load_audit(&conn).unwrap();
        let add = rows.iter().find(|r| r.action == "add").unwrap();
        assert_eq!(add.actor.as_deref(), Some("user-123"));
    }

    #[test]
    fn actor_is_bound_into_the_hash_chain() {
        // Rewriting who did something must invalidate the row hash, otherwise
        // attribution would be forgeable while the chain still "verified".
        let with = compute_audit_hash("add", "P", "T", Some("alice"), "prev");
        let other = compute_audit_hash("add", "P", "T", Some("bob"), "prev");
        let without = compute_audit_hash("add", "P", "T", None, "prev");
        assert_ne!(with, other, "different actor must give a different hash");
        assert_ne!(with, without);
    }

    #[test]
    fn actorless_rows_keep_the_v1_hash_format() {
        // Existing chains were written before the actor column; their hashes
        // must still reproduce or every old log would read as tampered.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for part in ["add", "|", "P", "|", "T", "|", "prev"] {
            h.update(part.as_bytes());
        }
        assert_eq!(
            compute_audit_hash("add", "P", "T", None, "prev"),
            hex::encode(h.finalize())
        );
    }

    // ── Expiry ─────────────────────────────────────────────────────────────────

    #[test]
    fn expiring_selects_only_the_window() {
        let now = time::OffsetDateTime::now_utc();
        let fmt = |d: i64| {
            let t = now + time::Duration::days(d);
            format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day())
        };
        let data = json!({ "api_keys": [
            { "provider": "expired",  "expires_at": fmt(-5)  },
            { "provider": "soon",     "expires_at": fmt(3)   },
            { "provider": "far",      "expires_at": fmt(365) },
            { "provider": "no-expiry" },
        ]});
        let found = expiring_from_value(&data, 30);
        let names: Vec<&str> = found
            .iter()
            .map(|e| e["provider"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["soon"],
            "already-expired, far-future and never-expiring entries are all excluded"
        );
    }
}

#[cfg(test)]
mod salt_pairing_tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("unv-salt-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// The bug: a database whose salt vanished was silently given a new one, and
    /// every unlock then reported "Wrong master password" for a correct password.
    /// By the time anyone looked, the missing file had already been replaced.
    #[test]
    fn a_database_without_its_salt_is_refused_not_re_salted() {
        let d = tmp("orphan");
        let db = d.join("vault.db");
        let salt = d.join("vault.salt");
        fs::write(&db, b"pretend this is a SQLCipher file").unwrap();

        let err = check_salt_pairing(&db, &salt).unwrap_err();
        assert!(err.contains("is missing"), "{err}");
        assert!(
            err.contains("nothing can recompute it"),
            "the message must not imply recovery is possible: {err}"
        );
        assert!(!salt.exists(), "the check must not create a salt");
        let _ = fs::remove_dir_all(&d);
    }

    /// A first run has neither file, and must be allowed to create both.
    #[test]
    fn a_fresh_directory_is_fine() {
        let d = tmp("fresh");
        assert!(check_salt_pairing(&d.join("vault.db"), &d.join("vault.salt")).is_ok());
        let _ = fs::remove_dir_all(&d);
    }

    /// An empty database file is a first run that got interrupted, not a vault.
    #[test]
    fn an_empty_database_file_is_not_treated_as_a_vault() {
        let d = tmp("empty");
        let db = d.join("vault.db");
        fs::write(&db, b"").unwrap();
        assert!(check_salt_pairing(&db, &d.join("vault.salt")).is_ok());
        let _ = fs::remove_dir_all(&d);
    }

    /// New salts are owner-only. They were 0644 until `unv doctor` said so.
    #[test]
    #[cfg(unix)]
    fn a_generated_salt_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("mode");
        let salt = d.join("vault.salt");
        read_or_create_salt(&salt).unwrap();
        let mode = fs::metadata(&salt).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "salt was created world-readable");
        let _ = fs::remove_dir_all(&d);
    }

    /// And so is a newly created database.
    #[test]
    #[cfg(unix)]
    fn a_created_database_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("dbmode");
        let db = d.join("vault.db");
        let key = derive_key(
            "correct-horse-battery",
            &read_or_create_salt(&d.join("vault.salt")).unwrap(),
        )
        .unwrap();
        let conn = open_db(&db, &key).unwrap();
        drop(conn);
        let mode = fs::metadata(&db).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "database was created world-readable");
        let _ = fs::remove_dir_all(&d);
    }
}

/// True for a value safe to write bare in a `.env`. Deliberately narrow.
fn env_bare_ok(v: &str) -> bool {
    !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | ':' | '@' | '-'))
}

/// A value as it must appear after the `=` in a `.env` (Phase 23, E1).
///
/// The empty string quotes to `""` rather than to nothing, because a bare `KEY=`
/// is how "unset" is spelled and a deliberately empty value must not read as
/// one. A newline is escaped rather than emitted, so the parser's backslash
/// line-continuation can never see one. Twin of `quoteEnvValue` in
/// `src/ts/state.ts`, pinned by `parity/env-names.json`.
pub fn env_quote(value: &str) -> String {
    if env_bare_ok(value) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' | '"' | '$' | '`' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}
