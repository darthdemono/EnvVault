//! `${…}` reference resolution — the Rust twin of `resolveFieldRef` in
//! `src/ts/chunk-ops.ts`.
//!
//! A placeholder that reaches a wg0.conf, a compose file or a `.env` is a broken
//! deploy, so every exporter here resolves through this module rather than
//! pattern-matching `${…}` by hand. All four spellings are understood:
//! `${Provider}`, `${Provider/field}`, `${Provider_KeyId}` and
//! `${chunk:ChunkName/FieldKey}`, plus the `env_file` fallback.

use serde_json::Value;

/// Map an env-var field suffix to the canonical vault-entry JSON field name.
///
/// **This table is one half of a twin pair** — `FIELD_ALIASES` in
/// `src/ts/chunk-ops.ts` is the other — and it had already drifted: `PASSWORD`,
/// `PASS` and `PWD` were missing here, so `${PgProd/password}` resolved in the
/// desktop app and reached `.pgpass`, a rendered template, a `.env` and every
/// exporter as the literal text `${PgProd/password}` from the CLI.
///
/// Pinned from both sides by `tests/fixtures/parity/field-aliases.json`.
pub fn canonical_field(field: &str) -> &str {
    match field.to_uppercase().as_str() {
        // A password entry stores its secret in `api_key`, which is why
        // PASSWORD/PASS/PWD belong in this arm rather than in one of their own.
        "APIKEY" | "API_KEY" | "KEY" | "TOKEN" | "ACCESS_TOKEN" | "BEARER" | "SECRET_KEY"
        | "PASSWORD" | "PASS" | "PWD" => "api_key",
        "SECRET" | "API_SECRET" | "CLIENT_SECRET" | "SHARED_SECRET" => "api_secret",
        "USERNAME" | "USER" | "LOGIN" | "USER_NAME" => "username",
        "URL" | "URI" | "ENDPOINT" | "API_URL" | "BASE_URL" => "api_url",
        "EMAIL" | "MAIL" => "email",
        "KEY_ID" | "KEYID" | "KID" => "key_id",
        // The public half of an OAuth pair. It resolves to `key_id` and then,
        // through `entry_field`'s fallback, to an `extra_vars` entry keyed `ID`
        // — which is where a client id actually lives in vaults written today.
        //
        // Without this arm `ID` fell through `_ => field` and was looked up as
        // the entry's `id`: a UUID, non-empty, silently written into a rendered
        // config by the CLI while the app left `${Spotify/ID}` as literal text.
        // The deny-list below is what stops that answer; this arm is what makes
        // the reference mean something useful instead of nothing.
        "ID" | "CLIENT_ID" | "APP_ID" | "ACCOUNT_ID" | "APPLICATION_ID" => "key_id",
        // E17: a file-shaped credential is consumed by pointing at it, so the
        // useful thing to render into a config is the **path**, never the bytes.
        // `${GCP/path}` is what a rendered `.env` wants beside
        // `GOOGLE_APPLICATION_CREDENTIALS`.
        "PATH" | "MOUNT" | "MOUNT_PATH" | "FILE" => "mount_path",
        _ => field,
    }
}

/// Entry fields no `${…}` may ever resolve to.
///
/// These are the entry's *metadata*, not its values: `id` is a UUID that
/// identifies the row, and the other three are lists that would stringify into
/// something no config format wants. A reference naming one of them is a
/// mistake, and the honest answer is "unresolved" — which every exporter already
/// reports — rather than a plausible-looking wrong value.
///
/// Checked **before** the lookup, so an `extra_vars` entry keyed `id` is
/// unreachable too. That is deliberate: the point is that `${X/id}` has one
/// answer everywhere, and making it depend on whether the entry happens to carry
/// such a var reintroduces exactly the silent divergence this closes.
///
/// The TypeScript twin is `REFERENCE_DENY` in `src/ts/chunk-ops.ts`; both are
/// pinned by `tests/fixtures/parity/field-aliases.json`.
pub const REFERENCE_DENY: [&str; 4] = ["id", "version_history", "projectIds", "categories"];

/// True when a reference names entry metadata rather than a value.
fn is_denied(field: &str, canonical: &str) -> bool {
    REFERENCE_DENY.contains(&field) || REFERENCE_DENY.contains(&canonical)
}

/// Normalise a role or a reference field for comparison — `account_sid`,
/// `ACCOUNT-SID` and `Account Sid` are one name.
fn role_key(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Resolve a named field on a vault entry (roles, built-in fields, aliases, then extra_vars).
pub fn entry_field(entry: &Value, field: &str) -> Option<String> {
    let canonical = canonical_field(field);
    if is_denied(field, canonical) {
        return None;
    }

    // A **declared role wins over the alias table** (Phase 23, step 2). An entry
    // whose `primary_role` is `id` holds a client id in `api_key`, so
    // `${Spotify/ID}` must answer with that rather than with `key_id` — which is
    // what the Phase 21 alias arm resolves to when no role is declared, and what
    // it still resolves to for every entry that declares none.
    //
    // This is also what makes the shapes with no primary value work:
    // `${Twilio/ACCOUNT_SID}` and `${Twilio/AUTH_TOKEN}` name the two halves of
    // a Twilio credential by the issuer's own words.
    let want = role_key(field);
    if !want.is_empty() && want != "VALUE" {
        for (role_field, value_field) in
            [("primary_role", "api_key"), ("secret_role", "api_secret")]
        {
            let declared = entry.get(role_field).and_then(|v| v.as_str()).unwrap_or("");
            if !declared.is_empty() && role_key(declared) == want {
                if let Some(s) = entry.get(value_field).and_then(|v| v.as_str()) {
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    if let Some(s) = entry.get(canonical).and_then(|v| v.as_str()) {
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    if let Some(arr) = entry.get("extra_vars").and_then(|v| v.as_array()) {
        for xv in arr {
            let k = xv.get("key").and_then(|v| v.as_str());
            if k == Some(field) || k == Some(canonical) {
                return xv.get("value").and_then(|v| v.as_str()).map(String::from);
            }
        }
    }
    None
}

/// Find the entry a bare `${NAME}` or a `${NAME/field}` prefix addresses.
///
/// Three attempts, in this order, and **ambiguity is refused rather than
/// guessed** (Phase 23, E9):
///
/// 1. An exact provider match — what a hand-written reference means.
/// 2. A **generated-name** match, i.e. the Phase 23 template. `${SPOTIFY_V2}`
///    names the entry whose version is 2, which is the point of putting versions
///    and labels into the name at all.
/// 3. The legacy `Provider_keyid` split on the last underscore.
///
/// 2 and 3 occupy the same syntactic position, so a vault holding both a
/// `SPOTIFY` entry with `key_id: V2` *and* a `SPOTIFY` entry with `version: 2`
/// has two honest answers. Returning either would write a silent wrong value
/// into a config — the defect class Phase 21 was about — so this returns nothing
/// and every exporter reports the reference unresolved. The explicit
/// `${Provider/field}` form is never ambiguous and is what the docs recommend.
///
/// Twin: `findEntryByRef` in `src/ts/chunk-ops.ts`, pinned by the
/// `reference_lookup` section of `tests/fixtures/parity/env-names.json`.
pub fn find_entry<'a>(entries: &'a [Value], prov: &str) -> Option<&'a Value> {
    if let Some(e) = entries
        .iter()
        .find(|e| e.get("provider").and_then(|v| v.as_str()) == Some(prov))
    {
        return Some(e);
    }

    let want = prov.to_uppercase();
    let by_template: Vec<&Value> = entries
        .iter()
        .filter(|e| {
            crate::envfile::env_name(e, &Default::default()) == want
                || crate::envfile::primary_name(e, None, false) == want
        })
        .collect();
    if by_template.len() > 1 {
        return None;
    }

    let legacy = prov.rfind('_').and_then(|us| {
        let (p, k) = (&prov[..us], &prov[us + 1..]);
        entries.iter().find(|e| {
            e.get("provider").and_then(|v| v.as_str()) == Some(p)
                && e.get("key_id").and_then(|v| v.as_str()) == Some(k)
        })
    });

    if let Some(t) = by_template.first() {
        return match legacy {
            Some(l) if !std::ptr::eq(*t, l) => None,
            _ => Some(t),
        };
    }
    legacy
}

/// The vault-entry field used as the resolved value for a bare `${Provider}` ref.
///
/// Mirrors the `envCopyField` setting: the desktop app lets a vault decide that
/// `.env` copies should emit `api_secret` or `key_id` instead of `api_key`, and a
/// CLI export that ignored it would write a different value than the UI does for
/// the same reference.
pub fn env_copy_field() -> String {
    let path = dirs::config_dir().map(|d| d.join("io.envvault").join("settings.json"));
    let field = path
        .filter(|p| p.exists())
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| {
            v.get("envCopyField")
                .and_then(|f| f.as_str())
                .map(String::from)
        });
    match field.as_deref() {
        Some("api_secret") => "api_secret".into(),
        Some("key_id") => "key_id".into(),
        _ => "api_key".into(),
    }
}

/// Outcome of resolving one field value.
pub struct Resolved {
    /// Resolved text, or `None` when the reference points at nothing.
    pub value: Option<String>,
    /// True when the value *was* a `${…}` reference that could not be resolved.
    pub unresolved: bool,
}

/// Resolve a whole field value. A value that is not a `${…}` reference comes back
/// verbatim.
pub fn resolve_value(
    entries: &[Value],
    projects: &[Value],
    raw: &str,
    env_field: &str,
) -> Resolved {
    let trimmed = raw.trim();
    if !(trimmed.starts_with("${") && trimmed.ends_with('}') && trimmed.len() > 3) {
        return Resolved {
            value: Some(raw.to_string()),
            unresolved: false,
        };
    }
    let inner = &trimmed[2..trimmed.len() - 1];
    match resolve_ref(entries, projects, inner, env_field, 0) {
        Some(v) => Resolved {
            value: Some(v),
            unresolved: false,
        },
        None => Resolved {
            value: None,
            unresolved: true,
        },
    }
}

/// Resolve, falling back to the literal text when the reference is stale — what
/// every exporter wants, since a literal `${…}` at least shows what broke.
pub fn resolve_or_literal(
    entries: &[Value],
    projects: &[Value],
    raw: &str,
    env_field: &str,
) -> String {
    resolve_value(entries, projects, raw, env_field)
        .value
        .unwrap_or_else(|| raw.to_string())
}

/// Resolve a `${...}` ref inner-string against vault entries and chunks.
pub fn resolve_ref(
    entries: &[Value],
    projects: &[Value],
    inner: &str,
    env_field: &str,
    depth: u8,
) -> Option<String> {
    if let Some(body) = inner.strip_prefix("chunk:") {
        let slash = body.find('/')?;
        let (chunk_name, field_key) = (&body[..slash], &body[slash + 1..]);
        for p in projects {
            let chunks = p.get("chunks").and_then(|v| v.as_array());
            for c in chunks.into_iter().flatten() {
                if c.get("name").and_then(|v| v.as_str()) != Some(chunk_name) {
                    continue;
                }
                let fields = c.get("fields").and_then(|v| v.as_array());
                for f in fields.into_iter().flatten() {
                    if f.get("key").and_then(|v| v.as_str()) != Some(field_key) {
                        continue;
                    }
                    let raw = f.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    if depth < 4 && raw.starts_with("${") && raw.ends_with('}') && raw.len() > 3 {
                        return resolve_ref(
                            entries,
                            projects,
                            &raw[2..raw.len() - 1],
                            env_field,
                            depth + 1,
                        );
                    }
                    return Some(raw.to_string());
                }
            }
        }
        return None;
    }

    if let Some(slash) = inner.find('/') {
        let (prov, field) = (&inner[..slash], &inner[slash + 1..]);
        return entry_field(find_entry(entries, prov)?, field);
    }

    if let Some(entry) = find_entry(entries, inner) {
        // Honour envCopyField, falling back to api_key when the chosen field is
        // empty — the UI does the same, and an empty value in a .env is worse
        // than the "wrong" field.
        let chosen = entry
            .get(env_field)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        return chosen
            .map(String::from)
            .or_else(|| {
                entry
                    .get("api_key")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .filter(|s| !s.is_empty());
    }

    // env_file chunks are the last fallback: a bare ${NAME} may name a key in a
    // project's .env chunk rather than a vault entry.
    for p in projects {
        for c in p
            .get("chunks")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            if c.get("chunk_type").and_then(|v| v.as_str()) != Some("env_file") {
                continue;
            }
            for f in c
                .get("fields")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
            {
                if f.get("key").and_then(|v| v.as_str()) == Some(inner) {
                    return f.get("value").and_then(|v| v.as_str()).map(String::from);
                }
            }
        }
    }
    None
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/// Everything needed to turn a stored field value into deployable text.
///
/// Carries the redaction decision with it, so an exporter cannot accidentally
/// print a resolved secret: the only way to get a real value out is to build a
/// resolver that says so, which happens exactly where a value is being written
/// to a file or handed to a child process.
pub struct Resolver {
    pub entries: Vec<Value>,
    pub projects: Vec<Value>,
    pub env_field: String,
    /// When true, a value pulled out of the vault is replaced by its fingerprint.
    pub redact: bool,
}

impl Resolver {
    /// A resolver honouring the current `--reveal` setting. Use for anything
    /// that may reach stdout.
    pub fn for_output(vault: &Value) -> Self {
        Self::new(vault, !crate::out::revealing())
    }

    /// A resolver that always produces real values. Use only where the output
    /// goes to a file or into a process environment, never to stdout.
    pub fn materialising(vault: &Value) -> Self {
        Self::new(vault, false)
    }

    fn new(vault: &Value, redact: bool) -> Self {
        Self {
            entries: vault
                .get("api_keys")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default(),
            projects: vault
                .get("projects")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default(),
            env_field: env_copy_field(),
            redact,
        }
    }

    /// Explicit construction, for tests and for callers holding the pieces already.
    pub fn from_parts(
        entries: Vec<Value>,
        projects: Vec<Value>,
        env_field: &str,
        redact: bool,
    ) -> Self {
        Self {
            entries,
            projects,
            env_field: env_field.to_string(),
            redact,
        }
    }

    pub fn resolve(&self, raw: &str) -> Resolved {
        resolve_value(&self.entries, &self.projects, raw, &self.env_field)
    }

    /// Resolve for output. A `${…}` that resolved is masked under redaction; a
    /// literal that was never a reference is config text and stays readable.
    pub fn or_literal(&self, raw: &str) -> String {
        let was_ref = is_ref(raw);
        let r = self.resolve(raw);
        match r.value {
            Some(v) => {
                if self.redact && was_ref {
                    crate::out::masked(&v)
                } else {
                    v
                }
            }
            None => raw.to_string(),
        }
    }

    /// Like [`Resolver::or_literal`], but the caller knows the field is secret
    /// (a `secret` flag, or a `.env` line) so a literal value is masked too.
    pub fn or_literal_secret(&self, raw: &str, field_is_secret: bool) -> String {
        let was_ref = is_ref(raw);
        let r = self.resolve(raw);
        match r.value {
            Some(v) => {
                if self.redact && (was_ref || field_is_secret) {
                    crate::out::masked(&v)
                } else {
                    v
                }
            }
            None => raw.to_string(),
        }
    }
}

/// True when a field value is a `${…}` reference rather than literal text.
pub fn is_ref(raw: &str) -> bool {
    let t = raw.trim();
    t.starts_with("${") && t.ends_with('}') && t.len() > 3
}
