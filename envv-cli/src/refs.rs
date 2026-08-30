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
        _ => field,
    }
}

/// Resolve a named field on a vault entry (built-in fields, aliases, then extra_vars).
pub fn entry_field(entry: &Value, field: &str) -> Option<String> {
    let canonical = canonical_field(field);
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

/// Find a vault entry by exact provider, or by `Provider_keyid` compound split.
pub fn find_entry<'a>(entries: &'a [Value], prov: &str) -> Option<&'a Value> {
    if let Some(e) = entries
        .iter()
        .find(|e| e.get("provider").and_then(|v| v.as_str()) == Some(prov))
    {
        return Some(e);
    }
    if let Some(us) = prov.rfind('_') {
        let (p, k) = (&prov[..us], &prov[us + 1..]);
        return entries.iter().find(|e| {
            e.get("provider").and_then(|v| v.as_str()) == Some(p)
                && e.get("key_id").and_then(|v| v.as_str()) == Some(k)
        });
    }
    None
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
