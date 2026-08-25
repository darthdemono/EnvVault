//! Output: one JSON envelope, one redaction rule, one place that decides.
//!
//! The design goal is that an agent (Claude, a Python wrapper, a CI job) can run
//! any command without a secret value ever entering its context. Two mechanisms
//! do that work:
//!
//! - **Redaction is the default.** Every path that would print a stored value to
//!   stdout prints a *fingerprint* instead: `sha256:` plus twelve hex characters.
//!   That is enough to tell "did this change?" and "do these two entries hold the
//!   same secret?" apart, and useless for authenticating anywhere.
//! - **Materialisation never passes through stdout.** `--out`, `envv exec` and
//!   `envv render --out` move real values from the vault into a file or a child
//!   process's environment. The orchestrator arranges the move; it never sees
//!   what moved.
//!
//! `--reveal` opts back in, for a human at a terminal.

use crate::error::CliError;
use serde_json::{json, Value};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy)]
pub struct Mode {
    pub json: bool,
    pub reveal: bool,
    pub dry_run: bool,
}

static MODE: OnceLock<Mode> = OnceLock::new();

pub fn init(mode: Mode) {
    let _ = MODE.set(mode);
}

pub fn mode() -> Mode {
    *MODE.get().unwrap_or(&Mode {
        json: false,
        reveal: false,
        dry_run: false,
    })
}

pub fn is_json() -> bool {
    mode().json
}

pub fn revealing() -> bool {
    mode().reveal
}

pub fn dry_run() -> bool {
    mode().dry_run
}

// ── Fingerprints ──────────────────────────────────────────────────────────────

/// Full lower-case hex SHA-256 of arbitrary bytes.
///
/// Distinct from [`fingerprint`], which truncates to 12 characters for display.
/// A manifest checksum must be the whole hash: it exists to prove two files
/// belong together, and 48 bits is not a proof.
pub fn raw_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// `sha256:` + the first 12 hex characters of the SHA-256 of `value`.
///
/// Twelve characters is 48 bits — enough that two different secrets colliding is
/// not a practical concern for comparison, and far too little to attack the
/// value from. An empty string gets its own marker rather than a hash, so
/// "unset" and "set to something" never look alike.
pub fn fingerprint(value: &str) -> String {
    if value.is_empty() {
        return "empty".into();
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    let digest = h.finalize();
    let hex: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// What a redacted value looks like in text output.
pub fn masked(value: &str) -> String {
    fingerprint(value)
}

/// What a redacted value looks like in JSON output: an object, never a string,
/// so a caller cannot mistake a fingerprint for the secret itself.
pub fn masked_json(value: &str) -> Value {
    json!({
        "redacted": true,
        "fingerprint": fingerprint(value),
        "length": value.chars().count(),
    })
}

// ── Entry / chunk redaction ───────────────────────────────────────────────────

/// Fields of a vault entry that hold secret material.
///
/// `blob_ref` and `api_url` are deliberately absent: a path and a URL are
/// locating information, and blanking them would make the redacted view useless
/// for deciding *which* entry you are looking at.
const SECRET_FIELDS: [&str; 4] = ["api_key", "api_secret", "certificate_data", "cert_key_data"];

/// Redact a single vault entry for JSON output. Returns it unchanged when
/// `--reveal` is in force.
pub fn redact_entry(entry: &Value) -> Value {
    if revealing() {
        return entry.clone();
    }
    let mut e = entry.clone();
    for f in SECRET_FIELDS {
        if let Some(v) = e.get(f).and_then(|v| v.as_str()) {
            let masked = masked_json(v);
            e[f] = masked;
        }
    }
    // An embedded icon is not a secret, but it is 20–90 KB of base64 that would
    // otherwise dominate every listing an agent reads. Collapse it to a
    // description; `--reveal` still returns the data URI intact.
    if let Some(icon) = e.get("custom_icon").and_then(|v| v.as_str()) {
        if icon.starts_with("data:image/") {
            let mime = icon
                .split(';')
                .next()
                .and_then(|h| h.strip_prefix("data:"))
                .unwrap_or("image")
                .to_string();
            e["custom_icon"] = json!({
                "embedded": true,
                "mime": mime,
                "bytes": icon.len(),
                "fingerprint": fingerprint(icon),
            });
        }
    }

    // extra_vars carry their own secret flag.
    if let Some(arr) = e.get_mut("extra_vars").and_then(|v| v.as_array_mut()) {
        for xv in arr.iter_mut() {
            let is_secret = xv.get("secret").and_then(|s| s.as_bool()).unwrap_or(false);
            if is_secret {
                if let Some(v) = xv.get("value").and_then(|v| v.as_str()) {
                    let masked = masked_json(v);
                    xv["value"] = masked;
                }
            }
        }
    }
    // version_history is a list of previous secrets — every one of them counts.
    if let Some(arr) = e.get_mut("version_history").and_then(|v| v.as_array_mut()) {
        for h in arr.iter_mut() {
            if let Some(v) = h.get("value").and_then(|v| v.as_str()) {
                let masked = masked_json(v);
                h["value"] = masked;
            }
        }
    }
    e
}

pub fn redact_entries(entries: &[Value]) -> Vec<Value> {
    entries.iter().map(redact_entry).collect()
}

/// True when a chunk field holds secret material.
pub fn chunk_field_is_secret(field: &Value) -> bool {
    field
        .get("secret")
        .and_then(|s| s.as_bool())
        .unwrap_or(false)
        || field.get("field_type").and_then(|t| t.as_str()) == Some("secret")
}

/// Redact a project (and its chunks) for JSON output.
pub fn redact_project(project: &Value) -> Value {
    if revealing() {
        return project.clone();
    }
    let mut p = project.clone();
    if let Some(chunks) = p.get_mut("chunks").and_then(|c| c.as_array_mut()) {
        for c in chunks.iter_mut() {
            let is_env_file = c.get("chunk_type").and_then(|t| t.as_str()) == Some("env_file");
            let Some(fields) = c.get_mut("fields").and_then(|f| f.as_array_mut()) else {
                continue;
            };
            for f in fields.iter_mut() {
                // Every value in an env_file is destined for a `.env`, so treat
                // the whole chunk as secret rather than trusting per-field flags
                // that an import may never have set.
                if !(is_env_file || chunk_field_is_secret(f)) {
                    continue;
                }
                let raw = f
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                // A `${ref}` is a pointer, not a secret. Leaving it visible is
                // what lets an agent wire configs together without ever holding
                // the value the pointer resolves to.
                if raw.starts_with("${") && raw.ends_with('}') {
                    continue;
                }
                let masked = masked_json(&raw);
                f["value"] = masked;
            }
        }
    }
    p
}

// ── Envelope ──────────────────────────────────────────────────────────────────

/// Print a success envelope in JSON mode, or run `text` for humans.
///
/// Every command funnels through here so the JSON shape is identical everywhere:
/// `{"ok": true, "command": "...", "data": ...}`.
pub fn ok(command: &str, data: Value, text: impl FnOnce()) {
    if is_json() {
        let mut env = json!({ "ok": true, "command": command, "data": data });
        if dry_run() {
            env["dry_run"] = json!(true);
        }
        println!("{}", serde_json::to_string_pretty(&env).unwrap_or_default());
    } else {
        text();
    }
}

/// Print an informational line that is not the command's result.
///
/// Goes to stderr in JSON mode so it cannot corrupt the document a caller is
/// parsing from stdout.
pub fn note(msg: &str) {
    if is_json() {
        eprintln!("{msg}");
    } else {
        println!("{msg}");
    }
}

/// Refuse to print secret material to stdout, and say what to do instead.
pub fn refuse_reveal(what: &str) -> CliError {
    CliError::redacted(format!(
        "{what} would contain secret values. Write it with --out <file>, or pass --reveal to print it."
    ))
}
