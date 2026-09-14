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
///
/// `totp_secret` **is** here. It is a stored authenticator seed — it grants a
/// login on its own, forever, and unlike an API key nothing about it expires.
/// The six-digit code derived from it is a different thing and prints freely;
/// see `envv-cli/src/totp_cmd.rs` for why that exemption is written down.
/// Public because every path that can print one of these has to apply the same
/// rule. `entries::cmd_get --field` and `pool::cmd_next --field` each carried
/// their own copy of this list, and the copy is what went stale: `totp_secret`
/// was added here and nowhere else, so `envv get X --field totp_secret` printed
/// an authenticator seed in clear while `envv get X` masked the same value.
pub const SECRET_FIELDS: [&str; 5] = [
    "api_key",
    "api_secret",
    "certificate_data",
    "cert_key_data",
    "totp_secret",
];

/// Entry fields a build knows to be free of secret material.
///
/// **This list is what makes redaction fail closed.** Masking used to be an
/// allow-list of fields to hide, so any field the running binary did not know
/// about was printed verbatim — and a binary reading a vault written by a newer
/// build is the ordinary case, not an edge one. A 0.20.0 `envv list --json`
/// against a vault holding a Phase 22 seed printed `api_key` as a fingerprint
/// and `totp_secret` in clear, because the field did not exist when that binary
/// was compiled.
///
/// So the question is inverted: a field is printed because it is *known* to be
/// safe, and anything else is masked. The cost is that an old binary masks a new
/// *non-secret* field too — visible, recoverable with `--reveal`, and the right
/// direction for the failure to go.
///
/// `key_id` is here deliberately: it is identity, it is what `provider:key_id`
/// disambiguates with, and masking it would break the wiring an agent composes
/// configs from. `custom_icon` is here because it is collapsed separately below.
const PUBLIC_FIELDS: [&str; 39] = [
    "id",
    "provider",
    "account_name",
    "key_id",
    "api_description",
    "description",
    "price_type",
    "environment",
    "categories",
    "api_url",
    "callback_url",
    "expires_at",
    "scopes",
    "rate_limit",
    "rate_limit_count",
    "rate_limit_period",
    "rate_limit_note",
    "purpose",
    "pool",
    "version",
    "custom_icon",
    "details",
    "version_history",
    "projectIds",
    "secretType",
    "username",
    "email",
    "cert_issuer",
    "blob_ref",
    "env_var_subtype",
    "created_at",
    "last_rotated_at",
    "rotation_days",
    "compromised",
    "tags",
    "pinned",
    "extra_vars",
    "env_prefixes",
    // Phase 22/22.2 parameters. Numbers and an enum, not secret material — the
    // seed beside them is in `SECRET_FIELDS`.
    "totp_algorithm",
];

/// Fields carrying a TOTP seed's non-secret parameters, listed separately only
/// because [`PUBLIC_FIELDS`] is a fixed-size array and these arrived later.
const PUBLIC_FIELDS_EXTRA: [&str; 4] = ["totp_digits", "totp_period", "totp_kind", "totp_counter"];

/// Phase 23 fields. Names, roles and flags — none of them hold secret material.
///
/// `primary_public` and `secret_public` are the E5 opt-out flags themselves, and
/// they are booleans, so the unknown-string sweep would never have touched them;
/// they are listed for the reader rather than for the code.
const PUBLIC_FIELDS_P23: [&str; 10] = [
    "primary_role",
    "secret_role",
    "label",
    "primary_public",
    "secret_public",
    "last_copied_name",
    // How a credential is sent is not the credential (E16). A scheme and a
    // header name are in the issuer's public documentation, and hiding them
    // would make the redacted view useless for the one question it is good at —
    // "what is this and how would I use it" — while protecting nothing.
    "auth_scheme",
    "auth_param",
    // A timestamp, and the whole point of E13's check is that a listing can say
    // which sessions nobody has confirmed lately.
    "last_verified_at",
    "mount_path",
];

// `user_agent` is deliberately **not** in that list. It is a browser
// fingerprint: it identifies the machine and build a session was minted in, and
// a listing full of them says which of the user's machines holds which account.
// It is masked like a secret even though it is not one — see the cookie branch
// of `redact_entry`.

/// True when a field is known not to hold secret material.
fn is_public_field(name: &str) -> bool {
    PUBLIC_FIELDS.contains(&name)
        || PUBLIC_FIELDS_EXTRA.contains(&name)
        || PUBLIC_FIELDS_P23.contains(&name)
}

/// Redact a single vault entry for JSON output. Returns it unchanged when
/// `--reveal` is in force.
pub fn redact_entry(entry: &Value) -> Value {
    if revealing() {
        return entry.clone();
    }
    let mut e = entry.clone();
    let is_cookie = entry.get("secretType").and_then(|v| v.as_str()) == Some("cookie");
    // The two fixed value slots can each be marked public (Phase 23, E5). An
    // OAuth client id lives in `api_key` and is printed in the issuer's own
    // documentation; masking it protects nothing and stops an agent building an
    // auth URL. The flag is per value and per entry — never per type.
    let public_slot = |field: &str| -> bool {
        if is_cookie {
            return false;
        }
        let flag = match field {
            "api_key" => "primary_public",
            "api_secret" => "secret_public",
            _ => return false,
        };
        entry.get(flag).and_then(|v| v.as_bool()).unwrap_or(false)
    };
    for f in SECRET_FIELDS {
        if public_slot(f) {
            continue;
        }
        if let Some(v) = e.get(f).and_then(|v| v.as_str()) {
            let masked = masked_json(v);
            e[f] = masked;
        }
    }
    // Anything this build does not recognise is masked rather than printed. Only
    // strings are touched: a number or a boolean is not a credential, and
    // masking one would make a listing unreadable for no gain.
    let unknown: Vec<String> = e
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, v)| {
                    v.is_string() && !is_public_field(k) && !SECRET_FIELDS.contains(&k.as_str())
                })
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default();
    for f in unknown {
        if let Some(v) = e.get(&f).and_then(|v| v.as_str()) {
            let masked = masked_json(v);
            e[&f] = masked;
        }
    }
    // A captured cookie jar is 2–8 KB and would otherwise dominate every listing
    // an agent reads (E6) — the same shape the embedded-icon collapse below
    // solves, so it gets the same treatment rather than a second one. The count
    // and the fingerprint are what a caller actually needs: two jars can be told
    // apart, and drift detected, without reading either. `--reveal` still
    // returns it whole.
    if is_cookie {
        if let Some(raw) = entry.get("api_key").and_then(|v| v.as_str()) {
            if !raw.is_empty() {
                let jar = crate::cookies::parse_cookie_header(raw);
                let names: Vec<&str> = jar.iter().map(|c| c.name.as_str()).collect();
                e["api_key"] = json!({
                    "cookies": jar.len(),
                    "names": names,
                    "bytes": raw.len(),
                    "fingerprint": fingerprint(raw),
                    "redacted": true,
                });
            }
        }
        // A User-Agent is a fingerprint, not a credential, and it identifies the
        // browser the session was minted in. It must never appear anywhere the
        // redacting resolver writes.
        if let Some(ua) = e.get("user_agent").and_then(|v| v.as_str()) {
            let masked = masked_json(ua);
            e["user_agent"] = masked;
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

    // `extra_vars` are masked **by default**, with `public: true` as the opt-out
    // (Phase 23, E5).
    //
    // They used to be masked only when `secret: true`, and that flag defaults to
    // unset — so an entry whose real payload lives in named variables (an AWS
    // key pair, a Twilio credential, a split cookie jar) printed every one of
    // them in clear, and the first unflagged password was the one that leaked.
    // This is the `env_file`-chunk trap wearing a different hat, and it is the
    // same shape as the Phase 22 seed leak: a value printed because nobody
    // marked it, rather than because somebody vouched for it.
    //
    // Opt-out **per value, never per type**: a client id, a region, an account
    // SID and a publishable key are each safe to print, and the secret beside
    // them is not. Without that, `--profile basic` output is either useless
    // (everything masked) or unsafe (nothing masked).
    if let Some(arr) = e.get_mut("extra_vars").and_then(|v| v.as_array_mut()) {
        for xv in arr.iter_mut() {
            // **A cookie entry's vars are masked whole, `public` ignored**
            // (E5). A jar split one cookie per var is N session credentials,
            // and any one of them is enough to be the account — so there is no
            // "this half is the public half" here, unlike a client id beside a
            // client secret. Same rule `env_file` chunks already follow, for the
            // same reason.
            let is_public =
                !is_cookie && xv.get("public").and_then(|s| s.as_bool()).unwrap_or(false);
            if !is_public {
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
