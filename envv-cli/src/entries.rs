//! Entry CRUD — the terminal half of the add/edit form, plus the card actions
//! (pin, tag, mark rotated, mark compromised) and version history.

use crate::access::Access;
use crate::data::{self, entries_mut, find_entry_index, projects};
use crate::error::{CliError, CliResult};
use crate::fmt::{confirm, fmt_entries, read_stdin};
use crate::out;
use clap::Args;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Every writable field of a `VaultEntry`, shared by `entry add` and `entry set`.
///
/// All optional: on `add` an absent flag means "leave unset", on `set` it means
/// "leave unchanged". Clearing a field is `--field ''`.
#[derive(Args, Clone, Default)]
pub struct EntryFields {
    /// Primary secret value. Use --key-stdin to keep it out of the process list.
    #[arg(long)]
    pub key: Option<String>,
    /// Read the primary secret from stdin (never appears in `ps` or shell history).
    #[arg(long, conflicts_with = "key")]
    pub key_stdin: bool,
    /// Secondary secret (client secret / shared secret).
    #[arg(long)]
    pub secret: Option<String>,
    #[arg(long)]
    pub account: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub email: Option<String>,
    #[arg(long)]
    pub key_id: Option<String>,
    /// api_key | password | certificate | env_var | connection_string | ssh_key | file_blob | cookie
    #[arg(long = "type", value_parser = SECRET_TYPES)]
    pub secret_type: Option<String>,
    /// free | local | paid | conditional
    #[arg(long, value_parser = ["free", "local", "paid", "conditional"])]
    pub price: Option<String>,
    /// production | staging | development | testing
    #[arg(long, value_parser = ["production", "staging", "development", "testing", ""])]
    pub env: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub callback_url: Option<String>,
    #[arg(long)]
    pub version: Option<String>,
    /// What the primary value *is* — the last segment of the generated variable
    /// name. `--role id` makes an OAuth client id export as `SPOTIFY_ID` rather
    /// than as `SPOTIFY`, which is what it did before.
    ///
    /// The vocabulary is open: `id`, `key`, `token`, `secret`, `password` and
    /// `value` are presets, and an issuer that invents its own (`account_sid`,
    /// `merchant_id`) is spelled out here rather than pushed into `extra_vars`.
    /// Absent keeps the bare name — which is what every already-deployed `.env`
    /// written by this tool uses.
    #[arg(long)]
    pub role: Option<String>,
    /// What `--secret` is called, when `SECRET` is wrong (Twilio's is an auth token).
    #[arg(long)]
    pub secret_role: Option<String>,
    /// Short namespace token inserted into generated names after the version —
    /// `SPOTIFY_V2_GAME_ID`.
    ///
    /// Not the account name: account names are email addresses, and
    /// `SPOTIFY_ME_GMAIL_COM_ID` is not a variable anyone wants. Letters, digits,
    /// `_` and `-`, starting with a letter or digit, 24 characters at most.
    #[arg(long)]
    pub label: Option<String>,
    /// The primary value is safe to print — an OAuth client id, a Stripe `pk_`,
    /// an AWS access key id.
    ///
    /// Opts it out of redaction everywhere. Per value and never per type: the
    /// secret beside a public client id stays masked. `--no-public` puts it back.
    #[arg(long, overrides_with = "no_public")]
    pub public: bool,
    #[arg(long = "no-public", overrides_with = "public")]
    pub no_public: bool,
    /// The same, for `--secret`.
    #[arg(long, overrides_with = "no_secret_public")]
    pub secret_public: bool,
    #[arg(long = "no-secret-public", overrides_with = "secret_public")]
    pub no_secret_public: bool,
    /// **How** this credential is sent: bearer | header | basic | query | cookie.
    ///
    /// This is what turns a stored string into a working request, and it is the
    /// one thing about a credential the vault did not hold — so two entries that
    /// look identical were used completely differently and the user had to
    /// remember which. `envv curl` reads it.
    #[arg(long, value_parser = ["bearer", "header", "basic", "query", "cookie", ""])]
    pub auth_scheme: Option<String>,
    /// The header or query-parameter name `--auth-scheme` puts the value in.
    ///
    /// Defaults to `X-Api-Key` for `header` and `api_key` for `query`; means
    /// nothing for `bearer` and `basic`, whose shapes are fixed.
    #[arg(long)]
    pub auth_param: Option<String>,
    /// The User-Agent this credential was minted against.
    ///
    /// Not optional metadata for a session cookie: replay without the matching
    /// User-Agent usually 401s.
    #[arg(long)]
    pub user_agent: Option<String>,
    /// Store the contents of a file in the vault (E17).
    ///
    /// `blob_ref` holds only a path, so a fresh machine has the reference and
    /// not the credential. This holds the file itself; `--mount-path` says where
    /// `envv file write` puts it back.
    #[arg(long)]
    pub blob_file: Option<PathBuf>,
    /// Where the consumer expects to find this credential on disk.
    #[arg(long)]
    pub mount_path: Option<String>,
    /// A composite's shape, with `{name}` holes — each part is an ordinary
    /// `--var` (Phase 24.1). Pass an empty string to clear it.
    #[arg(long)]
    pub template: Option<String>,
    /// A composite's kind: link | signed_link | connection | custom, or an
    /// open string past those four presets. Decides whether the rendered
    /// template is percent-encoded by zone (every preset but `custom`).
    #[arg(long = "composite-kind")]
    pub composite_kind: Option<String>,
    /// Rate limit as free text, e.g. "100/min" or "5000 requests per hour".
    ///
    /// Parsed into the structured count/period pair where it can be; kept
    /// verbatim as a note where it cannot ("varies by endpoint"). Pass an empty
    /// string to clear the limit entirely.
    #[arg(long)]
    pub rate_limit: Option<String>,
    /// Rate limit as a plain number. Needs --rate-limit-period to mean anything.
    #[arg(long, conflicts_with = "rate_limit")]
    pub rate_limit_count: Option<u64>,
    /// The window --rate-limit-count applies to.
    #[arg(
        long,
        conflicts_with = "rate_limit",
        value_parser = ["second", "minute", "hour", "day", "week", "month", "year"]
    )]
    pub rate_limit_period: Option<String>,
    /// Why this credential was requested — the justification given to the issuer.
    ///
    /// Distinct from --desc (what it is) and --notes (notes to self). This is
    /// the sentence you will be held to if the issuer asks why you have the key.
    #[arg(long)]
    pub purpose: Option<String>,
    /// Key pool this entry joins, so `envv get --pool <name>` can swap onto it.
    ///
    /// Membership is explicit: two keys for the same provider do not pool
    /// automatically. Pass an empty string to leave the pool.
    #[arg(long)]
    pub pool: Option<String>,
    /// ISO date (YYYY-MM-DD).
    #[arg(long)]
    pub expires: Option<String>,
    /// Rotation cadence in days; the health scan flags overdue entries.
    #[arg(long)]
    pub rotation_days: Option<u32>,
    /// Short "what is this for" description.
    #[arg(long)]
    pub desc: Option<String>,
    /// Longer free-text notes.
    #[arg(long)]
    pub notes: Option<String>,
    #[arg(long)]
    pub details: Option<String>,
    /// Simple Icons slug for the card icon.
    #[arg(long)]
    pub icon: Option<String>,
    /// Embed an image file (.ico, .png, .jpg, .gif, .webp, .bmp) as the icon.
    ///
    /// Stored in the vault as a data URI in the same `custom_icon` field a slug
    /// uses, so an entry can never end up with a slug and a file disagreeing.
    #[arg(long, conflicts_with = "icon")]
    pub icon_file: Option<PathBuf>,
    /// Comma-separated OAuth scopes (replaces the list).
    #[arg(long)]
    pub scopes: Option<String>,
    /// Comma-separated category names (replaces the list).
    #[arg(long)]
    pub categories: Option<String>,
    /// Comma-separated tags (replaces the list). See `entry tag` for add/remove.
    #[arg(long)]
    pub tags: Option<String>,
    /// Comma-separated project ids (replaces the list). "Universal" is always kept.
    #[arg(long)]
    pub projects: Option<String>,
    /// PEM certificate body, or @path to read a file.
    #[arg(long)]
    pub cert: Option<String>,
    /// PEM private key paired with --cert, or @path.
    #[arg(long)]
    pub cert_key: Option<String>,
    #[arg(long)]
    pub cert_issuer: Option<String>,
    /// File path for file_blob entries.
    #[arg(long)]
    pub blob_ref: Option<String>,
    /// Display hint for env_var entries.
    #[arg(long, value_parser = ENV_SUBTYPES)]
    pub env_subtype: Option<String>,
    /// Extra field as key=value. Repeatable. Prefix the key with `!` to mark it secret.
    #[arg(long = "var")]
    pub vars: Vec<String>,
    /// Comma-separated env-var prefixes (e.g. ND,SPOTIFYD).
    #[arg(long)]
    pub env_prefixes: Option<String>,

    /// Authenticator seed for this credential's service: base32, or a whole
    /// `otpauth://totp/...` URI.
    ///
    /// This is the seed a *third party* issued, from which `envv totp code`
    /// produces the six digits you type into that service. It is not EnvVault's
    /// own second factor — that is `envv user totp`.
    ///
    /// A URI is split: its algorithm, digits and period are stored alongside the
    /// seed, so pasting one is all that is ever needed. Pass an empty string to
    /// remove the seed. Prefer --totp-stdin to keep it out of `ps` and shell
    /// history — it is a credential, and one that grants a login by itself.
    #[arg(long)]
    pub totp: Option<String>,
    /// Read the authenticator seed from stdin (never appears in `ps`).
    #[arg(long, conflicts_with = "totp")]
    pub totp_stdin: bool,
    /// HMAC the issuer uses. Only needed for a bare seed whose issuer is unusual;
    /// an `otpauth://` URI carries it.
    #[arg(long, value_parser = ["SHA1", "SHA256", "SHA512"])]
    pub totp_algorithm: Option<String>,
    /// Digits in the generated code (6–10). Default 6.
    #[arg(long)]
    pub totp_digits: Option<u32>,
    /// Seconds a code is valid for. Default 30. Ignored for a counter-based seed.
    #[arg(long)]
    pub totp_period: Option<u64>,
    /// What the seed is: `totp` (time-based, the default), `hotp` (counter-based)
    /// or `steam` (Steam Guard's five characters).
    #[arg(long, value_parser = ["totp", "hotp", "steam"])]
    pub totp_kind: Option<String>,
    /// The next counter an `hotp` seed will use.
    ///
    /// Set it to resynchronise an account that has drifted; `envv totp advance`
    /// is how it moves in normal use.
    #[arg(long)]
    pub totp_counter: Option<u64>,

    /// Generate the secret instead of supplying one.
    ///
    /// The value is written straight into the vault and never printed — the
    /// caller learns only its fingerprint. This is how an orchestrator creates a
    /// credential it is structurally unable to leak.
    #[arg(long, conflicts_with_all = ["key", "key_stdin"])]
    pub generate: bool,
    /// Bytes of entropy for --generate (ignored for --generate-format password).
    #[arg(long, default_value_t = 32)]
    pub generate_bytes: usize,
    /// Shape of the generated secret.
    #[arg(long, default_value = "base64url", value_parser = ["hex", "base64", "base64url", "password"])]
    pub generate_format: String,
}

/// Every `--type` value the CLI accepts. Kept as a plain `const` array rather
/// than sourced from `vault_core::secret_types::registry()` at derive time —
/// clap's `value_parser` attribute wants something `const`-evaluable, and a
/// JSON-backed `Vec` is not. `tests::secret_types_matches_the_registry`
/// catches drift instead of preventing it by construction.
pub const SECRET_TYPES: [&str; 26] = [
    "api_key",
    "password",
    "certificate",
    "env_var",
    "connection_string",
    "ssh_key",
    "file_blob",
    "cookie",
    "composite",
    "bundle",
    "oauth_client",
    "signing_key",
    "registry_token",
    "database",
    "recovery_codes",
    "gpg_key",
    "age_key",
    "local_service",
    "tracker",
    "usenet_server",
    "wifi",
    "license_key",
    "crypto_wallet",
    "passkey",
    "secure_note",
    "identity_document",
];

pub const ENV_SUBTYPES: [&str; 11] = [
    "string",
    "multiline",
    "secret",
    "boolean",
    "number",
    "ip",
    "cidr",
    "port",
    "url",
    "date",
    "json",
];

/// Largest embedded icon accepted, as data-URI characters. Matches
/// `MAX_ICON_CHARS` in `src/ts/icons.ts` — the app and the CLI must agree, or a
/// file one accepts renders as a broken image in the other.
const MAX_ICON_CHARS: usize = 96 * 1024;

/// Read an image file and return it as a validated `data:` URI.
///
/// The type comes from the file's magic bytes, not its extension: an entry whose
/// icon claims to be a PNG and is not simply fails to render, with nothing on
/// screen explaining why.
fn embed_icon(path: &std::path::Path) -> CliResult<String> {
    use base64::Engine;
    let bytes = std::fs::read(path)
        .map_err(|e| CliError::not_found(format!("Cannot read {}: {e}", path.display())))?;

    let mime = match bytes.as_slice() {
        [0x89, b'P', b'N', b'G', ..] => "image/png",
        [0xFF, 0xD8, 0xFF, ..] => "image/jpeg",
        [b'G', b'I', b'F', b'8', ..] => "image/gif",
        [b'B', b'M', ..] => "image/bmp",
        [0x00, 0x00, 0x01, 0x00, ..] => "image/x-icon",
        b if b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" => "image/webp",
        _ => {
            return Err(CliError::invalid(
                "Not a recognised image (expected PNG, JPEG, GIF, WebP, BMP or ICO). \
                 SVG is deliberately unsupported: it is a script-bearing format.",
            ))
        }
    };

    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let uri = format!("data:{mime};base64,{encoded}");
    if uri.len() > MAX_ICON_CHARS {
        return Err(CliError::invalid(format!(
            "Icon is too large ({} KB encoded, max {} KB) — the vault is re-serialised on every save",
            uri.len() / 1024,
            MAX_ICON_CHARS / 1024
        )));
    }
    Ok(uri)
}

/// Read a flag value, expanding a leading `@` into the contents of that file.
fn maybe_file(raw: &str) -> CliResult<String> {
    match raw.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| CliError::not_found(format!("Cannot read {path}: {e}")))
            .map(|s| s.trim_end().to_string()),
        None => Ok(raw.to_string()),
    }
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Set a string field, or remove it when the caller passed an empty string.
/// What a `label` may be — the twin of `LABEL_RE` in `src/ts/modals.ts`.
///
/// Hand-written rather than a `regex` dependency: the crate is not in the tree
/// and this is one character class and a length.
pub fn label_is_valid(v: &str) -> bool {
    let mut chars = v.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    v.chars().count() <= 24 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn set_str(entry: &mut Value, field: &str, value: &str) {
    if value.is_empty() {
        entry.as_object_mut().map(|o| o.remove(field));
    } else {
        entry[field] = json!(value);
    }
}

impl EntryFields {
    /// Produce the value for `--generate`.
    pub fn generate_value(&self) -> CliResult<String> {
        if self.generate_format == "password" {
            let (pw, _) = crate::gen::password(
                &crate::gen::PwOpts {
                    length: self.generate_bytes.max(12),
                    upper: true,
                    lower: true,
                    digits: true,
                    symbols: true,
                    no_ambiguous: false,
                },
                &crate::gen::current(),
            )?;
            Ok(pw)
        } else {
            crate::gen::secret(
                self.generate_bytes,
                &self.generate_format,
                &crate::gen::current(),
            )
        }
    }

    /// Apply `--totp` and its three parameter flags as one unit.
    ///
    /// Parsing lives in `vault_core::totp` — the same parser the desktop app's
    /// form calls over IPC and the same one `src/ts/totp.ts` is pinned against —
    /// so a URI pasted into the CLI and one pasted into the app cannot be read
    /// two different ways.
    ///
    /// The parameters an `otpauth://` URI names win over the entry's previous
    /// ones and lose to flags passed alongside, which is the order of
    /// specificity a caller means: the URI describes the seed it carries, and an
    /// explicit flag describes what the caller knows that the URI got wrong.
    ///
    /// A URI's issuer and account are **not** written onto the entry. They are
    /// frequently stale, and silently renaming an entry — the thing every
    /// `${ref}` addresses it by — because a pasted URI disagreed is invariant 2
    /// with no cascade behind it.
    /// True when any seed flag was passed.
    ///
    /// **One list, named, beside the flags it mirrors.** It used to be written
    /// out at the call site, and Phase 22.2's `--totp-kind` and `--totp-counter`
    /// were not added to it — so `entry set X --totp-counter 5` reported success
    /// and changed nothing, which is the worst shape a write can fail in. Adding
    /// a seed flag means adding it here; there is nowhere else to forget.
    fn touches_totp(&self) -> bool {
        self.totp.is_some()
            || self.totp_stdin
            || self.totp_algorithm.is_some()
            || self.totp_digits.is_some()
            || self.totp_period.is_some()
            || self.totp_kind.is_some()
            || self.totp_counter.is_some()
    }

    fn apply_totp(&self, entry: &mut Value) -> CliResult {
        let raw = if self.totp_stdin {
            Some(read_stdin()?)
        } else {
            self.totp.clone()
        };

        // Clearing: `--totp ''` removes the seed and every parameter with it, so
        // an entry with no seed cannot carry a period that describes nothing.
        if raw.as_deref().map(str::trim) == Some("") {
            if let Some(o) = entry.as_object_mut() {
                o.remove("totp_secret");
                o.remove("totp_algorithm");
                o.remove("totp_digits");
                o.remove("totp_period");
                o.remove("totp_kind");
                o.remove("totp_counter");
            }
            return Ok(());
        }

        // One reader for all five fields, shared with `envv totp`, the desktop
        // command and the importer.
        let mut params = vault_core::totp::Params::from_fields(
            entry.get("totp_kind").and_then(|v| v.as_str()),
            entry.get("totp_algorithm").and_then(|v| v.as_str()),
            entry.get("totp_digits").and_then(|v| v.as_u64()),
            entry.get("totp_period").and_then(|v| v.as_u64()),
            entry.get("totp_counter").and_then(|v| v.as_u64()),
        );

        if let Some(raw) = raw {
            let parsed = vault_core::totp::parse_seed(&raw).map_err(CliError::invalid)?;
            entry["totp_secret"] = json!(parsed.secret);
            params = parsed.params;
        } else if entry.get("totp_secret").and_then(|v| v.as_str()).is_none() {
            return Err(CliError::invalid(
                "--totp-kind/--totp-algorithm/--totp-digits/--totp-period/--totp-counter \
                 describe a seed; pass --totp or --totp-stdin as well",
            ));
        }

        if let Some(k) = &self.totp_kind {
            params.kind = vault_core::totp::Kind::parse(k).ok_or_else(|| {
                CliError::invalid(format!("unknown OTP kind '{k}' — use totp, hotp or steam"))
            })?;
        }
        if let Some(c) = self.totp_counter {
            params.counter = c;
        }
        if let Some(a) = &self.totp_algorithm {
            params.algorithm = vault_core::totp::Algorithm::parse(a).unwrap_or(params.algorithm);
        }
        if let Some(d) = self.totp_digits {
            params.digits = d;
        }
        if let Some(p) = self.totp_period {
            params.period = p;
        }
        // Steam fixes its own shape, so a `--totp-digits 6` alongside
        // `--totp-kind steam` is corrected rather than stored and then refused.
        let params = vault_core::totp::Params::from_fields(
            Some(params.kind.as_str()),
            Some(params.algorithm.as_str()),
            Some(u64::from(params.digits)),
            Some(params.period),
            Some(params.counter),
        );
        params.validate().map_err(CliError::invalid)?;

        // Only non-default parameters are written. A `totp_algorithm: "SHA1"` on
        // every entry cannot be told apart from a defaulted one, and the UI
        // would have to guess whether the issuer said it or we did.
        let defaults = vault_core::totp::Params::default();
        if let Some(o) = entry.as_object_mut() {
            if params.algorithm == defaults.algorithm {
                o.remove("totp_algorithm");
            } else {
                o.insert("totp_algorithm".into(), json!(params.algorithm.as_str()));
            }
            if params.digits == defaults.digits {
                o.remove("totp_digits");
            } else {
                o.insert("totp_digits".into(), json!(params.digits));
            }
            if params.period == defaults.period {
                o.remove("totp_period");
            } else {
                o.insert("totp_period".into(), json!(params.period));
            }
            if params.kind == defaults.kind {
                o.remove("totp_kind");
            } else {
                o.insert("totp_kind".into(), json!(params.kind.as_str()));
            }
            // The counter is state, not configuration: it is written whenever
            // the seed is counter-based, zero included, because zero is a real
            // position rather than an absent one.
            if params.kind == vault_core::totp::Kind::Hotp {
                o.insert("totp_counter".into(), json!(params.counter));
            } else {
                o.remove("totp_counter");
            }
        }
        Ok(())
    }

    /// Apply every flag the caller actually passed onto `entry`.
    pub fn apply(&self, entry: &mut Value, vault_projects: &[Value]) -> CliResult {
        if self.generate {
            entry["api_key"] = json!(self.generate_value()?);
        } else if self.key_stdin {
            entry["api_key"] = json!(read_stdin()?);
        } else if let Some(v) = &self.key {
            entry["api_key"] = json!(v);
        }
        if let Some(v) = &self.secret {
            set_str(entry, "api_secret", v);
        }
        if let Some(v) = &self.account {
            set_str(entry, "account_name", v);
        }
        if let Some(v) = &self.username {
            set_str(entry, "username", v);
        }
        if let Some(v) = &self.email {
            set_str(entry, "email", v);
        }
        if let Some(v) = &self.key_id {
            set_str(entry, "key_id", v);
        }
        if let Some(v) = &self.secret_type {
            entry["secretType"] = json!(v);
        }
        if let Some(v) = &self.price {
            entry["price_type"] = json!(v);
        }
        if let Some(v) = &self.env {
            set_str(entry, "environment", v);
        }
        if let Some(v) = &self.url {
            set_str(entry, "api_url", v);
        }
        if let Some(v) = &self.callback_url {
            set_str(entry, "callback_url", v);
        }
        if let Some(v) = &self.version {
            set_str(entry, "version", v);
        }
        if let Some(v) = &self.role {
            set_str(entry, "primary_role", v);
        }
        // Absent means "leave unchanged", as every other flag here does, so the
        // pair is read rather than the single bool: a bare `entry set` must not
        // silently un-publish a value somebody marked public.
        if self.public {
            entry["primary_public"] = json!(true);
        } else if self.no_public {
            entry.as_object_mut().map(|o| o.remove("primary_public"));
        }
        if self.secret_public {
            entry["secret_public"] = json!(true);
        } else if self.no_secret_public {
            entry.as_object_mut().map(|o| o.remove("secret_public"));
        }
        if let Some(v) = &self.auth_scheme {
            set_str(entry, "auth_scheme", v);
        }
        if let Some(v) = &self.auth_param {
            set_str(entry, "auth_param", v);
        }
        if let Some(v) = &self.user_agent {
            set_str(entry, "user_agent", v);
        }
        if let Some(v) = &self.mount_path {
            set_str(entry, "mount_path", v);
        }
        if let Some(v) = &self.template {
            set_str(entry, "composite_template", v);
        }
        if let Some(v) = &self.composite_kind {
            set_str(entry, "composite_kind", v);
        }
        if let Some(path) = &self.blob_file {
            let raw = std::fs::read(path)
                .map_err(|e| CliError::from(format!("Cannot read {}: {e}", path.display())))?;
            // Refused above the cap rather than truncated. A truncated credential
            // fails at deploy time with an error about malformed JSON, which
            // names the consumer and not the vault that broke it.
            if raw.len() > crate::filecred::BLOB_MAX_BYTES {
                return Err(CliError::invalid(format!(
                    "{} is {} bytes; the cap is {}. Keep a bundle that large on disk and point \
                     `--mount-path` at it instead.",
                    path.display(),
                    raw.len(),
                    crate::filecred::BLOB_MAX_BYTES
                )));
            }
            let text = String::from_utf8(raw).map_err(|_| {
                CliError::invalid(
                    "That file is not UTF-8 text. Credentials of this shape (JSON, PEM, \
                     kubeconfig) always are; a binary one belongs on disk with --mount-path.",
                )
            })?;
            entry["blob_data"] = json!(text);
        }
        if let Some(v) = &self.secret_role {
            set_str(entry, "secret_role", v);
        }
        if let Some(v) = &self.label {
            // Refused rather than transliterated: a label is a *name segment*,
            // and quietly turning `my label!` into `MY_LABEL` produces a
            // variable name the user never typed and cannot predict. Same rule
            // and same expression as the form.
            if !v.is_empty() && !label_is_valid(v) {
                return Err(CliError::invalid(format!(
                    "--label '{v}': letters, digits, _ and - only, starting with a letter or digit, 24 characters at most"
                )));
            }
            set_str(entry, "label", v);
        }
        // The rate limit is three fields that must agree, so it is applied as a
        // unit rather than field by field. `--rate-limit` sets the free text and
        // lets the parser derive the pair; `--rate-limit-count`/`--period` set
        // the pair and let the formatter derive the text. Clearing either way
        // removes all three, so an entry with no limit looks like one that never
        // had one.
        if self.rate_limit.is_some()
            || self.rate_limit_count.is_some()
            || self.rate_limit_period.is_some()
        {
            if let Some(v) = &self.rate_limit {
                set_str(entry, "rate_limit", v);
                if v.trim().is_empty() {
                    if let Some(o) = entry.as_object_mut() {
                        o.remove("rate_limit_count");
                        o.remove("rate_limit_period");
                        o.remove("rate_limit_note");
                    }
                }
            }
            if let Some(v) = self.rate_limit_count {
                entry["rate_limit_count"] = json!(v);
            }
            if let Some(v) = &self.rate_limit_period {
                entry["rate_limit_period"] = json!(v);
            }
            let normalized = crate::ratelimit::normalize(entry);
            crate::ratelimit::apply(entry, &normalized);
        }
        if let Some(v) = &self.purpose {
            set_str(entry, "purpose", v);
        }
        if let Some(v) = &self.pool {
            set_str(entry, "pool", v.trim());
        }
        if let Some(v) = &self.expires {
            set_str(entry, "expires_at", v);
        }
        if let Some(v) = self.rotation_days {
            if v == 0 {
                entry.as_object_mut().map(|o| o.remove("rotation_days"));
            } else {
                entry["rotation_days"] = json!(v);
            }
        }
        if let Some(v) = &self.desc {
            set_str(entry, "api_description", v);
        }
        if let Some(v) = &self.notes {
            set_str(entry, "description", v);
        }
        if let Some(v) = &self.details {
            set_str(entry, "details", v);
        }
        if let Some(v) = &self.icon {
            set_str(entry, "custom_icon", v);
        }
        if let Some(path) = &self.icon_file {
            entry["custom_icon"] = json!(embed_icon(path)?);
        }
        if let Some(v) = &self.scopes {
            entry["scopes"] = json!(split_list(v));
        }
        if let Some(v) = &self.categories {
            entry["categories"] = json!(split_list(v));
        }
        if let Some(v) = &self.tags {
            let tags = split_list(v);
            if tags.is_empty() {
                entry.as_object_mut().map(|o| o.remove("tags"));
            } else {
                entry["tags"] = json!(tags);
            }
        }
        if let Some(v) = &self.cert {
            set_str(entry, "certificate_data", &maybe_file(v)?);
        }
        if let Some(v) = &self.cert_key {
            set_str(entry, "cert_key_data", &maybe_file(v)?);
        }
        if let Some(v) = &self.cert_issuer {
            set_str(entry, "cert_issuer", v);
        }
        if let Some(v) = &self.blob_ref {
            set_str(entry, "blob_ref", v);
        }
        if let Some(v) = &self.env_subtype {
            set_str(entry, "env_var_subtype", v);
        }
        // The seed is applied as a unit with its three parameters: a URI
        // carries all four, and applying them field by field would let a
        // `--totp-digits 8` from a previous command survive onto a seed pasted
        // from an issuer that uses six.
        if self.touches_totp() {
            self.apply_totp(entry)?;
        }
        if let Some(v) = &self.env_prefixes {
            let parts: Vec<String> = split_list(v)
                .into_iter()
                .map(|p| p.trim_end_matches('_').to_string())
                .filter(|p| !p.is_empty())
                .collect();
            if parts.is_empty() {
                entry.as_object_mut().map(|o| o.remove("env_prefixes"));
            } else {
                entry["env_prefixes"] = json!(parts);
            }
        }
        if !self.vars.is_empty() {
            let mut list: Vec<Value> = entry
                .get("extra_vars")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for raw in &self.vars {
                let (k, v) = raw
                    .split_once('=')
                    .ok_or_else(|| format!("--var expects key=value, got '{raw}'"))?;
                let (key, is_secret) = match k.strip_prefix('!') {
                    Some(stripped) => (stripped, true),
                    None => (k, false),
                };
                list.retain(|x| x.get("key").and_then(|kk| kk.as_str()) != Some(key));
                if !v.is_empty() {
                    list.push(json!({ "key": key, "value": v, "secret": is_secret }));
                }
            }
            if list.is_empty() {
                entry.as_object_mut().map(|o| o.remove("extra_vars"));
            } else {
                entry["extra_vars"] = json!(list);
            }
        }
        if let Some(v) = &self.projects {
            let mut ids = split_list(v);
            // A project id that does not exist matches nothing in any view, so
            // the entry would simply vanish from the grid with no explanation.
            for id in &ids {
                if id != "Universal"
                    && !vault_projects
                        .iter()
                        .any(|p| p.get("id").and_then(|x| x.as_str()) == Some(id))
                {
                    return Err(CliError::not_found(format!(
                        "No such project id: '{id}' (see `envv project ls`)"
                    )));
                }
            }
            if !ids.iter().any(|i| i == "Universal") {
                ids.insert(0, "Universal".into());
            }
            entry["projectIds"] = json!(ids);
        }
        Ok(())
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

pub fn cmd_add(
    access: &Access,
    provider: &str,
    fields: &EntryFields,
    if_missing: bool,
    template: Option<&str>,
) -> CliResult {
    let template = match template {
        Some(id) => Some(vault_core::templates::find(id).ok_or_else(|| {
            CliError::not_found(format!("No template '{id}' — see `envv template ls`"))
        })?),
        None => None,
    };
    let mut vault = access.load_vault_or_empty()?;
    let projs = projects(&vault);
    let existing = data::entries(&vault).iter().any(|e| {
        data::provider_of(e) == provider
            && e.get("key_id").and_then(|v| v.as_str())
                == fields.key_id.as_deref().filter(|s| !s.is_empty())
    });
    if existing {
        // Idempotency for orchestrators: re-running a provisioning script must
        // not be an error, but it must also not silently overwrite a secret.
        if if_missing {
            out::ok(
                "entry.add",
                json!({ "provider": provider, "created": false, "reason": "exists" }),
                || println!("'{provider}' already exists — left alone"),
            );
            return Ok(());
        }
        return Err(CliError::conflict(format!(
            "An entry named '{provider}' already exists — use `envv entry set` to change it, or pass a distinct --key-id"
        )));
    }

    let mut entry = json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "provider": provider,
        "api_key": "",
        "price_type": "free",
        "secretType": "api_key",
        "categories": [],
        "projectIds": ["Universal"],
        "scopes": [],
        // Stamped here and never rewritten. It is a creation date, not a
        // modification date — `cmd_set` deliberately leaves it alone, and
        // `version_history` is where "when did this last change" lives. The
        // desktop app stamps the same field on the same event, so an entry made
        // in either half of the product dates itself the same way.
        "created_at": vault_core::iso_now(),
    });
    // A template pre-fills; explicit flags then override it, so
    // `--preset github-pat --url …` does what it says.
    if let Some(t) = &template {
        entry["secretType"] = json!(t.secret_type);
        for (k, v) in &t.defaults {
            entry[k.as_str()] = v.clone();
        }
        // The name given on the command line is the entry's name, not the
        // preset's display provider.
        entry["provider"] = json!(provider);
    }
    fields.apply(&mut entry, &projs)?;
    let fingerprint = out::fingerprint(entry.get("api_key").and_then(|v| v.as_str()).unwrap_or(""));
    let id = entry
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    entries_mut(&mut vault).push(entry);
    access.save(&vault)?;
    out::ok(
        "entry.add",
        json!({ "provider": provider, "id": id, "created": true, "fingerprint": fingerprint }),
        || println!("Added '{provider}' ({fingerprint})"),
    );
    Ok(())
}

/// `envv totp add NAME --seed-stdin [--account …]` — the guided path that
/// mirrors the desktop Authenticator panel's "Add 2FA" form: attach to an
/// existing entry found by exact provider name, or create a bare
/// `password`-typed one with an empty primary when none exists.
///
/// This could otherwise just be a spelling of `entry set --create
/// --totp-stdin`, and the one thing that makes it a different command is the
/// safety check: it **refuses** when the target already carries a seed,
/// rather than overwriting on request as `entry set` rightly does for an
/// explicit edit. The whole pitch of a guided "add" command is that it is
/// safe to run without checking first — the same rule the totp-import merge
/// and the desktop form's own refusal both follow.
pub fn cmd_totp_add(
    access: &Access,
    name: &str,
    account: Option<&str>,
    fields: &EntryFields,
) -> CliResult {
    if !fields.touches_totp() {
        return Err(CliError::invalid(
            "Pass --totp or --totp-stdin with a seed to add.",
        ));
    }
    let mut vault = access.load_vault_or_empty()?;
    let existing_idx = data::entries(&vault)
        .iter()
        .position(|e| data::provider_of(e).eq_ignore_ascii_case(name));

    let (idx, created) = match existing_idx {
        Some(i) => {
            let already = data::entries(&vault)[i]
                .get("totp_secret")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.trim().is_empty());
            if already {
                return Err(CliError::conflict(format!(
                    "'{name}' already has a seed — use `envv entry set {name} --totp-stdin` \
                     to re-enroll it on purpose"
                )));
            }
            (i, false)
        }
        None => {
            let mut entry = json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "provider": name,
                "api_key": "",
                "price_type": "free",
                "secretType": "password",
                "categories": [],
                "projectIds": ["Universal"],
                "scopes": [],
                "created_at": vault_core::iso_now(),
            });
            if let Some(a) = account.filter(|a| !a.is_empty()) {
                entry["account_name"] = json!(a);
            }
            entries_mut(&mut vault).push(entry);
            (data::entries(&vault).len() - 1, true)
        }
    };

    fields.apply_totp(&mut entries_mut(&mut vault)[idx])?;
    access.save(&vault)?;
    out::ok(
        "totp.add",
        json!({ "provider": name, "created": created }),
        || {
            println!(
                "{} '{name}' with a 2FA seed",
                if created { "Created" } else { "Attached to" }
            )
        },
    );
    Ok(())
}

pub fn cmd_set(access: &Access, query: &str, fields: &EntryFields, create: bool) -> CliResult {
    let mut vault = access.load_vault_or_empty()?;
    let projs = projects(&vault);
    let idx = match find_entry_index(&vault, query) {
        Ok(i) => i,
        // `--create` makes set an upsert, so a provisioning script can run once
        // or a hundred times with the same result.
        Err(e) if create && e.code == crate::error::Code::NotFound => {
            return cmd_add(access, query, fields, false, None);
        }
        Err(e) => return Err(e),
    };
    let mut entry = data::entries(&vault)[idx].clone();
    let before = entry
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    fields.apply(&mut entry, &projs)?;
    // Entries written before ids existed still parse; stamp one rather than
    // leaving an entry the audit log and RBAC scoping cannot name.
    if entry
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        entry["id"] = json!(uuid::Uuid::new_v4().to_string());
    }
    let after = entry
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let provider = data::provider_of(&entry).to_string();
    entries_mut(&mut vault)[idx] = entry;
    access.save(&vault)?;

    let changed = before != after;
    out::ok(
        "entry.set",
        json!({
            "provider": provider,
            "created": false,
            "secret_changed": changed,
            "fingerprint": out::fingerprint(&after),
        }),
        || {
            println!("Updated '{provider}'");
            if changed {
                println!("Secret now {}", out::fingerprint(&after));
            }
        },
    );
    Ok(())
}

pub fn cmd_rm(access: &Access, query: &str, yes: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let provider = data::provider_of(&data::entries(&vault)[idx]).to_string();
    if !confirm(&format!("Delete entry '{provider}'?"), yes)? {
        println!("Cancelled.");
        return Ok(());
    }
    entries_mut(&mut vault).remove(idx);
    access.save(&vault)?;
    out::ok(
        "entry.rm",
        json!({ "provider": provider, "deleted": true }),
        || println!("Deleted '{provider}'"),
    );
    Ok(())
}

/// Rename an entry, carrying every `${Provider…}` chunk reference with it.
///
/// The rename cascade is not optional: references resolve by provider *name*, so
/// renaming without rewriting them leaves every `${Old/field}` in every project
/// silently unresolved, and the next export writes a literal `${…}` into a
/// config file. `${chunk:…}` refs address a chunk, not an entry, and are left alone.
pub fn cmd_rename(access: &Access, query: &str, new_name: &str) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let old = data::provider_of(&data::entries(&vault)[idx]).to_string();
    if old == new_name {
        return Ok(());
    }
    let key_id = data::entries(&vault)[idx]
        .get("key_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    entries_mut(&mut vault)[idx]["provider"] = json!(new_name);

    let mut rewritten = 0usize;
    let compound_old = if key_id.is_empty() {
        None
    } else {
        Some(format!("{old}_{key_id}"))
    };
    let compound_new = if key_id.is_empty() {
        None
    } else {
        Some(format!("{new_name}_{key_id}"))
    };

    for project in data::projects_mut(&mut vault).iter_mut() {
        let Some(chunks) = project.get_mut("chunks").and_then(|c| c.as_array_mut()) else {
            continue;
        };
        for chunk in chunks.iter_mut() {
            let Some(fields) = chunk.get_mut("fields").and_then(|f| f.as_array_mut()) else {
                continue;
            };
            for field in fields.iter_mut() {
                let val = match field.get("value").and_then(|v| v.as_str()) {
                    Some(v) => v.to_string(),
                    None => continue,
                };
                let Some(inner) = val.strip_prefix("${").and_then(|s| s.strip_suffix('}')) else {
                    continue;
                };
                if inner.starts_with("chunk:") {
                    continue;
                }
                let (head, tail) = match inner.split_once('/') {
                    Some((h, t)) => (h.to_string(), Some(t.to_string())),
                    None => (inner.to_string(), None),
                };
                let replacement = if head == old {
                    Some(new_name.to_string())
                } else if Some(head.clone()) == compound_old {
                    compound_new.clone()
                } else {
                    None
                };
                if let Some(new_head) = replacement {
                    let next = match &tail {
                        Some(t) => format!("${{{new_head}/{t}}}"),
                        None => format!("${{{new_head}}}"),
                    };
                    let ref_matches =
                        field.get("ref_name").and_then(|v| v.as_str()) == Some(head.as_str());
                    field["value"] = json!(next);
                    if ref_matches {
                        field["ref_name"] = json!(new_head);
                    }
                    rewritten += 1;
                }
            }
        }
    }

    access.save(&vault)?;
    out::ok(
        "entry.rename",
        json!({ "from": old, "to": new_name, "rewritten_refs": rewritten }),
        || {
            println!("Renamed '{old}' → '{new_name}'");
            if rewritten > 0 {
                println!("Rewrote {rewritten} chunk reference(s)");
            }
        },
    );
    Ok(())
}

pub fn cmd_tag(access: &Access, query: &str, add: &[String], remove: &[String]) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entries = entries_mut(&mut vault);
    let mut tags: Vec<String> = entries[idx]
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    for t in add {
        if !tags.iter().any(|x| x == t) {
            tags.push(t.clone());
        }
    }
    tags.retain(|t| !remove.iter().any(|r| r == t));
    if tags.is_empty() {
        entries[idx].as_object_mut().map(|o| o.remove("tags"));
    } else {
        entries[idx]["tags"] = json!(tags.clone());
    }
    access.save(&vault)?;
    let shown = tags.clone();
    out::ok("entry.tag", json!({ "tags": shown }), || {
        println!(
            "Tags: {}",
            if tags.is_empty() {
                "(none)".to_string()
            } else {
                tags.join(", ")
            }
        )
    });
    Ok(())
}

/// Toggle a boolean flag (`pinned`, `compromised`) on an entry.
pub fn cmd_flag(access: &Access, query: &str, field: &str, on: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entries = entries_mut(&mut vault);
    if on {
        entries[idx][field] = json!(true);
    } else {
        entries[idx].as_object_mut().map(|o| o.remove(field));
    }
    let provider = data::provider_of(&entries[idx]).to_string();
    access.save(&vault)?;
    out::ok(
        "entry.flag",
        json!({ "provider": provider, "field": field, "value": on }),
        || println!("{provider}: {field} = {on}"),
    );
    Ok(())
}

/// Mark an entry rotated — optionally storing a new secret at the same time.
///
/// `save_vault` appends the previous value to `version_history` whenever the key
/// changes, so passing `--key` here both rotates and records.
/// `envv entry verify <entry>` — stamp a session as still working.
///
/// The session equivalent of `rotate`, and the reason the rotation nag is
/// switched off for a cookie (Phase 23, E13): rotating one means logging in
/// again in a browser, which nothing here can do, so "never rotated" was a
/// finding with no available fix. "Never verified" has one, and it takes ten
/// seconds.
pub fn cmd_verify(access: &Access, query: &str, off: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let provider = data::provider_of(&data::entries(&vault)[idx]).to_string();
    let stamp = vault_core::iso_now();
    {
        let entry = &mut entries_mut(&mut vault)[idx];
        if off {
            entry.as_object_mut().map(|o| o.remove("last_verified_at"));
        } else {
            entry["last_verified_at"] = json!(stamp);
        }
    }
    access.save(&vault)?;
    out::ok(
        "entry.verify",
        json!({
            "provider": provider,
            "last_verified_at": if off { Value::Null } else { json!(stamp) },
        }),
        || {
            if off {
                println!("Cleared the verification stamp on '{provider}'");
            } else {
                println!("'{provider}' verified at {stamp}");
            }
        },
    );
    Ok(())
}

pub fn cmd_rotate(
    access: &Access,
    query: &str,
    new_key: Option<&str>,
    from_stdin: bool,
    generate: bool,
) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entries = entries_mut(&mut vault);
    let before = entries[idx]
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if generate {
        // Same shape as `entry add --generate`: the replacement is created,
        // stored and fingerprinted without ever being printed.
        let fields = EntryFields {
            generate: true,
            generate_bytes: 32,
            generate_format: "base64url".into(),
            ..Default::default()
        };
        entries[idx]["api_key"] = json!(fields.generate_value()?);
    } else if from_stdin {
        entries[idx]["api_key"] = json!(read_stdin()?);
    } else if let Some(k) = new_key {
        entries[idx]["api_key"] = json!(k);
    }
    let after = entries[idx]
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let at = vault_core::iso_now();
    entries[idx]["last_rotated_at"] = json!(at);
    // Rotating is the answer to being compromised, so clear the flag.
    entries[idx]
        .as_object_mut()
        .map(|o| o.remove("compromised"));
    let provider = data::provider_of(&entries[idx]).to_string();
    access.save(&vault)?;
    out::ok(
        "entry.rotate",
        json!({
            "provider": provider,
            "rotated_at": at,
            "secret_changed": before != after,
            "fingerprint": out::fingerprint(&after),
        }),
        || {
            println!("Marked '{provider}' rotated at {at}");
            if before != after {
                println!("Secret now {}", out::fingerprint(&after));
            }
        },
    );
    Ok(())
}

pub fn cmd_history(access: &Access, query: &str) -> CliResult {
    let vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entry = &data::entries(&vault)[idx];
    let hist = entry
        .get("version_history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let provider = data::provider_of(entry).to_string();
    let rotated = entry
        .get("last_rotated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // History is a list of previous secrets. Fingerprints answer the question
    // history is actually for — "did this value change, and when?" — without
    // handing back credentials that may still be live somewhere.
    let rows: Vec<Value> = hist
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let val = h.get("value").and_then(|v| v.as_str()).unwrap_or("");
            json!({
                "version": i + 1,
                "saved_at": h.get("saved_at").and_then(|v| v.as_str()).unwrap_or(""),
                // Absent has always meant `api_key` and every vault written
                // before Phase 22 relies on it, so it is filled in here rather
                // than being written into the record.
                "field": history_field(h),
                "value": if out::revealing() { json!(val) } else { out::masked_json(val) },
            })
        })
        .collect();

    out::ok(
        "entry.history",
        json!({ "provider": provider, "count": rows.len(), "last_rotated_at": rotated, "versions": rows }),
        || {
            println!("{provider} — {} previous value(s)", rows.len());
            if !rotated.is_empty() {
                println!("Last marked rotated: {rotated}");
            }
            for (i, h) in hist.iter().enumerate() {
                let when = h.get("saved_at").and_then(|v| v.as_str()).unwrap_or("?");
                let val = h.get("value").and_then(|v| v.as_str()).unwrap_or("");
                let shown = if out::revealing() {
                    val.to_string()
                } else {
                    out::masked(val)
                };
                println!(
                    "{:<4} {:<26} {:<22} {}",
                    i + 1,
                    when,
                    history_field(h),
                    shown
                );
            }
        },
    );
    Ok(())
}

/// `envv curl <entry> [-- URL]` — the command that actually sends the credential.
///
/// A **materialising** path: the output contains the real value, so it follows
/// the same rule as `envv export` and `envv render` — redacted to stdout unless
/// `--reveal`, written in full by `--out`.
///
/// Redacted rather than *refused*, unlike a vault-wide export: the shape of the
/// command is the useful part (which header, which parameter, which URL), and a
/// redacted one is safe to paste into a transcript while still answering the
/// question the user asked. A masked `.env` looks deployable and is not; a
/// masked curl line obviously is not.
pub fn cmd_curl(
    access: &Access,
    query: &str,
    url: Option<&str>,
    out_path: Option<&std::path::Path>,
) -> CliResult {
    let vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entry = data::entries(&vault)[idx].clone();
    let provider = data::provider_of(&entry).to_string();

    let real = crate::authreq::curl_for(&entry, url);
    if out_path.is_none() && !out::revealing() {
        // Build the same command from a redacted copy of the entry, so the
        // structure survives and every value in it is a fingerprint.
        let safe = out::redact_entry(&entry);
        let preview = crate::authreq::curl_for(&safe, url);
        out::ok(
            "entry.curl",
            json!({
                "provider": provider,
                "scheme": crate::authreq::scheme_of(&entry).as_str(),
                "command": preview,
                "redacted": true,
            }),
            || println!("{preview}"),
        );
        return Ok(());
    }
    crate::fmt::emit(&real, out_path)
}

/// Every cookie an entry holds, from wherever it keeps them.
///
/// The jar lives in `api_key` as a header string, and the individual cookies
/// live in `extra_vars` once the user has split them — with `attrs` carrying the
/// domain, path, secure flag and expiry that `cookies.txt` needs and a pasted
/// `document.cookie` string does not have. Reading both and preferring the split
/// form is what lets one entry serve `envv cookie header` (which needs neither)
/// and `envv cookie txt` (which needs all of them).
pub fn cookies_of(entry: &Value) -> Vec<crate::cookies::Cookie> {
    let split: Vec<crate::cookies::Cookie> = entry
        .get("extra_vars")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|xv| {
                    let name = xv.get("key").and_then(|v| v.as_str())?;
                    if name.is_empty() {
                        return None;
                    }
                    let a = xv.get("attrs");
                    let attr = |k: &str| {
                        a.and_then(|o| o.get(k))
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                    };
                    let flag = |k: &str| {
                        a.and_then(|o| o.get(k))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                    };
                    Some(crate::cookies::Cookie {
                        name: name.to_string(),
                        value: xv
                            .get("value")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        domain: attr("domain"),
                        path: attr("path"),
                        secure: flag("secure"),
                        http_only: flag("http_only"),
                        expires: a
                            .and_then(|o| o.get("expires"))
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if !split.is_empty() {
        return split;
    }
    crate::cookies::parse_cookie_header(entry.get("api_key").and_then(|v| v.as_str()).unwrap_or(""))
}

/// `envv file write <entry> [--out PATH]` — materialise a file-shaped credential.
///
/// **There is no stdout form and there deliberately never will be.** The whole
/// point of E17 is that the consumer wants a *path*: printing the contents is
/// the mistake, not a redaction question, so this is a materialising path by
/// construction rather than one guarded by `--reveal`.
///
/// Written 0600, and the `.env` line naming it is printed so the caller can pipe
/// it straight into a file — which is what makes this usable from a script
/// without the secret ever entering the script's output.
pub fn cmd_file_write(
    access: &Access,
    query: &str,
    out_path: Option<&std::path::Path>,
) -> CliResult {
    let vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entry = data::entries(&vault)[idx].clone();
    let provider = data::provider_of(&entry).to_string();

    let Some((contents, _ext)) = crate::filecred::contents_of(&entry) else {
        return Err(CliError::invalid(format!(
            "'{provider}' holds no file contents. A `blob_ref` is only a path — put the file in \
             the vault with `envv entry set {provider} --blob-file <path>`."
        )));
    };

    let target = match out_path {
        Some(p) => p.to_path_buf(),
        None => {
            let mount = entry
                .get("mount_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if mount.is_empty() {
                return Err(CliError::invalid(format!(
                    "'{provider}' has no mount path. Pass --out, or set one with \
                     `envv entry set {provider} --mount-path /etc/…`."
                )));
            }
            std::path::PathBuf::from(mount)
        }
    };

    if let Some(dir) = target.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)
                .map_err(|e| CliError::from(format!("Cannot create {}: {e}", dir.display())))?;
        }
    }
    // `write_secret_file`, not `emit`: the file *is* the credential, so 0600 is
    // not optional and there is no stdout branch to fall back to.
    crate::fmt::write_secret_file(&target, &contents)?;

    let name = crate::envfile::primary_name(&entry, None, false);
    let line = format!("{name}={}", target.display());
    out::ok(
        "file.write",
        json!({
            "provider": provider,
            "path": target.display().to_string(),
            "bytes": contents.len(),
            "env_line": line,
        }),
        || println!("{line}"),
    );
    Ok(())
}

/// `envv cookie header|curl|txt|json <entry>`.
///
/// Every form is a materialising path — the output *is* a live session — so each
/// is redacted to stdout and written in full only by `--out`, the same rule
/// `envv export` follows.
pub fn cmd_cookie(
    access: &Access,
    query: &str,
    form: &str,
    out_path: Option<&std::path::Path>,
) -> CliResult {
    let vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entry = data::entries(&vault)[idx].clone();
    let provider = data::provider_of(&entry).to_string();

    let jar = cookies_of(&entry);
    if jar.is_empty() {
        return Err(CliError::not_found(format!(
            "'{provider}' holds no cookies. Paste a jar into its value, or import a cookies.txt."
        )));
    }

    // `txt` is refused for a jar with no attributes **before** the reveal check,
    // because that refusal is about the data and is equally true with `--out`.
    // Reporting "redacted" for a file that could never have been written would
    // send the user looking for a `--reveal` that changes nothing.
    let text = match form {
        "header" => crate::cookies::to_cookie_header(&jar),
        "json" => crate::cookies::to_cookie_json(&jar),
        "curl" => crate::authreq::curl_for(&entry, None),
        "txt" => crate::cookies::to_cookies_txt(&jar).map_err(CliError::invalid)?,
        other => return Err(CliError::invalid(format!("Unknown cookie form '{other}'"))),
    };

    if out_path.is_none() && !out::revealing() {
        return Err(out::refuse_reveal("A cookie jar"));
    }
    crate::fmt::emit(&text, out_path)
}

/// Which value a history record is a snapshot of.
///
/// An absent `field` means `api_key` and always has — every vault written before
/// Phase 22 relies on that, which is why `api_key` still writes no discriminator.
/// A named variable is recorded as `extra_vars/<key>`, namespaced so a restore
/// can tell a var called `api_key` from the field of that name.
fn history_field(record: &Value) -> String {
    record
        .get("field")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("api_key")
        .to_string()
}

/// Restore a previous value from `version_history` by its 1-based position.
pub fn cmd_restore(access: &Access, query: &str, version: usize, yes: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let hist = data::entries(&vault)[idx]
        .get("version_history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let item = hist
        .get(
            version
                .checked_sub(1)
                .ok_or("Versions are numbered from 1")?,
        )
        .ok_or_else(|| format!("No version {version} — history holds {}", hist.len()))?;
    let value = item
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let provider = data::provider_of(&data::entries(&vault)[idx]).to_string();
    if !confirm(&format!("Restore '{provider}' to version {version}?"), yes)? {
        println!("Cancelled.");
        return Ok(());
    }
    // Restore to the field the record names, not to `api_key` (Phase 23, E8).
    // Every record used to be an `api_key` snapshot, so writing there was right;
    // now a record can be a re-enrolled seed, a replaced secret or a named
    // variable, and putting any of those back into the primary slot would
    // overwrite a live credential with an unrelated one.
    let field = history_field(item);
    let entry = &mut entries_mut(&mut vault)[idx];
    if let Some(var_key) = field.strip_prefix("extra_vars/") {
        let arr = entry
            .get_mut("extra_vars")
            .and_then(|v| v.as_array_mut())
            .map(std::mem::take)
            .unwrap_or_default();
        let mut arr: Vec<Value> = arr;
        match arr
            .iter_mut()
            .find(|xv| xv.get("key").and_then(|k| k.as_str()) == Some(var_key))
        {
            Some(existing) => existing["value"] = json!(value),
            // A variable deleted since the snapshot comes back. Deleting a row
            // makes its value exactly as unrecoverable as overwriting one, so a
            // restore that silently dropped it would be a restore that did not.
            None => arr.push(json!({ "key": var_key, "value": value })),
        }
        entry["extra_vars"] = json!(arr);
    } else {
        entry[field.as_str()] = json!(value);
    }
    access.save(&vault)?;
    out::ok(
        "entry.restore",
        json!({
            "provider": provider,
            "version": version,
            "field": field,
            "fingerprint": out::fingerprint(&value),
        }),
        || println!("Restored '{provider}' {field} to version {version}"),
    );
    Ok(())
}

/// `entry ls` with the filters the sidebar offers.
pub fn cmd_list(
    access: &Access,
    project: Option<&str>,
    type_filter: Option<&str>,
    tag: Option<&str>,
    env: Option<&str>,
    category: Option<&str>,
    search: Option<&str>,
    json_out: bool,
) -> CliResult {
    let vault = access.load_vault()?;
    let mut list = data::entries(&vault);

    if let Some(proj) = project {
        let proj_lc = proj.to_lowercase();
        let matching_ids: Vec<String> = projects(&vault)
            .iter()
            .filter(|p| {
                p.get("id").and_then(|i| i.as_str()) == Some(proj)
                    || p.get("name")
                        .and_then(|n| n.as_str())
                        .is_some_and(|n| n.to_lowercase().contains(&proj_lc))
            })
            .filter_map(|p| p.get("id").and_then(|i| i.as_str()).map(String::from))
            .collect();
        list.retain(|e| {
            e.get("projectIds")
                .and_then(|v| v.as_array())
                .is_some_and(|ids| {
                    ids.iter()
                        .any(|id| matching_ids.iter().any(|m| Some(m.as_str()) == id.as_str()))
                })
        });
    }
    if let Some(t) = type_filter {
        // Comma-separated, OR-combined — the CLI twin of the app's Phase 24.2
        // type chip bar. `2fa`/`totp` and `pool` are the same two virtual
        // tokens the chip bar uses (`__totp`/`__pool` there; spelled without
        // the underscores here since this is a flag value a human types).
        let wanted: Vec<&str> = t
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        list.retain(|e| {
            wanted.iter().any(|&w| match w {
                "2fa" | "totp" => e
                    .get("totp_secret")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.trim().is_empty()),
                "pool" => e
                    .get("pool")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.trim().is_empty()),
                _ => {
                    e.get("secretType")
                        .and_then(|v| v.as_str())
                        .unwrap_or("api_key")
                        == w
                }
            })
        });
    }
    if let Some(t) = tag {
        list.retain(|e| {
            e.get("tags")
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(t)))
        });
    }
    if let Some(v) = env {
        list.retain(|e| e.get("environment").and_then(|x| x.as_str()) == Some(v));
    }
    if let Some(c) = category {
        list.retain(|e| {
            e.get("categories")
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(c)))
        });
    }
    if let Some(q) = search {
        let q = q.to_lowercase();
        list.retain(|e| {
            let hay = format!(
                "{} {} {} {}",
                data::provider_of(e),
                e.get("account_name").and_then(|v| v.as_str()).unwrap_or(""),
                e.get("api_description")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
                e.get("description").and_then(|v| v.as_str()).unwrap_or(""),
            );
            hay.to_lowercase().contains(&q)
        });
    }

    // Redaction happens here, once, on the way out — not at each call site, so
    // a new command cannot forget it.
    let safe = out::redact_entries(&list);
    if json_out || out::is_json() {
        out::ok(
            "entry.ls",
            json!({ "count": safe.len(), "entries": safe }),
            || {},
        );
        return Ok(());
    }
    if list.is_empty() {
        println!("No entries found.");
    } else {
        fmt_entries(&list);
        println!("\n{} entries", list.len());
    }
    Ok(())
}

/// `envv get <entry> --profile <p>` — the terminal half of the app's Copy button.
///
/// The text carries **real values**, so it obeys the Phase 14 rule that governs
/// every other artefact: refused to stdout unless `--reveal`, written by
/// `--out`. Masking it instead would produce something that looks like a
/// deployable `.env` and is not — the exact reason `envv export` refuses rather
/// than masks.
pub fn cmd_get_profile(
    access: &Access,
    query: &str,
    profile: &str,
    metadata: Option<&str>,
    out_path: Option<&std::path::Path>,
) -> CliResult {
    let vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entry = data::entries(&vault)[idx].clone();

    if out_path.is_none() && !out::revealing() {
        return Err(out::refuse_reveal("A copy profile"));
    }

    let opts = crate::profile::CopyOpts {
        profile: crate::profile::Profile::parse(profile),
        metadata: metadata
            .map(crate::profile::MetadataStyle::parse)
            .unwrap_or(crate::profile::MetadataStyle::Comment),
        ..Default::default()
    };
    let text = crate::profile::build(&entry, &opts);
    crate::fmt::emit(&text, out_path)
}

pub fn cmd_get(access: &Access, query: &str, field: Option<&str>) -> CliResult {
    let vault = access.load_vault()?;
    if let Some(f) = field {
        let idx = find_entry_index(&vault, query)?;
        let entry = &data::entries(&vault)[idx];
        let val = crate::refs::entry_field(entry, f)
            .ok_or_else(|| CliError::not_found(format!("Entry has no field '{f}'")))?;
        // A named field is very often the secret itself, so the same rule
        // applies: fingerprint unless the caller asked to reveal.
        let secret_field = out::SECRET_FIELDS.contains(&crate::refs::canonical_field(f));
        let shown = if secret_field && !out::revealing() {
            out::masked(&val)
        } else {
            val.clone()
        };
        out::ok(
            "entry.get",
            json!({
                "provider": data::provider_of(entry),
                "field": crate::refs::canonical_field(f),
                "value": if secret_field && !out::revealing() { out::masked_json(&val) } else { json!(val) },
            }),
            || println!("{shown}"),
        );
        return Ok(());
    }
    let q = query.to_lowercase();
    // `bundle:Name[/slot]` names exactly one entry; everything else is the
    // substring search it always was.
    let found: Vec<Value> = if query.starts_with("bundle:") {
        vec![data::entries(&vault)[find_entry_index(&vault, query)?].clone()]
    } else {
        data::entries(&vault)
            .into_iter()
            .filter(|e| data::provider_of(e).to_lowercase().contains(&q))
            .collect()
    };
    if found.is_empty() {
        return Err(CliError::not_found(format!("No entry matching '{query}'")));
    }
    let safe = out::redact_entries(&found);
    out::ok(
        "entry.get",
        json!({ "count": safe.len(), "entries": safe }),
        || {
            for e in &safe {
                println!("{}", serde_json::to_string_pretty(e).unwrap_or_default());
            }
        },
    );
    Ok(())
}

/// Every tag in the vault with its entry count — the sidebar's tag section.
pub fn cmd_tags(access: &Access) -> CliResult {
    let vault = access.load_vault()?;
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for e in data::entries(&vault) {
        for t in e
            .get("tags")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            if let Some(s) = t.as_str() {
                *counts.entry(s.to_string()).or_insert(0) += 1;
            }
        }
    }
    let rows: Vec<Value> = counts
        .iter()
        .map(|(tag, n)| json!({ "tag": tag, "entry_count": n }))
        .collect();
    out::ok("tags", json!({ "count": rows.len(), "tags": rows }), || {
        if counts.is_empty() {
            println!("No tags.");
            return;
        }
        for (tag, n) in &counts {
            println!("{}  {n}", crate::fmt::cell(tag, 30));
        }
    });
    Ok(())
}

#[cfg(test)]
mod secret_type_tests {
    use super::SECRET_TYPES;
    use std::collections::HashSet;

    #[test]
    fn secret_types_matches_the_registry() {
        let cli: HashSet<&str> = SECRET_TYPES.iter().copied().collect();
        let registry: HashSet<String> = vault_core::secret_types::registry()
            .into_iter()
            .map(|t| t.id)
            .collect();
        let registry_refs: HashSet<&str> = registry.iter().map(String::as_str).collect();
        assert_eq!(
            cli, registry_refs,
            "envv-cli's --type list and secret-types.json disagree"
        );
    }
}
