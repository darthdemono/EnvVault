//! Reading and writing the export files other authenticator apps produce.
//!
//! Phase 22 gave the vault somewhere to keep a third-party TOTP seed. This
//! module is how a seed gets in and out without being retyped from a phone
//! screen — Ente Auth, Aegis, 2FAS, andOTP, Bitwarden and Google Authenticator
//! on the way in; a portable `otpauth://` list, Aegis or 2FAS on the way out.
//!
//! # It lives here, and only here
//!
//! Six formats parsed twice is six chances to disagree, and a disagreement here
//! is a seed that imports into the app and not the CLI — or worse, imports with
//! the wrong `period` and produces six digits the issuer rejects. So this is
//! Rust only: the CLI calls it directly, the desktop app calls it over IPC
//! (`totp_import_parse` / `totp_export_build`), and there is no TypeScript twin
//! to pin. That is the shape `pools.ts` already uses and the one CLAUDE.md's
//! twin-pair table says to prefer over a golden fixture.
//!
//! # Encrypted exports are refused, never decrypted
//!
//! Every app here can export encrypted, and each uses its own KDF and envelope.
//! Implementing six of those would mean this crate holding six password-guessing
//! paths whose failures are indistinguishable from a corrupt file. [`detect`]
//! recognises each encrypted shape and returns a message naming the app and
//! saying to export again without encryption. Refusing with a reason beats
//! failing to parse with none.
//!
//! # What is deliberately not read
//!
//! `otpauth://hotp/` and every counter-based entry in every format. HOTP has no
//! clock, so "the current code" does not exist for it: importing one produces an
//! entry whose code never changes and never works. They are counted and named in
//! the report rather than silently dropped.

use crate::totp::{self, Params, Stored};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// An export format this module can read, write, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// One `otpauth://` URI per line. What Ente Auth's plain-text export is,
    /// and what KeePassXC, Raivo, Proton Pass and most others accept back.
    OtpauthList,
    /// Aegis Authenticator's unencrypted JSON vault.
    Aegis,
    /// 2FAS Auth's unencrypted JSON backup.
    TwoFas,
    /// andOTP's unencrypted JSON export (also read by FreeOTP+).
    AndOtp,
    /// A Bitwarden JSON export — reads `login.totp` off each item.
    Bitwarden,
    /// Google Authenticator's `otpauth-migration://offline?data=…` QR payload.
    GoogleMigration,
}

impl Format {
    /// The name a human typed, or that a report prints.
    pub fn as_str(self) -> &'static str {
        match self {
            Format::OtpauthList => "otpauth",
            Format::Aegis => "aegis",
            Format::TwoFas => "2fas",
            Format::AndOtp => "andotp",
            Format::Bitwarden => "bitwarden",
            Format::GoogleMigration => "google",
        }
    }

    /// Parses a `--format` value.
    ///
    /// `ente` is an alias for `otpauth`, not a format of its own: Ente Auth's
    /// plain export *is* a list of `otpauth://` URIs, and its import accepts the
    /// same. The alias exists because somebody with an Ente export will type
    /// `--format ente`, and being told "unknown format" when the thing works is
    /// a bad answer.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '_'], "")
            .as_str()
        {
            "otpauth" | "uri" | "uris" | "txt" | "text" | "ente" | "keepassxc" | "raivo" => {
                Some(Format::OtpauthList)
            }
            "aegis" => Some(Format::Aegis),
            "2fas" | "twofas" => Some(Format::TwoFas),
            "andotp" | "freeotp" | "freeotpplus" => Some(Format::AndOtp),
            "bitwarden" => Some(Format::Bitwarden),
            "google" | "googleauthenticator" | "gauth" | "migration" => {
                Some(Format::GoogleMigration)
            }
            _ => None,
        }
    }

    /// The formats `--format` accepts on export.
    ///
    /// Read-only formats are absent on purpose. Bitwarden's export is a whole
    /// password vault and writing one containing nothing but TOTP seeds would
    /// produce a file that imports as a set of empty logins; Google's migration
    /// payload is a QR code this app cannot draw (see Phase 19's decision about
    /// the CSP), so writing the URI behind it would be a format nothing reads.
    pub const EXPORTABLE: [Format; 3] = [Format::OtpauthList, Format::Aegis, Format::TwoFas];

    /// Whether [`build`] can write this format.
    pub fn is_exportable(self) -> bool {
        Format::EXPORTABLE.contains(&self)
    }
}

/// One seed read out of somebody else's export.
///
/// `issuer` and `account` are what the file said. They are *offered* to the
/// caller — the CLI turns them into a provider name and an account for a new
/// entry — and never overwrite an existing entry's own names, for the reason in
/// [`crate::totp`]: renaming an entry is what every `${ref}` addresses it by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Imported {
    pub issuer: Option<String>,
    pub account: Option<String>,
    #[serde(flatten)]
    pub stored: Stored,
    /// A note or tag the source app carried, when it had one.
    pub note: Option<String>,
}

impl Imported {
    /// The name an entry made from this should carry.
    ///
    /// Issuer first because that is what a user calls the service; the account
    /// alone is usually an email address, and a vault full of entries named
    /// `me@example.com` is a vault you cannot search.
    pub fn suggested_provider(&self) -> String {
        self.issuer
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                self.account
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or("Unnamed")
            .to_string()
    }
}

/// What a parse produced, including what it refused.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseReport {
    pub format: Format,
    pub items: Vec<Imported>,
    /// Entries that were recognised and could not be imported, each with a
    /// reason. Reported rather than dropped: a count that does not add up is
    /// how somebody discovers six months later that one account never came
    /// across.
    pub skipped: Vec<Skipped>,
}

/// One entry the parser declined, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skipped {
    /// Whatever the file called it. Never the secret.
    pub name: String,
    pub reason: String,
}

// ── Detection ─────────────────────────────────────────────────────────────────

/// Work out which app wrote this file.
///
/// Errors name the app and what to do, rather than saying "unrecognised" — the
/// encrypted variants are the common case for a user who has just pressed
/// "export" in an app that defaults to encrypting, and they are all detectable.
pub fn detect(text: &str) -> Result<Format, String> {
    let trimmed = text.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Err("the file is empty".into());
    }

    if trimmed.len() >= 18 && trimmed[..18].eq_ignore_ascii_case("otpauth-migration:") {
        return Ok(Format::GoogleMigration);
    }
    if trimmed.len() >= 8 && trimmed[..8].eq_ignore_ascii_case("otpauth:") {
        return Ok(Format::OtpauthList);
    }

    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        // Aegis. Encrypted vaults keep `header.slots` populated and store `db`
        // as a base64 string instead of an object.
        if v.get("db").is_some() && v.get("header").is_some() {
            let encrypted = v
                .pointer("/header/slots")
                .map(|s| !s.is_null())
                .unwrap_or(false)
                || v.get("db").map(|d| d.is_string()).unwrap_or(false);
            if encrypted {
                return Err(encrypted_msg(
                    "Aegis",
                    "Export again with encryption turned off",
                ));
            }
            return Ok(Format::Aegis);
        }
        // 2FAS.
        if v.get("services").is_some() || v.get("servicesEncrypted").is_some() {
            let encrypted = v
                .get("servicesEncrypted")
                .and_then(|s| s.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if encrypted {
                return Err(encrypted_msg(
                    "2FAS",
                    "Export again without a password set on the backup",
                ));
            }
            return Ok(Format::TwoFas);
        }
        // Bitwarden.
        if v.get("items").is_some() {
            if v.get("encrypted").and_then(|e| e.as_bool()) == Some(true) {
                return Err(encrypted_msg(
                    "Bitwarden",
                    "Export again as an unencrypted .json",
                ));
            }
            return Ok(Format::Bitwarden);
        }
        // andOTP: a bare array of objects carrying `secret`.
        if v.as_array()
            .map(|a| a.iter().any(|e| e.get("secret").is_some()))
            .unwrap_or(false)
        {
            return Ok(Format::AndOtp);
        }
        return Err(
            "recognised the file as JSON but not as an authenticator export \
             (expected Aegis, 2FAS, andOTP or Bitwarden)"
                .into(),
        );
    }

    // A plain-text list is the last guess, because it is the loosest: any file
    // with an otpauth:// URI somewhere in it qualifies, so it must not shadow a
    // format that identifies itself.
    if text.lines().any(|l| {
        let l = l.trim();
        l.len() >= 8 && l[..8].eq_ignore_ascii_case("otpauth:")
    }) {
        return Ok(Format::OtpauthList);
    }

    Err(
        "could not tell which authenticator app wrote this file. Supported: \
         Ente Auth and any otpauth:// list, Aegis, 2FAS, andOTP, Bitwarden, \
         Google Authenticator"
            .into(),
    )
}

fn encrypted_msg(app: &str, advice: &str) -> String {
    format!(
        "this is an *encrypted* {app} export. EnvVault will not try to decrypt \
         another app's vault — {advice}, import it here, then delete the \
         plaintext file."
    )
}

// ── Parsing ───────────────────────────────────────────────────────────────────

/// Read an export, detecting the format.
pub fn parse(text: &str) -> Result<ParseReport, String> {
    let format = detect(text)?;
    parse_as(text, format)
}

/// Read an export in a format the caller has already decided.
pub fn parse_as(text: &str, format: Format) -> Result<ParseReport, String> {
    let text = text.trim_start_matches('\u{feff}');
    let (items, skipped) = match format {
        Format::OtpauthList => parse_uri_list(text),
        Format::Aegis => parse_aegis(text)?,
        Format::TwoFas => parse_2fas(text)?,
        Format::AndOtp => parse_andotp(text)?,
        Format::Bitwarden => parse_bitwarden(text)?,
        Format::GoogleMigration => parse_google(text)?,
    };
    Ok(ParseReport {
        format,
        items,
        skipped,
    })
}

/// One `otpauth://` URI per line — Ente Auth's plain export, and the format
/// every other app will take back.
///
/// Blank lines and `#` comments are skipped in silence; anything else that is
/// not a URI is reported. Ente writes an extra `codeDisplay={…}` parameter
/// holding its own UI state, which the URI parser ignores along with every other
/// unknown parameter — that is why it is ignored rather than special-cased.
fn parse_uri_list(text: &str) -> (Vec<Imported>, Vec<Skipped>) {
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        match totp::parse_otpauth(line) {
            Ok(stored) => items.push(Imported {
                issuer: stored.issuer.clone(),
                account: stored.account.clone(),
                stored,
                note: None,
            }),
            Err(e) => skipped.push(Skipped {
                // The line number, never the line: a malformed URI still holds
                // the secret, and this string reaches stdout.
                name: format!("line {}", n + 1),
                reason: e,
            }),
        }
    }
    (items, skipped)
}

/// Build a `Stored` from the pieces every JSON format spells slightly
/// differently, defaulting whatever the file left out.
fn stored_from(
    secret: &str,
    algo: Option<&str>,
    digits: Option<u64>,
    period: Option<u64>,
) -> Result<Stored, String> {
    let defaults = Params::default();
    let params = Params {
        algorithm: algo
            .and_then(totp::Algorithm::parse)
            .unwrap_or(defaults.algorithm),
        digits: digits
            .map(|d| d as u32)
            .filter(|d| (totp::MIN_DIGITS..=totp::MAX_DIGITS).contains(d))
            .unwrap_or(defaults.digits),
        period: period
            .filter(|p| *p > 0 && *p <= totp::MAX_PERIOD_SECS)
            .unwrap_or(defaults.period),
    };
    // Goes through the same validator every other entry point uses, so a seed
    // an export mangled is refused here rather than stored unusable.
    let mut stored = totp::parse_seed(secret)?;
    stored.params = params;
    Ok(stored)
}

/// True when a format's type field names something counter-based.
fn is_hotp(kind: &str) -> bool {
    kind.trim().eq_ignore_ascii_case("hotp")
}

fn nonempty(v: Option<&str>) -> Option<String> {
    v.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn parse_aegis(text: &str) -> Result<(Vec<Imported>, Vec<Skipped>), String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let entries = v
        .pointer("/db/entries")
        .and_then(|e| e.as_array())
        .ok_or("this Aegis file has no db.entries array")?;
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for e in entries {
        let name = nonempty(e.get("name").and_then(|x| x.as_str()));
        let issuer = nonempty(e.get("issuer").and_then(|x| x.as_str()));
        let label = issuer
            .clone()
            .or_else(|| name.clone())
            .unwrap_or_else(|| "unnamed".into());
        let kind = e.get("type").and_then(|x| x.as_str()).unwrap_or("totp");
        if is_hotp(kind) {
            skipped.push(Skipped {
                name: label,
                reason: "counter-based (HOTP); EnvVault stores time-based seeds only".into(),
            });
            continue;
        }
        let secret = e
            .pointer("/info/secret")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        match stored_from(
            secret,
            e.pointer("/info/algo").and_then(|x| x.as_str()),
            e.pointer("/info/digits").and_then(|x| x.as_u64()),
            e.pointer("/info/period").and_then(|x| x.as_u64()),
        ) {
            Ok(stored) => items.push(Imported {
                issuer,
                account: name,
                stored,
                note: nonempty(e.get("note").and_then(|x| x.as_str())),
            }),
            Err(reason) => skipped.push(Skipped {
                name: label,
                reason,
            }),
        }
    }
    Ok((items, skipped))
}

fn parse_2fas(text: &str) -> Result<(Vec<Imported>, Vec<Skipped>), String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let services = v
        .get("services")
        .and_then(|s| s.as_array())
        .ok_or("this 2FAS file has no services array")?;
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for s in services {
        // 2FAS keeps the display name at the top level and the issuer inside
        // `otp`, and real backups have one or the other empty depending on how
        // the entry was added.
        let issuer = nonempty(s.pointer("/otp/issuer").and_then(|x| x.as_str()))
            .or_else(|| nonempty(s.get("name").and_then(|x| x.as_str())));
        let account = nonempty(s.pointer("/otp/account").and_then(|x| x.as_str()))
            .or_else(|| nonempty(s.pointer("/otp/label").and_then(|x| x.as_str())));
        let label = issuer
            .clone()
            .or_else(|| account.clone())
            .unwrap_or_else(|| "unnamed".into());
        let kind = s
            .pointer("/otp/tokenType")
            .and_then(|x| x.as_str())
            .unwrap_or("TOTP");
        if is_hotp(kind) {
            skipped.push(Skipped {
                name: label,
                reason: "counter-based (HOTP); EnvVault stores time-based seeds only".into(),
            });
            continue;
        }
        match stored_from(
            s.get("secret").and_then(|x| x.as_str()).unwrap_or(""),
            s.pointer("/otp/algorithm").and_then(|x| x.as_str()),
            s.pointer("/otp/digits").and_then(|x| x.as_u64()),
            s.pointer("/otp/period").and_then(|x| x.as_u64()),
        ) {
            Ok(stored) => items.push(Imported {
                issuer,
                account,
                stored,
                note: None,
            }),
            Err(reason) => skipped.push(Skipped {
                name: label,
                reason,
            }),
        }
    }
    Ok((items, skipped))
}

fn parse_andotp(text: &str) -> Result<(Vec<Imported>, Vec<Skipped>), String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let arr = v
        .as_array()
        .ok_or("an andOTP export is a JSON array of entries")?;
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for e in arr {
        let issuer = nonempty(e.get("issuer").and_then(|x| x.as_str()));
        let account = nonempty(e.get("label").and_then(|x| x.as_str()));
        let label = issuer
            .clone()
            .or_else(|| account.clone())
            .unwrap_or_else(|| "unnamed".into());
        let kind = e.get("type").and_then(|x| x.as_str()).unwrap_or("TOTP");
        if is_hotp(kind) {
            skipped.push(Skipped {
                name: label,
                reason: "counter-based (HOTP); EnvVault stores time-based seeds only".into(),
            });
            continue;
        }
        match stored_from(
            e.get("secret").and_then(|x| x.as_str()).unwrap_or(""),
            e.get("algorithm").and_then(|x| x.as_str()),
            e.get("digits").and_then(|x| x.as_u64()),
            e.get("period").and_then(|x| x.as_u64()),
        ) {
            Ok(stored) => items.push(Imported {
                issuer,
                account,
                stored,
                note: e
                    .get("tags")
                    .and_then(|t| t.as_array())
                    .map(|t| {
                        t.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .filter(|s| !s.is_empty()),
            }),
            Err(reason) => skipped.push(Skipped {
                name: label,
                reason,
            }),
        }
    }
    Ok((items, skipped))
}

/// Read `login.totp` out of a Bitwarden export.
///
/// Bitwarden stores either a bare base32 seed or a whole `otpauth://` URI in
/// that one field, depending on how the entry was created — which is exactly the
/// pair `parse_seed` already accepts, so both work with no branch here.
fn parse_bitwarden(text: &str) -> Result<(Vec<Imported>, Vec<Skipped>), String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let items_json = v
        .get("items")
        .and_then(|i| i.as_array())
        .ok_or("this Bitwarden file has no items array")?;
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for it in items_json {
        let raw = it
            .pointer("/login/totp")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if raw.trim().is_empty() {
            // Most items in a password export have no TOTP at all. That is not
            // a skip worth reporting — it would drown the ones that are.
            continue;
        }
        let name = nonempty(it.get("name").and_then(|x| x.as_str()));
        let account = nonempty(it.pointer("/login/username").and_then(|x| x.as_str()));
        let label = name.clone().unwrap_or_else(|| "unnamed".into());
        match totp::parse_seed(raw) {
            Ok(stored) => items.push(Imported {
                // A URI in this field carries its own issuer; the item's name is
                // the fallback, and is usually the better of the two.
                issuer: name.or_else(|| stored.issuer.clone()),
                account: account.or_else(|| stored.account.clone()),
                stored,
                note: None,
            }),
            Err(reason) => skipped.push(Skipped {
                name: label,
                reason,
            }),
        }
    }
    Ok((items, skipped))
}

// ── Google Authenticator migration payloads ──────────────────────────────────

/// Read `otpauth-migration://offline?data=…`.
///
/// The payload is a protobuf, and it is decoded by hand for the same reason
/// base32 is: pulling in `prost` and a build-time code generator to read one
/// message with seven scalar fields costs more than the forty lines below, and
/// those forty lines are what a reader has to check.
///
/// A multi-QR export produces several URIs, one per batch. Pass them one per
/// line and they accumulate; `batch_index` is not checked, because a user who
/// scanned three of four codes should get three accounts and be told, not get an
/// error and none.
fn parse_google(text: &str) -> Result<(Vec<Imported>, Vec<Skipped>), String> {
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    let mut any = false;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() < 18 || !line[..18].eq_ignore_ascii_case("otpauth-migration:") {
            skipped.push(Skipped {
                name: format!("line {}", n + 1),
                reason: "not an otpauth-migration:// URI".into(),
            });
            continue;
        }
        any = true;
        let data = line
            .split_once("data=")
            .map(|(_, d)| d.split('&').next().unwrap_or(d))
            .ok_or("the migration URI carries no data= parameter")?;
        let decoded = decode_migration_b64(data)?;
        let (mut got, mut bad) = decode_migration_payload(&decoded)?;
        items.append(&mut got);
        skipped.append(&mut bad);
    }
    if !any {
        return Err("no otpauth-migration:// URI in this file".into());
    }
    Ok((items, skipped))
}

/// Percent-decode then base64-decode a migration payload.
///
/// Both alphabets are tried: the URI is standard base64 percent-encoded, but
/// every tool that has ever copied one out of a QR reader writes it URL-safe,
/// and telling a user their QR code is corrupt because of an alphabet is a poor
/// answer.
fn decode_migration_b64(data: &str) -> Result<Vec<u8>, String> {
    let pct = percent_decode(data);
    let cleaned: String = pct.chars().filter(|c| !c.is_whitespace()).collect();
    use base64::engine::general_purpose as b64;
    [
        b64::STANDARD.decode(&cleaned),
        b64::STANDARD_NO_PAD.decode(&cleaned),
        b64::URL_SAFE.decode(&cleaned),
        b64::URL_SAFE_NO_PAD.decode(&cleaned),
    ]
    .into_iter()
    .flatten()
    .next()
    .ok_or_else(|| "the migration payload is not valid base64".to_string())
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        // `+` is base64's 62nd character *and* a form-encoded space. In a
        // migration URI it is always the former — the payload is base64 and a
        // space cannot appear in it — so it is left alone here, unlike in the
        // otpauth label parser where the opposite is true.
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A minimal protobuf reader: just enough for `MigrationPayload`.
struct Pb<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Pb<'a> {
    fn new(b: &'a [u8]) -> Self {
        Pb { b, i: 0 }
    }
    fn done(&self) -> bool {
        self.i >= self.b.len()
    }
    /// Base-128 varint. Caps the shift so a malformed payload cannot loop or
    /// overflow — this parses a file somebody else wrote.
    fn varint(&mut self) -> Result<u64, String> {
        let mut out: u64 = 0;
        let mut shift = 0;
        loop {
            if self.i >= self.b.len() {
                return Err("truncated migration payload".into());
            }
            let byte = self.b[self.i];
            self.i += 1;
            out |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(out);
            }
            shift += 7;
            if shift > 63 {
                return Err("malformed varint in migration payload".into());
            }
        }
    }
    /// Field key, returning `(field number, wire type)`.
    fn key(&mut self) -> Result<(u64, u8), String> {
        let k = self.varint()?;
        Ok((k >> 3, (k & 0x07) as u8))
    }
    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.varint()? as usize;
        let end = self
            .i
            .checked_add(len)
            .filter(|e| *e <= self.b.len())
            .ok_or("truncated length-delimited field")?;
        let out = &self.b[self.i..end];
        self.i = end;
        Ok(out)
    }
    /// Step over a field this reader does not care about.
    fn skip(&mut self, wire: u8) -> Result<(), String> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => self.i = self.i.saturating_add(8).min(self.b.len()),
            2 => {
                self.bytes()?;
            }
            5 => self.i = self.i.saturating_add(4).min(self.b.len()),
            _ => return Err(format!("unsupported protobuf wire type {wire}")),
        }
        Ok(())
    }
}

fn decode_migration_payload(bytes: &[u8]) -> Result<(Vec<Imported>, Vec<Skipped>), String> {
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    let mut p = Pb::new(bytes);
    while !p.done() {
        let (field, wire) = p.key()?;
        // Field 1 is the repeated OtpParameters; 2..=5 are version and batch
        // bookkeeping we do not need.
        if field == 1 && wire == 2 {
            let inner = p.bytes()?;
            match decode_otp_parameters(inner) {
                Ok(Some(item)) => items.push(item),
                Ok(None) => {}
                Err(s) => skipped.push(s),
            }
        } else {
            p.skip(wire)?;
        }
    }
    Ok((items, skipped))
}

/// One `OtpParameters` message. `Ok(None)` means "nothing wrong, nothing to
/// import" — which never happens today but keeps the caller honest if it does.
fn decode_otp_parameters(bytes: &[u8]) -> Result<Option<Imported>, Skipped> {
    let mut secret_raw: Vec<u8> = Vec::new();
    let mut name = String::new();
    let mut issuer = String::new();
    let mut algo = 1u64; // 1 = SHA1, and 0 (unspecified) means the same thing.
    let mut digits_enum = 1u64; // 1 = SIX
    let mut kind = 2u64; // 2 = TOTP

    let mut p = Pb::new(bytes);
    let named = |n: &str, i: &str| {
        if !i.is_empty() {
            i.to_string()
        } else if !n.is_empty() {
            n.to_string()
        } else {
            "unnamed".to_string()
        }
    };
    while !p.done() {
        let (field, wire) = p.key().map_err(|e| Skipped {
            name: named(&name, &issuer),
            reason: e,
        })?;
        let fail = |e: String| Skipped {
            name: named(&name, &issuer),
            reason: e,
        };
        match (field, wire) {
            (1, 2) => secret_raw = p.bytes().map_err(fail)?.to_vec(),
            (2, 2) => name = String::from_utf8_lossy(p.bytes().map_err(fail)?).into_owned(),
            (3, 2) => issuer = String::from_utf8_lossy(p.bytes().map_err(fail)?).into_owned(),
            (4, 0) => algo = p.varint().map_err(fail)?,
            (5, 0) => digits_enum = p.varint().map_err(fail)?,
            (6, 0) => kind = p.varint().map_err(fail)?,
            _ => p.skip(wire).map_err(fail)?,
        }
    }

    let label = named(&name, &issuer);
    // 1 = HOTP. It has no clock, so there is no current code to show.
    if kind == 1 {
        return Err(Skipped {
            name: label,
            reason: "counter-based (HOTP); EnvVault stores time-based seeds only".into(),
        });
    }
    if secret_raw.is_empty() {
        return Err(Skipped {
            name: label,
            reason: "the migration entry carries no secret".into(),
        });
    }

    // Google stores raw bytes; everything else in this module speaks base32.
    let secret = totp::base32_encode(&secret_raw);
    let params = Params {
        algorithm: match algo {
            2 => totp::Algorithm::Sha256,
            3 => totp::Algorithm::Sha512,
            // 0 (unspecified) and 1 (SHA1) are the same answer. 4 is MD5, which
            // RFC 6238 does not define and nothing generates; it falls here
            // rather than being refused, because a wrong algorithm is visible
            // immediately (the code is rejected) while a lost account is not.
            _ => totp::Algorithm::Sha1,
        },
        digits: if digits_enum == 2 { 8 } else { 6 },
        // The migration format has no period field at all: Google only ever
        // exports 30-second entries.
        period: totp::STEP_SECS,
    };
    let stored = Stored {
        secret,
        params,
        issuer: (!issuer.is_empty()).then(|| issuer.clone()),
        account: (!name.is_empty()).then(|| name.clone()),
    };
    Ok(Some(Imported {
        issuer: stored.issuer.clone(),
        account: stored.account.clone(),
        stored,
        note: None,
    }))
}

// ── Building ─────────────────────────────────────────────────────────────────

/// Write the seeds out in a format another app reads.
///
/// **Every byte of this is secret material** — the whole point of the file is to
/// carry seeds to another device. Callers treat it exactly as they treat a
/// `.vaultbak`: `--out` to a 0600 file, refused to stdout without `--reveal`.
pub fn build(items: &[Imported], format: Format) -> Result<String, String> {
    if !format.is_exportable() {
        return Err(format!(
            "'{}' can be imported but not written. Export with {} instead.",
            format.as_str(),
            Format::EXPORTABLE
                .iter()
                .map(|f| f.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(match format {
        Format::OtpauthList => build_uri_list(items),
        Format::Aegis => build_aegis(items),
        Format::TwoFas => build_2fas(items),
        _ => unreachable!("is_exportable covers every arm above"),
    })
}

fn build_uri_list(items: &[Imported]) -> String {
    let mut out = String::new();
    for it in items {
        out.push_str(&it.stored.to_uri(
            it.issuer.as_deref().unwrap_or(""),
            it.account.as_deref().unwrap_or(""),
        ));
        out.push('\n');
    }
    out
}

fn build_aegis(items: &[Imported]) -> String {
    let entries: Vec<Value> = items
        .iter()
        .map(|it| {
            serde_json::json!({
                "type": "totp",
                // Aegis keys its own entries by uuid; a stable one derived from
                // the seed means re-importing the same file twice updates rather
                // than duplicating.
                "uuid": stable_uuid(&it.stored.secret),
                "name": it.account.clone().unwrap_or_default(),
                "issuer": it.issuer.clone().unwrap_or_default(),
                "note": it.note.clone().unwrap_or_default(),
                "favorite": false,
                "icon": Value::Null,
                "info": {
                    "secret": it.stored.secret,
                    "algo": it.stored.params.algorithm.as_str(),
                    "digits": it.stored.params.digits,
                    "period": it.stored.params.period,
                }
            })
        })
        .collect();
    // `header.slots: null` is how Aegis marks a vault as unencrypted, and it is
    // required — an absent header is not the same thing and Aegis refuses it.
    let doc = serde_json::json!({
        "version": 1,
        "header": { "slots": Value::Null, "params": Value::Null },
        "db": { "version": 3, "entries": entries }
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

fn build_2fas(items: &[Imported]) -> String {
    let services: Vec<Value> = items
        .iter()
        .map(|it| {
            let issuer = it.issuer.clone().unwrap_or_default();
            let account = it.account.clone().unwrap_or_default();
            serde_json::json!({
                "name": if issuer.is_empty() { account.clone() } else { issuer.clone() },
                "secret": it.stored.secret,
                "updatedAt": 0,
                "otp": {
                    "label": if account.is_empty() { issuer.clone() } else { account.clone() },
                    "account": account,
                    "issuer": issuer,
                    "digits": it.stored.params.digits,
                    "period": it.stored.params.period,
                    "algorithm": it.stored.params.algorithm.as_str(),
                    "tokenType": "TOTP",
                    "source": "Manual",
                },
                "order": { "position": 0 },
                "icon": { "selected": "Label", "label": { "text": "", "backgroundColor": "Blue" } },
            })
        })
        .collect();
    let doc = serde_json::json!({
        "services": services,
        // 2FAS refuses a backup whose schemaVersion it does not know. 4 is the
        // oldest version every current build still reads.
        "schemaVersion": 4,
        "appVersionCode": 0,
        "appVersionName": "EnvVault",
        "appOrigin": "android",
        "servicesEncrypted": Value::Null,
        "reference": Value::Null,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// A UUID-shaped string derived from the seed.
///
/// Not a real UUID and not claimed to be one — Aegis only needs the field to be
/// stable and unique per entry. Deriving it from the seed is what makes a second
/// import of the same file an update rather than a duplicate; a random one would
/// give the user two of everything on the second try.
///
/// It is a hash, so the file does not leak the seed through this field. The file
/// contains the seed anyway, which is why the whole thing is a materialising
/// path — but a field that *looked* opaque and was not would be worse.
fn stable_uuid(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("envvault-aegis-uuid:{secret}").as_bytes());
    let hex: String = h.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

// ── Merging an import into a vault ───────────────────────────────────────────
//
// The rules live here rather than in the CLI because they decide whether a
// working second factor survives an import, and a rule like that must not be
// able to differ between the app and the terminal. `envv totp import` and the
// desktop app's Import button both call [`plan`] and [`apply`].

/// Normalised key for "is this the same account?".
///
/// Provider and account together, case-folded and trimmed. Neither alone is
/// enough: two GitHub accounts are two entries, and two services can share an
/// email address. Case-folded because exports capitalise inconsistently —
/// "GitHub" in one app, "github" in the next — and a case-sensitive match
/// silently duplicates every account.
fn match_key(provider: &str, account: &str) -> (String, String) {
    (
        provider.trim().to_lowercase(),
        account.trim().to_lowercase(),
    )
}

/// What an import would do to one incoming seed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Plan {
    /// No entry matches provider+account; make one.
    Create,
    /// An entry matches and carries no seed, or `force` was set.
    Update { index: usize },
    /// An entry matches and already holds this exact seed. Doing nothing is
    /// what makes re-running an import idempotent.
    Unchanged { index: usize },
    /// An entry matches and holds a **different** seed. Reported, never
    /// overwritten without `force`.
    Conflict { index: usize },
}

/// Decide, for each incoming seed, what should happen to it.
///
/// The rule that matters is [`Plan::Conflict`]. A stored second factor is not
/// recoverable from EnvVault's side once it is gone, and an import is exactly
/// the moment a stale export gets pointed at a vault that has since been
/// re-enrolled. Silently taking the incoming value there would lock the user out
/// of an account at the moment they believe they are backing one up.
pub fn plan(entries: &[Value], items: &[Imported], force: bool) -> Vec<Plan> {
    let existing: std::collections::HashMap<(String, String), usize> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            (
                match_key(
                    e.get("provider").and_then(|v| v.as_str()).unwrap_or(""),
                    e.get("account_name").and_then(|v| v.as_str()).unwrap_or(""),
                ),
                i,
            )
        })
        .collect();

    items
        .iter()
        .map(|item| {
            let key = match_key(
                &item.suggested_provider(),
                item.account.as_deref().unwrap_or(""),
            );
            let Some(&index) = existing.get(&key) else {
                return Plan::Create;
            };
            let current = entries[index]
                .get("totp_secret")
                .and_then(|v| v.as_str())
                .map(totp::normalize_b32)
                .unwrap_or_default();
            if current == item.stored.secret {
                Plan::Unchanged { index }
            } else if current.is_empty() || force {
                Plan::Update { index }
            } else {
                Plan::Conflict { index }
            }
        })
        .collect()
}

/// Write a seed and its parameters onto an entry.
///
/// Parameters equal to the default are **removed**, not written: a field that
/// reads "SHA1" on every entry cannot be told apart from a defaulted one, and
/// removing rather than skipping is what makes re-importing a 60-second seed as
/// a 30-second one actually clear the old period.
pub fn write_fields(entry: &mut Value, stored: &Stored) {
    let defaults = Params::default();
    entry["totp_secret"] = Value::String(stored.secret.clone());
    let Some(o) = entry.as_object_mut() else {
        return;
    };
    if stored.params.algorithm == defaults.algorithm {
        o.remove("totp_algorithm");
    } else {
        o.insert(
            "totp_algorithm".into(),
            Value::String(stored.params.algorithm.as_str().into()),
        );
    }
    if stored.params.digits == defaults.digits {
        o.remove("totp_digits");
    } else {
        o.insert("totp_digits".into(), Value::from(stored.params.digits));
    }
    if stored.params.period == defaults.period {
        o.remove("totp_period");
    } else {
        o.insert("totp_period".into(), Value::from(stored.params.period));
    }
}

/// Build a fresh entry for a seed that matched nothing in the vault.
///
/// `secretType` is `password`, not `api_key`: a TOTP seed is a login's second
/// factor, and the password form is the one with a username field for the
/// account to live in. `api_key` is empty because there is no password beside it
/// yet — which is why the add/edit form lets an entry carrying a seed skip its
/// "value is required" check.
pub fn new_entry(
    item: &Imported,
    id: &str,
    now: &str,
    project: Option<&str>,
    category: Option<&str>,
) -> Value {
    let account = item.account.clone().unwrap_or_default();
    let mut projects = vec![Value::String("Universal".into())];
    if let Some(p) = project.filter(|p| *p != "Universal") {
        projects.push(Value::String(p.into()));
    }
    let mut e = serde_json::json!({
        "id": id,
        "provider": item.suggested_provider(),
        "api_key": "",
        "secretType": "password",
        "price_type": "free",
        "categories": category.map(|c| vec![Value::String(c.into())]).unwrap_or_default(),
        "projectIds": projects,
        "scopes": [],
        "created_at": now,
    });
    if !account.is_empty() {
        e["account_name"] = Value::String(account.clone());
        // Nearly always the login name, and the password form shows a username.
        e["username"] = Value::String(account);
    }
    if let Some(note) = &item.note {
        e["description"] = Value::String(note.clone());
    }
    write_fields(&mut e, &item.stored);
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "Hello!\u{0}\u{0}" — the RFC 4648 example, and a seed short enough to read.
    const SEED: &str = "JBSWY3DPEHPK3PXP";

    fn one(items: &[Imported]) -> &Imported {
        assert_eq!(items.len(), 1, "expected exactly one item: {items:?}");
        &items[0]
    }

    // ── Detection ───────────────────────────────────────────────────────────

    #[test]
    fn every_supported_format_is_recognised_from_its_own_bytes() {
        // Detection has to be right before anything else can be: guessing wrong
        // means parsing an Aegis file as andOTP and reporting "no entries",
        // which tells the user nothing about what actually happened.
        let cases: [(&str, Format); 6] = [
            (
                "otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP",
                Format::OtpauthList,
            ),
            (
                "otpauth-migration://offline?data=CjEKCkhlbGxvIePop-8SEmpvaG5AZXhhbXBsZS5jb20aBUFjbWUgIAEoATACEAEYASAA",
                Format::GoogleMigration,
            ),
            (
                r#"{"version":1,"header":{"slots":null,"params":null},"db":{"version":3,"entries":[]}}"#,
                Format::Aegis,
            ),
            (r#"{"services":[],"schemaVersion":4}"#, Format::TwoFas),
            (r#"[{"secret":"JBSWY3DPEHPK3PXP","label":"a"}]"#, Format::AndOtp),
            (r#"{"encrypted":false,"items":[]}"#, Format::Bitwarden),
        ];
        for (text, want) in cases {
            assert_eq!(detect(text).unwrap(), want, "detecting {want:?}");
        }
    }

    #[test]
    fn an_encrypted_export_is_refused_by_name_rather_than_failing_to_parse() {
        // This is the common case for somebody who just pressed "export" in an
        // app that encrypts by default. "Unrecognised file" would send them
        // looking for a bug; naming the app and the fix does not.
        let aegis = r#"{"version":1,"header":{"slots":[{"type":1}],"params":{}},"db":"AAAA"}"#;
        let err = detect(aegis).expect_err("encrypted Aegis must be refused");
        assert!(err.contains("Aegis"), "{err}");
        assert!(err.contains("encrypt"), "{err}");

        let twofas = r#"{"services":[],"servicesEncrypted":"deadbeef","schemaVersion":4}"#;
        let err = detect(twofas).expect_err("encrypted 2FAS must be refused");
        assert!(err.contains("2FAS"), "{err}");

        let bw = r#"{"encrypted":true,"items":[]}"#;
        let err = detect(bw).expect_err("encrypted Bitwarden must be refused");
        assert!(err.contains("Bitwarden"), "{err}");
    }

    #[test]
    fn detection_never_panics_on_junk() {
        // A file picker hands this whatever the user chose.
        for junk in ["", "   ", "\u{feff}", "not json {", "\0\0\0", "[]", "{}"] {
            let _ = detect(junk);
        }
    }

    // ── Ente / otpauth lists ────────────────────────────────────────────────

    #[test]
    fn an_ente_plain_export_imports_including_its_codedisplay_parameter() {
        // Ente writes its own UI state into an extra `codeDisplay` parameter.
        // The URI parser ignores unknown parameters, which is why this needs no
        // special case — but it needs a test, because "ignored" and "chokes on"
        // look identical until somebody tries it.
        let text = concat!(
            "otpauth://totp/Acme:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme",
            "&algorithm=SHA1&digits=6&period=30",
            "&codeDisplay=%7B%22pinned%22%3Afalse%2C%22trashed%22%3Afalse%7D\n",
            "\n",
            "# a comment Ente does not write, but a hand-edited file might\n",
            "otpauth://totp/Other?secret=MZXW6YTBOI&digits=8&period=60&algorithm=SHA512\n",
        );
        let r = parse(text).unwrap();
        assert_eq!(r.format, Format::OtpauthList);
        assert_eq!(r.items.len(), 2);
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);
        assert_eq!(r.items[0].stored.secret, SEED);
        assert_eq!(r.items[0].issuer.as_deref(), Some("Acme"));
        assert_eq!(r.items[0].account.as_deref(), Some("me@example.com"));
        assert_eq!(r.items[1].stored.params.digits, 8);
        assert_eq!(r.items[1].stored.params.period, 60);
        assert_eq!(r.items[1].stored.params.algorithm, totp::Algorithm::Sha512);
    }

    #[test]
    fn a_bad_line_is_reported_by_line_number_and_never_by_content() {
        // A malformed URI still holds a secret, and this string reaches stdout.
        let text = "otpauth://totp/Ok?secret=JBSWY3DPEHPK3PXP\n\
                    otpauth://totp/Bad?secret=NOTBASE32!!!\n\
                    otpauth://hotp/Counter?secret=JBSWY3DPEHPK3PXP&counter=1\n";
        let r = parse(text).unwrap();
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.skipped.len(), 2);
        for s in &r.skipped {
            assert!(s.name.starts_with("line "), "{s:?}");
            assert!(!s.reason.contains("NOTBASE32"), "{s:?}");
        }
        assert!(r.skipped[1].reason.contains("hotp"), "{:?}", r.skipped[1]);
    }

    // ── The JSON formats ────────────────────────────────────────────────────

    #[test]
    fn an_aegis_vault_imports_with_its_parameters_and_note() {
        let text = r#"{
          "version": 1,
          "header": { "slots": null, "params": null },
          "db": { "version": 3, "entries": [
            { "type": "totp", "uuid": "x", "name": "me@example.com", "issuer": "Acme",
              "note": "work laptop", "favorite": false, "icon": null,
              "info": { "secret": "JBSWY3DPEHPK3PXP", "algo": "SHA256", "digits": 8, "period": 60 } },
            { "type": "hotp", "uuid": "y", "name": "counter", "issuer": "Old",
              "info": { "secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 6, "counter": 3 } }
          ] }
        }"#;
        let r = parse(text).unwrap();
        assert_eq!(r.format, Format::Aegis);
        let it = one(&r.items);
        assert_eq!(it.stored.secret, SEED);
        assert_eq!(it.stored.params.algorithm, totp::Algorithm::Sha256);
        assert_eq!(it.stored.params.digits, 8);
        assert_eq!(it.stored.params.period, 60);
        assert_eq!(it.issuer.as_deref(), Some("Acme"));
        assert_eq!(it.account.as_deref(), Some("me@example.com"));
        assert_eq!(it.note.as_deref(), Some("work laptop"));
        // The HOTP entry is named in the report rather than vanishing.
        assert_eq!(r.skipped.len(), 1);
        assert_eq!(r.skipped[0].name, "Old");
    }

    #[test]
    fn a_2fas_backup_imports_from_either_place_it_keeps_the_name() {
        // Real backups have `otp.issuer` empty for entries added by hand and
        // `name` empty for some scanned ones, so both have to be read.
        let text = r#"{
          "services": [
            { "name": "Acme", "secret": "JBSWY3DPEHPK3PXP",
              "otp": { "label": "me", "account": "me", "issuer": "Acme",
                       "digits": 6, "period": 30, "algorithm": "SHA1", "tokenType": "TOTP" } },
            { "name": "Fallback", "secret": "MZXW6YTBOI",
              "otp": { "label": "lbl", "tokenType": "TOTP" } },
            { "name": "Counter", "secret": "JBSWY3DPEHPK3PXP",
              "otp": { "label": "c", "tokenType": "HOTP" } }
          ],
          "schemaVersion": 4
        }"#;
        let r = parse(text).unwrap();
        assert_eq!(r.format, Format::TwoFas);
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[0].issuer.as_deref(), Some("Acme"));
        // No `otp.issuer`: the top-level name stands in.
        assert_eq!(r.items[1].issuer.as_deref(), Some("Fallback"));
        assert_eq!(r.items[1].account.as_deref(), Some("lbl"));
        // Omitted parameters mean the defaults.
        assert!(r.items[1].stored.params.is_default());
        assert_eq!(r.skipped.len(), 1);
    }

    #[test]
    fn an_andotp_export_imports_with_its_tags_as_the_note() {
        let text = r#"[
          { "secret": "JBSWY3DPEHPK3PXP", "issuer": "Acme", "label": "me",
            "digits": 6, "type": "TOTP", "algorithm": "SHA1", "period": 30,
            "tags": ["work", "critical"] }
        ]"#;
        let r = parse(text).unwrap();
        assert_eq!(r.format, Format::AndOtp);
        let it = one(&r.items);
        assert_eq!(it.stored.secret, SEED);
        assert_eq!(it.note.as_deref(), Some("work, critical"));
    }

    #[test]
    fn a_bitwarden_export_reads_login_totp_in_both_spellings() {
        // Bitwarden stores a bare seed or a whole URI in the same field,
        // depending on how the item was created.
        let text = r#"{ "encrypted": false, "items": [
          { "type": 1, "name": "Plain", "login": { "username": "u1", "totp": "JBSWY3DPEHPK3PXP" } },
          { "type": 1, "name": "Uri", "login": { "username": "u2",
            "totp": "otpauth://totp/Ignored:x?secret=MZXW6YTBOI&digits=8" } },
          { "type": 1, "name": "NoTotp", "login": { "username": "u3", "password": "p" } },
          { "type": 2, "name": "SecureNote" }
        ] }"#;
        let r = parse(text).unwrap();
        assert_eq!(r.format, Format::Bitwarden);
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[0].stored.secret, SEED);
        assert_eq!(r.items[0].account.as_deref(), Some("u1"));
        assert_eq!(r.items[1].stored.params.digits, 8);
        // The item's own name beats the URI's issuer: it is the one the user
        // chose, and the URI's half is usually whatever the site sent.
        assert_eq!(r.items[1].issuer.as_deref(), Some("Uri"));
        // Items with no TOTP are not "skipped" — in a password export they are
        // the overwhelming majority and would drown the real report.
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    }

    // ── Google Authenticator ────────────────────────────────────────────────

    /// Hand-built `MigrationPayload`, so the test does not depend on owning a
    /// phone. Field numbers are from Google's `otpauth-migration` schema.
    fn google_payload(
        secret: &[u8],
        name: &str,
        issuer: &str,
        algo: u8,
        digits: u8,
        kind: u8,
    ) -> String {
        fn varint(out: &mut Vec<u8>, mut v: u64) {
            loop {
                let mut b = (v & 0x7f) as u8;
                v >>= 7;
                if v != 0 {
                    b |= 0x80;
                }
                out.push(b);
                if v == 0 {
                    break;
                }
            }
        }
        fn field_bytes(out: &mut Vec<u8>, num: u64, data: &[u8]) {
            varint(out, (num << 3) | 2);
            varint(out, data.len() as u64);
            out.extend_from_slice(data);
        }
        fn field_varint(out: &mut Vec<u8>, num: u64, v: u64) {
            varint(out, num << 3);
            varint(out, v);
        }

        let mut params = Vec::new();
        field_bytes(&mut params, 1, secret);
        field_bytes(&mut params, 2, name.as_bytes());
        field_bytes(&mut params, 3, issuer.as_bytes());
        field_varint(&mut params, 4, u64::from(algo));
        field_varint(&mut params, 5, u64::from(digits));
        field_varint(&mut params, 6, u64::from(kind));

        let mut payload = Vec::new();
        field_bytes(&mut payload, 1, &params);
        field_varint(&mut payload, 2, 1); // version
        field_varint(&mut payload, 3, 1); // batch_size
        field_varint(&mut payload, 4, 0); // batch_index

        let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        let pct: String = b64
            .chars()
            .map(|c| match c {
                '+' => "%2B".to_string(),
                '/' => "%2F".to_string(),
                '=' => "%3D".to_string(),
                c => c.to_string(),
            })
            .collect();
        format!("otpauth-migration://offline?data={pct}")
    }

    #[test]
    fn a_google_migration_payload_decodes_to_the_same_seed_google_encoded() {
        // Google stores the secret as raw bytes; everything else in this module
        // speaks base32. Getting that conversion wrong produces a seed that is
        // the right length and the wrong value — six plausible digits that are
        // rejected, with nothing on screen saying why.
        let raw = totp::base32_decode(SEED).unwrap();
        let uri = google_payload(&raw, "me@example.com", "Acme", 1, 1, 2);
        let r = parse(&uri).unwrap();
        assert_eq!(r.format, Format::GoogleMigration);
        let it = one(&r.items);
        assert_eq!(it.stored.secret, SEED);
        assert_eq!(it.issuer.as_deref(), Some("Acme"));
        assert_eq!(it.account.as_deref(), Some("me@example.com"));
        // The migration format has no period field: Google only exports 30s.
        assert!(it.stored.params.is_default());
    }

    #[test]
    fn the_migration_enums_map_to_the_right_algorithm_and_digit_count() {
        let raw = totp::base32_decode(SEED).unwrap();
        for (algo_enum, want) in [
            (0u8, totp::Algorithm::Sha1), // unspecified means SHA-1
            (1, totp::Algorithm::Sha1),
            (2, totp::Algorithm::Sha256),
            (3, totp::Algorithm::Sha512),
        ] {
            let uri = google_payload(&raw, "n", "i", algo_enum, 1, 2);
            assert_eq!(
                parse(&uri).unwrap().items[0].stored.params.algorithm,
                want,
                "algorithm enum {algo_enum}"
            );
        }
        // The digit count is an enum, not a number: 1 is SIX and 2 is EIGHT.
        let six = google_payload(&raw, "n", "i", 1, 1, 2);
        let eight = google_payload(&raw, "n", "i", 1, 2, 2);
        assert_eq!(parse(&six).unwrap().items[0].stored.params.digits, 6);
        assert_eq!(parse(&eight).unwrap().items[0].stored.params.digits, 8);
    }

    #[test]
    fn a_counter_based_migration_entry_is_named_rather_than_dropped() {
        let raw = totp::base32_decode(SEED).unwrap();
        let uri = google_payload(&raw, "counter", "Old", 1, 1, 1); // kind 1 = HOTP
        let r = parse(&uri).unwrap();
        assert!(r.items.is_empty());
        assert_eq!(r.skipped.len(), 1);
        assert_eq!(r.skipped[0].name, "Old");
        assert!(r.skipped[0].reason.contains("HOTP"), "{:?}", r.skipped[0]);
    }

    #[test]
    fn several_migration_uris_accumulate_rather_than_conflicting() {
        // A large export is several QR codes. Somebody who scanned three of four
        // should get three accounts and be told, not get an error and none.
        let raw = totp::base32_decode(SEED).unwrap();
        let text = format!(
            "{}\n{}\n",
            google_payload(&raw, "a", "One", 1, 1, 2),
            google_payload(&raw, "b", "Two", 1, 1, 2)
        );
        let r = parse(&text).unwrap();
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[1].issuer.as_deref(), Some("Two"));
    }

    #[test]
    fn a_truncated_or_junk_migration_payload_errors_rather_than_panicking() {
        // This parses bytes from a QR code somebody else generated. Every length
        // in it is attacker-controlled as far as this function is concerned.
        for bad in [
            "otpauth-migration://offline?data=",
            "otpauth-migration://offline?data=!!!!",
            "otpauth-migration://offline?data=CjEKCg", // truncated mid-field
            "otpauth-migration://offline?data=%FF%FF%FF%FF",
        ] {
            let _ = parse(bad);
        }
        // And a length header claiming more bytes than exist.
        let payload = base64::engine::general_purpose::STANDARD.encode([0x0a, 0x7f, 0x01]);
        let r = parse(&format!("otpauth-migration://offline?data={payload}"));
        assert!(r.is_err(), "a lying length prefix must not be accepted");
    }

    // ── Building ────────────────────────────────────────────────────────────

    fn sample() -> Vec<Imported> {
        vec![
            Imported {
                issuer: Some("Acme".into()),
                account: Some("me@example.com".into()),
                stored: Stored {
                    secret: SEED.into(),
                    params: Params::default(),
                    issuer: None,
                    account: None,
                },
                note: Some("work".into()),
            },
            Imported {
                issuer: Some("Other".into()),
                account: None,
                stored: Stored {
                    secret: "MZXW6YTBOI".into(),
                    params: Params {
                        algorithm: totp::Algorithm::Sha512,
                        digits: 8,
                        period: 45,
                    },
                    issuer: None,
                    account: None,
                },
                note: None,
            },
        ]
    }

    #[test]
    fn every_exportable_format_reads_back_through_this_modules_own_parser() {
        // The round trip is the property that matters, not the bytes: a file
        // that cannot be read back is one the destination app will not read
        // either, and the user finds that out on a phone with no other copy.
        for format in Format::EXPORTABLE {
            let text = build(&sample(), format).unwrap();
            let back = parse(&text)
                .unwrap_or_else(|e| panic!("{} did not read back: {e}", format.as_str()));
            assert_eq!(
                back.format, format,
                "detected the wrong format for {format:?}"
            );
            assert_eq!(back.items.len(), 2, "{format:?}");
            for (a, b) in sample().iter().zip(back.items.iter()) {
                assert_eq!(a.stored.secret, b.stored.secret, "{format:?}");
                assert_eq!(a.stored.params, b.stored.params, "{format:?}");
                assert_eq!(a.issuer, b.issuer, "{format:?}");
            }
        }
    }

    #[test]
    fn a_read_only_format_is_refused_by_name_with_the_alternatives() {
        for format in [Format::Bitwarden, Format::GoogleMigration, Format::AndOtp] {
            let err = build(&sample(), format).expect_err("must refuse");
            assert!(err.contains(format.as_str()), "{err}");
            assert!(err.contains("otpauth"), "{err}");
        }
    }

    #[test]
    fn the_aegis_uuid_is_stable_across_builds_so_a_re_import_updates() {
        // A random uuid would give the user two of everything the second time
        // they imported the same file.
        let a = build(&sample(), Format::Aegis).unwrap();
        let b = build(&sample(), Format::Aegis).unwrap();
        assert_eq!(a, b);
        // And it does not carry the seed it is derived from.
        assert!(!a.contains(&format!("\"uuid\": \"{SEED}\"")));
    }

    #[test]
    fn aegis_marks_the_vault_unencrypted_the_way_aegis_requires() {
        // `header.slots: null` is the marker. An absent header is not the same
        // thing, and Aegis refuses the file rather than importing it.
        let v: Value = serde_json::from_str(&build(&sample(), Format::Aegis).unwrap()).unwrap();
        assert!(v.pointer("/header/slots").unwrap().is_null());
        assert_eq!(
            v.pointer("/db/entries").unwrap().as_array().unwrap().len(),
            2
        );
    }

    #[test]
    fn format_names_round_trip_and_ente_is_an_alias_for_the_uri_list() {
        for f in [
            Format::OtpauthList,
            Format::Aegis,
            Format::TwoFas,
            Format::AndOtp,
            Format::Bitwarden,
            Format::GoogleMigration,
        ] {
            assert_eq!(Format::parse(f.as_str()), Some(f), "{f:?}");
        }
        // Ente's plain export *is* an otpauth list, and somebody holding one
        // will type --format ente. Refusing it would be pedantry.
        assert_eq!(Format::parse("ente"), Some(Format::OtpauthList));
        assert_eq!(Format::parse("Ente"), Some(Format::OtpauthList));
        assert_eq!(Format::parse("2FAS"), Some(Format::TwoFas));
        assert_eq!(
            Format::parse("google-authenticator"),
            Some(Format::GoogleMigration)
        );
        assert_eq!(Format::parse("nonsense"), None);
    }

    #[test]
    fn suggested_provider_prefers_the_issuer_over_an_email_address() {
        // A vault of forty entries all called me@example.com is a vault you
        // cannot search.
        let mut it = sample().remove(0);
        assert_eq!(it.suggested_provider(), "Acme");
        it.issuer = None;
        assert_eq!(it.suggested_provider(), "me@example.com");
        it.account = Some("   ".into());
        assert_eq!(it.suggested_provider(), "Unnamed");
    }

    // ── Merge rules ─────────────────────────────────────────────────────────

    fn entry(provider: &str, account: &str, seed: Option<&str>) -> Value {
        let mut e = serde_json::json!({
            "id": provider, "provider": provider, "api_key": "",
            "account_name": account, "categories": [], "projectIds": ["Universal"], "scopes": []
        });
        if let Some(s) = seed {
            e["totp_secret"] = Value::String(s.into());
        }
        e
    }

    fn incoming(issuer: &str, account: &str, seed: &str) -> Imported {
        Imported {
            issuer: Some(issuer.into()),
            account: Some(account.into()),
            stored: totp::parse_seed(seed).expect("fixture seed parses"),
            note: None,
        }
    }

    const OTHER: &str = "MZXW6YTBOI";

    #[test]
    fn an_unmatched_account_is_created() {
        assert_eq!(
            plan(&[], &[incoming("Acme", "me", SEED)], false),
            [Plan::Create]
        );
    }

    #[test]
    fn an_entry_with_no_seed_yet_is_updated_rather_than_duplicated() {
        // The common case: the vault already holds the password for this login
        // and the import is adding its second factor beside it. Creating a
        // second entry would split one credential across two cards.
        let vault = [entry("Acme", "me", None)];
        assert_eq!(
            plan(&vault, &[incoming("Acme", "me", SEED)], false),
            [Plan::Update { index: 0 }]
        );
    }

    #[test]
    fn re_running_the_same_import_changes_nothing() {
        // Idempotence is what makes an import safe to retry after it half-failed.
        let vault = [entry("Acme", "me", Some(SEED))];
        assert_eq!(
            plan(&vault, &[incoming("Acme", "me", SEED)], false),
            [Plan::Unchanged { index: 0 }]
        );
    }

    #[test]
    fn a_different_stored_seed_is_a_conflict_and_not_an_overwrite() {
        // The failure this exists to prevent: pointing a stale export at a vault
        // that has since been re-enrolled silently replaces a working second
        // factor with a dead one, at the moment the user believes they are
        // backing it up.
        let vault = [entry("Acme", "me", Some(SEED))];
        assert_eq!(
            plan(&vault, &[incoming("Acme", "me", OTHER)], false),
            [Plan::Conflict { index: 0 }]
        );
        assert_eq!(
            plan(&vault, &[incoming("Acme", "me", OTHER)], true),
            [Plan::Update { index: 0 }],
            "--force is how you say you meant it"
        );
    }

    #[test]
    fn matching_needs_both_the_provider_and_the_account() {
        // Two accounts at one service are two entries; two services can share an
        // email address. Matching on either alone merges credentials that are
        // not the same credential.
        let vault = [entry("Acme", "me", Some(SEED)), entry("Other", "me", None)];
        assert_eq!(
            plan(
                &vault,
                &[
                    incoming("Acme", "someone-else", OTHER),
                    incoming("Other", "me", OTHER),
                ],
                false
            ),
            [Plan::Create, Plan::Update { index: 1 }]
        );
    }

    #[test]
    fn matching_ignores_case_and_surrounding_space() {
        // "GitHub" in one app, "github" in the next. A case-sensitive match
        // silently duplicates every account.
        let vault = [entry("GitHub", "Me@Example.com", None)];
        assert_eq!(
            plan(
                &vault,
                &[incoming(" github ", "me@example.com", SEED)],
                false
            ),
            [Plan::Update { index: 0 }]
        );
    }

    #[test]
    fn a_seed_spelled_differently_is_still_the_same_seed() {
        // A stored seed written with the grouping spaces must not read as a
        // conflict against the same seed written without them.
        let vault = [entry("Acme", "me", Some("jbsw y3dp ehpk 3pxp"))];
        assert_eq!(
            plan(&vault, &[incoming("Acme", "me", SEED)], false),
            [Plan::Unchanged { index: 0 }]
        );
    }

    #[test]
    fn write_fields_clears_a_parameter_that_returned_to_its_default() {
        // Removing rather than skipping is the point: re-importing a 60-second
        // seed as a 30-second one has to actually clear the old period, or the
        // entry keeps generating against a period nothing sent it.
        let mut e = serde_json::json!({ "provider": "A", "totp_period": 60, "totp_digits": 8 });
        write_fields(
            &mut e,
            &Stored {
                secret: SEED.into(),
                params: Params::default(),
                issuer: None,
                account: None,
            },
        );
        assert_eq!(e["totp_secret"], SEED);
        assert!(e.get("totp_period").is_none(), "{e}");
        assert!(e.get("totp_digits").is_none(), "{e}");
    }

    #[test]
    fn a_new_entry_carries_the_account_into_username_and_stays_in_universal() {
        let it = incoming("Acme", "me@example.com", SEED);
        let e = new_entry(
            &it,
            "id-1",
            "2026-09-10T00:00:00Z",
            Some("web"),
            Some("2fa"),
        );
        assert_eq!(e["provider"], "Acme");
        assert_eq!(e["secretType"], "password");
        assert_eq!(e["api_key"], "");
        assert_eq!(e["account_name"], "me@example.com");
        assert_eq!(e["username"], "me@example.com");
        assert_eq!(e["totp_secret"], SEED);
        assert_eq!(e["categories"], serde_json::json!(["2fa"]));
        // A specific project never replaces Universal — every entry carries it.
        assert_eq!(e["projectIds"], serde_json::json!(["Universal", "web"]));
    }
}
