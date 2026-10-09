//! RFC 6238 time-based one-time passwords.
//!
//! # Two callers, one generator
//!
//! Phase 19 added this module for **sub-user login**: UnENVerse checking a code
//! its own user typed. Phase 22 added the mirror image — a TOTP seed the vault
//! *stores on behalf of a third party*, the way Bitwarden and 1Password hold an
//! authenticator entry, where UnENVerse produces the code and a website checks
//! it.
//!
//! They share every line of arithmetic and deliberately nothing else. The login
//! path is fixed at SHA-1/6 digits/30 seconds because that is what this product
//! mints and there is no interoperability question; the stored-seed path is
//! parameterised ([`Params`]) because the issuer chose those numbers years ago
//! and a generator that cannot follow is a generator that produces confidently
//! wrong codes. Only the login path has an anti-replay mark — see [`verify`] —
//! because only the login path is a verifier.
//!
//! # Why this exists twice
//!
//! Phase 5.1 shipped a TOTP implementation and Phase 7 removed it, because
//! nothing in the product ever reached it: there was no enrollment surface, no
//! CLI verb and no UI, so the only thing the code did was carry a schema column.
//! It comes back here with all three, and with the anti-replay rule that the
//! original had — see [`verify`].
//!
//! # Sub-users only, deliberately
//!
//! The vault owner authenticates by deriving the SQLCipher key from the master
//! password. There is no stored hash to check and therefore nothing for a second
//! factor to gate: an attacker who can derive the key does not go through a login
//! form, they open the file. Offering the owner a TOTP toggle would be a control
//! that protects nothing while looking as though it protects everything.
//!
//! # No new crates
//!
//! `hmac` is already a dependency (`entropy.rs` builds HKDF on it), `sha1` is
//! added for the one algorithm RFC 6238 pins for interoperability, and `sha2`
//! was already here for the KDF — which is the whole cost of supporting the
//! SHA-256 and SHA-512 variants a stored third-party seed may name. Base32 is
//! forty lines and lives here rather than behind a crate, for the same reason
//! HKDF does: the encoding is part of what a reader has to check.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// Digits in a generated code. Six is what every authenticator app assumes when
/// the `otpauth://` URI omits the parameter, and omitting it is what keeps the
/// QR-less manual-entry path working.
pub const DIGITS: u32 = 6;

/// Seconds per counter step. RFC 6238's recommended default.
pub const STEP_SECS: u64 = 30;

/// How many steps either side of the current one are accepted.
///
/// One step is 30 seconds, so a window of 1 tolerates a phone clock up to 30
/// seconds out in either direction. Anything larger widens the replay window
/// that [`verify`]'s `last_step` argument exists to close.
pub const SKEW_STEPS: i64 = 1;

/// Bytes of secret material. RFC 4226 requires at least 128 bits and recommends
/// 160 — which is also the SHA-1 block output, so nothing is truncated.
pub const SECRET_BYTES: usize = 20;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Fewest digits a code may carry. RFC 4226 sets six as the floor.
pub const MIN_DIGITS: u32 = 6;

/// Most digits a code may carry.
///
/// Ten is where `u32` runs out: dynamic truncation yields a 31-bit number, so
/// `10^10` already exceeds it and an eleventh digit would be a constant zero
/// that looks like part of the code.
pub const MAX_DIGITS: u32 = 10;

/// Longest step a stored seed may name, in seconds.
///
/// An hour. Nothing real uses more, and the cap is what stops a pasted URI with
/// `period=0` or `period=4294967295` from producing a division by zero or a
/// code that never changes.
pub const MAX_PERIOD_SECS: u64 = 3600;

// ── Base32 (RFC 4648, no padding) ─────────────────────────────────────────────

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes bytes as unpadded RFC 4648 base32.
///
/// Unpadded because `otpauth://` secrets are conventionally written without `=`,
/// and several authenticators reject the padding rather than ignoring it.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32_ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        // Left-align the remaining bits in the final group, as RFC 4648 requires.
        out.push(char::from(
            B32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    out
}

/// Decodes unpadded (or padded) RFC 4648 base32, case-insensitively.
///
/// Spaces are stripped because this is what a human types back out of the
/// grouped display the UI shows, and `=` is accepted because a user pasting a
/// secret exported from somewhere else should not have to know the difference.
pub fn base32_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in s.chars() {
        if ch == '=' || ch.is_whitespace() || ch == '-' {
            continue;
        }
        let up = ch.to_ascii_uppercase();
        let val = B32_ALPHABET
            .iter()
            .position(|&c| c == up as u8)
            .ok_or_else(|| format!("not base32: {ch:?}"))? as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

// ── Code generation ───────────────────────────────────────────────────────────

/// HOTP (RFC 4226) for one counter value, SHA-1 and six digits.
///
/// The login path's shape. A stored third-party seed goes through
/// [`hotp_with`], which is the same function with the two constants unpinned;
/// this one stays because every caller in `users.rs` means exactly these
/// numbers and spelling them out at each call site invites one of them to
/// drift.
pub fn hotp(secret: &[u8], counter: u64) -> String {
    hotp_with(secret, counter, Algorithm::Sha1, DIGITS)
}

/// HOTP (RFC 4226) for one counter value, with the algorithm and digit count
/// the issuer chose.
///
/// `digits` is clamped to [`MIN_DIGITS`]..=[`MAX_DIGITS`] rather than rejected:
/// this is the innermost function and it is reached only through validated
/// constructors, so a panic here would be a crash in a card renderer for a
/// number a user typed. [`Params::validate`] is where a bad value is refused.
pub fn hotp_with(secret: &[u8], counter: u64, algorithm: Algorithm, digits: u32) -> String {
    // Dynamic truncation, RFC 4226 §5.3, over whichever digest the issuer picked.
    // `new_from_slice` only fails for key lengths HMAC cannot take, and HMAC
    // accepts any length, so none of these can fail in practice.
    let digest: Vec<u8> = match algorithm {
        Algorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(&counter.to_be_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(&counter.to_be_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(&counter.to_be_bytes());
            mac.finalize().into_bytes().to_vec()
        }
    };

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);

    let digits = digits.clamp(MIN_DIGITS, MAX_DIGITS);
    let modulus = 10u32.pow(digits);
    format!("{:0width$}", binary % modulus, width = digits as usize)
}

/// Steam Guard's five characters for one counter value.
///
/// The HMAC and the dynamic truncation are RFC 4226's, unchanged — see
/// [`hotp_with`], whose first half this repeats. Only the rendering differs: the
/// 31-bit value is written in base 26 over [`STEAM_ALPHABET`] instead of base 10.
///
/// Written out rather than folded into `hotp_with` because the two produce
/// different *types* of answer from the same number, and a `digits`-shaped
/// parameter that silently switched alphabets would be the kind of flag that
/// gets passed wrongly once and then produces codes that look plausible.
fn steam_with(secret: &[u8], counter: u64) -> String {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let mut value = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);

    let n = STEAM_ALPHABET.len() as u32;
    let mut out = String::with_capacity(STEAM_DIGITS as usize);
    for _ in 0..STEAM_DIGITS {
        out.push(STEAM_ALPHABET[(value % n) as usize] as char);
        value /= n;
    }
    out
}

/// The counter step for a Unix timestamp.
pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// Current Unix time in seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// TOTP for a base32 secret at a given time. Exposed so a caller can show the
/// user the code their authenticator should be showing — used by nothing that
/// authenticates, only by diagnostics.
pub fn totp_at(secret_b32: &str, unix_secs: u64) -> Result<String, String> {
    let secret = base32_decode(secret_b32)?;
    if secret.is_empty() {
        return Err("empty TOTP secret".into());
    }
    Ok(hotp(&secret, step_at(unix_secs)))
}

// ── Verification ──────────────────────────────────────────────────────────────

/// The outcome of checking a code, carrying the step that was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    /// The counter step the code matched. The caller **must** persist this and
    /// pass it back as `last_step` next time.
    pub step: u64,
}

/// Verifies a code against a secret, refusing anything at or before `last_step`.
///
/// # The anti-replay rule is the whole point
///
/// A ±1-step skew window means any given code is valid for ninety seconds. Over
/// a network that is ninety seconds in which an observed code can be replayed by
/// whoever saw it — which for a second factor is the exact attack it exists to
/// stop. Refusing a step that has already been accepted reduces that to a single
/// use, and it is why every caller has to store what [`Accepted::step`] returns.
///
/// `last_step` of `None` means the factor has never been used.
pub fn verify(secret_b32: &str, code: &str, last_step: Option<u64>, now: u64) -> Option<Accepted> {
    let secret = base32_decode(secret_b32).ok()?;
    if secret.is_empty() {
        return None;
    }
    // Users type codes with a space in the middle because that is how phones
    // display them.
    let code: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if code.len() != DIGITS as usize {
        return None;
    }

    let current = step_at(now) as i64;
    for delta in -SKEW_STEPS..=SKEW_STEPS {
        let step = current + delta;
        if step < 0 {
            continue;
        }
        let step = step as u64;
        if let Some(last) = last_step {
            if step <= last {
                continue;
            }
        }
        if constant_time_eq(hotp(&secret, step).as_bytes(), code.as_bytes()) {
            return Some(Accepted { step });
        }
    }
    None
}

/// Length-aware, branch-free byte comparison.
///
/// Codes are six digits, so a timing oracle here leaks very little — but the
/// same reasoning retired the legacy SHA-256 password comparison in Phase 5.1,
/// and writing the fast version in a file about authentication invites the next
/// reader to copy it somewhere it matters.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Enrollment ────────────────────────────────────────────────────────────────

/// Generates a fresh base32 secret from the OS CSPRNG.
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut buf = [0u8; SECRET_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base32_encode(&buf)
}

/// Builds the `otpauth://` URI an authenticator scans or imports.
///
/// The label is `issuer:account` and the `issuer` parameter repeats it, which is
/// redundant by the spec and required in practice — several apps read only one
/// of the two, and which one differs between them.
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        pct(issuer),
        pct(account),
        secret_b32,
        pct(issuer),
        DIGITS,
        STEP_SECS
    )
}

/// Percent-encodes everything outside the unreserved set.
///
/// A username is user-supplied, so it reaches this function containing anything
/// at all: a `?`, `&` or `#` in it would otherwise terminate the path and turn
/// the rest of the username into query parameters of the caller's choosing.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Splits a secret into space-separated groups of four for manual entry.
///
/// The UI cannot render a QR code — the CSP does not allow the library that
/// would draw one, and relaxing it to display a secret would be an odd trade —
/// so the secret is typed by hand, and a 32-character unbroken string is typed
/// wrong.
pub fn grouped(secret_b32: &str) -> String {
    secret_b32
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Stored third-party seeds (Phase 22) ───────────────────────────────────────
//
// Everything below serves the *other* caller: a seed the vault holds on behalf
// of a website, from which UnENVerse produces a code the user types into that
// website. Nothing here verifies anything, so nothing here has — or wants — the
// anti-replay mark that `verify` above carries.

/// The alphabet Steam Guard draws its five characters from.
///
/// Steam runs ordinary RFC 6238 arithmetic — SHA-1, a 30-second step — and then
/// encodes the truncated value in base 26 instead of base 10. Nothing else about
/// it differs, which is why it is a [`Kind`] rather than an [`Algorithm`]: the
/// HMAC is the same, the rendering is not.
pub const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// How many characters a Steam code carries. Not configurable; Steam fixes it.
pub const STEAM_DIGITS: u32 = 5;

/// What a stored seed *is*, which decides what "the current code" means for it.
///
/// The three differ in where the counter comes from, not in the arithmetic:
/// `Totp` divides the clock by the period, `Steam` does the same and renders the
/// result in base 26, and `Hotp` has no clock at all and uses a number the vault
/// stores and the user advances.
///
/// Phase 22 refused the last two by name. That refusal was right while nothing
/// could store a counter — an `Hotp` entry with nowhere to keep its position
/// shows a code that never changes and never works. Phase 22.2 gives it
/// somewhere, so the refusal became a limitation instead of a safeguard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Time-based, RFC 6238. What an entry with no stored kind means.
    #[default]
    Totp,
    /// Counter-based, RFC 4226. The counter lives on the entry.
    Hotp,
    /// Time-based like `Totp`, rendered in Steam's five-character alphabet.
    Steam,
}

impl Kind {
    /// The spelling stored on the entry and used in an `otpauth://` path.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Totp => "totp",
            Kind::Hotp => "hotp",
            Kind::Steam => "steam",
        }
    }

    /// Reads that spelling, case-insensitively. `None` for anything else.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "totp" => Some(Kind::Totp),
            "hotp" => Some(Kind::Hotp),
            "steam" => Some(Kind::Steam),
            _ => None,
        }
    }

    /// True when the code advances on its own, so a countdown means something.
    ///
    /// The UI asks this rather than comparing against `Kind::Hotp`: a card with
    /// no clock must draw no countdown ring, and a card that draws one whose
    /// number never moves is worse than one that draws none.
    pub fn is_time_based(self) -> bool {
        !matches!(self, Kind::Hotp)
    }
}

/// The HMAC a stored seed names.
///
/// SHA-1 is the only value a login seed ever takes and the overwhelming
/// majority of what issuers hand out. The other two exist because `otpauth://`
/// can name them and a handful of issuers do: reading `algorithm=SHA256` and
/// then generating SHA-1 codes produces six digits that are correct-looking,
/// wrong, and give the user no way to tell which of the two ends is at fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    /// The spelling `otpauth://` uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    /// Reads the spelling `otpauth://` uses, case- and dash-insensitively.
    ///
    /// `SHA-256` appears in real URIs even though the spec does not allow it.
    /// Rejecting it would mean refusing a seed that every phone accepts.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Some(Algorithm::Sha1),
            "SHA256" => Some(Algorithm::Sha256),
            "SHA512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }
}

/// The three numbers a stored seed is generated under.
///
/// Defaults are what an `otpauth://` URI means when it omits the parameter, and
/// therefore what an entry that stores only a bare base32 seed means too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Time-based, counter-based or Steam. `#[serde(default)]` because every
    /// entry written before Phase 22.2 has no such field and means `Totp`.
    #[serde(default)]
    pub kind: Kind,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    /// The next counter value an `Hotp` seed will use. Meaningless for the other
    /// two kinds, and zero for them.
    ///
    /// It is *state*, not configuration — the only number in this struct that a
    /// correct implementation writes back — which is why advancing it is an
    /// explicit action rather than a side effect of reading a code. See
    /// `advance` in `unv-cli/src/totp_cmd.rs`.
    #[serde(default)]
    pub counter: u64,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            kind: Kind::Totp,
            algorithm: Algorithm::Sha1,
            digits: DIGITS,
            period: STEP_SECS,
            counter: 0,
        }
    }
}

impl Params {
    /// The parameters an entry's four stored fields mean, with anything
    /// unusable falling back to the `otpauth://` default.
    ///
    /// **This is the only place a vault's TOTP fields become `Params`.** They
    /// were read three separate ways before — `unv totp code` clamped, `unv
    /// totp ls` did not, and the IPC command did neither — so one entry
    /// carrying `totp_digits: 99` listed as a 99-digit credential, produced six
    /// digits when asked for a code, and returned an error rather than a code to
    /// any caller of `entry_totp_code` that had not clamped first. Three
    /// readings of one field is three answers.
    ///
    /// A vault is untrusted input (invariant 4): these fields arrive from an
    /// imported backup or a remote server as readily as from this CLI, and the
    /// unions are not enforced at rest. Falling back rather than refusing is
    /// what an omitted `otpauth://` parameter already means, and it keeps a
    /// single mistyped number from making the whole entry unreadable.
    ///
    /// The twin is `totpParamsOf` in `src/ts/totp.ts` — the form needs these
    /// before anything is saved — and the two are pinned by the `params`
    /// section of `tests/fixtures/parity/totp-seeds.json`.
    pub fn from_fields(
        kind: Option<&str>,
        algorithm: Option<&str>,
        digits: Option<u64>,
        period: Option<u64>,
        counter: Option<u64>,
    ) -> Self {
        let d = Params::default();
        let kind = kind.and_then(Kind::parse).unwrap_or(d.kind);
        Params {
            kind,
            algorithm: algorithm.and_then(Algorithm::parse).unwrap_or(d.algorithm),
            digits: digits
                .filter(|n| (u64::from(MIN_DIGITS)..=u64::from(MAX_DIGITS)).contains(n))
                .map(|n| n as u32)
                .unwrap_or(d.digits),
            period: period
                .filter(|p| *p > 0 && *p <= MAX_PERIOD_SECS)
                .unwrap_or(d.period),
            // A counter is only ever read for an `Hotp` seed. Carrying one on a
            // time-based entry would be a number that looks like state and is
            // never used, which is the kind of field a later reader trusts.
            counter: if kind == Kind::Hotp {
                counter.unwrap_or(0)
            } else {
                0
            },
        }
        .steam_normalised()
    }

    /// Forces the values Steam fixes, so nothing downstream has to special-case
    /// them.
    ///
    /// Steam issues one shape — SHA-1, five characters, a 30-second step — and an
    /// import that carried `digits: 6` from a generic exporter would otherwise
    /// produce six characters no Steam login accepts.
    fn steam_normalised(mut self) -> Self {
        if self.kind == Kind::Steam {
            self.algorithm = Algorithm::Sha1;
            self.digits = STEAM_DIGITS;
            self.period = STEP_SECS;
            self.counter = 0;
        }
        self
    }

    /// Refuses a combination that cannot produce a code, naming the field.
    ///
    /// Called at every boundary a number can enter through — the URI parser, the
    /// CLI flags, the IPC command — rather than at the generator, so that a
    /// `period` of zero is a message about the value the user typed instead of a
    /// division by zero three frames deeper.
    pub fn validate(&self) -> Result<(), String> {
        // Steam fixes its own shape, so there is nothing here for a user to get
        // wrong — and its five characters are below `MIN_DIGITS`, which the
        // check below would otherwise refuse.
        if self.kind == Kind::Steam {
            return if self.digits == STEAM_DIGITS {
                Ok(())
            } else {
                Err(format!(
                    "a Steam code is always {STEAM_DIGITS} characters, got {}",
                    self.digits
                ))
            };
        }
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&self.digits) {
            return Err(format!(
                "digits must be between {MIN_DIGITS} and {MAX_DIGITS}, got {}",
                self.digits
            ));
        }
        // An `Hotp` seed has no clock, so its period is meaningless rather than
        // wrong. It is still range-checked, because a stored zero would divide
        // by zero the moment somebody converted the entry to time-based.
        if self.period == 0 || self.period > MAX_PERIOD_SECS {
            return Err(format!(
                "period must be between 1 and {MAX_PERIOD_SECS} seconds, got {}",
                self.period
            ));
        }
        Ok(())
    }

    /// True when these are the values an `otpauth://` URI may omit.
    ///
    /// Used to keep the stored entry honest: writing `algorithm: "SHA1"` onto
    /// every entry would make the field look chosen when it was defaulted, and
    /// the UI would then have to distinguish "the issuer said SHA-1" from "we
    /// wrote SHA-1 because nobody said anything". They are the same thing, so
    /// the field is simply absent.
    pub fn is_default(&self) -> bool {
        *self == Params::default()
    }
}

/// A parsed seed: the base32 secret plus everything the URI said about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    /// Base32, uppercased, with the grouping spaces and any padding removed.
    pub secret: String,
    #[serde(flatten)]
    pub params: Params,
    /// The service, when the URI named one. Never overwrites an entry's
    /// provider — see `unv-cli`'s `--totp` handling; it is offered, not applied.
    pub issuer: Option<String>,
    /// The account at that service, when the URI named one.
    pub account: Option<String>,
}

impl Stored {
    /// Rebuilds an `otpauth://` URI, for exporting the seed back to a phone.
    ///
    /// The URI **contains the secret**, so every caller of this is a
    /// materialising path: it is refused to stdout without `--reveal`, exactly
    /// as the seed itself is.
    pub fn to_uri(&self, issuer_fallback: &str, account_fallback: &str) -> String {
        let issuer = self.issuer.as_deref().unwrap_or(issuer_fallback);
        let account = self.account.as_deref().unwrap_or(account_fallback);
        let label = if issuer.is_empty() {
            pct(account)
        } else {
            format!("{}:{}", pct(issuer), pct(account))
        };
        // Steam is written as `otpauth://totp/…&encoder=steam` rather than as
        // `otpauth://steam/`: both spellings exist, Aegis reads either, and the
        // `totp` path is the one every *other* authenticator will at least
        // import as a working — if wrongly rendered — seed instead of rejecting
        // the line outright.
        let path = match self.params.kind {
            Kind::Hotp => "hotp",
            Kind::Totp | Kind::Steam => "totp",
        };
        let mut uri = format!("otpauth://{path}/{label}?secret={}", self.secret);
        if !issuer.is_empty() {
            uri.push_str(&format!("&issuer={}", pct(issuer)));
        }
        uri.push_str(&format!(
            "&algorithm={}&digits={}",
            self.params.algorithm.as_str(),
            self.params.digits,
        ));
        match self.params.kind {
            // A counter-based URI carries its position instead of a period. An
            // exporter that dropped it would hand the next phone a seed starting
            // from zero, which is a second factor that fails until it is resynced.
            Kind::Hotp => uri.push_str(&format!("&counter={}", self.params.counter)),
            Kind::Totp => uri.push_str(&format!("&period={}", self.params.period)),
            Kind::Steam => uri.push_str(&format!("&period={}&encoder=steam", self.params.period)),
        }
        uri
    }
}

/// Percent-decodes, leaving anything malformed alone.
///
/// A label that ends in a bare `%` is a typo in someone's export, not an attack,
/// and dropping the whole seed over it helps nobody.
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        // `+` is a form-encoding convention, not a URI one, but exports written
        // by web tooling use it in the label and a literal plus in an account
        // name is vanishingly rare next to a space that reads as one.
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Normalises a base32 secret: uppercase, no spaces, dashes or padding.
///
/// The value that reaches the vault, so that two entries holding the same seed
/// typed differently are byte-identical and their fingerprints match.
pub fn normalize_b32(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

/// Reads either a bare base32 seed or a full `otpauth://` URI.
///
/// One entry point because the form field, the CLI flag and the paste handler
/// all accept whichever the user has to hand, and a user who pastes a URI into a
/// box labelled "secret" is doing the reasonable thing.
pub fn parse_seed(input: &str) -> Result<Stored, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty TOTP secret".into());
    }
    if trimmed.len() >= 8 && trimmed[..8].eq_ignore_ascii_case("otpauth:") {
        return parse_otpauth(trimmed);
    }
    let secret = normalize_b32(trimmed);
    validate_secret(&secret)?;
    Ok(Stored {
        secret,
        params: Params::default(),
        issuer: None,
        account: None,
    })
}

/// Rejects a secret that cannot produce a code, before it is stored.
///
/// Storing an unusable seed is worse than refusing it: the entry then shows a
/// code field that is permanently blank, and the user has no way to tell a
/// mistyped secret from a bug.
fn validate_secret(secret: &str) -> Result<(), String> {
    if secret.is_empty() {
        return Err("empty TOTP secret".into());
    }
    let bytes = Zeroizing::new(base32_decode(secret)?);
    if bytes.is_empty() {
        return Err("TOTP secret decodes to no bytes".into());
    }
    Ok(())
}

/// Parses an `otpauth://totp/...` URI.
///
/// Deliberately strict about the scheme and the type, and forgiving about
/// everything else: an unknown query parameter is ignored, an unreadable
/// `digits` falls back to the default rather than failing, and only a missing or
/// unusable `secret` is fatal. A URI is pasted from a third party's export and
/// half of them are slightly wrong.
pub fn parse_otpauth(uri: &str) -> Result<Stored, String> {
    let rest = uri
        .get(..10)
        .filter(|p| p.eq_ignore_ascii_case("otpauth://"))
        .and_then(|_| uri.get(10..))
        .ok_or("not an otpauth:// URI")?;

    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, q),
        None => (rest, ""),
    };
    let (kind, label) = match path.split_once('/') {
        Some((k, l)) => (k, l),
        None => (path, ""),
    };
    // Phase 22 refused everything but `totp` here, because an `hotp` seed with
    // nowhere to keep its counter shows a code that never changes. The entry can
    // hold a counter now, so the three kinds are read and anything else is still
    // refused by name.
    let kind = Kind::parse(kind).ok_or_else(|| {
        format!("only otpauth://totp/, //hotp/ and //steam/ are supported, got 'otpauth://{kind}/'")
    })?;

    let mut secret = String::new();
    let mut issuer_param: Option<String> = None;
    let mut params = Params {
        kind,
        ..Params::default()
    };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = normalize_b32(&pct_decode(v)),
            "issuer" => {
                let decoded = pct_decode(v);
                if !decoded.trim().is_empty() {
                    issuer_param = Some(decoded.trim().to_string());
                }
            }
            "algorithm" => {
                if let Some(a) = Algorithm::parse(&pct_decode(v)) {
                    params.algorithm = a;
                }
            }
            "digits" => {
                if let Ok(d) = pct_decode(v).trim().parse::<u32>() {
                    if (MIN_DIGITS..=MAX_DIGITS).contains(&d) {
                        params.digits = d;
                    }
                }
            }
            // RFC 4226 calls this the "initial counter value"; every exporter
            // writes the *next* value to use, which is what the entry stores.
            "counter" => {
                if let Ok(c) = pct_decode(v).trim().parse::<u64>() {
                    params.counter = c;
                }
            }
            // Aegis writes `encoder=steam` on an `otpauth://totp/` URI rather
            // than using the `steam` path, so a seed exported from it would
            // otherwise import as an ordinary six-digit TOTP and produce codes
            // Steam rejects. Recognised by this parameter and by the path — never
            // by the issuer *name*, which is text a user can edit into anything.
            "encoder" if pct_decode(v).trim().eq_ignore_ascii_case("steam") => {
                params.kind = Kind::Steam;
            }
            "period" => {
                if let Ok(p) = pct_decode(v).trim().parse::<u64>() {
                    if p > 0 && p <= MAX_PERIOD_SECS {
                        params.period = p;
                    }
                }
            }
            _ => {}
        }
    }

    validate_secret(&secret)?;
    // `encoder=steam` can arrive after `digits=6`, and the `steam` path arrives
    // before any parameter at all, so the shape Steam fixes is forced once the
    // whole query has been read rather than in whichever arm saw it first.
    params = params.steam_normalised();
    params.validate()?;

    // The label is `issuer:account`, and the `issuer` query parameter repeats
    // it. Where the two disagree the parameter wins — it is the one an exporter
    // writes deliberately, while the label half is often whatever the user typed
    // into their phone years ago.
    let label = pct_decode(label);
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (
            Some(i.trim().to_string()).filter(|s| !s.is_empty()),
            a.trim().to_string(),
        ),
        None => (None, label.trim().to_string()),
    };

    Ok(Stored {
        secret,
        params,
        issuer: issuer_param.or(label_issuer),
        account: Some(account).filter(|a| !a.is_empty()),
    })
}

/// The counter a seed uses at a given moment.
///
/// The one place the three kinds differ before the arithmetic starts: two divide
/// the clock, one ignores it entirely and reads the number the vault stored.
fn counter_at(params: &Params, unix_secs: u64) -> u64 {
    match params.kind {
        Kind::Hotp => params.counter,
        Kind::Totp | Kind::Steam => unix_secs / params.period.max(1),
    }
}

/// The code a stored seed produces at a given time.
///
/// For an `Hotp` seed the time is ignored and `params.counter` is used, so this
/// is still the single entry point for every kind and no caller has to know
/// which it holds.
pub fn code_at(secret_b32: &str, params: &Params, unix_secs: u64) -> Result<String, String> {
    code_for_counter(secret_b32, params, counter_at(params, unix_secs))
}

/// The code for one explicit counter value.
///
/// Exposed because "the next code" is this function at `counter + 1`, and
/// deriving it that way keeps one arithmetic path rather than two that must
/// agree.
pub fn code_for_counter(secret_b32: &str, params: &Params, counter: u64) -> Result<String, String> {
    params.validate()?;
    // Zeroized on drop: this is the decoded seed, and it is the one value in
    // this function that would still be readable in a heap dump afterwards.
    let secret = Zeroizing::new(base32_decode(secret_b32)?);
    if secret.is_empty() {
        return Err("empty TOTP secret".into());
    }
    Ok(match params.kind {
        Kind::Steam => steam_with(&secret, counter),
        Kind::Totp | Kind::Hotp => hotp_with(&secret, counter, params.algorithm, params.digits),
    })
}

/// The code that replaces the current one.
///
/// For a time-based seed that is the next step; for an `Hotp` seed it is the
/// next counter, which is the value the *service* will expect after this one is
/// spent. Both are the same operation, which is the point.
pub fn next_code_at(secret_b32: &str, params: &Params, unix_secs: u64) -> Result<String, String> {
    code_for_counter(secret_b32, params, counter_at(params, unix_secs) + 1)
}

/// Seconds until the current code is replaced.
///
/// Zero is never returned: at the instant of a step boundary the *new* code has
/// a full period ahead of it, and a countdown that reads 0 for one second in
/// every period is a countdown users report as a bug.
pub fn remaining_secs(period: u64, unix_secs: u64) -> u64 {
    let period = period.clamp(1, MAX_PERIOD_SECS);
    period - (unix_secs % period)
}

/// A code and how long it has left — the shape the desktop app and the CLI both
/// render.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveCode {
    pub code: String,
    /// The code that replaces `code`, when the caller asked for it.
    ///
    /// Absent unless requested: it is a second live credential, and a panel that
    /// always painted one would put two working codes in every screenshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_code: Option<String>,
    /// What produced it, so a renderer knows whether a countdown means anything.
    pub kind: Kind,
    /// The counter this code was generated at. For an `Hotp` seed it is the
    /// entry's stored position, which is what the user is deciding whether to
    /// advance.
    pub counter: u64,
    /// Seconds until `code` is replaced, or **0 for an `Hotp` seed**, which has
    /// no clock and whose code is replaced only when somebody advances it.
    pub remaining_secs: u64,
    /// Echoed back so a caller can draw a countdown without re-deriving it from
    /// the entry, and so a stale response is recognisable as stale.
    pub period: u64,
    pub digits: u32,
    pub algorithm: Algorithm,
}

/// The code a stored seed produces right now, with its countdown.
pub fn live_code(secret_b32: &str, params: &Params) -> Result<LiveCode, String> {
    live_code_with(secret_b32, params, false)
}

/// The same, optionally carrying the code that comes next.
///
/// `with_next` is a parameter rather than always-on because the next code is a
/// second working credential with a longer life than the one on screen: a
/// screenshot of a panel showing both is good for up to two periods rather than
/// one. The authenticator screen puts it behind a toggle and the CLI behind
/// `--next`.
pub fn live_code_with(
    secret_b32: &str,
    params: &Params,
    with_next: bool,
) -> Result<LiveCode, String> {
    let now = now_unix();
    Ok(LiveCode {
        code: code_at(secret_b32, params, now)?,
        next_code: if with_next {
            Some(next_code_at(secret_b32, params, now)?)
        } else {
            None
        },
        kind: params.kind,
        counter: counter_at(params, now),
        // An `Hotp` code is not replaced by the passage of time, and a countdown
        // that never moves reads as a frozen UI. Zero says "no clock" and the
        // renderer draws no ring.
        remaining_secs: if params.kind.is_time_based() {
            remaining_secs(params.period, now)
        } else {
            0
        },
        period: params.period,
        digits: params.digits,
        algorithm: params.algorithm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trips_every_remainder_length() {
        // The tail handling has a different shape for each input length mod 5,
        // and the left-align in the final group is the part that is easy to get
        // wrong — it is silent, and produces a secret an authenticator accepts
        // and then disagrees with.
        for n in 0..=16usize {
            let data: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(37)).collect();
            let enc = base32_encode(&data);
            assert!(
                enc.chars().all(|c| B32_ALPHABET.contains(&(c as u8))),
                "non-alphabet char in {enc}"
            );
            assert_eq!(
                base32_decode(&enc).unwrap(),
                data,
                "round trip failed at {n}"
            );
        }
    }

    #[test]
    fn base32_matches_rfc_4648_vectors() {
        // Without a published vector this file could be self-consistently wrong,
        // and every authenticator on earth would disagree with it.
        for (input, expect) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(
                base32_encode(input.as_bytes()),
                expect,
                "encoding {input:?}"
            );
        }
    }

    #[test]
    fn hotp_matches_rfc_4226_vectors() {
        // RFC 4226 Appendix D, the ASCII secret "12345678901234567890".
        let secret = b"12345678901234567890";
        for (counter, expect) in [
            (0u64, "755224"),
            (1, "287082"),
            (2, "359152"),
            (3, "969429"),
            (4, "338314"),
            (5, "254676"),
            (6, "287922"),
            (7, "162583"),
            (8, "399871"),
            (9, "520489"),
        ] {
            assert_eq!(hotp(secret, counter), expect, "counter {counter}");
        }
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_vectors() {
        let secret = base32_encode(b"12345678901234567890");
        // RFC 6238 Appendix B, SHA-1 rows, truncated to our six digits.
        for (t, expect) in [
            (59u64, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ] {
            assert_eq!(totp_at(&secret, t).unwrap(), expect, "t={t}");
        }
    }

    #[test]
    fn accepts_the_current_code_and_one_step_of_skew_either_way() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        for offset in [-(STEP_SECS as i64), 0, STEP_SECS as i64] {
            let at = (now as i64 + offset) as u64;
            let code = totp_at(&secret, at).unwrap();
            assert!(
                verify(&secret, &code, None, now).is_some(),
                "offset {offset} should be inside the skew window"
            );
        }
        // Two steps out is outside the window.
        let far = totp_at(&secret, now + 2 * STEP_SECS).unwrap();
        assert!(verify(&secret, &far, None, now).is_none());
    }

    #[test]
    fn refuses_a_code_whose_step_was_already_used() {
        // The replay this whole module exists to prevent: without the last_step
        // check, an observed code stays valid for the rest of its ninety-second
        // window and anyone who saw it can use it.
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let code = totp_at(&secret, now).unwrap();

        let first = verify(&secret, &code, None, now).expect("first use accepted");
        assert_eq!(first.step, step_at(now));
        assert!(
            verify(&secret, &code, Some(first.step), now).is_none(),
            "the same code must not be accepted twice"
        );
        // And nor may the *earlier* code from the skew window, which is still
        // arithmetically valid but is a step the user has already moved past.
        let earlier = totp_at(&secret, now - STEP_SECS).unwrap();
        assert!(verify(&secret, &earlier, Some(first.step), now).is_none());
    }

    #[test]
    fn tolerates_the_spacing_a_phone_displays() {
        let secret = generate_secret();
        let now = now_unix();
        let code = totp_at(&secret, now).unwrap();
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert!(verify(&secret, &spaced, None, now).is_some());
    }

    #[test]
    fn refuses_malformed_input_rather_than_panicking() {
        let secret = generate_secret();
        let now = now_unix();
        for bad in ["", "12345", "1234567", "abcdef", "!!!!!!"] {
            assert!(
                verify(&secret, bad, None, now).is_none(),
                "accepted {bad:?}"
            );
        }
        assert!(verify("not base32 ∅", "123456", None, now).is_none());
        assert!(verify("", "123456", None, now).is_none());
    }

    #[test]
    fn otpauth_uri_escapes_a_username_that_would_break_the_query() {
        // A username is user-supplied. Unescaped, `a&issuer=Evil` would append a
        // parameter of the attacker's choosing to the URI a user is about to
        // paste into their authenticator.
        let uri = otpauth_uri("UnENVerse", "a&issuer=Evil?x=1", "ABCD");
        assert!(uri.contains("a%26issuer%3DEvil%3Fx%3D1"), "{uri}");
        assert_eq!(uri.matches("issuer=").count(), 1, "{uri}");
    }

    #[test]
    fn grouped_secret_decodes_to_the_same_bytes_as_the_ungrouped_one() {
        // The UI shows the grouped form and users type it back with the spaces.
        let secret = generate_secret();
        assert_eq!(
            base32_decode(&grouped(&secret)).unwrap(),
            base32_decode(&secret).unwrap()
        );
    }

    // ── Stored third-party seeds (Phase 22) ──────────────────────────────────

    /// RFC 6238 Appendix B seeds. The three are different lengths on purpose:
    /// the spec's SHA-256 and SHA-512 vectors use 32- and 64-byte keys, and a
    /// generator that quietly truncated or padded would still match the SHA-1
    /// row and fail only for the users who have a SHA-512 seed.
    fn rfc6238_seed(algorithm: Algorithm) -> String {
        let ascii: &[u8] = match algorithm {
            Algorithm::Sha1 => b"12345678901234567890",
            Algorithm::Sha256 => b"12345678901234567890123456789012",
            Algorithm::Sha512 => {
                b"1234567890123456789012345678901234567890123456789012345678901234"
            }
        };
        base32_encode(ascii)
    }

    #[test]
    fn code_at_matches_rfc_6238_for_all_three_algorithms() {
        // Without these the SHA-256 and SHA-512 arms could be self-consistently
        // wrong: they would produce six plausible digits that the issuer
        // rejects, and nothing in the app could tell the user which end was at
        // fault. Eight digits because that is the width the RFC tabulates —
        // which also exercises the non-default `digits`.
        let rows: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, sha1, sha256, sha512) in rows {
            for (algorithm, want) in [
                (Algorithm::Sha1, sha1),
                (Algorithm::Sha256, sha256),
                (Algorithm::Sha512, sha512),
            ] {
                let params = Params {
                    kind: Kind::Totp,
                    counter: 0,
                    algorithm,
                    digits: 8,
                    period: 30,
                };
                assert_eq!(
                    code_at(&rfc6238_seed(algorithm), &params, t).unwrap(),
                    want,
                    "{} at t={t}",
                    algorithm.as_str()
                );
            }
        }
    }

    #[test]
    fn the_default_params_reproduce_the_login_paths_answer() {
        // `hotp` delegates to `hotp_with`, so the two must agree for every
        // secret or Phase 19's login would start failing the moment Phase 21
        // touched the generator.
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        assert_eq!(
            code_at(&secret, &Params::default(), now).unwrap(),
            totp_at(&secret, now).unwrap()
        );
    }

    #[test]
    fn a_bare_base32_seed_parses_with_the_omitted_defaults() {
        let stored = parse_seed("jbsw y3dp ehpk 3pxp").unwrap();
        // Normalised: the vault holds one spelling, so two entries carrying the
        // same seed typed differently fingerprint the same.
        assert_eq!(stored.secret, "JBSWY3DPEHPK3PXP");
        assert!(stored.params.is_default());
        assert_eq!(stored.issuer, None);
        assert_eq!(stored.account, None);
    }

    #[test]
    fn an_otpauth_uri_parses_label_issuer_and_every_parameter() {
        let stored = parse_seed(
            "otpauth://totp/GitHub:darth%40example.com?secret=JBSWY3DPEHPK3PXP\
             &issuer=GitHub&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(stored.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(stored.params.algorithm, Algorithm::Sha256);
        assert_eq!(stored.params.digits, 8);
        assert_eq!(stored.params.period, 60);
        assert_eq!(stored.issuer.as_deref(), Some("GitHub"));
        assert_eq!(stored.account.as_deref(), Some("darth@example.com"));
    }

    #[test]
    fn the_issuer_parameter_beats_the_label_when_they_disagree() {
        // The label half is often years-old text a user typed into a phone; the
        // parameter is what an exporter wrote deliberately.
        let stored =
            parse_seed("otpauth://totp/Stale:me?secret=JBSWY3DPEHPK3PXP&issuer=Current").unwrap();
        assert_eq!(stored.issuer.as_deref(), Some("Current"));
        assert_eq!(stored.account.as_deref(), Some("me"));
    }

    #[test]
    fn a_uri_with_no_secret_is_refused_rather_than_stored_unusable() {
        // Storing it would give the entry a code field that is permanently
        // blank, with nothing on screen distinguishing that from a bug.
        assert!(parse_seed("otpauth://totp/Acme:me?issuer=Acme").is_err());
        assert!(parse_seed("otpauth://totp/Acme:me?secret=").is_err());
        assert!(parse_seed("otpauth://totp/Acme:me?secret=!!!!").is_err());
    }

    #[test]
    fn a_counter_based_uri_keeps_its_counter() {
        // Phase 22 refused this by name, because an `hotp` seed with nowhere to
        // keep its position produces a card whose code never changes. The entry
        // holds a counter now (Phase 22.2), so the URI is read — and the counter
        // is the half that must survive: an `hotp` seed imported at zero is a
        // second factor that fails until the account is resynced.
        let stored = parse_seed("otpauth://hotp/Acme:me?secret=JBSWY3DPEHPK3PXP&counter=7")
            .expect("hotp is read");
        assert_eq!(stored.params.kind, Kind::Hotp);
        assert_eq!(stored.params.counter, 7);
        assert!(!stored.params.kind.is_time_based());

        // A scheme nothing here implements is still refused, and still by name.
        let err = parse_seed("otpauth://yubico/Acme:me?secret=JBSWY3DPEHPK3PXP")
            .expect_err("an unknown type must be refused");
        assert!(err.contains("yubico"), "{err}");
    }

    #[test]
    fn a_counter_based_code_ignores_the_clock_and_advances_only_with_its_counter() {
        // The whole difference between the two kinds, asserted directly: time
        // moves and the code does not; the counter moves and it does.
        let p = Params {
            kind: Kind::Hotp,
            counter: 3,
            ..Params::default()
        };
        let at_zero = code_at("JBSWY3DPEHPK3PXP", &p, 0).unwrap();
        let much_later = code_at("JBSWY3DPEHPK3PXP", &p, 5_000_000).unwrap();
        assert_eq!(at_zero, much_later, "an hotp code must not move with time");

        let next = Params { counter: 4, ..p };
        assert_ne!(at_zero, code_at("JBSWY3DPEHPK3PXP", &next, 0).unwrap());
        // And "the next code" is exactly the next counter, not the next step.
        assert_eq!(
            next_code_at("JBSWY3DPEHPK3PXP", &p, 0).unwrap(),
            code_at("JBSWY3DPEHPK3PXP", &next, 0).unwrap()
        );
        // No clock means no countdown; a ring that never moves reads as a
        // frozen UI, so the renderer is told there is nothing to draw.
        assert_eq!(live_code("JBSWY3DPEHPK3PXP", &p).unwrap().remaining_secs, 0);
    }

    #[test]
    fn steam_matches_an_independent_implementation() {
        // Steam publishes no test vectors, so these were computed by a separate
        // implementation written from the algorithm description and checked
        // against this one at a pinned step — not by running this code twice.
        // Without fixed vectors the only check available is "the two agree
        // right now", which passes for two identical mistakes.
        let p = Params {
            kind: Kind::Steam,
            ..Params::default()
        }
        .steam_normalised();
        for (counter, want) in [(0u64, "VH8YJ"), (1, "2YXGV"), (59_636_971, "5TC5V")] {
            assert_eq!(
                code_for_counter("JBSWY3DPEHPK3PXP", &p, counter).unwrap(),
                want,
                "steam code at counter {counter}"
            );
        }
        // The same seed at the same counter under the ordinary renderer is a
        // different answer, which is the whole reason `Kind` exists.
        assert_ne!(
            code_for_counter("JBSWY3DPEHPK3PXP", &Params::default(), 0).unwrap(),
            "VH8YJ"
        );
    }

    #[test]
    fn a_steam_seed_produces_five_characters_from_steams_alphabet() {
        let p = Params {
            kind: Kind::Steam,
            ..Params::default()
        }
        .steam_normalised();
        let code = code_at("JBSWY3DPEHPK3PXP", &p, 0).unwrap();
        assert_eq!(code.len(), STEAM_DIGITS as usize, "{code}");
        for c in code.chars() {
            assert!(
                STEAM_ALPHABET.contains(&(c as u8)),
                "{c} is not in Steam's alphabet"
            );
        }
        // Same HMAC underneath: it is the rendering that differs, which is why
        // this is a `Kind` and not an `Algorithm`.
        assert_ne!(code, hotp(&base32_decode("JBSWY3DPEHPK3PXP").unwrap(), 0));
        // It moves with the clock like any time-based seed.
        assert_ne!(code, code_at("JBSWY3DPEHPK3PXP", &p, 30).unwrap());
    }

    #[test]
    fn steam_forces_its_own_shape_whatever_the_file_said() {
        // A generic exporter writes `digits: 6` beside a Steam seed. Six
        // characters is not something Steam accepts, and `MIN_DIGITS` would
        // otherwise refuse the five it does.
        let p = Params::from_fields(Some("steam"), Some("SHA512"), Some(8), Some(60), Some(9));
        assert_eq!(p.digits, STEAM_DIGITS);
        assert_eq!(p.algorithm, Algorithm::Sha1);
        assert_eq!(p.period, STEP_SECS);
        assert_eq!(p.counter, 0, "a time-based seed carries no counter");
        p.validate().expect("steam's own shape must validate");

        // Aegis writes the encoder as a parameter on a `totp` URI rather than
        // using the `steam` path, and the parameter can arrive after `digits`.
        let stored =
            parse_seed("otpauth://totp/Steam:me?secret=JBSWY3DPEHPK3PXP&digits=6&encoder=steam")
                .expect("aegis's spelling is read");
        assert_eq!(stored.params.kind, Kind::Steam);
        assert_eq!(stored.params.digits, STEAM_DIGITS);
    }

    #[test]
    fn every_kind_round_trips_through_its_uri() {
        for (kind, counter) in [(Kind::Totp, 0), (Kind::Hotp, 42), (Kind::Steam, 0)] {
            let stored = Stored {
                secret: "JBSWY3DPEHPK3PXP".into(),
                params: Params {
                    kind,
                    counter,
                    ..Params::default()
                }
                .steam_normalised(),
                issuer: Some("Acme".into()),
                account: Some("me".into()),
            };
            let back = parse_seed(&stored.to_uri("", "")).expect("its own URI parses");
            assert_eq!(back.params.kind, kind, "kind for {kind:?}");
            assert_eq!(back.params.counter, counter, "counter for {kind:?}");
            assert_eq!(back.secret, stored.secret);
        }
    }

    #[test]
    fn nonsense_parameters_fall_back_to_the_defaults_instead_of_failing() {
        // Half of the URIs people paste come out of someone else's export and
        // are slightly wrong. Losing the seed over an unreadable `digits` is a
        // worse outcome than generating six digits.
        let stored = parse_seed(
            "otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP&digits=nine&period=0\
             &algorithm=WHIRLPOOL&unknown=1",
        )
        .unwrap();
        assert!(stored.params.is_default());
    }

    #[test]
    fn a_lowercase_scheme_and_a_sha_dash_256_still_parse() {
        let stored =
            parse_seed("OTPAUTH://TOTP/Acme:me?secret=jbswy3dpehpk3pxp&algorithm=sha-256").unwrap();
        assert_eq!(stored.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(stored.params.algorithm, Algorithm::Sha256);
    }

    #[test]
    fn to_uri_round_trips_through_the_parser() {
        // The exported URI is what a user scans into a replacement phone. One
        // that does not read back is a lockout discovered at the worst moment.
        let original = parse_seed(
            "otpauth://totp/Acme%20Corp:d%40e.com?secret=JBSWY3DPEHPK3PXP\
             &issuer=Acme%20Corp&algorithm=SHA512&digits=7&period=45",
        )
        .unwrap();
        let round = parse_seed(&original.to_uri("", "")).unwrap();
        assert_eq!(round, original);
    }

    #[test]
    fn to_uri_falls_back_to_the_entrys_own_names_and_escapes_them() {
        // The fallbacks are the entry's provider and account, which are vault
        // data and therefore untrusted (CLAUDE.md invariant 4). Unescaped,
        // `a&issuer=Evil` would append a parameter of the writer's choosing.
        let stored = parse_seed("JBSWY3DPEHPK3PXP").unwrap();
        let uri = stored.to_uri("Acme", "a&issuer=Evil");
        assert!(uri.contains("a%26issuer%3DEvil"), "{uri}");
        assert_eq!(uri.matches("issuer=").count(), 1, "{uri}");
        assert_eq!(parse_seed(&uri).unwrap().secret, stored.secret);
    }

    #[test]
    fn remaining_secs_counts_down_a_full_period_and_never_reaches_zero() {
        // A countdown that reads 0 for one second in every period gets reported
        // as a bug; at a step boundary the *new* code has a full period ahead.
        assert_eq!(remaining_secs(30, 0), 30);
        assert_eq!(remaining_secs(30, 1), 29);
        assert_eq!(remaining_secs(30, 29), 1);
        assert_eq!(remaining_secs(30, 30), 30);
        assert_eq!(remaining_secs(60, 119), 1);
        // A period of zero cannot divide; the clamp is what stops a malformed
        // stored entry from panicking a card renderer.
        assert_eq!(remaining_secs(0, 12345), 1);
    }

    #[test]
    fn params_refuse_the_values_that_cannot_produce_a_code() {
        for bad in [
            Params {
                digits: 5,
                ..Default::default()
            },
            Params {
                digits: 11,
                ..Default::default()
            },
            Params {
                period: 0,
                ..Default::default()
            },
            Params {
                period: MAX_PERIOD_SECS + 1,
                ..Default::default()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?} should be refused");
            assert!(code_at("JBSWY3DPEHPK3PXP", &bad, 0).is_err());
        }
        assert!(Params::default().validate().is_ok());
    }

    #[test]
    fn live_code_agrees_with_code_at_and_its_own_countdown() {
        let stored = parse_seed("JBSWY3DPEHPK3PXP").unwrap();
        let live = live_code(&stored.secret, &stored.params).unwrap();
        assert_eq!(live.code.len(), stored.params.digits as usize);
        assert!(live.remaining_secs >= 1 && live.remaining_secs <= live.period);
        // The code is the one for the step the countdown belongs to. Deriving
        // them from two different `now` readings is how a card shows a code that
        // expires a second later.
        let step_start = now_unix() + live.remaining_secs - live.period;
        assert_eq!(
            code_at(&stored.secret, &stored.params, step_start).unwrap(),
            live.code
        );
    }
}
