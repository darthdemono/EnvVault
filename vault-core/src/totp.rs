//! RFC 6238 time-based one-time passwords, for sub-user login only.
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
//! `hmac` is already a dependency (`entropy.rs` builds HKDF on it) and `sha1` is
//! added for the one algorithm RFC 6238 pins for interoperability. Base32 is
//! forty lines and lives here rather than behind a crate, for the same reason
//! HKDF does: the encoding is part of what a reader has to check.

use hmac::{Hmac, Mac};
use sha1::Sha1;

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

/// HOTP (RFC 4226) for one counter value.
pub fn hotp(secret: &[u8], counter: u64) -> String {
    // `new_from_slice` only fails for key lengths HMAC cannot take, and HMAC
    // accepts any length, so this cannot fail in practice.
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // Dynamic truncation, RFC 4226 §5.3.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);

    let modulus = 10u32.pow(DIGITS);
    format!("{:0width$}", binary % modulus, width = DIGITS as usize)
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
        let uri = otpauth_uri("EnvVault", "a&issuer=Evil?x=1", "ABCD");
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
}
