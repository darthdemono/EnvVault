//! How a credential is *sent* — Phase 23, E16.
//!
//! The twin of `src/ts/auth-request.ts`, pinned by
//! `tests/fixtures/parity/auth-request.json` and asserted from both sides.
//!
//! *How to send it* is part of the credential, and it was nowhere in the model:
//! two entries holding the same-looking string go one in `Authorization:
//! Bearer`, one in `X-Api-Key`, one in `?api_key=`, one as the password half of
//! HTTP basic. The vault knew the secret and not the one other thing you need in
//! order to use it.
//!
//! **Shell quoting is not optional here.** A cookie, a User-Agent or a password
//! containing `'` breaks `-H '…'`, and every one of these values is vault data,
//! i.e. untrusted input (invariant 4).

use serde_json::Value;

/// The ways a credential can be attached to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Bearer,
    Header,
    Basic,
    Query,
    Cookie,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Bearer => "bearer",
            Scheme::Header => "header",
            Scheme::Basic => "basic",
            Scheme::Query => "query",
            Scheme::Cookie => "cookie",
        }
    }
}

fn s<'a>(e: &'a Value, k: &str) -> &'a str {
    e.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// The scheme this entry uses.
///
/// Absent means `bearer`: it is what most issuers want, and it is the one that
/// fails *loudly* — a wrong header name and a missing query parameter both
/// produce a 401 that names nothing, but a bearer header at least leaves the
/// user something to read in the command.
pub fn scheme_of(entry: &Value) -> Scheme {
    match s(entry, "auth_scheme").to_ascii_lowercase().as_str() {
        "header" => Scheme::Header,
        "basic" => Scheme::Basic,
        "query" => Scheme::Query,
        "cookie" => Scheme::Cookie,
        _ => Scheme::Bearer,
    }
}

/// The header or query-parameter name, with each scheme's default filled in.
pub fn param_of(entry: &Value) -> String {
    let explicit = s(entry, "auth_param").trim();
    if !explicit.is_empty() {
        return explicit.to_string();
    }
    match scheme_of(entry) {
        Scheme::Header => "X-Api-Key".into(),
        Scheme::Query => "api_key".into(),
        Scheme::Cookie => "Cookie".into(),
        _ => String::new(),
    }
}

/// POSIX single-quoting.
///
/// `'` cannot appear inside single quotes at all, so the only way to include one
/// is to close, emit an escaped quote, and reopen. Everything else — `$`, a
/// backtick, a newline, a semicolon — is literal there, which is exactly the
/// property wanted for a value that came out of a vault.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Minimal base64, so this crate needs no encoder for one `Basic` header.
fn b64(raw: &str) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The header this entry contributes, or `None` for the schemes that use none.
pub fn header_for(entry: &Value) -> Option<(String, String)> {
    let value = s(entry, "api_key");
    if value.is_empty() {
        return None;
    }
    match scheme_of(entry) {
        Scheme::Bearer => Some(("Authorization".into(), format!("Bearer {value}"))),
        Scheme::Header => Some((param_of(entry), value.to_string())),
        Scheme::Basic => Some((
            "Authorization".into(),
            format!(
                "Basic {}",
                b64(&format!("{}:{value}", s(entry, "username")))
            ),
        )),
        Scheme::Cookie => Some(("Cookie".into(), value.to_string())),
        Scheme::Query => None,
    }
}

/// Percent-encode everything that is not unreserved, so a key with a `+` or a
/// `/` in it survives the query string.
fn pct(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'!'
            | b'*'
            | b'\''
            | b'('
            | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The query fragment this entry contributes, or `None`.
pub fn query_for(entry: &Value) -> Option<String> {
    if scheme_of(entry) != Scheme::Query {
        return None;
    }
    let value = s(entry, "api_key");
    if value.is_empty() {
        return None;
    }
    Some(format!("{}={}", pct(&param_of(entry)), pct(value)))
}

/// Attach the credential to a URL. Only `query` changes it.
pub fn url_for(entry: &Value, url: &str) -> String {
    match query_for(entry) {
        Some(q) if url.contains('?') => format!("{url}&{q}"),
        Some(q) => format!("{url}?{q}"),
        None => url.to_string(),
    }
}

/// A `curl` command that sends this credential to `url`.
///
/// A **materialising** path: it contains the real credential, so the caller
/// refuses it to stdout without `--reveal` and writes it with `--out`, exactly
/// as `envv export` does.
pub fn curl_for(entry: &Value, url: Option<&str>) -> String {
    let target = match url {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => match s(entry, "api_url") {
            "" => "https://example.invalid/".into(),
            u => u.to_string(),
        },
    };
    let mut parts = vec!["curl".to_string()];
    if let Some((name, value)) = header_for(entry) {
        parts.push("-H".into());
        parts.push(shell_quote(&format!("{name}: {value}")));
    }
    let ua = s(entry, "user_agent");
    if !ua.is_empty() {
        parts.push("-H".into());
        parts.push(shell_quote(&format!("User-Agent: {ua}")));
    }
    parts.push(shell_quote(&url_for(entry, &target)));
    parts.join(" ")
}
