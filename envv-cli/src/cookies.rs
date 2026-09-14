//! Session cookies — Phase 23, step 5.
//!
//! The twin of `src/ts/cookies.ts`, pinned by
//! `tests/fixtures/parity/cookies.json` and asserted from both sides.
//!
//! Spotify, YouTube, Instagram and everything driven by `yt-dlp` are used
//! through a session cookie and nothing else, and before this there was no home
//! for one: the jar went in a free-text field and the User-Agent it was minted
//! against went nowhere — so the vault held half a credential and did not say
//! which half was missing.
//!
//! **`cookies.txt` is refused rather than approximated.** The Netscape format
//! needs a domain, an include-subdomains flag, a path, a secure flag and an
//! expiry per cookie; a jar pasted as a bare `document.cookie` string carries
//! none of them, and a file `yt-dlp` silently ignores is worse than no button.

use serde_json::Value;

/// One cookie, with whatever attributes the source carried.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    /// Unix seconds. `0` is a session cookie.
    pub expires: i64,
}

/// Split a `document.cookie` string, or a `Cookie:` header.
///
/// Deliberately forgiving: half the jars people paste carry a trailing `;`, a
/// stray newline, or the `Cookie: ` prefix. Unlike an `otpauth://` URI there is
/// no checksum to tell a mangled jar from a good one, so the rule is to take
/// what parses and drop what does not.
pub fn parse_cookie_header(raw: &str) -> Vec<Cookie> {
    let body = raw.trim();
    let body = body
        .strip_prefix("Cookie:")
        .or_else(|| body.strip_prefix("cookie:"))
        .unwrap_or(body)
        .trim();
    let mut out = Vec::new();
    for piece in body.split([';', '\n']) {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let Some(eq) = piece.find('=') else { continue };
        if eq == 0 {
            continue;
        }
        let name = piece[..eq].trim();
        if name.is_empty() {
            continue;
        }
        out.push(Cookie {
            name: name.to_string(),
            value: piece[eq + 1..].trim().to_string(),
            ..Default::default()
        });
    }
    out
}

/// Parse a Netscape `cookies.txt`.
///
/// Seven tab-separated fields. `#HttpOnly_` is curl's line prefix and carries
/// the flag, so it is read rather than skipped as a comment.
pub fn parse_cookies_txt(raw: &str) -> Vec<Cookie> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let mut l = line.trim();
        let mut http_only = false;
        if let Some(rest) = l
            .strip_prefix("#HttpOnly_")
            .or_else(|| l.strip_prefix("#httponly_"))
        {
            http_only = true;
            l = rest;
        } else if l.starts_with('#') || l.is_empty() {
            continue;
        }
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 7 {
            continue;
        }
        out.push(Cookie {
            domain: Some(f[0].to_string()),
            path: Some(f[2].to_string()),
            secure: f[3].eq_ignore_ascii_case("TRUE"),
            expires: f[4].parse().unwrap_or(0),
            name: f[5].to_string(),
            value: f[6..].join("\t"),
            http_only,
        });
    }
    out
}

fn from_json_cookie(raw: &Value) -> Option<Cookie> {
    let name = raw
        .get("name")
        .or_else(|| raw.get("Name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if name.is_empty() {
        return None;
    }
    let flag = |a: &str, b: &str| {
        raw.get(a)
            .or_else(|| raw.get(b))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let expires = ["expirationDate", "expires", "expiry", "Expires"]
        .iter()
        .find_map(|k| raw.get(*k).and_then(|v| v.as_f64()))
        .map(|f| f as i64)
        .unwrap_or(0);
    Some(Cookie {
        name: name.to_string(),
        value: raw
            .get("value")
            .or_else(|| raw.get("Value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        domain: raw
            .get("domain")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        path: raw
            .get("path")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        secure: flag("secure", "Secure"),
        http_only: flag("httpOnly", "HttpOnly"),
        expires,
    })
}

/// Parse the array shape every "Copy all as JSON" / cookie-editor extension writes.
pub fn parse_cookie_json(raw: &str) -> Vec<Cookie> {
    let Ok(doc) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    let arr = match &doc {
        Value::Array(a) => a.clone(),
        Value::Object(o) => o
            .get("cookies")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    arr.iter().filter_map(from_json_cookie).collect()
}

/// Whatever was pasted, as cookies.
///
/// One entry point rather than three: the user pasting a jar does not know which
/// of the three formats their browser gave them, and asking is a worse question
/// than looking.
pub fn parse_any(raw: &str) -> Vec<Cookie> {
    let text = raw.trim();
    if text.is_empty() {
        return Vec::new();
    }
    if text.starts_with('[') || text.starts_with('{') {
        let json = parse_cookie_json(text);
        if !json.is_empty() {
            return json;
        }
    }
    if text.contains('\t') {
        let txt = parse_cookies_txt(text);
        if !txt.is_empty() {
            return txt;
        }
    }
    parse_cookie_header(text)
}

/// The `Cookie:` header value — what a request actually sends.
pub fn to_cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .filter(|c| !c.name.is_empty())
        .map(|c| format!("{}={}", c.name, c.value))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Which attributes `cookies.txt` needs and this jar does not have.
pub fn missing_txt_attributes(cookies: &[Cookie]) -> Vec<String> {
    let mut missing: Vec<String> = Vec::new();
    for c in cookies {
        if c.domain.as_deref().unwrap_or("").is_empty() && !missing.iter().any(|m| m == "domain") {
            missing.push("domain".into());
        }
        if c.path.as_deref().unwrap_or("").is_empty() && !missing.iter().any(|m| m == "path") {
            missing.push("path".into());
        }
    }
    missing.sort();
    missing
}

/// Netscape `cookies.txt`, for `curl -b` and `yt-dlp --cookies`.
///
/// **Errors when the attributes are not there.** A file missing them is one
/// `yt-dlp` reads and silently ignores, which the user discovers as "the
/// download is not logged in", with nothing pointing at the file.
pub fn to_cookies_txt(cookies: &[Cookie]) -> Result<String, String> {
    let missing = missing_txt_attributes(cookies);
    if !missing.is_empty() {
        return Err(format!(
            "cookies.txt needs {} for every cookie, and this jar has none. Re-export it from the \
             browser as JSON or as cookies.txt rather than copying document.cookie.",
            missing.join(" and ")
        ));
    }
    let mut lines = vec![
        "# Netscape HTTP Cookie File".to_string(),
        "# Written by EnvVault. Move it somewhere safe and delete it when done.".to_string(),
    ];
    for c in cookies {
        let domain = c.domain.clone().unwrap_or_default();
        // The include-subdomains column is the leading dot, restated. Deriving
        // it rather than storing it means the two can never disagree.
        let include_sub = if domain.starts_with('.') {
            "TRUE"
        } else {
            "FALSE"
        };
        let line = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            domain,
            include_sub,
            c.path.clone().unwrap_or_else(|| "/".into()),
            if c.secure { "TRUE" } else { "FALSE" },
            c.expires,
            c.name,
            c.value
        );
        lines.push(if c.http_only {
            format!("#HttpOnly_{line}")
        } else {
            line
        });
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

/// The browser-extension array shape, so a jar round-trips back into a browser.
pub fn to_cookie_json(cookies: &[Cookie]) -> String {
    let arr: Vec<Value> = cookies
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "value": c.value,
                "domain": c.domain.clone().unwrap_or_default(),
                "path": c.path.clone().unwrap_or_else(|| "/".into()),
                "secure": c.secure,
                "httpOnly": c.http_only,
                // Seconds, because that is what `cookies.txt` carries — a jar
                // that round-trips must not gain or lose a factor of 1000.
                "expirationDate": c.expires,
            })
        })
        .collect();
    serde_json::to_string_pretty(&arr).unwrap_or_default()
}

/// The cookie name with any `__Host-` / `__Secure-` prefix removed.
pub fn bare_cookie_name(name: &str) -> &str {
    for p in ["__Host-", "__Secure-"] {
        if name.len() >= p.len() && name[..p.len()].eq_ignore_ascii_case(p) {
            return &name[p.len()..];
        }
    }
    name
}
