//! Web-session capture parsers (Phase 24.5, step 3).
//!
//! One implementation, in `vault-core`: the app reaches it over IPC and the CLI
//! calls it directly, the `pools.ts` shape, so a paste that imports one way in
//! the window cannot import another way from the terminal.
//!
//! Inputs: DevTools **Copy as cURL** (bash, cmd and PowerShell), **HAR**,
//! `Set-Cookie` lines, and a **Firefox `cookies.sqlite`**. Everything parsed is
//! attacker-controlled text (a pasted file from a site you were logged into), so
//! nothing is executed or fetched, lengths are bounded, and cookie values are
//! checked against RFC 6265's cookie-octet set (S10).
//!
//! What a capture is *not*: a place for other credentials. A cURL or HAR paste
//! carries an `Authorization` header and cookies for CDNs and trackers; S12 says
//! only the chosen origin's survive and the caller is told what was dropped, by
//! name and never by value.

use serde::Serialize;
use serde_json::Value;

/// Hard cap on pasted input. A HAR of a long session is megabytes; anything past
/// this is not a login capture.
pub const MAX_INPUT: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    /// Unix seconds. `0` is a session cookie.
    pub expires: i64,
    /// CHIPS. `cookies.txt` cannot express it, so that export refuses (S3).
    pub partitioned: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Capture {
    /// `scheme://host[:port]` the capture was scoped to.
    pub origin: Option<String>,
    pub cookies: Vec<Cookie>,
    /// Headers worth keeping (never `Cookie`, never `Authorization`).
    pub headers: Vec<(String, String)>,
    pub user_agent: Option<String>,
    /// What was left out, by name only — see S12.
    pub dropped: Vec<String>,
}

/// Headers that are either consumed elsewhere or are separate credentials.
const SENSITIVE: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
];
/// Transport noise that tells a replay nothing and bloats the stored recipe.
const NOISE: [&str; 8] = [
    "host",
    "content-length",
    "accept-encoding",
    "connection",
    "cookie",
    "user-agent",
    "priority",
    "te",
];

fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = rest.split(['/', '?', '#']).next()?;
    // userinfo never belongs in an origin
    let host = host.rsplit('@').next()?;
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

fn host_of(origin: &str) -> &str {
    let h = origin.split_once("://").map_or(origin, |(_, r)| r);
    h.rsplit_once(':')
        .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()) && !h.ends_with(']'))
        .map_or(h, |(h, _)| h)
}

/// RFC 6265 cookie-octet: no controls, space, `"`, `,`, `;` or `\`. A value
/// wrapped in one pair of double quotes is allowed to contain the rest.
fn valid_cookie_value(v: &str) -> bool {
    let inner = v
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(v);
    inner
        .chars()
        .all(|c| (c as u32) > 0x20 && (c as u32) < 0x7f && !matches!(c, '"' | ',' | ';' | '\\'))
}

fn cookie_pairs(header: &str, out: &mut Vec<Cookie>, dropped: &mut Vec<String>) {
    for piece in header.split(';') {
        let piece = piece.trim();
        let Some((name, value)) = piece.split_once('=') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() {
            continue;
        }
        if !valid_cookie_value(value) {
            dropped.push(format!("cookie {name} (illegal character in value)"));
            continue;
        }
        upsert(
            out,
            Cookie {
                name: name.to_string(),
                value: value.to_string(),
                ..Default::default()
            },
        );
    }
}

/// Same name + domain + path replaces; a later capture of a cookie wins (S2).
fn upsert(out: &mut Vec<Cookie>, c: Cookie) {
    // An attribute-less cookie (from a request) and an attributed one of the same
    // name (from a response) are the same cookie seen twice; two attributed ones
    // with different domains or paths are genuinely different (S2).
    let bare = |x: &Cookie| x.domain.is_none() && x.path.is_none();
    if let Some(slot) = out.iter_mut().find(|x| {
        x.name == c.name && ((x.domain == c.domain && x.path == c.path) || bare(x) || bare(&c))
    }) {
        *slot = c;
    } else {
        out.push(c);
    }
}

fn keep_header(name: &str, value: &str, cap: &mut Capture) {
    let lower = name.to_ascii_lowercase();
    if lower == "user-agent" {
        cap.user_agent = Some(value.to_string());
    } else if SENSITIVE.contains(&lower.as_str()) {
        let note = format!("{name} header");
        if !cap.dropped.contains(&note) {
            cap.dropped.push(note);
        }
    } else if !NOISE.contains(&lower.as_str()) && !lower.starts_with("sec-fetch-") {
        cap.headers.push((name.to_string(), value.to_string()));
    }
}

// ── Shell tokenising ─────────────────────────────────────────────────────────

/// Splits a bash command line: `'...'`, `"..."` with backslash escapes, `$'...'`
/// (ANSI-C), and `\`-newline continuations. `cmd` mode is un-caret-ed first.
fn shell_split(s: &str) -> Vec<String> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut have = false;
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '\\' if matches!(c.get(i + 1), Some('\n')) => i += 2,
            '\\' if matches!(c.get(i + 1), Some('\r')) => i += 3,
            '\\' => {
                if let Some(n) = c.get(i + 1) {
                    cur.push(*n);
                    have = true;
                }
                i += 2;
            }
            '\'' => {
                have = true;
                i += 1;
                while i < c.len() && c[i] != '\'' {
                    cur.push(c[i]);
                    i += 1;
                }
                i += 1;
            }
            '$' if c.get(i + 1) == Some(&'\'') => {
                have = true;
                i += 2;
                while i < c.len() && c[i] != '\'' {
                    if c[i] == '\\' && i + 1 < c.len() {
                        i += 1;
                        match c[i] {
                            'n' => cur.push('\n'),
                            'r' => cur.push('\r'),
                            't' => cur.push('\t'),
                            'u' | 'x' => {
                                let width = if c[i] == 'u' { 4 } else { 2 };
                                let hex: String = c[i + 1..].iter().take(width).collect();
                                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                                    Some(ch) => {
                                        cur.push(ch);
                                        i += hex.len();
                                    }
                                    None => cur.push(c[i]),
                                }
                            }
                            other => cur.push(other),
                        }
                    } else {
                        cur.push(c[i]);
                    }
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                have = true;
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' && matches!(c.get(i + 1), Some('"' | '\\' | '$' | '`')) {
                        i += 1;
                    }
                    cur.push(c[i]);
                    i += 1;
                }
                i += 1;
            }
            ch if ch.is_whitespace() => {
                if have {
                    out.push(std::mem::take(&mut cur));
                    have = false;
                }
                i += 1;
            }
            ch => {
                cur.push(ch);
                have = true;
                i += 1;
            }
        }
    }
    if have {
        out.push(cur);
    }
    out
}

/// Chrome's "Copy as cURL (cmd)" caret-escapes everything and uses `^"` quotes.
fn uncaret(s: &str) -> String {
    let joined = s.replace("^\r\n", "").replace("^\n", "");
    let mut out = String::new();
    let mut it = joined.chars().peekable();
    while let Some(ch) = it.next() {
        if ch == '^' {
            if let Some(n) = it.next() {
                out.push(n);
            }
        } else {
            out.push(ch);
        }
    }
    // cmd quoting escapes an inner quote as \" inside "..."
    out
}

/// DevTools **Copy as cURL**, bash or cmd flavour.
pub fn parse_curl(text: &str) -> Result<Capture, String> {
    if text.len() > MAX_INPUT {
        return Err("input is too large to be a login capture".into());
    }
    let text = text.trim();
    let normalized = if text.contains("^\"") || text.contains("^\n") {
        uncaret(text)
    } else {
        text.to_string()
    };
    let toks = shell_split(&normalized);
    let mut it = toks.into_iter();
    match it.next().as_deref() {
        Some("curl") | Some("curl.exe") => {}
        _ => return Err("not a curl command".into()),
    }
    let mut cap = Capture::default();
    let mut url: Option<String> = None;
    let mut body = false;
    let mut args = it.peekable();
    while let Some(a) = args.next() {
        let take = |args: &mut std::iter::Peekable<std::vec::IntoIter<String>>| args.next();
        match a.as_str() {
            "-H" | "--header" => {
                if let Some(h) = take(&mut args) {
                    if let Some((k, v)) = h.split_once(':') {
                        let (k, v) = (k.trim(), v.trim());
                        if k.eq_ignore_ascii_case("cookie") {
                            cookie_pairs(v, &mut cap.cookies, &mut cap.dropped);
                        } else {
                            keep_header(k, v, &mut cap);
                        }
                    }
                }
            }
            "-b" | "--cookie" => {
                if let Some(v) = take(&mut args) {
                    if v.contains('=') {
                        cookie_pairs(&v, &mut cap.cookies, &mut cap.dropped);
                    } else {
                        cap.dropped.push("cookie file reference (-b FILE)".into());
                    }
                }
            }
            "-A" | "--user-agent" => cap.user_agent = take(&mut args),
            "-d" | "--data" | "--data-raw" | "--data-binary" | "--data-urlencode" | "-F"
            | "--form" => {
                let _ = take(&mut args);
                body = true;
            }
            "-X" | "--request" | "-e" | "--referer" | "-o" | "--output" | "-m" | "--max-time"
            | "--connect-timeout" | "-x" | "--proxy" | "-u" | "--user" => {
                if matches!(a.as_str(), "-u" | "--user") {
                    cap.dropped.push("basic-auth credentials (-u)".into());
                }
                let _ = take(&mut args);
            }
            "--url" => url = take(&mut args),
            s if s.starts_with('-') => {} // --compressed, -s, -L, --insecure ...
            s => {
                if url.is_none() {
                    url = Some(s.to_string());
                }
            }
        }
    }
    if body {
        cap.dropped.push("request body".into());
    }
    cap.origin = url.as_deref().and_then(origin_of);
    if cap.origin.is_none() {
        return Err("no http(s) URL in the curl command".into());
    }
    Ok(cap)
}

/// DevTools **Copy as PowerShell** (`Invoke-WebRequest`).
pub fn parse_powershell(text: &str) -> Result<Capture, String> {
    if !text.contains("Invoke-WebRequest") && !text.contains("Invoke-RestMethod") {
        return Err("not a PowerShell Invoke-WebRequest".into());
    }
    let mut cap = Capture::default();
    // PowerShell escapes a quote inside "..." as `" and a backtick as ``.
    let unesc = |s: &str| s.replace("`\"", "\"").replace("``", "`").replace("`$", "$");
    let quoted = |hay: &str, from: usize| -> Option<(String, usize)> {
        let rest = &hay[from..];
        let open = rest.find('"')?;
        let bytes = rest.as_bytes();
        let mut i = open + 1;
        while i < bytes.len() {
            if bytes[i] == b'`' {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                return Some((unesc(&rest[open + 1..i]), from + i + 1));
            }
            i += 1;
        }
        None
    };
    // cookies: New-Object System.Net.Cookie("name", "value", "/", "domain")
    let mut at = 0;
    while let Some(p) = text[at..].find("System.Net.Cookie(") {
        let start = at + p + "System.Net.Cookie(".len();
        let Some((name, n1)) = quoted(text, start) else {
            break;
        };
        let Some((value, n2)) = quoted(text, n1) else {
            break;
        };
        let path = quoted(text, n2);
        let (path_v, n3) = path.map_or((None, n2), |(p, n)| (Some(p), n));
        let dom = quoted(text, n3);
        let (dom_v, n4) = dom.map_or((None, n3), |(d, n)| (Some(d), n));
        if valid_cookie_value(&value) {
            upsert(
                &mut cap.cookies,
                Cookie {
                    name,
                    value,
                    path: path_v,
                    domain: dom_v,
                    ..Default::default()
                },
            );
        } else {
            cap.dropped
                .push(format!("cookie {name} (illegal character in value)"));
        }
        at = n4;
    }
    // headers: @{ "name"="value" \n "name2"="value2" }
    if let Some(h) = text.find("-Headers @{") {
        let mut pos = h + "-Headers @{".len();
        while let Some((k, n)) = quoted(text, pos) {
            // stop at the closing brace of the hashtable
            if text[pos..n].contains('}') {
                break;
            }
            let Some((v, n2)) = quoted(text, n) else {
                break;
            };
            keep_header(&k, &v, &mut cap);
            pos = n2;
            if text[pos..].trim_start().starts_with('}') {
                break;
            }
        }
    }
    if let Some(u) = text.find("-Uri ") {
        if let Some((url, _)) = quoted(text, u) {
            cap.origin = origin_of(&url);
        }
    }
    if let Some(ua) = text.find("-UserAgent ") {
        if let Some((v, _)) = quoted(text, ua) {
            cap.user_agent = Some(v);
        }
    }
    if text.contains("-Body ") {
        cap.dropped.push("request body".into());
    }
    if cap.origin.is_none() {
        return Err("no -Uri in the PowerShell command".into());
    }
    Ok(cap)
}

// ── HAR ──────────────────────────────────────────────────────────────────────

/// Parses a HAR **in memory** and keeps only the chosen origin's request cookies
/// and headers. The HAR itself is never stored: it holds every other site the
/// browser talked to. With several origins and no `origin`, the error lists
/// them so the caller can ask.
pub fn parse_har(text: &str, origin: Option<&str>) -> Result<Capture, String> {
    if text.len() > MAX_INPUT {
        return Err("HAR is larger than 32 MiB; export a smaller capture".into());
    }
    let doc: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let entries = doc
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .ok_or("not a HAR: no log.entries")?;

    let origin_for = |e: &Value| {
        e.pointer("/request/url")
            .and_then(Value::as_str)
            .and_then(origin_of)
    };
    let want = match origin {
        Some(o) => origin_of(o).ok_or_else(|| format!("'{o}' is not an http(s) origin"))?,
        None => {
            let mut seen: Vec<String> = Vec::new();
            for e in entries {
                if let Some(o) = origin_for(e) {
                    if !seen.contains(&o) {
                        seen.push(o);
                    }
                }
            }
            match seen.len() {
                0 => return Err("the HAR has no http(s) requests".into()),
                1 => seen.remove(0),
                _ => {
                    return Err(format!(
                        "the HAR touches {} origins; pass --origin one of: {}",
                        seen.len(),
                        seen.join(", ")
                    ))
                }
            }
        }
    };

    let mut cap = Capture {
        origin: Some(want.clone()),
        ..Default::default()
    };
    let mut other_hosts: Vec<String> = Vec::new();
    for e in entries {
        let Some(o) = origin_for(e) else { continue };
        if o != want {
            let host = host_of(&o).to_string();
            if !other_hosts.contains(&host) {
                other_hosts.push(host);
            }
            continue;
        }
        let req = &e["request"];
        for c in req["cookies"].as_array().into_iter().flatten() {
            let (Some(n), Some(v)) = (c["name"].as_str(), c["value"].as_str()) else {
                continue;
            };
            if valid_cookie_value(v) {
                upsert(
                    &mut cap.cookies,
                    Cookie {
                        name: n.into(),
                        value: v.into(),
                        ..Default::default()
                    },
                );
            } else {
                cap.dropped
                    .push(format!("cookie {n} (illegal character in value)"));
            }
        }
        // Response cookies carry the attributes request cookies lack.
        for c in e["response"]["cookies"].as_array().into_iter().flatten() {
            let (Some(n), Some(v)) = (c["name"].as_str(), c["value"].as_str()) else {
                continue;
            };
            if !valid_cookie_value(v) {
                continue;
            }
            let expires = c["expires"]
                .as_str()
                .and_then(|s| {
                    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                        .ok()
                })
                .map_or(0, |d| d.unix_timestamp());
            upsert(
                &mut cap.cookies,
                Cookie {
                    name: n.into(),
                    value: v.into(),
                    domain: c["domain"].as_str().map(String::from),
                    path: c["path"].as_str().map(String::from),
                    secure: c["secure"].as_bool().unwrap_or(false),
                    http_only: c["httpOnly"].as_bool().unwrap_or(false),
                    expires,
                    partitioned: false,
                },
            );
        }
        for h in req["headers"].as_array().into_iter().flatten() {
            if let (Some(n), Some(v)) = (h["name"].as_str(), h["value"].as_str()) {
                if n.starts_with(':') {
                    continue; // HTTP/2 pseudo-headers
                }
                // later requests win by header name
                cap.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(n));
                keep_header(n, v, &mut cap);
            }
        }
        if req.get("postData").is_some() && !cap.dropped.iter().any(|d| d == "request body") {
            cap.dropped.push("request body".into());
        }
    }
    if !other_hosts.is_empty() {
        cap.dropped.push(format!(
            "requests to {} other host(s): {}",
            other_hosts.len(),
            other_hosts.join(", ")
        ));
    }
    Ok(cap)
}

// ── Set-Cookie ───────────────────────────────────────────────────────────────

fn parse_http_date(s: &str) -> Option<i64> {
    // RFC 2822 allows nested `(comments)`, and `time` < 0.3.47 recurses on them
    // (RUSTSEC-2026-0009: stack exhaustion). The text is attacker-controlled — a
    // pasted `Set-Cookie` from any site — and a real cookie date is ~30 bytes with
    // no parentheses, so both are refused before the parser sees them.
    if s.len() > 64 || s.contains(['(', ')']) {
        return None;
    }
    time::OffsetDateTime::parse(s.trim(), &time::format_description::well_known::Rfc2822)
        .ok()
        .map(|d| d.unix_timestamp())
        .or_else(|| {
            // "Wed, 21-Oct-2015 07:28:00 GMT" (the obsolete cookie spelling)
            let fixed = s.trim().replace('-', " ");
            time::OffsetDateTime::parse(&fixed, &time::format_description::well_known::Rfc2822)
                .ok()
                .map(|d| d.unix_timestamp())
        })
}

/// One or more `Set-Cookie:` lines (or bare `name=value; Attr` lines).
pub fn parse_set_cookie(text: &str, now_unix: i64) -> Result<Capture, String> {
    let mut cap = Capture::default();
    for line in text.lines() {
        let line = line.trim();
        let line = line
            .strip_prefix("Set-Cookie:")
            .or_else(|| line.strip_prefix("set-cookie:"))
            .unwrap_or(line)
            .trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(';');
        let Some((name, value)) = parts.next().and_then(|p| p.split_once('=')) else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() {
            continue;
        }
        if !valid_cookie_value(value) {
            cap.dropped
                .push(format!("cookie {name} (illegal character in value)"));
            continue;
        }
        let mut c = Cookie {
            name: name.into(),
            value: value.into(),
            ..Default::default()
        };
        let mut max_age: Option<i64> = None;
        for attr in parts {
            let (k, v) = attr
                .split_once('=')
                .map_or((attr.trim(), ""), |(k, v)| (k.trim(), v.trim()));
            match k.to_ascii_lowercase().as_str() {
                "domain" => {
                    c.domain = Some(v.trim_start_matches('.').to_string())
                        .filter(|d| !d.is_empty())
                        .map(|d| format!(".{d}"))
                }
                "path" => c.path = Some(v.to_string()),
                "secure" => c.secure = true,
                "httponly" => c.http_only = true,
                "partitioned" => c.partitioned = true,
                "max-age" => max_age = v.parse().ok(),
                "expires" => c.expires = parse_http_date(v).unwrap_or(0),
                _ => {}
            }
        }
        // Max-Age beats Expires (RFC 6265 5.3).
        if let Some(m) = max_age {
            c.expires = if m <= 0 { 1 } else { now_unix + m };
        }
        // __Host- requires Secure, Path=/ and no Domain; a violating cookie is
        // one the browser would have rejected, so importing it would mislead.
        if name.starts_with("__Host-")
            && (!c.secure || c.path.as_deref() != Some("/") || c.domain.is_some())
        {
            cap.dropped
                .push(format!("cookie {name} (violates the __Host- prefix rules)"));
            continue;
        }
        if name.starts_with("__Secure-") && !c.secure {
            cap.dropped.push(format!(
                "cookie {name} (violates the __Secure- prefix rules)"
            ));
            continue;
        }
        upsert(&mut cap.cookies, c);
    }
    if cap.cookies.is_empty() && cap.dropped.is_empty() {
        return Err("no Set-Cookie lines found".into());
    }
    Ok(cap)
}

// ── Firefox ──────────────────────────────────────────────────────────────────

/// Reads a Firefox profile's `cookies.sqlite` for one host (matching `host` and
/// its subdomains). Opened read-only from a **copy** (Firefox keeps the live file
/// locked and its WAL separate). Firefox does not encrypt this file.
///
/// Chrome on Windows is deliberately not here: since Chrome 127, app-bound
/// encryption ties cookie decryption to the Chrome process, so no external tool
/// can read it — the same wall `yt-dlp --cookies-from-browser` hits.
pub fn read_firefox(path: &std::path::Path, host: &str) -> Result<Capture, String> {
    let dir = std::env::temp_dir().join(format!(
        "envv-ff-{}-{}",
        std::process::id(),
        crate::new_uuid()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let result = (|| {
        let copy = dir.join("cookies.sqlite");
        std::fs::copy(path, &copy).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let wal = path.with_extension("sqlite-wal");
        if wal.exists() {
            let _ = std::fs::copy(&wal, dir.join("cookies.sqlite-wal"));
        }
        let conn = rusqlite::Connection::open_with_flags(
            &copy,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE, // WAL replay needs write on the copy
        )
        .map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT name, value, host, path, expiry, isSecure, isHttpOnly, originAttributes \
                 FROM moz_cookies WHERE host = ?1 OR host = ?2 OR host LIKE ?3",
            )
            .map_err(|e| format!("not a Firefox cookies.sqlite: {e}"))?;
        let host = host.trim_start_matches('.');
        let rows = stmt
            .query_map(
                rusqlite::params![host, format!(".{host}"), format!("%.{host}")],
                |r| {
                    Ok(Cookie {
                        name: r.get(0)?,
                        value: r.get(1)?,
                        domain: Some(r.get::<_, String>(2)?),
                        path: Some(r.get::<_, String>(3)?),
                        // Newer Firefox stores milliseconds
                        expires: {
                            let e: i64 = r.get(4)?;
                            if e > 100_000_000_000 {
                                e / 1000
                            } else {
                                e
                            }
                        },
                        secure: r.get::<_, i64>(5)? != 0,
                        http_only: r.get::<_, i64>(6)? != 0,
                        partitioned: r.get::<_, String>(7)?.contains("partitionKey="),
                    })
                },
            )
            .map_err(|e| e.to_string())?;
        let mut cap = Capture::default();
        for row in rows {
            let c = row.map_err(|e| e.to_string())?;
            if valid_cookie_value(&c.value) {
                upsert(&mut cap.cookies, c);
            } else {
                cap.dropped
                    .push(format!("cookie {} (illegal character in value)", c.name));
            }
        }
        Ok(cap)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// What to say when someone asks for Chrome.
pub const CHROME_REFUSAL: &str =
    "Chrome cookies are not read. Since Chrome 127 on Windows, app-bound encryption ties cookie \
     decryption to the Chrome process, so no outside tool can read them (yt-dlp's \
     --cookies-from-browser fails the same way). Export from DevTools (Copy as cURL, or Save all \
     as HAR) or use Firefox.";

/// Sniffs which dialect a paste is.
pub fn detect(text: &str) -> &'static str {
    let t = text.trim_start();
    if t.starts_with("curl") {
        "curl"
    } else if t.contains("Invoke-WebRequest") || t.contains("Invoke-RestMethod") {
        "powershell"
    } else if t.starts_with('{') && t.contains("\"log\"") {
        "har"
    } else {
        "set-cookie"
    }
}

/// Parse a paste of unknown dialect.
pub fn parse_auto(text: &str, origin: Option<&str>, now_unix: i64) -> Result<Capture, String> {
    match detect(text) {
        "curl" => parse_curl(text),
        "powershell" => parse_powershell(text),
        "har" => parse_har(text, origin),
        _ => parse_set_cookie(text, now_unix),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASH: &str = r#"curl 'https://www.example.com/api/me?x=1' \
  -H 'accept: application/json' \
  -H 'authorization: Bearer topsecret' \
  -H 'cookie: sid=abc123; csrftoken=zz9; bad=a b' \
  -H 'user-agent: Mozilla/5.0 (X11; Linux x86_64)' \
  -H 'sec-fetch-mode: cors' \
  -H 'x-csrf-token: zz9' \
  --data-raw '{"a":1}' \
  --compressed"#;

    #[test]
    fn bash_curl_keeps_the_origins_session_and_names_what_it_dropped() {
        let c = parse_curl(BASH).unwrap();
        assert_eq!(c.origin.as_deref(), Some("https://www.example.com"));
        assert_eq!(
            c.cookies
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["sid", "csrftoken"]
        );
        assert_eq!(
            c.user_agent.as_deref(),
            Some("Mozilla/5.0 (X11; Linux x86_64)")
        );
        let names: Vec<_> = c.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            ["accept", "x-csrf-token"],
            "noise and credentials are not kept"
        );
        // S12: reported by name, never by value.
        assert!(c.dropped.iter().any(|d| d == "authorization header"));
        assert!(c.dropped.iter().any(|d| d == "request body"));
        assert!(c
            .dropped
            .iter()
            .any(|d| d.contains("bad") && d.contains("illegal")));
        assert!(!format!("{:?}", c.dropped).contains("topsecret"));
    }

    #[test]
    fn cmd_flavoured_curl_is_uncaret_ed() {
        let cmd = "curl ^\"https://www.example.com/^\" ^\n  -H ^\"cookie: sid=abc^\" ^\n  -H ^\"user-agent: UA/1^\"";
        let c = parse_curl(cmd).unwrap();
        assert_eq!(c.origin.as_deref(), Some("https://www.example.com"));
        assert_eq!(c.cookies[0].value, "abc");
        assert_eq!(c.user_agent.as_deref(), Some("UA/1"));
    }

    #[test]
    fn ansi_c_quoting_is_decoded() {
        let c = parse_curl("curl 'https://e.test/' -H $'user-agent: caf\\u00e9'").unwrap();
        assert_eq!(c.user_agent.as_deref(), Some("café"));
    }

    #[test]
    fn powershell_capture_yields_cookies_headers_and_origin() {
        let ps = r#"$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = "x"
$session.Cookies.Add((New-Object System.Net.Cookie("sid", "abc", "/", "www.example.com")))
Invoke-WebRequest -UseBasicParsing -Uri "https://www.example.com/a" `
-WebSession $session `
-Headers @{
"accept"="text/html"
"authorization"="Bearer nope"
}"#;
        let c = parse_powershell(ps).unwrap();
        assert_eq!(c.origin.as_deref(), Some("https://www.example.com"));
        assert_eq!(c.cookies[0].name, "sid");
        assert_eq!(c.cookies[0].domain.as_deref(), Some("www.example.com"));
        assert_eq!(
            c.headers,
            vec![("accept".to_string(), "text/html".to_string())]
        );
        assert!(c.dropped.iter().any(|d| d == "authorization header"));
    }

    fn har() -> String {
        serde_json::json!({"log":{"entries":[
          {"request":{"url":"https://www.example.com/a","headers":[
              {"name":":authority","value":"x"},{"name":"user-agent","value":"UA"},
              {"name":"authorization","value":"Bearer t"},{"name":"x-csrf-token","value":"old"}],
            "cookies":[{"name":"sid","value":"1"}]},
           "response":{"cookies":[{"name":"sid","value":"2","domain":".example.com","path":"/","secure":true,"httpOnly":true,"expires":"2030-01-01T00:00:00Z"}]}},
          {"request":{"url":"https://www.example.com/b","headers":[{"name":"x-csrf-token","value":"new"}],
            "cookies":[{"name":"csrf","value":"c"}]},"response":{"cookies":[]}},
          {"request":{"url":"https://cdn.tracker.test/p","headers":[],"cookies":[{"name":"t","value":"9"}]},"response":{"cookies":[]}}
        ]}}).to_string()
    }

    #[test]
    fn har_keeps_one_origin_and_lists_the_others_it_dropped() {
        let c = parse_har(&har(), Some("https://www.example.com")).unwrap();
        assert!(
            c.cookies.iter().all(|c| c.name != "t"),
            "a CDN's cookie must not be kept"
        );
        let sid = c.cookies.iter().find(|c| c.name == "sid").unwrap();
        assert_eq!(
            sid.value, "2",
            "the response cookie's value and attributes win"
        );
        assert!(sid.secure && sid.http_only && sid.expires > 0);
        assert_eq!(
            c.headers,
            vec![("x-csrf-token".to_string(), "new".to_string())]
        );
        assert!(c.dropped.iter().any(|d| d.contains("cdn.tracker.test")));
        assert!(c.dropped.iter().any(|d| d == "authorization header"));
    }

    #[test]
    fn har_with_several_origins_asks_instead_of_guessing() {
        let err = parse_har(&har(), None).unwrap_err();
        assert!(err.contains("--origin") && err.contains("cdn.tracker.test"));
    }

    #[test]
    fn set_cookie_attributes_and_prefix_rules() {
        let now = 1_700_000_000;
        let c = parse_set_cookie(
            "Set-Cookie: sid=abc; Domain=example.com; Path=/; Secure; HttpOnly; Max-Age=3600; Partitioned\n\
             Set-Cookie: __Host-x=1; Domain=example.com; Path=/; Secure\n\
             Set-Cookie: old=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
            now,
        )
        .unwrap();
        let sid = &c.cookies[0];
        assert_eq!(sid.domain.as_deref(), Some(".example.com"));
        assert_eq!(sid.expires, now + 3600, "Max-Age beats Expires");
        assert!(sid.secure && sid.http_only && sid.partitioned);
        assert!(c.cookies.iter().all(|c| c.name != "__Host-x"));
        assert!(c.dropped.iter().any(|d| d.contains("__Host-")));
        assert_eq!(
            c.cookies.iter().find(|c| c.name == "old").unwrap().expires,
            1_445_412_480
        );
    }

    #[test]
    fn a_hostile_expires_value_cannot_exhaust_the_stack() {
        let nested = format!(
            "Wed, 21 Oct 2015 07:28:00 GMT {}{}",
            "(".repeat(200_000),
            ")".repeat(200_000)
        );
        let c = parse_set_cookie(&format!("Set-Cookie: a=b; Expires={nested}"), 0).unwrap();
        assert_eq!(
            c.cookies[0].expires, 0,
            "an unparseable date is a session cookie, not a crash"
        );
    }

    #[test]
    fn detect_routes_each_dialect() {
        assert_eq!(detect("curl 'https://a.test'"), "curl");
        assert_eq!(
            detect("Invoke-WebRequest -Uri \"https://a.test\""),
            "powershell"
        );
        assert_eq!(detect("{\"log\":{}}"), "har");
        assert_eq!(detect("Set-Cookie: a=b"), "set-cookie");
    }

    #[test]
    fn firefox_sqlite_is_read_from_a_copy_and_filtered_by_host() {
        let dir = std::env::temp_dir().join(format!("envv-ffsrc-{}", crate::new_uuid()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("cookies.sqlite");
        {
            let c = rusqlite::Connection::open(&db).unwrap();
            c.execute_batch(
                "CREATE TABLE moz_cookies (name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, originAttributes TEXT);
                 INSERT INTO moz_cookies VALUES ('sid','1','.example.com','/',1893456000,1,1,'');
                 INSERT INTO moz_cookies VALUES ('p','2','www.example.com','/',1893456000000,0,0,'^partitionKey=%28https%2Cexample.com%29');
                 INSERT INTO moz_cookies VALUES ('other','3','.evil.test','/',0,0,0,'');",
            )
            .unwrap();
        }
        let cap = read_firefox(&db, "example.com").unwrap();
        assert_eq!(cap.cookies.len(), 2);
        assert!(cap.cookies.iter().all(|c| c.name != "other"));
        let p = cap.cookies.iter().find(|c| c.name == "p").unwrap();
        assert!(p.partitioned);
        assert_eq!(p.expires, 1_893_456_000, "millisecond expiry is normalised");
        assert!(db.exists(), "the live file is never modified");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
