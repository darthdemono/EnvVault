//! `unv cookie import` — Phase 24.5. Turns a DevTools capture (Copy as cURL,
//! HAR, `Set-Cookie` lines, a Firefox `cookies.sqlite`) into a web-session entry.
//!
//! All parsing is `vault_core::session_import`; this file is only the vault
//! edit. Without `--entry` it is a **preview** and writes nothing, printing
//! cookie names, attributes and fingerprints, never values.

use crate::access::Access;
use crate::data::{self, entries_mut, find_entry_index};
use crate::error::{CliError, CliResult};
use crate::out;
use serde_json::{json, Value};
use std::io::Read;
use vault_core::session_import::{self as si, Capture};

pub struct ImportArgs<'a> {
    pub from: &'a str,
    pub file: &'a str,
    pub origin: Option<&'a str>,
    pub host: Option<&'a str>,
    pub entry: Option<&'a str>,
    pub create: bool,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn read_input(file: &str) -> CliResult<String> {
    if file == "-" {
        let mut s = String::new();
        std::io::stdin()
            .take(si::MAX_INPUT as u64 + 1)
            .read_to_string(&mut s)
            .map_err(|e| CliError::invalid(format!("cannot read stdin: {e}")))?;
        return Ok(s);
    }
    let meta = std::fs::metadata(file)
        .map_err(|e| CliError::not_found(format!("cannot read {file}: {e}")))?;
    if meta.len() as usize > si::MAX_INPUT {
        return Err(CliError::invalid("input is larger than 32 MiB"));
    }
    std::fs::read_to_string(file).map_err(|e| CliError::invalid(format!("cannot read {file}: {e}")))
}

fn capture(a: &ImportArgs) -> CliResult<Capture> {
    match a.from {
        "chrome" => Err(CliError::invalid(si::CHROME_REFUSAL)),
        "firefox" => {
            let host = a
                .host
                .or(a.origin)
                .map(|h| {
                    h.split("://")
                        .last()
                        .unwrap_or(h)
                        .split('/')
                        .next()
                        .unwrap_or(h)
                })
                .ok_or_else(|| CliError::invalid("--from firefox needs --host (or --origin)"))?;
            si::read_firefox(std::path::Path::new(a.file), host).map_err(CliError::invalid)
        }
        kind => {
            let text = read_input(a.file)?;
            let r = match kind {
                "curl" => si::parse_curl(&text),
                "powershell" => si::parse_powershell(&text),
                "har" => si::parse_har(&text, a.origin),
                "set-cookie" => si::parse_set_cookie(&text, now()),
                "auto" => si::parse_auto(&text, a.origin, now()),
                other => Err(format!(
                    "unknown --from '{other}' (curl, powershell, har, set-cookie, firefox, auto)"
                )),
            };
            r.map_err(CliError::invalid)
        }
    }
}

fn attrs_json(c: &si::Cookie) -> Value {
    let mut o = serde_json::Map::new();
    if let Some(d) = &c.domain {
        o.insert("domain".into(), json!(d));
    }
    if let Some(p) = &c.path {
        o.insert("path".into(), json!(p));
    }
    if c.secure {
        o.insert("secure".into(), json!(true));
    }
    if c.http_only {
        o.insert("http_only".into(), json!(true));
    }
    if c.expires != 0 {
        o.insert("expires".into(), json!(c.expires));
    }
    Value::Object(o)
}

fn same_cookie(xv: &Value, c: &si::Cookie) -> bool {
    let attr = |k: &str| xv.pointer(&format!("/attrs/{k}")).and_then(Value::as_str);
    xv.get("key").and_then(Value::as_str) == Some(c.name.as_str())
        && (attr("domain").is_none() || c.domain.is_none() || attr("domain") == c.domain.as_deref())
        && (attr("path").is_none() || c.path.is_none() || attr("path") == c.path.as_deref())
}

/// Writes `cap` into `entry` (a web-session entry). Returns (added, updated).
fn merge_into(entry: &mut Value, cap: &Capture) -> (usize, usize) {
    let (mut added, mut updated) = (0, 0);
    let vars = entry
        .as_object_mut()
        .expect("entry is an object")
        .entry("extra_vars")
        .or_insert_with(|| json!([]));
    let vars = vars.as_array_mut().expect("extra_vars is an array");
    for c in &cap.cookies {
        let attrs = attrs_json(c);
        let new = json!({ "key": c.name, "value": c.value, "secret": true, "attrs": attrs });
        match vars.iter_mut().find(|xv| same_cookie(xv, c)) {
            Some(slot) => {
                *slot = new;
                updated += 1;
            }
            None => {
                vars.push(new);
                added += 1;
            }
        }
    }
    if let Some(ua) = &cap.user_agent {
        entry["user_agent"] = json!(ua);
    }
    if entry
        .get("api_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        if let Some(o) = &cap.origin {
            entry["api_url"] = json!(o);
        }
    }
    // A header whose value is a cookie's value is that cookie, copied: record it
    // as `source: cookie` so it follows the cookie when the session is refreshed.
    if !cap.headers.is_empty() {
        let recipe = entry
            .as_object_mut()
            .expect("entry is an object")
            .entry("header_recipe")
            .or_insert_with(|| json!([]));
        let recipe = recipe.as_array_mut().expect("header_recipe is an array");
        for (name, value) in &cap.headers {
            let from_cookie = cap.cookies.iter().find(|c| &c.value == value);
            let item = match from_cookie {
                Some(c) => json!({ "name": name, "source": "cookie", "cookie_name": c.name }),
                None => json!({ "name": name, "source": "static", "static_value": value }),
            };
            match recipe.iter_mut().find(|r| {
                r["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            }) {
                Some(slot) => *slot = item,
                None => recipe.push(item),
            }
        }
    }
    (added, updated)
}

pub fn import(access: &Access, a: &ImportArgs) -> CliResult {
    let cap = capture(a)?;
    if cap.cookies.is_empty() {
        return Err(CliError::invalid(format!(
            "No cookies found.{}",
            if cap.dropped.is_empty() {
                String::new()
            } else {
                format!(" Dropped: {}", cap.dropped.join("; "))
            }
        )));
    }
    let preview: Vec<Value> = cap
        .cookies
        .iter()
        .map(|c| {
            json!({
                "name": c.name, "domain": c.domain, "path": c.path,
                "secure": c.secure, "http_only": c.http_only, "expires": c.expires,
                "partitioned": c.partitioned, "value": out::masked_json(&c.value),
            })
        })
        .collect();
    let header_names: Vec<&str> = cap.headers.iter().map(|(k, _)| k.as_str()).collect();

    let Some(name) = a.entry else {
        let n = cap.cookies.len();
        out::ok(
            "cookie.import.preview",
            json!({
                "written": false, "origin": cap.origin, "cookies": preview,
                "headers": header_names, "user_agent": cap.user_agent.is_some(),
                "dropped": cap.dropped,
            }),
            || {
                println!(
                    "{n} cookie(s) from {}; nothing written (pass --entry NAME).",
                    cap.origin.as_deref().unwrap_or("?")
                );
                for d in &cap.dropped {
                    eprintln!("dropped: {d}");
                }
            },
        );
        return Ok(());
    };

    let mut vault = access.load_vault_or_empty()?;
    let idx = match find_entry_index(&vault, name) {
        Ok(i) => i,
        Err(e) if a.create && e.code == crate::error::Code::NotFound => {
            entries_mut(&mut vault).push(json!({
                "id": vault_core::new_uuid(), "provider": name, "secretType": "cookie",
                "api_key": "", "projectIds": ["Universal"], "categories": [],
            }));
            data::entries(&vault).len() - 1
        }
        Err(e) => return Err(e),
    };
    if data::entries(&vault)[idx]
        .get("secretType")
        .and_then(Value::as_str)
        != Some("cookie")
    {
        return Err(CliError::invalid(format!(
            "'{name}' is not a web-session (cookie) entry; refusing to put cookies in it."
        )));
    }
    let (added, updated) = merge_into(&mut entries_mut(&mut vault)[idx], &cap);
    access.save(&vault)?;
    out::ok(
        "cookie.import",
        json!({
            "written": true, "entry": name, "added": added, "updated": updated,
            "headers": header_names, "dropped": cap.dropped,
        }),
        || {
            println!("'{name}': {added} cookie(s) added, {updated} updated");
            for d in &cap.dropped {
                eprintln!("dropped: {d}");
            }
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_one_cookie_per_name_domain_path_and_links_headers_to_cookies() {
        let mut entry = json!({"provider":"X","secretType":"cookie","extra_vars":[
            {"key":"sid","value":"old","attrs":{"domain":".example.com","path":"/"}},
            {"key":"sid","value":"other-site","attrs":{"domain":".other.test","path":"/"}}]});
        let cap = Capture {
            origin: Some("https://www.example.com".into()),
            cookies: vec![
                si::Cookie {
                    name: "sid".into(),
                    value: "new".into(),
                    domain: Some(".example.com".into()),
                    path: Some("/".into()),
                    ..Default::default()
                },
                si::Cookie {
                    name: "csrf".into(),
                    value: "tok".into(),
                    ..Default::default()
                },
            ],
            headers: vec![
                ("x-csrf-token".into(), "tok".into()),
                ("accept".into(), "a/b".into()),
            ],
            user_agent: Some("UA".into()),
            dropped: vec![],
        };
        let (added, updated) = merge_into(&mut entry, &cap);
        assert_eq!((added, updated), (1, 1));
        let vars = entry["extra_vars"].as_array().unwrap();
        assert_eq!(
            vars.len(),
            3,
            "the other domain's sid is a different cookie"
        );
        assert_eq!(vars[0]["value"], "new");
        assert_eq!(vars[1]["value"], "other-site");
        assert_eq!(entry["user_agent"], "UA");
        assert_eq!(entry["api_url"], "https://www.example.com");
        let r = entry["header_recipe"].as_array().unwrap();
        assert_eq!(
            r[0],
            json!({"name":"x-csrf-token","source":"cookie","cookie_name":"csrf"})
        );
        assert_eq!(r[1]["source"], "static");
    }
}
