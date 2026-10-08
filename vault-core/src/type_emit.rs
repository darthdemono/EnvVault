//! Per-type emitters and validators for the Phase 24.5 credential types.
//!
//! The registry (`secret-types.json`) says which types exist; this is what a few
//! of them *do* beyond holding fields. Everything is pure over the entry JSON, so
//! the desktop app (over IPC) and `envv emit` produce the same bytes.
//!
//! **These are materialising paths.** An emitted `.npmrc`, `config.json` or DSN
//! contains the credential, so the CLI treats them like `export`: refused to
//! stdout unless `--reveal`, written 0600 by `--out`. Nothing here masks; that is
//! the caller's rule, decided once (Phase 14).

use crate::composite::{self, Kind, Part};
use base64::Engine;
use serde_json::Value;

fn s<'a>(entry: &'a Value, key: &str) -> &'a str {
    entry.get(key).and_then(Value::as_str).unwrap_or("")
}

/// A named variable's value, or `""`.
pub fn var<'a>(entry: &'a Value, key: &str) -> &'a str {
    entry
        .get("extra_vars")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|v| v.get("key").and_then(Value::as_str) == Some(key))
        .and_then(|v| v.get("value").and_then(Value::as_str))
        .unwrap_or("")
}

fn first<'a>(candidates: &[&'a str]) -> &'a str {
    candidates
        .iter()
        .copied()
        .find(|c| !c.is_empty())
        .unwrap_or("")
}

fn need<'a>(label: &str, value: &'a str) -> Result<&'a str, String> {
    if value.is_empty() {
        Err(format!("{label} is empty; fill it in before emitting"))
    } else {
        Ok(value)
    }
}

/// Formats an entry's type offers.
pub fn formats_for(secret_type: &str) -> &'static [&'static str] {
    match secret_type {
        "registry_token" => &[
            "npmrc",
            "pypirc",
            "cargo-credentials",
            "docker-config",
            "netrc",
        ],
        "database" => &["dsn", "libpq", "jdbc"],
        "wifi" => &["wifi-uri"],
        _ => &[],
    }
}

pub fn emit(entry: &Value, format: &str) -> Result<String, String> {
    let ty = s(entry, "secretType");
    if !formats_for(ty).contains(&format) {
        return Err(format!(
            "'{format}' is not an output of a {ty} entry (it offers: {})",
            formats_for(ty).join(", ")
        ));
    }
    match format {
        "npmrc" | "pypirc" | "cargo-credentials" | "docker-config" | "netrc" => {
            registry(entry, format)
        }
        "dsn" | "libpq" | "jdbc" => database(entry, format),
        "wifi-uri" => wifi_uri(entry),
        _ => unreachable!("formats_for gates this"),
    }
}

// ── Registry tokens ──────────────────────────────────────────────────────────

fn registry_host(entry: &Value) -> String {
    let url = s(entry, "api_url");
    if !url.is_empty() {
        return url
            .split("://")
            .last()
            .unwrap_or(url)
            .trim_end_matches('/')
            .to_string();
    }
    match var(entry, "registry").to_ascii_lowercase().as_str() {
        "npm" | "" => "registry.npmjs.org",
        "pypi" => "upload.pypi.org/legacy",
        "crates" | "crates.io" | "cargo" => "crates.io",
        "docker" | "dockerhub" => "index.docker.io/v1/",
        "ghcr" => "ghcr.io",
        other => return other.to_string(),
    }
    .to_string()
}

fn toml_str(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

fn registry(entry: &Value, format: &str) -> Result<String, String> {
    let token = need("the token", s(entry, "api_key"))?;
    let user = first(&[s(entry, "username"), var(entry, "username")]);
    let host = registry_host(entry);
    if token.contains(['\n', '\r']) {
        return Err("a token with a line break cannot be written into a config file".into());
    }
    Ok(match format {
        "npmrc" => format!("//{host}/:_authToken={token}\n"),
        "pypirc" => format!(
            "[pypi]\nusername = {}\npassword = {token}\n",
            if user.is_empty() { "__token__" } else { user }
        ),
        "cargo-credentials" => {
            if host == "crates.io" {
                format!("[registry]\ntoken = {}\n", toml_str(token))
            } else {
                let name = host.split('.').next().unwrap_or("registry");
                format!("[registries.{name}]\ntoken = {}\n", toml_str(token))
            }
        }
        "docker-config" => {
            let user = need("the username (Docker's auth is user:token)", user)?;
            let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"));
            let server = host.trim_end_matches('/');
            serde_json::to_string_pretty(&serde_json::json!({
                "auths": { server: { "auth": auth } }
            }))
            .map_err(|e| e.to_string())?
                + "\n"
        }
        "netrc" => {
            let user = need("the username", user)?;
            let machine = host.split('/').next().unwrap_or(&host);
            format!("machine {machine} login {user} password {token}\n")
        }
        _ => unreachable!(),
    })
}

// ── Databases ────────────────────────────────────────────────────────────────

fn parts(entry: &Value) -> Vec<Part> {
    [
        ("user", first(&[var(entry, "user"), s(entry, "username")])),
        ("password", s(entry, "api_key")),
        ("host", var(entry, "host")),
        ("port", var(entry, "port")),
        ("database", var(entry, "database")),
        ("sslmode", var(entry, "sslmode")),
    ]
    .into_iter()
    .map(|(k, v)| Part {
        key: k.into(),
        value: v.into(),
    })
    .collect()
}

fn render_conn(template: &str, entry: &Value) -> Result<String, String> {
    composite::render(template, &parts(entry), Kind::Connection)
        .map(|r| r.text)
        .map_err(|e| e.to_string())
}

fn database(entry: &Value, format: &str) -> Result<String, String> {
    let engine = var(entry, "engine").to_ascii_lowercase();
    let engine = if engine.is_empty() {
        "postgres".to_string()
    } else {
        engine
    };
    need("the host", var(entry, "host"))?;
    let q = if var(entry, "sslmode").is_empty() {
        ""
    } else {
        "?sslmode={sslmode}"
    };
    let port = if var(entry, "port").is_empty() {
        ""
    } else {
        ":{port}"
    };
    match format {
        "dsn" => {
            let scheme = match engine.as_str() {
                "postgres" | "postgresql" => "postgresql",
                "mysql" | "mariadb" => "mysql",
                "mongodb" | "mongo" => "mongodb",
                "redis" => "redis",
                "amqp" | "rabbitmq" => "amqp",
                other => return Err(format!("no DSN scheme is known for engine '{other}'")),
            };
            let auth = if var(entry, "user").is_empty() && s(entry, "username").is_empty() {
                "{password}"
            } else {
                "{user}:{password}"
            };
            let at = if engine == "redis" && auth == "{password}" {
                ":{password}@"
            } else {
                "{auth}@"
            };
            let at = at.replace("{auth}", auth);
            let db = if var(entry, "database").is_empty() {
                ""
            } else {
                "/{database}"
            };
            render_conn(&format!("{scheme}://{at}{{host}}{port}{db}{q}"), entry)
        }
        "libpq" => {
            if !matches!(engine.as_str(), "postgres" | "postgresql") {
                return Err("libpq variables (PGHOST, …) are PostgreSQL's".into());
            }
            let mut out = String::new();
            for (name, value) in [
                ("PGHOST", var(entry, "host")),
                ("PGPORT", var(entry, "port")),
                ("PGDATABASE", var(entry, "database")),
                ("PGUSER", first(&[var(entry, "user"), s(entry, "username")])),
                ("PGPASSWORD", s(entry, "api_key")),
                ("PGSSLMODE", var(entry, "sslmode")),
            ] {
                if !value.is_empty() {
                    out.push_str(&format!("{name}={}\n", crate::env_quote(value)));
                }
            }
            Ok(out)
        }
        "jdbc" => {
            let user = first(&[var(entry, "user"), s(entry, "username")]);
            match engine.as_str() {
                "postgres" | "postgresql" | "mysql" | "mariadb" => {
                    let sub = if engine.starts_with("postgres") {
                        "postgresql"
                    } else {
                        engine.as_str()
                    };
                    let db = if var(entry, "database").is_empty() {
                        ""
                    } else {
                        "/{database}"
                    };
                    let mut query = vec![];
                    if !user.is_empty() {
                        query.push("user={user}");
                    }
                    if !s(entry, "api_key").is_empty() {
                        query.push("password={password}");
                    }
                    if !var(entry, "sslmode").is_empty() {
                        query.push("sslmode={sslmode}");
                    }
                    let query = if query.is_empty() {
                        String::new()
                    } else {
                        format!("?{}", query.join("&"))
                    };
                    render_conn(&format!("jdbc:{sub}://{{host}}{port}{db}{query}"), entry)
                }
                "sqlserver" | "mssql" => {
                    // SQL Server's JDBC uses `;key=value` properties, and a `;`
                    // or `}` in a value must be brace-escaped rather than
                    // percent-encoded.
                    let esc = |v: &str| format!("{{{}}}", v.replace('}', "}}"));
                    let mut out = format!("jdbc:sqlserver://{}", var(entry, "host"));
                    if !var(entry, "port").is_empty() {
                        out.push_str(&format!(":{}", var(entry, "port")));
                    }
                    if !var(entry, "database").is_empty() {
                        out.push_str(&format!(";databaseName={}", esc(var(entry, "database"))));
                    }
                    if !user.is_empty() {
                        out.push_str(&format!(";user={}", esc(user)));
                    }
                    if !s(entry, "api_key").is_empty() {
                        out.push_str(&format!(";password={}", esc(s(entry, "api_key"))));
                    }
                    Ok(out)
                }
                other => Err(format!("no JDBC URL form is known for engine '{other}'")),
            }
        }
        _ => unreachable!(),
    }
}

// ── Wi-Fi ────────────────────────────────────────────────────────────────────

/// The `WIFI:T:…;S:…;P:…;H:…;;` string phones read from a QR code. `\ ; , : "`
/// are backslash-escaped, because an unescaped `;` in a passphrase ends the field
/// and joins the network with a truncated key.
pub fn wifi_uri(entry: &Value) -> Result<String, String> {
    let ssid = need(
        "the SSID",
        first(&[var(entry, "ssid"), s(entry, "provider")]),
    )?;
    let security = var(entry, "security").to_ascii_lowercase();
    let (t, needs_pass) = match security.as_str() {
        "open" | "none" | "nopass" => ("nopass", false),
        "wep" => ("WEP", true),
        "wpa" | "wpa2" | "" => ("WPA", true),
        "wpa3" | "sae" => ("SAE", true),
        s if s.contains("enterprise") || s.contains("eap") => {
            return Err(
                "WPA-Enterprise needs a username and certificate, which the Wi-Fi QR \
                        format cannot carry"
                    .into(),
            )
        }
        other => return Err(format!("unknown security '{other}'")),
    };
    let esc = |v: &str| {
        let mut o = String::new();
        for c in v.chars() {
            if matches!(c, '\\' | ';' | ',' | ':' | '"') {
                o.push('\\');
            }
            o.push(c);
        }
        o
    };
    let mut out = format!("WIFI:T:{t};S:{};", esc(ssid));
    if needs_pass {
        out.push_str(&format!(
            "P:{};",
            esc(need("the passphrase", s(entry, "api_key"))?)
        ));
    }
    if matches!(
        var(entry, "hidden").to_ascii_lowercase().as_str(),
        "true" | "yes" | "1"
    ) {
        out.push_str("H:true;");
    }
    out.push(';');
    Ok(out)
}

// ── Recovery codes ───────────────────────────────────────────────────────────

/// One line per code. A used code keeps its text and gains `\tUSED <date>`:
/// the value is never discarded, so "which did I burn?" stays answerable.
#[derive(Debug, PartialEq, Eq)]
pub struct CodeStatus {
    pub total: usize,
    pub remaining: usize,
}

fn code_lines(entry: &Value) -> Vec<String> {
    var(entry, "codes")
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect()
}

pub fn code_status(entry: &Value) -> CodeStatus {
    let lines = code_lines(entry);
    CodeStatus {
        total: lines.len(),
        remaining: lines.iter().filter(|l| !l.contains('\t')).count(),
    }
}

/// The first unused code. **Reading never consumes** (the HOTP rule): a code is
/// spent when the service accepts it, and only the caller knows that.
pub fn next_code(entry: &Value) -> Option<String> {
    code_lines(entry).into_iter().find(|l| !l.contains('\t'))
}

/// New value of `codes` with `code` (or the first unused, when `None`) marked used.
pub fn mark_used(entry: &Value, code: Option<&str>, date: &str) -> Result<String, String> {
    let mut lines = code_lines(entry);
    let idx = match code {
        Some(c) => lines
            .iter()
            .position(|l| l.split('\t').next() == Some(c.trim()))
            .ok_or("that code is not in this entry")?,
        None => lines
            .iter()
            .position(|l| !l.contains('\t'))
            .ok_or("no unused codes remain")?,
    };
    if lines[idx].contains('\t') {
        return Err("that code is already marked used".into());
    }
    lines[idx] = format!("{}\tUSED {date}", lines[idx]);
    Ok(lines.join("\n"))
}

// ── BIP39 ────────────────────────────────────────────────────────────────────

const BIP39: &str = include_str!("../data/bip39-english.txt");

/// Validates a BIP39 mnemonic against the bundled English wordlist **and its
/// checksum**. A mistyped word is otherwise discovered when the funds are needed.
pub fn bip39_validate(mnemonic: &str) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        return Err(format!(
            "{} words; a mnemonic has 12, 15, 18, 21 or 24",
            words.len()
        ));
    }
    let list: Vec<&str> = BIP39.lines().collect();
    let mut bits: Vec<bool> = Vec::with_capacity(words.len() * 11);
    for (n, w) in words.iter().enumerate() {
        // The error names the word's position, never the word: this text reaches
        // health-scan output, and a recovery phrase must not be echoed into it.
        let idx = list
            .iter()
            .position(|x| x.eq_ignore_ascii_case(w))
            .ok_or_else(|| format!("word {} is not in the BIP39 English wordlist", n + 1))?;
        for b in (0..11).rev() {
            bits.push((idx >> b) & 1 == 1);
        }
    }
    let cs_len = bits.len() / 33;
    let ent_len = bits.len() - cs_len;
    let entropy: Vec<u8> = bits[..ent_len]
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |a, b| (a << 1) | u8::from(*b)))
        .collect();
    let hash = Sha256::digest(&entropy);
    let expect: Vec<bool> = (0..cs_len)
        .map(|i| (hash[i / 8] >> (7 - i % 8)) & 1 == 1)
        .collect();
    if bits[ent_len..] != expect[..] {
        return Err("the checksum does not match: a word is wrong or out of order".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(ty: &str, key: &str, vars: &[(&str, &str)]) -> Value {
        json!({ "secretType": ty, "provider": "P", "api_key": key,
                "extra_vars": vars.iter().map(|(k,v)| json!({"key":k,"value":v})).collect::<Vec<_>>() })
    }

    #[test]
    fn the_registry_and_the_emitters_agree_on_which_formats_exist() {
        for t in crate::secret_types::registry() {
            assert_eq!(
                t.emitters,
                formats_for(&t.id),
                "secret-types.json and type_emit::formats_for disagree for {}",
                t.id
            );
        }
    }

    #[test]
    fn registry_tokens_emit_the_file_each_tool_reads() {
        let e = entry("registry_token", "tok123", &[("registry", "npm")]);
        assert_eq!(
            emit(&e, "npmrc").unwrap(),
            "//registry.npmjs.org/:_authToken=tok123\n"
        );
        assert_eq!(
            emit(&e, "pypirc").unwrap(),
            "[pypi]\nusername = __token__\npassword = tok123\n"
        );
        let e = entry("registry_token", "t\"k", &[("registry", "crates")]);
        assert_eq!(
            emit(&e, "cargo-credentials").unwrap(),
            "[registry]\ntoken = \"t\\\"k\"\n"
        );
        let mut e = entry("registry_token", "tok", &[("registry", "ghcr")]);
        e["username"] = json!("me");
        let docker = emit(&e, "docker-config").unwrap();
        // base64("me:tok")
        assert!(
            docker.contains("\"ghcr.io\"") && docker.contains("bWU6dG9r"),
            "{docker}"
        );
        assert_eq!(
            emit(&e, "netrc").unwrap(),
            "machine ghcr.io login me password tok\n"
        );
        // Docker's auth is user:token — refusing beats writing a blank user.
        assert!(emit(&entry("registry_token", "tok", &[]), "docker-config").is_err());
        assert!(emit(&entry("registry_token", "a\nb", &[]), "npmrc").is_err());
    }

    #[test]
    fn database_forms_encode_the_password_by_zone() {
        let e = entry(
            "database",
            "p@ss:w/rd#1 x",
            &[
                ("engine", "postgres"),
                ("host", "db.local"),
                ("port", "5432"),
                ("database", "app"),
                ("user", "u"),
                ("sslmode", "require"),
            ],
        );
        let dsn = emit(&e, "dsn").unwrap();
        assert_eq!(
            dsn,
            "postgresql://u:p%40ss%3Aw%2Frd%231%20x@db.local:5432/app?sslmode=require"
        );
        assert!(emit(&e, "libpq").unwrap().contains("PGPASSWORD="));
        let jdbc = emit(&e, "jdbc").unwrap();
        assert!(
            jdbc.starts_with("jdbc:postgresql://db.local:5432/app?user=u&password=p%40ss"),
            "{jdbc}"
        );
        let mut ms = e.clone();
        ms["extra_vars"] = json!([{"key":"engine","value":"sqlserver"},{"key":"host","value":"h"},{"key":"user","value":"u"}]);
        ms["api_key"] = json!("a;b}c");
        assert_eq!(
            emit(&ms, "jdbc").unwrap(),
            "jdbc:sqlserver://h;user={u};password={a;b}}c}"
        );
        assert!(emit(
            &entry("database", "x", &[("engine", "oracle"), ("host", "h")]),
            "dsn"
        )
        .is_err());
    }

    #[test]
    fn wifi_uri_escapes_the_characters_that_end_a_field() {
        let mut e = entry(
            "wifi",
            "pa;ss,w:o\\rd\"",
            &[("security", "WPA2"), ("hidden", "true")],
        );
        e["provider"] = json!("Home;Net");
        assert_eq!(
            wifi_uri(&e).unwrap(),
            r#"WIFI:T:WPA;S:Home\;Net;P:pa\;ss\,w\:o\\rd\";H:true;;"#
        );
        assert_eq!(
            wifi_uri(&entry(
                "wifi",
                "",
                &[("ssid", "Cafe"), ("security", "open")]
            ))
            .unwrap(),
            "WIFI:T:nopass;S:Cafe;;"
        );
        assert!(wifi_uri(&entry(
            "wifi",
            "x",
            &[("ssid", "c"), ("security", "WPA2-Enterprise")]
        ))
        .is_err());
    }

    #[test]
    fn recovery_codes_are_spent_by_marking_never_by_reading() {
        let e = entry(
            "recovery_codes",
            "",
            &[("codes", "aaaa-1111\nbbbb-2222\ncccc-3333")],
        );
        assert_eq!(
            code_status(&e),
            CodeStatus {
                total: 3,
                remaining: 3
            }
        );
        assert_eq!(next_code(&e).as_deref(), Some("aaaa-1111"));
        assert_eq!(code_status(&e).remaining, 3, "reading consumed nothing");
        let used = mark_used(&e, None, "2026-10-08").unwrap();
        let e2 = entry("recovery_codes", "", &[("codes", &used)]);
        assert_eq!(
            code_status(&e2),
            CodeStatus {
                total: 3,
                remaining: 2
            }
        );
        assert_eq!(next_code(&e2).as_deref(), Some("bbbb-2222"));
        assert!(
            used.starts_with("aaaa-1111\tUSED 2026-10-08"),
            "the burnt code stays visible"
        );
        assert!(mark_used(&e2, Some("aaaa-1111"), "d").is_err());
        assert!(mark_used(&e2, Some("zzzz"), "d").is_err());
    }

    #[test]
    fn recovery_code_lines_match_the_typescript_twin() {
        let root = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/fixtures/parity/recovery-codes.json"
        );
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(root).unwrap()).unwrap();
        let e = |codes: &str| entry("recovery_codes", "", &[("codes", codes)]);
        for c in doc["cases"].as_array().unwrap() {
            let ent = e(c["codes"].as_str().unwrap());
            let st = code_status(&ent);
            assert_eq!(
                st.total as u64,
                c["total"].as_u64().unwrap(),
                "{}",
                c["name"]
            );
            assert_eq!(
                st.remaining as u64,
                c["remaining"].as_u64().unwrap(),
                "{}",
                c["name"]
            );
            assert_eq!(
                next_code(&ent).as_deref(),
                c["next"].as_str(),
                "{}",
                c["name"]
            );
        }
        let m = &doc["mark_used"];
        let ent = e(m["codes"].as_str().unwrap());
        let date = m["date"].as_str().unwrap();
        assert_eq!(
            mark_used(&ent, None, date).unwrap(),
            m["first_unused"].as_str().unwrap()
        );
        let named = &m["named"];
        assert_eq!(
            mark_used(&ent, named["code"].as_str(), date).unwrap(),
            named["result"].as_str().unwrap()
        );
        for bad in m["refused"].as_array().unwrap() {
            assert!(mark_used(&ent, bad.as_str(), date).is_err());
        }
    }

    #[test]
    fn bip39_wordlist_is_the_official_one_and_the_checksum_is_checked() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(BIP39.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        // The canonical all-zero-entropy vector from the BIP39 test suite.
        let ok = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(bip39_validate(ok).is_ok());
        let bad_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(bip39_validate(bad_checksum)
            .unwrap_err()
            .contains("checksum"));
        assert!(bip39_validate("abandon ability")
            .unwrap_err()
            .contains("12"));
        let err = bip39_validate(&ok.replace("about", "notaword")).unwrap_err();
        assert!(
            err.contains("word 12") && !err.contains("notaword"),
            "{err}"
        );
        let zoo = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        assert!(bip39_validate(zoo).is_ok(), "all-ones entropy vector");
    }
}
