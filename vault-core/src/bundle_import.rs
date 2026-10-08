//! Import a Python config module as bundle-local variables (Phase 24.1).
//!
//! Twin of `src/ts/bundle-import.ts`, pinned by
//! `tests/fixtures/parity/bundle-import.json`. The assignment subset only:
//! string and f-string literals, ints, floats, `True`/`False`/`None`. Nothing is
//! executed; any other right-hand side is imported as source text with a
//! warning naming the line. See the TypeScript header for the rules (duplicate
//! names, large ids, f-strings holding only plain names).

use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Serialize, PartialEq)]
pub struct ImportedVar {
    pub key: String,
    pub value: String,
    pub kind: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct BundleImport {
    pub vars: Vec<ImportedVar>,
    pub warnings: Vec<String>,
}

fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next()
        .is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && c.all(|f| f.is_ascii_alphanumeric() || f == '_')
}

/// `(prefix, body, rest)` for a leading quoted literal.
fn read_quoted(source: &str) -> Option<(String, String, String)> {
    let b: Vec<char> = source.chars().collect();
    let mut i = 0;
    while i < b.len() && i < 2 && "fFuUrRbB".contains(b[i]) {
        i += 1;
    }
    if i >= b.len() || (b[i] != '\'' && b[i] != '"') {
        return None;
    }
    let prefix: String = b[..i].iter().collect::<String>().to_lowercase();
    let quote = b[i];
    let start = i + 1;
    let mut end = start;
    while end < b.len() {
        if b[end] == '\\' {
            end += 2;
            continue;
        }
        if b[end] == quote {
            break;
        }
        end += 1;
    }
    if end >= b.len() || b[end] != quote {
        return None;
    }
    Some((
        prefix,
        b[start..end].iter().collect(),
        b[end + 1..].iter().collect(),
    ))
}

fn unescape_py(body: &str, raw: bool) -> Option<String> {
    if raw {
        return Some(body.to_string());
    }
    let mut out = String::new();
    let mut it = body.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next()? {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            _ => return None,
        }
    }
    Some(out)
}

/// `{name}` holes only. `None` when anything else is inside braces.
fn convert_fstring(
    body: &str,
    bound: &HashMap<String, String>,
) -> Option<(String, Vec<(String, String)>)> {
    let c: Vec<char> = body.chars().collect();
    let mut out = String::new();
    let mut rewrote = Vec::new();
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '{' if c.get(i + 1) == Some(&'{') => {
                out.push_str("{{");
                i += 2;
            }
            '}' if c.get(i + 1) == Some(&'}') => {
                out.push_str("}}");
                i += 2;
            }
            '{' => {
                let end = (i..c.len()).find(|&j| c[j] == '}')?;
                let reference: String = c[i + 1..end].iter().collect();
                let reference = reference.trim().to_string();
                if !is_ident(&reference) {
                    return None;
                }
                let key = bound.get(&reference)?;
                if *key != reference {
                    rewrote.push((reference.clone(), key.clone()));
                }
                out.push('{');
                out.push_str(key);
                out.push('}');
                i = end + 1;
            }
            '}' => return None,
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    Some((out, rewrote))
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

fn signed(s: &str) -> &str {
    s.strip_prefix(['-', '+']).unwrap_or(s)
}

fn is_radix_int(s: &str) -> bool {
    let t = signed(s);
    let Some(rest) = t.get(2..) else { return false };
    match t.get(..2) {
        Some("0x") | Some("0X") => !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()),
        Some("0o") | Some("0O") => {
            !rest.is_empty() && rest.chars().all(|c| ('0'..='7').contains(&c))
        }
        Some("0b") | Some("0B") => !rest.is_empty() && rest.chars().all(|c| c == '0' || c == '1'),
        _ => false,
    }
}

fn is_float(s: &str) -> bool {
    let t = signed(s);
    let (mant, exp) = match t.find(['e', 'E']) {
        Some(i) => (&t[..i], Some(&t[i + 1..])),
        None => (t, None),
    };
    if let Some(e) = exp {
        if !all_digits(signed(e)) {
            return false;
        }
    }
    let mut parts = mant.splitn(2, '.');
    let int = parts.next().unwrap_or("");
    let frac = parts.next();
    match frac {
        None => all_digits(int),
        Some(f) => {
            (int.is_empty() || all_digits(int))
                && (f.is_empty() || all_digits(f))
                && !(int.is_empty() && f.is_empty())
        }
    }
}

/// Strip a trailing ` # comment` that holds no quote (twin of the TS regex).
fn strip_comment(s: &str) -> &str {
    if let Some(i) = s.rfind(" #").or_else(|| s.rfind("\t#")) {
        let tail = &s[i + 1..];
        if !tail.contains('\'') && !tail.contains('"') {
            return s[..i].trim_end();
        }
    }
    s
}

fn kind_for_string(name: &str, body: &str) -> &'static str {
    let looks_id = name.eq_ignore_ascii_case("id")
        || name.eq_ignore_ascii_case("ids")
        || name.to_lowercase().ends_with("_id")
        || name.to_lowercase().ends_with("_ids");
    // `[label](http(s)://target)` — the label may hold spaces, the target may not.
    let md = body
        .strip_prefix('[')
        .and_then(|b| b.strip_suffix(')'))
        .and_then(|b| b.split_once("]("))
        .is_some_and(|(label, target)| {
            !label.contains(']')
                && (target.starts_with("http://") || target.starts_with("https://"))
                && !target.contains(char::is_whitespace)
                && !target.contains(')')
        });
    let url = (body.starts_with("http://") || body.starts_with("https://"))
        && !body.contains(char::is_whitespace);
    if (all_digits(body) && body.len() >= 15) || (looks_id && all_digits(body) && body.len() >= 10)
    {
        "large_id"
    } else if md {
        "markdown_link"
    } else if url {
        "url"
    } else {
        "string"
    }
}

pub fn import_python_config(text: &str) -> BundleImport {
    let mut vars: Vec<ImportedVar> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut bound: HashMap<String, String> = HashMap::new();
    let mut taken: HashSet<String> = HashSet::new();
    let mut rewrites: Vec<(String, String, usize)> = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.trim();
        let Some(eq) = line.find('=') else { continue };
        let name = line[..eq].trim_end();
        if !is_ident(name) || line[eq + 1..].starts_with('=') {
            continue;
        }
        let source_full = line[eq + 1..].trim_start();
        let source = strip_comment(source_full).trim();

        let (value, kind, extra): (String, &str, Option<String>);
        let quoted = read_quoted(source).filter(|(_, _, rest)| {
            let r = rest.trim();
            r.is_empty() || r.starts_with('#')
        });
        if let Some((prefix, body, _)) = quoted {
            let is_f = prefix.contains('f');
            match unescape_py(&body, prefix.contains('r')) {
                None => {
                    warnings.push(format!(
                        "line {line_no}: unsupported escape in {name}; imported as source text"
                    ));
                    value = source.to_string();
                    kind = "string";
                    extra = None;
                }
                Some(body) if is_f => match convert_fstring(&body, &bound) {
                    None => {
                        warnings.push(format!(
                            "line {line_no}: {name} is an f-string with an expression a template cannot hold; imported as a string"
                        ));
                        value = body;
                        kind = "string";
                        extra = None;
                    }
                    Some((text, rewrote)) => {
                        for (from, to) in rewrote {
                            match rewrites.iter_mut().find(|r| r.0 == from) {
                                Some(r) => {
                                    r.1 = to;
                                    r.2 += 1;
                                }
                                None => rewrites.push((from, to, 1)),
                            }
                        }
                        value = text;
                        kind = "template";
                        extra = None;
                    }
                },
                Some(body) => {
                    kind = kind_for_string(name, &body);
                    value = body;
                    extra = None;
                }
            }
        } else if is_radix_int(source) {
            value = source.to_string();
            kind = "hex_int";
            extra = None;
        } else if all_digits(signed(source)) {
            value = source.to_string();
            kind = "int";
            extra = None;
        } else if is_float(source) {
            value = source.to_string();
            kind = "float";
            extra = None;
        } else if source == "True" || source == "False" {
            value = (source == "True").to_string();
            kind = "bool";
            extra = None;
        } else if source == "None" {
            value = String::new();
            kind = "string";
            extra = Some(format!("{name} is None; imported as an empty string"));
        } else {
            value = source.to_string();
            kind = "string";
            extra = Some(format!(
                "{name} is not a supported literal; imported as source text"
            ));
        }
        if let Some(w) = extra {
            warnings.push(format!("line {line_no}: {w}"));
        }

        let mut key = name.to_string();
        if taken.contains(name) {
            let mut n = 2;
            while taken.contains(&format!("{name}_{n}")) {
                n += 1;
            }
            key = format!("{name}_{n}");
            warnings.push(format!(
                "line {line_no}: {name} is assigned more than once; the first stays {name}, this one is imported as {key}, and later references use {key}"
            ));
        }
        taken.insert(key.clone());
        bound.insert(name.to_string(), key.clone());
        vars.push(ImportedVar {
            key,
            value,
            kind: kind.to_string(),
        });
    }

    for (from, to, n) in rewrites {
        warnings.push(format!(
            "{n} later reference{} to {from} now {} {to}",
            if n == 1 { "" } else { "s" },
            if n == 1 { "uses" } else { "use" }
        ));
    }
    BundleImport { vars, warnings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_golden_file_the_typescript_twin_wrote() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/parity/");
        let src = std::fs::read_to_string(format!("{root}bundle-import-synthetic.py")).unwrap();
        let gold: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{root}bundle-import.json")).unwrap(),
        )
        .unwrap();
        let got = serde_json::to_value(import_python_config(&src)).unwrap();
        assert_eq!(got, gold);
    }

    #[test]
    fn large_ids_stay_strings_and_nothing_is_executed() {
        let r = import_python_config("owner = '708766134927442001'\nx = len(owner)\n");
        assert_eq!(r.vars[0].kind, "large_id");
        assert_eq!(r.vars[1].value, "len(owner)");
        assert!(r.warnings[0].contains("not a supported literal"));
    }
}
