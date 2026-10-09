//! Phase 38 — stack integrations as data (ADR-0144).
//!
//! The homelab stack is where secrets and config already meet: Prometheus scrape
//! jobs with `basic_auth`, Grafana datasources with `secureJsonData`, Homepage
//! widgets with one API key per service. Eleven hand-written exporters were
//! already "eleven treadmills" (review-01 section 1); five more would be sixteen.
//! So an integration is not code here, it is a **descriptor** in
//! `data/stack-adapters.json`: the chunk types it adds (with their fields,
//! defaults and which are secret), the shape of the file it produces, and the
//! rules a generated file has to satisfy. This module interprets descriptors;
//! `src/ts/stack.ts` interprets the same file for the app, and a golden fixture
//! asserted from both sides keeps the two interpreters honest.
//!
//! If an integration cannot be expressed in the descriptor grammar, that is
//! information about the grammar, not a reason to hand-write another exporter.
//!
//! # Rendering
//!
//! The caller supplies how a stored field value becomes text (`resolve`): it
//! decides whether `${Provider/field}` becomes the real value (a deploy), a
//! fingerprint (a terminal), or stays literal. The interpreter only knows which
//! fields the descriptor marks `secret`, and passes that flag along so a
//! redacting caller can mask a literal secret as well as a reference.

use crate::config_check::Finding;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::OnceLock;

const DESCRIPTORS: &str = include_str!("../data/stack-adapters.json");

#[derive(Debug, Clone)]
pub struct FieldSpec {
    pub key: String,
    /// `text` (default), `list` or `bool`.
    pub kind: String,
    pub secret: bool,
    pub default: Option<String>,
    pub choices: Vec<String>,
    pub help: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChunkSpec {
    pub type_id: String,
    pub label: String,
    pub singleton: bool,
    pub fields: Vec<FieldSpec>,
}

#[derive(Debug, Clone)]
pub struct Starter {
    pub type_id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: &'static str,
    pub kind: String,
    pub type_id: String,
    pub field: Option<String>,
    pub fields: Vec<String>,
    pub when: Option<String>,
    pub values: Vec<String>,
    pub severity: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Adapter {
    pub id: String,
    pub label: String,
    pub abbr: String,
    pub description: String,
    pub file: String,
    pub chunks: Vec<ChunkSpec>,
    pub starter: Vec<Starter>,
    pub output: Value,
    pub rules: Vec<Rule>,
}

fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn strs(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Rule ids and severities live for the whole process: there is one descriptor
/// file, parsed once, and `Finding` carries `&'static str`.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn parse() -> Vec<Adapter> {
    let doc: Value = serde_json::from_str(DESCRIPTORS).expect("stack-adapters.json is valid JSON");
    doc["adapters"]
        .as_array()
        .expect("adapters is an array")
        .iter()
        .map(|a| {
            let id = str_of(a, "id");
            let chunks = a["chunks"]
                .as_array()
                .map(|cs| {
                    cs.iter()
                        .map(|c| ChunkSpec {
                            type_id: str_of(c, "type"),
                            label: str_of(c, "label"),
                            singleton: c["singleton"].as_bool().unwrap_or(false),
                            fields: c["fields"]
                                .as_array()
                                .map(|fs| {
                                    fs.iter()
                                        .map(|f| FieldSpec {
                                            key: str_of(f, "key"),
                                            kind: if f["kind"].is_string() {
                                                str_of(f, "kind")
                                            } else {
                                                "text".into()
                                            },
                                            secret: f["secret"].as_bool().unwrap_or(false),
                                            default: f["default"].as_str().map(String::from),
                                            choices: strs(f, "choices"),
                                            help: f["help"].as_str().map(String::from),
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let rules = a["rules"]
                .as_array()
                .map(|rs| {
                    rs.iter()
                        .map(|r| Rule {
                            id: leak(format!("stack-{id}-{}", str_of(r, "id"))),
                            kind: str_of(r, "kind"),
                            type_id: str_of(r, "type"),
                            field: r["field"].as_str().map(String::from),
                            fields: strs(r, "fields"),
                            when: r["when"].as_str().map(String::from),
                            values: strs(r, "values"),
                            severity: if str_of(r, "severity") == "error" {
                                "error"
                            } else {
                                "warning"
                            },
                            message: str_of(r, "message"),
                        })
                        .collect()
                })
                .unwrap_or_default();
            Adapter {
                label: str_of(a, "label"),
                abbr: str_of(a, "abbr"),
                description: str_of(a, "description"),
                file: str_of(a, "file"),
                starter: a["starter"]
                    .as_array()
                    .map(|ss| {
                        ss.iter()
                            .map(|s| Starter {
                                type_id: str_of(s, "type"),
                                name: str_of(s, "name"),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                output: a["output"].clone(),
                chunks,
                rules,
                id,
            }
        })
        .collect()
}

pub fn adapters() -> &'static [Adapter] {
    static ALL: OnceLock<Vec<Adapter>> = OnceLock::new();
    ALL.get_or_init(parse)
}

pub fn adapter(id: &str) -> Option<&'static Adapter> {
    adapters().iter().find(|a| a.id == id)
}

/// Every chunk type any adapter adds, in descriptor order.
pub fn chunk_types() -> Vec<&'static str> {
    adapters()
        .iter()
        .flat_map(|a| a.chunks.iter().map(|c| c.type_id.as_str()))
        .collect()
}

impl Adapter {
    pub fn chunk_spec(&self, type_id: &str) -> Option<&ChunkSpec> {
        self.chunks.iter().find(|c| c.type_id == type_id)
    }
}

// ── The value tree and its YAML writer ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Y {
    Str(String),
    Bool(bool),
    Int(i64),
    List(Vec<Y>),
    Map(Vec<(String, Y)>),
}

/// YAML words that are not strings when written bare (YAML 1.1 as well as 1.2,
/// because Prometheus and Grafana are Go programs on 1.1-flavoured parsers).
fn reserved(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "y" | "n" | "null" | "~" | "nan" | "inf"
    )
}

/// A scalar that a parser will read back as the same string. Only plain words
/// are written bare; anything else (a number-like password, a URL, a value with
/// a colon or a leading symbol) is double-quoted, because a password of `123456`
/// written bare becomes an integer and a config that "works" with the wrong value
/// is the worst failure here.
fn scalar(s: &str) -> String {
    let bare = !s.is_empty()
        && !reserved(s)
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if bare {
        s.to_string()
    } else {
        serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""))
    }
}

fn write_map(out: &mut String, entries: &[(String, Y)], indent: usize) {
    let pad = " ".repeat(indent);
    for (k, v) in entries {
        out.push_str(&pad);
        out.push_str(&scalar(k));
        out.push(':');
        match v {
            Y::Str(s) => {
                out.push(' ');
                out.push_str(&scalar(s));
                out.push('\n');
            }
            Y::Bool(b) => out.push_str(&format!(" {b}\n")),
            Y::Int(i) => out.push_str(&format!(" {i}\n")),
            Y::Map(m) if m.is_empty() => out.push_str(" {}\n"),
            Y::List(l) if l.is_empty() => out.push_str(" []\n"),
            Y::Map(m) => {
                out.push('\n');
                write_map(out, m, indent + 2);
            }
            Y::List(l) => {
                out.push('\n');
                write_list(out, l, indent + 2);
            }
        }
    }
}

fn write_list(out: &mut String, items: &[Y], indent: usize) {
    let pad = " ".repeat(indent);
    for item in items {
        match item {
            Y::Map(m) if !m.is_empty() => {
                // The first key shares the dash's line; the rest align under it.
                let mut inner = String::new();
                write_map(&mut inner, m, indent + 2);
                out.push_str(&pad);
                out.push_str("- ");
                out.push_str(&inner[indent + 2..]);
            }
            Y::List(l) if !l.is_empty() => {
                out.push_str(&pad);
                out.push_str("-\n");
                write_list(out, l, indent + 2);
            }
            Y::Str(s) => out.push_str(&format!("{pad}- {}\n", scalar(s))),
            Y::Bool(b) => out.push_str(&format!("{pad}- {b}\n")),
            Y::Int(i) => out.push_str(&format!("{pad}- {i}\n")),
            Y::Map(_) => out.push_str(&format!("{pad}- {{}}\n")),
            Y::List(_) => out.push_str(&format!("{pad}- []\n")),
        }
    }
}

fn to_yaml(root: &Y) -> String {
    let mut out = String::from("# Generated by UnENVerse\n");
    match root {
        Y::Map(m) => write_map(&mut out, m, 0),
        Y::List(l) => write_list(&mut out, l, 0),
        _ => {}
    }
    out
}

// ── The interpreter ──────────────────────────────────────────────────────────

/// How a stored field value becomes text: `(raw, is_secret) -> text`.
pub type Resolve<'a> = &'a dyn Fn(&str, bool) -> String;

struct Ctx<'a> {
    adapter: &'a Adapter,
    chunks: &'a [&'a Value],
    resolve: Resolve<'a>,
    /// The chunk a field lookup reads from, and its spec.
    cur: Option<(&'a Value, &'a ChunkSpec)>,
}

fn chunk_type(c: &Value) -> &str {
    c.get("chunk_type").and_then(Value::as_str).unwrap_or("")
}

fn raw_field<'a>(chunk: &'a Value, key: &str) -> &'a str {
    if key == "@name" {
        return chunk.get("name").and_then(Value::as_str).unwrap_or("");
    }
    chunk
        .get("fields")
        .and_then(Value::as_array)
        .and_then(|fs| {
            fs.iter()
                .find(|f| f.get("key").and_then(Value::as_str) == Some(key))
        })
        .and_then(|f| f.get("value"))
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn is_secret(spec: &ChunkSpec, key: &str) -> bool {
    spec.fields.iter().any(|f| f.key == key && f.secret)
}

impl Ctx<'_> {
    fn field_text(&self, key: &str) -> String {
        let Some((chunk, spec)) = self.cur else {
            return String::new();
        };
        let raw = raw_field(chunk, key);
        if raw.trim().is_empty() {
            return String::new();
        }
        if key == "@name" {
            return raw.to_string();
        }
        (self.resolve)(raw, is_secret(spec, key))
    }

    fn of_type(&self, type_id: &str) -> Vec<&Value> {
        self.chunks
            .iter()
            .copied()
            .filter(|c| chunk_type(c) == type_id)
            .collect()
    }

    fn with<'b>(&'b self, chunk: &'b Value, spec: &'b ChunkSpec) -> Ctx<'b> {
        Ctx {
            adapter: self.adapter,
            chunks: self.chunks,
            resolve: self.resolve,
            cur: Some((chunk, spec)),
        }
    }

    fn each_chunk(&self, type_id: &str) -> Vec<Ctx<'_>> {
        let Some(spec) = self.adapter.chunk_spec(type_id) else {
            return Vec::new();
        };
        self.of_type(type_id)
            .into_iter()
            .map(|c| self.with(c, spec))
            .collect()
    }
}

fn split_list(s: &str) -> Vec<String> {
    s.split(['\n', ','])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect()
}

fn truthy(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

fn keep(node: &Value) -> bool {
    node.get("keep").and_then(Value::as_bool).unwrap_or(false)
}

fn eval(node: &Value, ctx: &Ctx) -> Option<Y> {
    match node {
        Value::String(s) => Some(Y::Str(s.clone())),
        Value::Bool(b) => Some(Y::Bool(*b)),
        Value::Number(n) => n.as_i64().map(Y::Int),
        Value::Object(o) => {
            if let Some(f) = o.get("f").and_then(Value::as_str) {
                let text = ctx.field_text(f);
                if text.is_empty() {
                    return None;
                }
                return match o.get("as").and_then(Value::as_str).unwrap_or("str") {
                    "list" => {
                        let items = split_list(&text);
                        (!items.is_empty())
                            .then(|| Y::List(items.into_iter().map(Y::Str).collect()))
                    }
                    "bool" => truthy(&text).map(Y::Bool),
                    "int" => Some(text.trim().parse::<i64>().map_or(Y::Str(text), Y::Int)),
                    _ => Some(Y::Str(match o.get("fmt").and_then(Value::as_str) {
                        Some(fmt) => fmt.replace("{}", &text),
                        None => text,
                    })),
                };
            }
            if let Some(pairs) = o.get("map").and_then(Value::as_array) {
                let entries: Vec<(String, Y)> = pairs
                    .iter()
                    .filter_map(|p| {
                        let p = p.as_array()?;
                        let key = p.first()?.as_str()?.to_string();
                        Some((key, eval(p.get(1)?, ctx)?))
                    })
                    .collect();
                return (!entries.is_empty() || keep(node)).then_some(Y::Map(entries));
            }
            if let Some(items) = o.get("list").and_then(Value::as_array) {
                let l: Vec<Y> = items.iter().filter_map(|n| eval(n, ctx)).collect();
                return (!l.is_empty() || keep(node)).then_some(Y::List(l));
            }
            if let Some(t) = o.get("each").and_then(Value::as_str) {
                let inner = o.get("node")?;
                let l: Vec<Y> = ctx
                    .each_chunk(t)
                    .iter()
                    .filter_map(|c| eval(inner, c))
                    .collect();
                return (!l.is_empty() || keep(node)).then_some(Y::List(l));
            }
            if let Some(t) = o.get("singleton").and_then(Value::as_str) {
                let inner = o.get("node")?;
                let first = ctx.each_chunk(t).into_iter().next()?;
                return eval(inner, &first);
            }
            if let Some(g) = o.get("group") {
                let of = g.get("of").and_then(Value::as_str)?;
                let by = g.get("by").and_then(Value::as_str)?;
                let default = g.get("default").and_then(Value::as_str).unwrap_or("");
                let item = g.get("item")?;
                let mut groups: Vec<(String, Vec<Y>)> = Vec::new();
                for c in ctx.each_chunk(of) {
                    let name = match c.field_text(by) {
                        n if n.is_empty() => default.to_string(),
                        n => n,
                    };
                    let Some(y) = eval(item, &c) else {
                        continue;
                    };
                    match groups.iter_mut().find(|(n, _)| *n == name) {
                        Some((_, items)) => items.push(y),
                        None => groups.push((name, vec![y])),
                    }
                }
                let l: Vec<Y> = groups
                    .into_iter()
                    .map(|(n, items)| Y::Map(vec![(n, Y::List(items))]))
                    .collect();
                return (!l.is_empty() || keep(node)).then_some(Y::List(l));
            }
            if let Some(e) = o.get("entry") {
                let key = match eval(e.get("key")?, ctx)? {
                    Y::Str(s) => s,
                    _ => return None,
                };
                let value = e
                    .get("value")
                    .and_then(|v| eval(v, ctx))
                    .unwrap_or(Y::Map(Vec::new()));
                return Some(Y::Map(vec![(key, value)]));
            }
            if let Some(fields) = o.get("when").and_then(Value::as_array) {
                let any = fields
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|f| !ctx.field_text(f).is_empty());
                return if any { eval(o.get("node")?, ctx) } else { None };
            }
            None
        }
        _ => None,
    }
}

/// Renders a project of this adapter's type to the file it produces.
pub fn render(adapter: &Adapter, project: &Value, resolve: Resolve) -> String {
    let chunks: Vec<&Value> = project
        .get("chunks")
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .filter(|c| !c.get("disabled").and_then(Value::as_bool).unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();
    let ctx = Ctx {
        adapter,
        chunks: &chunks,
        resolve,
        cur: None,
    };
    match eval(&adapter.output, &ctx) {
        Some(root) => to_yaml(&root),
        None => "# Generated by UnENVerse\n".to_string(),
    }
}

/// The chunks a new project of this type starts with.
pub fn starter_chunks(adapter: &Adapter, new_id: &dyn Fn() -> String) -> Vec<Value> {
    adapter
        .starter
        .iter()
        .filter_map(|s| {
            let spec = adapter.chunk_spec(&s.type_id)?;
            Some(new_chunk(spec, &s.name, new_id()))
        })
        .collect()
}

/// A new, empty chunk of this type, with its defaults filled in.
pub fn new_chunk(spec: &ChunkSpec, name: &str, id: String) -> Value {
    serde_json::json!({
        "id": id,
        "name": name,
        "chunk_type": spec.type_id,
        "fields": spec.fields.iter().map(|f| serde_json::json!({
            "key": f.key,
            "value": f.default.clone().unwrap_or_default(),
            "field_type": if f.secret { "secret" } else if f.kind == "list" { "list" } else { "var" },
        })).collect::<Vec<_>>(),
    })
}

// ── Rules ────────────────────────────────────────────────────────────────────

fn finding(rule: &Rule, chunk: &Value, field: &str, related: Vec<String>) -> Finding {
    let name = chunk.get("name").and_then(Value::as_str).unwrap_or("");
    Finding {
        rule: rule.id,
        severity: rule.severity,
        chunk_id: chunk
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        chunk_name: name.to_string(),
        chunk_type: chunk_type(chunk).to_string(),
        field: field.to_string(),
        // Only the chunk's name and a field name go into a message, never a value:
        // a finding is shown in places a secret must not reach.
        message: rule
            .message
            .replace("{name}", name)
            .replace("{field}", field),
        related,
    }
}

fn set(chunk: &Value, key: &str) -> bool {
    !raw_field(chunk, key).trim().is_empty()
}

/// Checks a project of this adapter's type against the descriptor's rules, plus
/// the one rule every adapter shares: a `${…}` that names no vault entry.
pub fn check(adapter: &Adapter, project: &Value, vault_names: &[String]) -> Vec<Finding> {
    let chunks: Vec<&Value> = project
        .get("chunks")
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .filter(|c| !c.get("disabled").and_then(Value::as_bool).unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for rule in &adapter.rules {
        let of: Vec<&Value> = chunks
            .iter()
            .copied()
            .filter(|c| chunk_type(c) == rule.type_id)
            .collect();
        match rule.kind.as_str() {
            "unique" => {
                let field = rule.field.as_deref().unwrap_or("@name");
                let mut seen: Vec<&str> = Vec::new();
                for c in &of {
                    let v = raw_field(c, field).trim();
                    if v.is_empty() {
                        continue;
                    }
                    if seen.contains(&v) {
                        out.push(finding(rule, c, field, vec![]));
                    } else {
                        seen.push(v);
                    }
                }
            }
            "required" => {
                let field = rule.field.as_deref().unwrap_or("");
                for c in &of {
                    if !set(c, field) {
                        out.push(finding(rule, c, field, vec![]));
                    }
                }
            }
            "exclusive" => {
                for c in &of {
                    if rule.fields.iter().all(|f| set(c, f)) {
                        out.push(finding(rule, c, &rule.fields.join(" and "), vec![]));
                    }
                }
            }
            "together" => {
                for c in &of {
                    let n = rule.fields.iter().filter(|f| set(c, f)).count();
                    if n > 0 && n < rule.fields.len() {
                        out.push(finding(rule, c, &rule.fields.join(" and "), vec![]));
                    }
                }
            }
            "choices" => {
                let field = rule.field.as_deref().unwrap_or("");
                for c in &of {
                    let v = raw_field(c, field).trim();
                    // A reference is checked when it is resolved, not here.
                    if !v.is_empty() && !v.starts_with("${") && !rule.values.iter().any(|x| x == v)
                    {
                        out.push(finding(rule, c, field, vec![]));
                    }
                }
            }
            "needs_one_of" => {
                let when = rule.when.as_deref().unwrap_or("");
                for c in &of {
                    if set(c, when) && !rule.fields.iter().any(|f| set(c, f)) {
                        out.push(finding(rule, c, &rule.fields.join(" or "), vec![]));
                    }
                }
            }
            _ => {}
        }
    }

    // A reference to something the vault does not hold renders as literal
    // `${…}` text in a file a service is about to read.
    let known: Vec<String> = vault_names.iter().map(|n| norm(n)).collect();
    let mut reported: HashSet<String> = HashSet::new();
    for c in &chunks {
        if adapter.chunk_spec(chunk_type(c)).is_none() {
            continue;
        }
        let Some(fields) = c.get("fields").and_then(Value::as_array) else {
            continue;
        };
        for f in fields {
            let raw = f.get("value").and_then(Value::as_str).unwrap_or("").trim();
            let Some(name) = raw.strip_prefix("${").and_then(|r| r.strip_suffix('}')) else {
                continue;
            };
            if name.starts_with("chunk:") || name.starts_with("bundle:") {
                continue; // resolved by machinery this module does not duplicate
            }
            let head = norm(name.split('/').next().unwrap_or(name));
            let resolves = known
                .iter()
                .any(|p| !p.is_empty() && (head == *p || head.starts_with(&format!("{p}_"))));
            let key = f.get("key").and_then(Value::as_str).unwrap_or("");
            if !resolves && reported.insert(format!("{}|{key}|{name}", chunk_type(c))) {
                out.push(Finding {
                    rule: leak(format!("stack-{}-unresolved-ref", adapter.id)),
                    severity: "warning",
                    chunk_id: c
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    chunk_name: c
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    chunk_type: chunk_type(c).to_string(),
                    field: key.to_string(),
                    message: format!("`{key}` reads `${{{name}}}`, which is not a vault entry"),
                    related: vec![],
                });
            }
        }
    }
    out
}

fn norm(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chunk(t: &str, name: &str, fields: &[(&str, &str)]) -> Value {
        json!({
            "id": format!("id-{name}"), "name": name, "chunk_type": t,
            "fields": fields.iter().map(|(k, v)| json!({"key": k, "value": v})).collect::<Vec<_>>()
        })
    }

    fn project(ptype: &str, chunks: Vec<Value>) -> Value {
        json!({"id": "p", "name": "p", "project_type": ptype, "chunks": chunks})
    }

    fn plain(raw: &str, _secret: bool) -> String {
        raw.to_string()
    }

    fn render_plain(id: &str, p: &Value) -> String {
        render(adapter(id).unwrap(), p, &plain)
    }

    #[test]
    fn the_descriptors_are_internally_consistent() {
        assert_eq!(
            adapters().iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            vec!["prometheus", "grafana", "homepage"]
        );
        let mut ids = HashSet::new();
        let mut types = HashSet::new();
        for a in adapters() {
            assert!(ids.insert(&a.id), "duplicate adapter {}", a.id);
            assert!(!a.file.is_empty() && !a.label.is_empty() && !a.abbr.is_empty());
            for c in &a.chunks {
                assert!(
                    types.insert(&c.type_id),
                    "chunk type {} is in two adapters",
                    c.type_id
                );
                assert!(c.type_id.starts_with(match a.id.as_str() {
                    "prometheus" => "prom_",
                    "grafana" => "grafana_",
                    _ => "homepage_",
                }));
                let keys: HashSet<_> = c.fields.iter().map(|f| &f.key).collect();
                assert_eq!(
                    keys.len(),
                    c.fields.len(),
                    "duplicate field in {}",
                    c.type_id
                );
            }
            for s in &a.starter {
                assert!(
                    a.chunk_spec(&s.type_id).is_some(),
                    "starter names unknown chunk {}",
                    s.type_id
                );
            }
            // Every field the output reads, and every rule's field, exists in its chunk type.
            for r in &a.rules {
                let spec = a
                    .chunk_spec(&r.type_id)
                    .unwrap_or_else(|| panic!("rule {} names unknown chunk {}", r.id, r.type_id));
                let mut named: Vec<&str> = r.fields.iter().map(String::as_str).collect();
                named.extend(r.field.as_deref());
                named.extend(r.when.as_deref());
                for f in named {
                    assert!(
                        f == "@name" || spec.fields.iter().any(|x| x.key == f),
                        "rule {} names unknown field {f}",
                        r.id
                    );
                }
                assert!(
                    [
                        "unique",
                        "required",
                        "exclusive",
                        "together",
                        "choices",
                        "needs_one_of"
                    ]
                    .contains(&r.kind.as_str()),
                    "rule kind {}",
                    r.kind
                );
            }
        }
    }

    #[test]
    fn every_field_the_output_reads_exists_in_the_chunk_it_reads_from() {
        // A typo in a descriptor would silently drop a field from every file.
        fn walk(n: &Value, chunk: Option<&str>, a: &Adapter, bad: &mut Vec<String>) {
            match n {
                Value::Object(o) => {
                    if let Some(f) = o.get("f").and_then(Value::as_str) {
                        let ok = chunk
                            .and_then(|c| a.chunk_spec(c))
                            .is_some_and(|s| f == "@name" || s.fields.iter().any(|x| x.key == f));
                        if !ok {
                            bad.push(format!("{}: field '{f}' not in {chunk:?}", a.id));
                        }
                    }
                    if let Some(fs) = o.get("when").and_then(Value::as_array) {
                        for f in fs.iter().filter_map(Value::as_str) {
                            let ok = chunk
                                .and_then(|c| a.chunk_spec(c))
                                .is_some_and(|s| s.fields.iter().any(|x| x.key == f));
                            if !ok {
                                bad.push(format!("{}: when '{f}' not in {chunk:?}", a.id));
                            }
                        }
                    }
                    let inner = o
                        .get("each")
                        .or_else(|| o.get("singleton"))
                        .and_then(Value::as_str)
                        .or_else(|| {
                            o.get("group")
                                .and_then(|g| g.get("of"))
                                .and_then(Value::as_str)
                        })
                        .or(chunk);
                    if let Some(g) = o.get("group") {
                        if let Some(by) = g.get("by").and_then(Value::as_str) {
                            let of = g.get("of").and_then(Value::as_str);
                            let ok = of
                                .and_then(|c| a.chunk_spec(c))
                                .is_some_and(|s| s.fields.iter().any(|x| x.key == by));
                            if !ok {
                                bad.push(format!("{}: group by '{by}' not in {of:?}", a.id));
                            }
                        }
                    }
                    for (k, v) in o {
                        if k == "f" || k == "when" {
                            continue;
                        }
                        walk(v, inner, a, bad);
                    }
                }
                Value::Array(arr) => arr.iter().for_each(|v| walk(v, chunk, a, bad)),
                _ => {}
            }
        }
        for a in adapters() {
            let mut bad = Vec::new();
            walk(&a.output, None, a, &mut bad);
            assert!(bad.is_empty(), "{bad:?}");
        }
    }

    #[test]
    fn a_prometheus_project_renders_a_prometheus_file() {
        let p = project(
            "prometheus",
            vec![
                chunk(
                    "prom_global",
                    "global",
                    &[("scrape_interval", "30s"), ("evaluation_interval", "15s")],
                ),
                chunk(
                    "prom_scrape",
                    "node",
                    &[("targets", "a:9100\nb:9100"), ("metrics_path", "/metrics")],
                ),
                chunk(
                    "prom_scrape",
                    "app",
                    &[
                        ("targets", "app:8080"),
                        ("scheme", "https"),
                        ("username", "scraper"),
                        ("password", "s3cret"),
                        ("ca_file", "/etc/ca.pem"),
                    ],
                ),
                chunk(
                    "prom_scrape",
                    "api",
                    &[("targets", "api:8080"), ("bearer_token", "tok")],
                ),
                chunk(
                    "prom_remote_write",
                    "cloud",
                    &[
                        ("url", "https://prom.example/api/v1/write"),
                        ("username", "u"),
                        ("password", "p"),
                    ],
                ),
            ],
        );
        assert_eq!(
            render_plain("prometheus", &p),
            "# Generated by UnENVerse
global:
  scrape_interval: \"30s\"
  evaluation_interval: \"15s\"
scrape_configs:
  - job_name: node
    metrics_path: \"/metrics\"
    static_configs:
      - targets:
          - \"a:9100\"
          - \"b:9100\"
  - job_name: app
    scheme: https
    basic_auth:
      username: scraper
      password: s3cret
    tls_config:
      ca_file: \"/etc/ca.pem\"
    static_configs:
      - targets:
          - \"app:8080\"
  - job_name: api
    authorization:
      type: Bearer
      credentials: tok
    static_configs:
      - targets:
          - \"api:8080\"
remote_write:
  - url: \"https://prom.example/api/v1/write\"
    basic_auth:
      username: u
      password: p
"
        );
    }

    #[test]
    fn an_empty_scrape_list_is_written_not_dropped_and_empty_sections_vanish() {
        let p = project("prometheus", vec![]);
        assert_eq!(
            render_plain("prometheus", &p),
            "# Generated by UnENVerse\nscrape_configs: []\n"
        );
        let only_global = project(
            "prometheus",
            vec![chunk("prom_global", "g", &[("scrape_interval", "1m")])],
        );
        assert!(render_plain("prometheus", &only_global)
            .starts_with("# Generated by UnENVerse\nglobal:\n  scrape_interval: \"1m\"\n"));
    }

    #[test]
    fn a_disabled_chunk_is_left_out() {
        let mut off = chunk("prom_scrape", "paused", &[("targets", "x:1")]);
        off["disabled"] = json!(true);
        let p = project(
            "prometheus",
            vec![off, chunk("prom_scrape", "active", &[("targets", "y:2")])],
        );
        let out = render_plain("prometheus", &p);
        assert!(out.contains("job_name: active") && !out.contains("paused"));
    }

    #[test]
    fn strings_that_yaml_would_read_as_something_else_are_quoted() {
        let p = project(
            "prometheus",
            vec![chunk(
                "prom_scrape",
                "j",
                &[
                    ("targets", "h:1"),
                    ("username", "true"),
                    ("password", "123456"),
                ],
            )],
        );
        let out = render_plain("prometheus", &p);
        assert!(out.contains("username: \"true\""), "{out}");
        assert!(out.contains("password: \"123456\""), "{out}");
        for (s, want) in [
            ("plain", "plain"),
            ("with-dash_and.dot", "with-dash_and.dot"),
            ("", "\"\""),
            ("null", "\"null\""),
            ("No", "\"No\""),
            ("~", "\"~\""),
            ("0x1F", "\"0x1F\""),
            ("1e3", "\"1e3\""),
            ("a: b", "\"a: b\""),
            ("- x", "\"- x\""),
            ("# c", "\"# c\""),
            ("line\nbreak", "\"line\\nbreak\""),
            ("quo\"te", "\"quo\\\"te\""),
            ("ünï", "\"ünï\""),
        ] {
            assert_eq!(scalar(s), want, "{s:?}");
        }
    }

    #[test]
    fn the_resolver_decides_what_a_reference_becomes_and_is_told_which_fields_are_secret() {
        let p = project(
            "prometheus",
            vec![chunk(
                "prom_scrape",
                "j",
                &[
                    ("targets", "h:1"),
                    ("username", "u"),
                    ("password", "${Prom/password}"),
                ],
            )],
        );
        let seen = std::cell::RefCell::new(Vec::new());
        let r = |raw: &str, secret: bool| {
            seen.borrow_mut().push((raw.to_string(), secret));
            if raw.starts_with("${") {
                "RESOLVED".into()
            } else {
                raw.to_string()
            }
        };
        let out = render(adapter("prometheus").unwrap(), &p, &r);
        assert!(out.contains("password: RESOLVED"), "{out}");
        let seen = seen.borrow();
        assert!(seen.contains(&("${Prom/password}".to_string(), true)));
        assert!(
            seen.contains(&("u".to_string(), false)),
            "username is not secret"
        );
    }

    #[test]
    fn grafana_datasources_carry_credentials_in_secure_json_data() {
        let p = project(
            "grafana",
            vec![
                chunk(
                    "grafana_datasource",
                    "Prometheus",
                    &[
                        ("type", "prometheus"),
                        ("url", "http://prometheus:9090"),
                        ("access", "proxy"),
                        ("is_default", "true"),
                        ("api_token", "tok"),
                    ],
                ),
                chunk(
                    "grafana_datasource",
                    "pg",
                    &[
                        ("type", "postgres"),
                        ("url", "db:5432"),
                        ("user", "grafana"),
                        ("password", "pw"),
                        ("database", "app"),
                    ],
                ),
            ],
        );
        assert_eq!(
            render_plain("grafana", &p),
            "# Generated by UnENVerse
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: \"http://prometheus:9090\"
    isDefault: true
    jsonData:
      httpHeaderName1: Authorization
    secureJsonData:
      httpHeaderValue1: \"Bearer tok\"
  - name: pg
    type: postgres
    url: \"db:5432\"
    user: grafana
    database: app
    secureJsonData:
      password: pw
"
        );
    }

    #[test]
    fn homepage_groups_services_in_first_seen_order_and_attaches_widget_credentials() {
        let p = project(
            "homepage",
            vec![
                chunk(
                    "homepage_service",
                    "Jellyfin",
                    &[
                        ("group", "Media"),
                        ("href", "http://jf:8096"),
                        ("icon", "jellyfin.png"),
                        ("widget_type", "jellyfin"),
                        ("widget_url", "http://jf:8096"),
                        ("widget_key", "k1"),
                    ],
                ),
                chunk(
                    "homepage_service",
                    "Pi-hole",
                    &[("group", "Network"), ("href", "http://pi.hole/admin")],
                ),
                chunk(
                    "homepage_service",
                    "Sonarr",
                    &[
                        ("group", "Media"),
                        ("widget_type", "sonarr"),
                        ("widget_url", "http://sonarr:8989"),
                        ("widget_key", "k2"),
                    ],
                ),
                chunk("homepage_service", "Loose", &[("group", "")]),
            ],
        );
        assert_eq!(
            render_plain("homepage", &p),
            "# Generated by UnENVerse
- Media:
    - Jellyfin:
        icon: jellyfin.png
        href: \"http://jf:8096\"
        widget:
          type: jellyfin
          url: \"http://jf:8096\"
          key: k1
    - Sonarr:
        widget:
          type: sonarr
          url: \"http://sonarr:8989\"
          key: k2
- Network:
    - Pi-hole:
        href: \"http://pi.hole/admin\"
- Services:
    - Loose: {}
"
        );
    }

    #[test]
    fn starter_chunks_carry_the_descriptors_defaults() {
        let a = adapter("prometheus").unwrap();
        let n = std::cell::Cell::new(0);
        let chunks = starter_chunks(a, &|| {
            n.set(n.get() + 1);
            format!("id{}", n.get())
        });
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0]["chunk_type"], "prom_global");
        let targets = chunks[1]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["key"] == "targets")
            .unwrap();
        assert_eq!(targets["value"], "localhost:9090");
        assert_eq!(targets["field_type"], "list");
        let pw = chunks[1]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["key"] == "password")
            .unwrap();
        assert_eq!(pw["field_type"], "secret");
    }

    fn rules_of(a: &str, p: &Value, names: &[&str]) -> Vec<(String, String)> {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        check(adapter(a).unwrap(), p, &names)
            .into_iter()
            .map(|f| (f.rule.to_string(), f.chunk_name))
            .collect()
    }

    #[test]
    fn each_prometheus_rule_fires_on_its_case_and_stays_silent_on_a_clean_file() {
        let clean = project(
            "prometheus",
            vec![chunk(
                "prom_scrape",
                "a",
                &[
                    ("targets", "x:1"),
                    ("scheme", "https"),
                    ("username", "u"),
                    ("password", "p"),
                ],
            )],
        );
        assert!(rules_of("prometheus", &clean, &[]).is_empty());
        let dup = project(
            "prometheus",
            vec![
                chunk("prom_scrape", "a", &[("targets", "x:1")]),
                chunk("prom_scrape", "a", &[("targets", "y:1")]),
            ],
        );
        assert_eq!(
            rules_of("prometheus", &dup, &[]),
            vec![("stack-prometheus-duplicate-job".into(), "a".into())]
        );
        let none = project(
            "prometheus",
            vec![chunk("prom_scrape", "a", &[("targets", " ")])],
        );
        assert_eq!(
            rules_of("prometheus", &none, &[])[0].0,
            "stack-prometheus-job-without-targets"
        );
        let both = project(
            "prometheus",
            vec![chunk(
                "prom_scrape",
                "a",
                &[
                    ("targets", "x:1"),
                    ("username", "u"),
                    ("password", "p"),
                    ("bearer_token", "t"),
                ],
            )],
        );
        assert_eq!(
            rules_of("prometheus", &both, &[])[0].0,
            "stack-prometheus-auth-conflict"
        );
        let half = project(
            "prometheus",
            vec![chunk(
                "prom_scrape",
                "a",
                &[("targets", "x:1"), ("username", "u")],
            )],
        );
        assert_eq!(
            rules_of("prometheus", &half, &[])[0].0,
            "stack-prometheus-basic-auth-incomplete"
        );
        let scheme = project(
            "prometheus",
            vec![chunk(
                "prom_scrape",
                "a",
                &[("targets", "x:1"), ("scheme", "ftp")],
            )],
        );
        assert_eq!(
            rules_of("prometheus", &scheme, &[])[0].0,
            "stack-prometheus-bad-scheme"
        );
        let rw = project(
            "prometheus",
            vec![chunk("prom_remote_write", "r", &[("url", "")])],
        );
        assert_eq!(
            rules_of("prometheus", &rw, &[])[0].0,
            "stack-prometheus-remote-write-without-url"
        );
    }

    #[test]
    fn homepage_and_grafana_rules() {
        let dup = project(
            "homepage",
            vec![
                chunk("homepage_service", "A", &[]),
                chunk("homepage_service", "A", &[]),
            ],
        );
        assert_eq!(
            rules_of("homepage", &dup, &[])[0].0,
            "stack-homepage-duplicate-service"
        );
        let w = project(
            "homepage",
            vec![chunk(
                "homepage_service",
                "A",
                &[("widget_type", "sonarr"), ("widget_url", "http://x")],
            )],
        );
        assert_eq!(
            rules_of("homepage", &w, &[])[0].0,
            "stack-homepage-widget-without-credential"
        );
        let ok = project(
            "homepage",
            vec![chunk(
                "homepage_service",
                "A",
                &[
                    ("widget_type", "sonarr"),
                    ("widget_url", "http://x"),
                    ("widget_key", "k"),
                ],
            )],
        );
        assert!(rules_of("homepage", &ok, &[]).is_empty());
        let half = project(
            "homepage",
            vec![chunk(
                "homepage_service",
                "A",
                &[("widget_type", "sonarr"), ("widget_key", "k")],
            )],
        );
        assert_eq!(
            rules_of("homepage", &half, &[])[0].0,
            "stack-homepage-widget-without-url"
        );
        let g = project(
            "grafana",
            vec![chunk(
                "grafana_datasource",
                "d",
                &[("type", ""), ("access", "weird")],
            )],
        );
        let got: Vec<String> = rules_of("grafana", &g, &[])
            .into_iter()
            .map(|r| r.0)
            .collect();
        assert!(got.contains(&"stack-grafana-datasource-without-type".to_string()));
        assert!(got.contains(&"stack-grafana-bad-access".to_string()));
    }

    #[test]
    fn a_reference_to_nothing_in_the_vault_is_flagged_once_and_a_real_one_is_not() {
        let p = project(
            "prometheus",
            vec![chunk(
                "prom_scrape",
                "a",
                &[
                    ("targets", "x:1"),
                    ("username", "u"),
                    ("password", "${Ghost/password}"),
                ],
            )],
        );
        let found = rules_of("prometheus", &p, &["Prometheus"]);
        assert_eq!(
            found,
            vec![("stack-prometheus-unresolved-ref".into(), "a".into())]
        );
        assert!(rules_of("prometheus", &p, &["Ghost"]).is_empty());
        let keyed = project(
            "prometheus",
            vec![chunk(
                "prom_scrape",
                "a",
                &[
                    ("targets", "x:1"),
                    ("username", "u"),
                    ("password", "${Ghost_Admin}"),
                ],
            )],
        );
        assert!(
            rules_of("prometheus", &keyed, &["Ghost"]).is_empty(),
            "PROVIDER_KEYID still names the provider"
        );
        let chunkref = project(
            "prometheus",
            vec![chunk(
                "prom_scrape",
                "a",
                &[
                    ("targets", "x:1"),
                    ("username", "u"),
                    ("password", "${chunk:other/pw}"),
                ],
            )],
        );
        assert!(rules_of("prometheus", &chunkref, &[]).is_empty());
    }

    #[test]
    fn a_finding_never_carries_a_field_value() {
        let p = project(
            "prometheus",
            vec![chunk(
                "prom_scrape",
                "a",
                &[
                    ("targets", "x:1"),
                    ("username", "alice"),
                    ("password", "hunter2-SECRET"),
                    ("bearer_token", "tok-SECRET"),
                ],
            )],
        );
        for f in check(adapter("prometheus").unwrap(), &p, &[]) {
            let all = format!("{} {} {}", f.message, f.field, f.related.join(" "));
            assert!(!all.contains("SECRET") && !all.contains("alice"), "{all}");
        }
    }
}
