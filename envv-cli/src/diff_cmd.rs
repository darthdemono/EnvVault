//! `envv diff A B` — compare two entries field by field, the CLI side of the app's
//! Diff tool (Phase 33.6). Secrets are redacted like everywhere else: a
//! fingerprint on each side, so "equal" and "different" are still answerable
//! without reading either value; `--reveal` shows them.

use crate::access::Access;
use crate::data::{self, find_entry_index};
use crate::error::{CliError, CliResult};
use crate::out;
use serde_json::{json, Value};

/// The same fields, in the same order, as the app's Diff pane.
const FIELDS: [(&str, &str); 14] = [
    ("provider", "Provider"),
    ("account_name", "Account"),
    ("api_key", "Key"),
    ("api_secret", "Secret"),
    ("key_id", "Label"),
    ("price_type", "Price"),
    ("environment", "Environment"),
    ("api_url", "API URL"),
    ("expires_at", "Expires"),
    ("rate_limit", "Rate Limit"),
    ("purpose", "Purpose"),
    ("pool", "Key Pool"),
    ("version", "Version"),
    ("api_description", "Description"),
];

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

pub fn run(access: &Access, a: &str, b: &str) -> CliResult {
    let vault = access.load_vault()?;
    let ia = find_entry_index(&vault, a)?;
    let ib = find_entry_index(&vault, b)?;
    if ia == ib {
        return Err(CliError::invalid("Pick two different entries"));
    }
    let (ea, eb) = (&data::entries(&vault)[ia], &data::entries(&vault)[ib]);
    let reveal = out::revealing();
    let mut rows = Vec::new();
    for (key, label) in FIELDS {
        let (va, vb) = (text(ea.get(key)), text(eb.get(key)));
        let secret = key == "api_key" || key == "api_secret";
        let show = |v: &str| {
            if secret && !reveal && !v.is_empty() {
                out::fingerprint(v)
            } else {
                v.to_string()
            }
        };
        rows.push(json!({
            "field": key, "label": label, "a": show(&va), "b": show(&vb), "changed": va != vb,
        }));
    }
    let changed = rows.iter().filter(|r| r["changed"] == true).count();
    out::ok(
        "diff",
        json!({ "a": a, "b": b, "changed": changed, "rows": rows }),
        || {
            for r in &rows {
                let mark = if r["changed"] == true { "~" } else { " " };
                println!(
                    "{mark} {:<12} {:<30} {}",
                    r["label"].as_str().unwrap_or(""),
                    r["a"].as_str().unwrap_or(""),
                    r["b"].as_str().unwrap_or("")
                );
            }
            println!("{changed} field(s) differ");
        },
    );
    Ok(())
}
