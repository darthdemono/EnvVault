//! `unv blast-radius` — which credentials were on a machine, and when (Phase 36,
//! ADR-0142).
//!
//! `--host NODE` asks the hub (its audit chain says which files the node applied,
//! its config history says what each contained). `--host local` reads this
//! machine's materialisation log. Either way the answer is the entries to
//! rotate, only the ones whose exposed value is still the live one, and one
//! command that rotates exactly those.
//!
//! The command rotates the vault's copy. Revoking the old credential at its
//! issuer is separate, and the report says so; where the entry carries a
//! console link it is printed next to the entry.

use crate::access::Access;
use crate::error::CliResult;
use crate::{exposure, history_cmd, matlog, out};
use serde_json::{json, Value};
use vault_core::blast::{self, Deployment};

pub fn run(a: &Access, host: &str, since: Option<&str>) -> CliResult {
    let report: Value = if matches!(host, "local" | "this") {
        local(a, since)?
    } else {
        history_cmd::invoke(a, "blast", json!({ "host": host, "since": since }))?
    };
    out::ok("blast-radius", report.clone(), || print_report(&report));
    Ok(())
}

fn local(a: &Access, since: Option<&str>) -> CliResult<Value> {
    let vault = a.load_vault()?;
    let label = match a {
        Access::Local(_) => "local".to_string(),
        Access::Remote(c) => c.base.clone(),
    };
    let records: Vec<matlog::Record> = matlog::read(&matlog::path())
        .into_iter()
        .filter(|r| r.vault == label)
        .collect();
    let deployments: Vec<Deployment> = records
        .iter()
        .enumerate()
        .map(|(i, r)| Deployment {
            at: r.at.clone(),
            via: format!("{} {}", r.kind, r.note).trim().to_string(),
            // The index into `records`; a local record carries its exposures, not a hash.
            sha256: i.to_string(),
            ok: true,
            error: None,
        })
        .collect();
    let current = exposure::current_map(&vault);
    let rep = blast::report(
        &format!("this machine ({})", crate::node_agent::hostname()),
        since,
        &deployments,
        &|d| {
            d.sha256
                .parse::<usize>()
                .ok()
                .and_then(|i| records.get(i))
                .map(|r| r.exposed.clone())
        },
        &|id| current.get(id).cloned(),
    );
    serde_json::to_value(rep).map_err(|e| crate::error::CliError::from(e.to_string()))
}

fn print_report(r: &Value) {
    println!(
        "Blast radius of {}{}: {} deployment(s), {} credential(s)",
        r["host"].as_str().unwrap_or("?"),
        r["since"]
            .as_str()
            .map(|s| format!(" since {s}"))
            .unwrap_or_default(),
        r["deployments"],
        r["entries"].as_array().map_or(0, Vec::len)
    );
    for e in r["entries"].as_array().cloned().unwrap_or_default() {
        let tag = if e["removed"] == true {
            "removed"
        } else if e["still_current"] == true {
            "ROTATE "
        } else {
            "rotated"
        };
        let name = match e["key_id"].as_str().filter(|k| !k.is_empty()) {
            Some(k) => format!("{}:{k}", e["provider"].as_str().unwrap_or("?")),
            None => e["provider"].as_str().unwrap_or("?").to_string(),
        };
        let fields: Vec<&str> = e["fields"]
            .as_array()
            .map_or(vec![], |f| f.iter().filter_map(Value::as_str).collect());
        println!(
            "  {tag} {name} ({})  first {}  last {}  x{}{}{}",
            fields.join(", "),
            e["first_seen"].as_str().unwrap_or(""),
            e["last_seen"].as_str().unwrap_or(""),
            e["times"],
            if e["short"] == true {
                "  [short value: may be a coincidence]"
            } else {
                ""
            },
            e["console_url"]
                .as_str()
                .map(|u| format!("  revoke at {u}"))
                .unwrap_or_default()
        );
    }
    let un = r["unaccounted"].as_array().cloned().unwrap_or_default();
    if !un.is_empty() {
        println!(
            "\n{} deployment(s) have no recorded contents (history was off, or pruned): their exposure is unknown.",
            un.len()
        );
        for d in &un {
            println!(
                "  {} {} {}",
                d["at"].as_str().unwrap_or(""),
                d["via"].as_str().unwrap_or(""),
                d["sha256"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(8)
                    .collect::<String>()
            );
        }
    }
    let cmd = r["command"].as_str().unwrap_or("");
    if cmd.is_empty() {
        println!("\nNothing in the vault needs rotating for this host.");
    } else {
        println!("\nRotate these and nothing else:\n  {cmd}\n\nThat replaces the vault's copy. Revoke the old credential at its issuer too.");
    }
}
