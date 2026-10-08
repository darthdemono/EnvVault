//! `envv check [PROJECT]` — cross-chunk checks (Phase 29).
//!
//! The rules live in `vault_core::config_check` so the desktop app asks the same
//! code over IPC. Findings carry chunk and field names, never field values, so the
//! report is safe to print without `--reveal`; this is not a materialising path.

use crate::access::Access;
use crate::data::{self, find_project_index, projects};
use crate::error::{CliError, CliResult};
use crate::fmt::cell;
use serde_json::{json, Value};
use vault_core::config_check;

/// Entry names a `${…}` reference can legitimately point at.
pub fn vault_names(vault: &Value) -> Vec<String> {
    let mut v = Vec::new();
    for e in data::entries(vault) {
        let p = data::provider_of(&e).to_string();
        if p.is_empty() {
            continue;
        }
        if let Some(k) = e
            .get("key_id")
            .and_then(Value::as_str)
            .filter(|k| !k.is_empty())
        {
            v.push(format!("{p}_{k}"));
        }
        v.push(p);
    }
    v
}

/// `fail_on`: `None` always exits 0; `Some("error")` or `Some("warning")` exits 10
/// when a finding at or above that severity exists.
pub fn run(
    access: &Access,
    project: Option<&str>,
    fail_on: Option<&str>,
    json_out: bool,
) -> CliResult {
    let vault = access.load_vault()?;
    let names = vault_names(&vault);
    let explicit = crate::context::project(project)?;
    let targets: Vec<Value> = match explicit {
        Some(q) => vec![projects(&vault)[find_project_index(&vault, &q)?].clone()],
        None => projects(&vault),
    };

    let mut rows: Vec<Value> = Vec::new();
    for p in &targets {
        let pname = p.get("name").and_then(Value::as_str).unwrap_or("");
        for f in config_check::check_project(p, &names) {
            let mut j = f.to_json();
            j["project"] = json!(pname);
            rows.push(j);
        }
    }
    let errors = rows.iter().filter(|r| r["severity"] == "error").count();
    let warnings = rows.len() - errors;
    let failing = match fail_on {
        Some("error") => errors,
        Some("warning") => rows.len(),
        _ => 0,
    };
    let summary = json!({
        "projects": targets.len(),
        "errors": errors,
        "warnings": warnings,
        "rules": config_check::RULES,
        "findings": rows,
    });

    if failing > 0 && (json_out || crate::out::is_json()) {
        return Err(
            CliError::invalid(format!("{failing} finding(s) at or above --fail-on"))
                .with_details(summary),
        );
    }
    if json_out || crate::out::is_json() {
        crate::out::ok("check", summary, || {});
        return Ok(());
    }
    if rows.is_empty() {
        println!(
            "No cross-chunk problems found in {} project(s).",
            targets.len()
        );
    } else {
        println!(
            "{:<8} {:<18} {:<28} Problem",
            "Severity", "Project", "Chunk"
        );
        println!("{}", "-".repeat(100));
        for r in &rows {
            println!(
                "{:<8} {} {} {}",
                r["severity"].as_str().unwrap_or(""),
                cell(r["project"].as_str().unwrap_or(""), 18),
                cell(r["chunk"].as_str().unwrap_or(""), 28),
                r["message"].as_str().unwrap_or("")
            );
        }
        println!("\n{errors} error(s), {warnings} warning(s)");
    }
    if failing > 0 {
        return Err(CliError::invalid(format!(
            "{failing} finding(s) at or above --fail-on"
        )));
    }
    Ok(())
}
