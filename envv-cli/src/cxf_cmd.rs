//! `envv cxf import|export` — FIDO Credential Exchange (CXF), Phase 24.5.
//!
//! Both directions call `vault_core::cxf` and nothing else, the same split
//! every multi-format importer in this project uses and for the same reason:
//! parsed or written twice is two chances for the app and the CLI to
//! disagree about what a file meant.

use crate::access::Access;
use crate::error::{CliError, CliResult};
use crate::out;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use vault_core::cxf;

/// `envv cxf import FILE [--project …] [--category …]`
///
/// Every imported entry is **appended**, never merged into an existing one —
/// unlike `envv totp import`'s conflict-aware merge, there is no single field
/// here ("the seed") whose collision defines a conflict; a CXF item can carry
/// an entirely different credential shape than anything already in the
/// vault. Re-running this against the same file therefore produces
/// duplicates rather than being idempotent, which is the trade this command
/// makes for staying simple — say so if it becomes a problem in practice.
pub fn cmd_import(
    access: &Access,
    file: &Path,
    project: Option<&str>,
    category: Option<&str>,
) -> CliResult {
    let bytes = std::fs::read(file)
        .map_err(|e| CliError::not_found(format!("Cannot read {}: {e}", file.display())))?;
    let doc = cxf::parse(&bytes).map_err(CliError::invalid)?;

    let mut vault = access.load_vault_or_empty()?;
    if let Some(id) = project {
        let known = crate::data::projects(&vault)
            .iter()
            .any(|p| p.get("id").and_then(|x| x.as_str()) == Some(id));
        if id != "Universal" && !known {
            return Err(CliError::not_found(format!(
                "No such project id: '{id}' (see `envv project ls`)"
            )));
        }
    }

    let now = vault_core::iso_now();
    let mut imported = cxf::import(&doc, || uuid::Uuid::new_v4().to_string(), &now);
    for e in &mut imported {
        let mut ids: Vec<String> = e
            .get("projectIds")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| vec!["Universal".to_string()]);
        if let Some(p) = project.filter(|p| *p != "Universal") {
            if !ids.iter().any(|x| x == p) {
                ids.push(p.to_string());
            }
        }
        e["projectIds"] = json!(ids);
        if let Some(c) = category {
            let mut cats: Vec<String> = e
                .get("categories")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if !cats.iter().any(|x| x == c) {
                cats.push(c.to_string());
            }
            e["categories"] = json!(cats);
        }
    }

    let count = imported.len();
    let summary: Vec<Value> = imported
        .iter()
        .map(|e| {
            json!({
                "provider": e.get("provider").and_then(|v| v.as_str()).unwrap_or(""),
                "secretType": e.get("secretType").and_then(|v| v.as_str()).unwrap_or(""),
            })
        })
        .collect();

    if count == 0 {
        out::ok("cxf.import", json!({ "count": 0 }), || {
            println!("Nothing to import — the file has no items.")
        });
        return Ok(());
    }

    crate::data::entries_mut(&mut vault).extend(imported);
    access.save(&vault)?;

    out::ok(
        "cxf.import",
        json!({ "count": count, "entries": summary }),
        || {
            println!(
                "Imported {count} entr{}",
                if count == 1 { "y" } else { "ies" }
            );
            for s in &summary {
                println!(
                    "  {} ({})",
                    s["provider"].as_str().unwrap_or(""),
                    s["secretType"].as_str().unwrap_or(""),
                );
            }
        },
    );
    Ok(())
}

/// `envv cxf export --out FILE [--provider NEEDLE]`
///
/// Materialising by construction, per the Phase 14 rule every export in this
/// project follows: the file is nothing but credentials, so `--out` is the
/// only way it leaves. Unlike `envv totp export`, there is no `--reveal`
/// escape to stdout — a CXF document does not have TOTP's thirty-second decay
/// to fall back on, and nothing here is safe to print in a transcript.
pub fn cmd_export(access: &Access, out_path: &PathBuf, only: Option<&str>) -> CliResult {
    let vault = access.load_vault_or_empty()?;
    let needle = only.map(|s| s.to_lowercase());
    let filtered: Vec<Value> = crate::data::entries(&vault)
        .into_iter()
        .filter(|e| {
            let Some(n) = &needle else { return true };
            e.get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase()
                .contains(n.as_str())
        })
        .collect();

    let doc = cxf::export(&filtered);
    let count = doc.items.len();
    let text = serde_json::to_string_pretty(&doc).map_err(|e| CliError::from(e.to_string()))?;

    std::fs::write(out_path, &text)
        .map_err(|e| CliError::from(format!("Cannot write {}: {e}", out_path.display())))?;
    vault_core::restrict_to_owner(out_path).map_err(CliError::from)?;

    out::ok(
        "cxf.export",
        json!({ "count": count, "written": out_path.display().to_string() }),
        || println!("Wrote {count} item(s) → {}", out_path.display()),
    );
    Ok(())
}
