//! `.env` parsing, import and watch — the file-drop path from the UI.

use crate::access::Access;
use crate::data::{self, entries_mut, find_project_index, projects};
use crate::error::{CliError, CliResult};
use crate::out;
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// Parse a `.env`, matching `parseEnvFile()` in `src/ts/import-export.ts`:
/// backslash line continuations, an optional `export ` prefix, and one layer of
/// surrounding quotes stripped.
pub fn parse_env_file(text: &str) -> Vec<EnvVar> {
    let lines: Vec<&str> = text.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let mut combined = lines[i].to_string();
        i += 1;
        while combined.trim_end().ends_with('\\') && i < lines.len() {
            let head = combined.trim_end();
            combined = format!("{}{}", &head[..head.len() - 1], lines[i].trim());
            i += 1;
        }
        let trimmed = combined.trim().to_string();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let mut name = trimmed[..eq].trim().to_string();
        if name.to_uppercase().starts_with("EXPORT ") {
            name = name[7..].trim().to_string();
        }
        let mut value = trimmed[eq + 1..].trim().to_string();
        if value.chars().count() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            value = value[1..value.len() - 1].to_string();
        }
        if !name.is_empty() {
            out.push(EnvVar { name, value });
        }
    }
    out
}

pub struct ImportOpts<'a> {
    pub project: Option<&'a str>,
    pub category: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub price: &'a str,
    /// Append a second entry instead of updating one that already carries the key.
    pub allow_duplicates: bool,
}

/// Import a `.env` into the vault.
///
/// Existing keys are **updated** rather than appended by default. The previous
/// behaviour appended unconditionally, which made `envv watch` grow the vault by
/// a full copy of the file on every save — the command was unusable for the one
/// job it exists to do.
pub fn import(access: &Access, file: &PathBuf, opts: &ImportOpts<'_>) -> CliResult {
    let raw = std::fs::read_to_string(file)
        .map_err(|e| CliError::from(format!("Cannot read {}: {e}", file.display())))?;
    let vars = parse_env_file(&raw);
    if vars.is_empty() {
        println!("No KEY=VALUE pairs found in file.");
        return Ok(());
    }

    let mut vault = access.load_vault_or_empty()?;

    let project_ids: Vec<String> = match opts.project {
        Some(p) => {
            let pi = find_project_index(&vault, p)?;
            let id = projects(&vault)[pi]
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("Universal")
                .to_string();
            if id == "Universal" {
                vec!["Universal".into()]
            } else {
                vec![id, "Universal".into()]
            }
        }
        None => vec!["Universal".into()],
    };
    let categories: Vec<String> = opts
        .category
        .filter(|c| !c.is_empty())
        .map(|c| vec![c.to_string()])
        .unwrap_or_default();

    let mut added = 0usize;
    let mut updated = 0usize;
    for v in &vars {
        let existing = if opts.allow_duplicates {
            None
        } else {
            data::entries(&vault).iter().position(|e| {
                data::provider_of(e) == v.name
                    && e.get("secretType")
                        .and_then(|s| s.as_str())
                        .unwrap_or("api_key")
                        == "env_var"
            })
        };
        match existing {
            Some(idx) => {
                let entries = entries_mut(&mut vault);
                if entries[idx].get("api_key").and_then(|k| k.as_str()) != Some(v.value.as_str()) {
                    entries[idx]["api_key"] = json!(v.value);
                    updated += 1;
                }
            }
            None => {
                let mut entry = json!({
                    "id": uuid::Uuid::new_v4().to_string(),
                    "provider": v.name,
                    "api_key": v.value,
                    "price_type": opts.price,
                    "secretType": "env_var",
                    "categories": categories,
                    "projectIds": project_ids,
                    "scopes": [],
                    // When it entered *this* vault. An imported credential is
                    // usually older than that, and there is nothing in a .env
                    // that says how much older.
                    "created_at": vault_core::iso_now(),
                });
                if let Some(e) = opts.environment.filter(|s| !s.is_empty()) {
                    entry["environment"] = json!(e);
                }
                entries_mut(&mut vault).push(entry);
                added += 1;
            }
        }
    }

    if added == 0 && updated == 0 {
        out::ok(
            "import",
            json!({ "added": 0, "updated": 0, "parsed": vars.len(), "changed": false }),
            || println!("Nothing changed — every variable already matches the vault."),
        );
        return Ok(());
    }
    access.save(&vault)?;
    out::ok(
        "import",
        json!({ "added": added, "updated": updated, "parsed": vars.len(), "changed": true }),
        || println!("{added} added, {updated} updated from {}", file.display()),
    );
    Ok(())
}

pub fn watch(access: &Access, file: &PathBuf, opts: &ImportOpts<'_>) -> CliResult {
    use notify::{recommended_watcher, Event, RecursiveMode, Watcher};
    use std::sync::mpsc::channel;

    if !file.exists() {
        return Err(CliError::not_found(format!(
            "File not found: {}",
            file.display()
        )));
    }
    println!("Watching {} for changes (Ctrl-C to stop)…", file.display());

    let (tx, rx) = channel::<notify::Result<Event>>();
    let mut watcher = recommended_watcher(tx).map_err(|e| CliError::from(e.to_string()))?;
    watcher
        .watch(file, RecursiveMode::NonRecursive)
        .map_err(|e| CliError::from(e.to_string()))?;

    for event in rx {
        match event {
            Ok(ev) if ev.kind.is_modify() || ev.kind.is_create() => {
                println!("[{}] Change detected — syncing…", vault_core::iso_now());
                if let Err(e) = import(access, file, opts) {
                    eprintln!("Sync error: {e}");
                }
            }
            Ok(_) => {}
            Err(e) => eprintln!("Watch error: {e}"),
        }
    }
    Ok(())
}

/// Export the whole vault in one of the flat formats offered by "Export as".
pub fn export_vault(
    access: &Access,
    format: &str,
    project: Option<&str>,
    name: &str,
    out: Option<&std::path::Path>,
) -> CliResult {
    let vault = access.load_vault()?;
    let mut list = data::entries(&vault);

    if let Some(proj) = project {
        list = data::entries_in_project(&vault, proj);
    }

    // Same rule as `project export`: values reach a file, never stdout.
    if out.is_none() && !crate::out::revealing() && format != "json" {
        return Err(crate::out::refuse_reveal("This export"));
    }
    if out.is_none() && !crate::out::revealing() && format == "json" {
        // The JSON document is the whole vault; redact it rather than refuse,
        // since its structure is what a caller usually wants to inspect.
        let safe: Vec<Value> = crate::out::redact_entries(&list);
        let doc = if project.is_some() {
            json!(safe)
        } else {
            let mut v = vault.clone();
            v["api_keys"] = json!(safe);
            if let Some(ps) = v.get("projects").and_then(|p| p.as_array()) {
                let redacted: Vec<Value> = ps.iter().map(crate::out::redact_project).collect();
                v["projects"] = json!(redacted);
            }
            v
        };
        crate::out::ok("export", doc.clone(), || {
            println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default())
        });
        return Ok(());
    }

    let content: String = match format {
        "yaml" => crate::exporters::yaml(&list),
        // `json` exports the whole vault document (projects and categories
        // included), matching the app's "Export as JSON" — that file is what
        // `envv backup import` and the app's importer expect to read back.
        "json" => {
            if project.is_some() {
                serde_json::to_string_pretty(&list).unwrap_or_default()
            } else {
                serde_json::to_string_pretty(&vault).unwrap_or_default()
            }
        }
        "k8s" => crate::exporters::k8s_secret(&list, name),
        "tfvars" => crate::exporters::tfvars(&list),
        "dotenv" => crate::exporters::dotenv(&list),
        other => {
            return Err(CliError::invalid(format!(
                "Unknown format '{other}'. Supported: dotenv, yaml, json, k8s, tfvars."
            )))
        }
    };
    crate::fmt::emit(&content, out)
}

/// `import` for a full-vault JSON document (the app's "Export as JSON" file).
pub fn import_json(access: &Access, file: &PathBuf, yes: bool) -> CliResult {
    let raw = std::fs::read_to_string(file)
        .map_err(|e| CliError::from(format!("Cannot read {}: {e}", file.display())))?;
    let data: Value =
        serde_json::from_str(&raw).map_err(|e| CliError::from(format!("Not valid JSON: {e}")))?;
    let list = data
        .get("api_keys")
        .and_then(|v| v.as_array())
        .ok_or("Not a vault export — no api_keys array")?;
    let current = access.load_vault().ok();
    let current_n = current
        .as_ref()
        .and_then(|v| v.get("api_keys"))
        .and_then(|v| v.as_array())
        .map_or(0, |a| a.len());
    if !crate::fmt::confirm(
        &format!(
            "Replace the current vault ({current_n} entries) with {} entries from {}?",
            list.len(),
            file.display()
        ),
        yes,
    )? {
        println!("Cancelled.");
        return Ok(());
    }
    let restored = json!({
        "api_keys": data.get("api_keys").cloned().unwrap_or(json!([])),
        "user_categories": data.get("user_categories").cloned().unwrap_or(json!([])),
        "projects": data.get("projects").cloned().unwrap_or(json!([{
            "id": "Universal", "name": "Universal",
            "description": "All keys belong here by default"
        }])),
    });
    access.save(&restored)?;
    out::ok(
        "import.json",
        json!({ "entries": list.len(), "replaced": true }),
        || println!("Imported {} entries", list.len()),
    );
    Ok(())
}
