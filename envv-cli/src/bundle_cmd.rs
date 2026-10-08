//! `envv bundle` — Phase 24.1. A bundle is an ordinary entry of
//! `secretType: "bundle"`; members are ordinary entries pointing back at it
//! with `bundle_id` / `bundle_slot` / `bundle_order`. Membership is stored once,
//! on the member, so nothing here writes a member list onto the bundle.
//!
//! Every mutation is one `Access::save`, so the compare-and-swap covers all of
//! it and a conflict leaves nothing half-bundled (B14).

use crate::access::Access;
use crate::data::{self, entries_mut, find_entry_index};
use crate::error::{CliError, CliResult};
use crate::fmt::confirm;
use crate::out;
use serde_json::{json, Value};

fn s<'a>(e: &'a Value, k: &str) -> &'a str {
    e.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// Same rule as `label`: `^[A-Za-z0-9][A-Za-z0-9_-]{0,23}$`.
fn valid_slot(slot: &str) -> bool {
    let mut chars = slot.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && slot.len() <= 24
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_bundle(e: &Value) -> bool {
    s(e, "secretType") == "bundle"
}

/// Locate exactly one bundle by name (case-insensitive), refusing ambiguity.
fn bundle_index(vault: &Value, name: &str) -> CliResult<usize> {
    let hits: Vec<usize> = data::entries(vault)
        .iter()
        .enumerate()
        .filter(|(_, e)| is_bundle(e) && data::provider_of(e).eq_ignore_ascii_case(name))
        .map(|(i, _)| i)
        .collect();
    match hits.len() {
        1 => Ok(hits[0]),
        0 => Err(CliError::not_found(format!("No bundle named '{name}'"))),
        n => Err(CliError::ambiguous(format!(
            "{n} bundles are named '{name}'"
        ))),
    }
}

fn bundle_id(vault: &Value, idx: usize) -> CliResult<String> {
    let e = &data::entries(vault)[idx];
    match s(e, "id") {
        "" => Err(CliError::invalid(
            "That bundle has no id; run `envv doctor --fix` first.",
        )),
        id => Ok(id.to_string()),
    }
}

fn members_of(vault: &Value, id: &str) -> Vec<usize> {
    let mut v: Vec<usize> = data::entries(vault)
        .iter()
        .enumerate()
        .filter(|(_, e)| s(e, "bundle_id") == id)
        .map(|(i, _)| i)
        .collect();
    let list = data::entries(vault);
    v.sort_by_key(|i| {
        list[*i]
            .get("bundle_order")
            .and_then(|o| o.as_i64())
            .unwrap_or(0)
    });
    v
}

/// Attach entry `idx` to bundle `id` under `slot`. Does not save.
fn attach(vault: &mut Value, idx: usize, id: &str, slot: &str) -> CliResult {
    if !valid_slot(slot) {
        return Err(CliError::invalid(format!(
            "Slot '{slot}' must match [A-Za-z0-9][A-Za-z0-9_-]{{0,23}}"
        )));
    }
    let list = data::entries(vault);
    let e = &list[idx];
    if is_bundle(e) {
        return Err(CliError::invalid(
            "A bundle cannot be a member of a bundle.",
        ));
    }
    if !s(e, "bundle_id").is_empty() && s(e, "bundle_id") != id {
        return Err(CliError::invalid(format!(
            "'{}' already belongs to another bundle; an entry is in at most one.",
            data::provider_of(e)
        )));
    }
    let clash = list.iter().enumerate().any(|(i, o)| {
        i != idx && s(o, "bundle_id") == id && s(o, "bundle_slot").eq_ignore_ascii_case(slot)
    });
    let bundle = list.iter().find(|o| s(o, "id") == id);
    let local = bundle
        .and_then(|b| b.get("extra_vars").and_then(|v| v.as_array()))
        .is_some_and(|vars| vars.iter().any(|x| s(x, "key").eq_ignore_ascii_case(slot)));
    if clash || local {
        return Err(CliError::conflict(format!(
            "Slot '{slot}' is already used in this bundle."
        )));
    }
    let order = (members_of(vault, id).len() as i64 + 1) * 10;
    let entry = &mut entries_mut(vault)[idx];
    entry["bundle_id"] = json!(id);
    entry["bundle_slot"] = json!(slot);
    entry["bundle_order"] = json!(order);
    Ok(())
}

fn detach(entry: &mut Value) {
    if let Some(o) = entry.as_object_mut() {
        o.remove("bundle_id");
        o.remove("bundle_slot");
        o.remove("bundle_order");
    }
}

pub fn ls(a: &Access) -> CliResult {
    let vault = a.load_vault()?;
    let list = data::entries(&vault);
    let rows: Vec<Value> = list
        .iter()
        .filter(|e| is_bundle(e))
        .map(|b| {
            let id = s(b, "id");
            let members: Vec<Value> = members_of(&vault, id)
                .iter()
                .map(|i| json!({ "slot": s(&list[*i], "bundle_slot"), "provider": data::provider_of(&list[*i]) }))
                .collect();
            let locals: Vec<&str> = b
                .get("extra_vars")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .map(|x| s(x, "key"))
                .collect();
            json!({ "name": data::provider_of(b), "members": members, "locals": locals })
        })
        .collect();
    out::ok(
        "bundle.ls",
        json!({ "count": rows.len(), "bundles": rows }),
        || {
            if rows.is_empty() {
                println!("No bundles.");
            }
            for r in &rows {
                let slots: Vec<String> = r["members"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|m| {
                        format!(
                            "{}={}",
                            m["slot"].as_str().unwrap_or(""),
                            m["provider"].as_str().unwrap_or("")
                        )
                    })
                    .collect();
                println!("{}  {}", r["name"].as_str().unwrap_or(""), slots.join("  "));
            }
        },
    );
    Ok(())
}

/// `members` are `SLOT=ENTRY` pairs.
pub fn new(
    a: &Access,
    name: &str,
    members: &[String],
    import: Option<&std::path::Path>,
) -> CliResult {
    let mut vault = a.load_vault_or_empty()?;
    if data::entries(&vault)
        .iter()
        .any(|e| is_bundle(e) && data::provider_of(e).eq_ignore_ascii_case(name))
    {
        return Err(CliError::conflict(format!(
            "A bundle named '{name}' already exists."
        )));
    }
    let id = vault_core::new_uuid();
    let mut pairs = Vec::new();
    for m in members {
        let (slot, q) = m
            .split_once('=')
            .ok_or_else(|| CliError::invalid(format!("--member wants SLOT=ENTRY, got '{m}'")))?;
        pairs.push((slot.to_string(), find_entry_index(&vault, q)?));
    }
    entries_mut(&mut vault).push(json!({
        "id": id, "provider": name, "secretType": "bundle", "api_key": "",
        "projectIds": ["Universal"], "categories": [],
    }));
    for (slot, idx) in &pairs {
        attach(&mut vault, *idx, &id, slot)?;
    }
    if let Some((_, first)) = pairs.first() {
        let pid = s(&data::entries(&vault)[*first], "id").to_string();
        if !pid.is_empty() {
            let last = data::entries(&vault).len() - 1;
            entries_mut(&mut vault)[last]["bundle_primary"] = json!(pid);
        }
    }
    let mut warnings: Vec<String> = Vec::new();
    let mut locals = 0usize;
    if let Some(path) = import {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CliError::invalid(format!("Cannot read {}: {e}", path.display())))?;
        let imported = vault_core::bundle_import::import_python_config(&text);
        let last = data::entries(&vault).len() - 1;
        let vars: Vec<Value> = imported
            .vars
            .iter()
            .map(|v| json!({ "key": v.key, "value": v.value, "kind": v.kind }))
            .collect();
        locals = vars.len();
        entries_mut(&mut vault)[last]["extra_vars"] = json!(vars);
        warnings = imported.warnings;
    }
    a.save(&vault)?;
    out::ok(
        "bundle.new",
        json!({ "name": name, "members": pairs.len(), "locals": locals, "warnings": warnings }),
        || {
            println!(
                "Created bundle '{name}' with {} member(s), {locals} local variable(s)",
                pairs.len()
            );
            for w in &warnings {
                eprintln!("warning: {w}");
            }
        },
    );
    Ok(())
}

pub fn add(a: &Access, bundle: &str, entry: &str, slot: &str) -> CliResult {
    let mut vault = a.load_vault()?;
    let bi = bundle_index(&vault, bundle)?;
    let id = bundle_id(&vault, bi)?;
    let ei = find_entry_index(&vault, entry)?;
    attach(&mut vault, ei, &id, slot)?;
    a.save(&vault)?;
    out::ok(
        "bundle.add",
        json!({ "bundle": bundle, "slot": slot }),
        || println!("Added to '{bundle}' as {slot}"),
    );
    Ok(())
}

pub fn remove(a: &Access, bundle: &str, slot: &str) -> CliResult {
    let mut vault = a.load_vault()?;
    let bi = bundle_index(&vault, bundle)?;
    let id = bundle_id(&vault, bi)?;
    let idx = members_of(&vault, &id)
        .into_iter()
        .find(|i| s(&data::entries(&vault)[*i], "bundle_slot").eq_ignore_ascii_case(slot))
        .ok_or_else(|| CliError::not_found(format!("No slot '{slot}' in '{bundle}'")))?;
    detach(&mut entries_mut(&mut vault)[idx]);
    a.save(&vault)?;
    out::ok(
        "bundle.remove",
        json!({ "bundle": bundle, "slot": slot }),
        || println!("Removed {slot} from '{bundle}'"),
    );
    Ok(())
}

/// Return every member to the grid and keep the bundle entry (and its local
/// variables) as an ordinary `env_var`-shaped entry. Deletes nothing.
pub fn dissolve(a: &Access, bundle: &str, yes: bool) -> CliResult {
    let mut vault = a.load_vault()?;
    let bi = bundle_index(&vault, bundle)?;
    let id = bundle_id(&vault, bi)?;
    let ms = members_of(&vault, &id);
    if !confirm(
        &format!("Dissolve '{bundle}' ({} member(s) kept)?", ms.len()),
        yes,
    )? {
        println!("Cancelled.");
        return Ok(());
    }
    for i in &ms {
        detach(&mut entries_mut(&mut vault)[*i]);
    }
    let b = &mut entries_mut(&mut vault)[bi];
    b["secretType"] = json!("env_var");
    if let Some(o) = b.as_object_mut() {
        o.remove("bundle_primary");
    }
    a.save(&vault)?;
    out::ok(
        "bundle.dissolve",
        json!({ "bundle": bundle, "members": ms.len() }),
        || println!("Dissolved '{bundle}'; {} entries preserved", ms.len()),
    );
    Ok(())
}

/// Delete the bundle **and its members**. Named separately from `dissolve`
/// and refuses without `--yes`, because it destroys secrets.
pub fn delete(a: &Access, bundle: &str, yes: bool) -> CliResult {
    let mut vault = a.load_vault()?;
    let bi = bundle_index(&vault, bundle)?;
    let id = bundle_id(&vault, bi)?;
    let n = members_of(&vault, &id).len();
    if !confirm(
        &format!("Delete bundle '{bundle}' AND its {n} member entries?"),
        yes,
    )? {
        println!("Cancelled.");
        return Ok(());
    }
    entries_mut(&mut vault).retain(|e| s(e, "id") != id && s(e, "bundle_id") != id);
    a.save(&vault)?;
    out::ok(
        "bundle.delete",
        json!({ "bundle": bundle, "deleted_members": n }),
        || println!("Deleted '{bundle}' and {n} member(s)"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> Value {
        json!({ "api_keys": [
            { "id": "b", "provider": "Spotify", "secretType": "bundle" },
            { "id": "m1", "provider": "Spotify web" },
            { "id": "m2", "provider": "Spotify api" },
            { "id": "other", "provider": "Other", "secretType": "bundle" },
        ]})
    }

    #[test]
    fn selector_finds_bundle_and_member_by_slot() {
        let mut v = vault();
        attach(&mut v, 1, "b", "web").unwrap();
        assert_eq!(data::find_entry_index(&v, "bundle:spotify").unwrap(), 0);
        assert_eq!(data::find_entry_index(&v, "bundle:Spotify/web").unwrap(), 1);
        assert!(data::find_entry_index(&v, "bundle:Spotify/nope").is_err());
    }

    #[test]
    fn membership_rules_are_enforced() {
        let mut v = vault();
        attach(&mut v, 1, "b", "web").unwrap();
        // one slot, one member
        assert!(attach(&mut v, 2, "b", "WEB").is_err());
        // at most one bundle per entry
        assert!(attach(&mut v, 1, "other", "x").is_err());
        // no bundle in a bundle, and slot names are validated
        assert!(attach(&mut v, 3, "b", "x").is_err());
        assert!(attach(&mut v, 2, "b", "bad slot").is_err());
        attach(&mut v, 2, "b", "api").unwrap();
        assert_eq!(v["api_keys"][2]["bundle_order"], 20);
    }
}
