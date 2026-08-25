//! Project and category CRUD, mirroring `src/ts/projects.ts` — including the
//! rename/delete cascades, which are the part that must not drift.

use crate::access::Access;
use crate::data::{
    self, categories_mut, entries_mut, find_project_index, projects, projects_mut, slugify,
};
use crate::error::{CliError, CliResult};
use crate::fmt::{cell, confirm};
use crate::out;
use serde_json::{json, Value};

// ── Projects ──────────────────────────────────────────────────────────────────

pub fn cmd_ls(access: &Access, json_out: bool) -> CliResult {
    let vault = access.load_vault()?;
    let list = projects(&vault);
    let entries = data::entries(&vault);
    if json_out || out::is_json() {
        let rows: Vec<Value> = list
            .iter()
            .map(|p| {
                let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let count = entries
                    .iter()
                    .filter(|e| {
                        e.get("projectIds")
                            .and_then(|v| v.as_array())
                            .is_some_and(|ids| ids.iter().any(|x| x.as_str() == Some(id)))
                    })
                    .count();
                let mut row = out::redact_project(p);
                row["entry_count"] = json!(count);
                row
            })
            .collect();
        out::ok(
            "project.ls",
            json!({ "count": rows.len(), "projects": rows }),
            || {},
        );
        return Ok(());
    }
    if list.is_empty() {
        println!("No projects.");
        return Ok(());
    }
    println!(
        "{:<28} {:<28} {:<12} {:>7} {:>7}",
        "Id", "Name", "Type", "Entries", "Chunks"
    );
    println!("{}", "-".repeat(86));
    for p in &list {
        let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let ptype = p
            .get("project_type")
            .and_then(|v| v.as_str())
            .unwrap_or("generic");
        let chunks = p
            .get("chunks")
            .and_then(|v| v.as_array())
            .map_or(0, |a| a.len());
        let n = entries
            .iter()
            .filter(|e| {
                e.get("projectIds")
                    .and_then(|v| v.as_array())
                    .is_some_and(|ids| ids.iter().any(|x| x.as_str() == Some(id)))
            })
            .count();
        println!(
            "{} {} {} {:>7} {:>7}",
            cell(id, 28),
            cell(name, 28),
            cell(ptype, 12),
            n,
            chunks
        );
    }
    Ok(())
}

pub fn cmd_show(access: &Access, query: &str) -> CliResult {
    let vault = access.load_vault()?;
    let idx = find_project_index(&vault, query)?;
    let safe = out::redact_project(&projects(&vault)[idx]);
    out::ok("project.show", safe.clone(), || {
        println!(
            "{}",
            serde_json::to_string_pretty(&safe).unwrap_or_default()
        )
    });
    Ok(())
}

pub fn cmd_add(
    access: &Access,
    name: &str,
    ptype: &str,
    desc: Option<&str>,
    slug: Option<&str>,
    experimental: bool,
    if_missing: bool,
) -> CliResult {
    // Creating the project is what writes `project_type` into the vault, so the
    // experimental gate lives here, at the write — the same place `setProjectCreateType`
    // enforces it in the UI, and for the same reason: these types have never been
    // run against a real deployment and a wrong config is a broken deploy.
    if data::is_experimental_project_type(ptype) && !experimental {
        return Err(CliError::invalid(format!(
            "'{ptype}' is an untested project type — pass --experimental to create it anyway.\nStable types: {}",
            data::STABLE_PROJECT_TYPES.join(", ")
        )));
    }

    let mut vault = access.load_vault_or_empty()?;
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Name is required".into());
    }
    // One rule decides the id, and the UI applies the same one: an explicit
    // slug wins, otherwise it is derived from the name.
    let leaf_id = match slug {
        Some(raw) => data::validate_slug(raw, &projects(&vault), None)?,
        None => slugify(trimmed),
    };
    if leaf_id.is_empty() {
        return Err(CliError::invalid(
            "That name produces an empty slug — pass --slug to set one explicitly",
        ));
    }
    if projects(&vault)
        .iter()
        .any(|p| p.get("id").and_then(|v| v.as_str()) == Some(&leaf_id))
    {
        // Idempotency for provisioning scripts: re-running is not an error.
        if if_missing {
            crate::out::ok(
                "project.add",
                serde_json::json!({ "id": leaf_id, "created": false, "reason": "exists" }),
                || println!("Project '{leaf_id}' already exists — left alone"),
            );
            return Ok(());
        }
        return Err(CliError::conflict(format!(
            "Project '{leaf_id}' already exists"
        )));
    }

    let mut new_project = json!({ "id": leaf_id, "name": trimmed });
    if let Some(d) = desc.filter(|d| !d.is_empty()) {
        new_project["description"] = json!(d);
    }
    if ptype != "generic" {
        new_project["project_type"] = json!(ptype);
    }
    if let Some(chunks) = crate::starters::starter_chunks(ptype) {
        new_project["chunks"] = json!(chunks);
    }

    // Slash segments are a hierarchy: creating "Acme/Web" must leave "Acme"
    // existing, or the sidebar synthesises a phantom parent node.
    let parts: Vec<&str> = trimmed.split('/').collect();
    for i in 1..parts.len() {
        let ancestor_name = parts[..i].join("/");
        let ancestor_id = slugify(&ancestor_name);
        if !projects(&vault)
            .iter()
            .any(|p| p.get("id").and_then(|v| v.as_str()) == Some(&ancestor_id))
        {
            projects_mut(&mut vault).push(json!({ "id": ancestor_id, "name": ancestor_name }));
        }
    }
    let created_id = new_project
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let chunk_count = new_project
        .get("chunks")
        .and_then(|c| c.as_array())
        .map_or(0, |a| a.len());
    projects_mut(&mut vault).push(new_project);
    access.save(&vault)?;
    let custom = slug.is_some();
    out::ok(
        "project.add",
        json!({
            "id": created_id, "name": trimmed, "type": ptype,
            "chunks": chunk_count, "created": true, "custom_slug": custom,
        }),
        || println!("Created project '{trimmed}' ({created_id})"),
    );
    Ok(())
}

pub fn cmd_rename(
    access: &Access,
    query: &str,
    new_name: Option<&str>,
    new_slug: Option<&str>,
) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_project_index(&vault, query)?;
    let old_name = projects(&vault)[idx]
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let old_id = projects(&vault)[idx]
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let new_name = new_name.unwrap_or(&old_name).to_string();
    let new_name = new_name.as_str();
    if new_name == old_name && new_slug.is_none() {
        return Ok(());
    }

    // A hand-chosen slug survives a rename. The id is what every entry, every
    // permission rule and every scope value points at, so re-deriving it from a
    // new display name would silently retarget all of them — which is the reason
    // someone pinned it in the first place. `--slug` changes it deliberately,
    // and the cascade below remaps the references that follow.
    let new_id = match new_slug {
        Some(raw) => data::validate_slug(raw, &projects(&vault), Some(&old_id))?,
        None if data::has_custom_slug(&projects(&vault)[idx]) => old_id.clone(),
        None => slugify(new_name),
    };
    if new_id != old_id
        && projects(&vault)
            .iter()
            .any(|p| p.get("id").and_then(|v| v.as_str()) == Some(&new_id))
    {
        return Err(CliError::conflict(format!(
            "Project '{new_id}' already exists"
        )));
    }

    // Sub-projects are names sharing a `parent/` prefix, so the rename has to
    // carry them. Renaming only the parent strands "Acme/Web" under a project
    // that no longer exists.
    let child_prefix = format!("{old_name}/");
    let child_ids: Vec<String> = projects(&vault)
        .iter()
        .filter(|p| {
            p.get("id").and_then(|v| v.as_str()) != Some(&old_id)
                && p.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .starts_with(&child_prefix)
        })
        .filter_map(|p| p.get("id").and_then(|v| v.as_str()).map(String::from))
        .collect();

    let mut id_remap: Vec<(String, String)> = Vec::new();
    if new_id != old_id {
        id_remap.push((old_id.clone(), new_id.clone()));
    }
    {
        let list = projects_mut(&mut vault);
        list[idx]["id"] = json!(new_id);
        list[idx]["name"] = json!(new_name);
    }

    for cid in child_ids {
        let (ci, child_name, child_custom) = {
            let list = projects(&vault);
            let ci = list
                .iter()
                .position(|p| p.get("id").and_then(|v| v.as_str()) == Some(&cid))
                .ok_or("child project vanished mid-rename")?;
            let n = list[ci]
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (ci, n, data::has_custom_slug(&list[ci]))
        };
        let next_name = format!("{new_name}{}", &child_name[old_name.len()..]);
        // Same rule per child: a sub-project with its own pinned slug keeps it.
        if child_custom {
            projects_mut(&mut vault)[ci]["name"] = json!(next_name);
            continue;
        }
        let base = slugify(&next_name);
        let mut fid = base.clone();
        let mut n = 1;
        while projects(&vault)
            .iter()
            .enumerate()
            .any(|(i, p)| i != ci && p.get("id").and_then(|v| v.as_str()) == Some(&fid))
        {
            fid = format!("{base}-{n}");
            n += 1;
        }
        if fid != cid {
            id_remap.push((cid.clone(), fid.clone()));
        }
        let list = projects_mut(&mut vault);
        list[ci]["id"] = json!(fid);
        list[ci]["name"] = json!(next_name);
    }

    let touched = if id_remap.is_empty() {
        0
    } else {
        remap_entry_projects(&mut vault, &id_remap)
    };
    access.save(&vault)?;
    out::ok(
        "project.rename",
        json!({
            "from": old_name, "to": new_name,
            "id": new_id, "slug_changed": new_id != old_id,
            "remapped_ids": id_remap.len(), "entries_repointed": touched,
        }),
        || {
            println!("Renamed project '{old_name}' → '{new_name}'");
            if new_id != old_id {
                println!(
                    "Slug '{old_id}' → '{new_id}' ({touched} entr{} repointed)",
                    if touched == 1 { "y" } else { "ies" }
                );
            }
        },
    );
    Ok(())
}

/// Point every entry at the new ids. Returns how many entries actually changed —
/// the number worth reporting, since the count of id *mappings* says nothing
/// about how much data moved.
fn remap_entry_projects(vault: &mut Value, remap: &[(String, String)]) -> usize {
    let mut touched = 0usize;
    for entry in entries_mut(vault).iter_mut() {
        let Some(ids) = entry.get("projectIds").and_then(|v| v.as_array()) else {
            continue;
        };
        let next: Vec<Value> = ids
            .iter()
            .map(|id| {
                let s = id.as_str().unwrap_or("");
                match remap.iter().find(|(old, _)| old == s) {
                    Some((_, new)) => json!(new),
                    None => id.clone(),
                }
            })
            .collect();
        if next != *ids {
            touched += 1;
        }
        entry["projectIds"] = json!(next);
    }
    touched
}

pub fn cmd_rm(access: &Access, query: &str, yes: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_project_index(&vault, query)?;
    let id = projects(&vault)[idx]
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if id == "Universal" {
        return Err("The Universal project cannot be deleted".into());
    }
    let name = projects(&vault)[idx]
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let child_prefix = format!("{name}/");
    let child_ids: Vec<String> = projects(&vault)
        .iter()
        .filter(|p| {
            p.get("id").and_then(|v| v.as_str()) != Some(&id)
                && p.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .starts_with(&child_prefix)
        })
        .filter_map(|p| p.get("id").and_then(|v| v.as_str()).map(String::from))
        .collect();

    let mut msg = format!("Delete project '{name}'?");
    if !child_ids.is_empty() {
        msg += &format!(
            " {} sub-project{} will be promoted to top level.",
            child_ids.len(),
            if child_ids.len() == 1 { "" } else { "s" }
        );
    }
    if !confirm(&msg, yes)? {
        println!("Cancelled.");
        return Ok(());
    }

    for entry in entries_mut(&mut vault).iter_mut() {
        if let Some(ids) = entry.get("projectIds").and_then(|v| v.as_array()) {
            let kept: Vec<Value> = ids
                .iter()
                .filter(|x| x.as_str() != Some(&id))
                .cloned()
                .collect();
            entry["projectIds"] = json!(kept);
        }
    }
    projects_mut(&mut vault).remove(idx);

    // Promoting a sub-project changes its id, so every entry pointing at the old
    // id has to follow. Skipping this remap makes the dangling-reference prune
    // below strip them, and deleting a parent silently empties every survivor.
    let mut id_remap: Vec<(String, String)> = Vec::new();
    for cid in child_ids {
        let (ci, child_name, child_custom) = {
            let list = projects(&vault);
            let ci = list
                .iter()
                .position(|p| p.get("id").and_then(|v| v.as_str()) == Some(&cid))
                .ok_or("child project vanished mid-delete")?;
            let n = list[ci]
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (ci, n, data::has_custom_slug(&list[ci]))
        };
        let next_name = child_name[name.len() + 1..].to_string();
        // Promotion changes where a project sits in the tree, not what points
        // at it — a pinned slug survives it.
        if child_custom {
            projects_mut(&mut vault)[ci]["name"] = json!(next_name);
            continue;
        }
        let base = slugify(&next_name);
        let mut fid = base.clone();
        let mut n = 1;
        while projects(&vault)
            .iter()
            .enumerate()
            .any(|(i, p)| i != ci && p.get("id").and_then(|v| v.as_str()) == Some(&fid))
        {
            fid = format!("{base}-{n}");
            n += 1;
        }
        if fid != cid {
            id_remap.push((cid.clone(), fid.clone()));
        }
        let list = projects_mut(&mut vault);
        list[ci]["id"] = json!(fid);
        list[ci]["name"] = json!(next_name);
    }
    if !id_remap.is_empty() {
        remap_entry_projects(&mut vault, &id_remap);
    }

    // Prune dangling ids and restore the Universal catch-all.
    let live: Vec<String> = projects(&vault)
        .iter()
        .filter_map(|p| p.get("id").and_then(|v| v.as_str()).map(String::from))
        .collect();
    for entry in entries_mut(&mut vault).iter_mut() {
        let mut ids: Vec<String> = entry
            .get("projectIds")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        ids.retain(|i| i == "Universal" || live.iter().any(|l| l == i));
        if !ids.iter().any(|i| i == "Universal") {
            ids.push("Universal".into());
        }
        entry["projectIds"] = json!(ids);
    }

    access.save(&vault)?;
    out::ok(
        "project.rm",
        json!({ "id": id, "name": name, "promoted": id_remap.len(), "deleted": true }),
        || println!("Deleted project '{name}'"),
    );
    Ok(())
}

// ── Categories ────────────────────────────────────────────────────────────────

pub fn cat_ls(access: &Access) -> CliResult {
    let vault = access.load_vault()?;
    let cats = data::categories(&vault);
    let entries = data::entries(&vault);
    if out::is_json() {
        let rows: Vec<Value> = cats
            .iter()
            .map(|c| {
                let n = entries
                    .iter()
                    .filter(|e| {
                        e.get("categories")
                            .and_then(|v| v.as_array())
                            .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(c.as_str())))
                    })
                    .count();
                json!({ "name": c, "entry_count": n })
            })
            .collect();
        out::ok(
            "category.ls",
            json!({ "count": rows.len(), "categories": rows }),
            || {},
        );
        return Ok(());
    }
    if cats.is_empty() {
        println!("No categories.");
        return Ok(());
    }
    for c in cats {
        let n = entries
            .iter()
            .filter(|e| {
                e.get("categories")
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(&c)))
            })
            .count();
        println!("{}  {n}", cell(&c, 34));
    }
    Ok(())
}

pub fn cat_add(access: &Access, name: &str) -> CliResult {
    let mut vault = access.load_vault_or_empty()?;
    // The UI lowercases on create; matching it keeps one spelling per category.
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        return Err("Name is required".into());
    }
    if data::categories(&vault).iter().any(|c| c == &name) {
        return Err(CliError::conflict(format!(
            "Category '{name}' already exists"
        )));
    }
    categories_mut(&mut vault).push(json!(name));
    access.save(&vault)?;
    out::ok(
        "category.add",
        json!({ "name": name, "created": true }),
        || println!("Created category '{name}'"),
    );
    Ok(())
}

pub fn cat_rename(access: &Access, name: &str, new_name: &str) -> CliResult {
    let mut vault = access.load_vault()?;
    if !data::categories(&vault).iter().any(|c| c == name) {
        return Err(CliError::not_found(format!("No category '{name}'")));
    }
    if data::categories(&vault).iter().any(|c| c == new_name) {
        return Err(CliError::conflict(format!(
            "Category '{new_name}' already exists"
        )));
    }
    // Categories nest by slash exactly as projects do — carry the sub-tree.
    let prefix = format!("{name}/");
    let remap = |c: &str| -> String {
        if c == name {
            new_name.to_string()
        } else if c.starts_with(&prefix) {
            format!("{new_name}{}", &c[name.len()..])
        } else {
            c.to_string()
        }
    };

    let next: Vec<Value> = data::categories(&vault)
        .iter()
        .map(|c| json!(remap(c)))
        .collect();
    *categories_mut(&mut vault) = next;
    for entry in entries_mut(&mut vault).iter_mut() {
        if let Some(cats) = entry.get("categories").and_then(|v| v.as_array()) {
            let mapped: Vec<Value> = cats
                .iter()
                .map(|c| json!(remap(c.as_str().unwrap_or(""))))
                .collect();
            entry["categories"] = json!(mapped);
        }
    }
    access.save(&vault)?;
    out::ok(
        "category.rename",
        json!({ "from": name, "to": new_name }),
        || println!("Renamed category '{name}' → '{new_name}'"),
    );
    Ok(())
}

pub fn cat_rm(access: &Access, name: &str, yes: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let prefix = format!("{name}/");
    let doomed = |c: &str| c == name || c.starts_with(&prefix);
    let cats = data::categories(&vault);
    if !cats.iter().any(|c| doomed(c)) {
        return Err(CliError::not_found(format!("No category '{name}'")));
    }
    let sub_count = cats.iter().filter(|c| c.starts_with(&prefix)).count();
    let mut msg = format!("Delete category '{name}'?");
    if sub_count > 0 {
        msg += &format!(
            " {sub_count} sub-categor{} will be deleted too.",
            if sub_count == 1 { "y" } else { "ies" }
        );
    }
    if !confirm(&msg, yes)? {
        println!("Cancelled.");
        return Ok(());
    }

    let kept: Vec<Value> = cats
        .iter()
        .filter(|c| !doomed(c))
        .map(|c| json!(c))
        .collect();
    *categories_mut(&mut vault) = kept;
    for entry in entries_mut(&mut vault).iter_mut() {
        if let Some(list) = entry.get("categories").and_then(|v| v.as_array()) {
            let kept: Vec<Value> = list
                .iter()
                .filter(|c| !doomed(c.as_str().unwrap_or("")))
                .cloned()
                .collect();
            entry["categories"] = json!(kept);
        }
    }
    access.save(&vault)?;
    out::ok(
        "category.rm",
        json!({ "name": name, "sub_categories": sub_count, "deleted": true }),
        || println!("Deleted category '{name}'"),
    );
    Ok(())
}
