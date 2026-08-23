//! Shared accessors and lookup rules over the vault JSON blob.
//!
//! Lookups deliberately refuse ambiguity. A CLI that picks the "first match" for
//! `envv entry rm git` deletes whichever of GitHub / GitLab / Gitea happens to
//! sit earlier in the array — the same class of bug as identifying an entry by
//! array index (see the invariants in CLAUDE.md).

use serde_json::{json, Value};
use crate::error::{CliError, CliResult};

pub fn entries(vault: &Value) -> Vec<Value> {
    vault.get("api_keys").and_then(|v| v.as_array()).cloned().unwrap_or_default()
}

pub fn projects(vault: &Value) -> Vec<Value> {
    vault.get("projects").and_then(|v| v.as_array()).cloned().unwrap_or_default()
}

pub fn categories(vault: &Value) -> Vec<String> {
    vault
        .get("user_categories")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|c| c.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

pub fn entries_mut(vault: &mut Value) -> &mut Vec<Value> {
    if !vault.get("api_keys").map(|v| v.is_array()).unwrap_or(false) {
        vault["api_keys"] = json!([]);
    }
    vault["api_keys"].as_array_mut().unwrap()
}

pub fn projects_mut(vault: &mut Value) -> &mut Vec<Value> {
    if !vault.get("projects").map(|v| v.is_array()).unwrap_or(false) {
        vault["projects"] = json!([]);
    }
    vault["projects"].as_array_mut().unwrap()
}

pub fn categories_mut(vault: &mut Value) -> &mut Vec<Value> {
    if !vault.get("user_categories").map(|v| v.is_array()).unwrap_or(false) {
        vault["user_categories"] = json!([]);
    }
    vault["user_categories"].as_array_mut().unwrap()
}

pub fn provider_of(entry: &Value) -> &str {
    entry.get("provider").and_then(|v| v.as_str()).unwrap_or("")
}

/// Locate exactly one entry: exact provider match wins, otherwise a
/// case-insensitive substring match that must be unique.
///
/// `query` may also be `provider:key_id` to disambiguate two keys of the same
/// provider without renaming either.
pub fn find_entry_index(vault: &Value, query: &str) -> CliResult<usize> {
    let list = entries(vault);
    if let Some((prov, kid)) = query.split_once(':') {
        let hits: Vec<usize> = list
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                provider_of(e).eq_ignore_ascii_case(prov)
                    && e.get("key_id").and_then(|v| v.as_str()).unwrap_or("").eq_ignore_ascii_case(kid)
            })
            .map(|(i, _)| i)
            .collect();
        if hits.len() == 1 {
            return Ok(hits[0]);
        }
        if hits.is_empty() {
            return Err(CliError::not_found(format!("No entry '{prov}' with key id '{kid}'")));
        }
    }

    let exact: Vec<usize> = list
        .iter()
        .enumerate()
        .filter(|(_, e)| provider_of(e).eq_ignore_ascii_case(query))
        .map(|(i, _)| i)
        .collect();
    if exact.len() == 1 {
        return Ok(exact[0]);
    }
    if exact.len() > 1 {
        return Err(ambiguous(query, &exact, &list));
    }

    let q = query.to_lowercase();
    let fuzzy: Vec<usize> = list
        .iter()
        .enumerate()
        .filter(|(_, e)| provider_of(e).to_lowercase().contains(&q))
        .map(|(i, _)| i)
        .collect();
    match fuzzy.len() {
        1 => Ok(fuzzy[0]),
        0 => Err(CliError::not_found(format!("No entry matching '{query}'"))),
        _ => Err(ambiguous(query, &fuzzy, &list)),
    }
}

fn ambiguous(query: &str, hits: &[usize], list: &[Value]) -> CliError {
    let names: Vec<String> = hits
        .iter()
        .map(|i| {
            let e = &list[*i];
            match e.get("key_id").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                Some(k) => format!("{}:{k}", provider_of(e)),
                None => provider_of(e).to_string(),
            }
        })
        .collect();
    CliError::ambiguous(format!(
        "'{query}' matches {} entries: {}\nBe exact, or use provider:key_id.",
        hits.len(),
        names.join(", ")
    ))
    // The candidate list is the useful half for a caller that has to choose:
    // a program can present it, or retry with `provider:key_id`.
    .with_details(serde_json::json!({ "candidates": names }))
}

/// Project name → id. Kept identical to `slugifyProjectName` in `projects.ts`;
/// the two must agree or the UI and CLI produce different ids for one name.
pub fn slugify(name: &str) -> String {
    let lower = name.to_lowercase();
    let mut out = String::new();
    let mut pending_dash = false;
    for ch in lower.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '/' {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(ch);
        } else {
            pending_dash = !out.is_empty();
        }
    }
    out.trim_matches('-').to_string()
}

/// Whether a project's id was chosen by hand rather than derived from its name.
///
/// Derived rather than stored, exactly as `hasCustomSlug` does in `projects.ts`:
/// a project whose id is not what `slugify` would produce for its current name
/// must have been given one deliberately. Nothing to migrate, and no flag that
/// can disagree with the data it describes.
pub fn has_custom_slug(project: &Value) -> bool {
    let id = project.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let name = project.get("name").and_then(|v| v.as_str()).unwrap_or("");
    id != slugify(name)
}

/// Validate a hand-written slug. Returns the reason it is unacceptable, if any.
///
/// The id reaches `entry.projectIds`, RBAC scope values and exported filenames,
/// so its shape has to stay predictable: an id with a space or a capital would
/// round-trip through `slugify` into a *different* id the next time anything
/// derived one.
pub fn validate_slug(raw: &str, existing: &[Value], self_id: Option<&str>) -> CliResult<String> {
    let slug = raw.trim().to_string();
    if slug.is_empty() {
        return Err(CliError::invalid("Slug cannot be empty"));
    }
    if slug.chars().count() > 64 {
        return Err(CliError::invalid("Slug must be 64 characters or fewer"));
    }
    if slug.eq_ignore_ascii_case("universal") {
        return Err(CliError::invalid("\"Universal\" is reserved"));
    }
    let shape_ok = !slug.starts_with(['-', '/'])
        && !slug.ends_with(['-', '/'])
        && !slug.contains("//")
        && !slug.contains("--")
        && !slug.contains("-/")
        && !slug.contains("/-")
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '/');
    if !shape_ok {
        return Err(CliError::invalid(
            "Slug may use lowercase letters, digits, - and / (no leading, trailing or repeated separators)",
        ));
    }
    if existing.iter().any(|p| {
        let id = p.get("id").and_then(|v| v.as_str());
        id == Some(slug.as_str()) && id != self_id
    }) {
        return Err(CliError::conflict(format!("Slug '{slug}' is already taken")));
    }
    Ok(slug)
}

/// Locate exactly one project: exact id, then exact name, then unique substring.
pub fn find_project_index(vault: &Value, query: &str) -> CliResult<usize> {
    let list = projects(vault);
    let by_id = list
        .iter()
        .position(|p| p.get("id").and_then(|v| v.as_str()) == Some(query));
    if let Some(i) = by_id {
        return Ok(i);
    }
    let by_name = list
        .iter()
        .position(|p| p.get("name").and_then(|v| v.as_str()) == Some(query));
    if let Some(i) = by_name {
        return Ok(i);
    }
    let q = query.to_lowercase();
    let hits: Vec<usize> = list
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            p.get("name").and_then(|v| v.as_str()).unwrap_or("").to_lowercase().contains(&q)
        })
        .map(|(i, _)| i)
        .collect();
    match hits.len() {
        1 => Ok(hits[0]),
        0 => Err(CliError::not_found(format!("No project matching '{query}'"))),
        _ => {
            let names: Vec<&str> = hits
                .iter()
                .map(|i| list[*i].get("name").and_then(|v| v.as_str()).unwrap_or(""))
                .collect();
            Err(CliError::ambiguous(format!(
                "'{query}' matches {} projects: {}",
                hits.len(),
                names.join(", ")
            ))
            .with_details(serde_json::json!({ "candidates": names })))
        }
    }
}

/// Locate exactly one chunk inside a project, by id or by name.
pub fn find_chunk_index(project: &Value, query: &str) -> CliResult<usize> {
    let chunks = project.get("chunks").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if let Some(i) = chunks.iter().position(|c| c.get("id").and_then(|v| v.as_str()) == Some(query))
    {
        return Ok(i);
    }
    if let Some(i) =
        chunks.iter().position(|c| c.get("name").and_then(|v| v.as_str()) == Some(query))
    {
        return Ok(i);
    }
    let q = query.to_lowercase();
    let hits: Vec<usize> = chunks
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            c.get("name").and_then(|v| v.as_str()).unwrap_or("").to_lowercase().contains(&q)
        })
        .map(|(i, _)| i)
        .collect();
    match hits.len() {
        1 => Ok(hits[0]),
        0 => Err(CliError::not_found(format!("No chunk matching '{query}'"))),
        _ => {
            let names: Vec<&str> = hits
                .iter()
                .map(|i| chunks[*i].get("name").and_then(|v| v.as_str()).unwrap_or(""))
                .collect();
            Err(CliError::ambiguous(format!(
                "'{query}' matches {} chunks: {}",
                hits.len(),
                names.join(", ")
            ))
            .with_details(serde_json::json!({ "candidates": names })))
        }
    }
}

/// Project types the desktop app will create without the experimental setting.
pub const STABLE_PROJECT_TYPES: [&str; 4] = ["generic", "wireguard", "docker", "nginx"];

pub const ALL_PROJECT_TYPES: [&str; 11] = [
    "generic", "wireguard", "docker", "nginx", "kubernetes", "ssh_config", "traefik", "apache",
    "haproxy", "ansible", "postgres",
];

pub fn is_experimental_project_type(t: &str) -> bool {
    !STABLE_PROJECT_TYPES.contains(&t)
}

/// Env-var key derived from a provider name, matching `envKey()` in the UI.
pub fn env_key(provider: &str) -> String {
    provider
        .to_uppercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
