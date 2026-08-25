//! Users, classes, tokens and permission expressions — the Users panel.
//!
//! Local mode drives `vault-core::users` directly; remote mode goes through the
//! server's `/api/users` and `/api/classes` endpoints, which apply the same
//! authority-tier guards a scoped session is subject to in the UI.

use crate::access::Access;
use crate::error::{CliError, CliResult};
use crate::fmt::{cell, confirm};
use crate::out;
use reqwest::Method;
use serde_json::{json, Value};

// ── Users ─────────────────────────────────────────────────────────────────────

pub fn user_ls(access: &Access, json_out: bool) -> CliResult {
    let rows: Vec<Value> = match access {
        Access::Remote(c) => c
            .get_json("/api/users")?
            .as_array()
            .cloned()
            .unwrap_or_default(),
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::list_users(&conn)?
                .into_iter()
                .map(|u| serde_json::to_value(u).unwrap_or(Value::Null))
                .collect()
        }
    };
    if json_out || out::is_json() {
        out::ok(
            "user.ls",
            json!({ "count": rows.len(), "users": rows }),
            || {},
        );
        return Ok(());
    }
    if rows.is_empty() {
        println!("No users.");
        return Ok(());
    }
    println!(
        "{:<38} {:<20} {:<8} {:<6} Last seen",
        "Id", "Username", "Password", "Owner"
    );
    println!("{}", "-".repeat(96));
    for u in &rows {
        println!(
            "{} {} {:<8} {:<6} {}",
            cell(u.get("id").and_then(|v| v.as_str()).unwrap_or(""), 38),
            cell(u.get("username").and_then(|v| v.as_str()).unwrap_or(""), 20),
            if u.get("has_password")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                "yes"
            } else {
                "no"
            },
            if u.get("is_owner").and_then(|v| v.as_bool()).unwrap_or(false) {
                "yes"
            } else {
                "no"
            },
            u.get("last_seen_at")
                .and_then(|v| v.as_str())
                .unwrap_or("—"),
        );
    }
    Ok(())
}

/// Resolve a username or id to a user id.
fn resolve_user(access: &Access, query: &str) -> CliResult<String> {
    let rows: Vec<Value> = match access {
        Access::Remote(c) => c
            .get_json("/api/users")?
            .as_array()
            .cloned()
            .unwrap_or_default(),
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::list_users(&conn)?
                .into_iter()
                .map(|u| serde_json::to_value(u).unwrap_or(Value::Null))
                .collect()
        }
    };
    if let Some(u) = rows
        .iter()
        .find(|u| u.get("id").and_then(|v| v.as_str()) == Some(query))
    {
        return Ok(u["id"].as_str().unwrap_or("").to_string());
    }
    let hits: Vec<&Value> = rows
        .iter()
        .filter(|u| {
            u.get("username")
                .and_then(|v| v.as_str())
                .is_some_and(|n| n.eq_ignore_ascii_case(query))
        })
        .collect();
    match hits.len() {
        1 => Ok(hits[0]["id"].as_str().unwrap_or("").to_string()),
        0 => Err(CliError::not_found(format!("No user '{query}'"))),
        _ => Err(CliError::ambiguous(format!(
            "'{query}' matches {} users — use the id",
            hits.len()
        ))),
    }
}

fn prompt_optional_password(flag: Option<&str>, ask: bool) -> CliResult<Option<String>> {
    if let Some(p) = flag {
        return Ok(Some(p.to_string()));
    }
    if !ask {
        return Ok(None);
    }
    let pw = rpassword::prompt_password("New user password (blank for token-only): ")
        .map_err(|e| CliError::from(e.to_string()))?;
    Ok(if pw.is_empty() { None } else { Some(pw) })
}

pub fn user_add(
    access: &Access,
    username: &str,
    password: Option<&str>,
    no_password: bool,
) -> CliResult {
    let pw = prompt_optional_password(password, !no_password)?;
    match access {
        Access::Remote(c) => {
            let body = json!({ "username": username, "password": pw });
            let created = c.send_json(Method::POST, "/api/users", Some(&body))?;
            let id = created
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            out::ok(
                "user.add",
                json!({ "username": username, "id": id, "created": true }),
                || println!("Created user '{username}' ({id})"),
            );
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            let u = vault_core::create_user(&conn, username, pw.as_deref(), false)?;
            out::ok(
                "user.add",
                json!({ "username": u.username, "id": u.id, "created": true, "has_password": u.has_password }),
                || println!("Created user '{}' ({})", u.username, u.id),
            );
        }
    }
    Ok(())
}

pub fn user_rm(access: &Access, query: &str, yes: bool) -> CliResult {
    let id = resolve_user(access, query)?;
    if !confirm(&format!("Delete user '{query}'?"), yes)? {
        println!("Cancelled.");
        return Ok(());
    }
    match access {
        Access::Remote(c) => {
            c.send_json(Method::DELETE, &format!("/api/users/{id}"), None)?;
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::delete_user(&conn, &id)?;
        }
    }
    out::ok(
        "user.rm",
        json!({ "user": query, "id": id, "deleted": true }),
        || println!("Deleted user '{query}'"),
    );
    Ok(())
}

pub fn user_rename(access: &Access, query: &str, new_name: &str) -> CliResult {
    let id = resolve_user(access, query)?;
    match access {
        Access::Remote(c) => {
            c.send_json(
                Method::PUT,
                &format!("/api/users/{id}/rename"),
                Some(&json!({ "username": new_name })),
            )?;
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::rename_user(&conn, &id, new_name)?;
        }
    }
    out::ok(
        "user.rename",
        json!({ "from": query, "to": new_name }),
        || println!("Renamed user '{query}' → '{new_name}'"),
    );
    Ok(())
}

pub fn user_passwd(access: &Access, query: &str, clear: bool) -> CliResult {
    let id = resolve_user(access, query)?;
    let pw: Option<String> = if clear {
        None
    } else {
        let p = rpassword::prompt_password("New password: ")
            .map_err(|e| CliError::from(e.to_string()))?;
        let again =
            rpassword::prompt_password("Repeat: ").map_err(|e| CliError::from(e.to_string()))?;
        if p != again {
            return Err("Passwords do not match".into());
        }
        Some(p)
    };
    match access {
        Access::Remote(c) => {
            c.send_json(
                Method::PUT,
                &format!("/api/users/{id}/password"),
                Some(&json!({ "password": pw })),
            )?;
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::set_user_password(&conn, &id, pw.as_deref())?;
        }
    }
    out::ok(
        "user.passwd",
        json!({ "user": query, "has_password": !clear }),
        || {
            println!(
                "{}",
                if clear {
                    "Password cleared (token-only auth)"
                } else {
                    "Password set"
                }
            )
        },
    );
    Ok(())
}

/// Turn strict write scoping on or off for a user or a class.
///
/// Under strict mode a write must satisfy **every** scope the subject has, not
/// any one of them. Local mode only for now: the server has no route for it, and
/// inventing one silently would leave the flag looking set on a remote vault
/// while writes carried on as before — the worst outcome available for a
/// security control.
pub fn set_strict(access: &Access, kind: &str, query: &str, strict: bool) -> CliResult {
    let id = match kind {
        "user" => resolve_user(access, query)?,
        "class" => resolve_class(access, query)?,
        other => return Err(CliError::invalid(format!("unknown subject kind '{other}'"))),
    };
    match access {
        Access::Remote(_) => {
            return Err(CliError::unavailable(
                "Strict write scoping is a local-vault setting for now — run this against \
                 the vault file (no --server).",
            ))
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::users::set_strict_write(&conn, kind, &id, strict)?;
        }
    }
    out::ok(
        "user.strict-write",
        json!({ "subject_kind": kind, "id": id, "strict_write": strict }),
        || {
            if strict {
                println!("{query}: writes must now match EVERY scope, not any one of them.");
            } else {
                println!("{query}: writes match any scope again (the default).");
            }
        },
    );
    Ok(())
}

pub fn user_class(access: &Access, query: &str, class: Option<&str>) -> CliResult {
    let id = resolve_user(access, query)?;
    let class_id = match class {
        Some(c) => Some(resolve_class(access, c)?),
        None => None,
    };
    match access {
        Access::Remote(c) => {
            c.send_json(
                Method::PUT,
                &format!("/api/users/{id}/class"),
                Some(&json!({ "class_id": class_id })),
            )?;
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::assign_user_class(&conn, &id, class_id.as_deref())?;
        }
    }
    out::ok(
        "user.class",
        json!({ "user": query, "class": class }),
        || {
            println!(
                "{}",
                match class {
                    Some(c) => format!("Assigned '{query}' to class '{c}'"),
                    None => format!("Removed '{query}' from its class"),
                }
            )
        },
    );
    Ok(())
}

// ── Tokens ────────────────────────────────────────────────────────────────────

pub fn token_ls(access: &Access, query: &str) -> CliResult {
    let id = resolve_user(access, query)?;
    let rows: Vec<Value> = match access {
        Access::Remote(c) => c
            .get_json(&format!("/api/users/{id}/tokens"))?
            .as_array()
            .cloned()
            .unwrap_or_default(),
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::list_user_tokens(&conn, &id)?
                .into_iter()
                .map(|t| serde_json::to_value(t).unwrap_or(Value::Null))
                .collect()
        }
    };
    if out::is_json() {
        out::ok(
            "user.token.ls",
            json!({ "count": rows.len(), "tokens": rows }),
            || {},
        );
        return Ok(());
    }
    if rows.is_empty() {
        println!("No tokens for '{query}'.");
        return Ok(());
    }
    println!(
        "{:<38} {:<26} {:<22} Expires",
        "Token id", "Description", "Created"
    );
    println!("{}", "-".repeat(100));
    for t in &rows {
        println!(
            "{} {} {} {}",
            cell(t.get("id").and_then(|v| v.as_str()).unwrap_or(""), 38),
            cell(
                t.get("description").and_then(|v| v.as_str()).unwrap_or("—"),
                26
            ),
            cell(
                t.get("created_at").and_then(|v| v.as_str()).unwrap_or(""),
                22
            ),
            t.get("expires_at")
                .and_then(|v| v.as_str())
                .unwrap_or("never"),
        );
    }
    Ok(())
}

pub fn token_new(
    access: &Access,
    query: &str,
    description: Option<&str>,
    expires: Option<&str>,
    out_path: Option<&std::path::Path>,
) -> CliResult {
    // Refuse *before* minting. Checking afterwards left a live credential in the
    // database that nobody could ever read — an orphan token that still
    // authenticates, which is worse than either printing it or not creating it.
    if out_path.is_none() && !crate::out::revealing() {
        return Err(CliError::redacted(
            "A token is a live credential, so it is not printed by default.\n\
             Pass --out <file> to write it to a 0600 file, or --reveal to print it.\n\
             Nothing was created.",
        ));
    }

    let id = resolve_user(access, query)?;
    let (token_id, plaintext) = match access {
        Access::Remote(c) => {
            let body = json!({ "description": description, "expires_at": expires });
            let created = c.send_json(
                Method::POST,
                &format!("/api/users/{id}/tokens"),
                Some(&body),
            )?;
            (
                created
                    .get("token_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                created
                    .get("token")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::create_user_token(&conn, &id, description, expires)
                .map_err(CliError::from)?
        }
    };

    // `--out` writes the token to a 0600 file so a provisioning run can hand it
    // to a machine without it passing through an orchestrator's transcript.
    if let Some(path) = out_path {
        std::fs::write(path, format!("{plaintext}\n"))
            .map_err(|e| CliError::from(format!("Cannot write {}: {e}", path.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)
                .map_err(|e| CliError::from(e.to_string()))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms).map_err(|e| CliError::from(e.to_string()))?;
        }
        crate::out::ok(
            "user.token.new",
            json!({
                "token_id": token_id,
                "path": path.display().to_string(),
                "fingerprint": crate::out::fingerprint(&plaintext),
                "printed": false,
            }),
            || {
                println!("Token written to {} (0600)", path.display());
                println!("Token id: {token_id}");
            },
        );
        return Ok(());
    }

    crate::out::ok(
        "user.token.new",
        json!({ "token_id": token_id, "token": plaintext, "printed": true }),
        || {
            // The token alone on stdout so it can be piped; notes to stderr.
            println!("{plaintext}");
            eprintln!("Token id: {token_id}");
            eprintln!("Store this token now — it will not be shown again.");
        },
    );
    Ok(())
}

pub fn token_revoke(access: &Access, query: &str, token_id: &str, yes: bool) -> CliResult {
    let id = resolve_user(access, query)?;
    if !confirm(&format!("Revoke token {token_id}?"), yes)? {
        println!("Cancelled.");
        return Ok(());
    }
    match access {
        Access::Remote(c) => {
            c.send_json(
                Method::DELETE,
                &format!("/api/users/{id}/tokens/{token_id}"),
                None,
            )?;
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::revoke_user_token(&conn, token_id)?;
        }
    }
    out::ok(
        "user.token.revoke",
        json!({ "token_id": token_id, "revoked": true }),
        || println!("Revoked {token_id}"),
    );
    Ok(())
}

// ── Classes ───────────────────────────────────────────────────────────────────

fn class_rows(access: &Access) -> CliResult<Vec<Value>> {
    match access {
        Access::Remote(c) => Ok(c
            .get_json("/api/classes")?
            .as_array()
            .cloned()
            .unwrap_or_default()),
        Access::Local(_) => {
            let conn = access.conn()?;
            Ok(vault_core::list_user_classes(&conn)?
                .into_iter()
                .map(|c| serde_json::to_value(c).unwrap_or(Value::Null))
                .collect())
        }
    }
}

fn resolve_class(access: &Access, query: &str) -> CliResult<String> {
    let rows = class_rows(access)?;
    if let Some(c) = rows
        .iter()
        .find(|c| c.get("id").and_then(|v| v.as_str()) == Some(query))
    {
        return Ok(c["id"].as_str().unwrap_or("").to_string());
    }
    let hits: Vec<&Value> = rows
        .iter()
        .filter(|c| {
            c.get("name")
                .and_then(|v| v.as_str())
                .is_some_and(|n| n.eq_ignore_ascii_case(query))
        })
        .collect();
    match hits.len() {
        1 => Ok(hits[0]["id"].as_str().unwrap_or("").to_string()),
        0 => Err(CliError::not_found(format!("No class '{query}'"))),
        _ => Err(CliError::ambiguous(format!(
            "'{query}' matches {} classes — use the id",
            hits.len()
        ))),
    }
}

pub fn class_ls(access: &Access, json_out: bool) -> CliResult {
    let rows = class_rows(access)?;
    if json_out || out::is_json() {
        out::ok(
            "class.ls",
            json!({ "count": rows.len(), "classes": rows }),
            || {},
        );
        return Ok(());
    }
    if rows.is_empty() {
        println!("No classes.");
        return Ok(());
    }
    println!(
        "{:<38} {:<20} {:<7} {:<7} {:<7} Description",
        "Id", "Name", "Users", "Classes", "DelProj"
    );
    println!("{}", "-".repeat(110));
    let b = |c: &Value, k: &str| {
        if c.get(k).and_then(|v| v.as_bool()).unwrap_or(false) {
            "yes"
        } else {
            "—"
        }
    };
    for c in &rows {
        println!(
            "{} {} {:<7} {:<7} {:<7} {}",
            cell(c.get("id").and_then(|v| v.as_str()).unwrap_or(""), 38),
            cell(c.get("name").and_then(|v| v.as_str()).unwrap_or(""), 20),
            b(c, "cap_manage_users"),
            b(c, "cap_manage_classes"),
            b(c, "cap_delete_projects"),
            c.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        );
    }
    Ok(())
}

pub struct ClassCaps {
    pub manage_users: bool,
    pub manage_classes: bool,
    pub delete_projects: bool,
}

pub fn class_add(access: &Access, name: &str, description: &str, caps: &ClassCaps) -> CliResult {
    match access {
        Access::Remote(c) => {
            let body = json!({
                "name": name, "description": description,
                "cap_manage_users": caps.manage_users,
                "cap_manage_classes": caps.manage_classes,
                "cap_delete_projects": caps.delete_projects,
            });
            let created = c.send_json(Method::POST, "/api/classes", Some(&body))?;
            let id = created
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            out::ok(
                "class.add",
                json!({ "name": name, "id": id, "created": true }),
                || println!("Created class '{name}' ({id})"),
            );
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            let cls = vault_core::create_user_class(
                &conn,
                name,
                description,
                caps.manage_users,
                caps.manage_classes,
                caps.delete_projects,
            )?;
            out::ok(
                "class.add",
                json!({ "name": cls.name, "id": cls.id, "created": true }),
                || println!("Created class '{}' ({})", cls.name, cls.id),
            );
        }
    }
    Ok(())
}

pub fn class_set(
    access: &Access,
    query: &str,
    name: Option<&str>,
    description: Option<&str>,
    caps: &ClassCaps,
) -> CliResult {
    let id = resolve_class(access, query)?;
    let existing = class_rows(access)?
        .into_iter()
        .find(|c| c.get("id").and_then(|v| v.as_str()) == Some(id.as_str()))
        .ok_or("Class vanished")?;
    let name = name.unwrap_or_else(|| existing.get("name").and_then(|v| v.as_str()).unwrap_or(""));
    let description = description.unwrap_or_else(|| {
        existing
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    });

    match access {
        Access::Remote(c) => {
            let body = json!({
                "name": name, "description": description,
                "cap_manage_users": caps.manage_users,
                "cap_manage_classes": caps.manage_classes,
                "cap_delete_projects": caps.delete_projects,
            });
            c.send_json(Method::PUT, &format!("/api/classes/{id}"), Some(&body))?;
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::update_user_class(
                &conn,
                &id,
                name,
                description,
                caps.manage_users,
                caps.manage_classes,
                caps.delete_projects,
            )?;
        }
    }
    out::ok(
        "class.set",
        json!({
            "id": id, "name": name, "description": description,
            "cap_manage_users": caps.manage_users,
            "cap_manage_classes": caps.manage_classes,
            "cap_delete_projects": caps.delete_projects,
        }),
        || println!("Updated class '{name}'"),
    );
    Ok(())
}

pub fn class_rm(access: &Access, query: &str, yes: bool) -> CliResult {
    let id = resolve_class(access, query)?;
    if !confirm(
        &format!("Delete class '{query}'? Members are unassigned."),
        yes,
    )? {
        println!("Cancelled.");
        return Ok(());
    }
    match access {
        Access::Remote(c) => {
            c.send_json(Method::DELETE, &format!("/api/classes/{id}"), None)?;
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::delete_user_class(&conn, &id)?;
        }
    }
    out::ok(
        "class.rm",
        json!({ "class": query, "id": id, "deleted": true }),
        || println!("Deleted class '{query}'"),
    );
    Ok(())
}

// ── Permission expressions ────────────────────────────────────────────────────

/// Show the read/write expressions for a user or class.
pub fn perm_show(access: &Access, subject_kind: &str, query: &str) -> CliResult {
    let (id, path) = match subject_kind {
        "user" => (resolve_user(access, query)?, "users"),
        _ => (resolve_class(access, query)?, "classes"),
    };
    let exprs: Value = match access {
        Access::Remote(c) => c.get_json(&format!("/api/{path}/{id}/permissions"))?,
        Access::Local(_) => {
            let conn = access.conn()?;
            json!({
                "read":  vault_core::get_permission_expr(&conn, subject_kind, &id, "read")?.unwrap_or_default(),
                "write": vault_core::get_permission_expr(&conn, subject_kind, &id, "write")?.unwrap_or_default(),
            })
        }
    };
    let read = exprs
        .get("read")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let write = exprs
        .get("write")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    // Stored text is not what the evaluator uses once strict write scoping is on:
    // the OR chain is narrowed to an AND chain at evaluation time. Showing only
    // the stored form would leave an operator who has just enabled strict mode
    // looking at an unchanged rule and concluding the flag did nothing — which
    // is the worst way for a security control to behave.
    let (strict, effective_write) = match (access, subject_kind) {
        (Access::Local(_), "user") => {
            let conn = access.conn()?;
            let strict = vault_core::users::strict_write_for(&conn, &id).unwrap_or(false);
            let eff = vault_core::effective_permission_expr(&conn, &id, "write")
                .ok()
                .flatten()
                .map(|e| e.to_string());
            (strict, eff)
        }
        _ => (false, None),
    };

    out::ok(
        "perm.show",
        json!({
            "subject_kind": subject_kind,
            "subject": query,
            "read": read,
            "write": write,
            "strict_write": strict,
            "effective_write": effective_write,
        }),
        || {
            let show = |v: &str| {
                if v.is_empty() {
                    "(none — denies everything)".to_string()
                } else {
                    v.to_string()
                }
            };
            println!("read   {}", show(&read));
            println!("write  {}", show(&write));
            if strict {
                println!("strict write scoping is ON — a write must match every scope:");
                println!(
                    "       {}",
                    effective_write
                        .as_deref()
                        .unwrap_or("(none — denies everything)")
                );
            }
        },
    );
    Ok(())
}

/// Replace the read and/or write expression for a user or class.
///
/// An absent flag leaves that expression alone; `--read ''` clears it. Clearing
/// is a *deny*, not a wildcard: an absent expression under the AND-combining
/// rule would otherwise hand a user with no rules full access.
pub fn perm_set(
    access: &Access,
    subject_kind: &str,
    query: &str,
    read: Option<&str>,
    write: Option<&str>,
) -> CliResult {
    if read.is_none() && write.is_none() {
        return Err("Nothing to set — pass --read and/or --write".into());
    }
    let (id, path) = match subject_kind {
        "user" => (resolve_user(access, query)?, "users"),
        _ => (resolve_class(access, query)?, "classes"),
    };

    // Read the current pair first: the server's PUT replaces both expressions at
    // once, so sending only the changed one would silently wipe the other.
    let current: Value = match access {
        Access::Remote(c) => c.get_json(&format!("/api/{path}/{id}/permissions"))?,
        Access::Local(_) => {
            let conn = access.conn()?;
            json!({
                "read":  vault_core::get_permission_expr(&conn, subject_kind, &id, "read")?.unwrap_or_default(),
                "write": vault_core::get_permission_expr(&conn, subject_kind, &id, "write")?.unwrap_or_default(),
            })
        }
    };
    let next_read =
        read.unwrap_or_else(|| current.get("read").and_then(|v| v.as_str()).unwrap_or(""));
    let next_write =
        write.unwrap_or_else(|| current.get("write").and_then(|v| v.as_str()).unwrap_or(""));

    match access {
        Access::Remote(c) => {
            c.send_json(
                Method::PUT,
                &format!("/api/{path}/{id}/permissions"),
                Some(&json!({ "read": next_read, "write": next_write })),
            )?;
        }
        Access::Local(_) => {
            let conn = access.conn()?;
            // set_permission_expr parses before storing — an unparseable rule
            // denies everything at evaluation time, so it must fail loudly here.
            vault_core::set_permission_expr(&conn, subject_kind, &id, "read", next_read)?;
            vault_core::set_permission_expr(&conn, subject_kind, &id, "write", next_write)?;
        }
    }
    out::ok(
        "perm.set",
        json!({ "subject_kind": subject_kind, "subject": query, "read": next_read, "write": next_write }),
        || println!("Permissions updated for {subject_kind} '{query}'"),
    );
    Ok(())
}

/// Check a permission expression parses, without storing it.
pub fn perm_check(expr: &str) -> CliResult {
    let parsed = vault_core::parse_perm_expr(expr).map_err(CliError::invalid)?;
    out::ok(
        "perm.check",
        json!({ "valid": true, "normalized": parsed.to_string() }),
        || println!("OK: {parsed}"),
    );
    Ok(())
}
