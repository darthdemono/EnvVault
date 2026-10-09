//! `unv node` — Nodes (Phase 34, ADR-0140).
//!
//! Two halves in one command group, because the operator types both:
//!
//! - **Hub side** (`token`, `ls`, `show`, `revoke`, `pull`, `accept`): talk to an
//!   `unv-server --nodes` over the ordinary authenticated connection, so they
//!   refuse against a local vault and name the reason.
//! - **Agent side** (`enroll`, `run`, `check`): run on the managed host, use no
//!   vault and no session, and are CLI-only by nature (the app has no concept of
//!   the machine a node runs on; the capability map records that exemption).

use crate::access::Access;
use crate::error::{CliError, CliResult};
use crate::fmt::{cell, confirm, write_secret_file};
use crate::history_cmd;
use crate::node_agent;
use crate::out;
use base64::Engine;
use reqwest::Method;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

/// `90s`, `15m`, `2h`, `1d` to seconds.
pub fn parse_ttl(s: &str) -> CliResult<i64> {
    let s = s.trim();
    let (n, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = n.parse().map_err(|_| {
        CliError::invalid(format!("'{s}' is not a duration like 90s, 15m, 2h or 1d"))
    })?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => {
            return Err(CliError::invalid(format!(
                "'{s}' is not a duration like 90s, 15m, 2h or 1d"
            )))
        }
    };
    Ok(n * mult)
}

fn hub(a: &Access) -> CliResult<&crate::access::RemoteClient> {
    a.remote().ok_or_else(|| {
        CliError::unavailable(
            "Nodes are managed on a hub. Connect with --server to an `unv-server --nodes`.",
        )
    })
}

fn nodes_list(c: &crate::access::RemoteClient) -> CliResult<Vec<Value>> {
    let v = c.send_json(Method::GET, "/api/nodes", None)?;
    Ok(v["nodes"].as_array().cloned().unwrap_or_default())
}

/// Resolves a name or id to one active node, refusing ambiguity like every
/// other lookup in this CLI.
fn find(c: &crate::access::RemoteClient, query: &str) -> CliResult<Value> {
    let all: Vec<Value> = nodes_list(c)?
        .into_iter()
        .filter(|n| n["revoked_at"].is_null())
        .filter(|n| n["id"] == query || n["name"] == query)
        .collect();
    match all.len() {
        0 => Err(CliError::not_found(format!("No active node '{query}'"))),
        1 => Ok(all[0].clone()),
        _ => Err(CliError::new(
            crate::error::Code::Ambiguous,
            format!("'{query}' matches several nodes"),
        )
        .with_details(
            json!({ "candidates": all.iter().map(|n| n["id"].clone()).collect::<Vec<_>>() }),
        )),
    }
}

pub fn token_new(
    a: &Access,
    name: &str,
    projects: &[String],
    ttl_secs: Option<i64>,
    out_file: Option<&Path>,
) -> CliResult {
    let c = hub(a)?;
    let body = json!({ "name": name, "projects": projects, "ttl_secs": ttl_secs });
    let r = c.send_json(Method::POST, "/api/nodes/tokens", Some(&body))?;
    let token = r["token"].as_str().unwrap_or_default().to_string();
    // An enrollment token is a one-time credential. Phase 14's rule applies:
    // to a terminal it is refused, to a file it is written 0600.
    match out_file {
        Some(p) => {
            write_secret_file(p, &token)?;
            out::ok(
                "node.token.new",
                json!({ "name": name, "expires_at": r["expires_at"], "written_to": p.display().to_string() }),
                || println!("Token for '{name}' written to {} (0600).", p.display()),
            );
        }
        None if out::revealing() => {
            out::ok(
                "node.token.new",
                json!({ "name": name, "expires_at": r["expires_at"], "token": token }),
                || println!("{token}"),
            );
        }
        None => {
            return Err(CliError::new(
                crate::error::Code::Redacted,
                "The enrollment token would be printed. Pass --out FILE, or --reveal to print it.",
            ))
        }
    }
    Ok(())
}

pub fn ls(a: &Access) -> CliResult {
    let c = hub(a)?;
    let nodes = nodes_list(c)?;
    out::ok("node.ls", json!({ "nodes": nodes }), || {
        if nodes.is_empty() {
            println!("No nodes enrolled.");
        }
        for n in &nodes {
            let state = if n["revoked_at"].is_null() {
                "active"
            } else {
                "revoked"
            };
            println!(
                "{} {} {} last seen {}  [{}]",
                cell(n["name"].as_str().unwrap_or(""), 20),
                cell(state, 8),
                cell(n["host"]["hostname"].as_str().unwrap_or("-"), 20),
                n["last_seen"].as_str().unwrap_or("never"),
                n["targets"]
                    .as_array()
                    .map(|t| t
                        .iter()
                        .map(|x| format!(
                            "{}:{}",
                            x["id"].as_str().unwrap_or("?"),
                            x["status"].as_str().unwrap_or("?")
                        ))
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_default()
            );
        }
    });
    Ok(())
}

pub fn show(a: &Access, node: &str) -> CliResult {
    let c = hub(a)?;
    let n = find(c, node)?;
    out::ok("node.show", n.clone(), || {
        println!(
            "{}  ({})",
            n["name"].as_str().unwrap_or(""),
            n["id"].as_str().unwrap_or("")
        );
        println!(
            "  key fingerprint  {}",
            n["fingerprint"].as_str().unwrap_or("")
        );
        println!("  projects         {}", n["projects"]);
        println!(
            "  last seen        {}",
            n["last_seen"].as_str().unwrap_or("never")
        );
        if let Some(h) = n["host"].as_object() {
            println!(
                "  host             {} / {} {} / unv {}",
                h["hostname"].as_str().unwrap_or(""),
                h["os"].as_str().unwrap_or(""),
                h["arch"].as_str().unwrap_or(""),
                h["version"].as_str().unwrap_or("")
            );
        }
        for t in n["targets"].as_array().cloned().unwrap_or_default() {
            println!(
                "  target {:<20} {:<10} {:<5} apply={}  {}{}",
                t["id"].as_str().unwrap_or(""),
                t["status"].as_str().unwrap_or(""),
                t["mode"].as_str().unwrap_or(""),
                t["apply"],
                t["refusal"].as_str().unwrap_or(""),
                t["error"]
                    .as_str()
                    .map(|e| format!(" error: {e}"))
                    .unwrap_or_default()
            );
        }
    });
    Ok(())
}

pub fn revoke(a: &Access, node: &str, yes: bool) -> CliResult {
    let c = hub(a)?;
    let n = find(c, node)?;
    let name = n["name"].as_str().unwrap_or(node).to_string();
    if !confirm(
        &format!("Revoke node '{name}'? It stops receiving config at once; files already written stay where they are."),
        yes,
    )? {
        return Err(CliError::invalid("Cancelled"));
    }
    if out::dry_run() {
        out::ok(
            "node.revoke",
            json!({ "name": name, "dry_run": true }),
            || println!("Would revoke '{name}'."),
        );
        return Ok(());
    }
    c.send_json(
        Method::DELETE,
        &format!("/api/nodes/{}", n["id"].as_str().unwrap_or("")),
        None,
    )?;
    out::ok("node.revoke", json!({ "name": name }), || {
        println!("Revoked '{name}'.")
    });
    Ok(())
}

/// Asks a node for one pull target's file and writes it with `--out` (0600).
/// The file is the node's own, secrets included, so there is no stdout form.
pub fn pull(
    a: &Access,
    node: &str,
    target: &str,
    out_file: Option<&Path>,
    into_chunk: Option<&str>,
    apply: bool,
    timeout_secs: u64,
) -> CliResult {
    let c = hub(a)?;
    let n = find(c, node)?;
    let id = n["id"].as_str().unwrap_or("").to_string();
    c.send_json(
        Method::POST,
        &format!("/api/nodes/{id}/pull"),
        Some(&json!({ "target": target })),
    )?;
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let r = c.send_json(
            Method::GET,
            &format!("/api/nodes/{id}/content/{target}"),
            None,
        )?;
        if let Some(b64) = r["content_b64"].as_str() {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| CliError::from(format!("The hub sent invalid content: {e}")))?;
            let text = String::from_utf8_lossy(&bytes).to_string();
            if let Some(chunk) = into_chunk {
                let t = n["targets"]
                    .as_array()
                    .and_then(|ts| ts.iter().find(|t| t["id"] == target))
                    .cloned()
                    .unwrap_or(Value::Null);
                return import_into_chunk(
                    a,
                    t["project"].as_str().unwrap_or(""),
                    t["exporter"].as_str().unwrap_or(""),
                    chunk,
                    &text,
                    apply,
                );
            }
            let out_file = out_file.ok_or_else(|| CliError::invalid("Give --out FILE"))?;
            // So the materialisation log can say which vault secrets this file held.
            let _ = a.load_vault();
            write_secret_file(out_file, &text)?;
            out::ok(
                "node.pull",
                json!({ "target": target, "sha256": r["sha256"], "bytes": bytes.len(), "written_to": out_file.display().to_string() }),
                || {
                    println!(
                        "{} bytes from '{target}' written to {} (0600).",
                        bytes.len(),
                        out_file.display()
                    )
                },
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(CliError::unavailable(format!(
                "The node did not upload '{target}' within {timeout_secs}s. It picks up requests on its next beat."
            )));
        }
        std::thread::sleep(Duration::from_millis(700));
    }
}

/// What reading a `.env` back into an `env_file` chunk would change. Names only:
/// this is printed.
#[derive(Debug, Default, PartialEq)]
pub struct EnvImportPlan {
    /// The chunk's fields after the import.
    pub fields: Vec<Value>,
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub removed: Vec<String>,
    /// Fields that hold a `${reference}` and were left alone: overwriting one
    /// would replace a pointer with the secret it points at.
    pub kept_references: Vec<String>,
}

pub fn plan_env_import(existing: &[Value], vars: &[crate::envfile::EnvVar]) -> EnvImportPlan {
    let mut plan = EnvImportPlan::default();
    let mut seen = std::collections::HashSet::new();
    for v in vars {
        if !seen.insert(v.name.clone()) {
            continue; // the last occurrence's value is used below, as dotenv loaders do
        }
        let last = vars
            .iter()
            .rev()
            .find(|x| x.name == v.name)
            .map_or(v.value.as_str(), |x| x.value.as_str());
        match existing.iter().find(|f| f["key"] == v.name.as_str()) {
            Some(f) if f["value"].as_str().is_some_and(|x| x.contains("${")) => {
                plan.kept_references.push(v.name.clone());
                plan.fields.push(f.clone());
            }
            Some(f) => {
                let mut f = f.clone();
                if f["value"].as_str() != Some(last) {
                    plan.changed.push(v.name.clone());
                    f["value"] = json!(last);
                }
                plan.fields.push(f);
            }
            None => {
                plan.added.push(v.name.clone());
                plan.fields
                    .push(json!({ "key": v.name, "value": last, "field_type": "var" }));
            }
        }
    }
    for f in existing {
        let key = f["key"].as_str().unwrap_or("");
        if !seen.contains(key) {
            plan.removed.push(key.to_string());
        }
    }
    plan
}

/// Reads a pulled `.env`-style file into an `env_file` chunk. The file passes
/// through memory only; nothing is written unless `apply`.
fn import_into_chunk(
    a: &Access,
    project: &str,
    exporter: &str,
    chunk: &str,
    text: &str,
    apply: bool,
) -> CliResult {
    if !matches!(exporter, "env" | "compose-env") {
        return Err(CliError::invalid(format!(
            "A '{exporter}' file cannot be read back into a chunk from the CLI: only .env-style \
             targets can. Use --out and import it in the app."
        )));
    }
    let mut vault = a.load_vault()?;
    let pi = crate::data::find_project_index(&vault, project)?;
    let project_v = crate::data::projects(&vault)[pi].clone();
    let ci = crate::data::find_chunk_index(&project_v, chunk)?;
    let existing = project_v["chunks"][ci].clone();
    if existing["chunk_type"] != "env_file" {
        return Err(CliError::invalid(format!(
            "Chunk '{chunk}' is a {}, not an env_file chunk",
            existing["chunk_type"].as_str().unwrap_or("?")
        )));
    }
    let vars = crate::envfile::parse_env_file(text);
    let old: Vec<Value> = existing["fields"].as_array().cloned().unwrap_or_default();
    let plan = plan_env_import(&old, &vars);
    let summary = json!({
        "project": project, "chunk": chunk, "applied": apply,
        "added": plan.added, "changed": plan.changed, "removed": plan.removed,
        "kept_references": plan.kept_references,
    });
    if apply {
        crate::data::projects_mut(&mut vault)[pi]["chunks"][ci]["fields"] = json!(plan.fields);
        a.save(&vault)?;
    }
    out::ok("node.pull.into-chunk", summary.clone(), || {
        println!(
            "{}{} added, {} changed, {} removed, {} kept as references (names only; values are not shown).",
            if apply { "" } else { "Preview: " },
            plan.added.len(), plan.changed.len(), plan.removed.len(), plan.kept_references.len()
        );
        for (tag, names) in [
            ("+", &plan.added),
            ("~", &plan.changed),
            ("-", &plan.removed),
            ("=", &plan.kept_references),
        ] {
            for n in names {
                println!("  {tag} {n}");
            }
        }
        if !apply {
            println!("\nNothing was written. Re-run with --apply.");
        }
    });
    Ok(())
}

pub fn accept(a: &Access, node: &str, target: &str) -> CliResult {
    let c = hub(a)?;
    let n = find(c, node)?;
    let id = n["id"].as_str().unwrap_or("");
    let r = c.send_json(
        Method::POST,
        &format!("/api/nodes/{id}/accept"),
        Some(&json!({ "target": target })),
    )?;
    out::ok("node.accept", r.clone(), || {
        println!(
            "Accepted {} for '{target}'.",
            r["sha256"].as_str().unwrap_or("")
        )
    });
    Ok(())
}

// ── Approval (Phase 37) ───────────────────────────────────────────────────────

pub fn policy(a: &Access, node: &str, approval: &str) -> CliResult {
    let c = hub(a)?;
    let n = find(c, node)?;
    let id = n["id"].as_str().unwrap_or("");
    let r = c.send_json(
        Method::POST,
        &format!("/api/nodes/{id}/policy"),
        Some(&json!({ "approval": approval })),
    )?;
    out::ok("node.policy", r.clone(), || {
        println!(
            "'{}': {}.",
            r["name"].as_str().unwrap_or(node),
            if approval == "device" {
                "every push is held until you sign an approval on your own device"
            } else if approval == "required" {
                "every push is held until you approve those exact bytes"
            } else {
                "pushes go out as soon as the node's own config allows"
            }
        )
    });
    Ok(())
}

fn approver_dir() -> CliResult<std::path::PathBuf> {
    vault_core::nodes::default_approver_dir()
        .ok_or_else(|| CliError::unavailable("This machine has no per-user data directory"))
}

/// `unv node approver show`.
pub fn approver_show() -> CliResult {
    let seed = vault_core::nodes::approver_seed(&approver_dir()?).map_err(CliError::from)?;
    let public = vault_core::nodes::hub_public(&seed).map_err(CliError::from)?;
    let fp = vault_core::nodes::key_fingerprint(&public).map_err(CliError::from)?;
    out::ok(
        "node.approver",
        json!({ "public_key": public, "fingerprint": fp }),
        || {
            println!("Approver public key: {public}");
            println!("Fingerprint:         {fp}");
            println!("\nPut the public key in a node's config as `approver = \"{public}\"`,");
            println!("register it with `unv node approver register --label NAME`, then set a");
            println!("node to `unv node policy NODE --approval device`.");
        },
    );
    Ok(())
}

/// `unv node approver register`.
pub fn approver_register(a: &Access, label: &str) -> CliResult {
    let c = hub(a)?;
    let seed = vault_core::nodes::approver_seed(&approver_dir()?).map_err(CliError::from)?;
    let public = vault_core::nodes::hub_public(&seed).map_err(CliError::from)?;
    let r = c.send_json(
        Method::POST,
        "/api/node-approvers",
        Some(&json!({ "pubkey": public, "label": label })),
    )?;
    out::ok("node.approver.register", r.clone(), || {
        println!(
            "Registered '{}' ({}).",
            r["label"].as_str().unwrap_or(label),
            r["fingerprint"].as_str().unwrap_or("")
        )
    });
    Ok(())
}

/// `unv node approver ls`.
pub fn approver_ls(a: &Access) -> CliResult {
    let c = hub(a)?;
    let r = c.send_json(Method::GET, "/api/node-approvers", None)?;
    let rows = r["approvers"].as_array().cloned().unwrap_or_default();
    out::ok("node.approver.ls", json!({ "approvers": rows }), || {
        if rows.is_empty() {
            println!("No approver devices are registered.");
        }
        for d in &rows {
            println!(
                "{}  {}  {}",
                cell(d["fingerprint"].as_str().unwrap_or(""), 16),
                cell(d["label"].as_str().unwrap_or(""), 24),
                d["added"].as_str().unwrap_or("")
            );
        }
    });
    Ok(())
}

/// `unv node approver rm`.
pub fn approver_rm(a: &Access, fingerprint: &str, yes: bool) -> CliResult {
    let c = hub(a)?;
    if !confirm("Stop accepting this device as your approval?", yes)? {
        return Err(CliError::invalid("Not removed"));
    }
    c.send_json(
        Method::DELETE,
        &format!("/api/node-approvers/{fingerprint}"),
        None,
    )?;
    out::ok(
        "node.approver.rm",
        json!({ "removed": fingerprint }),
        || println!("Removed."),
    );
    Ok(())
}

/// Every approval request on the hub, newest first, with its node name.
fn all_approvals(c: &crate::access::RemoteClient) -> CliResult<Vec<(String, Value)>> {
    let mut v = Vec::new();
    for n in nodes_list(c)? {
        let name = n["name"].as_str().unwrap_or("").to_string();
        for a in n["approvals"].as_array().cloned().unwrap_or_default() {
            v.push((name.clone(), a));
        }
    }
    v.sort_by(|x, y| {
        y.1["requested_at"]
            .as_str()
            .cmp(&x.1["requested_at"].as_str())
    });
    Ok(v)
}

fn find_approval(c: &crate::access::RemoteClient, id: &str) -> CliResult<(String, Value)> {
    pick_approval(all_approvals(c)?, id)
}

/// One request by full id or by a prefix of at least 8 characters, refusing a
/// prefix that fits several rather than choosing one.
fn pick_approval(rows: Vec<(String, Value)>, id: &str) -> CliResult<(String, Value)> {
    let hits: Vec<(String, Value)> = rows
        .into_iter()
        .filter(|(_, a)| {
            a["id"]
                .as_str()
                .is_some_and(|x| x == id || (id.len() >= 8 && x.starts_with(id)))
        })
        .collect();
    match hits.len() {
        0 => Err(CliError::not_found(format!("No approval request '{id}'"))),
        1 => Ok(hits.into_iter().next().expect("one")),
        _ => Err(CliError::new(
            crate::error::Code::Ambiguous,
            format!("'{id}' matches several requests"),
        )),
    }
}

/// What changes if this is approved: the proposed file against the one the node
/// has, as a diff with secrets as fingerprints (or real with --reveal).
fn approval_diff(a: &Access, ap: &Value) -> CliResult<String> {
    let to = ap["to_seq"].as_i64();
    let from = ap["from_seq"].as_i64();
    match (from, to) {
        (Some(f), Some(t)) => {
            let d = history_cmd::invoke(
                a,
                "diff",
                json!({ "from": f, "to": t, "reveal": out::revealing() }),
            )?;
            let text = d["diff"].as_str().unwrap_or("").to_string();
            Ok(if text.is_empty() {
                "(the two render identically)\n".into()
            } else {
                text
            })
        }
        (None, Some(t)) => {
            let d =
                history_cmd::invoke(a, "show", json!({ "seq": t, "reveal": out::revealing() }))?;
            let body = d["text"].as_str().unwrap_or("");
            Ok(format!(
                "(the node's current file is not in the history: this is the whole proposed file)\n{}",
                body.lines().map(|l| format!("+{l}\n")).collect::<String>()
            ))
        }
        _ => Ok("(the proposal is not in the history; the config history may be off)\n".into()),
    }
}

pub fn approvals(a: &Access, node: Option<&str>, all: bool) -> CliResult {
    let c = hub(a)?;
    let rows: Vec<(String, Value)> = all_approvals(c)?
        .into_iter()
        .filter(|(n, _)| node.is_none_or(|q| q == n))
        .filter(|(_, ap)| all || ap["status"] == "pending")
        .collect();
    out::ok(
        "node.approvals",
        json!({ "approvals": rows.iter().map(|(n, ap)| { let mut v = ap.clone(); v["node"] = json!(n); v }).collect::<Vec<_>>() }),
        || {
            if rows.is_empty() {
                println!("Nothing is waiting for approval.");
            }
            for (n, ap) in &rows {
                println!(
                    "{} {} {} {} {} sha {}",
                    cell(
                        &ap["id"].as_str().unwrap_or("")
                            [..8.min(ap["id"].as_str().unwrap_or("").len())],
                        8
                    ),
                    cell(n, 16),
                    cell(ap["target"].as_str().unwrap_or(""), 16),
                    cell(ap["status"].as_str().unwrap_or(""), 9),
                    cell(ap["requested_at"].as_str().unwrap_or(""), 20),
                    &ap["sha256"].as_str().unwrap_or("")
                        [..12.min(ap["sha256"].as_str().unwrap_or("").len())]
                );
            }
        },
    );
    Ok(())
}

pub fn decide(a: &Access, id: &str, approve: bool, yes: bool) -> CliResult {
    let c = hub(a)?;
    let (node, ap) = find_approval(c, id)?;
    let verb = if approve { "approve" } else { "reject" };
    if ap["status"] != "pending" {
        return Err(CliError::conflict(format!(
            "That request is already {}",
            ap["status"].as_str().unwrap_or("decided")
        )));
    }
    // The human sees exactly what they are saying yes to, hash included, before
    // the question is asked; --yes is for someone who has already looked.
    if approve && !yes {
        eprintln!(
            "Node '{node}', target '{}', proposed file sha256 {}\n",
            ap["target"].as_str().unwrap_or(""),
            ap["sha256"].as_str().unwrap_or("")
        );
        eprint!("{}", approval_diff(a, &ap)?);
        eprintln!();
    }
    if approve
        && !confirm(
            &format!("Approve exactly these bytes for '{node}'? The approval lapses in an hour."),
            yes,
        )?
    {
        return Err(CliError::invalid("Not approved"));
    }
    if out::dry_run() {
        out::ok("node.decide", json!({ "dry_run": true }), || {
            println!("Would {verb} the request.")
        });
        return Ok(());
    }
    let aid = ap["id"].as_str().unwrap_or("");
    // A node set to `device` is approved by a signature made here, with a key that
    // never leaves this machine; the hub only checks it and passes it on.
    let device_node = approve
        && nodes_list(c)?
            .iter()
            .any(|n| n["id"] == ap["node_id"] && n["approval"] == "device");
    let body = if device_node {
        let seed = vault_core::nodes::approver_seed(&approver_dir()?).map_err(CliError::from)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let signed = vault_core::nodes::sign_device_approval(
            &seed,
            ap["node_id"].as_str().unwrap_or(""),
            ap["target"].as_str().unwrap_or(""),
            ap["sha256"].as_str().unwrap_or(""),
            aid,
            now,
            &vault_core::iso_now(),
        )
        .map_err(CliError::from)?;
        Some(json!({ "signed": signed }))
    } else {
        None
    };
    let r = c.send_json(
        Method::POST,
        &format!("/api/node-approvals/{aid}/{verb}"),
        body.as_ref(),
    )?;
    out::ok("node.decide", r.clone(), || {
        println!(
            "{} {} for '{node}'.",
            if approve { "Approved" } else { "Rejected" },
            &r["sha256"].as_str().unwrap_or("")[..12.min(r["sha256"].as_str().unwrap_or("").len())]
        )
    });
    Ok(())
}

// ── Agent side ────────────────────────────────────────────────────────────────

pub fn enroll(
    dir: &Path,
    hub_url: &str,
    token: &str,
    fingerprint: Option<&str>,
    tofu: bool,
    force: bool,
    listen: Option<(&str, &str)>,
) -> CliResult {
    let mut fp = fingerprint.map(String::from);
    if fp.is_none() && tofu && hub_url.starts_with("https://") {
        let seen = crate::tls::probe(hub_url)?;
        eprintln!("The hub presented a certificate with SHA-256 {seen}");
        eprintln!("Compare it with what `unv-server --tls` printed on the hub.");
        if !confirm("Pin this certificate?", false)? {
            return Err(CliError::invalid("Not pinned; nothing was enrolled."));
        }
        fp = Some(seen);
    }
    let st = node_agent::enroll(dir, hub_url, token, fp.as_deref(), force, listen)?;
    out::ok(
        "node.enroll",
        json!({ "node_id": st.node_id, "name": st.name, "hub": st.hub_url, "state_file": node_agent::state_path(dir).display().to_string() }),
        || {
            println!("Enrolled as '{}' ({}).", st.name, st.node_id);
            println!(
                "Identity saved to {} (0600).",
                node_agent::state_path(dir).display()
            );
            if let Some((bind, advertise)) = listen {
                println!("Listening node: binds {bind}, the hub dials {advertise}.");
                println!(
                    "Its TLS certificate is in {} and was pinned by the hub.",
                    dir.join(node_agent::TLS_CERT_FILE).display()
                );
            }
            println!("Next: write a node config and start `unv node run --config FILE`.");
        },
    );
    Ok(())
}

pub fn check(config: &Path) -> CliResult {
    let text = std::fs::read_to_string(config)
        .map_err(|e| CliError::not_found(format!("{}: {e}", config.display())))?;
    let cfg = vault_core::nodes::NodeConfig::parse(&text).map_err(CliError::invalid)?;
    let rows: Vec<Value> = cfg
        .targets
        .iter()
        .map(|t| {
            let sha = vault_core::nodes_apply::hash_file(&t.path).ok().flatten();
            json!({
                "id": t.id, "path": t.path.display().to_string(), "project": t.project,
                "exporter": t.exporter, "mode": t.mode, "apply": t.apply,
                "validate": t.validate, "reload": t.reload,
                "present": sha.is_some(),
                "sha256": sha,
            })
        })
        .collect();
    out::ok("node.check", json!({ "targets": rows }), || {
        println!("{} target(s), config is valid.", rows.len());
        for t in &rows {
            println!(
                "  {:<20} {:<4} apply={:<5} {}",
                t["id"].as_str().unwrap_or(""),
                t["mode"].as_str().unwrap_or(""),
                t["apply"],
                t["path"].as_str().unwrap_or("")
            );
            if t["apply"] == true && t["validate"].is_null() {
                println!("    note: apply is on and no validate command is set");
            }
        }
    });
    Ok(())
}

pub fn run(dir: &Path, config: &Path, once: bool) -> CliResult {
    let mut agent = node_agent::Agent::new(dir, config)?;
    let name = agent.state().name.clone();
    if agent.state().listen.is_some() {
        if once {
            return Err(CliError::invalid(
                "--once makes no sense for a listening node: it answers when the hub dials it",
            ));
        }
        let stop = std::sync::atomic::AtomicBool::new(false);
        return crate::node_listen::serve(&mut agent, &stop);
    }
    if once {
        let reply = agent.beat_once(0)?;
        out::ok(
            "node.run",
            json!({
                "name": name, "actions": reply.actions.len(),
                "hub_locked": reply.hub_locked, "held_for_approval": reply.pending.len(),
            }),
            || {
                println!(
                    "Beat sent; {} action(s) handled. Hub locked: {}.",
                    reply.actions.len(),
                    reply.hub_locked
                );
                for p in &reply.pending {
                    println!("  held for approval: {} ({})", p.target, p.status);
                }
            },
        );
        return Ok(());
    }
    eprintln!(
        "unv node '{name}' running against {}; Ctrl+C to stop.",
        agent.state().hub_url
    );
    let stop = std::sync::atomic::AtomicBool::new(false);
    agent.run(&stop)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<(String, Value)> {
        vec![
            (
                "a".into(),
                json!({"id": "11111111-aaaa", "status": "pending"}),
            ),
            (
                "b".into(),
                json!({"id": "11111111-bbbb", "status": "pending"}),
            ),
            (
                "c".into(),
                json!({"id": "22222222-cccc", "status": "approved"}),
            ),
        ]
    }

    #[test]
    fn a_request_is_found_by_full_id_or_a_long_enough_prefix_and_never_guessed() {
        assert_eq!(pick_approval(rows(), "22222222-cccc").unwrap().0, "c");
        assert_eq!(pick_approval(rows(), "22222222").unwrap().0, "c");
        assert_eq!(pick_approval(rows(), "11111111-a").unwrap().0, "a");
        // A prefix that fits two is refused, not resolved to the first.
        assert_eq!(
            pick_approval(rows(), "11111111").unwrap_err().code,
            crate::error::Code::Ambiguous
        );
        // Under 8 characters is not a prefix, it is a guess.
        assert_eq!(
            pick_approval(rows(), "1111").unwrap_err().code,
            crate::error::Code::NotFound
        );
        assert_eq!(
            pick_approval(rows(), "nope").unwrap_err().code,
            crate::error::Code::NotFound
        );
    }

    #[test]
    fn durations_parse_and_nonsense_is_refused() {
        assert_eq!(parse_ttl("90s").unwrap(), 90);
        assert_eq!(parse_ttl("15m").unwrap(), 900);
        assert_eq!(parse_ttl("2h").unwrap(), 7200);
        assert_eq!(parse_ttl("1d").unwrap(), 86_400);
        assert!(parse_ttl("15").is_err());
        assert!(parse_ttl("m").is_err());
        assert!(parse_ttl("").is_err());
    }

    #[test]
    fn reading_a_env_file_back_adds_changes_removes_and_never_flattens_a_reference() {
        use crate::envfile::EnvVar;
        let var = |k: &str, v: &str| EnvVar {
            name: k.into(),
            value: v.into(),
        };
        let existing = vec![
            json!({"key": "KEEP", "value": "same", "field_type": "var", "description": "d"}),
            json!({"key": "EDIT", "value": "old", "field_type": "secret", "secret": true}),
            json!({"key": "GONE", "value": "x", "field_type": "var"}),
            json!({"key": "TOKEN", "value": "${Stripe/key}", "field_type": "var"}),
        ];
        let plan = plan_env_import(
            &existing,
            &[
                var("KEEP", "same"),
                var("EDIT", "new"),
                var("NEW", "n"),
                var("TOKEN", "sk_live_the_literal"),
                var("EDIT", "newer"),
            ],
        );
        assert_eq!(plan.added, ["NEW"]);
        assert_eq!(plan.changed, ["EDIT"]);
        assert_eq!(plan.removed, ["GONE"]);
        assert_eq!(plan.kept_references, ["TOKEN"]);
        let field = |k: &str| plan.fields.iter().find(|f| f["key"] == k).unwrap().clone();
        assert_eq!(field("EDIT")["value"], "newer", "the last occurrence wins");
        assert_eq!(
            field("EDIT")["secret"],
            true,
            "a field's flags survive a value change"
        );
        assert_eq!(field("KEEP")["description"], "d");
        assert_eq!(
            field("TOKEN")["value"],
            "${Stripe/key}",
            "a reference is not replaced by its secret"
        );
        assert!(
            !format!("{:?}", plan.added).contains("sk_live")
                && !format!("{:?}", plan.changed).contains("sk_live")
        );
        assert!(plan.fields.iter().all(|f| f["key"] != "GONE"));
    }
}
