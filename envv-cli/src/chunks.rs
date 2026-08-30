//! Chunk CRUD inside a project, plus project-level config export.

use crate::access::Access;
use crate::data::{find_chunk_index, find_project_index, projects, projects_mut};
use crate::error::{CliError, CliResult};
use crate::exporters;
use crate::fmt::{cell, confirm, emit};
use crate::out;
use crate::refs::Resolver;
use serde_json::json;
use std::path::{Path, PathBuf};

pub const CHUNK_TYPES: [&str; 29] = [
    "wg_interface",
    "wg_peer",
    "docker_service",
    "docker_network",
    "docker_volume",
    "env_file",
    "nginx_server",
    "nginx_upstream",
    "nginx_location",
    "nginx_key",
    "k8s_deployment",
    "k8s_service",
    "k8s_configmap",
    "k8s_secret",
    "k8s_ingress",
    "ssh_host",
    "traefik_router",
    "traefik_service",
    "traefik_middleware",
    "apache_vhost",
    "apache_directory",
    "haproxy_global",
    "haproxy_frontend",
    "haproxy_backend",
    "ansible_vars",
    "ansible_task",
    "pg_connection",
    "pg_role",
    "generic",
];

pub const FIELD_TYPES: [&str; 12] = [
    "var",
    "env_var",
    "secret",
    "list",
    "multiline",
    "port",
    "user_id",
    "subnet",
    "ip",
    "endpoint",
    "volume_mount",
    "cert",
];

pub fn ls(access: &Access, project: &str) -> CliResult {
    let vault = access.load_vault()?;
    let pi = find_project_index(&vault, project)?;
    let p = &projects(&vault)[pi];
    let chunks = p
        .get("chunks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if out::is_json() {
        let rows: Vec<serde_json::Value> = chunks
            .iter()
            .map(|c| {
                json!({
                    "id": c.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                    "name": c.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    "chunk_type": c.get("chunk_type").and_then(|v| v.as_str()).unwrap_or(""),
                    "fields": c.get("fields").and_then(|v| v.as_array()).map_or(0, |a| a.len()),
                    "disabled": c.get("disabled").and_then(|d| d.as_bool()).unwrap_or(false),
                })
            })
            .collect();
        out::ok(
            "project.chunk.ls",
            json!({ "count": rows.len(), "chunks": rows }),
            || {},
        );
        return Ok(());
    }
    if chunks.is_empty() {
        println!(
            "Project '{}' has no chunks.",
            p.get("name").and_then(|v| v.as_str()).unwrap_or("")
        );
        return Ok(());
    }
    println!("{:<30} {:<18} {:>7}  State", "Name", "Type", "Fields");
    println!("{}", "-".repeat(70));
    for c in &chunks {
        let disabled = c.get("disabled").and_then(|d| d.as_bool()).unwrap_or(false);
        println!(
            "{} {} {:>7}  {}",
            cell(c.get("name").and_then(|v| v.as_str()).unwrap_or(""), 30),
            cell(
                c.get("chunk_type").and_then(|v| v.as_str()).unwrap_or(""),
                18
            ),
            c.get("fields")
                .and_then(|v| v.as_array())
                .map_or(0, |a| a.len()),
            if disabled { "disabled" } else { "enabled" }
        );
    }
    Ok(())
}

pub fn show(access: &Access, project: &str, chunk: &str, raw: bool) -> CliResult {
    let vault = access.load_vault()?;
    let pi = find_project_index(&vault, project)?;
    let p = &projects(&vault)[pi];
    let ci = find_chunk_index(p, chunk)?;
    let c = &p.get("chunks").and_then(|v| v.as_array()).unwrap()[ci];
    if raw {
        // A chunk's raw JSON carries its field values, so it goes through the
        // same redaction as everything else.
        let project_view = out::redact_project(p);
        let safe = project_view
            .get("chunks")
            .and_then(|v| v.as_array())
            .and_then(|a| a.get(ci))
            .cloned()
            .unwrap_or_else(|| c.clone());
        out::ok("project.chunk.show", safe.clone(), || {
            println!(
                "{}",
                serde_json::to_string_pretty(&safe).unwrap_or_default()
            )
        });
        return Ok(());
    }
    // Printing a chunk puts its text on stdout, so this resolver redacts unless
    // the caller asked to reveal.
    let r = Resolver::for_output(&vault);
    let text = exporters::chunk_to_string(c, &r);
    out::ok(
        "project.chunk.show",
        json!({ "text": text, "redacted": r.redact }),
        || println!("{text}"),
    );
    Ok(())
}

pub fn add(access: &Access, project: &str, name: &str, ctype: &str) -> CliResult {
    let mut vault = access.load_vault()?;
    let pi = find_project_index(&vault, project)?;
    if projects(&vault)[pi]
        .get("chunks")
        .and_then(|v| v.as_array())
        .is_some_and(|a| {
            a.iter()
                .any(|c| c.get("name").and_then(|n| n.as_str()) == Some(name))
        })
    {
        return Err(CliError::conflict(format!(
            "Chunk '{name}' already exists in this project"
        )));
    }
    let list = projects_mut(&mut vault);
    if !list[pi]
        .get("chunks")
        .map(|c| c.is_array())
        .unwrap_or(false)
    {
        list[pi]["chunks"] = json!([]);
    }
    list[pi]["chunks"].as_array_mut().unwrap().push(json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "name": name,
        "chunk_type": ctype,
        "fields": [],
    }));
    access.save(&vault)?;
    out::ok(
        "project.chunk.add",
        json!({ "name": name, "chunk_type": ctype, "created": true }),
        || println!("Added chunk '{name}' ({ctype})"),
    );
    Ok(())
}

pub fn rm(access: &Access, project: &str, chunk: &str, yes: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let pi = find_project_index(&vault, project)?;
    let ci = find_chunk_index(&projects(&vault)[pi], chunk)?;
    let name = projects(&vault)[pi]["chunks"][ci]
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if !confirm(&format!("Delete chunk '{name}'?"), yes)? {
        println!("Cancelled.");
        return Ok(());
    }
    projects_mut(&mut vault)[pi]["chunks"]
        .as_array_mut()
        .unwrap()
        .remove(ci);
    access.save(&vault)?;
    out::ok(
        "project.chunk.rm",
        json!({ "name": name, "deleted": true }),
        || println!("Deleted chunk '{name}'"),
    );
    Ok(())
}

/// Set (or add) fields on a chunk from `KEY=VALUE` pairs.
///
/// Repeated keys are legal in these configs — nginx takes two `listen` lines —
/// so `--append` adds a field rather than replacing the one that matches.
pub fn set(
    access: &Access,
    project: &str,
    chunk: &str,
    pairs: &[String],
    field_type: &str,
    secret: bool,
    append: bool,
) -> CliResult {
    let mut vault = access.load_vault()?;
    let pi = find_project_index(&vault, project)?;
    let ci = find_chunk_index(&projects(&vault)[pi], chunk)?;
    let list = projects_mut(&mut vault);
    let fields = list[pi]["chunks"][ci]["fields"]
        .as_array_mut()
        .ok_or("Chunk has no fields array")?;

    for pair in pairs {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("Expected key=value, got '{pair}'"))?;
        let mut field = json!({ "key": key, "value": value, "field_type": field_type });
        if secret {
            field["secret"] = json!(true);
        }
        match (
            append,
            fields
                .iter()
                .position(|f| f.get("key").and_then(|k| k.as_str()) == Some(key)),
        ) {
            (false, Some(idx)) => {
                // Preserve the existing field_type unless the caller named one.
                if field_type == "var" {
                    if let Some(prev) = fields[idx].get("field_type").and_then(|t| t.as_str()) {
                        field["field_type"] = json!(prev);
                    }
                }
                fields[idx] = field;
            }
            _ => fields.push(field),
        }
    }
    let n = pairs.len();
    let keys: Vec<&str> = pairs.iter().filter_map(|p| p.split('=').next()).collect();
    access.save(&vault)?;
    out::ok(
        "project.chunk.set",
        json!({ "fields": n, "keys": keys }),
        || println!("Set {n} field(s)"),
    );
    Ok(())
}

pub fn unset(access: &Access, project: &str, chunk: &str, keys: &[String]) -> CliResult {
    let mut vault = access.load_vault()?;
    let pi = find_project_index(&vault, project)?;
    let ci = find_chunk_index(&projects(&vault)[pi], chunk)?;
    let list = projects_mut(&mut vault);
    let fields = list[pi]["chunks"][ci]["fields"]
        .as_array_mut()
        .ok_or("Chunk has no fields array")?;
    let before = fields.len();
    fields.retain(|f| {
        !keys
            .iter()
            .any(|k| f.get("key").and_then(|x| x.as_str()) == Some(k.as_str()))
    });
    let removed = before - fields.len();
    access.save(&vault)?;
    out::ok("project.chunk.unset", json!({ "removed": removed }), || {
        println!("Removed {removed} field(s)")
    });
    Ok(())
}

pub fn toggle(access: &Access, project: &str, chunk: &str, disable: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let pi = find_project_index(&vault, project)?;
    let ci = find_chunk_index(&projects(&vault)[pi], chunk)?;
    let list = projects_mut(&mut vault);
    if disable {
        list[pi]["chunks"][ci]["disabled"] = json!(true);
    } else {
        list[pi]["chunks"][ci]
            .as_object_mut()
            .map(|o| o.remove("disabled"));
    }
    let name = list[pi]["chunks"][ci]
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    access.save(&vault)?;
    out::ok(
        "project.chunk.toggle",
        json!({ "name": name, "disabled": disable }),
        || {
            println!(
                "Chunk '{name}' {}",
                if disable { "disabled" } else { "enabled" }
            )
        },
    );
    Ok(())
}

pub fn rename(access: &Access, project: &str, chunk: &str, new_name: &str) -> CliResult {
    let mut vault = access.load_vault()?;
    let pi = find_project_index(&vault, project)?;
    let ci = find_chunk_index(&projects(&vault)[pi], chunk)?;
    let old = projects(&vault)[pi]["chunks"][ci]
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    projects_mut(&mut vault)[pi]["chunks"][ci]["name"] = json!(new_name);

    // `${chunk:Name/Field}` addresses a chunk by name, so a rename that does not
    // rewrite them leaves every cross-chunk reference dangling.
    let old_prefix = format!("${{chunk:{old}/");
    let mut rewritten = 0usize;
    for p in projects_mut(&mut vault).iter_mut() {
        let Some(chunks) = p.get_mut("chunks").and_then(|c| c.as_array_mut()) else {
            continue;
        };
        for c in chunks.iter_mut() {
            let Some(fields) = c.get_mut("fields").and_then(|f| f.as_array_mut()) else {
                continue;
            };
            for f in fields.iter_mut() {
                let Some(val) = f.get("value").and_then(|v| v.as_str()) else {
                    continue;
                };
                if let Some(rest) = val.strip_prefix(&old_prefix) {
                    f["value"] = json!(format!("${{chunk:{new_name}/{rest}"));
                    rewritten += 1;
                }
            }
        }
    }
    access.save(&vault)?;
    out::ok(
        "project.chunk.rename",
        json!({ "from": old, "to": new_name, "rewritten_refs": rewritten }),
        || {
            println!("Renamed chunk '{old}' → '{new_name}'");
            if rewritten > 0 {
                println!("Rewrote {rewritten} cross-chunk reference(s)");
            }
        },
    );
    Ok(())
}

/// Export a project's config in its native format.
///
/// Only the four stable project types have exporters here. The experimental
/// types stay UI-only rather than existing as a second implementation that can
/// silently drift from the one the app uses.
/// Every value `--format` accepts. Also the `value_parser` for the flag, so an
/// unknown format is a clap usage error (exit 2) at parse time rather than a
/// runtime error after the vault has already been opened.
pub const EXPORT_FORMATS: &[&str] = &[
    "wireguard",
    "compose",
    "nginx",
    "apache",
    "haproxy",
    "ansible",
    "postgres",
    "k8s",
    "ssh",
    "traefik",
    "env",
    "json",
];

/// The format a project of this type exports as when `--format` is omitted.
///
/// Every one of the eleven project types maps to the exporter for its own
/// format. Before Phase 18's graduation only four did, and the other seven fell
/// through to `env` — so the CLI silently wrote the wrong file format for
/// haproxy, kubernetes, traefik, apache, ansible, postgres and ssh_config
/// projects, or refused with an error about env_file chunks that named neither
/// the cause nor the fix.
pub fn default_format_for(ptype: &str) -> &'static str {
    match ptype {
        "wireguard" => "wireguard",
        "docker" => "compose",
        "nginx" => "nginx",
        "apache" => "apache",
        "haproxy" => "haproxy",
        "ansible" => "ansible",
        "postgres" => "postgres",
        "kubernetes" => "k8s",
        "ssh_config" => "ssh",
        "traefik" => "traefik",
        // `generic` holds env_file chunks by definition, so .env is right for it
        // — and it is the right answer for an unknown type from a newer build
        // too, since a .env of the project's env chunks is the one output that
        // cannot be wrong about a format it does not know.
        _ => "env",
    }
}

pub fn export(
    access: &Access,
    project: &str,
    format: Option<&str>,
    out: Option<&Path>,
) -> CliResult {
    let vault = access.load_vault()?;
    let pi = find_project_index(&vault, project)?;
    let p = projects(&vault)[pi].clone();

    // The one rule that makes this safe to hand to an agent: a file gets real
    // values, stdout gets fingerprints. An orchestrator can therefore write a
    // deployable config it is never able to read out of its own tool output.
    let r = if out.is_some() {
        Resolver::materialising(&vault)
    } else {
        Resolver::for_output(&vault)
    };

    let ptype = p
        .get("project_type")
        .and_then(|v| v.as_str())
        .unwrap_or("generic");
    // The default format is now *derived from the project type for every type*,
    // not for three of them with a silent `.env` fallback for the rest.
    //
    // The old fallback meant `envv project export my-lb` on an haproxy project
    // either wrote a file that was not an haproxy config, or failed with
    // "Project 'my-lb' has no env_file chunks" — a diagnosis naming neither the
    // cause nor the fix. `generic` still defaults to `.env`, which is correct:
    // that is the type for a project whose chunks *are* env files.
    let fmt = format.unwrap_or(default_format_for(ptype));

    match fmt {
        "wireguard" => emit(&exporters::export_wireguard(&p, &r), out),
        "nginx" => emit(&exporters::export_nginx(&p, &r), out),
        "apache" => emit(&exporters::export_apache(&p, &r), out),
        "haproxy" => emit(&exporters::export_haproxy(&p, &r), out),
        "ansible" => emit(&exporters::export_ansible(&p, &r), out),
        "postgres" => emit(&exporters::export_postgres(&p, &r), out),
        "k8s" => emit(&exporters::export_k8s(&p, &r), out),
        "ssh" => emit(&exporters::export_ssh_config(&p, &r), out),
        "traefik" => emit(&exporters::export_traefik(&p, &r), out),
        "compose" => {
            let c = exporters::export_docker_compose(&p, &r);
            match out {
                // The compose file and its .env are one deliverable: Compose
                // substitutes ${VAR} from the .env sitting beside it, so writing
                // the YAML without the .env produces a stack with blank secrets.
                Some(path) => {
                    emit(&c.yaml, Some(path))?;
                    if !c.env_file.is_empty() {
                        let env_path: PathBuf =
                            path.parent().unwrap_or_else(|| Path::new(".")).join(".env");
                        emit(&c.env_file, Some(&env_path))?;
                    }
                    Ok(())
                }
                None => {
                    print!("{}", c.yaml);
                    if !c.env_file.is_empty() {
                        println!("\n# ---- .env (write beside the compose file) ----");
                        println!("{}", c.env_file);
                    }
                    Ok(())
                }
            }
        }
        "env" => {
            let e = exporters::export_project_env(&p, &r);
            if !e.had_chunks {
                return Err(CliError::not_found(format!(
                    "Project '{}' has no env_file chunks",
                    p.get("name").and_then(|v| v.as_str()).unwrap_or(project)
                )));
            }
            for u in &e.unresolved {
                eprintln!("# WARN unresolved ref: {u}");
            }
            emit(&e.text, out)?;
            if !e.unresolved.is_empty() {
                eprintln!(
                    "\n{} unresolved ref(s) emitted as literal ${{...}}",
                    e.unresolved.len()
                );
            }
            Ok(())
        }
        "json" => emit(
            &serde_json::to_string_pretty(&out::redact_project(&p)).unwrap_or_default(),
            out,
        ),
        other => Err(CliError::invalid(format!(
            "Unknown format '{other}'. Supported: {}.",
            EXPORT_FORMATS.join(", ")
        ))),
    }
}
