//! `unv history` — the config time machine (Phase 35, ADR-0141).
//!
//! Local vault: calls the shared dispatcher directly. Remote: the same
//! operation over `POST /api/history`, so the two cannot differ.
//!
//! The Phase 14 rule holds: stdout shows the fingerprinted text. The real text,
//! secrets included, comes only with `--reveal` or into a file with `--out`.

use crate::access::Access;
use crate::error::{CliError, CliResult};
use crate::fmt::{cell, confirm, write_secret_file};
use crate::{history, out};
use reqwest::Method;
use serde_json::{json, Value};
use std::path::Path;

pub(crate) fn invoke(a: &Access, op: &str, args: Value) -> CliResult<Value> {
    match a.local_conn()? {
        Some(conn) => {
            let actor = vault_core::ensure_owner_user(&conn).ok();
            history::call(&conn, op, &args, actor.as_deref()).map_err(CliError::invalid)
        }
        None => {
            let c = a.remote().expect("not local, so remote");
            c.send_json(
                Method::POST,
                "/api/history",
                Some(&json!({ "op": op, "args": args })),
            )
        }
    }
}

pub fn ls(
    a: &Access,
    project: Option<&str>,
    exporter: Option<&str>,
    since: Option<&str>,
    limit: i64,
) -> CliResult {
    let v = invoke(
        a,
        "list",
        json!({ "project": project, "exporter": exporter, "since": since, "limit": limit }),
    )?;
    let rows = v["snapshots"].as_array().cloned().unwrap_or_default();
    out::ok("history.ls", v.clone(), || {
        if rows.is_empty() {
            println!("No snapshots yet. They are recorded when a save changes a project's rendered config.");
        }
        for r in &rows {
            println!(
                "#{:<5} {} {} {} {:>7}B {} {}",
                r["seq"],
                cell(r["at"].as_str().unwrap_or(""), 20),
                cell(r["project_name"].as_str().unwrap_or(""), 18),
                cell(r["exporter"].as_str().unwrap_or(""), 11),
                r["bytes"],
                cell(
                    &r["sha256"].as_str().unwrap_or("")
                        [..8.min(r["sha256"].as_str().unwrap_or("").len())],
                    8
                ),
                r["cause"].as_str().unwrap_or("")
            );
        }
    });
    Ok(())
}

pub fn show(a: &Access, seq: i64, out_file: Option<&Path>) -> CliResult {
    let reveal = out::revealing() || out_file.is_some();
    let v = invoke(a, "show", json!({ "seq": seq, "reveal": reveal }))?;
    let text = v["text"].as_str().unwrap_or("").to_string();
    match out_file {
        Some(p) => {
            // The real text is about to be written to this machine: remember the
            // vault so the materialisation log can say which secrets it holds.
            let _ = a.load_vault();
            write_secret_file(p, &text)?;
            out::ok(
                "history.show",
                json!({ "meta": v["meta"], "written_to": p.display().to_string(), "bytes": text.len() }),
                || println!("Snapshot #{seq} written to {} (0600).", p.display()),
            );
        }
        None => {
            out::ok("history.show", v.clone(), || {
                print!("{text}");
                if !text.ends_with('\n') {
                    println!();
                }
                if !reveal {
                    eprintln!("(secrets shown as fingerprints; --reveal for the real values, or --out FILE)");
                }
            })
        }
    }
    Ok(())
}

pub fn diff(
    a: &Access,
    project: Option<&str>,
    exporter: Option<&str>,
    from: Option<i64>,
    to: Option<i64>,
    out_file: Option<&Path>,
) -> CliResult {
    let reveal = out::revealing() || out_file.is_some();
    let v = invoke(
        a,
        "diff",
        json!({ "project": project, "exporter": exporter, "from": from, "to": to, "reveal": reveal }),
    )?;
    let text = v["diff"].as_str().unwrap_or("").to_string();
    if let Some(p) = out_file {
        let _ = a.load_vault();
        write_secret_file(p, &text)?;
        out::ok(
            "history.diff",
            json!({ "from": v["from"], "to": v["to"], "added": v["added"], "removed": v["removed"], "written_to": p.display().to_string() }),
            || {
                println!(
                    "Diff #{} to #{} written to {} (0600).",
                    v["from"],
                    v["to"],
                    p.display()
                )
            },
        );
        return Ok(());
    }
    out::ok("history.diff", v.clone(), || {
        if text.is_empty() {
            println!("#{} and #{} render identically.", v["from"], v["to"]);
        } else {
            print!("{text}");
        }
    });
    Ok(())
}

/// `unv history diff-file`: a snapshot against a file on this machine (a node's
/// live config, fetched with `unv node pull`).
pub fn diff_file(
    a: &Access,
    project: Option<&str>,
    exporter: Option<&str>,
    seq: Option<i64>,
    file: &Path,
) -> CliResult {
    let text = std::fs::read_to_string(file)
        .map_err(|e| CliError::not_found(format!("Cannot read {}: {e}", file.display())))?;
    let v = invoke(
        a,
        "diff_text",
        json!({ "project": project, "exporter": exporter, "seq": seq, "text": text, "reveal": out::revealing() }),
    )?;
    out::ok("history.diff-file", v.clone(), || {
        if v["identical"] == true {
            println!("#{} and the file are identical.", v["seq"]);
        } else {
            if v["revealed"] != true {
                println!("(values hidden; --reveal shows the lines)");
            }
            print!("{}", v["diff"].as_str().unwrap_or(""));
        }
    });
    Ok(())
}

pub fn snapshot(a: &Access, project: Option<&str>) -> CliResult {
    if out::dry_run() {
        out::ok("history.snapshot", json!({ "dry_run": true }), || {
            println!("Would snapshot every changed config.")
        });
        return Ok(());
    }
    let v = invoke(a, "snapshot", json!({ "project": project }))?;
    out::ok("history.snapshot", v.clone(), || {
        println!(
            "{} recorded, {} unchanged, {} with nothing to render.",
            v["recorded"], v["unchanged"], v["skipped"]
        )
    });
    Ok(())
}

pub fn prune(a: &Access, keep: Option<i64>, days: Option<i64>, yes: bool) -> CliResult {
    let dry = out::dry_run();
    let preview = invoke(
        a,
        "prune",
        json!({ "keep": keep, "days": days, "dry_run": true }),
    )?;
    let n = preview["would_delete"].as_i64().unwrap_or(0);
    if dry || n == 0 {
        out::ok("history.prune", preview.clone(), || {
            println!(
                "{n} snapshot(s) would be deleted ({} bytes).",
                preview["bytes_freed"]
            )
        });
        return Ok(());
    }
    if !confirm(
        &format!(
            "Delete {n} old snapshot(s)? Their secrets are gone for good, and so is the ability to show what was deployed then."
        ),
        yes,
    )? {
        return Err(CliError::invalid("Cancelled"));
    }
    let v = invoke(
        a,
        "prune",
        json!({ "keep": keep, "days": days, "dry_run": false }),
    )?;
    out::ok("history.prune", v.clone(), || {
        println!(
            "Deleted {} snapshot(s); a checkpoint keeps the rest verifiable.",
            v["deleted"]
        )
    });
    Ok(())
}

pub fn verify(a: &Access) -> CliResult {
    let v = invoke(a, "verify", json!({}))?;
    let problems = v["problems"].as_array().cloned().unwrap_or_default();
    out::ok("history.verify", v.clone(), || {
        println!(
            "{} snapshot(s) in {} stream(s), {} checkpoint(s): {}",
            v["snapshots"],
            v["streams"],
            v["checkpoints"],
            if problems.is_empty() {
                "intact".to_string()
            } else {
                format!("{} problem(s)", problems.len())
            }
        );
        for p in &problems {
            println!("  {}", p.as_str().unwrap_or(""));
        }
    });
    if problems.is_empty() {
        Ok(())
    } else {
        Err(CliError::invalid(format!(
            "{} history problem(s)",
            problems.len()
        )))
    }
}

pub fn policy(
    a: &Access,
    enabled: Option<bool>,
    keep: Option<i64>,
    days: Option<i64>,
) -> CliResult {
    let v = invoke(
        a,
        "policy",
        json!({ "enabled": enabled, "keep": keep, "days": days }),
    )?;
    out::ok("history.policy", v.clone(), || {
        println!(
            "history {}; keep the newest {} per config and everything from the last {} days.",
            if v["enabled"] == true { "on" } else { "off" },
            v["keep"],
            v["days"]
        )
    });
    Ok(())
}

pub fn stats(a: &Access) -> CliResult {
    let v = invoke(a, "stats", json!({}))?;
    out::ok("history.stats", v.clone(), || {
        println!(
            "{} snapshot(s), {} config(s), {} bytes, oldest {}",
            v["snapshots"],
            v["streams"],
            v["bytes"],
            v["oldest"].as_str().unwrap_or("-")
        )
    });
    Ok(())
}

pub fn which(a: &Access, sha: &str) -> CliResult {
    let v = invoke(a, "where", json!({ "sha256": sha }))?;
    let rows = v["snapshots"].as_array().cloned().unwrap_or_default();
    out::ok("history.where", v.clone(), || {
        if rows.is_empty() {
            println!("No snapshot has that hash.");
        }
        for r in &rows {
            println!(
                "#{} {} {} {} ({})",
                r["seq"],
                r["at"].as_str().unwrap_or(""),
                r["project_name"].as_str().unwrap_or(""),
                r["exporter"].as_str().unwrap_or(""),
                r["cause"].as_str().unwrap_or("")
            );
        }
    });
    Ok(())
}
