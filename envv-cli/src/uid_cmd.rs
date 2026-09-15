//! `envv uid` — the unique-ID registry (Phase 24.4). Server-side only, and
//! opt-in there (`envv-server --uid-registry`); every command refuses against
//! `Access::Local` and against a server with the feature off, both by naming
//! the reason rather than surfacing a raw HTTP error.

use crate::access::Access;
use crate::error::{CliError, CliResult};
use crate::out;
use reqwest::Method;
use serde_json::{json, Value};

fn require_remote(a: &Access) -> CliResult<&crate::access::RemoteClient> {
    a.remote().ok_or_else(|| {
        CliError::unavailable(
            "The unique-ID registry is server-side only. Connect with --server, or run \
             `envv-server --uid-registry` and point at it.",
        )
    })
}

pub fn check(a: &Access, values: &[String], normalise: &str) -> CliResult {
    let c = require_remote(a)?;
    let body = json!({ "values": values, "normalise": normalise });
    let resp = c.send_json(Method::POST, "/api/uid/check", Some(&body))?;
    let results = resp
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    out::ok("uid.check", json!({ "results": results }), || {
        for r in &results {
            let v = r.get("value").and_then(Value::as_str).unwrap_or("");
            let unique = r.get("unique").and_then(Value::as_bool).unwrap_or(false);
            println!("{v}: {}", if unique { "unique" } else { "taken" });
        }
    });
    Ok(())
}

pub fn register(
    a: &Access,
    values: &[String],
    normalise: &str,
    namespace: Option<&str>,
    generator: Option<&str>,
    note: Option<&str>,
) -> CliResult {
    let c = require_remote(a)?;
    let body = json!({
        "values": values, "normalise": normalise,
        "namespace": namespace, "generator": generator, "note": note,
    });
    let resp = c.send_json(Method::POST, "/api/uid/register", Some(&body))?;
    let results = resp
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let conflicts = results
        .iter()
        .filter(|r| {
            !r.get("registered")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    out::ok(
        "uid.register",
        json!({ "results": results, "conflicts": conflicts }),
        || {
            for r in &results {
                let v = r.get("value").and_then(Value::as_str).unwrap_or("");
                let ok = r
                    .get("registered")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                println!(
                    "{v}: {}",
                    if ok {
                        "registered"
                    } else {
                        "conflict (already registered)"
                    }
                );
            }
        },
    );
    if conflicts > 0 && conflicts == results.len() {
        return Err(CliError::conflict(format!(
            "All {conflicts} value(s) were already registered."
        )));
    }
    Ok(())
}

pub fn mint(
    a: &Access,
    length: usize,
    namespace: Option<&str>,
    generator: Option<&str>,
) -> CliResult {
    let c = require_remote(a)?;
    let body = json!({ "length": length, "namespace": namespace, "generator": generator });
    let resp = c.send_json(Method::POST, "/api/uid/mint", Some(&body))?;
    match resp.get("value").and_then(Value::as_str) {
        Some(v) => {
            out::ok("uid.mint", json!({ "value": v }), || println!("{v}"));
            Ok(())
        }
        None => Err(CliError::conflict(
            "Could not mint a unique value after 3 attempts. Try a longer --length.",
        )),
    }
}

pub fn lookup(a: &Access, value: &str, normalise: &str) -> CliResult {
    let c = require_remote(a)?;
    let body = json!({ "value": value, "normalise": normalise });
    let resp = c.send_json(Method::POST, "/api/uid/lookup", Some(&body))?;
    out::ok("uid.lookup", resp.clone(), || {
        let issued = resp.get("issued").and_then(Value::as_bool).unwrap_or(false);
        if !issued {
            println!("unknown");
            return;
        }
        println!(
            "issued — namespace: {}, generator: {}, actor: {}",
            resp.get("namespace").and_then(Value::as_str).unwrap_or("—"),
            resp.get("generator").and_then(Value::as_str).unwrap_or("—"),
            resp.get("actor").and_then(Value::as_str).unwrap_or("—"),
        );
    });
    Ok(())
}

pub fn prune(
    a: &Access,
    before: &str,
    namespace: Option<&str>,
    generator: Option<&str>,
    actor: Option<&str>,
    dry_run: bool,
    assume_yes: bool,
) -> CliResult {
    let c = require_remote(a)?;
    // A dry run always runs first, even when the caller did not ask for one —
    // "how many rows" is what the confirmation prompt needs, and pruning
    // deletes the only evidence an ID was issued.
    let dry_body = json!({
        "before": before, "namespace": namespace, "generator": generator,
        "actor": actor, "dry_run": true,
    });
    let dry = c.send_json(Method::POST, "/api/uid/prune", Some(&dry_body))?;
    let matched = dry.get("matched").and_then(Value::as_u64).unwrap_or(0);

    if dry_run {
        out::ok("uid.prune", dry.clone(), || {
            println!("{matched} row(s) would be deleted. Pass without --dry-run to delete them.");
        });
        return Ok(());
    }
    if matched == 0 {
        out::ok("uid.prune", dry, || println!("Nothing to prune."));
        return Ok(());
    }
    if !crate::fmt::confirm(
        &format!(
            "Delete {matched} registry row(s)? This deletes the only evidence those IDs were \
             issued — a pruned ID can be issued again without a collision being detected, and \
             a lookup on it will answer 'unknown'. Cannot be undone."
        ),
        assume_yes,
    )? {
        return Ok(());
    }
    let body = json!({
        "before": before, "namespace": namespace, "generator": generator,
        "actor": actor, "dry_run": false,
    });
    let resp = c.send_json(Method::POST, "/api/uid/prune", Some(&body))?;
    out::ok("uid.prune", resp.clone(), || {
        let deleted = resp.get("deleted").and_then(Value::as_u64).unwrap_or(0);
        println!("Deleted {deleted} row(s).");
    });
    Ok(())
}

pub fn stats(a: &Access) -> CliResult {
    let c = require_remote(a)?;
    let resp = c.get_json("/api/uid/stats")?;
    out::ok("uid.stats", resp.clone(), || {
        println!(
            "{} id(s), {} bytes on disk, oldest {}",
            resp.get("count").and_then(Value::as_i64).unwrap_or(0),
            resp.get("size_bytes").and_then(Value::as_i64).unwrap_or(0),
            resp.get("oldest_ts")
                .and_then(Value::as_i64)
                .map(|t| t.to_string())
                .unwrap_or_else(|| "—".to_string()),
        );
    });
    Ok(())
}
