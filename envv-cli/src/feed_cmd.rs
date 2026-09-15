//! `envv calendar feed` — subscribable `.ics` URLs served by `envv-server`
//! (Phase 24.3). Server-side only: there is nothing local to serve a feed from,
//! so every command here refuses against `Access::Local` with an explanation
//! rather than a confusing HTTP error.

use crate::access::Access;
use crate::error::{CliError, CliResult};
use crate::out;
use reqwest::Method;
use serde_json::{json, Value};

fn require_remote(a: &Access) -> CliResult<&crate::access::RemoteClient> {
    a.remote().ok_or_else(|| {
        CliError::unavailable(
            "Calendar feeds are server-side only. Connect with --server, or run \
             `envv-server` and point at it.",
        )
    })
}

pub fn new(
    a: &Access,
    kinds: &[String],
    name: &str,
    include_account_names: bool,
    out_path: Option<&std::path::Path>,
) -> CliResult {
    // Refuse *before* minting, not after — the same rule `user token new`
    // follows. A feed created and then refused to print is a live URL nobody
    // can reach to use or revoke by name.
    if out_path.is_none() && !out::revealing() {
        return Err(CliError::redacted(
            "A feed URL is a bearer credential, so it is not printed by default.\n\
             Pass --out <file> to write it to a 0600 file, or --reveal to print it.\n\
             Nothing was created.",
        ));
    }
    let c = require_remote(a)?;
    let body = json!({
        "name": name,
        "kinds": kinds,
        "include_account_names": include_account_names,
    });
    let resp = c.send_json(Method::POST, "/api/calendar/feeds", Some(&body))?;
    let id = resp.get("id").and_then(Value::as_str).unwrap_or("");
    let path = resp.get("path").and_then(Value::as_str).unwrap_or("");
    let url = format!("{}{}", c.base, path);

    if let Some(p) = out_path {
        std::fs::write(p, format!("{url}\n"))
            .map_err(|e| CliError::from(format!("Cannot write {}: {e}", p.display())))?;
        vault_core::restrict_to_owner(p).map_err(CliError::from)?;
    }

    out::ok(
        "calendar.feed.new",
        json!({ "id": id, "url": if out::revealing() { Some(url.clone()) } else { None },
                "written": out_path.map(|p| p.display().to_string()) }),
        || {
            if out::revealing() {
                println!("Feed created: {url}");
            } else {
                println!("Feed created (id {id}) → {}", out_path.unwrap().display());
            }
            println!("Anyone holding this URL can read event names and dates until revoked.");
        },
    );
    Ok(())
}

pub fn ls(a: &Access) -> CliResult {
    let c = require_remote(a)?;
    let resp = c.get_json("/api/calendar/feeds")?;
    let feeds = resp
        .get("feeds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if out::is_json() {
        out::ok(
            "calendar.feed.ls",
            json!({ "count": feeds.len(), "feeds": feeds }),
            || {},
        );
        return Ok(());
    }
    if feeds.is_empty() {
        println!("No calendar feeds.");
        return Ok(());
    }
    println!("{:<38} {:<20} {:<26} Status", "Id", "Name", "Created");
    println!("{}", "-".repeat(100));
    for f in &feeds {
        let revoked = f.get("revoked_at").and_then(Value::as_str).is_some();
        println!(
            "{:<38} {:<20} {:<26} {}",
            f.get("id").and_then(Value::as_str).unwrap_or(""),
            f.get("name").and_then(Value::as_str).unwrap_or(""),
            f.get("created_at").and_then(Value::as_str).unwrap_or(""),
            if revoked { "revoked" } else { "active" },
        );
    }
    Ok(())
}

pub fn revoke(a: &Access, id: &str, assume_yes: bool) -> CliResult {
    if !crate::fmt::confirm(
        "Revoke this feed? The URL stops working immediately and cannot be un-revoked.",
        assume_yes,
    )? {
        return Ok(());
    }
    let c = require_remote(a)?;
    c.send_json(Method::DELETE, &format!("/api/calendar/feeds/{id}"), None)?;
    out::ok("calendar.feed.revoke", json!({ "id": id }), || {
        println!("Revoked {id}");
    });
    Ok(())
}
