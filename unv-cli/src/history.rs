//! Phase 35 — the config time machine's one dispatcher (ADR-0141).
//!
//! The CLI (local), `unv-server` (`POST /api/history`) and the desktop app (the
//! `history_call` command) all reach the history through [`call`], so the three
//! cannot disagree about what a list, a diff or a prune does. Each caller only
//! supplies a connection and the JSON arguments.
//!
//! Rendering lives here rather than in `vault-core` because it needs the
//! exporters. Every snapshot is rendered twice, once as it would be deployed and
//! once with each resolved secret replaced by its fingerprint; see
//! `vault_core::config_history` for why both are stored.

use crate::chunks::{default_format_for, render_project_as};
use crate::data::projects;
use serde_json::{json, Value};
use vault_core::config_history as ch;
use vault_core::SqlConnection as Connection;

/// `(project id, project name, exporter)` for every config a project renders.
fn streams(vault: &Value) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for p in projects(vault) {
        let id = p.get("id").and_then(Value::as_str).unwrap_or("");
        let name = p.get("name").and_then(Value::as_str).unwrap_or("");
        if id.is_empty() {
            continue;
        }
        let ptype = p
            .get("project_type")
            .and_then(Value::as_str)
            .unwrap_or("generic");
        let fmt = default_format_for(ptype);
        out.push((id.into(), name.into(), fmt.into()));
        // Compose substitutes ${VAR} from the `.env` beside it, so the pair is
        // one deliverable and the `.env` is a stream of its own.
        if fmt == "compose" {
            out.push((id.into(), name.into(), "compose-env".into()));
        }
    }
    out
}

/// Renders one project with one exporter and records it if it changed. The
/// hub calls this with the exact target a node is about to be sent, so a file
/// that goes to a host is always in the history, whether or not a save came first.
pub fn snapshot_stream(
    conn: &Connection,
    vault: &Value,
    project: &str,
    exporter: &str,
    cause: &str,
    actor: Option<&str>,
) -> Result<Option<i64>, String> {
    let pi = crate::data::find_project_index(vault, project).map_err(|e| e.to_string())?;
    let p = &projects(vault)[pi];
    let id = p.get("id").and_then(Value::as_str).unwrap_or("");
    let name = p.get("name").and_then(Value::as_str).unwrap_or("");
    let real = render_project_as(vault, id, exporter, false).map_err(|e| e.to_string())?;
    let masked = render_project_as(vault, id, exporter, true).map_err(|e| e.to_string())?;
    let exposed = serde_json::to_string(&crate::exposure::Matcher::from_vault(vault).find(&real))
        .unwrap_or_else(|_| "[]".into());
    let stream = ch::Stream {
        project: id,
        project_name: name,
        exporter,
    };
    ch::record(conn, &stream, &real, &masked, &exposed, cause, actor)
}

#[derive(Debug, Default, PartialEq)]
pub struct SnapshotReport {
    pub recorded: usize,
    pub unchanged: usize,
    /// Streams that render to nothing or fail to render (a generic project with
    /// no `.env` chunk, say). Not an error: most projects have one real config.
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// Renders every project's config and records the ones that changed.
pub fn snapshot_all(
    conn: &Connection,
    vault: &Value,
    only_project: Option<&str>,
    cause: &str,
    actor: Option<&str>,
) -> SnapshotReport {
    let mut rep = SnapshotReport::default();
    if !ch::policy(conn).enabled {
        return rep;
    }
    // Built on first use: most saves change no config and never need it.
    let matcher = std::cell::OnceCell::new();
    for (id, name, exporter) in streams(vault) {
        if let Some(q) = only_project {
            if q != id && q != name {
                continue;
            }
        }
        let real = render_project_as(vault, &id, &exporter, false);
        let masked = render_project_as(vault, &id, &exporter, true);
        let (Ok(real), Ok(masked)) = (real, masked) else {
            rep.skipped += 1;
            continue;
        };
        if real.trim().is_empty() {
            rep.skipped += 1;
            continue;
        }
        let stream = ch::Stream {
            project: &id,
            project_name: &name,
            exporter: &exporter,
        };
        // The secrets whose exact value is in this file, kept with the snapshot
        // because by the time of a compromise the entry may have been rotated,
        // edited or deleted (blast radius, Phase 36).
        let exposed = serde_json::to_string(
            &matcher
                .get_or_init(|| crate::exposure::Matcher::from_vault(vault))
                .find(&real),
        )
        .unwrap_or_else(|_| "[]".into());
        match ch::record(conn, &stream, &real, &masked, &exposed, cause, actor) {
            Ok(Some(_)) => rep.recorded += 1,
            Ok(None) => rep.unchanged += 1,
            Err(e) => rep.errors.push(e),
        }
    }
    rep
}

/// The differing lines of a diff reduced to their names: the text before the
/// first `=`, `:` or space, and "(value hidden)". Safe to print.
fn masked_summary(ops: &[vault_core::textdiff::Op<'_>]) -> String {
    use vault_core::textdiff::Op;
    let name = |l: &str| -> String {
        let t = l.trim_start();
        let end = t.find(['=', ':', ' ', '\t']).unwrap_or(t.len());
        t[..end].chars().take(48).collect()
    };
    let mut out = String::new();
    let mut line = 0usize;
    for op in ops {
        match op {
            Op::Equal(_) => line += 1,
            Op::Delete(l) => {
                line += 1;
                out.push_str(&format!("- line {line}: {} (value hidden)\n", name(l)));
            }
            Op::Insert(l) => out.push_str(&format!("+ {} (value hidden)\n", name(l))),
        }
    }
    out
}

/// The hook every writer calls after a successful save. Never fails the save: a
/// history that cannot record is reported on the log, not by losing the user's
/// edit.
pub fn after_save(conn: &Connection, vault: &Value, actor: Option<&str>) {
    let rep = snapshot_all(conn, vault, None, "save", actor);
    for e in &rep.errors {
        tracing::warn!(error = %e, "config history could not record a snapshot");
    }
}

fn s<'a>(args: &'a Value, k: &str) -> Option<&'a str> {
    args.get(k)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}
fn n(args: &Value, k: &str) -> Option<i64> {
    args.get(k).and_then(Value::as_i64)
}
fn b(args: &Value, k: &str) -> bool {
    args.get(k).and_then(Value::as_bool).unwrap_or(false)
}

/// One history operation. `op` and `args` are the same on every surface.
pub fn call(
    conn: &Connection,
    op: &str,
    args: &Value,
    actor: Option<&str>,
) -> Result<Value, String> {
    match op {
        "list" => {
            let rows = ch::list(
                conn,
                s(args, "project"),
                s(args, "exporter"),
                s(args, "since"),
                n(args, "limit").unwrap_or(50),
            )?;
            Ok(json!({ "snapshots": rows }))
        }
        "show" => {
            let seq = n(args, "seq").ok_or("show needs a snapshot number")?;
            let snap = ch::get(conn, seq)?.ok_or_else(|| format!("No snapshot #{seq}"))?;
            let reveal = b(args, "reveal");
            Ok(json!({
                "meta": snap.meta,
                "revealed": reveal,
                "text": if reveal { snap.content } else { snap.masked },
            }))
        }
        "diff" => {
            let (from, to) = ch::resolve_pair(
                conn,
                s(args, "project"),
                s(args, "exporter"),
                n(args, "from"),
                n(args, "to"),
            )?;
            let reveal = b(args, "reveal");
            let text = ch::diff(
                conn,
                from,
                to,
                !reveal,
                n(args, "context").unwrap_or(3).clamp(0, 50) as usize,
            )?;
            let (added, removed) = {
                let sa = ch::get(conn, from)?.ok_or("missing snapshot")?;
                let sb = ch::get(conn, to)?.ok_or("missing snapshot")?;
                let pick = |x: &ch::Snapshot| {
                    if reveal {
                        x.content.clone()
                    } else {
                        x.masked.clone()
                    }
                };
                vault_core::textdiff::stat(&vault_core::textdiff::diff_ops(&pick(&sa), &pick(&sb)))
            };
            Ok(
                json!({ "from": from, "to": to, "revealed": reveal, "added": added, "removed": removed, "diff": text }),
            )
        }
        // Phase 35 leftover: a stored snapshot against text the caller supplies,
        // typically a node's live file fetched with `unv node pull`.
        "diff_text" => {
            let seq = match n(args, "seq") {
                Some(x) => x,
                None => ch::list(conn, s(args, "project"), s(args, "exporter"), None, 1)?
                    .first()
                    .map(|m| m.seq)
                    .ok_or("There is no snapshot of that config yet")?,
            };
            let snap = ch::get(conn, seq)?.ok_or_else(|| format!("No snapshot #{seq}"))?;
            let other = args
                .get("text")
                .and_then(Value::as_str)
                .ok_or("diff_text needs the text to compare")?;
            let reveal = b(args, "reveal");
            let ops = vault_core::textdiff::diff_ops(&snap.content, other);
            let (added, removed) = vault_core::textdiff::stat(&ops);
            let diff = if reveal {
                vault_core::textdiff::unified(
                    &format!("#{seq} {}", snap.meta.at),
                    "the file",
                    &snap.content,
                    other,
                    n(args, "context").unwrap_or(3).clamp(0, 50) as usize,
                )
            } else {
                // The file is real text and the snapshot's masking was made from the
                // vault as it stood then, so a masked line-by-line diff cannot be
                // promised to hide a value. Without --reveal only the *names* of the
                // lines that differ are shown, and never what follows them.
                masked_summary(&ops)
            };
            Ok(
                json!({ "seq": seq, "revealed": reveal, "added": added, "removed": removed, "identical": added + removed == 0, "diff": diff }),
            )
        }
        "snapshot" => {
            let vault = vault_core::load_vault(conn)?.ok_or("The vault is empty")?;
            let rep = snapshot_all(conn, &vault, s(args, "project"), "manual", actor);
            Ok(json!({
                "recorded": rep.recorded, "unchanged": rep.unchanged,
                "skipped": rep.skipped, "errors": rep.errors,
            }))
        }
        "prune" => {
            let pol = ch::policy(conn);
            let rep = ch::prune(
                conn,
                n(args, "keep").unwrap_or(pol.keep),
                n(args, "days").unwrap_or(pol.days),
                b(args, "dry_run"),
                actor,
            )?;
            Ok(serde_json::to_value(rep).map_err(|e| e.to_string())?)
        }
        "verify" => Ok(serde_json::to_value(ch::verify(conn)?).map_err(|e| e.to_string())?),
        "stats" => Ok(serde_json::to_value(ch::stats(conn)?).map_err(|e| e.to_string())?),
        "policy" => {
            let set = args.get("enabled").is_some()
                || args.get("keep").is_some()
                || args.get("days").is_some();
            let p = if set {
                ch::set_policy(
                    conn,
                    args.get("enabled").and_then(Value::as_bool),
                    n(args, "keep"),
                    n(args, "days"),
                )?
            } else {
                ch::policy(conn)
            };
            Ok(serde_json::to_value(p).map_err(|e| e.to_string())?)
        }
        "blast" => {
            let host = s(args, "host").ok_or("blast needs a node name")?;
            let vault = vault_core::load_vault(conn)?.unwrap_or_else(|| json!({ "api_keys": [] }));
            let current = crate::exposure::current_map(&vault);
            let deployments = node_deployments(conn, host)?;
            let report = vault_core::blast::report(
                host,
                s(args, "since"),
                &deployments,
                &|d| ch::exposed_by_sha(conn, &d.sha256).ok().flatten(),
                &|id| current.get(id).cloned(),
            );
            Ok(serde_json::to_value(report).map_err(|e| e.to_string())?)
        }
        "where" => {
            let sha = s(args, "sha256").ok_or("where needs a sha256")?;
            Ok(json!({ "snapshots": ch::find_by_sha(conn, sha, 5)? }))
        }
        other => Err(format!("Unknown history operation '{other}'")),
    }
}

/// Every apply a node reported, from the hub's audit chain. The time is the
/// audit row's (the hub's clock), not the one the node put in its own report:
/// a node being investigated is not the source for when things happened.
fn node_deployments(
    conn: &Connection,
    node: &str,
) -> Result<Vec<vault_core::blast::Deployment>, String> {
    let mut out = Vec::new();
    for row in vault_core::load_audit(conn)? {
        if row.action != "node.apply" || row.entry_provider.as_deref() != Some(node) {
            continue;
        }
        let d: Value =
            serde_json::from_str(row.details.as_deref().unwrap_or("{}")).unwrap_or_default();
        out.push(vault_core::blast::Deployment {
            at: row.timestamp,
            via: d["target"].as_str().unwrap_or("?").to_string(),
            sha256: d["sha256"].as_str().unwrap_or("").to_string(),
            ok: d["ok"].as_bool().unwrap_or(false),
            error: d["error"].as_str().map(String::from),
        });
    }
    out.reverse(); // oldest first
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        vault_core::init_schema(&c).unwrap();
        c
    }

    fn vault(secret: &str) -> Value {
        json!({
            "api_keys": [{ "id": "e1", "provider": "Stripe", "secretType": "api_key", "api_key": secret }],
            "user_categories": [],
            "projects": [{
                "id": "web", "name": "web", "project_type": "generic",
                "chunks": [{
                    "id": "c1", "name": "app.env", "chunk_type": "env_file",
                    "fields": [
                        { "key": "STRIPE_KEY", "value": "${Stripe/api_key}" },
                        { "key": "MODE", "value": "live" }
                    ]
                }]
            }, {
                "id": "empty", "name": "nothing", "project_type": "generic", "chunks": []
            }]
        })
    }

    #[test]
    fn snapshotting_records_changes_once_and_skips_projects_with_nothing_to_render() {
        let c = conn();
        let v = vault("sk_live_ONE");
        let r = snapshot_all(&c, &v, None, "save", Some("owner"));
        assert_eq!((r.recorded, r.unchanged, r.skipped), (1, 0, 1));
        let again = snapshot_all(&c, &v, None, "save", None);
        assert_eq!((again.recorded, again.unchanged), (0, 1));
        let rotated = snapshot_all(&c, &vault("sk_live_TWO"), None, "save", None);
        assert_eq!(
            rotated.recorded, 1,
            "rotating a secret changes the deployed file"
        );
    }

    #[test]
    fn the_stored_text_has_the_secret_and_the_masked_text_does_not() {
        let c = conn();
        snapshot_all(&c, &vault("sk_live_ONE"), None, "save", None);
        let shown = call(&c, "show", &json!({ "seq": 1 }), None).unwrap();
        assert!(!shown["text"].as_str().unwrap().contains("sk_live_ONE"));
        let revealed = call(&c, "show", &json!({ "seq": 1, "reveal": true }), None).unwrap();
        assert!(revealed["text"].as_str().unwrap().contains("sk_live_ONE"));
    }

    #[test]
    fn a_rotation_shows_as_a_changed_fingerprint_without_either_secret() {
        let c = conn();
        snapshot_all(&c, &vault("sk_live_ONE"), None, "save", None);
        snapshot_all(&c, &vault("sk_live_TWO"), None, "save", None);
        let d = call(&c, "diff", &json!({ "project": "web" }), None).unwrap();
        let text = d["diff"].as_str().unwrap();
        assert!(!text.contains("sk_live_"), "{text}");
        assert!(
            text.contains("-STRIPE_KEY=") && text.contains("+STRIPE_KEY="),
            "{text}"
        );
        assert_eq!(
            (d["added"].as_u64(), d["removed"].as_u64()),
            (Some(1), Some(1))
        );
        let real = call(
            &c,
            "diff",
            &json!({ "project": "web", "reveal": true }),
            None,
        )
        .unwrap();
        assert!(real["diff"].as_str().unwrap().contains("sk_live_TWO"));
    }

    #[test]
    fn a_snapshot_against_a_nodes_live_file_hides_values_unless_asked() {
        let c = conn();
        snapshot_all(&c, &vault("sk_live_ONE"), None, "save", None);
        let real = call(&c, "show", &json!({ "seq": 1, "reveal": true }), None).unwrap();
        let deployed = real["text"].as_str().unwrap().to_string();
        // The node still has exactly what was rendered.
        let same = call(
            &c,
            "diff_text",
            &json!({ "project": "web", "text": deployed }),
            None,
        )
        .unwrap();
        assert_eq!(same["identical"], true, "{same}");
        // Someone edited the live file by hand; the newest snapshot is the default.
        let drifted = deployed.replace("sk_live_ONE", "sk_live_HAND_EDITED");
        let d = call(
            &c,
            "diff_text",
            &json!({ "project": "web", "text": drifted }),
            None,
        )
        .unwrap();
        let text = d["diff"].as_str().unwrap();
        assert_eq!(d["identical"], false);
        assert!(
            !text.contains("sk_live_"),
            "a value reached the masked view: {text}"
        );
        assert!(
            text.contains("STRIPE_KEY") && text.contains("value hidden"),
            "{text}"
        );
        let r = call(
            &c,
            "diff_text",
            &json!({ "seq": 1, "text": drifted, "reveal": true }),
            None,
        )
        .unwrap();
        assert!(r["diff"].as_str().unwrap().contains("sk_live_HAND_EDITED"));
        // Nothing to compare, or no such config: refused, not an empty diff.
        call(&c, "diff_text", &json!({ "project": "web" }), None).unwrap_err();
        call(
            &c,
            "diff_text",
            &json!({ "project": "ghost", "text": "x" }),
            None,
        )
        .unwrap_err();
    }

    #[test]
    fn disabled_history_snapshots_nothing_and_manual_snapshot_says_so() {
        let c = conn();
        call(&c, "policy", &json!({ "enabled": false }), None).unwrap();
        assert_eq!(
            snapshot_all(&c, &vault("k"), None, "save", None),
            SnapshotReport::default()
        );
    }

    #[test]
    fn the_operations_cover_list_where_policy_prune_verify_and_refuse_the_unknown() {
        let c = conn();
        call(&c, "snapshot", &json!({}), None).unwrap_err(); // empty vault
        vault_core::save_vault(&c, vault("sk_live_ONE"), vault_core::SaveCtx::default()).unwrap();
        let r = call(&c, "snapshot", &json!({ "project": "web" }), Some("owner")).unwrap();
        assert_eq!(r["recorded"], 1);
        let l = call(&c, "list", &json!({ "project": "web" }), None).unwrap();
        let sha = l["snapshots"][0]["sha256"].as_str().unwrap().to_string();
        let w = call(&c, "where", &json!({ "sha256": sha }), None).unwrap();
        assert_eq!(w["snapshots"][0]["cause"], "manual");
        assert_eq!(call(&c, "policy", &json!({}), None).unwrap()["keep"], 50);
        assert_eq!(
            call(&c, "prune", &json!({ "dry_run": true }), None).unwrap()["would_delete"],
            0
        );
        assert_eq!(
            call(&c, "verify", &json!({}), None).unwrap()["problems"],
            json!([])
        );
        assert!(call(&c, "explode", &json!({}), None)
            .unwrap_err()
            .contains("Unknown"));
    }

    #[test]
    fn a_nodes_deployments_are_timed_by_the_hubs_audit_row_not_the_nodes_own_claim() {
        let c = conn();
        vault_core::record_event(
            &c,
            "node.apply",
            "vps-01",
            Some(r#"{"target":"nginx","at":"1999-01-01T00:00:00Z","sha256":"abc","ok":true,"error":null}"#),
            Some("node:vps-01"),
        )
        .unwrap();
        vault_core::record_event(&c, "node.apply", "other-node", Some("{}"), None).unwrap();
        vault_core::record_event(&c, "entry.add", "vps-01", Some("{}"), None).unwrap();
        let d = node_deployments(&c, "vps-01").unwrap();
        assert_eq!(
            d.len(),
            1,
            "another node's and another action's rows are not this node's"
        );
        assert_ne!(
            d[0].at, "1999-01-01T00:00:00Z",
            "the node's own timestamp was trusted"
        );
        assert!(d[0].at.starts_with("20"), "{}", d[0].at);
        assert_eq!(
            (d[0].via.as_str(), d[0].sha256.as_str(), d[0].ok),
            ("nginx", "abc", true)
        );
    }

    #[test]
    fn the_blast_operation_honours_since_and_reports_an_empty_host_as_empty() {
        let c = conn();
        vault_core::save_vault(&c, vault("sk_live_ONE"), vault_core::SaveCtx::default()).unwrap();
        snapshot_all(&c, &vault("sk_live_ONE"), None, "save", None);
        let sha = call(&c, "list", &json!({}), None).unwrap()["snapshots"][0]["sha256"]
            .as_str()
            .unwrap()
            .to_string();
        vault_core::record_event(
            &c,
            "node.apply",
            "vps-01",
            Some(&json!({ "target": "env", "sha256": sha, "ok": true, "error": null }).to_string()),
            Some("node:vps-01"),
        )
        .unwrap();
        let all = call(&c, "blast", &json!({ "host": "vps-01" }), None).unwrap();
        assert_eq!(all["deployments"], 1);
        assert_eq!(all["entries"][0]["provider"], "Stripe");
        assert_eq!(all["entries"][0]["still_current"], true);
        let later = call(
            &c,
            "blast",
            &json!({ "host": "vps-01", "since": "2999-01-01T00:00:00Z" }),
            None,
        )
        .unwrap();
        assert_eq!(later["deployments"], 0, "since was ignored");
        let none = call(&c, "blast", &json!({ "host": "nobody" }), None).unwrap();
        assert_eq!(
            (
                none["deployments"].as_i64(),
                none["entries"].as_array().map(Vec::len)
            ),
            (Some(0), Some(0))
        );
        assert!(call(&c, "blast", &json!({}), None).is_err());
    }

    #[test]
    fn compose_is_two_streams_because_the_env_file_is_part_of_the_deliverable() {
        let v = json!({ "api_keys": [], "projects": [{ "id": "c", "name": "c", "project_type": "docker", "chunks": [] }] });
        let ex: Vec<String> = streams(&v).into_iter().map(|s| s.2).collect();
        assert_eq!(ex, vec!["compose", "compose-env"]);
    }
}
