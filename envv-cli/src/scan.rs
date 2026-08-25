//! Health scan, audit-chain verification and vault statistics — the Tools
//! panel's read-only analyses, ported from `src/ts/tools.ts` and `src/ts/audit.ts`.

use crate::access::Access;
use crate::data;
use crate::error::{CliError, CliResult};
use crate::fmt::cell;
use crate::refs::resolve_value;
use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    High,
    Med,
    Low,
}

impl Severity {
    fn label(&self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Med => "MED",
            Severity::Low => "LOW",
        }
    }
}

pub struct Issue {
    pub severity: Severity,
    pub subject: String,
    pub message: String,
}

fn today() -> String {
    vault_core::iso_now().chars().take(10).collect()
}

fn days_from_now(days: i64) -> String {
    // Date arithmetic on the ISO string only, matching the UI's comparisons,
    // which are lexical on `YYYY-MM-DD`.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let target = now + days * 86_400;
    let dt = time::OffsetDateTime::from_unix_timestamp(target)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!("{:04}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day())
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut cur = vec![0usize; n + 1];
    for i in 1..=m {
        cur[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[n]
}

/// Every check the Health Dashboard runs, in the same order and with the same
/// thresholds — a CLI that disagreed with the UI about what "weak" means would
/// be worse than no CLI check at all.
pub fn analyse(vault: &Value) -> Vec<Issue> {
    let entries = data::entries(vault);
    let projects = data::projects(vault);
    let today = today();
    let warn30 = days_from_now(30);
    let mut issues: Vec<Issue> = Vec::new();

    for k in &entries {
        let prov = match k.get("provider").and_then(|v| v.as_str()) {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => "?".to_string(),
        };
        let api_key = k.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
        let stype = k
            .get("secretType")
            .and_then(|v| v.as_str())
            .unwrap_or("api_key");

        if k.get("compromised")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            issues.push(Issue {
                severity: Severity::High,
                subject: prov.clone(),
                message: "Marked COMPROMISED — rotate immediately".into(),
            });
        }
        let token_shaped = api_key.chars().count() >= 20
            && api_key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if (stype == "password" || stype == "api_key")
            && api_key.chars().count() < 12
            && !token_shaped
        {
            issues.push(Issue {
                severity: Severity::High,
                subject: prov.clone(),
                message: "Short or weak secret value (< 12 chars)".into(),
            });
        }
        const WEAK: [&str; 9] = [
            "password", "secret", "changeme", "admin", "test", "123456", "qwerty", "letmein",
            "default",
        ];
        let lower = api_key.to_lowercase();
        if !api_key.is_empty() && WEAK.iter().any(|w| lower.starts_with(w)) {
            issues.push(Issue {
                severity: Severity::High,
                subject: prov.clone(),
                message: "Secret starts with a common weak value".into(),
            });
        }
        if let Some(exp) = k
            .get("expires_at")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            let day: String = exp.chars().take(10).collect();
            if day < today {
                issues.push(Issue {
                    severity: Severity::High,
                    subject: prov.clone(),
                    message: format!("Expired on {day}"),
                });
            } else if day <= warn30 {
                issues.push(Issue {
                    severity: Severity::Med,
                    subject: prov.clone(),
                    message: format!("Expiring {day}"),
                });
            }
        }
        let rotation_days = k.get("rotation_days").and_then(|v| v.as_i64()).unwrap_or(0);
        if rotation_days > 0 {
            if let Some(last) = k.get("last_rotated_at").and_then(|v| v.as_str()) {
                if let Ok(t) = time::OffsetDateTime::parse(
                    last,
                    &time::format_description::well_known::Rfc3339,
                ) {
                    let due = t.unix_timestamp() + rotation_days * 86_400;
                    let now = time::OffsetDateTime::now_utc().unix_timestamp();
                    if due < now {
                        let overdue = (now - due) / 86_400;
                        issues.push(Issue {
                            severity: Severity::Med,
                            subject: prov.clone(),
                            message: format!(
                                "Rotation overdue by {overdue}d (every {rotation_days}d)"
                            ),
                        });
                    }
                }
            }
        }
        let never_rotated = k
            .get("last_rotated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty()
            && k.get("version_history")
                .and_then(|v| v.as_array())
                .is_none_or(|a| a.is_empty());
        if never_rotated {
            issues.push(Issue {
                severity: Severity::Low,
                subject: prov.clone(),
                message: "Never rotated".into(),
            });
        }
        let described = !k
            .get("api_description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty()
            || !k
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty();
        if !described {
            issues.push(Issue {
                severity: Severity::Low,
                subject: prov.clone(),
                message: "No description — hard to identify later".into(),
            });
        }
    }

    // Duplicate value detection — the same secret stored under several entries.
    let mut by_value: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
    for k in &entries {
        let v = k.get("api_key").and_then(|x| x.as_str()).unwrap_or("");
        if v.chars().count() < 6 {
            continue;
        }
        by_value.entry(v).or_default().push(
            k.get("provider")
                .and_then(|p| p.as_str())
                .unwrap_or("?")
                .to_string(),
        );
    }
    for (_, provs) in by_value {
        if provs.len() > 1 {
            issues.push(Issue {
                severity: Severity::Med,
                subject: provs.join(", "),
                message: format!(
                    "Same secret value in {} entries — consider merging",
                    provs.len()
                ),
            });
        }
    }

    // Stale ${ref} detection, with a "did you mean" suggestion by edit distance.
    let providers: Vec<String> = {
        let mut v: Vec<String> = entries
            .iter()
            .filter_map(|e| e.get("provider").and_then(|p| p.as_str()).map(String::from))
            .filter(|p| !p.is_empty())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let nearest = |target: &str| -> Option<String> {
        let mut best: Option<(usize, &String)> = None;
        for p in &providers {
            let d = levenshtein(&target.to_lowercase(), &p.to_lowercase());
            if best.is_none_or(|(bd, _)| d < bd) {
                best = Some((d, p));
            }
        }
        let limit = 2.max((target.chars().count() as f64 * 0.4).ceil() as usize);
        best.filter(|(d, _)| *d <= limit).map(|(_, p)| p.clone())
    };

    let env_field = crate::refs::env_copy_field();
    let mut seen: std::collections::BTreeSet<String> = Default::default();
    for p in &projects {
        let pname = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
        for c in p
            .get("chunks")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let cname = c.get("name").and_then(|v| v.as_str()).unwrap_or("");
            for f in c
                .get("fields")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
            {
                let raw = f.get("value").and_then(|v| v.as_str()).unwrap_or("");
                if !(raw.starts_with("${") && raw.ends_with('}') && raw.len() > 3) {
                    continue;
                }
                if !resolve_value(&entries, &projects, raw, &env_field).unresolved {
                    continue;
                }
                let dedupe = format!("{pname}|{raw}");
                if !seen.insert(dedupe) {
                    continue;
                }
                let inner = raw[2..raw.len() - 1].trim_start_matches("chunk:");
                let prov_part = inner
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .split('_')
                    .next()
                    .unwrap_or("");
                let hint = nearest(prov_part)
                    .map(|g| format!(" — did you mean ${{{g}/…}}?"))
                    .unwrap_or_default();
                issues.push(Issue {
                    severity: Severity::High,
                    subject: format!("{pname} / {cname}"),
                    message: format!("Stale ref {raw}{hint}"),
                });
            }
        }
    }

    issues.sort_by_key(|i| i.severity);
    issues
}

pub fn cmd_scan(access: &Access, min_severity: &str, json_out: bool) -> CliResult {
    let vault = access.load_vault()?;
    let floor = match min_severity {
        "high" => Severity::High,
        "med" => Severity::Med,
        _ => Severity::Low,
    };
    let issues: Vec<Issue> = analyse(&vault)
        .into_iter()
        .filter(|i| i.severity <= floor)
        .collect();

    let high = issues
        .iter()
        .filter(|i| i.severity == Severity::High)
        .count();
    let med = issues
        .iter()
        .filter(|i| i.severity == Severity::Med)
        .count();
    let low = issues
        .iter()
        .filter(|i| i.severity == Severity::Low)
        .count();

    if json_out || crate::out::is_json() {
        let arr: Vec<Value> = issues
            .iter()
            .map(|i| {
                serde_json::json!({
                    "severity": i.severity.label().to_lowercase(),
                    "subject": i.subject,
                    "message": i.message,
                })
            })
            .collect();
        crate::out::ok(
            "scan",
            serde_json::json!({
                "count": arr.len(),
                "high": high, "medium": med, "low": low,
                "issues": arr,
            }),
            || {},
        );
        return Ok(());
    }

    if issues.is_empty() {
        println!("No issues found.");
        return Ok(());
    }
    println!("{:<6} {:<34} Issue", "Sev", "Subject");
    println!("{}", "-".repeat(96));
    for i in &issues {
        println!(
            "{:<6} {} {}",
            i.severity.label(),
            cell(&i.subject, 34),
            i.message
        );
    }
    println!(
        "\n{} issue(s): {high} high, {med} medium, {low} low",
        issues.len()
    );
    Ok(())
}

// ── Audit chain verification ──────────────────────────────────────────────────

fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Recompute the audit hash chain oldest-first.
///
/// Two checks per row: the stored `entry_hash` must equal a fresh hash of the
/// row's contents, and `prev_hash` must equal the previous row's `entry_hash`.
/// The first chained row must anchor to `genesis` — without that check, deleting
/// the *start* of the log verifies clean, which is the most useful part to erase.
pub fn cmd_verify(access: &Access) -> CliResult {
    let rows: Vec<Value> = match access {
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::load_audit(&conn)?
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id, "action": r.action, "entry_provider": r.entry_provider,
                        "timestamp": r.timestamp, "entry_hash": r.entry_hash,
                        "prev_hash": r.prev_hash, "actor": r.actor,
                    })
                })
                .collect()
        }
        Access::Remote(c) => c.get_audit()?,
    };

    let mut ordered = rows;
    ordered.sort_by_key(|r| r.get("id").and_then(|v| v.as_i64()).unwrap_or(0));
    let chained: Vec<&Value> = ordered
        .iter()
        .filter(|r| {
            !r.get("entry_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
        })
        .collect();

    if chained.is_empty() {
        crate::out::ok(
            "audit.verify",
            serde_json::json!({ "ok": true, "checked": 0, "note": "no hash-chained rows yet" }),
            || println!("No hash-chained rows yet — nothing to verify."),
        );
        return Ok(());
    }
    let first_prev = chained[0]
        .get("prev_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !first_prev.is_empty() && first_prev != "genesis" {
        return Err(CliError::new(crate::error::Code::Error, format!(
            "Row #{} is the oldest hashed row but links to an earlier hash — rows before it were removed.",
            chained[0].get("id").and_then(|v| v.as_i64()).unwrap_or(0)
        )));
    }

    let mut prev: Option<String> = None;
    for (i, r) in chained.iter().enumerate() {
        let id = r.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let action = r.get("action").and_then(|v| v.as_str()).unwrap_or("");
        let provider = r
            .get("entry_provider")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ts = r.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let actor = r
            .get("actor")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let stored = r.get("entry_hash").and_then(|v| v.as_str()).unwrap_or("");
        let prev_for_hash = r
            .get("prev_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("genesis");

        // Two chain formats coexist, mirroring `compute_audit_hash`:
        //   v2  action|provider|timestamp|actor|prev
        //   v1  action|provider|timestamp|prev   (rows predating actor tracking)
        let expected = match actor {
            Some(a) => sha256_hex(&format!("{action}|{provider}|{ts}|{a}|{prev_for_hash}")),
            None => sha256_hex(&format!("{action}|{provider}|{ts}|{prev_for_hash}")),
        };
        if expected != stored {
            return Err(CliError::new(
                crate::error::Code::Error,
                format!(
                    "Chain broken at row {} (#{id}): contents do not match the stored hash.",
                    i + 1
                ),
            ));
        }
        if let Some(p) = &prev {
            if r.get("prev_hash").and_then(|v| v.as_str()).unwrap_or("") != p {
                return Err(CliError::new(
                    crate::error::Code::Error,
                    format!(
                        "Chain broken at row {} (#{id}): does not link to the previous row.",
                        i + 1
                    ),
                ));
            }
        }
        prev = Some(stored.to_string());
    }
    crate::out::ok(
        "audit.verify",
        serde_json::json!({ "ok": true, "checked": chained.len() }),
        || println!("All {} chained rows verified.", chained.len()),
    );
    Ok(())
}

// ── Status / stats ────────────────────────────────────────────────────────────

pub fn cmd_status(access: &Access) -> CliResult {
    let (mode, location, fingerprint) = match access {
        Access::Local(_) => (
            "local",
            crate::access::default_db_path().display().to_string(),
            None,
        ),
        Access::Remote(c) => {
            let fp = c.get_json("/api/status").ok().and_then(|s| {
                s.get("cert_fingerprint")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });
            ("remote", c.base.clone(), fp)
        }
    };

    // An empty vault is a state to report, not an error: `status` is the command
    // you reach for when you are not sure what this CLI is pointed at.
    let vault = access.load_vault_or_empty()?;
    let entries = data::entries(&vault);
    let projects = data::projects(&vault);
    let chunks: usize = projects
        .iter()
        .map(|p| {
            p.get("chunks")
                .and_then(|c| c.as_array())
                .map_or(0, |a| a.len())
        })
        .sum();
    let mut by_type: std::collections::BTreeMap<&str, usize> = Default::default();
    for e in &entries {
        *by_type
            .entry(
                e.get("secretType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("api_key"),
            )
            .or_insert(0) += 1;
    }

    crate::out::ok(
        "status",
        serde_json::json!({
            "mode": mode,
            "location": location,
            "cert_fingerprint": fingerprint,
            "entries": entries.len(),
            "projects": projects.len(),
            "categories": data::categories(&vault).len(),
            "chunks": chunks,
            "by_type": by_type,
            "redacting": !crate::out::revealing(),
        }),
        || {
            println!("Mode        {mode}");
            println!(
                "{:<11} {location}",
                if mode == "local" { "Vault" } else { "Server" }
            );
            if let Some(fp) = &fingerprint {
                println!("Cert SHA256 {fp}");
            }
            println!("Entries     {}", entries.len());
            println!("Projects    {}", projects.len());
            println!("Categories  {}", data::categories(&vault).len());
            println!("Chunks      {chunks}");
            if !by_type.is_empty() {
                println!("\nBy type:");
                for (t, n) in &by_type {
                    println!("  {} {n}", cell(t, 20));
                }
            }
        },
    );
    Ok(())
}
