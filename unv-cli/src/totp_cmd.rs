//! `unv totp` — the authenticator half of the vault (Phase 22).
//!
//! An entry's `totp_secret` is a seed a **third-party service** issued, from
//! which this command produces the six digits you type into that service. It is
//! the mirror image of `unv user totp`, which enrolls a second factor on
//! *UnENVerse's own* sub-user login; the two share the RFC 6238 arithmetic in
//! `vault-core::totp` and nothing else.
//!
//! # What prints and what does not
//!
//! Phase 14's rule is that stdout redacts stored values by default. It applies
//! here exactly as written, to the two things that *are* stored values:
//!
//! - the **seed** (`unv get X --field totp_secret`) is masked to a fingerprint,
//!   `--reveal` opts back in — it is in `SECRET_FIELDS` like every other secret;
//! - the **`otpauth://` URI** (`unv totp uri`) contains the seed, so it is
//!   refused to stdout and written with `--out`, exactly like `unv export`.
//!
//! The **code** prints. It is not a stored value: it is derived, it is six
//! digits, and it is dead in under thirty seconds. This is an exemption to the
//! default and it is written down here because an unwritten exemption is
//! indistinguishable from an oversight (invariant 10) — a command whose entire
//! purpose is to hand you a code, that then refuses to hand you the code, is a
//! command with no purpose. `--json` carries it as a plain string for the same
//! reason.
//!
//! # Import and export
//!
//! `unv totp import` reads what Ente Auth, Aegis, 2FAS, andOTP, Bitwarden and
//! Google Authenticator write; `unv totp export` writes the three formats those
//! apps read back. Both go through `vault_core::totp_import`, which is the only
//! implementation — the desktop app calls the same code over IPC rather than
//! parsing six formats a second time.
//!
//! Export **is** a file full of seeds, so it follows the seed's rule and not the
//! code's: refused to stdout unless `--reveal`, written 0600 by `--out`, exactly
//! like `unv backup export`. Import writes to the vault, so it never overwrites
//! a seed that is already there with a different one — see `cmd_import`.

use crate::access::Access;
use crate::data::{self, find_entry_index};
use crate::error::{CliError, CliResult};
use crate::out;
use serde_json::{json, Value};
use std::path::PathBuf;
use vault_core::totp;

/// The parameters an entry's stored TOTP fields mean.
///
/// A thin adapter onto [`totp::Params::from_fields`], which is the only reader
/// of those fields in the project — the app's `entry_totp_code` and the form's
/// `totpParamsOf` are the other two callers of the same rule.
fn params_of(entry: &Value) -> totp::Params {
    totp::Params::from_fields(
        entry.get("totp_kind").and_then(|v| v.as_str()),
        entry.get("totp_algorithm").and_then(|v| v.as_str()),
        entry.get("totp_digits").and_then(|v| v.as_u64()),
        entry.get("totp_period").and_then(|v| v.as_u64()),
        entry.get("totp_counter").and_then(|v| v.as_u64()),
    )
}
/// The seed stored on an entry, with the parameters it generates under.
///
/// Returns `None` when the entry carries no seed, and an error when it carries
/// one that cannot produce a code — which is a broken entry, not an absent
/// feature, and the two must not look alike.
fn seed_of(entry: &Value) -> CliResult<Option<(String, totp::Params)>> {
    let raw = entry
        .get("totp_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let secret = totp::normalize_b32(raw);
    // A vault is untrusted input, and `Params::from_fields` is the one reader of
    // these three fields — see its doc comment for what having had three cost.
    let params = params_of(entry);
    // Prove it works now rather than handing back an unusable pair.
    totp::code_at(&secret, &params, 0).map_err(|e| {
        CliError::invalid(format!(
            "'{}' has a stored TOTP seed that cannot produce a code: {e}",
            data::provider_of(entry)
        ))
    })?;
    Ok(Some((secret, params)))
}

fn require_seed(entry: &Value) -> CliResult<(String, totp::Params)> {
    seed_of(entry)?.ok_or_else(|| {
        CliError::not_found(format!(
            "'{}' has no TOTP seed — add one with `unv entry set '{}' --totp <SEED|otpauth://…>`",
            data::provider_of(entry),
            data::provider_of(entry),
        ))
    })
}

/// `unv totp code <entry>` — the current code and how long it has left.
pub fn cmd_code(access: &Access, query: &str, next: bool) -> CliResult {
    let vault = access.load_vault_or_empty()?;
    let idx = find_entry_index(&vault, query)?;
    let entry = &data::entries(&vault)[idx];
    let (secret, params) = require_seed(entry)?;
    let live = totp::live_code_with(&secret, &params, next).map_err(CliError::invalid)?;
    let provider = data::provider_of(entry).to_string();

    out::ok(
        "totp.code",
        json!({
            "provider": provider,
            "code": live.code,
            "next_code": live.next_code,
            "kind": live.kind.as_str(),
            "counter": live.counter,
            "remaining_secs": live.remaining_secs,
            "period": live.period,
            "digits": live.digits,
            "algorithm": live.algorithm.as_str(),
        }),
        || {
            // A counter-based code has no clock, so there is no countdown to
            // print — its position is the useful number, and it is what
            // `unv totp advance` moves.
            if live.kind == totp::Kind::Hotp {
                println!("{}  (counter {})", grouped_code(&live.code), live.counter);
            } else {
                println!(
                    "{}  ({}s left)",
                    grouped_code(&live.code),
                    live.remaining_secs
                );
            }
            if let Some(n) = &live.next_code {
                println!("next: {}", grouped_code(n));
            }
        },
    );
    Ok(())
}

/// `unv totp advance` — move a counter-based seed to its next position.
///
/// Reading a code deliberately does **not** advance it. A counter-based code
/// stands until it is used, and the service moves on only when it accepts one;
/// advancing on every read would walk the vault's counter past the service's the
/// first time somebody looked at a card twice, and the failure — a second factor
/// that stops working with no error anywhere — looks exactly like a wrong seed.
pub fn cmd_advance(access: &Access, query: &str, by: u64, yes: bool) -> CliResult {
    let mut vault = access.load_vault_or_empty()?;
    let idx = find_entry_index(&vault, query)?;
    let entry = &data::entries(&vault)[idx];
    let provider = data::provider_of(entry).to_string();
    let (_secret, params) = require_seed(entry)?;

    if params.kind != totp::Kind::Hotp {
        return Err(CliError::invalid(format!(
            "'{provider}' holds a {} seed, which advances on its own — there is \
             no counter to move",
            params.kind.as_str()
        )));
    }
    if by == 0 {
        return Err(CliError::invalid("--by 0 would move nothing"));
    }
    let from = params.counter;
    let to = from.checked_add(by).ok_or_else(|| {
        CliError::invalid(
            "the counter would overflow; resynchronise with `entry set --totp-counter`",
        )
    })?;

    // Advancing past the service's position is what breaks the factor, and it
    // cannot be undone from here — only resynchronised against the service.
    if by > 1
        && !crate::fmt::confirm(
            &format!("Advance '{provider}' from {from} to {to} ({by} positions)?"),
            yes,
        )?
    {
        return Ok(());
    }

    if let Some(e) = data::entries_mut(&mut vault).get_mut(idx) {
        e["totp_counter"] = json!(to);
    }
    access.save(&vault)?;

    out::ok(
        "totp.advance",
        json!({ "provider": provider, "from": from, "counter": to }),
        || println!("'{provider}' advanced from {from} to {to}."),
    );
    Ok(())
}

/// Split a code in half the way every authenticator displays it.
fn grouped_code(code: &str) -> String {
    if code.len() < 6 {
        return code.to_string();
    }
    let half = code.len().div_ceil(2);
    format!("{} {}", &code[..half], &code[half..])
}

/// `unv totp ls` — which entries carry a seed.
///
/// Names and parameters only, never codes. A vault-wide dump of live codes is
/// the same shape as a vault-wide export to stdout, which Phase 14 refuses: it
/// hands the caller every second factor in the vault in one call, and the fact
/// that each dies in thirty seconds does not make the transcript it lands in
/// any less of one.
pub fn cmd_ls(access: &Access) -> CliResult {
    let vault = access.load_vault_or_empty()?;
    let mut rows: Vec<Value> = Vec::new();
    for entry in &data::entries(&vault) {
        // A broken seed is reported rather than aborting the listing: one bad
        // entry must not make `unv totp ls` useless for the other forty.
        let (ok, note) = match seed_of(entry) {
            Ok(Some(_)) => (true, None),
            Ok(None) => continue,
            Err(e) => (false, Some(e.message)),
        };
        // The same reader `unv totp code` uses. Listing the raw stored numbers
        // instead — which is what this did — reported a credential the code
        // command would never produce: 99 digits listed, six digits handed over.
        let params = params_of(entry);
        rows.push(json!({
            "provider": data::provider_of(entry),
            "account": entry.get("account_name").and_then(|v| v.as_str()).unwrap_or(""),
            "kind": params.kind.as_str(),
            "algorithm": params.algorithm.as_str(),
            "digits": params.digits,
            // A counter-based seed has no meaningful period and a time-based one
            // has no counter. Printing both for every row would make two of the
            // four columns noise.
            "period": if params.kind == totp::Kind::Hotp { Value::Null } else { json!(params.period) },
            "counter": if params.kind == totp::Kind::Hotp { json!(params.counter) } else { Value::Null },
            "usable": ok,
            "problem": note,
        }));
    }

    let count = rows.len();
    out::ok("totp.ls", json!(rows.clone()), || {
        if count == 0 {
            println!("No entry carries a TOTP seed.");
            return;
        }
        println!(
            "{:<24} {:<22} {:<6} {:<8} {:>6} {:>8}",
            "PROVIDER", "ACCOUNT", "KIND", "ALGO", "DIGITS", "STEP/CTR"
        );
        for r in &rows {
            let flag = if r["usable"].as_bool() == Some(true) {
                ""
            } else {
                "  ⚠ unusable seed"
            };
            // Unwrapped to numbers rather than printed as `Value`: serde_json's
            // Display ignores width and alignment, so the columns under DIGITS
            // and PERIOD ran together as `6 30` under a header claiming two
            // right-aligned fields.
            // One column for two things that are never both present: a period
            // for a time-based seed, a counter position for a counter-based one.
            // `#41` is what says which is being shown.
            let step_or_counter = match r["counter"].as_u64() {
                Some(c) => format!("#{c}"),
                None => r["period"].as_u64().unwrap_or(0).to_string(),
            };
            println!(
                "{:<24} {:<22} {:<6} {:<8} {:>6} {:>8}{flag}",
                r["provider"].as_str().unwrap_or(""),
                r["account"].as_str().unwrap_or(""),
                r["kind"].as_str().unwrap_or("totp"),
                r["algorithm"].as_str().unwrap_or(""),
                r["digits"].as_u64().unwrap_or(0),
                step_or_counter,
            );
        }
    });
    Ok(())
}

/// `unv totp uri <entry> [--out FILE]` — the `otpauth://` URI, for a new phone.
///
/// The URI **is** the seed, so it obeys the export rule rather than the code
/// rule: refused to stdout (exit 9) unless `--reveal`, written in full by
/// `--out`.
pub fn cmd_uri(access: &Access, query: &str, out_path: Option<&PathBuf>) -> CliResult {
    let vault = access.load_vault_or_empty()?;
    let idx = find_entry_index(&vault, query)?;
    let entry = &data::entries(&vault)[idx];
    let (secret, params) = require_seed(entry)?;
    let stored = totp::Stored {
        secret,
        params,
        issuer: None,
        account: None,
    };
    let provider = data::provider_of(entry).to_string();
    let account = entry
        .get("account_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let uri = stored.to_uri(&provider, &account);

    match out_path {
        Some(path) => {
            crate::fmt::write_secret_file(path, &uri)?;
            out::ok(
                "totp.uri",
                json!({ "provider": provider, "written": path.display().to_string() }),
                || {
                    println!(
                        "Wrote the otpauth:// URI for '{provider}' to {}",
                        path.display()
                    )
                },
            );
        }
        None if out::revealing() => {
            out::ok(
                "totp.uri",
                json!({ "provider": provider, "uri": uri }),
                || println!("{uri}"),
            );
        }
        None => {
            return Err(out::refuse_reveal(&format!(
                "The otpauth:// URI for '{provider}' contains its seed and"
            )))
        }
    }
    Ok(())
}

/// `unv totp rm <entry>` — forget the seed.
///
/// Destructive and unrecoverable from UnENVerse's side once the last copy is
/// gone, so it goes through the same confirmation every delete does. The
/// previous value lands in `version_history`, which is the one thing standing
/// between a mis-typed provider name and a locked account.
pub fn cmd_rm(access: &Access, query: &str, yes: bool) -> CliResult {
    let mut vault = access.load_vault_or_empty()?;
    let idx = find_entry_index(&vault, query)?;
    let provider = data::provider_of(&data::entries(&vault)[idx]).to_string();
    if data::entries(&vault)[idx].get("totp_secret").is_none() {
        return Err(CliError::not_found(format!(
            "'{provider}' has no TOTP seed"
        )));
    }
    if !crate::fmt::confirm(
        &format!("Remove the TOTP seed from '{provider}'? Its history keeps the old value."),
        yes,
    )? {
        println!("Cancelled.");
        return Ok(());
    }
    if let Some(obj) = data::entries_mut(&mut vault)[idx].as_object_mut() {
        obj.remove("totp_secret");
        obj.remove("totp_algorithm");
        obj.remove("totp_digits");
        obj.remove("totp_period");
    }
    access.save(&vault)?;
    out::ok(
        "totp.rm",
        json!({ "provider": provider, "removed": true }),
        || println!("Removed the TOTP seed from '{provider}'"),
    );
    Ok(())
}

// ── Import and export ─────────────────────────────────────────────────────────

/// `unv totp import <file>` — read another authenticator's export into the vault.
///
/// The merge rules are `vault_core::totp_import::{plan, write_fields, new_entry}`
/// and not this file's: whether a working second factor survives an import must
/// not be able to differ between the terminal and the app, so the desktop
/// Import button calls the same three functions over IPC. What is left here is
/// argument handling and the report.
pub fn cmd_import(
    access: &Access,
    file: &std::path::Path,
    format: Option<&str>,
    project: Option<&str>,
    category: Option<&str>,
    force: bool,
) -> CliResult {
    use vault_core::totp_import::{self as imp, Plan};

    let text = std::fs::read_to_string(file)
        .map_err(|e| CliError::not_found(format!("Cannot read {}: {e}", file.display())))?;

    let report = match format {
        Some(raw) => {
            let f = imp::Format::parse(raw).ok_or_else(|| {
                CliError::invalid(format!(
                    "Unknown format '{raw}'. Try: otpauth (also: ente), aegis, 2fas, andotp, \
                     bitwarden, google"
                ))
            })?;
            imp::parse_as(&text, f)
        }
        None => imp::parse(&text),
    }
    .map_err(CliError::invalid)?;

    let mut vault = access.load_vault_or_empty()?;
    // A project that does not exist matches nothing in any view, so an entry
    // assigned to one simply vanishes from the grid with no explanation.
    if let Some(id) = project {
        let known = data::projects(&vault)
            .iter()
            .any(|p| p.get("id").and_then(|x| x.as_str()) == Some(id));
        if id != "Universal" && !known {
            return Err(CliError::not_found(format!(
                "No such project id: '{id}' (see `unv project ls`)"
            )));
        }
    }

    let plans = imp::plan(&data::entries(&vault), &report.items, force);

    let mut created: Vec<Value> = Vec::new();
    let mut updated: Vec<Value> = Vec::new();
    let mut unchanged: Vec<String> = Vec::new();
    let mut conflicts: Vec<Value> = Vec::new();

    for (item, plan) in report.items.iter().zip(plans.iter()) {
        let provider = item.suggested_provider();
        let account = item.account.clone().unwrap_or_default();
        match plan {
            Plan::Unchanged { .. } => unchanged.push(provider),
            Plan::Conflict { index } => {
                let entries = data::entries(&vault);
                let current = entries[*index]
                    .get("totp_secret")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                conflicts.push(json!({
                    "provider": provider,
                    "account": account,
                    // Fingerprints, never seeds: this reaches stdout, and equal
                    // fingerprints are all a caller needs to tell whether the
                    // two are the same secret.
                    "stored": out::fingerprint(&totp::normalize_b32(&current)),
                    "incoming": out::fingerprint(&item.stored.secret),
                }));
            }
            Plan::Update { index } => {
                imp::write_fields(&mut data::entries_mut(&mut vault)[*index], &item.stored);
                updated.push(json!({ "provider": provider, "account": account }));
            }
            Plan::Create => {
                let e = imp::new_entry(
                    item,
                    &uuid::Uuid::new_v4().to_string(),
                    &vault_core::iso_now(),
                    project,
                    category,
                );
                created.push(json!({ "provider": provider, "account": account }));
                data::entries_mut(&mut vault).push(e);
            }
        }
    }

    if !created.is_empty() || !updated.is_empty() {
        access.save(&vault)?;
    }

    let skipped: Vec<Value> = report
        .skipped
        .iter()
        .map(|s| json!({ "name": s.name, "reason": s.reason }))
        .collect();
    let (n_created, n_updated, n_unchanged) = (created.len(), updated.len(), unchanged.len());
    let (n_conflict, n_skipped) = (conflicts.len(), skipped.len());
    let format_name = report.format.as_str();

    out::ok(
        "totp.import",
        json!({
            "format": format_name,
            "created": created,
            "updated": updated,
            "unchanged": unchanged,
            "conflicts": conflicts,
            "skipped": skipped,
        }),
        || {
            println!(
                "Read {} usable and {n_skipped} unusable entries from a {format_name} export.",
                n_created + n_updated + n_unchanged + n_conflict
            );
            println!("  created   {n_created}");
            println!("  updated   {n_updated}");
            println!("  unchanged {n_unchanged}");
            if n_conflict > 0 {
                println!(
                    "  conflicts {n_conflict}  — these already hold a *different* seed and were left alone:"
                );
                for c in &conflicts {
                    println!(
                        "      {} ({}) stored {} vs incoming {}",
                        c["provider"].as_str().unwrap_or(""),
                        c["account"].as_str().unwrap_or(""),
                        c["stored"].as_str().unwrap_or(""),
                        c["incoming"].as_str().unwrap_or(""),
                    );
                }
                println!(
                    "      Re-run with --force to replace them; the old values stay in `entry history`."
                );
            }
            for s in &skipped {
                println!(
                    "  skipped   {} — {}",
                    s["name"].as_str().unwrap_or(""),
                    s["reason"].as_str().unwrap_or("")
                );
            }
        },
    );
    Ok(())
}

/// `unv totp export` — write every stored seed in a format another app reads.
///
/// This is a **materialising path by construction**: the file it produces is
/// nothing but seeds, so it obeys the same rule `unv backup export` and
/// `unv totp uri` do — refused to stdout (exit 9) unless `--reveal`, written
/// 0600 by `--out`.
pub fn cmd_export(
    access: &Access,
    format: &str,
    out_path: Option<&PathBuf>,
    only: Option<&str>,
) -> CliResult {
    let fmt = vault_core::totp_import::Format::parse(format).ok_or_else(|| {
        CliError::invalid(format!(
            "Unknown format '{format}'. Writable: otpauth (also: ente), aegis, 2fas"
        ))
    })?;
    if !fmt.is_exportable() {
        return Err(CliError::invalid(format!(
            "'{format}' can be imported but not written. Use otpauth, aegis or 2fas."
        )));
    }

    let vault = access.load_vault_or_empty()?;
    let needle = only.map(|s| s.to_lowercase());
    let mut items = Vec::new();
    let mut broken: Vec<Value> = Vec::new();
    for entry in &data::entries(&vault) {
        let provider = data::provider_of(entry).to_string();
        if let Some(n) = &needle {
            if !provider.to_lowercase().contains(n) {
                continue;
            }
        }
        let (secret, params) = match seed_of(entry) {
            Ok(Some(pair)) => pair,
            Ok(None) => continue,
            // One unusable seed must not make the export fail for the other
            // forty — but it must be named, or the count silently disagrees
            // with what the user expected to move to their new phone.
            Err(e) => {
                broken.push(json!({ "provider": provider, "reason": e.message }));
                continue;
            }
        };
        items.push(vault_core::totp_import::Imported {
            issuer: Some(provider),
            account: entry
                .get("account_name")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .filter(|s| !s.is_empty()),
            stored: totp::Stored {
                secret,
                params,
                issuer: None,
                account: None,
            },
            note: None,
        });
    }

    if items.is_empty() {
        return Err(CliError::not_found(
            "No entry carries a TOTP seed — nothing to export.",
        ));
    }
    let body = vault_core::totp_import::build(&items, fmt).map_err(CliError::invalid)?;
    let count = items.len();
    let fmt_name = fmt.as_str();

    match out_path {
        Some(path) => {
            crate::fmt::write_secret_file(path, &body)?;
            out::ok(
                "totp.export",
                json!({
                    "format": fmt_name,
                    "count": count,
                    "written": path.display().to_string(),
                    "unusable": broken,
                }),
                || {
                    println!("Wrote {count} seeds as {fmt_name} to {}", path.display());
                    for b in &broken {
                        println!(
                            "  skipped {} — {}",
                            b["provider"].as_str().unwrap_or(""),
                            b["reason"].as_str().unwrap_or("")
                        );
                    }
                    println!("This file is plaintext secret material. Move it and delete it.");
                },
            );
        }
        None if out::revealing() => {
            out::ok(
                "totp.export",
                json!({ "format": fmt_name, "count": count, "body": body, "unusable": broken }),
                || print!("{body}"),
            );
        }
        None => {
            return Err(out::refuse_reveal(
                "A TOTP export is nothing but seeds, and",
            ))
        }
    }
    Ok(())
}
