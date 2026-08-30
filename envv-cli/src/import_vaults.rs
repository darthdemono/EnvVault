//! Importers for other password managers — Bitwarden and 1Password.
//!
//! Both vendors export JSON. The shapes differ, so each gets a reader that
//! produces the same intermediate [`Incoming`] record, and one writer turns
//! those into vault entries. Adding a third vendor means writing a reader, not
//! touching the writer.
//!
//! Three rules the whole module follows, all of them learned from bugs this
//! project has already shipped:
//!
//! * **Upsert by identity, never append.** `envv import` used to append
//!   unconditionally, so `envv watch` added a full copy of the file to the vault
//!   on every save. Re-running an import must be a no-op.
//! * **Preview by default.** Writing a hundred entries into someone's vault
//!   because they wanted to see what would happen is not recoverable by undo.
//! * **Never print a secret.** The preview shows fingerprints, exactly as every
//!   other stdout path does.

use serde_json::{json, Value};

use crate::access::Access;
use crate::error::{CliError, CliResult};

/// One credential, normalised away from whichever vendor produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct Incoming {
    pub provider: String,
    pub secret: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
    /// `password`, `api_key`, `ssh_key`, `connection_string`, …
    pub secret_type: String,
    /// Folder / vault name at the source, kept as a category.
    pub folder: Option<String>,
}

impl Incoming {
    fn is_usable(&self) -> bool {
        !self.provider.trim().is_empty() && !self.secret.is_empty()
    }
}

fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
}

// ── Bitwarden ────────────────────────────────────────────────────────────────

/// Read a Bitwarden JSON export (`{"folders":[…],"items":[…]}`).
///
/// Bitwarden's `type` is 1=login, 2=secure note, 3=card, 4=identity. Only logins
/// and notes carry something this vault can hold; cards and identities are
/// dropped rather than mangled into an `api_key`, and the count is reported so
/// nobody believes the import was complete when it was not.
pub fn read_bitwarden(doc: &Value) -> (Vec<Incoming>, usize) {
    let folders: std::collections::HashMap<String, String> = doc
        .get("folders")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| Some((s(f.get("id"))?, s(f.get("name"))?)))
                .collect()
        })
        .unwrap_or_default();

    let mut out = Vec::new();
    let mut skipped = 0usize;
    let empty = vec![];
    for item in doc
        .get("items")
        .and_then(|i| i.as_array())
        .unwrap_or(&empty)
    {
        let name = s(item.get("name")).unwrap_or_default();
        let folder = s(item.get("folderId")).and_then(|id| folders.get(&id).cloned());
        let notes = s(item.get("notes"));
        let kind = item.get("type").and_then(|t| t.as_u64()).unwrap_or(0);

        let rec = match kind {
            1 => {
                let login = item.get("login");
                let password = s(login.and_then(|l| l.get("password")));
                let username = s(login.and_then(|l| l.get("username")));
                let totp = s(login.and_then(|l| l.get("totp")));
                let url = login
                    .and_then(|l| l.get("uris"))
                    .and_then(|u| u.as_array())
                    .and_then(|a| a.first())
                    .and_then(|u| s(u.get("uri")));
                let Some(secret) = password else {
                    skipped += 1;
                    continue;
                };
                Incoming {
                    // Classified from the value, not assumed from the vendor's
                    // category: a `postgres://` URL kept as a Bitwarden "login"
                    // is a connection string, and typing it as a password makes
                    // the entry render with the wrong fields forever.
                    secret_type: classify(&secret),
                    provider: name,
                    secret,
                    username,
                    url,
                    notes,
                    totp,
                    folder,
                }
            }
            2 => {
                // A secure note's body *is* the secret. Bitwarden keeps it in
                // `notes`, so it moves to the value and the note is cleared —
                // leaving it in both places would print it in the entry list.
                let Some(secret) = notes.clone() else {
                    skipped += 1;
                    continue;
                };
                Incoming {
                    provider: name,
                    secret,
                    username: None,
                    url: None,
                    notes: None,
                    totp: None,
                    secret_type: classify(&notes.unwrap_or_default()),
                    folder,
                }
            }
            _ => {
                skipped += 1;
                continue;
            }
        };
        if rec.is_usable() {
            out.push(rec);
        } else {
            skipped += 1;
        }
    }
    (out, skipped)
}

// ── 1Password ────────────────────────────────────────────────────────────────

/// Read a 1Password export.
///
/// Accepts both shapes the CLI produces: `op item list --format json` (a bare
/// array) and the `.1pux`-style `{"accounts":[{"vaults":[{"items":[…]}]}]}`.
/// The field model is the same underneath — an item has `fields`, each with a
/// `purpose` or `id` — so one walker handles both.
pub fn read_onepassword(doc: &Value) -> (Vec<Incoming>, usize) {
    let mut items: Vec<(&Value, Option<String>)> = Vec::new();
    if let Some(arr) = doc.as_array() {
        items.extend(arr.iter().map(|i| (i, None)));
    }
    if let Some(accounts) = doc.get("accounts").and_then(|a| a.as_array()) {
        for acct in accounts {
            for vault in acct
                .get("vaults")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
            {
                let vname = s(vault.get("attrs").and_then(|a| a.get("name")))
                    .or_else(|| s(vault.get("name")));
                for item in vault
                    .get("items")
                    .and_then(|i| i.as_array())
                    .into_iter()
                    .flatten()
                {
                    // .1pux nests the real item under `item`.
                    let inner = item.get("item").unwrap_or(item);
                    items.push((inner, vname.clone()));
                }
            }
        }
    }
    if let Some(arr) = doc.get("items").and_then(|i| i.as_array()) {
        items.extend(arr.iter().map(|i| (i, None)));
    }

    let mut out = Vec::new();
    let mut skipped = 0usize;
    for (item, vault_name) in items {
        let overview = item.get("overview");
        let title = s(item.get("title"))
            .or_else(|| s(overview.and_then(|o| o.get("title"))))
            .unwrap_or_default();
        let url = s(item.get("url")).or_else(|| s(overview.and_then(|o| o.get("url"))));

        let mut secret = None;
        let mut username = None;
        let mut totp = None;
        let mut notes = None;

        let mut consider = |f: &Value| {
            let purpose = s(f.get("purpose")).unwrap_or_default();
            let id = s(f.get("id")).unwrap_or_default();
            let label = s(f.get("label")).unwrap_or_default().to_lowercase();
            let value = s(f.get("value")).or_else(|| s(f.get("v")));
            let designation = s(f.get("designation")).unwrap_or_default();
            match (purpose.as_str(), id.as_str(), designation.as_str()) {
                ("PASSWORD", _, _) | (_, "password", _) | (_, _, "password") => {
                    secret = secret.take().or(value)
                }
                ("USERNAME", _, _) | (_, "username", _) | (_, _, "username") => {
                    username = username.take().or(value)
                }
                ("NOTES", _, _) | (_, "notesPlain", _) => notes = notes.take().or(value),
                _ => {
                    if label.contains("otp") || label.contains("one-time") {
                        totp = totp.take().or(value);
                    } else if secret.is_none()
                        && (label.contains("token")
                            || label.contains("key")
                            || label.contains("secret"))
                    {
                        secret = value;
                    }
                }
            }
        };

        for f in item
            .get("fields")
            .and_then(|f| f.as_array())
            .into_iter()
            .flatten()
        {
            consider(f);
        }
        // .1pux keeps most fields inside sections.
        for sect in item
            .get("details")
            .and_then(|d| d.get("sections"))
            .and_then(|s| s.as_array())
            .into_iter()
            .flatten()
        {
            for f in sect
                .get("fields")
                .and_then(|f| f.as_array())
                .into_iter()
                .flatten()
            {
                consider(f);
            }
        }
        if let Some(v) = s(item.get("details").and_then(|d| d.get("password"))) {
            secret = secret.or(Some(v));
        }
        if let Some(v) = s(item.get("details").and_then(|d| d.get("notesPlain"))) {
            notes = notes.or(Some(v));
        }

        let Some(secret) = secret else {
            skipped += 1;
            continue;
        };
        let rec = Incoming {
            secret_type: classify(&secret),
            provider: title,
            secret,
            username,
            url,
            notes,
            totp,
            folder: vault_name,
        };
        if rec.is_usable() {
            out.push(rec);
        } else {
            skipped += 1;
        }
    }
    (out, skipped)
}

// ── Proton Pass ──────────────────────────────────────────────────────────────

/// Read a Proton Pass JSON export.
///
/// Shape is `{"encrypted":false,"vaults":{"<id>":{"name":…,"items":[…]}}}`, and
/// each item nests the interesting parts two levels down under
/// `data.metadata` and `data.content`.
///
/// An **encrypted** export is refused rather than silently yielding nothing:
/// Proton offers both, and the encrypted one parses as perfectly valid JSON
/// with no readable items in it — so a naive reader reports "0 credentials
/// found" for a file that is full of them.
pub fn read_proton(doc: &Value) -> Result<(Vec<Incoming>, usize), String> {
    if doc.get("encrypted").and_then(|e| e.as_bool()) == Some(true) {
        return Err(
            "This Proton Pass export is encrypted. Re-export with encryption turned off \
             (Settings → Export → uncheck 'Encrypt export'), or decrypt it first — the \
             file parses as JSON either way, so this would otherwise look like an empty \
             vault."
                .to_string(),
        );
    }

    let mut out = Vec::new();
    let mut skipped = 0usize;
    let Some(vaults) = doc.get("vaults").and_then(|v| v.as_object()) else {
        return Err("No `vaults` object — this does not look like a Proton Pass export.".into());
    };

    for vault in vaults.values() {
        let vault_name = s(vault.get("name"));
        for item in vault
            .get("items")
            .and_then(|i| i.as_array())
            .into_iter()
            .flatten()
        {
            // state 2 is trashed. Importing someone's deleted credentials back
            // into a live vault is the opposite of what they asked for.
            if item.get("state").and_then(|s| s.as_u64()) == Some(2) {
                skipped += 1;
                continue;
            }
            let data = item.get("data");
            let meta = data.and_then(|d| d.get("metadata"));
            let content = data.and_then(|d| d.get("content"));
            let kind = s(data.and_then(|d| d.get("type"))).unwrap_or_default();
            let name = s(meta.and_then(|m| m.get("name"))).unwrap_or_default();
            let note = s(meta.and_then(|m| m.get("note")));

            let rec = match kind.as_str() {
                "login" => {
                    let Some(password) = s(content.and_then(|c| c.get("password"))) else {
                        skipped += 1;
                        continue;
                    };
                    // Proton splits identity across two fields and fills
                    // whichever the user gave.
                    let username = s(content.and_then(|c| c.get("itemUsername")))
                        .or_else(|| s(content.and_then(|c| c.get("itemEmail"))))
                        .or_else(|| s(content.and_then(|c| c.get("username"))));
                    let url = content
                        .and_then(|c| c.get("urls"))
                        .and_then(|u| u.as_array())
                        .and_then(|a| a.first())
                        .and_then(|u| u.as_str())
                        .map(str::to_string);
                    Incoming {
                        secret_type: classify(&password),
                        provider: name,
                        secret: password,
                        username,
                        url,
                        notes: note,
                        totp: s(content.and_then(|c| c.get("totpUri"))),
                        folder: vault_name.clone(),
                    }
                }
                "note" => {
                    let Some(secret) = note.clone() else {
                        skipped += 1;
                        continue;
                    };
                    Incoming {
                        secret_type: classify(&secret),
                        provider: name,
                        secret,
                        username: None,
                        url: None,
                        notes: None,
                        totp: None,
                        folder: vault_name.clone(),
                    }
                }
                // alias, creditCard, identity: nothing here can hold them
                // faithfully, and mangling a card number into an `api_key` is
                // worse than saying it was skipped.
                _ => {
                    skipped += 1;
                    continue;
                }
            };
            if rec.is_usable() {
                out.push(rec);
            } else {
                skipped += 1;
            }
        }
    }
    Ok((out, skipped))
}

/// Guess a secret type from the value's own shape.
///
/// Deliberately conservative: only shapes that are unambiguous. Everything else
/// is a password, because that is what a password manager mostly holds and a
/// wrong guess makes the entry render with the wrong fields.
fn classify(v: &str) -> String {
    let t = v.trim();
    if t.starts_with("-----BEGIN") {
        if t.contains("CERTIFICATE") {
            return "certificate".into();
        }
        return "ssh_key".into();
    }
    if t.starts_with("postgres://")
        || t.starts_with("postgresql://")
        || t.starts_with("mysql://")
        || t.starts_with("mongodb://")
        || t.starts_with("redis://")
    {
        return "connection_string".into();
    }
    // Issuer prefixes `enrich` already knows. Keeping the list short beats
    // duplicating that table badly.
    for p in [
        "ghp_",
        "gho_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "sk_live_",
        "sk_test_",
        "sk-ant-",
        "sk-",
        "dop_v1_",
        "npm_",
        "AKIA",
    ] {
        if t.starts_with(p) {
            return "api_key".into();
        }
    }
    "password".into()
}

// ── Writing ──────────────────────────────────────────────────────────────────

pub struct ImportOpts<'a> {
    pub apply: bool,
    pub project: Option<&'a str>,
    pub category: Option<&'a str>,
    /// Use the source folder/vault name as the category.
    pub keep_folders: bool,
}

/// Turn incoming records into vault entries.
///
/// Returns `(entries_to_write, created, updated, unchanged)`.
fn merge(
    vault: &Value,
    incoming: &[Incoming],
    opts: &ImportOpts<'_>,
) -> (Vec<Value>, usize, usize, usize) {
    let mut entries = crate::data::entries(vault).to_vec();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);

    for rec in incoming {
        let idx = entries
            .iter()
            .position(|e| crate::data::provider_of(e) == rec.provider);

        let categories: Vec<String> = opts
            .category
            .map(|c| vec![c.to_string()])
            .or_else(|| {
                opts.keep_folders
                    .then(|| rec.folder.clone().map(|f| vec![f]))
                    .flatten()
            })
            .unwrap_or_default();
        let projects = vec![opts.project.unwrap_or("Universal").to_string()];

        match idx {
            Some(i) => {
                // Upsert, not append. Importing the same export twice must not
                // double the vault — `envv import` shipped that bug once.
                let same =
                    entries[i].get("api_key").and_then(|v| v.as_str()) == Some(rec.secret.as_str());
                if same {
                    unchanged += 1;
                    continue;
                }
                entries[i]["api_key"] = json!(rec.secret);
                entries[i]["secretType"] = json!(rec.secret_type);
                if let Some(u) = &rec.username {
                    entries[i]["account_name"] = json!(u);
                }
                updated += 1;
            }
            None => {
                let mut e = json!({
                    "id": uuid::Uuid::new_v4().to_string(),
                    "provider": rec.provider,
                    "api_key": rec.secret,
                    "secretType": rec.secret_type,
                    "price_type": "free",
                    "categories": categories,
                    "projectIds": projects,
                    "scopes": [],
                    // Import time, not issue time. Bitwarden and 1Password both
                    // record a creation date, but it is the date the *other*
                    // vault first held it — carrying it over would date this
                    // entry to a history this vault does not have.
                    "created_at": vault_core::iso_now(),
                });
                if let Some(u) = &rec.username {
                    e["account_name"] = json!(u);
                }
                if let Some(u) = &rec.url {
                    e["api_url"] = json!(u);
                }
                if let Some(n) = &rec.notes {
                    e["notes"] = json!(n);
                }
                if let Some(t) = &rec.totp {
                    // Stored as a note, not as a field this vault pretends to
                    // understand: there is no TOTP support here to feed it to.
                    e["notes"] = json!(format!(
                        "{}{}TOTP secret imported: {t}",
                        rec.notes.clone().unwrap_or_default(),
                        if rec.notes.is_some() { "\n\n" } else { "" }
                    ));
                }
                entries.push(e);
                created += 1;
            }
        }
    }
    (entries, created, updated, unchanged)
}

/// `envv import bitwarden FILE` / `envv import onepassword FILE`.
pub fn run(
    access: &Access,
    vendor: &str,
    file: &std::path::Path,
    opts: &ImportOpts<'_>,
) -> CliResult {
    let raw = std::fs::read_to_string(file)
        .map_err(|e| CliError::not_found(format!("Cannot read {}: {e}", file.display())))?;
    let doc: Value = serde_json::from_str(&raw).map_err(|e| {
        CliError::invalid(format!(
            "{} is not JSON: {e}. Export from {vendor} in JSON format.",
            file.display()
        ))
    })?;

    let (incoming, skipped) = match vendor {
        "bitwarden" => read_bitwarden(&doc),
        "onepassword" => read_onepassword(&doc),
        "proton" => read_proton(&doc).map_err(CliError::invalid)?,
        other => return Err(CliError::invalid(format!("Unknown vendor '{other}'"))),
    };
    if incoming.is_empty() {
        return Err(CliError::invalid(format!(
            "No importable credentials found in {}. \
             {skipped} item(s) were skipped — cards, identities and items with no \
             password have nothing this vault can store.",
            file.display()
        )));
    }

    let vault = access.load_vault_or_empty()?;
    let (entries, created, updated, unchanged) = merge(&vault, &incoming, opts);

    let preview: Vec<Value> = incoming
        .iter()
        .map(|r| {
            json!({
                "provider": r.provider,
                "secret_type": r.secret_type,
                // Fingerprint, never the value: this is stdout.
                "fingerprint": crate::out::fingerprint(&r.secret),
                "username": r.username,
                "folder": r.folder,
            })
        })
        .collect();

    if !opts.apply {
        crate::out::ok(
            &format!("import.{vendor}"),
            json!({
                "applied": false,
                "created": created, "updated": updated, "unchanged": unchanged,
                "skipped": skipped,
                "items": preview,
            }),
            || {
                println!(
                    "{} would create, {updated} update, {unchanged} unchanged, {skipped} skipped.",
                    created
                );
                for p in &preview {
                    println!(
                        "  {:<28} {:<18} {}",
                        p["provider"].as_str().unwrap_or(""),
                        p["secret_type"].as_str().unwrap_or(""),
                        p["fingerprint"].as_str().unwrap_or("")
                    );
                }
                println!("\nNothing was written. Re-run with --apply.");
            },
        );
        return Ok(());
    }

    let mut next = vault.clone();
    next["api_keys"] = json!(entries);
    // `Access::save` is the single write point — it is also where `--dry-run`
    // is enforced, so an import that forgot the flag still cannot write.
    access.save(&next)?;

    crate::out::ok(
        &format!("import.{vendor}"),
        json!({
            "applied": true,
            "created": created, "updated": updated, "unchanged": unchanged, "skipped": skipped,
        }),
        || {
            println!("Imported: {created} created, {updated} updated, {unchanged} unchanged, {skipped} skipped.")
        },
    );
    Ok(())
}
