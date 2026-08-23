//! Entry CRUD — the terminal half of the add/edit form, plus the card actions
//! (pin, tag, mark rotated, mark compromised) and version history.

use crate::access::Access;
use crate::data::{self, entries_mut, find_entry_index, projects};
use crate::fmt::{confirm, fmt_entries, read_stdin};
use crate::out;
use clap::Args;
use serde_json::{json, Value};
use std::path::PathBuf;
use crate::error::{CliError, CliResult};

/// Every writable field of a `VaultEntry`, shared by `entry add` and `entry set`.
///
/// All optional: on `add` an absent flag means "leave unset", on `set` it means
/// "leave unchanged". Clearing a field is `--field ''`.
#[derive(Args, Clone, Default)]
pub struct EntryFields {
    /// Primary secret value. Use --key-stdin to keep it out of the process list.
    #[arg(long)]
    pub key: Option<String>,
    /// Read the primary secret from stdin (never appears in `ps` or shell history).
    #[arg(long, conflicts_with = "key")]
    pub key_stdin: bool,
    /// Secondary secret (client secret / shared secret).
    #[arg(long)]
    pub secret: Option<String>,
    #[arg(long)]
    pub account: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub email: Option<String>,
    #[arg(long)]
    pub key_id: Option<String>,
    /// api_key | password | certificate | env_var | connection_string | ssh_key | file_blob
    #[arg(long = "type", value_parser = SECRET_TYPES)]
    pub secret_type: Option<String>,
    /// free | local | paid | conditional
    #[arg(long, value_parser = ["free", "local", "paid", "conditional"])]
    pub price: Option<String>,
    /// production | staging | development | testing
    #[arg(long, value_parser = ["production", "staging", "development", "testing", ""])]
    pub env: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub callback_url: Option<String>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub rate_limit: Option<String>,
    /// ISO date (YYYY-MM-DD).
    #[arg(long)]
    pub expires: Option<String>,
    /// Rotation cadence in days; the health scan flags overdue entries.
    #[arg(long)]
    pub rotation_days: Option<u32>,
    /// Short "what is this for" description.
    #[arg(long)]
    pub desc: Option<String>,
    /// Longer free-text notes.
    #[arg(long)]
    pub notes: Option<String>,
    #[arg(long)]
    pub details: Option<String>,
    /// Simple Icons slug for the card icon.
    #[arg(long)]
    pub icon: Option<String>,
    /// Embed an image file (.ico, .png, .jpg, .gif, .webp, .bmp) as the icon.
    ///
    /// Stored in the vault as a data URI in the same `custom_icon` field a slug
    /// uses, so an entry can never end up with a slug and a file disagreeing.
    #[arg(long, conflicts_with = "icon")]
    pub icon_file: Option<PathBuf>,
    /// Comma-separated OAuth scopes (replaces the list).
    #[arg(long)]
    pub scopes: Option<String>,
    /// Comma-separated category names (replaces the list).
    #[arg(long)]
    pub categories: Option<String>,
    /// Comma-separated tags (replaces the list). See `entry tag` for add/remove.
    #[arg(long)]
    pub tags: Option<String>,
    /// Comma-separated project ids (replaces the list). "Universal" is always kept.
    #[arg(long)]
    pub projects: Option<String>,
    /// PEM certificate body, or @path to read a file.
    #[arg(long)]
    pub cert: Option<String>,
    /// PEM private key paired with --cert, or @path.
    #[arg(long)]
    pub cert_key: Option<String>,
    #[arg(long)]
    pub cert_issuer: Option<String>,
    /// File path for file_blob entries.
    #[arg(long)]
    pub blob_ref: Option<String>,
    /// Display hint for env_var entries.
    #[arg(long, value_parser = ENV_SUBTYPES)]
    pub env_subtype: Option<String>,
    /// Extra field as key=value. Repeatable. Prefix the key with `!` to mark it secret.
    #[arg(long = "var")]
    pub vars: Vec<String>,
    /// Comma-separated env-var prefixes (e.g. ND,SPOTIFYD).
    #[arg(long)]
    pub env_prefixes: Option<String>,

    /// Generate the secret instead of supplying one.
    ///
    /// The value is written straight into the vault and never printed — the
    /// caller learns only its fingerprint. This is how an orchestrator creates a
    /// credential it is structurally unable to leak.
    #[arg(long, conflicts_with_all = ["key", "key_stdin"])]
    pub generate: bool,
    /// Bytes of entropy for --generate (ignored for --generate-format password).
    #[arg(long, default_value_t = 32)]
    pub generate_bytes: usize,
    /// Shape of the generated secret.
    #[arg(long, default_value = "base64url", value_parser = ["hex", "base64", "base64url", "password"])]
    pub generate_format: String,
}

pub const SECRET_TYPES: [&str; 7] = [
    "api_key", "password", "certificate", "env_var", "connection_string", "ssh_key", "file_blob",
];

pub const ENV_SUBTYPES: [&str; 11] = [
    "string", "multiline", "secret", "boolean", "number", "ip", "cidr", "port", "url", "date",
    "json",
];

/// Largest embedded icon accepted, as data-URI characters. Matches
/// `MAX_ICON_CHARS` in `src/ts/icons.ts` — the app and the CLI must agree, or a
/// file one accepts renders as a broken image in the other.
const MAX_ICON_CHARS: usize = 96 * 1024;

/// Read an image file and return it as a validated `data:` URI.
///
/// The type comes from the file's magic bytes, not its extension: an entry whose
/// icon claims to be a PNG and is not simply fails to render, with nothing on
/// screen explaining why.
fn embed_icon(path: &std::path::Path) -> CliResult<String> {
    use base64::Engine;
    let bytes = std::fs::read(path)
        .map_err(|e| CliError::not_found(format!("Cannot read {}: {e}", path.display())))?;

    let mime = match bytes.as_slice() {
        [0x89, b'P', b'N', b'G', ..] => "image/png",
        [0xFF, 0xD8, 0xFF, ..] => "image/jpeg",
        [b'G', b'I', b'F', b'8', ..] => "image/gif",
        [b'B', b'M', ..] => "image/bmp",
        [0x00, 0x00, 0x01, 0x00, ..] => "image/x-icon",
        b if b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" => "image/webp",
        _ => {
            return Err(CliError::invalid(
                "Not a recognised image (expected PNG, JPEG, GIF, WebP, BMP or ICO). \
                 SVG is deliberately unsupported: it is a script-bearing format.",
            ))
        }
    };

    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let uri = format!("data:{mime};base64,{encoded}");
    if uri.len() > MAX_ICON_CHARS {
        return Err(CliError::invalid(format!(
            "Icon is too large ({} KB encoded, max {} KB) — the vault is re-serialised on every save",
            uri.len() / 1024,
            MAX_ICON_CHARS / 1024
        )));
    }
    Ok(uri)
}

/// Read a flag value, expanding a leading `@` into the contents of that file.
fn maybe_file(raw: &str) -> CliResult<String> {
    match raw.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| CliError::not_found(format!("Cannot read {path}: {e}")))
            .map(|s| s.trim_end().to_string()),
        None => Ok(raw.to_string()),
    }
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// Set a string field, or remove it when the caller passed an empty string.
fn set_str(entry: &mut Value, field: &str, value: &str) {
    if value.is_empty() {
        entry.as_object_mut().map(|o| o.remove(field));
    } else {
        entry[field] = json!(value);
    }
}

impl EntryFields {
    /// Produce the value for `--generate`.
    pub fn generate_value(&self) -> CliResult<String> {
        if self.generate_format == "password" {
            let (pw, _) = crate::gen::password(&crate::gen::PwOpts {
                length: self.generate_bytes.max(12),
                upper: true,
                lower: true,
                digits: true,
                symbols: true,
                no_ambiguous: false,
            })?;
            Ok(pw)
        } else {
            crate::gen::secret(self.generate_bytes, &self.generate_format)
        }
    }

    /// Apply every flag the caller actually passed onto `entry`.
    pub fn apply(&self, entry: &mut Value, vault_projects: &[Value]) -> CliResult {
        if self.generate {
            entry["api_key"] = json!(self.generate_value()?);
        } else if self.key_stdin {
            entry["api_key"] = json!(read_stdin()?);
        } else if let Some(v) = &self.key {
            entry["api_key"] = json!(v);
        }
        if let Some(v) = &self.secret { set_str(entry, "api_secret", v); }
        if let Some(v) = &self.account { set_str(entry, "account_name", v); }
        if let Some(v) = &self.username { set_str(entry, "username", v); }
        if let Some(v) = &self.email { set_str(entry, "email", v); }
        if let Some(v) = &self.key_id { set_str(entry, "key_id", v); }
        if let Some(v) = &self.secret_type { entry["secretType"] = json!(v); }
        if let Some(v) = &self.price { entry["price_type"] = json!(v); }
        if let Some(v) = &self.env { set_str(entry, "environment", v); }
        if let Some(v) = &self.url { set_str(entry, "api_url", v); }
        if let Some(v) = &self.callback_url { set_str(entry, "callback_url", v); }
        if let Some(v) = &self.version { set_str(entry, "version", v); }
        if let Some(v) = &self.rate_limit { set_str(entry, "rate_limit", v); }
        if let Some(v) = &self.expires { set_str(entry, "expires_at", v); }
        if let Some(v) = self.rotation_days {
            if v == 0 { entry.as_object_mut().map(|o| o.remove("rotation_days")); }
            else { entry["rotation_days"] = json!(v); }
        }
        if let Some(v) = &self.desc { set_str(entry, "api_description", v); }
        if let Some(v) = &self.notes { set_str(entry, "description", v); }
        if let Some(v) = &self.details { set_str(entry, "details", v); }
        if let Some(v) = &self.icon { set_str(entry, "custom_icon", v); }
        if let Some(path) = &self.icon_file {
            entry["custom_icon"] = json!(embed_icon(path)?);
        }
        if let Some(v) = &self.scopes { entry["scopes"] = json!(split_list(v)); }
        if let Some(v) = &self.categories { entry["categories"] = json!(split_list(v)); }
        if let Some(v) = &self.tags {
            let tags = split_list(v);
            if tags.is_empty() { entry.as_object_mut().map(|o| o.remove("tags")); }
            else { entry["tags"] = json!(tags); }
        }
        if let Some(v) = &self.cert { set_str(entry, "certificate_data", &maybe_file(v)?); }
        if let Some(v) = &self.cert_key { set_str(entry, "cert_key_data", &maybe_file(v)?); }
        if let Some(v) = &self.cert_issuer { set_str(entry, "cert_issuer", v); }
        if let Some(v) = &self.blob_ref { set_str(entry, "blob_ref", v); }
        if let Some(v) = &self.env_subtype { set_str(entry, "env_var_subtype", v); }
        if let Some(v) = &self.env_prefixes {
            let parts: Vec<String> = split_list(v)
                .into_iter()
                .map(|p| p.trim_end_matches('_').to_string())
                .filter(|p| !p.is_empty())
                .collect();
            if parts.is_empty() { entry.as_object_mut().map(|o| o.remove("env_prefixes")); }
            else { entry["env_prefixes"] = json!(parts); }
        }
        if !self.vars.is_empty() {
            let mut list: Vec<Value> = entry
                .get("extra_vars")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for raw in &self.vars {
                let (k, v) = raw
                    .split_once('=')
                    .ok_or_else(|| format!("--var expects key=value, got '{raw}'"))?;
                let (key, is_secret) = match k.strip_prefix('!') {
                    Some(stripped) => (stripped, true),
                    None => (k, false),
                };
                list.retain(|x| x.get("key").and_then(|kk| kk.as_str()) != Some(key));
                if !v.is_empty() {
                    list.push(json!({ "key": key, "value": v, "secret": is_secret }));
                }
            }
            if list.is_empty() { entry.as_object_mut().map(|o| o.remove("extra_vars")); }
            else { entry["extra_vars"] = json!(list); }
        }
        if let Some(v) = &self.projects {
            let mut ids = split_list(v);
            // A project id that does not exist matches nothing in any view, so
            // the entry would simply vanish from the grid with no explanation.
            for id in &ids {
                if id != "Universal"
                    && !vault_projects.iter().any(|p| p.get("id").and_then(|x| x.as_str()) == Some(id))
                {
                    return Err(CliError::not_found(format!("No such project id: '{id}' (see `envv project ls`)")));
                }
            }
            if !ids.iter().any(|i| i == "Universal") {
                ids.insert(0, "Universal".into());
            }
            entry["projectIds"] = json!(ids);
        }
        Ok(())
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

pub fn cmd_add(
    access: &Access,
    provider: &str,
    fields: &EntryFields,
    if_missing: bool,
) -> CliResult {
    let mut vault = access.load_vault_or_empty()?;
    let projs = projects(&vault);
    let existing = data::entries(&vault).iter().any(|e| {
        data::provider_of(e) == provider
            && e.get("key_id").and_then(|v| v.as_str())
                == fields.key_id.as_deref().filter(|s| !s.is_empty())
    });
    if existing {
        // Idempotency for orchestrators: re-running a provisioning script must
        // not be an error, but it must also not silently overwrite a secret.
        if if_missing {
            out::ok(
                "entry.add",
                json!({ "provider": provider, "created": false, "reason": "exists" }),
                || println!("'{provider}' already exists — left alone"),
            );
            return Ok(());
        }
        return Err(CliError::conflict(format!(
            "An entry named '{provider}' already exists — use `envv entry set` to change it, or pass a distinct --key-id"
        )));
    }

    let mut entry = json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "provider": provider,
        "api_key": "",
        "price_type": "free",
        "secretType": "api_key",
        "categories": [],
        "projectIds": ["Universal"],
        "scopes": [],
    });
    fields.apply(&mut entry, &projs)?;
    let fingerprint = out::fingerprint(entry.get("api_key").and_then(|v| v.as_str()).unwrap_or(""));
    let id = entry.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();

    entries_mut(&mut vault).push(entry);
    access.save(&vault)?;
    out::ok(
        "entry.add",
        json!({ "provider": provider, "id": id, "created": true, "fingerprint": fingerprint }),
        || println!("Added '{provider}' ({fingerprint})"),
    );
    Ok(())
}

pub fn cmd_set(
    access: &Access,
    query: &str,
    fields: &EntryFields,
    create: bool,
) -> CliResult {
    let mut vault = access.load_vault_or_empty()?;
    let projs = projects(&vault);
    let idx = match find_entry_index(&vault, query) {
        Ok(i) => i,
        // `--create` makes set an upsert, so a provisioning script can run once
        // or a hundred times with the same result.
        Err(e) if create && e.code == crate::error::Code::NotFound => {
            return cmd_add(access, query, fields, false);
        }
        Err(e) => return Err(e),
    };
    let mut entry = data::entries(&vault)[idx].clone();
    let before = entry.get("api_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
    fields.apply(&mut entry, &projs)?;
    // Entries written before ids existed still parse; stamp one rather than
    // leaving an entry the audit log and RBAC scoping cannot name.
    if entry.get("id").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
        entry["id"] = json!(uuid::Uuid::new_v4().to_string());
    }
    let after = entry.get("api_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let provider = data::provider_of(&entry).to_string();
    entries_mut(&mut vault)[idx] = entry;
    access.save(&vault)?;

    let changed = before != after;
    out::ok(
        "entry.set",
        json!({
            "provider": provider,
            "created": false,
            "secret_changed": changed,
            "fingerprint": out::fingerprint(&after),
        }),
        || {
            println!("Updated '{provider}'");
            if changed {
                println!("Secret now {}", out::fingerprint(&after));
            }
        },
    );
    Ok(())
}

pub fn cmd_rm(access: &Access, query: &str, yes: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let provider = data::provider_of(&data::entries(&vault)[idx]).to_string();
    if !confirm(&format!("Delete entry '{provider}'?"), yes)? {
        println!("Cancelled.");
        return Ok(());
    }
    entries_mut(&mut vault).remove(idx);
    access.save(&vault)?;
    out::ok("entry.rm", json!({ "provider": provider, "deleted": true }), || {
        println!("Deleted '{provider}'")
    });
    Ok(())
}

/// Rename an entry, carrying every `${Provider…}` chunk reference with it.
///
/// The rename cascade is not optional: references resolve by provider *name*, so
/// renaming without rewriting them leaves every `${Old/field}` in every project
/// silently unresolved, and the next export writes a literal `${…}` into a
/// config file. `${chunk:…}` refs address a chunk, not an entry, and are left alone.
pub fn cmd_rename(access: &Access, query: &str, new_name: &str) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let old = data::provider_of(&data::entries(&vault)[idx]).to_string();
    if old == new_name {
        return Ok(());
    }
    let key_id = data::entries(&vault)[idx]
        .get("key_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    entries_mut(&mut vault)[idx]["provider"] = json!(new_name);

    let mut rewritten = 0usize;
    let compound_old = if key_id.is_empty() { None } else { Some(format!("{old}_{key_id}")) };
    let compound_new = if key_id.is_empty() { None } else { Some(format!("{new_name}_{key_id}")) };

    for project in data::projects_mut(&mut vault).iter_mut() {
        let Some(chunks) = project.get_mut("chunks").and_then(|c| c.as_array_mut()) else { continue };
        for chunk in chunks.iter_mut() {
            let Some(fields) = chunk.get_mut("fields").and_then(|f| f.as_array_mut()) else { continue };
            for field in fields.iter_mut() {
                let val = match field.get("value").and_then(|v| v.as_str()) {
                    Some(v) => v.to_string(),
                    None => continue,
                };
                let Some(inner) = val.strip_prefix("${").and_then(|s| s.strip_suffix('}')) else { continue };
                if inner.starts_with("chunk:") {
                    continue;
                }
                let (head, tail) = match inner.split_once('/') {
                    Some((h, t)) => (h.to_string(), Some(t.to_string())),
                    None => (inner.to_string(), None),
                };
                let replacement = if head == old {
                    Some(new_name.to_string())
                } else if Some(head.clone()) == compound_old {
                    compound_new.clone()
                } else {
                    None
                };
                if let Some(new_head) = replacement {
                    let next = match &tail {
                        Some(t) => format!("${{{new_head}/{t}}}"),
                        None => format!("${{{new_head}}}"),
                    };
                    let ref_matches =
                        field.get("ref_name").and_then(|v| v.as_str()) == Some(head.as_str());
                    field["value"] = json!(next);
                    if ref_matches {
                        field["ref_name"] = json!(new_head);
                    }
                    rewritten += 1;
                }
            }
        }
    }

    access.save(&vault)?;
    out::ok(
        "entry.rename",
        json!({ "from": old, "to": new_name, "rewritten_refs": rewritten }),
        || {
            println!("Renamed '{old}' → '{new_name}'");
            if rewritten > 0 {
                println!("Rewrote {rewritten} chunk reference(s)");
            }
        },
    );
    Ok(())
}

pub fn cmd_tag(
    access: &Access,
    query: &str,
    add: &[String],
    remove: &[String],
) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entries = entries_mut(&mut vault);
    let mut tags: Vec<String> = entries[idx]
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect())
        .unwrap_or_default();
    for t in add {
        if !tags.iter().any(|x| x == t) {
            tags.push(t.clone());
        }
    }
    tags.retain(|t| !remove.iter().any(|r| r == t));
    if tags.is_empty() {
        entries[idx].as_object_mut().map(|o| o.remove("tags"));
    } else {
        entries[idx]["tags"] = json!(tags.clone());
    }
    access.save(&vault)?;
    let shown = tags.clone();
    out::ok("entry.tag", json!({ "tags": shown }), || {
        println!("Tags: {}", if tags.is_empty() { "(none)".to_string() } else { tags.join(", ") })
    });
    Ok(())
}

/// Toggle a boolean flag (`pinned`, `compromised`) on an entry.
pub fn cmd_flag(access: &Access, query: &str, field: &str, on: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entries = entries_mut(&mut vault);
    if on {
        entries[idx][field] = json!(true);
    } else {
        entries[idx].as_object_mut().map(|o| o.remove(field));
    }
    let provider = data::provider_of(&entries[idx]).to_string();
    access.save(&vault)?;
    out::ok("entry.flag", json!({ "provider": provider, "field": field, "value": on }), || {
        println!("{provider}: {field} = {on}")
    });
    Ok(())
}

/// Mark an entry rotated — optionally storing a new secret at the same time.
///
/// `save_vault` appends the previous value to `version_history` whenever the key
/// changes, so passing `--key` here both rotates and records.
pub fn cmd_rotate(
    access: &Access,
    query: &str,
    new_key: Option<&str>,
    from_stdin: bool,
    generate: bool,
) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entries = entries_mut(&mut vault);
    let before = entries[idx].get("api_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if generate {
        // Same shape as `entry add --generate`: the replacement is created,
        // stored and fingerprinted without ever being printed.
        let fields = EntryFields { generate: true, generate_bytes: 32, generate_format: "base64url".into(), ..Default::default() };
        entries[idx]["api_key"] = json!(fields.generate_value()?);
    } else if from_stdin {
        entries[idx]["api_key"] = json!(read_stdin()?);
    } else if let Some(k) = new_key {
        entries[idx]["api_key"] = json!(k);
    }
    let after = entries[idx].get("api_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let at = vault_core::iso_now();
    entries[idx]["last_rotated_at"] = json!(at);
    // Rotating is the answer to being compromised, so clear the flag.
    entries[idx].as_object_mut().map(|o| o.remove("compromised"));
    let provider = data::provider_of(&entries[idx]).to_string();
    access.save(&vault)?;
    out::ok(
        "entry.rotate",
        json!({
            "provider": provider,
            "rotated_at": at,
            "secret_changed": before != after,
            "fingerprint": out::fingerprint(&after),
        }),
        || {
            println!("Marked '{provider}' rotated at {at}");
            if before != after {
                println!("Secret now {}", out::fingerprint(&after));
            }
        },
    );
    Ok(())
}

pub fn cmd_history(access: &Access, query: &str) -> CliResult {
    let vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entry = &data::entries(&vault)[idx];
    let hist = entry.get("version_history").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let provider = data::provider_of(entry).to_string();
    let rotated = entry.get("last_rotated_at").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // History is a list of previous secrets. Fingerprints answer the question
    // history is actually for — "did this value change, and when?" — without
    // handing back credentials that may still be live somewhere.
    let rows: Vec<Value> = hist
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let val = h.get("value").and_then(|v| v.as_str()).unwrap_or("");
            json!({
                "version": i + 1,
                "saved_at": h.get("saved_at").and_then(|v| v.as_str()).unwrap_or(""),
                "value": if out::revealing() { json!(val) } else { out::masked_json(val) },
            })
        })
        .collect();

    out::ok(
        "entry.history",
        json!({ "provider": provider, "count": rows.len(), "last_rotated_at": rotated, "versions": rows }),
        || {
            println!("{provider} — {} previous value(s)", rows.len());
            if !rotated.is_empty() {
                println!("Last marked rotated: {rotated}");
            }
            for (i, h) in hist.iter().enumerate() {
                let when = h.get("saved_at").and_then(|v| v.as_str()).unwrap_or("?");
                let val = h.get("value").and_then(|v| v.as_str()).unwrap_or("");
                let shown = if out::revealing() { val.to_string() } else { out::masked(val) };
                println!("{:<4} {:<26} {}", i + 1, when, shown);
            }
        },
    );
    Ok(())
}

/// Restore a previous value from `version_history` by its 1-based position.
pub fn cmd_restore(access: &Access, query: &str, version: usize, yes: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let hist = data::entries(&vault)[idx]
        .get("version_history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let item = hist
        .get(version.checked_sub(1).ok_or("Versions are numbered from 1")?)
        .ok_or_else(|| format!("No version {version} — history holds {}", hist.len()))?;
    let value = item.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let provider = data::provider_of(&data::entries(&vault)[idx]).to_string();
    if !confirm(&format!("Restore '{provider}' to version {version}?"), yes)? {
        println!("Cancelled.");
        return Ok(());
    }
    entries_mut(&mut vault)[idx]["api_key"] = json!(value);
    access.save(&vault)?;
    out::ok(
        "entry.restore",
        json!({ "provider": provider, "version": version, "fingerprint": out::fingerprint(&value) }),
        || println!("Restored '{provider}' to version {version}"),
    );
    Ok(())
}

/// `entry ls` with the filters the sidebar offers.
pub fn cmd_list(
    access: &Access,
    project: Option<&str>,
    type_filter: Option<&str>,
    tag: Option<&str>,
    env: Option<&str>,
    category: Option<&str>,
    search: Option<&str>,
    json_out: bool,
) -> CliResult {
    let vault = access.load_vault()?;
    let mut list = data::entries(&vault);

    if let Some(proj) = project {
        let proj_lc = proj.to_lowercase();
        let matching_ids: Vec<String> = projects(&vault)
            .iter()
            .filter(|p| {
                p.get("id").and_then(|i| i.as_str()) == Some(proj)
                    || p.get("name")
                        .and_then(|n| n.as_str())
                        .map_or(false, |n| n.to_lowercase().contains(&proj_lc))
            })
            .filter_map(|p| p.get("id").and_then(|i| i.as_str()).map(String::from))
            .collect();
        list.retain(|e| {
            e.get("projectIds").and_then(|v| v.as_array()).map_or(false, |ids| {
                ids.iter().any(|id| matching_ids.iter().any(|m| Some(m.as_str()) == id.as_str()))
            })
        });
    }
    if let Some(t) = type_filter {
        list.retain(|e| e.get("secretType").and_then(|v| v.as_str()).unwrap_or("api_key") == t);
    }
    if let Some(t) = tag {
        list.retain(|e| {
            e.get("tags")
                .and_then(|v| v.as_array())
                .map_or(false, |a| a.iter().any(|x| x.as_str() == Some(t)))
        });
    }
    if let Some(v) = env {
        list.retain(|e| e.get("environment").and_then(|x| x.as_str()) == Some(v));
    }
    if let Some(c) = category {
        list.retain(|e| {
            e.get("categories")
                .and_then(|v| v.as_array())
                .map_or(false, |a| a.iter().any(|x| x.as_str() == Some(c)))
        });
    }
    if let Some(q) = search {
        let q = q.to_lowercase();
        list.retain(|e| {
            let hay = format!(
                "{} {} {} {}",
                data::provider_of(e),
                e.get("account_name").and_then(|v| v.as_str()).unwrap_or(""),
                e.get("api_description").and_then(|v| v.as_str()).unwrap_or(""),
                e.get("description").and_then(|v| v.as_str()).unwrap_or(""),
            );
            hay.to_lowercase().contains(&q)
        });
    }

    // Redaction happens here, once, on the way out — not at each call site, so
    // a new command cannot forget it.
    let safe = out::redact_entries(&list);
    if json_out || out::is_json() {
        out::ok("entry.ls", json!({ "count": safe.len(), "entries": safe }), || {});
        return Ok(());
    }
    if list.is_empty() {
        println!("No entries found.");
    } else {
        fmt_entries(&list);
        println!("\n{} entries", list.len());
    }
    Ok(())
}

pub fn cmd_get(access: &Access, query: &str, field: Option<&str>) -> CliResult {
    let vault = access.load_vault()?;
    if let Some(f) = field {
        let idx = find_entry_index(&vault, query)?;
        let entry = &data::entries(&vault)[idx];
        let val = crate::refs::entry_field(entry, f)
            .ok_or_else(|| CliError::not_found(format!("Entry has no field '{f}'")))?;
        // A named field is very often the secret itself, so the same rule
        // applies: fingerprint unless the caller asked to reveal.
        let secret_field = SECRET_FIELD_NAMES.contains(&crate::refs::canonical_field(f));
        let shown = if secret_field && !out::revealing() { out::masked(&val) } else { val.clone() };
        out::ok(
            "entry.get",
            json!({
                "provider": data::provider_of(entry),
                "field": crate::refs::canonical_field(f),
                "value": if secret_field && !out::revealing() { out::masked_json(&val) } else { json!(val) },
            }),
            || println!("{shown}"),
        );
        return Ok(());
    }
    let q = query.to_lowercase();
    let found: Vec<Value> = data::entries(&vault)
        .into_iter()
        .filter(|e| data::provider_of(e).to_lowercase().contains(&q))
        .collect();
    if found.is_empty() {
        return Err(CliError::not_found(format!("No entry matching '{query}'")));
    }
    let safe = out::redact_entries(&found);
    out::ok("entry.get", json!({ "count": safe.len(), "entries": safe }), || {
        for e in &safe {
            println!("{}", serde_json::to_string_pretty(e).unwrap_or_default());
        }
    });
    Ok(())
}

/// Entry fields whose contents are secret material.
const SECRET_FIELD_NAMES: [&str; 4] = ["api_key", "api_secret", "certificate_data", "cert_key_data"];

/// Every tag in the vault with its entry count — the sidebar's tag section.
pub fn cmd_tags(access: &Access) -> CliResult {
    let vault = access.load_vault()?;
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for e in data::entries(&vault) {
        for t in e.get("tags").and_then(|v| v.as_array()).into_iter().flatten() {
            if let Some(s) = t.as_str() {
                *counts.entry(s.to_string()).or_insert(0) += 1;
            }
        }
    }
    let rows: Vec<Value> =
        counts.iter().map(|(tag, n)| json!({ "tag": tag, "entry_count": n })).collect();
    out::ok("tags", json!({ "count": rows.len(), "tags": rows }), || {
        if counts.is_empty() {
            println!("No tags.");
            return;
        }
        for (tag, n) in &counts {
            println!("{}  {n}", crate::fmt::cell(tag, 30));
        }
    });
    Ok(())
}
