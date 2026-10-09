//! FIDO Credential Exchange (CXF) import and export — Phase 24.5.
//!
//! CXF (FIDO Alliance) is the JSON format password managers are converging on
//! for moving credentials between products. This is the one place it is read
//! or written: `unv-cli` calls it directly, and the desktop app reaches it
//! over IPC, the same split TOTP import/export already uses and for the same
//! reason — six formats parsed twice is six chances for the app and the CLI
//! to disagree about what a file meant.
//!
//! # What this is modelled from, and what that means
//!
//! Built from the public CXF field tables (`Item`, `Collection`, the
//! `basic-auth` / `api-key` / `totp` / `note` / `wifi` / `ssh-key` /
//! `custom-fields` credential shapes) rather than against a corpus of real
//! exports from other managers — the design's own note said to check which
//! managers emit a CXF **file** today before building this, and that check is
//! still outstanding. Treat the shape here as a reasonable-effort reading of
//! the spec, not a verified interop guarantee, until it has been run against
//! a real export from at least one other product.
//!
//! # The mapping
//!
//! An `Item` with **one** credential becomes a plain entry. An `Item` with
//! **several** becomes a Phase 24.1 bundle: one `secretType: "bundle"` parent
//! plus one member per non-`custom-fields` credential. CXF custom fields become
//! the bundle's local variables, so they can participate in scoped templates
//! rather than appearing as a fake member.
//!
//! A `totp` credential never becomes its own entry: it is Phase 22's stored
//! seed, a field *on* whichever entry the rest of the item produced, matching
//! how this project already refuses to give TOTP its own `SecretType`.
//!
//! Every UnENVerse type without a native CXF shape — the majority of the 26 in
//! `secret_types` — exports as `custom-fields` carrying an
//! `_unenverse_type` field, so another manager sees labelled fields and
//! UnENVerse-to-UnENVerse round-trips losslessly. Import of `custom-fields`
//! reads `_unenverse_type` back when present and falls back to `extra_vars`
//! otherwise, so a CXF file honestly written by some other tool still imports
//! as something rather than being refused.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ── The CXF document shape ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
pub struct CxfDocument {
    #[serde(default)]
    pub items: Vec<CxfItem>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct CxfItem {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub favorite: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<CxfScope>,
    #[serde(default)]
    pub credentials: Vec<CxfCredential>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct CxfScope {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum CxfCredential {
    BasicAuth {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        password: String,
    },
    ApiKey {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expiry_date: Option<String>,
    },
    Totp {
        secret: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        period: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        digits: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        algorithm: Option<String>,
    },
    Note {
        content: String,
    },
    Wifi {
        ssid: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network_security_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        hidden: bool,
    },
    SshKey {
        private_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
    },
    #[serde(rename = "custom-fields")]
    CustomFields {
        fields: Vec<CxfField>,
    },
}

#[derive(Serialize, Deserialize)]
pub struct CxfField {
    pub name: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_type: Option<String>,
}

// ── Export: our entries → a CXF document ───────────────────────────────────

fn s(entry: &Value, key: &str) -> Option<String> {
    entry
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn has_totp(entry: &Value) -> bool {
    s(entry, "totp_secret").is_some()
}

fn totp_credential(entry: &Value) -> CxfCredential {
    CxfCredential::Totp {
        secret: s(entry, "totp_secret").unwrap_or_default(),
        issuer: s(entry, "provider"),
        username: s(entry, "account_name"),
        period: entry.get("totp_period").and_then(|v| v.as_u64()),
        digits: entry
            .get("totp_digits")
            .and_then(|v| v.as_u64())
            .map(|d| d as u32),
        algorithm: s(entry, "totp_algorithm"),
    }
}

/// Every field CXF has no native slot for, as `custom-fields`, tagged with the
/// UnENVerse type so a re-import (from this program or another UnENVerse
/// instance) recovers it exactly. This is the fallback every type without a
/// native mapping below uses, and it is what keeps the export lossless.
fn custom_fields_credential(entry: &Value) -> CxfCredential {
    let mut fields = Vec::new();
    let secret_type = s(entry, "secretType").unwrap_or_else(|| "api_key".to_string());
    fields.push(CxfField {
        name: "_unenverse_type".to_string(),
        value: secret_type,
        field_type: None,
    });
    for key in [
        "api_key",
        "api_secret",
        "api_url",
        "key_id",
        "user_agent",
        "mount_path",
        "composite_template",
        "connection_string_note",
    ] {
        if let Some(v) = s(entry, key) {
            fields.push(CxfField {
                name: key.to_string(),
                value: v,
                field_type: None,
            });
        }
    }
    if let Some(vars) = entry.get("extra_vars").and_then(|v| v.as_array()) {
        for var in vars {
            let (Some(key), Some(value)) = (
                var.get("key").and_then(|v| v.as_str()),
                var.get("value").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            fields.push(CxfField {
                name: key.to_string(),
                value: value.to_string(),
                field_type: None,
            });
        }
    }
    CxfCredential::CustomFields { fields }
}

/// CXF has no bundle-level fields; this extension preserves parent locals.
const BUNDLE_LOCAL_ESCAPE: &str = "__unenverse_local__";

fn encode_bundle_local_name(name: &str) -> String {
    if name == "_unenverse_type"
        || name == "_unenverse_bundle"
        || name.starts_with(BUNDLE_LOCAL_ESCAPE)
    {
        format!("{BUNDLE_LOCAL_ESCAPE}{name}")
    } else {
        name.to_string()
    }
}

fn decode_bundle_local_name(name: &str) -> &str {
    name.strip_prefix(BUNDLE_LOCAL_ESCAPE).unwrap_or(name)
}

fn bundle_locals_credential(entry: Option<&Value>) -> CxfCredential {
    let mut fields = vec![CxfField {
        name: "_unenverse_bundle".into(),
        value: "true".into(),
        field_type: None,
    }];
    if let Some(vars) = entry
        .and_then(|value| value.get("extra_vars"))
        .and_then(Value::as_array)
    {
        fields.extend(vars.iter().filter_map(|var| {
            Some(CxfField {
                name: encode_bundle_local_name(var.get("key")?.as_str()?),
                value: var.get("value")?.as_str()?.to_string(),
                field_type: None,
            })
        }));
    }
    CxfCredential::CustomFields { fields }
}

/// One entry's non-TOTP credential, native where a mapping exists in
/// `secret_types.json`, `custom-fields` otherwise.
fn native_credential(entry: &Value) -> CxfCredential {
    match s(entry, "secretType").as_deref() {
        Some("password") => CxfCredential::BasicAuth {
            username: s(entry, "account_name"),
            password: s(entry, "api_key").unwrap_or_default(),
        },
        Some("api_key") | Some("registry_token") | Some("local_service") => CxfCredential::ApiKey {
            key: s(entry, "api_key").unwrap_or_default(),
            username: s(entry, "account_name"),
            key_type: s(entry, "secretType"),
            url: s(entry, "api_url"),
            expiry_date: s(entry, "expires_at"),
        },
        Some("secure_note") => CxfCredential::Note {
            content: s(entry, "description")
                .or_else(|| s(entry, "api_key"))
                .unwrap_or_default(),
        },
        Some("ssh_key") => CxfCredential::SshKey {
            private_key: s(entry, "api_key").unwrap_or_default(),
            public_key: s(entry, "api_secret"),
        },
        Some("wifi") => CxfCredential::Wifi {
            ssid: s(entry, "account_name")
                .or_else(|| s(entry, "provider"))
                .unwrap_or_default(),
            network_security_type: extra_var(entry, "security"),
            passphrase: s(entry, "api_key"),
            hidden: extra_var(entry, "hidden").as_deref() == Some("true"),
        },
        _ => custom_fields_credential(entry),
    }
}

fn extra_var(entry: &Value, key: &str) -> Option<String> {
    entry
        .get("extra_vars")
        .and_then(|v| v.as_array())
        .and_then(|a| {
            a.iter()
                .find(|var| var.get("key").and_then(|v| v.as_str()) == Some(key))
        })
        .and_then(|var| var.get("value").and_then(|v| v.as_str()))
        .map(str::to_string)
}

fn item_from_entry(entry: &Value) -> CxfItem {
    let mut credentials = vec![native_credential(entry)];
    if has_totp(entry) {
        credentials.push(totp_credential(entry));
    }
    let urls = s(entry, "api_url").into_iter().collect::<Vec<_>>();
    CxfItem {
        id: s(entry, "id").unwrap_or_default(),
        title: s(entry, "provider").unwrap_or_default(),
        subtitle: s(entry, "account_name"),
        favorite: entry
            .get("pinned")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        tags: entry
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        scope: if urls.is_empty() {
            None
        } else {
            Some(CxfScope { urls })
        },
        credentials,
    }
}

/// Builds a CXF document from a slice of entries (`VaultData.api_keys`).
///
/// Bundle members (`bundle_id` set) are grouped into one multi-credential
/// `Item` per bundle; the bundle's own parent entry contributes the item's
/// title but no credential of its own — a `bundle` entry's payload is its
/// members, not a value in `api_key`.
pub fn export(entries: &[Value]) -> CxfDocument {
    let mut bundles: std::collections::BTreeMap<String, Vec<&Value>> = Default::default();
    let mut bundle_parents: std::collections::HashMap<String, &Value> = Default::default();
    let mut standalone = Vec::new();

    for e in entries {
        if s(e, "secretType").as_deref() == Some("bundle") {
            if let Some(id) = s(e, "id") {
                bundle_parents.insert(id.clone(), e);
                bundles.entry(id).or_default();
            }
            continue;
        }
        match s(e, "bundle_id") {
            Some(bid) => bundles.entry(bid).or_default().push(e),
            None => standalone.push(e),
        }
    }

    let mut items: Vec<CxfItem> = standalone.iter().map(|e| item_from_entry(e)).collect();
    for (bundle_id, members) in bundles {
        let mut credentials = vec![bundle_locals_credential(
            bundle_parents.get(&bundle_id).copied(),
        )];
        for m in &members {
            credentials.push(native_credential(m));
            if has_totp(m) {
                credentials.push(totp_credential(m));
            }
        }
        items.push(CxfItem {
            id: bundle_id.clone(),
            title: bundle_parents
                .get(&bundle_id)
                .and_then(|parent| s(parent, "provider"))
                .unwrap_or_else(|| "Bundle".to_string()),
            subtitle: None,
            favorite: false,
            tags: Vec::new(),
            scope: None,
            credentials,
        });
    }

    CxfDocument { items }
}

// ── Import: a CXF document → our entries ───────────────────────────────────

/// One imported entry, or two when an `Item` held several non-TOTP
/// credentials (a bundle parent plus its members).
fn entries_from_item(item: &CxfItem, mut new_id: impl FnMut() -> String, now: &str) -> Vec<Value> {
    let non_totp: Vec<&CxfCredential> = item
        .credentials
        .iter()
        .filter(|c| !matches!(c, CxfCredential::Totp { .. }))
        .collect();
    let totp: Option<&CxfCredential> = item
        .credentials
        .iter()
        .find(|c| matches!(c, CxfCredential::Totp { .. }));
    let is_bundle = non_totp.iter().any(|credential| match credential {
        CxfCredential::CustomFields { fields } => fields
            .iter()
            .any(|field| field.name == "_unenverse_bundle" && field.value == "true"),
        _ => false,
    });

    let apply_totp = |entry: &mut Value| {
        if let Some(CxfCredential::Totp {
            secret,
            period,
            digits,
            algorithm,
            ..
        }) = totp
        {
            entry["totp_secret"] = json!(secret);
            if let Some(p) = period {
                entry["totp_period"] = json!(p);
            }
            if let Some(d) = digits {
                entry["totp_digits"] = json!(d);
            }
            if let Some(a) = algorithm {
                entry["totp_algorithm"] = json!(a);
            }
        }
    };

    if non_totp.is_empty() {
        // A TOTP-only item (rare, but the format allows it): a seed with
        // nowhere else to live, exactly what Phase 22's import produces for
        // the same case — an entry with an empty primary.
        let mut entry = base_entry(&new_id(), &item.title, "password", now);
        apply_totp(&mut entry);
        return vec![entry];
    }

    if non_totp.len() == 1 && !is_bundle {
        let mut entry = entry_from_credential(&new_id(), &item.title, non_totp[0], now);
        apply_totp(&mut entry);
        return vec![entry];
    }

    // Several non-TOTP credentials: a bundle. The TOTP credential (if any)
    // attaches to the first member — CXF gives no stronger signal for which
    // login it belongs to, and the alternative is dropping it.
    let bundle_id = new_id();
    let mut members = Vec::new();
    let mut local_vars = Vec::new();
    for credential in non_totp {
        match credential {
            CxfCredential::CustomFields { fields } => local_vars.extend(
                fields
                    .iter()
                    .filter(|field| {
                        field.name != "_unenverse_type" && field.name != "_unenverse_bundle"
                    })
                    .map(|field| {
                        json!({ "key": decode_bundle_local_name(&field.name), "value": field.value })
                    }),
            ),
            _ => members.push(credential),
        }
    }
    let mut out = vec![json!({
        "id": bundle_id,
        "provider": item.title,
        "api_key": "",
        "price_type": "free",
        "secretType": "bundle",
        "categories": [],
        "scopes": [],
        "projectIds": ["Universal"],
        "extra_vars": local_vars,
        "created_at": now,
    })];
    for (i, cred) in members.iter().enumerate() {
        let mut member = entry_from_credential(&new_id(), &item.title, cred, now);
        member["bundle_id"] = json!(bundle_id);
        member["bundle_slot"] = json!(cxf_credential_kind(cred));
        member["bundle_order"] = json!((i as i64) * 10);
        if i == 0 {
            apply_totp(&mut member);
        }
        out.push(member);
    }
    out
}

fn cxf_credential_kind(c: &CxfCredential) -> &'static str {
    match c {
        CxfCredential::BasicAuth { .. } => "basic-auth",
        CxfCredential::ApiKey { .. } => "api-key",
        CxfCredential::Totp { .. } => "totp",
        CxfCredential::Note { .. } => "note",
        CxfCredential::Wifi { .. } => "wifi",
        CxfCredential::SshKey { .. } => "ssh-key",
        CxfCredential::CustomFields { .. } => "custom-fields",
    }
}

fn base_entry(id: &str, title: &str, secret_type: &str, now: &str) -> Value {
    json!({
        "id": id,
        "provider": title,
        "api_key": "",
        "price_type": "free",
        "secretType": secret_type,
        "categories": [],
        "scopes": [],
        "projectIds": ["Universal"],
        "extra_vars": [],
        "created_at": now,
    })
}

fn entry_from_credential(id: &str, title: &str, cred: &CxfCredential, now: &str) -> Value {
    match cred {
        CxfCredential::BasicAuth { username, password } => {
            let mut e = base_entry(id, title, "password", now);
            e["api_key"] = json!(password);
            if let Some(u) = username {
                e["account_name"] = json!(u);
            }
            e
        }
        CxfCredential::ApiKey {
            key,
            username,
            key_type,
            url,
            expiry_date,
        } => {
            let secret_type = key_type
                .as_deref()
                .filter(|t| crate::secret_types::find(t).is_some())
                .unwrap_or("api_key");
            let mut e = base_entry(id, title, secret_type, now);
            e["api_key"] = json!(key);
            if let Some(u) = username {
                e["account_name"] = json!(u);
            }
            if let Some(u) = url {
                e["api_url"] = json!(u);
            }
            if let Some(x) = expiry_date {
                e["expires_at"] = json!(x);
            }
            e
        }
        CxfCredential::Note { content } => {
            let mut e = base_entry(id, title, "secure_note", now);
            e["description"] = json!(content);
            e
        }
        CxfCredential::SshKey {
            private_key,
            public_key,
        } => {
            let mut e = base_entry(id, title, "ssh_key", now);
            e["api_key"] = json!(private_key);
            if let Some(p) = public_key {
                e["api_secret"] = json!(p);
            }
            e
        }
        CxfCredential::Wifi {
            ssid,
            network_security_type,
            passphrase,
            hidden,
        } => {
            let mut e = base_entry(id, ssid, "wifi", now);
            e["account_name"] = json!(ssid);
            if let Some(p) = passphrase {
                e["api_key"] = json!(p);
            }
            let mut vars = vec![];
            if let Some(sec) = network_security_type {
                vars.push(json!({ "key": "security", "value": sec }));
            }
            if *hidden {
                vars.push(json!({ "key": "hidden", "value": "true" }));
            }
            e["extra_vars"] = json!(vars);
            e
        }
        CxfCredential::CustomFields { fields } => {
            let unenverse_type = fields
                .iter()
                .find(|f| f.name == "_unenverse_type")
                .map(|f| f.value.as_str())
                .filter(|t| crate::secret_types::find(t).is_some())
                .unwrap_or("api_key");
            let mut e = base_entry(id, title, unenverse_type, now);
            let mut vars = vec![];
            for f in fields {
                if f.name == "_unenverse_type" {
                    continue;
                }
                match f.name.as_str() {
                    "api_key" | "api_secret" | "api_url" | "key_id" | "user_agent"
                    | "mount_path" | "composite_template" => {
                        e[&f.name] = json!(f.value);
                    }
                    _ => vars.push(json!({ "key": f.name, "value": f.value })),
                }
            }
            e["extra_vars"] = json!(vars);
            e
        }
        CxfCredential::Totp { .. } => unreachable!("filtered out before this point"),
    }
}

/// Parses and converts a whole document. `new_id`/`now` are injected the way
/// every other importer in this project injects them — determinism for
/// tests, and one clock rather than each entry stamping its own.
pub fn import(doc: &CxfDocument, mut new_id: impl FnMut() -> String, now: &str) -> Vec<Value> {
    doc.items
        .iter()
        .flat_map(|item| entries_from_item(item, &mut new_id, now))
        .collect()
}

/// Parses a CXF JSON document from bytes.
pub fn parse(bytes: &[u8]) -> Result<CxfDocument, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("Not a readable CXF file: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> impl FnMut() -> String {
        let mut n = 0;
        move || {
            n += 1;
            format!("id-{n}")
        }
    }

    #[test]
    fn a_password_entry_round_trips_through_basic_auth() {
        let entry = json!({
            "id": "e1", "provider": "GitHub", "account_name": "octocat",
            "api_key": "hunter2", "secretType": "password",
        });
        let doc = export(std::slice::from_ref(&entry));
        assert_eq!(doc.items.len(), 1);
        let imported = import(&doc, ids(), "2026-01-01T00:00:00Z");
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0]["provider"], "GitHub");
        assert_eq!(imported[0]["account_name"], "octocat");
        assert_eq!(imported[0]["api_key"], "hunter2");
        assert_eq!(imported[0]["secretType"], "password");
    }

    #[test]
    fn a_totp_seed_attaches_to_its_entry_rather_than_becoming_one() {
        let entry = json!({
            "id": "e1", "provider": "GitHub", "api_key": "hunter2",
            "secretType": "password", "totp_secret": "JBSWY3DPEHPK3PXP",
        });
        let doc = export(std::slice::from_ref(&entry));
        assert_eq!(doc.items[0].credentials.len(), 2);
        let imported = import(&doc, ids(), "2026-01-01T00:00:00Z");
        assert_eq!(imported.len(), 1, "the seed must not become its own entry");
        assert_eq!(imported[0]["totp_secret"], "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn a_type_with_no_native_mapping_round_trips_through_custom_fields() {
        let entry = json!({
            "id": "e1", "provider": "Postgres", "secretType": "database",
            "api_key": "postgres://…", "extra_vars": [
                { "key": "host", "value": "db.internal" },
            ],
        });
        let doc = export(std::slice::from_ref(&entry));
        match &doc.items[0].credentials[0] {
            CxfCredential::CustomFields { fields } => {
                assert!(fields
                    .iter()
                    .any(|f| f.name == "_unenverse_type" && f.value == "database"));
            }
            _ => panic!("expected custom-fields"),
        }
        let imported = import(&doc, ids(), "2026-01-01T00:00:00Z");
        assert_eq!(imported[0]["secretType"], "database");
        assert_eq!(imported[0]["api_key"], "postgres://…");
        let vars = imported[0]["extra_vars"].as_array().unwrap();
        assert!(vars
            .iter()
            .any(|v| v["key"] == "host" && v["value"] == "db.internal"));
    }

    #[test]
    fn several_credentials_on_one_item_import_as_a_bundle() {
        let doc = CxfDocument {
            items: vec![CxfItem {
                id: "item-1".into(),
                title: "Spotify".into(),
                subtitle: None,
                favorite: false,
                tags: vec![],
                scope: None,
                credentials: vec![
                    CxfCredential::BasicAuth {
                        username: Some("me".into()),
                        password: "pw".into(),
                    },
                    CxfCredential::ApiKey {
                        key: "client-secret".into(),
                        username: None,
                        key_type: Some("api_key".into()),
                        url: None,
                        expiry_date: None,
                    },
                ],
            }],
        };
        let imported = import(&doc, ids(), "2026-01-01T00:00:00Z");
        assert_eq!(imported.len(), 3, "one bundle parent + two members");
        assert_eq!(imported[0]["secretType"], "bundle");
        assert_eq!(imported[1]["bundle_id"], imported[0]["id"]);
        assert_eq!(imported[2]["bundle_id"], imported[0]["id"]);
    }

    #[test]
    fn cxf_custom_fields_become_bundle_locals_not_a_member() {
        let doc = CxfDocument {
            items: vec![CxfItem {
                id: "item-1".into(),
                title: "Discord bot".into(),
                subtitle: None,
                favorite: false,
                tags: vec![],
                scope: None,
                credentials: vec![
                    CxfCredential::ApiKey {
                        key: "bot-token".into(),
                        username: None,
                        key_type: Some("api_key".into()),
                        url: None,
                        expiry_date: None,
                    },
                    CxfCredential::CustomFields {
                        fields: vec![
                            CxfField {
                                name: "application_id".into(),
                                value: "9007199254740993".into(),
                                field_type: Some("text".into()),
                            },
                            CxfField {
                                name: "_unenverse_type".into(),
                                value: "api_key".into(),
                                field_type: None,
                            },
                        ],
                    },
                ],
            }],
        };
        let imported = import(&doc, ids(), "2026-01-01T00:00:00Z");
        assert_eq!(imported.len(), 2, "bundle parent plus actual credential");
        assert_eq!(imported[0]["secretType"], "bundle");
        assert_eq!(imported[0]["extra_vars"][0]["key"], "application_id");
        assert_eq!(imported[0]["extra_vars"][0]["value"], "9007199254740993");
        assert_eq!(imported[1]["bundle_id"], imported[0]["id"]);
    }

    #[test]
    fn parsing_junk_bytes_refuses_rather_than_panics() {
        assert!(parse(b"{not json").is_err());
    }

    #[test]
    fn exporting_a_bundle_and_reimporting_keeps_membership() {
        let bundle = json!({
            "id": "b1", "provider": "Spotify", "secretType": "bundle",
            "extra_vars": [{ "key": "region", "value": "eu-west" }],
        });
        let m1 = json!({
            "id": "m1", "provider": "Spotify", "secretType": "password",
            "api_key": "pw", "bundle_id": "b1",
        });
        let m2 = json!({
            "id": "m2", "provider": "Spotify", "secretType": "api_key",
            "api_key": "sk", "bundle_id": "b1",
        });
        let doc = export(&[bundle, m1, m2]);
        assert_eq!(doc.items.len(), 1);
        assert_eq!(doc.items[0].credentials.len(), 3);
        let imported = import(&doc, ids(), "2026-01-01T00:00:00Z");
        assert_eq!(imported.len(), 3);
        assert_eq!(imported[0]["extra_vars"][0]["key"], "region");
        assert_eq!(imported[0]["extra_vars"][0]["value"], "eu-west");
    }

    #[test]
    fn empty_bundle_with_locals_round_trips_as_a_bundle() {
        let bundle = json!({
            "id": "b1", "provider": "Discord", "secretType": "bundle",
            "extra_vars": [
                { "key": "guild_id", "value": "123" },
                { "key": "_unenverse_bundle", "value": "true" },
            ],
        });
        let doc = export(&[bundle]);
        assert_eq!(doc.items[0].credentials.len(), 1);
        let imported = import(&doc, ids(), "2026-01-01T00:00:00Z");
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0]["secretType"], "bundle");
        assert_eq!(imported[0]["extra_vars"][0]["key"], "guild_id");
        assert_eq!(imported[0]["extra_vars"][1]["key"], "_unenverse_bundle");
        assert_eq!(imported[0]["extra_vars"][1]["value"], "true");
    }
}
