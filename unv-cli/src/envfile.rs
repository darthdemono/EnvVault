//! `.env` parsing, import and watch — the file-drop path from the UI.
//!
//! Also home to **the environment-variable name template** and **`.env`
//! quoting** (Phase 23, step 1). Both are twins of TypeScript in
//! `src/ts/state.ts`, pinned by `tests/fixtures/parity/env-names.json` and
//! asserted from both sides — see `unv-cli/tests/parity.rs` and
//! `tests/cli-parity.test.ts`.
//!
//! They exist twice because the app's add/edit form previews the generated name
//! as it is typed, and an IPC round trip per keystroke is not a form. Same
//! reasoning as the TOTP seed parser.

use crate::access::Access;
use crate::data::{self, entries_mut, find_project_index, projects};
use crate::error::{CliError, CliResult};
use crate::out;
use serde_json::{json, Value};
use std::path::PathBuf;

/// How a generated name is cased. `Upper` is the shell convention and the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameCase {
    Upper,
    Preserve,
    Lower,
}

/// `--env-case` / `--env-prefix`, set once from the flags. They are the CLI side of
/// the app's `envCopyCase` and `envIncludePrefix` settings, and like those they
/// govern what a *copy or export* writes. Reference resolution and `exec` keep the
/// default names: a `${SPOTIFY_ID}` must mean the same thing whatever flags a
/// run was given.
static NAMING: std::sync::OnceLock<(Option<NameCase>, bool)> = std::sync::OnceLock::new();

pub fn set_naming(case: Option<NameCase>, include_prefix: bool) {
    let _ = NAMING.set((case, include_prefix));
}

/// The case and prefix choice for exporters and the copy-profile builder.
pub fn export_naming() -> (Option<NameCase>, bool) {
    NAMING.get().copied().unwrap_or((None, false))
}

impl NameCase {
    /// Parse the `envCopyCase` setting / `--case` flag. Anything unknown is `Upper`.
    pub fn parse(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "preserve" => NameCase::Preserve,
            "lower" => NameCase::Lower,
            _ => NameCase::Upper,
        }
    }
    fn folds(self) -> bool {
        self != NameCase::Preserve
    }
}

/// Everything `env_name` needs that does not come from the entry.
#[derive(Debug, Clone, Default)]
pub struct NameOpts<'a> {
    /// The value's role — `ID`, `SECRET`, an `extra_vars` key. `None` or `value` omits it.
    pub role: Option<&'a str>,
    pub case: Option<NameCase>,
    /// Prepend `env_prefixes[0]`. Off unless asked for.
    pub include_prefix: bool,
}

/// One segment, normalised: non-alphanumerics become `_`, runs collapse, edges trim.
fn segment(raw: &str, fold: bool) -> String {
    let src = if fold {
        raw.to_uppercase()
    } else {
        raw.to_string()
    };
    let mut out = String::with_capacity(src.len());
    let mut last_us = true; // leading underscores are trimmed by never being written
    for ch in src.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_us = false;
        } else if !last_us {
            out.push('_');
            last_us = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

/// The version segment: `2`, `v2`, `V2` → `V2`; `2.0` → `V2_0`.
///
/// The leading `v` is dropped **only when a digit follows**, so the `V` is added
/// once and never doubled and a word-shaped version keeps its first letter.
pub fn version_segment(raw: &str, fold: bool) -> String {
    let trimmed = raw.trim();
    let mut chars = trimmed.chars();
    let body = match (chars.next(), chars.next()) {
        (Some(v), Some(d)) if (v == 'v' || v == 'V') && d.is_ascii_digit() => &trimmed[1..],
        _ => trimmed,
    };
    let seg = segment(body, fold);
    if seg.is_empty() {
        return seg;
    }
    if seg.starts_with(|c: char| c.is_ascii_digit()) {
        format!("V{seg}")
    } else {
        seg
    }
}

/// Strip a cookie's `__Host-` / `__Secure-` prefix. See the TypeScript twin for why.
pub fn strip_cookie_prefix(name: &str) -> &str {
    for p in ["__Host-", "__Secure-"] {
        if name.len() >= p.len() && name[..p.len()].eq_ignore_ascii_case(p) {
            return &name[p.len()..];
        }
    }
    name
}

/// The environment-variable name an entry generates for `opts.role`.
///
/// Always a legal identifier: a leading digit gains a `_`, and an entry that
/// normalises away to nothing comes back as `UNKNOWN` rather than as the empty
/// string, which would write a nameless `=value` line.
pub fn env_name(entry: &Value, opts: &NameOpts<'_>) -> String {
    let case = opts.case.unwrap_or(NameCase::Upper);
    let fold = case.folds();
    let f = |k: &str| entry.get(k).and_then(|v| v.as_str()).unwrap_or("");

    let role = match opts.role {
        Some(r) if !r.eq_ignore_ascii_case("value") => strip_cookie_prefix(r),
        _ => "",
    };
    let prefix = if opts.include_prefix {
        entry
            .get("env_prefixes")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("")
    } else {
        ""
    };
    let provider = if f("provider").is_empty() {
        "UNKNOWN"
    } else {
        f("provider")
    };

    let parts: Vec<String> = vec![
        segment(prefix, fold),
        segment(provider, fold),
        segment(f("key_id"), fold),
        version_segment(f("version"), fold),
        segment(f("label"), fold),
        segment(role, fold),
    ]
    .into_iter()
    .filter(|p| !p.is_empty())
    .collect();

    let mut name = parts.join("_");
    if name.is_empty() {
        name = "UNKNOWN".into();
    }
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        name.insert(0, '_');
    }
    if case == NameCase::Lower {
        name = name.to_lowercase();
    }
    name
}

/// The name of an entry's **primary** value.
///
/// Role-aware: an entry marked `primary_role: "id"` generates `SPOTIFY_ID`
/// rather than `SPOTIFY`, which is the reported bug Phase 23 exists to fix — an
/// OAuth client id exported as though it were the key. An entry with no
/// `primary_role` keeps the bare name, which is why the field is opt-in.
pub fn primary_name(entry: &Value, case: Option<NameCase>, include_prefix: bool) -> String {
    env_name(
        entry,
        &NameOpts {
            role: entry.get("primary_role").and_then(|v| v.as_str()),
            case,
            include_prefix,
        },
    )
}

/// The name of an entry's `api_secret` — `SECRET` unless `secret_role` says otherwise.
pub fn secret_name(entry: &Value, case: Option<NameCase>, include_prefix: bool) -> String {
    let role = entry
        .get("secret_role")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("SECRET");
    env_name(
        entry,
        &NameOpts {
            role: Some(role),
            case,
            include_prefix,
        },
    )
}

/// A name derived from a bare string rather than from an entry — a pool name, a
/// `--pool github-ci` with no explicit variable.
///
/// The same normaliser the template's segments use, so `unv exec --pool
/// github-ci` and an export of a member of that pool agree about what is a legal
/// character. It is deliberately *not* the template: a pool is not an entry and
/// has no version, label or role.
pub fn env_name_from_text(raw: &str) -> String {
    let mut name = segment(raw, true);
    if name.is_empty() {
        name = "UNKNOWN".into();
    }
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        name.insert(0, '_');
    }
    name
}

/// Every name one entry generates, in the order a copy emits them.
///
/// Twin of `namesGeneratedBy` in `src/ts/state.ts`.
pub fn names_generated_by(
    entry: &Value,
    case: Option<NameCase>,
    include_prefix: bool,
) -> Vec<(String, String)> {
    let f = |k: &str| entry.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let mut out = Vec::new();
    if !f("api_key").is_empty() {
        out.push((
            primary_name(entry, case, include_prefix),
            f("api_key").to_string(),
        ));
    }
    if !f("api_secret").is_empty() {
        out.push((
            secret_name(entry, case, include_prefix),
            f("api_secret").to_string(),
        ));
    }
    if !f("api_url").is_empty() {
        out.push((
            env_name(
                entry,
                &NameOpts {
                    role: Some("URL"),
                    case,
                    include_prefix,
                },
            ),
            f("api_url").to_string(),
        ));
    }
    if let Some(vars) = entry.get("extra_vars").and_then(|v| v.as_array()) {
        for xv in vars {
            let k = xv.get("key").and_then(|v| v.as_str()).unwrap_or("");
            if k.is_empty() {
                continue;
            }
            out.push((
                env_name(
                    entry,
                    &NameOpts {
                        role: Some(k),
                        case,
                        include_prefix,
                    },
                ),
                xv.get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            ));
        }
    }
    out
}

/// Make every name unique, **appending rather than dropping** (Phase 23, E2).
///
/// Two values generating one name is a silent overwrite in whatever loads the
/// file — every `.env` parser takes the last line, and the YAML writer keys a
/// map. One entry with `primary_role: "id"` and an `extra_vars` entry keyed `ID`
/// does it all by itself.
///
/// Compared **case-insensitively**, because Windows environment variables are
/// case-insensitive: `preserve` casing can produce a pair that collides there
/// and not on Linux, which is the worst possible place to find out.
///
/// Twin of `disambiguateNames` in `src/ts/state.ts`.
pub fn disambiguate_names(names: &[String]) -> Vec<String> {
    use std::collections::{HashMap, HashSet};
    let mut counts: HashMap<String, usize> = HashMap::new();
    for n in names {
        *counts.entry(n.to_uppercase()).or_insert(0) += 1;
    }
    // Everything already emitted, so a suffix can never collide with a name that
    // was fine on its own — appending `_2` and hitting an entry that genuinely
    // generates `X_2` would trade one silent overwrite for another.
    let mut used: HashSet<String> = names.iter().map(|n| n.to_uppercase()).collect();
    // The **first** occurrence keeps the name it generated. Renaming both halves
    // of a collision would change a variable that was never ambiguous for the
    // consumer that reads it first, which is the rename this phase's "one thing
    // this must not break" section is about.
    let mut taken: HashSet<String> = HashSet::new();

    names
        .iter()
        .map(|n| {
            let key = n.to_uppercase();
            if counts.get(&key).copied().unwrap_or(0) < 2 {
                return n.clone();
            }
            if taken.insert(key) {
                return n.clone();
            }
            // An **ordinal**, not the `key_id`. The design says pool members get
            // `_1`/`_2` and everything else gets the `key_id` — written when
            // `key_id` was not expected to be part of the generated name. Here it
            // always is (it is a segment of the template), so appending it again
            // can never disambiguate anything: the two colliding names already
            // contain it. Ordinals are stable for a given entry because the
            // emission order is.
            for i in 2..=(names.len() + 2) {
                let c = format!("{n}_{i}");
                if !used.contains(&c.to_uppercase()) {
                    used.insert(c.to_uppercase());
                    return c;
                }
            }
            n.clone()
        })
        .collect()
}

/// A value as it must appear after the `=` (E1). The one implementation lives
/// in `vault_core::env_quote`, because `vault-core`'s emitters write `.env`
/// lines too and two copies of an escaping rule is how a value gets corrupted.
pub fn quote_env_value(value: &str) -> String {
    vault_core::env_quote(value)
}

/// The inverse, applied by the parser.
///
/// Double quotes unescape, single quotes do not — which is what the shells and
/// the `dotenv` libraries these files are read by do.
pub fn unquote_env_value(raw: &str) -> String {
    let n = raw.chars().count();
    if n >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        return raw[1..raw.len() - 1].to_string();
    }
    if n >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch != '\\' {
                out.push(ch);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        }
        return out;
    }
    raw.to_string()
}

pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// Parse a `.env`, matching `parseEnvFile()` in `src/ts/import-export.ts`:
/// backslash line continuations, an optional `export ` prefix, and one layer of
/// surrounding quotes stripped.
pub fn parse_env_file(text: &str) -> Vec<EnvVar> {
    let lines: Vec<&str> = text.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let mut combined = lines[i].to_string();
        i += 1;
        while combined.trim_end().ends_with('\\') && i < lines.len() {
            let head = combined.trim_end();
            combined = format!("{}{}", &head[..head.len() - 1], lines[i].trim());
            i += 1;
        }
        let trimmed = combined.trim().to_string();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let mut name = trimmed[..eq].trim().to_string();
        if name.to_uppercase().starts_with("EXPORT ") {
            name = name[7..].trim().to_string();
        }
        // Strips the quotes *and* unescapes what the writer escaped (E1).
        let value = unquote_env_value(trimmed[eq + 1..].trim());
        if !name.is_empty() {
            out.push(EnvVar { name, value });
        }
    }
    out
}

pub struct ImportOpts<'a> {
    pub project: Option<&'a str>,
    pub category: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub price: &'a str,
    /// Append a second entry instead of updating one that already carries the key.
    pub allow_duplicates: bool,
}

/// Import a `.env` into the vault.
///
/// Existing keys are **updated** rather than appended by default. The previous
/// behaviour appended unconditionally, which made `unv watch` grow the vault by
/// a full copy of the file on every save — the command was unusable for the one
/// job it exists to do.
pub fn import(access: &Access, file: &PathBuf, opts: &ImportOpts<'_>) -> CliResult {
    let raw = std::fs::read_to_string(file)
        .map_err(|e| CliError::from(format!("Cannot read {}: {e}", file.display())))?;
    let vars = parse_env_file(&raw);
    if vars.is_empty() {
        println!("No KEY=VALUE pairs found in file.");
        return Ok(());
    }

    let mut vault = access.load_vault_or_empty()?;

    let project_ids: Vec<String> = match opts.project {
        Some(p) => {
            let pi = find_project_index(&vault, p)?;
            let id = projects(&vault)[pi]
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("Universal")
                .to_string();
            if id == "Universal" {
                vec!["Universal".into()]
            } else {
                vec![id, "Universal".into()]
            }
        }
        None => vec!["Universal".into()],
    };
    let categories: Vec<String> = opts
        .category
        .filter(|c| !c.is_empty())
        .map(|c| vec![c.to_string()])
        .unwrap_or_default();

    let mut added = 0usize;
    let mut updated = 0usize;
    for v in &vars {
        let existing = if opts.allow_duplicates {
            None
        } else {
            data::entries(&vault).iter().position(|e| {
                data::provider_of(e) == v.name
                    && e.get("secretType")
                        .and_then(|s| s.as_str())
                        .unwrap_or("api_key")
                        == "env_var"
            })
        };
        match existing {
            Some(idx) => {
                let entries = entries_mut(&mut vault);
                if entries[idx].get("api_key").and_then(|k| k.as_str()) != Some(v.value.as_str()) {
                    entries[idx]["api_key"] = json!(v.value);
                    updated += 1;
                }
            }
            None => {
                let mut entry = json!({
                    "id": uuid::Uuid::new_v4().to_string(),
                    "provider": v.name,
                    "api_key": v.value,
                    "price_type": opts.price,
                    "secretType": "env_var",
                    "categories": categories,
                    "projectIds": project_ids,
                    "scopes": [],
                    // When it entered *this* vault. An imported credential is
                    // usually older than that, and there is nothing in a .env
                    // that says how much older.
                    "created_at": vault_core::iso_now(),
                });
                if let Some(e) = opts.environment.filter(|s| !s.is_empty()) {
                    entry["environment"] = json!(e);
                }
                entries_mut(&mut vault).push(entry);
                added += 1;
            }
        }
    }

    if added == 0 && updated == 0 {
        out::ok(
            "import",
            json!({ "added": 0, "updated": 0, "parsed": vars.len(), "changed": false }),
            || println!("Nothing changed — every variable already matches the vault."),
        );
        return Ok(());
    }
    access.save(&vault)?;
    out::ok(
        "import",
        json!({ "added": added, "updated": updated, "parsed": vars.len(), "changed": true }),
        || println!("{added} added, {updated} updated from {}", file.display()),
    );
    Ok(())
}

pub fn watch(access: &Access, file: &PathBuf, opts: &ImportOpts<'_>) -> CliResult {
    use notify::{recommended_watcher, Event, RecursiveMode, Watcher};
    use std::sync::mpsc::channel;

    if !file.exists() {
        return Err(CliError::not_found(format!(
            "File not found: {}",
            file.display()
        )));
    }
    println!("Watching {} for changes (Ctrl-C to stop)…", file.display());

    let (tx, rx) = channel::<notify::Result<Event>>();
    let mut watcher = recommended_watcher(tx).map_err(|e| CliError::from(e.to_string()))?;
    watcher
        .watch(file, RecursiveMode::NonRecursive)
        .map_err(|e| CliError::from(e.to_string()))?;

    for event in rx {
        match event {
            Ok(ev) if ev.kind.is_modify() || ev.kind.is_create() => {
                println!("[{}] Change detected — syncing…", vault_core::iso_now());
                if let Err(e) = import(access, file, opts) {
                    eprintln!("Sync error: {e}");
                }
            }
            Ok(_) => {}
            Err(e) => eprintln!("Watch error: {e}"),
        }
    }
    Ok(())
}

/// Export the whole vault in one of the flat formats offered by "Export as".
pub fn export_vault(
    access: &Access,
    format: &str,
    project: Option<&str>,
    name: &str,
    out: Option<&std::path::Path>,
    profile: Option<&str>,
    metadata: Option<&str>,
) -> CliResult {
    let vault = access.load_vault()?;
    let mut list = data::entries(&vault);

    if let Some(proj) = project {
        list = data::entries_in_project(&vault, proj);
    }

    // Same rule as `project export`: values reach a file, never stdout.
    if out.is_none() && !crate::out::revealing() && format != "json" {
        return Err(crate::out::refuse_reveal("This export"));
    }
    if out.is_none() && !crate::out::revealing() && format == "json" {
        // The JSON document is the whole vault; redact it rather than refuse,
        // since its structure is what a caller usually wants to inspect.
        let safe: Vec<Value> = crate::out::redact_entries(&list);
        let doc = if project.is_some() {
            json!(safe)
        } else {
            let mut v = vault.clone();
            v["api_keys"] = json!(safe);
            if let Some(ps) = v.get("projects").and_then(|p| p.as_array()) {
                let redacted: Vec<Value> = ps.iter().map(crate::out::redact_project).collect();
                v["projects"] = json!(redacted);
            }
            v
        };
        crate::out::ok("export", doc.clone(), || {
            println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default())
        });
        return Ok(());
    }

    // `full` is refused **vault-wide**, the same way a plaintext export to
    // stdout is. One entry's metadata is a convenience; every entry's —
    // purposes, projects, tags, rotation dates — is a map of what matters in the
    // vault, and it is exactly the document you would not want copied off the
    // machine. Naming a project narrows it to something the user chose.
    if profile == Some("full") && project.is_none() {
        return Err(CliError::invalid(
            "`--profile full` is per-entry or per-project: it writes every entry's purposes, \
             projects, tags and rotation dates, which is a map of the vault. Pass --project, or \
             use `unv get <entry> --profile full`.",
        ));
    }

    let content: String = match format {
        "dotenv" if profile.is_some() => crate::profile::build_all(
            &list,
            &crate::profile::CopyOpts {
                profile: crate::profile::Profile::parse(profile.unwrap()),
                metadata: metadata
                    .map(crate::profile::MetadataStyle::parse)
                    .unwrap_or(crate::profile::MetadataStyle::Comment),
                ..Default::default()
            },
        ),
        "yaml" => crate::exporters::yaml(&list),
        // `json` exports the whole vault document (projects and categories
        // included), matching the app's "Export as JSON" — that file is what
        // `unv backup import` and the app's importer expect to read back.
        "json" => {
            if project.is_some() {
                serde_json::to_string_pretty(&list).unwrap_or_default()
            } else {
                serde_json::to_string_pretty(&vault).unwrap_or_default()
            }
        }
        "k8s" => crate::exporters::k8s_secret(&list, name),
        "tfvars" => crate::exporters::tfvars(&list),
        "dotenv" => crate::exporters::dotenv(&list),
        other => {
            return Err(CliError::invalid(format!(
                "Unknown format '{other}'. Supported: dotenv, yaml, json, k8s, tfvars."
            )))
        }
    };
    crate::fmt::emit(&content, out)
}

/// `import` for a full-vault JSON document (the app's "Export as JSON" file).
pub fn import_json(access: &Access, file: &PathBuf, yes: bool) -> CliResult {
    let raw = std::fs::read_to_string(file)
        .map_err(|e| CliError::from(format!("Cannot read {}: {e}", file.display())))?;
    let data: Value =
        serde_json::from_str(&raw).map_err(|e| CliError::from(format!("Not valid JSON: {e}")))?;
    let list = data
        .get("api_keys")
        .and_then(|v| v.as_array())
        .ok_or("Not a vault export — no api_keys array")?;
    let current = access.load_vault().ok();
    let current_n = current
        .as_ref()
        .and_then(|v| v.get("api_keys"))
        .and_then(|v| v.as_array())
        .map_or(0, |a| a.len());
    if !crate::fmt::confirm(
        &format!(
            "Replace the current vault ({current_n} entries) with {} entries from {}?",
            list.len(),
            file.display()
        ),
        yes,
    )? {
        println!("Cancelled.");
        return Ok(());
    }
    let restored = json!({
        "api_keys": data.get("api_keys").cloned().unwrap_or(json!([])),
        "user_categories": data.get("user_categories").cloned().unwrap_or(json!([])),
        "projects": data.get("projects").cloned().unwrap_or(json!([{
            "id": "Universal", "name": "Universal",
            "description": "All keys belong here by default"
        }])),
    });
    access.save(&restored)?;
    out::ok(
        "import.json",
        json!({ "entries": list.len(), "replaced": true }),
        || println!("Imported {} entries", list.len()),
    );
    Ok(())
}
