//! Copy profiles — how much of an entry a copy or an export actually emits.
//!
//! Phase 23, step 3. The twin of `src/ts/copy-profile.ts`, pinned by
//! `tests/fixtures/parity/copy-profiles.json` and asserted from both sides.
//!
//! | Profile    | Emits |
//! | ---------- | ----- |
//! | `basic`    | Primary value, `api_secret`, `api_url`, every `extra_vars` entry. |
//! | `extended` | `basic` + version, expiry, rate limit, scopes, environment, account, pool. |
//! | `full`     | `extended` + description, purpose, tags, categories, projects, timestamps, rotation, compromised. |
//!
//! **Metadata is comments by default.** A `.env` is loaded into a process, and
//! injecting six non-functional variables per credential into every container is
//! a cost nobody asked for by pressing Copy. `--metadata var` is the opt-in.
//!
//! **This emits real values, and that is deliberate.** There is no masker and no
//! reveal flag here: redaction is the caller's job and it is decided by the
//! Phase 14 rule that already governs every other artefact — refuse to stdout
//! unless `--reveal`, write the real thing with `--out`. A second redaction
//! policy living in here is the shape that produced the two-lists-of-secret-fields
//! leak in Phase 22.

use crate::envfile::{env_name, quote_env_value, NameCase, NameOpts};
use serde_json::Value;

/// How much of an entry a copy emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Basic,
    Extended,
    Full,
}

impl Profile {
    /// Parse `--profile`. Anything unknown is `Basic`, which is the cheapest and
    /// the least surprising answer.
    pub fn parse(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "extended" => Profile::Extended,
            "full" => Profile::Full,
            _ => Profile::Basic,
        }
    }
}

/// Where the metadata goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataStyle {
    Comment,
    Var,
}

impl MetadataStyle {
    pub fn parse(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "var" => MetadataStyle::Var,
            _ => MetadataStyle::Comment,
        }
    }
}

/// Everything the builder needs beyond the entry itself.
#[derive(Debug, Clone)]
pub struct CopyOpts {
    pub profile: Profile,
    pub metadata: MetadataStyle,
    pub case: Option<NameCase>,
    pub include_prefix: bool,
}

impl Default for CopyOpts {
    fn default() -> Self {
        Self {
            profile: Profile::Basic,
            metadata: MetadataStyle::Comment,
            case: crate::envfile::export_naming().0,
            include_prefix: crate::envfile::export_naming().1,
        }
    }
}

fn s<'a>(e: &'a Value, k: &str) -> &'a str {
    e.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

fn join(e: &Value, k: &str) -> String {
    e.get(k)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

/// The metadata a profile adds, in a **fixed** order — it is asserted byte for
/// byte from two implementations, and an order that depends on key iteration
/// produces a diff every time anybody touches the type.
fn meta_for(entry: &Value, profile: Profile) -> Vec<(String, String)> {
    if profile == Profile::Basic {
        return Vec::new();
    }
    let rl = crate::ratelimit::normalize(entry);
    let mut out: Vec<(String, String)> = vec![
        ("VERSION".into(), s(entry, "version").to_string()),
        ("EXPIRES_AT".into(), s(entry, "expires_at").to_string()),
        (
            "RATE_LIMIT".into(),
            rl.legacy.clone().or(rl.note.clone()).unwrap_or_default(),
        ),
        ("SCOPES".into(), join(entry, "scopes")),
        ("ENVIRONMENT".into(), s(entry, "environment").to_string()),
        ("ACCOUNT".into(), s(entry, "account_name").to_string()),
        ("POOL".into(), s(entry, "pool").to_string()),
    ];

    if profile == Profile::Full {
        let projects = entry
            .get("projectIds")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    // "Universal" is the catch-all every entry carries, so
                    // listing it says nothing about this one.
                    .filter(|x| !x.is_empty() && *x != "Universal")
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        out.extend([
            ("DESCRIPTION".into(), s(entry, "description").to_string()),
            ("PURPOSE".into(), s(entry, "purpose").to_string()),
            ("TAGS".into(), join(entry, "tags")),
            ("CATEGORIES".into(), join(entry, "categories")),
            ("PROJECTS".into(), projects),
            ("CREATED_AT".into(), s(entry, "created_at").to_string()),
            (
                "LAST_ROTATED_AT".into(),
                s(entry, "last_rotated_at").to_string(),
            ),
            (
                "ROTATION_DAYS".into(),
                entry
                    .get("rotation_days")
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
            ),
            // Only when true. `COMPROMISED=false` on every entry is noise, and
            // the one entry where it matters would be invisible among them.
            (
                "COMPROMISED".into(),
                if entry
                    .get("compromised")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    "true".into()
                } else {
                    String::new()
                },
            ),
        ]);
    }

    out.retain(|(_, v)| !v.is_empty());
    out
}

/// The identity header — present in every profile, `basic` included.
///
/// It is what the entry *is* rather than metadata about it, and the `.env`
/// exporter has written it since Phase 3. Dropping it from `basic` would make
/// the cheapest profile the only one whose output does not say which credential
/// it holds.
fn header_for(entry: &Value) -> String {
    let provider = match s(entry, "provider") {
        "" => "UNKNOWN",
        p => p,
    };
    let mut bits = vec![provider.to_string()];
    if !s(entry, "label").is_empty() {
        bits.push(format!("— {}", s(entry, "label")));
    }
    if !s(entry, "account_name").is_empty() {
        bits.push(format!("— {}", s(entry, "account_name")));
    }
    if !s(entry, "version").is_empty() {
        bits.push(format!("({})", s(entry, "version")));
    }
    format!("# {}", bits.join(" "))
}

/// Build the `.env` text for one entry at the given profile.
pub fn build(entry: &Value, opts: &CopyOpts) -> String {
    let name = |role: Option<&str>| {
        env_name(
            entry,
            &NameOpts {
                role,
                case: opts.case,
                include_prefix: opts.include_prefix,
            },
        )
    };

    let mut lines = vec![header_for(entry)];
    let meta = meta_for(entry, opts.profile);

    if opts.metadata == MetadataStyle::Comment {
        for (role, value) in &meta {
            lines.push(format!("# {}: {value}", role.to_lowercase()));
        }
    }

    // Names are disambiguated **within the entry** before anything is written
    // (E2): one entry with `primary_role: "id"` and an `extra_vars` entry keyed
    // `ID` emits `SPOTIFY_ID` twice by itself, and every `.env` parser takes the
    // last — so the user loses a variable and is told nothing.
    //
    // An entry may also legitimately have no primary value — an authenticator
    // seed on its own is one (Phase 22), and an `env_var` entry's payload is
    // entirely named variables. `names_generated_by` omits an empty slot rather
    // than writing `SPOTIFY=`, which means "set to the empty string" in a file
    // about to be loaded.
    let generated = crate::envfile::names_generated_by(entry, opts.case, opts.include_prefix);
    let raw_names: Vec<String> = generated.iter().map(|(n, _)| n.clone()).collect();
    let unique = crate::envfile::disambiguate_names(&raw_names);
    for (n, (_, value)) in unique.iter().zip(generated.iter()) {
        lines.push(format!("{n}={}", quote_env_value(value)));
    }

    if opts.metadata == MetadataStyle::Var {
        for (role, value) in &meta {
            lines.push(format!("{}={}", name(Some(role)), quote_env_value(value)));
        }
    }

    lines.join("\n")
}

/// The whole selection, blank-line separated.
pub fn build_all(entries: &[Value], opts: &CopyOpts) -> String {
    entries
        .iter()
        .map(|e| build(e, opts))
        .collect::<Vec<_>>()
        .join("\n\n")
}
