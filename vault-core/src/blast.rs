//! Phase 36 — blast radius (ADR-0142).
//!
//! After a compromise the question is always *which credentials were on that
//! machine, and when?* It is never answerable, so the honest answer becomes
//! "rotate everything", so nobody does. This module answers it from three things
//! the vault already keeps:
//!
//! - the hub's audit chain says which files a node **applied** and when
//!   (`node.apply` rows, Phase 34);
//! - the config history says what each of those files **contained**, as the list
//!   of vault secrets whose exact value appears in it (`exposed`, Phase 36), kept
//!   per snapshot because by the time of a compromise the entry may have been
//!   rotated, edited or deleted;
//! - the vault says which of those values are **still current**, by fingerprint.
//!
//! The pure logic lives here so it is testable without a database; callers
//! supply the three lookups.
//!
//! # What it cannot know, and says so
//!
//! A file applied before the history existed, or whose snapshot was pruned, has
//! no recorded contents: it is reported as *unaccounted* rather than silently
//! dropped, because "nothing was exposed" would be a lie. A pull target's file
//! was never rendered by the hub, so it is not covered at all.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A secret whose exact value appeared in a rendered file or an environment.
/// Stored with the snapshot (or the local log) at the moment it was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposed {
    pub entry_id: String,
    pub provider: String,
    #[serde(default)]
    pub key_id: String,
    /// Which part of the entry matched: `api_key`, `api_secret`,
    /// `extra_vars/NAME`, `version_history`, …
    pub field: String,
    /// Fingerprint of the value that matched (`out::fingerprint`), so "is it
    /// still the live value" is a comparison and not a guess from timestamps.
    pub fp: String,
    /// Under 8 characters: it may be a coincidence of text rather than a leak.
    /// Still reported, because a missed exposure is the failure that matters.
    #[serde(default)]
    pub short: bool,
}

/// One thing a host received.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Deployment {
    pub at: String,
    /// A node target id, or `exec` / `file` / … for a local materialisation.
    pub via: String,
    /// SHA-256 of the file, for a node deployment.
    pub sha256: String,
    pub ok: bool,
    pub error: Option<String>,
}

/// What the vault holds for an entry now.
#[derive(Debug, Clone, Default)]
pub struct CurrentEntry {
    pub provider: String,
    pub key_id: String,
    /// Fingerprints of every present (not historical) secret value.
    pub fps: Vec<String>,
    pub console_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EntryExposure {
    pub entry_id: String,
    pub provider: String,
    pub key_id: String,
    pub fields: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub times: usize,
    /// The value that was on the host is still the entry's value, so it still
    /// opens whatever it opened: rotate it.
    pub still_current: bool,
    /// The entry no longer exists in the vault.
    pub removed: bool,
    pub short: bool,
    pub console_url: Option<String>,
    pub via: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub host: String,
    pub since: Option<String>,
    pub deployments: usize,
    /// Deployments with no recorded contents.
    pub unaccounted: Vec<Deployment>,
    pub entries: Vec<EntryExposure>,
    /// Entries to rotate: still current, in the order listed.
    pub rotate: Vec<String>,
    /// One command that rotates exactly those and nothing else.
    pub command: String,
}

/// True when a failed apply still put the new file on disk for a moment (it
/// was written, then restored). A refused or hash-mismatched one never was.
pub fn failed_apply_touched_disk(error: &str) -> bool {
    error.contains("validate failed") || error.contains("reload failed")
}

fn entry_label(provider: &str, key_id: &str) -> String {
    if key_id.is_empty() {
        provider.to_string()
    } else {
        format!("{provider}:{key_id}")
    }
}

/// A shell-safe single-quoted word, or `None` when the name has a quote in it
/// (quoting differs between shells, and a wrong guess runs the wrong command).
fn quote(s: &str) -> Option<String> {
    if s.contains(['\'', '"', '\n', '\r', '\0']) {
        None
    } else {
        Some(format!("'{s}'"))
    }
}

/// Builds the report. `deployments` are what the host received, `lookup` maps a
/// file hash to what it contained (`None` = not recorded), `current` maps an
/// entry id to what the vault holds now (`None` = deleted).
pub fn report(
    host: &str,
    since: Option<&str>,
    deployments: &[Deployment],
    lookup: &dyn Fn(&Deployment) -> Option<Vec<Exposed>>,
    current: &dyn Fn(&str) -> Option<CurrentEntry>,
) -> Report {
    let mut unaccounted = Vec::new();
    let mut by_entry: BTreeMap<String, EntryExposure> = BTreeMap::new();
    let mut counted = 0usize;

    for d in deployments {
        if since.is_some_and(|s| d.at.as_str() < s) {
            continue;
        }
        if !d.ok && !d.error.as_deref().is_some_and(failed_apply_touched_disk) {
            continue;
        }
        counted += 1;
        let Some(exposed) = lookup(d) else {
            unaccounted.push(d.clone());
            continue;
        };
        for e in exposed {
            let cur = current(&e.entry_id);
            let still = cur.as_ref().is_some_and(|c| c.fps.contains(&e.fp));
            let slot = by_entry
                .entry(e.entry_id.clone())
                .or_insert_with(|| EntryExposure {
                    entry_id: e.entry_id.clone(),
                    provider: e.provider.clone(),
                    key_id: e.key_id.clone(),
                    fields: Vec::new(),
                    first_seen: d.at.clone(),
                    last_seen: d.at.clone(),
                    times: 0,
                    still_current: false,
                    removed: cur.is_none(),
                    short: true,
                    console_url: cur.as_ref().and_then(|c| c.console_url.clone()),
                    via: Vec::new(),
                });
            if !slot.fields.contains(&e.field) {
                slot.fields.push(e.field.clone());
            }
            if d.at < slot.first_seen {
                slot.first_seen = d.at.clone();
            }
            if d.at > slot.last_seen {
                slot.last_seen = d.at.clone();
            }
            slot.times += 1;
            // One exposed value that is still live is enough to need a rotation.
            slot.still_current |= still;
            slot.short &= e.short;
            if !slot.via.contains(&d.via) {
                slot.via.push(d.via.clone());
            }
            // Use the live name where there is one: the entry may have been renamed.
            if let Some(c) = &cur {
                slot.provider.clone_from(&c.provider);
                slot.key_id.clone_from(&c.key_id);
            }
        }
    }

    let mut entries: Vec<EntryExposure> = by_entry.into_values().collect();
    entries.sort_by(|a, b| {
        b.still_current
            .cmp(&a.still_current)
            .then_with(|| a.provider.to_lowercase().cmp(&b.provider.to_lowercase()))
            .then_with(|| a.key_id.cmp(&b.key_id))
    });
    let rotate: Vec<String> = entries
        .iter()
        .filter(|e| e.still_current)
        .map(|e| entry_label(&e.provider, &e.key_id))
        .collect();
    let mut parts = Vec::new();
    for label in &rotate {
        match quote(label) {
            Some(q) => parts.push(format!("unv entry rotate {q} --generate")),
            None => parts.push(format!(
                "# cannot quote this name safely, rotate it by hand: {label}"
            )),
        }
    }
    Report {
        host: host.to_string(),
        since: since.map(String::from),
        deployments: counted,
        unaccounted,
        entries,
        rotate,
        command: parts.join("; "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exp(id: &str, provider: &str, field: &str, fp: &str) -> Exposed {
        Exposed {
            entry_id: id.into(),
            provider: provider.into(),
            key_id: String::new(),
            field: field.into(),
            fp: fp.into(),
            short: false,
        }
    }

    fn dep(at: &str, via: &str, sha: &str) -> Deployment {
        Deployment {
            at: at.into(),
            via: via.into(),
            sha256: sha.into(),
            ok: true,
            error: None,
        }
    }

    fn cur(provider: &str, fps: &[&str]) -> Option<CurrentEntry> {
        Some(CurrentEntry {
            provider: provider.into(),
            key_id: String::new(),
            fps: fps.iter().map(|s| s.to_string()).collect(),
            console_url: Some("https://console.example/keys".into()),
        })
    }

    #[test]
    fn a_still_live_secret_is_rotated_and_a_rotated_away_one_is_not() {
        let deps = [dep("2026-10-01T00:00:00Z", "nginx", "h1")];
        let lookup = |_: &Deployment| {
            Some(vec![
                exp("e1", "Stripe", "api_key", "fp-live"),
                exp("e2", "GitHub", "api_key", "fp-old"),
            ])
        };
        let current = |id: &str| match id {
            "e1" => cur("Stripe", &["fp-live"]),
            "e2" => cur("GitHub", &["fp-new"]), // rotated since the file was written
            _ => None,
        };
        let r = report("vps-01", None, &deps, &lookup, &current);
        assert_eq!(r.rotate, vec!["Stripe"]);
        assert_eq!(r.command, "unv entry rotate 'Stripe' --generate");
        let github = r.entries.iter().find(|e| e.provider == "GitHub").unwrap();
        assert!(
            !github.still_current,
            "a value rotated away needs no rotation"
        );
        assert!(
            r.entries[0].still_current,
            "still-current entries sort first"
        );
    }

    #[test]
    fn a_deleted_entry_is_reported_but_never_in_the_rotate_command() {
        let deps = [dep("2026-10-01T00:00:00Z", "nginx", "h1")];
        let lookup = |_: &Deployment| Some(vec![exp("gone", "Old", "api_key", "fp")]);
        let r = report("h", None, &deps, &lookup, &|_| None);
        assert_eq!(r.entries.len(), 1);
        assert!(r.entries[0].removed);
        assert!(r.rotate.is_empty());
        assert_eq!(r.command, "");
    }

    #[test]
    fn a_deployment_with_no_recorded_contents_is_unaccounted_not_silently_clean() {
        let deps = [dep("2026-10-01T00:00:00Z", "nginx", "unknown-hash")];
        let r = report("h", None, &deps, &|_| None, &|_| None);
        assert_eq!(r.unaccounted.len(), 1);
        assert_eq!(r.deployments, 1);
        assert!(r.entries.is_empty());
    }

    #[test]
    fn since_filters_by_time_and_the_window_is_inclusive() {
        let deps = [
            dep("2026-09-01T00:00:00Z", "a", "h1"),
            dep("2026-10-01T00:00:00Z", "b", "h2"),
        ];
        let lookup = |d: &Deployment| {
            Some(vec![exp(
                if d.sha256 == "h1" { "old" } else { "new" },
                "P",
                "api_key",
                "fp",
            )])
        };
        let r = report("h", Some("2026-10-01T00:00:00Z"), &deps, &lookup, &|id| {
            cur(id, &["fp"])
        });
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].entry_id, "new");
    }

    #[test]
    fn repeated_exposures_collapse_into_one_row_with_a_count_and_a_range() {
        let deps = [
            dep("2026-10-03T00:00:00Z", "nginx", "h2"),
            dep("2026-10-01T00:00:00Z", "nginx", "h1"),
            dep("2026-10-02T00:00:00Z", "env", "h3"),
        ];
        let lookup = |_: &Deployment| Some(vec![exp("e1", "Stripe", "api_key", "fp")]);
        let r = report("h", None, &deps, &lookup, &|_| cur("Stripe", &["fp"]));
        assert_eq!(r.entries.len(), 1);
        let e = &r.entries[0];
        assert_eq!(
            (e.times, e.first_seen.as_str(), e.last_seen.as_str()),
            (3, "2026-10-01T00:00:00Z", "2026-10-03T00:00:00Z")
        );
        assert_eq!(e.via, vec!["nginx", "env"]);
    }

    #[test]
    fn a_failed_apply_counts_only_when_the_file_reached_the_disk() {
        let mut validate = dep("2026-10-01T00:00:00Z", "t", "h1");
        validate.ok = false;
        validate.error = Some("validate failed, previous file restored: x".into());
        let mut refused = dep("2026-10-01T00:00:00Z", "t", "h2");
        refused.ok = false;
        refused.error =
            Some("content does not match the hash the hub announced; nothing was written".into());
        let lookup = |_: &Deployment| Some(vec![exp("e1", "Stripe", "api_key", "fp")]);
        let r = report("h", None, &[validate, refused], &lookup, &|_| {
            cur("Stripe", &["fp"])
        });
        assert_eq!(r.deployments, 1, "the refused one never touched the disk");
        assert_eq!(r.entries[0].times, 1);
    }

    #[test]
    fn a_name_that_cannot_be_quoted_is_left_for_a_human_not_guessed() {
        let deps = [dep("2026-10-01T00:00:00Z", "t", "h")];
        let lookup = |_: &Deployment| Some(vec![exp("e1", "O'Brien", "api_key", "fp")]);
        let r = report("h", None, &deps, &lookup, &|_| cur("O'Brien", &["fp"]));
        assert!(r.command.starts_with("# cannot quote"), "{}", r.command);
        assert!(!r.command.contains("unv entry rotate"));
    }

    #[test]
    fn a_renamed_entry_is_listed_under_its_current_name() {
        let deps = [dep("2026-10-01T00:00:00Z", "t", "h")];
        let lookup = |_: &Deployment| Some(vec![exp("e1", "OldName", "api_key", "fp")]);
        let r = report("h", None, &deps, &lookup, &|_| cur("NewName", &["fp"]));
        assert_eq!(r.rotate, vec!["NewName"]);
    }

    #[test]
    fn short_only_matches_are_marked_short() {
        let deps = [dep("2026-10-01T00:00:00Z", "t", "h")];
        let mut e = exp("e1", "P", "api_key", "fp");
        e.short = true;
        let lookup = move |_: &Deployment| Some(vec![e.clone()]);
        let r = report("h", None, &deps, &lookup, &|_| cur("P", &["fp"]));
        assert!(r.entries[0].short);
    }
}
