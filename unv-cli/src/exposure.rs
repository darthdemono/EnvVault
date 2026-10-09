//! Phase 36 — which vault secrets appear, by exact value, in some text.
//!
//! The same exact-value idea as `unv shield` (Phase 26): the matcher is built
//! from values the vault actually holds, so a hit is an exposure rather than a
//! guess. This one keeps *which entry and which field* matched, and the
//! fingerprint of the matched value, because blast radius has to name the
//! credential and decide later whether that value is still the live one.

use crate::data;
use crate::out;
use aho_corasick::AhoCorasick;
use serde_json::Value;
use std::collections::BTreeMap;
use vault_core::blast::Exposed;

/// Shorter than this may be a coincidence of text. Still reported (a missed
/// exposure is the failure that matters), but marked.
pub const SHORT: usize = 8;

pub struct Matcher {
    ac: Option<AhoCorasick>,
    /// One value can belong to several entries (two keys pasted twice), so each
    /// pattern carries every owner.
    owners: Vec<Vec<Exposed>>,
}

impl Matcher {
    pub fn from_vault(vault: &Value) -> Self {
        let mut by_value: BTreeMap<String, Vec<Exposed>> = BTreeMap::new();
        for e in data::entries(vault) {
            let id = e.get("id").and_then(Value::as_str).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            let provider = data::provider_of(&e).to_string();
            let key_id = e
                .get("key_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            for (field, value) in out::secret_pairs(&e) {
                if value.is_empty() {
                    continue;
                }
                let x = Exposed {
                    entry_id: id.to_string(),
                    provider: provider.clone(),
                    key_id: key_id.clone(),
                    field,
                    fp: out::fingerprint(&value),
                    short: value.chars().count() < SHORT,
                };
                let owners = by_value.entry(value).or_default();
                if !owners.contains(&x) {
                    owners.push(x);
                }
            }
        }
        let (values, owners): (Vec<String>, Vec<Vec<Exposed>>) = by_value.into_iter().unzip();
        let ac = (!values.is_empty())
            .then(|| AhoCorasick::new(&values).expect("vault strings build a matcher"));
        Self { ac, owners }
    }

    /// Every secret whose value appears in `text`, once each.
    pub fn find(&self, text: &str) -> Vec<Exposed> {
        let Some(ac) = &self.ac else {
            return Vec::new();
        };
        let mut seen = vec![false; self.owners.len()];
        for m in ac.find_overlapping_iter(text) {
            seen[m.pattern().as_usize()] = true;
        }
        let mut out: Vec<Exposed> = Vec::new();
        for (i, hit) in seen.iter().enumerate() {
            if *hit {
                out.extend(self.owners[i].iter().cloned());
            }
        }
        out.sort_by(|a, b| (&a.entry_id, &a.field).cmp(&(&b.entry_id, &b.field)));
        out
    }
}

/// What the vault holds for each entry now, for the "is it still live" check.
pub fn current_map(vault: &Value) -> BTreeMap<String, vault_core::blast::CurrentEntry> {
    let mut map = BTreeMap::new();
    for e in data::entries(vault) {
        let Some(id) = e.get("id").and_then(Value::as_str) else {
            continue;
        };
        // History values are values the entry no longer holds, so they are not
        // "current": a file carrying one is exactly the rotated-away case.
        let fps = out::secret_pairs(&e)
            .into_iter()
            .filter(|(f, v)| f != "version_history" && !v.is_empty())
            .map(|(_, v)| out::fingerprint(&v))
            .collect();
        map.insert(
            id.to_string(),
            vault_core::blast::CurrentEntry {
                provider: data::provider_of(&e).to_string(),
                key_id: e
                    .get("key_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                fps,
                console_url: e
                    .get("console_url")
                    .and_then(Value::as_str)
                    .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
                    .map(String::from),
            },
        );
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vault() -> Value {
        json!({ "api_keys": [
            { "id": "e1", "provider": "Stripe", "key_id": "live", "api_key": "sk_live_abcdef123456",
              "extra_vars": [{ "key": "WEBHOOK", "value": "whsec_zzzzzzzzzz" }, { "key": "REGION", "value": "eu", "public": true }],
              "version_history": [{ "value": "sk_live_OLDOLDOLDOLD", "field": "api_key" }] },
            { "id": "e2", "provider": "Twin", "api_key": "shared-secret-value" },
            { "id": "e3", "provider": "Twin2", "api_key": "shared-secret-value" },
            { "id": "e4", "provider": "Tiny", "api_key": "qzq" }
        ]})
    }

    #[test]
    fn it_names_the_entry_and_the_field_that_matched() {
        let m = Matcher::from_vault(&vault());
        let hits = m.find("KEY=sk_live_abcdef123456\nWH=whsec_zzzzzzzzzz");
        let fields: Vec<(&str, &str)> = hits
            .iter()
            .map(|h| (h.entry_id.as_str(), h.field.as_str()))
            .collect();
        assert_eq!(
            fields,
            vec![("e1", "api_key"), ("e1", "extra_vars/WEBHOOK")]
        );
        assert_eq!(hits[0].key_id, "live");
        assert_eq!(hits[0].fp, out::fingerprint("sk_live_abcdef123456"));
        assert!(!hits[0].short);
    }

    #[test]
    fn a_rotated_away_value_in_the_text_matches_its_history_not_the_live_field() {
        let m = Matcher::from_vault(&vault());
        let hits = m.find("old=sk_live_OLDOLDOLDOLD");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].field, "version_history");
        let cur = &current_map(&vault())["e1"];
        assert!(
            !cur.fps.contains(&hits[0].fp),
            "a history value must not count as current"
        );
    }

    #[test]
    fn a_value_two_entries_share_names_both() {
        let hits = Matcher::from_vault(&vault()).find("x shared-secret-value y");
        let ids: Vec<&str> = hits.iter().map(|h| h.entry_id.as_str()).collect();
        assert_eq!(ids, vec!["e2", "e3"]);
    }

    #[test]
    fn public_values_and_text_without_secrets_match_nothing_and_short_values_are_marked() {
        let m = Matcher::from_vault(&vault());
        assert!(m.find("REGION=eu nothing here").is_empty());
        let tiny = m.find("qzq");
        assert_eq!(tiny.len(), 1);
        assert!(tiny[0].short);
        assert!(Matcher::from_vault(&json!({ "api_keys": [] }))
            .find("anything")
            .is_empty());
    }

    #[test]
    fn only_http_console_links_are_carried() {
        let v = json!({ "api_keys": [
            { "id": "a", "provider": "A", "api_key": "k", "console_url": "https://x.example/keys" },
            { "id": "b", "provider": "B", "api_key": "k", "console_url": "javascript:alert(1)" }
        ]});
        let m = current_map(&v);
        assert!(m["a"].console_url.is_some());
        assert!(m["b"].console_url.is_none());
    }
}
