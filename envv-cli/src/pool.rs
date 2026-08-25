//! Key pools: several interchangeable credentials for one service, swapped
//! between so a caller can keep working when one is rate limited.
//!
//! # Membership is explicit
//!
//! An entry joins a pool by carrying `"pool": "<name>"`. Two keys for the same
//! provider do **not** pool automatically. That is deliberate: `envv get GitHub`
//! refusing an ambiguous match is what stops a command from silently acting on
//! a credential the caller did not mean, and quietly turning that refusal into
//! "pick one" would undo it everywhere at once, including for `entry rm`.
//!
//! # State lives here, not in the vault
//!
//! Cursor, cooldowns and use counts are written to `pools.json` in the CLI's
//! per-user state directory — never to the vault. Three reasons, in order of how
//! badly the alternative fails:
//!
//! 1. `save_vault` appends a `vault_audit` row on every update. A CI loop
//!    calling `envv exec` would grow the hash-chained log without bound, which
//!    is exactly why read events stopped being audited.
//! 2. `save_vault` is a compare-and-swap. Concurrent `envv get` calls against
//!    one vault would collide and start returning conflicts (exit 6) for reads.
//! 3. A vault is shared; a rotation cursor is not. Two CI runners pulling from
//!    the same remote vault want independent cursors, not a shared one they
//!    fight over.
//!
//! The cost is that the cursor is per-machine: two runners each start at the
//! first key. For spreading load across N keys that is fine — and it is the
//! honest trade, not an oversight.

use crate::error::{CliError, CliResult};
use crate::out;
use serde_json::{json, Value};

// The state file itself — its path, shape, permissions and cooldown arithmetic —
// lives in `vault_core::pool`, because the desktop app reads the same file. Two
// implementations of one format drift silently; this module keeps only what is
// CLI-specific (resolving members against a vault, the selection rule, and the
// commands).
use vault_core::pool as state;

/// A member of a pool, resolved against the vault and its stored state.
#[derive(Debug, Clone)]
pub struct Member {
    /// Index into `vault["api_keys"]`. Valid only for the vault it was resolved
    /// against — never stored, never held across a write.
    pub idx: usize,
    /// Stable identity, and the key this member's state is filed under.
    pub ck: String,
    pub provider: String,
    pub key_id: String,
    pub uses: u64,
    /// RFC 3339 instant before which this member must not be selected.
    pub cooling_until: Option<String>,
}

impl Member {
    /// A human label that distinguishes members of one pool.
    pub fn label(&self) -> String {
        if self.key_id.is_empty() {
            self.provider.clone()
        } else {
            format!("{}:{}", self.provider, self.key_id)
        }
    }

    fn cooling_at(&self, now: i64) -> bool {
        state::is_cooling(self.cooling_until.as_deref(), now)
    }
}

/// Which vault this state belongs to.
///
/// Local vaults are keyed by database path and remotes by base URL, so
/// connecting to a different server does not inherit the cursor of the last one
/// — the same reasoning as `resetViewState` on a vault switch in the app.
pub fn vault_key(access: &crate::access::Access) -> String {
    match access {
        crate::access::Access::Local(_) => {
            state::local_vault_key(&crate::access::default_db_path())
        }
        crate::access::Access::Remote(c) => state::remote_vault_key(&c.base),
    }
}

/// Every pool name present in the vault, sorted.
pub fn pool_names(vault: &Value) -> Vec<String> {
    let mut names: Vec<String> = crate::data::entries(vault)
        .iter()
        .filter_map(|e| e.get("pool").and_then(Value::as_str))
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Resolve a pool's members, in vault order, with their stored state attached.
///
/// Vault order — not the order they were last used — because the cursor is an
/// index into this list, and a list that reorders itself would make the cursor
/// point somewhere different every call.
pub fn members(
    access: &crate::access::Access,
    vault: &Value,
    name: &str,
) -> CliResult<Vec<Member>> {
    let state = state::load();
    let stored = &state["vaults"][vault_key(access)][name]["members"];

    let list: Vec<Member> = crate::data::entries(vault)
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.get("pool")
                .and_then(Value::as_str)
                .is_some_and(|p| p.trim().eq_ignore_ascii_case(name))
        })
        .map(|(idx, e)| {
            let ck = vault_core::entry_ck(e);
            let st = &stored[&ck];
            Member {
                idx,
                provider: crate::data::provider_of(e).to_string(),
                key_id: e
                    .get("key_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                uses: st["uses"].as_u64().unwrap_or(0),
                cooling_until: st["cooling_until"].as_str().map(str::to_string),
                ck,
            }
        })
        .collect();

    if list.is_empty() {
        return Err(CliError::not_found(format!(
            "No entries in pool '{name}'. Add one with \
             `envv entry set <provider> --pool {name}`."
        )));
    }
    Ok(list)
}

/// Round-robin from `cursor`, skipping members that are cooling at `now`.
///
/// The cursor indexes the **full** member list rather than the available subset.
/// That distinction is the whole point: filter first and the indices shift every
/// time a member goes on or off cooldown, so putting key 2 on cooldown would
/// silently change which key the cursor means and the rotation would start
/// skipping an unrelated key.
///
/// Split out from [`select`] so it can be tested without a vault, a key or a
/// state file — the selection rule is the part worth pinning.
fn pick_index(list: &[Member], cursor: usize, now: i64) -> Option<usize> {
    let n = list.len();
    if n == 0 {
        return None;
    }
    (0..n)
        .map(|off| (cursor + off) % n)
        .find(|i| !list[*i].cooling_at(now))
}

/// Pick the next usable member and advance the cursor.
///
/// Round-robin over the members that are not cooling. The cursor indexes the
/// **full** member list rather than the filtered one, so a member going on
/// cooldown does not shift every other member's position and make the next call
/// skip an unrelated key.
///
/// Returns `unavailable` (exit 7) when every member is cooling, naming the one
/// that frees up first — a caller that cannot distinguish "no keys left right
/// now" from "no such pool" has to treat both as fatal.
pub fn select(access: &crate::access::Access, vault: &Value, name: &str) -> CliResult<Member> {
    let list = members(access, vault, name)?;
    let now = state::now_ts();

    let mut state = state::load();
    let vk = vault_key(access);
    let cursor = state["vaults"][&vk][name]["cursor"].as_u64().unwrap_or(0) as usize;

    let n = list.len();
    let Some(i) = pick_index(&list, cursor, now) else {
        // Every member is cooling. Name the soonest, so a script can sleep for a
        // known interval instead of retrying blind.
        let soonest = list
            .iter()
            .filter_map(|m| {
                m.cooling_until
                    .as_deref()
                    .and_then(state::parse_rfc3339)
                    .map(|t| (t, m.label()))
            })
            .min_by_key(|(t, _)| *t);
        let detail = match soonest {
            Some((t, label)) => {
                let secs = (t - now).max(0);
                format!(" — '{label}' frees up in {}s ({})", secs, state::iso_at(t))
            }
            None => String::new(),
        };
        return Err(CliError::unavailable(format!(
            "Every key in pool '{name}' is rate limited{detail}"
        )));
    };

    let chosen = list[i].clone();

    // Persist cursor and usage. Failing to write is NOT fatal: the caller asked
    // for a credential, and refusing to hand one over because a bookkeeping file
    // is unwritable would turn a read-only home directory into an outage. Say so
    // on stderr and carry on with a cursor that does not advance.
    state::record_use(&mut state, &vk, name, &chosen.ck, (i + 1) % n, now);
    if let Err(e) = state::save(&state) {
        eprintln!("envv: pool state not saved ({e}); cursor will not advance");
    }

    Ok(chosen)
}

/// Put a member on cooldown, or clear its cooldown.
///
/// `envv exec` hands the secret to a child process and never sees the child's
/// HTTP responses, so the CLI cannot detect a 429 on its own. The caller — which
/// did see it — reports it.
pub fn report(
    access: &crate::access::Access,
    vault: &Value,
    name: &str,
    target: Option<&str>,
    cooldown_secs: Option<i64>,
) -> CliResult<Member> {
    let list = members(access, vault, name)?;
    let member = match target {
        Some(t) => {
            let hits: Vec<&Member> = list
                .iter()
                .filter(|m| {
                    m.label().eq_ignore_ascii_case(t)
                        || m.key_id.eq_ignore_ascii_case(t)
                        || m.provider.eq_ignore_ascii_case(t)
                })
                .collect();
            match hits.len() {
                1 => hits[0].clone(),
                0 => {
                    return Err(CliError::not_found(format!(
                        "Pool '{name}' has no member '{t}'"
                    )))
                }
                _ => {
                    // Same rule as every other lookup: refuse rather than guess.
                    let names: Vec<String> = hits.iter().map(|m| m.label()).collect();
                    return Err(CliError::ambiguous(format!(
                        "'{t}' matches several members of pool '{name}': {}",
                        names.join(", ")
                    ))
                    .with_details(json!({ "candidates": names })));
                }
            }
        }
        // No target: the member the last `select` handed out is the one the
        // caller just failed on, and making them name it again is friction that
        // guarantees scripts get it wrong.
        None => last_used(access, name, &list).ok_or_else(|| {
            CliError::invalid(format!(
                "Nothing has been taken from pool '{name}' on this machine yet — \
                 name the key explicitly, e.g. `envv pool report {name} <provider>:<key-id>`"
            ))
        })?,
    };

    let mut st = state::load();
    let vk = vault_key(access);
    let until = cooldown_secs.map(|secs| state::now_ts() + secs);
    state::set_cooldown(&mut st, &vk, name, &member.ck, until);
    state::save(&st).map_err(CliError::from)?;

    let mut updated = member;
    updated.cooling_until = until.map(state::iso_at);
    Ok(updated)
}

fn last_used(access: &crate::access::Access, name: &str, list: &[Member]) -> Option<Member> {
    let state = state::load();
    let stored = &state["vaults"][vault_key(access)][name]["members"];
    list.iter()
        .filter_map(|m| {
            stored[&m.ck]["last_used_at"]
                .as_str()
                .and_then(state::parse_rfc3339)
                .map(|t| (t, m.clone()))
        })
        .max_by_key(|(t, _)| *t)
        .map(|(_, m)| m)
}

/// Forget a pool's cursor, cooldowns and counts on this machine.
pub fn reset(access: &crate::access::Access, name: &str) -> CliResult {
    let mut st = state::load();
    let vk = vault_key(access);
    state::forget(&mut st, &vk, name);
    state::save(&st).map_err(CliError::from)
}

/// Human-readable duration: `30s`, `15m`, `2h`, `1d`. A bare number is seconds.
///
/// Rejects rather than defaults on nonsense, because `--for 15min` silently
/// meaning 15 seconds is the kind of thing nobody notices until a CI job has
/// hammered a rate-limited key for an hour.
pub fn parse_duration(s: &str) -> CliResult<i64> {
    let t = s.trim().to_lowercase();
    if t.is_empty() {
        return Err(CliError::invalid("Empty duration"));
    }
    let (num, mult) = match t.chars().last() {
        Some('s') => (&t[..t.len() - 1], 1),
        Some('m') => (&t[..t.len() - 1], 60),
        Some('h') => (&t[..t.len() - 1], 3_600),
        Some('d') => (&t[..t.len() - 1], 86_400),
        Some(c) if c.is_ascii_digit() => (t.as_str(), 1),
        _ => {
            return Err(CliError::invalid(format!(
                "Cannot read duration '{s}' — use 30s, 15m, 2h or 1d"
            )))
        }
    };
    let n: i64 = num.parse().map_err(|_| {
        CliError::invalid(format!(
            "Cannot read duration '{s}' — use 30s, 15m, 2h or 1d"
        ))
    })?;
    if n < 0 {
        return Err(CliError::invalid("Duration cannot be negative"));
    }
    Ok(n * mult)
}

/// State of every member, for `pool show` / `pool ls`.
pub fn snapshot(members: &[Member]) -> Vec<Value> {
    let now = state::now_ts();
    members
        .iter()
        .map(|m| {
            json!({
                "label": m.label(),
                "provider": m.provider,
                "key_id": m.key_id,
                "uses": m.uses,
                "cooling": m.cooling_at(now),
                "cooling_until": m.cooling_until,
            })
        })
        .collect()
}

// ── Commands ─────────────────────────────────────────────────────────────────

/// `envv pool ls` — every pool in the vault, with member counts and cooldowns.
pub fn cmd_ls(access: &crate::access::Access) -> CliResult {
    let vault = access.load_vault()?;
    let names = pool_names(&vault);
    if names.is_empty() {
        out::ok("pool.ls", json!({ "count": 0, "pools": [] }), || {
            println!(
                "No key pools. Add an entry to one with `envv entry set <provider> --pool <name>`."
            );
        });
        return Ok(());
    }

    let now = state::now_ts();
    let mut rows = Vec::new();
    for name in &names {
        let list = members(access, &vault, name)?;
        let cooling = list.iter().filter(|m| m.cooling_at(now)).count();
        rows.push(json!({
            "pool": name,
            "members": list.len(),
            "available": list.len() - cooling,
            "cooling": cooling,
        }));
    }

    out::ok(
        "pool.ls",
        json!({ "count": rows.len(), "pools": rows }),
        || {
            for r in &rows {
                println!(
                    "{:<24} {} member(s), {} available, {} cooling",
                    r["pool"].as_str().unwrap_or(""),
                    r["members"],
                    r["available"],
                    r["cooling"]
                );
            }
        },
    );
    Ok(())
}

/// `envv pool show <name>` — per-member state.
///
/// Never prints a secret: a member is identified by provider and key id, and the
/// only numbers here are usage counts.
pub fn cmd_show(access: &crate::access::Access, name: &str) -> CliResult {
    let vault = access.load_vault()?;
    let list = members(access, &vault, name)?;
    let rows = snapshot(&list);
    out::ok(
        "pool.show",
        json!({ "pool": name, "count": rows.len(), "members": rows }),
        || {
            for r in &rows {
                let state = if r["cooling"].as_bool().unwrap_or(false) {
                    format!(
                        "cooling until {}",
                        r["cooling_until"].as_str().unwrap_or("?")
                    )
                } else {
                    "available".to_string()
                };
                println!(
                    "{:<28} {:>6} use(s)  {}",
                    r["label"].as_str().unwrap_or(""),
                    r["uses"],
                    state
                );
            }
        },
    );
    Ok(())
}

/// `envv pool next <name>` — take the next key and advance the cursor.
///
/// Redacted by default like every other stdout path; `--reveal` opts in, and
/// `envv exec --pool` is the way to use the value without ever seeing it.
pub fn cmd_next(access: &crate::access::Access, name: &str, field: Option<&str>) -> CliResult {
    let vault = access.load_vault()?;
    let picked = select(access, &vault, name)?;
    let entry = &crate::data::entries(&vault)[picked.idx];

    let field = field.unwrap_or("api_key");
    let value = crate::refs::entry_field(entry, field).ok_or_else(|| {
        CliError::not_found(format!("'{}' has no field '{field}'", picked.label()))
    })?;

    let secret = crate::entries::SECRET_FIELD_NAMES.contains(&crate::refs::canonical_field(field));
    let reveal = out::revealing();
    let shown = if secret && !reveal {
        out::masked(&value)
    } else {
        value.clone()
    };

    out::ok(
        "pool.next",
        json!({
            "pool": name,
            "label": picked.label(),
            "provider": picked.provider,
            "key_id": picked.key_id,
            "field": crate::refs::canonical_field(field),
            "uses": picked.uses + 1,
            "value": if secret && !reveal { out::masked_json(&value) } else { json!(value) },
        }),
        || println!("{shown}"),
    );
    Ok(())
}

/// `envv pool report <name> [target] --limited|--ok`
pub fn cmd_report(
    access: &crate::access::Access,
    name: &str,
    target: Option<&str>,
    limited: bool,
    for_dur: Option<&str>,
) -> CliResult {
    let vault = access.load_vault()?;
    let secs = if limited {
        Some(match for_dur {
            Some(d) => parse_duration(d)?,
            // Fifteen minutes: long enough that a per-minute limit has certainly
            // reset, short enough that a mistaken report does not take a key out
            // of service for the rest of a CI run.
            None => 15 * 60,
        })
    } else {
        None
    };

    let m = report(access, &vault, name, target, secs)?;
    out::ok(
        "pool.report",
        json!({
            "pool": name,
            "label": m.label(),
            "limited": limited,
            "cooling_until": m.cooling_until,
        }),
        || match &m.cooling_until {
            Some(until) => println!("'{}' is cooling until {until}", m.label()),
            None => println!("'{}' is available again", m.label()),
        },
    );
    Ok(())
}

/// `envv pool reset <name>`
pub fn cmd_reset(access: &crate::access::Access, name: &str) -> CliResult {
    // Resolve first: resetting a pool that does not exist is almost always a
    // typo, and silently succeeding hides it.
    let vault = access.load_vault()?;
    let list = members(access, &vault, name)?;
    reset(access, name)?;
    out::ok(
        "pool.reset",
        json!({ "pool": name, "members": list.len() }),
        || println!("Cleared cursor, cooldowns and counts for pool '{name}' on this machine"),
    );
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn member(key_id: &str, cooling_until: Option<&str>) -> Member {
        Member {
            idx: 0,
            ck: format!("id\u{1}{key_id}"),
            provider: "GitHub".into(),
            key_id: key_id.into(),
            uses: 0,
            cooling_until: cooling_until.map(str::to_string),
        }
    }

    /// A fixed instant, so these tests do not depend on the wall clock.
    const NOW: i64 = 1_700_000_000;

    fn at(offset: i64) -> String {
        state::iso_at(NOW + offset)
    }

    #[test]
    fn round_robin_wraps() {
        let list = [member("a", None), member("b", None), member("c", None)];
        assert_eq!(pick_index(&list, 0, NOW), Some(0));
        assert_eq!(pick_index(&list, 1, NOW), Some(1));
        assert_eq!(pick_index(&list, 2, NOW), Some(2));
        assert_eq!(
            pick_index(&list, 3, NOW),
            Some(0),
            "cursor wraps past the end"
        );
    }

    #[test]
    fn a_cooling_member_is_skipped() {
        let list = [
            member("a", Some(&at(600))),
            member("b", None),
            member("c", None),
        ];
        assert_eq!(
            pick_index(&list, 0, NOW),
            Some(1),
            "skips the cooling first member"
        );
        assert_eq!(pick_index(&list, 1, NOW), Some(1));
        assert_eq!(pick_index(&list, 2, NOW), Some(2));
    }

    #[test]
    fn cooling_does_not_shift_the_cursor_meaning() {
        // The regression this guards: if the cursor indexed the *available*
        // members instead of all of them, putting "b" on cooldown would make
        // cursor 1 point at "c" rather than skipping to it — and when "b" came
        // back, every later position would shift again. The cursor has to mean
        // the same member regardless of who is currently cooling.
        let all_up = [member("a", None), member("b", None), member("c", None)];
        let b_down = [
            member("a", None),
            member("b", Some(&at(600))),
            member("c", None),
        ];
        assert_eq!(pick_index(&all_up, 2, NOW), Some(2));
        assert_eq!(pick_index(&b_down, 2, NOW), Some(2), "c is still index 2");
        assert_eq!(pick_index(&b_down, 0, NOW), Some(0), "a is still index 0");
    }

    #[test]
    fn an_expired_cooldown_is_not_a_cooldown() {
        let list = [member("a", Some(&at(-1))), member("b", None)];
        assert_eq!(
            pick_index(&list, 0, NOW),
            Some(0),
            "the cooldown has passed"
        );
    }

    #[test]
    fn a_cooldown_that_is_not_a_timestamp_is_ignored() {
        // pools.json is a plain file a user can edit, and a half-written one is
        // a real state. Treating garbage as "cooling forever" would take a key
        // out of service with no way to see why.
        let list = [member("a", Some("not a date")), member("b", None)];
        assert_eq!(pick_index(&list, 0, NOW), Some(0));
    }

    #[test]
    fn everything_cooling_yields_nothing() {
        let list = [member("a", Some(&at(60))), member("b", Some(&at(120)))];
        assert_eq!(pick_index(&list, 0, NOW), None);
    }

    #[test]
    fn empty_pool_yields_nothing() {
        assert_eq!(pick_index(&[], 0, NOW), None);
    }

    #[test]
    fn label_distinguishes_members_and_falls_back_to_the_provider() {
        assert_eq!(member("ci-1", None).label(), "GitHub:ci-1");
        assert_eq!(member("", None).label(), "GitHub");
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("30s").unwrap(), 30);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration("2h").unwrap(), 7_200);
        assert_eq!(parse_duration("1d").unwrap(), 86_400);
        assert_eq!(
            parse_duration("45").unwrap(),
            45,
            "a bare number is seconds"
        );
        assert_eq!(parse_duration("  10M  ").unwrap(), 600, "case and spacing");
    }

    #[test]
    fn nonsense_durations_are_refused_rather_than_defaulted() {
        // `--for 15min` silently meaning 15 seconds is the kind of thing nobody
        // notices until CI has hammered a rate-limited key for an hour.
        for bad in ["", "15min", "abc", "m", "-5m", "5x"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn iso_at_matches_the_shape_vault_core_writes() {
        // These strings sit beside `last_rotated_at` and friends; a different
        // shape would compare wrong and read wrong.
        let s = state::iso_at(NOW);
        assert_eq!(s.len(), 20, "YYYY-MM-DDTHH:MM:SSZ");
        assert!(s.ends_with('Z'));
        assert_eq!(state::parse_rfc3339(&s), Some(NOW), "and it reads back");
    }
}
