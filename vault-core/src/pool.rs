//! The key-pool state file: `pools.json`.
//!
//! A key pool is several interchangeable credentials for one service. Which one
//! to hand out next, which are cooling after a rate limit, and how often each
//! has been used are **per-machine** facts, so they are kept here rather than in
//! the vault. Three reasons, worst failure first:
//!
//! 1. [`save_vault`](crate::save_vault) appends a `vault_audit` row on every
//!    update. A CI loop calling `envv exec` would grow the hash-chained log
//!    without bound - the same reason read events stopped being audited.
//! 2. `save_vault` is a compare-and-swap. Concurrent reads against one vault
//!    would collide and start returning conflicts for *reads*.
//! 3. A vault is shared; a rotation cursor is not. Two CI runners pulling from
//!    one remote vault want independent cursors.
//!
//! # Why this lives in vault-core
//!
//! Two programs read this file: `envv` and the desktop app. The app's
//! `app_data_dir` and the CLI's `dirs::data_dir()/io.envvault` resolve to the
//! same directory, so one vault produces the same [`local_vault_key`] in both -
//! report a key rate limited from CI and the desktop shows it cooling.
//!
//! That only holds while both agree on the file's shape, its path, and the
//! cooldown arithmetic. This project has been bitten by two implementations of
//! one format drifting apart often enough to have a convention about it, so
//! there is exactly one implementation and both callers use it.
//!
//! # Shape
//!
//! ```json
//! {
//!   "version": 1,
//!   "vaults": {
//!     "local:/home/me/.local/share/io.envvault/vault.db": {
//!       "github-ci": {
//!         "cursor": 1,
//!         "members": {
//!           "<entry_ck>": {
//!             "uses": 12,
//!             "last_used_at": "2026-08-25T11:02:31Z",
//!             "cooling_until": "2026-08-25T11:17:31Z"
//!           }
//!         }
//!       }
//!     }
//!   }
//! }
//! ```
//!
//! Members are keyed by [`entry_ck`](crate::entry_ck) - the same stable identity
//! version history and audit attribution use - so renaming an entry keeps its
//! pool state, and two entries sharing a provider never collapse into one.

use serde_json::{json, Value};
use std::path::PathBuf;

/// Where `pools.json` lives.
///
/// `$XDG_STATE_HOME/envv/` on Unix, `%LOCALAPPDATA%\envv\` on Windows, falling
/// back to `~/.local/state/envv/`. The same directory as the CLI's
/// `sessions.json`.
///
/// Returns `None` rather than guessing when there is no home directory to work
/// from. There is deliberately no `.` fallback: a per-directory rotation cursor
/// is its own quiet bug, where the same pool restarts at the first key every
/// time you change directory.
pub fn state_path() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("ENVV_POOL_FILE") {
        return Some(PathBuf::from(explicit));
    }
    #[cfg(windows)]
    {
        // %LOCALAPPDATA% is per-user and excluded from roaming profiles, so a
        // machine-local cursor cannot be synced onto another machine by a
        // domain profile nobody thinks about.
        if let Some(dir) = dirs::data_local_dir() {
            return Some(dir.join("envv").join("pools.json"));
        }
    }
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME") {
        return Some(PathBuf::from(dir).join("envv").join("pools.json"));
    }
    dirs::home_dir().map(|h| {
        h.join(".local")
            .join("state")
            .join("envv")
            .join("pools.json")
    })
}

/// An empty state document.
fn empty() -> Value {
    json!({ "version": 1, "vaults": {} })
}

/// Read the state file, or an empty document.
///
/// A missing, unreadable or malformed file all yield the empty document rather
/// than an error. This file is bookkeeping: refusing to work because it is
/// corrupt would turn a cosmetic problem into an outage, and the next write
/// repairs it.
pub fn load() -> Value {
    state_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(empty)
}

/// Write the state file, creating its directory and restricting it to its owner.
pub fn save(state: &Value) -> Result<(), String> {
    let path = state_path().ok_or_else(|| {
        "Cannot determine a home directory for per-user state (no $HOME on Unix, \
         no %USERPROFILE% on Windows). Set ENVV_POOL_FILE to choose the location."
            .to_string()
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(state).unwrap_or_default(),
    )
    .map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
    restrict(&path)
}

/// Restrict the state file to its owner.
///
/// It holds no secret, but it records which credentials this machine uses and
/// how often - a usage map of the vault, which is the kind of thing the audit
/// design already treats as sensitive. Same 0600 treatment as the session file.
///
/// The body is `#[cfg(unix)]`, so on Windows `path` genuinely is unused, and the
/// workspace builds with warnings denied. Silenced only on the target where that
/// is true, so a real unused binding added here later still fails on Linux.
#[cfg_attr(not(unix), allow(unused_variables))]
fn restrict(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// State is filed per vault, so connecting to a different server does not
/// inherit the last one's cursor - the same reasoning as resetting view state on
/// a vault switch in the app.
pub fn local_vault_key(db_path: &std::path::Path) -> String {
    format!("local:{}", db_path.display())
}

/// The remote counterpart of [`local_vault_key`].
pub fn remote_vault_key(base_url: &str) -> String {
    format!("remote:{base_url}")
}

/// One member's stored state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemberState {
    pub uses: u64,
    pub last_used_at: Option<String>,
    pub cooling_until: Option<String>,
}

/// Read one member's state out of a loaded document.
pub fn member_state(state: &Value, vault_key: &str, pool: &str, ck: &str) -> MemberState {
    let slot = &state["vaults"][vault_key][pool]["members"][ck];
    MemberState {
        uses: slot["uses"].as_u64().unwrap_or(0),
        last_used_at: slot["last_used_at"].as_str().map(str::to_string),
        cooling_until: slot["cooling_until"].as_str().map(str::to_string),
    }
}

/// The cursor for a pool, or 0.
pub fn cursor(state: &Value, vault_key: &str, pool: &str) -> usize {
    state["vaults"][vault_key][pool]["cursor"]
        .as_u64()
        .unwrap_or(0) as usize
}

/// Ensure `vaults.<key>.<pool>` exists so the writers below can index into it.
fn ensure(state: &mut Value, vault_key: &str, pool: &str) {
    if !state["vaults"][vault_key][pool].is_object() {
        state["vaults"][vault_key][pool] = json!({ "cursor": 0, "members": {} });
    }
}

/// Record that a member was handed out, and where the cursor moves to.
pub fn record_use(
    state: &mut Value,
    vault_key: &str,
    pool: &str,
    ck: &str,
    next_cursor: usize,
    now: i64,
) {
    ensure(state, vault_key, pool);
    let uses = member_state(state, vault_key, pool, ck).uses;
    state["vaults"][vault_key][pool]["cursor"] = json!(next_cursor as u64);
    state["vaults"][vault_key][pool]["members"][ck]["uses"] = json!(uses + 1);
    state["vaults"][vault_key][pool]["members"][ck]["last_used_at"] = json!(iso_at(now));
}

/// Put a member on cooldown until `until_ts`, or clear its cooldown with `None`.
pub fn set_cooldown(
    state: &mut Value,
    vault_key: &str,
    pool: &str,
    ck: &str,
    until_ts: Option<i64>,
) {
    ensure(state, vault_key, pool);
    let slot = &mut state["vaults"][vault_key][pool]["members"][ck];
    match until_ts {
        Some(ts) => slot["cooling_until"] = json!(iso_at(ts)),
        None => {
            if let Some(obj) = slot.as_object_mut() {
                obj.remove("cooling_until");
            }
        }
    }
}

/// Forget a pool's cursor, cooldowns and counts for one vault.
pub fn forget(state: &mut Value, vault_key: &str, pool: &str) {
    if let Some(obj) = state["vaults"][vault_key].as_object_mut() {
        obj.remove(pool);
    }
}

/// Is this member cooling at `now`?
///
/// A `cooling_until` that is not a timestamp is treated as **not** cooling.
/// `pools.json` is a plain file a user can edit and a half-written one is a real
/// state; reading garbage as "cooling forever" would take a key out of service
/// with nothing on screen explaining why.
pub fn is_cooling(cooling_until: Option<&str>, now: i64) -> bool {
    cooling_until
        .and_then(parse_rfc3339)
        .is_some_and(|t| t > now)
}

/// Seconds since the epoch, now.
pub fn now_ts() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// RFC 3339 for an arbitrary instant.
///
/// Hand-formatted rather than `OffsetDateTime::format`, because the workspace
/// pins `time` without its `formatting` feature. [`iso_now`](crate::iso_now)
/// does the same for "now"; keeping the shape identical matters because these
/// strings sit beside `last_rotated_at` and friends written by that function.
pub fn iso_at(ts: i64) -> String {
    let Ok(t) = time::OffsetDateTime::from_unix_timestamp(ts) else {
        return String::new();
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Read one of the timestamps [`iso_at`] writes: exactly `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Hand-parsed rather than via `OffsetDateTime::parse`, which needs the `time`
/// crate's `parsing` feature that vault-core deliberately does not enable — the
/// same reasoning as [`iso_at`] not using `format`. Nothing is lost by being
/// strict here: this only ever reads back a string this module wrote, and
/// anything else must be rejected anyway, because `pools.json` is a plain file
/// a user can edit and [`is_cooling`] has to treat garbage as "not cooling"
/// rather than "cooling forever".
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |from: usize, to: usize| s.get(from..to)?.parse::<u32>().ok();
    let year = num(0, 4)? as i32;
    let month = time::Month::try_from(num(5, 7)? as u8).ok()?;
    let day = num(8, 10)? as u8;
    let (h, m, sec) = (num(11, 13)? as u8, num(14, 16)? as u8, num(17, 19)? as u8);

    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let time_of_day = time::Time::from_hms(h, m, sec).ok()?;
    Some(
        time::PrimitiveDateTime::new(date, time_of_day)
            .assume_utc()
            .unix_timestamp(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;
    const A: &str = "id-aaa";
    const B: &str = "id-bbb";

    #[test]
    fn cooling_reads_a_future_timestamp() {
        assert!(is_cooling(Some(&iso_at(NOW + 60)), NOW));
    }

    #[test]
    fn an_expired_cooldown_is_not_a_cooldown() {
        assert!(!is_cooling(Some(&iso_at(NOW - 1)), NOW));
    }

    #[test]
    fn garbage_is_not_a_cooldown() {
        // A hand-edited or half-written pools.json must not take a key out of
        // service with nothing on screen explaining why.
        assert!(!is_cooling(Some("not a date"), NOW));
        assert!(!is_cooling(Some(""), NOW));
        assert!(!is_cooling(None, NOW));
    }

    #[test]
    fn iso_at_round_trips_and_matches_iso_now_shape() {
        let s = iso_at(NOW);
        assert_eq!(s.len(), 20, "YYYY-MM-DDTHH:MM:SSZ");
        assert!(s.ends_with('Z'));
        assert_eq!(parse_rfc3339(&s), Some(NOW));
    }

    #[test]
    fn use_and_cooldown_accumulate_on_the_right_member() {
        let mut st = empty();
        let vk = "local:/tmp/v.db";
        record_use(&mut st, vk, "p", A, 1, NOW);
        record_use(&mut st, vk, "p", A, 0, NOW);
        record_use(&mut st, vk, "p", B, 1, NOW);

        assert_eq!(member_state(&st, vk, "p", A).uses, 2);
        assert_eq!(member_state(&st, vk, "p", B).uses, 1);
        assert_eq!(cursor(&st, vk, "p"), 1);

        set_cooldown(&mut st, vk, "p", A, Some(NOW + 900));
        assert!(is_cooling(
            member_state(&st, vk, "p", A).cooling_until.as_deref(),
            NOW
        ));
        assert!(
            !is_cooling(member_state(&st, vk, "p", B).cooling_until.as_deref(), NOW),
            "cooling one member must not cool another"
        );

        set_cooldown(&mut st, vk, "p", A, None);
        assert_eq!(
            member_state(&st, vk, "p", A).cooling_until,
            None,
            "clearing removes the key rather than writing a past timestamp"
        );
        assert_eq!(
            member_state(&st, vk, "p", A).uses,
            2,
            "clearing a cooldown must not reset the use count"
        );
    }

    #[test]
    fn state_is_partitioned_by_vault() {
        // Connecting to a different vault must not inherit the last one's
        // cursor - the same reasoning as resetting view state on a switch.
        let mut st = empty();
        record_use(&mut st, "local:/a.db", "p", A, 3, NOW);
        assert_eq!(cursor(&st, "local:/a.db", "p"), 3);
        assert_eq!(cursor(&st, "remote:https://host", "p"), 0);
        assert_eq!(member_state(&st, "remote:https://host", "p", A).uses, 0);
    }

    #[test]
    fn forget_clears_one_pool_and_leaves_the_others() {
        let mut st = empty();
        let vk = "local:/a.db";
        record_use(&mut st, vk, "keep", A, 1, NOW);
        record_use(&mut st, vk, "drop", B, 1, NOW);
        forget(&mut st, vk, "drop");
        assert_eq!(member_state(&st, vk, "drop", B).uses, 0);
        assert_eq!(member_state(&st, vk, "keep", A).uses, 1);
    }
}
