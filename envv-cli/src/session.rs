//! Password sources and cached remote sessions.
//!
//! An orchestrator should never hold the vault password. Three ways out of that,
//! in priority order:
//!
//! 1. `--password-command` — the password comes from a keyring helper (`pass`,
//!    `secret-tool`, 1Password's CLI). It never appears in argv, in the
//!    environment, or in an agent's transcript.
//! 2. `--password-file` — a 0600 file the human placed there.
//! 3. `envv login` — a human authenticates once; the session token lands in a
//!    0600 file and every later command reuses it. The agent runs commands, not
//!    logins.
//!
//! `ENVV_PASSWORD` still works and is still the wrong default for anything an
//! agent can read.

use crate::error::{CliError, CliResult};
use serde_json::{json, Value};
use std::path::PathBuf;

/// Where cached sessions live.
///
/// `$XDG_STATE_HOME/envv/` on Unix, `%LOCALAPPDATA%\envv\` on Windows. The
/// Windows path matters beyond tidiness: `LOCALAPPDATA` is per-user and excluded
/// from roaming profiles, so a session token cannot be synced onto another
/// machine by a domain profile the user never thinks about.
pub fn session_path() -> PathBuf {
    if let Some(explicit) = std::env::var_os("ENVV_SESSION_FILE") {
        return PathBuf::from(explicit);
    }
    #[cfg(windows)]
    {
        if let Some(dir) = dirs::data_local_dir() {
            return dir.join("envv").join("sessions.json");
        }
    }
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(dir).join("envv").join("sessions.json");
    }
    // No `.` fallback. This file holds a live bearer token at 0600, and writing
    // it to the current working directory means dropping a credential into
    // whatever the caller happened to `cd` into — a checked-out repository, a
    // shared build directory — where the mode protects it and nothing else does.
    // Refusing is the safer half of the choice.
    let Some(home) = dirs::home_dir() else {
        eprintln!(
            "envv: cannot determine a home directory to cache the session in \
             (no $HOME on Unix, no %USERPROFILE% on Windows).\n\
             Set ENVV_SESSION_FILE to choose the location explicitly."
        );
        std::process::exit(crate::error::Code::Unavailable as i32);
    };
    home.join(".local")
        .join("state")
        .join("envv")
        .join("sessions.json")
}

fn read_all() -> Value {
    std::fs::read_to_string(session_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| json!({}))
}

fn write_all(v: &Value) -> CliResult {
    let path = session_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CliError::from(e.to_string()))?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(v).unwrap_or_default())
        .map_err(|e| CliError::from(format!("Cannot write {}: {e}", path.display())))?;
    restrict(&path)
}

/// Restrict the session file to its owner.
///
/// A session token is a bearer credential; a world-readable one is the same
/// mistake as a world-readable private key. On Unix that is a 0600 chmod. On
/// Windows there is no equivalent one-liner — the file inherits the directory
/// ACL — which is why the path above is `%LOCALAPPDATA%`, a directory that is
/// already user-scoped.
///
/// The whole body is `#[cfg(unix)]`, so on Windows `path` genuinely is unused —
/// and CI builds with `-D warnings`. Silenced only on the target where that is
/// true, rather than for the function, so a real unused binding added here later
/// still fails the Linux build.
#[cfg_attr(not(unix), allow(unused_variables))]
fn restrict(path: &std::path::Path) -> CliResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|e| CliError::from(e.to_string()))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| CliError::from(e.to_string()))?;
    }
    Ok(())
}

/// The name a session is filed under when no `--user` was given.
///
/// The owner is not a sub-user and cannot log in through `/api/auth`; it
/// authenticates by proving it can derive the vault key. It still needs a
/// key in this file, and it must be one no real username can collide with —
/// hence the angle brackets, which `create_user` rejects.
pub const OWNER_SUBJECT: &str = "<owner>";

/// Sessions are filed per **server *and* subject**, not per server.
///
/// Keying by URL alone meant logging in as a second user silently replaced the
/// first, and every later command ran as whoever logged in last — with nothing
/// on screen saying so. Two people sharing a workstation, or one person holding
/// an admin identity beside a scoped one, is an ordinary thing to want.
///
/// ```json
/// { "https://vault.example.com": {
///     "default": "alice",
///     "subjects": { "alice": { "token": "…", "created_at": "…" } } } }
/// ```
///
/// Entries written before this shape existed are `{token, subject, created_at}`
/// directly under the URL. [`read_all`] migrates those on read, so an existing
/// login survives the upgrade rather than silently failing to authenticate.
fn migrate(entry: &Value) -> Value {
    if entry.get("subjects").is_some() {
        return entry.clone();
    }
    let subject = entry
        .get("subject")
        .and_then(|s| s.as_str())
        .unwrap_or(OWNER_SUBJECT);
    json!({
        "default": subject,
        "subjects": {
            subject: {
                "token": entry.get("token").cloned().unwrap_or(Value::Null),
                "created_at": entry.get("created_at").cloned().unwrap_or(Value::Null),
            }
        }
    })
}

/// The stored session token for a server, for `subject` if named and the
/// server's default identity otherwise.
pub fn load(url: &str, subject: Option<&str>) -> Option<String> {
    let all = read_all();
    let entry = migrate(all.get(url)?);
    let want = match subject {
        Some(s) => s.to_string(),
        None => entry.get("default")?.as_str()?.to_string(),
    };
    entry
        .get("subjects")?
        .get(&want)?
        .get("token")?
        .as_str()
        .map(String::from)
}

/// Every cached identity for one server: `{default, subjects}`.
pub fn describe(url: &str) -> Option<Value> {
    read_all().get(url).map(migrate)
}

/// Every cached session, as `{url: {default, subjects}}`. Tokens included —
/// callers that print this must redact.
pub fn list_all() -> Value {
    let all = read_all();
    let mut out = json!({});
    if let Some(obj) = all.as_object() {
        for (url, entry) in obj {
            out[url] = migrate(entry);
        }
    }
    out
}

/// Cache a session. The newest login becomes the server's default identity,
/// which is what makes `envv login --user alice` followed by a bare `envv list`
/// do the obvious thing.
pub fn save(url: &str, token: &str, subject: &str) -> CliResult {
    let mut all = read_all();
    let mut entry = all
        .get(url)
        .map(migrate)
        .unwrap_or_else(|| json!({ "subjects": {} }));
    entry["default"] = json!(subject);
    entry["subjects"][subject] = json!({
        "token": token,
        "created_at": vault_core::iso_now(),
    });
    all[url] = entry;
    write_all(&all)
}

/// Forget one identity, or every identity for the server when `subject` is None.
///
/// Dropping the last subject drops the server too, so a cleared file is empty
/// rather than a husk of URLs with no sessions behind them.
pub fn clear(url: &str, subject: Option<&str>) -> CliResult {
    let mut all = read_all();
    let Some(subject) = subject else {
        if let Some(obj) = all.as_object_mut() {
            obj.remove(url);
        }
        return write_all(&all);
    };
    let Some(mut entry) = all.get(url).map(migrate) else {
        return Ok(());
    };
    let mut survivor: Option<String> = None;
    let mut emptied = false;
    if let Some(subs) = entry["subjects"].as_object_mut() {
        subs.remove(subject);
        emptied = subs.is_empty();
        survivor = subs.keys().next().cloned();
    }
    if emptied {
        if let Some(obj) = all.as_object_mut() {
            obj.remove(url);
        }
        return write_all(&all);
    }
    // The default just went away; promote a survivor rather than leaving a
    // dangling pointer that makes every later command fail to find a session.
    if entry["default"].as_str() == Some(subject) {
        entry["default"] = json!(survivor.unwrap_or_default());
    }
    all[url] = entry;
    write_all(&all)
}

pub fn clear_all() -> CliResult {
    write_all(&json!({}))
}

// ── Password sources ──────────────────────────────────────────────────────────

/// Read `KEY=VALUE` pairs out of a Docker-style `.env` file.
///
/// This is the file `docker compose` already reads to start `envv-server`, so
/// pointing the CLI at the same one means there is exactly one copy of the
/// password on the machine, owned by the compose stack. Nothing is exported into
/// the environment — the values are read, used, and dropped.
pub fn read_dotenv(path: &std::path::Path) -> CliResult<Vec<(String, String)>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CliError::not_found(format!("Cannot read {}: {e}", path.display())))?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let mut value = v.trim().to_string();
        // compose keeps the quotes out of the value; so do we.
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            value = value[1..value.len() - 1].to_string();
        }
        out.push((k.trim().to_string(), value));
    }
    Ok(out)
}

/// Pull one variable out of a `.env` file.
pub fn dotenv_var(path: &std::path::Path, key: &str) -> CliResult<Option<String>> {
    Ok(read_dotenv(path)?
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v))
}

/// Resolve the password without ever putting it in argv.
///
/// Returns `None` when no source was configured, leaving the caller to prompt —
/// which is right for a human and correctly fails for a non-interactive agent.
pub fn resolve_password(
    inline: Option<&str>,
    file: Option<&std::path::Path>,
    command: Option<&str>,
) -> CliResult<Option<String>> {
    if let Some(p) = inline {
        return Ok(Some(p.to_string()));
    }
    if let Some(path) = file {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| CliError::not_found(format!("Cannot read {}: {e}", path.display())))?;
        let first = raw.lines().next().unwrap_or("").to_string();
        if first.is_empty() {
            return Err(CliError::invalid(format!("{} is empty", path.display())));
        }
        return Ok(Some(first));
    }
    if let Some(cmd) = command {
        // Run through the platform shell so the documented form
        // ("pass show envv") works without the caller splitting arguments —
        // and so the same flag works on Windows, where there is no `sh`.
        let (shell, flag) = if cfg!(windows) {
            ("cmd", "/C")
        } else {
            ("sh", "-c")
        };
        let out = std::process::Command::new(shell)
            .arg(flag)
            .arg(cmd)
            .output()
            .map_err(|e| CliError::from(format!("password command failed to start: {e}")))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(CliError::denied(format!(
                "password command exited {}: {err}",
                out.status.code().unwrap_or(-1)
            )));
        }
        let pw = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        if pw.is_empty() {
            return Err(CliError::invalid("password command produced no output"));
        }
        return Ok(Some(pw));
    }
    Ok(None)
}
