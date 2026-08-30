//! Per-directory project and environment context — `envv use` and `.envv.json`.
//!
//! Every command that scopes to a project repeats `--project web` forever. This
//! pins the answer to a directory once, the way a `.git` directory or a
//! `.nvmrc` does, so a repository checkout carries its own vault scope and the
//! flags disappear from every later command.
//!
//! # Precedence, highest first
//!
//! 1. An explicit `--project` / `--env` flag.
//! 2. `ENVV_PROJECT` / `ENVV_ENV` in the environment — what CI sets.
//! 3. The nearest `.envv.json`, searching upward from the working directory.
//!
//! # This file holds no secrets, and that is deliberate
//!
//! It *names* a project and an environment; it never contains a value, so it is
//! written 0644 and belongs in version control if the team wants it there. A
//! context file that held credentials would be the thing this whole program
//! exists to avoid, and would have to be gitignored by every consumer to be
//! safe — which is a rule that gets forgotten exactly once.
//!
//! # Validated on read, never trusted
//!
//! A pinned project the vault no longer has is invariant 7 from `CLAUDE.md`,
//! one directory at a time: a stale reference that silently matches nothing.
//! The desktop app's answer is to drop the reference and repaint; a CLI cannot
//! do that, because "matched nothing" and "no filter" produce visibly different
//! output for `list` and *identical* output for a vault of one project. So a
//! context naming a project that is not there is an error, and the error says
//! how to fix it. Failing loudly beats quietly widening a scope the user
//! believes is narrow.

use crate::error::{CliError, CliResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The file name searched for, upward from the working directory.
pub const FILE_NAME: &str = ".envv.json";

/// Contents of a `.envv.json`.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// Format version. Present so a future field can be added without an older
    /// binary silently ignoring a file it does not understand.
    #[serde(default = "one")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

fn one() -> u32 {
    1
}

/// Walks up from `start` looking for `.envv.json`, stopping at the filesystem
/// root.
///
/// Upward search, not just the current directory: the whole point is running
/// `envv get` from `src/deep/nested/` in a checkout whose context sits at its
/// top level.
pub fn find_file(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

/// Loads the nearest context, or `None` when there is none.
///
/// A malformed file is an error rather than a silent `None`: it was put there
/// deliberately, and ignoring it means every command quietly runs unscoped.
pub fn load_from(start: &Path) -> Result<Option<(PathBuf, Context)>, CliError> {
    let Some(path) = find_file(start) else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| CliError::from(format!("Cannot read {}: {e}", path.display())))?;
    let ctx: Context = serde_json::from_str(&raw).map_err(|e| {
        CliError::invalid(format!(
            "{} is not valid context JSON: {e}\nFix it, or run `envv use --clear` in that directory.",
            path.display()
        ))
    })?;
    Ok(Some((path, ctx)))
}

/// [`load_from`] anchored at the current working directory.
pub fn load() -> Result<Option<(PathBuf, Context)>, CliError> {
    let cwd = std::env::current_dir()
        .map_err(|e| CliError::from(format!("Cannot read the working directory: {e}")))?;
    load_from(&cwd)
}

/// The project a command should use, applying the precedence above.
///
/// `explicit` is whatever `--project` carried. Returns `None` when nothing
/// anywhere names a project, which means "the whole vault" exactly as before.
pub fn project(explicit: Option<&str>) -> Result<Option<String>, CliError> {
    if let Some(p) = explicit {
        return Ok(Some(p.to_string()));
    }
    if let Ok(p) = std::env::var("ENVV_PROJECT") {
        if !p.is_empty() {
            return Ok(Some(p));
        }
    }
    Ok(load()?.and_then(|(_, c)| c.project))
}

/// The environment a command should use. Same precedence as [`project`].
pub fn environment(explicit: Option<&str>) -> Result<Option<String>, CliError> {
    if let Some(e) = explicit {
        return Ok(Some(e.to_string()));
    }
    if let Ok(e) = std::env::var("ENVV_ENV") {
        if !e.is_empty() {
            return Ok(Some(e));
        }
    }
    Ok(load()?.and_then(|(_, c)| c.environment))
}

/// True when this project name came from a context file rather than a flag —
/// used to decide whether a failure to resolve it should mention `envv use`.
pub fn is_from_context(explicit: Option<&str>) -> bool {
    explicit.is_none()
        && std::env::var("ENVV_PROJECT")
            .map(|v| v.is_empty())
            .unwrap_or(true)
}

/// Checks that `name` resolves to a project in `vault`, and returns its id.
///
/// Matching is the same rule `--project` has always used — exact id, or a
/// case-insensitive substring of the name — so pinning a project cannot mean
/// something different from passing it.
pub fn resolve_in_vault(vault: &serde_json::Value, name: &str) -> Option<String> {
    let lc = name.to_lowercase();
    crate::data::projects(vault)
        .iter()
        .find(|p| {
            p.get("id").and_then(|i| i.as_str()) == Some(name)
                || p.get("name")
                    .and_then(|n| n.as_str())
                    .is_some_and(|n| n.to_lowercase().contains(&lc))
        })
        .and_then(|p| p.get("id").and_then(|i| i.as_str()).map(String::from))
}

/// Writes a context file in `dir`.
pub fn save(dir: &Path, ctx: &Context) -> Result<PathBuf, CliError> {
    let path = dir.join(FILE_NAME);
    let body = serde_json::to_string_pretty(ctx).unwrap_or_default();
    std::fs::write(&path, format!("{body}\n"))
        .map_err(|e| CliError::from(format!("Cannot write {}: {e}", path.display())))?;
    Ok(path)
}

/// Removes the context file in `dir`, reporting whether there was one.
pub fn clear(dir: &Path) -> Result<bool, CliError> {
    let path = dir.join(FILE_NAME);
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&path)
        .map_err(|e| CliError::from(format!("Cannot remove {}: {e}", path.display())))?;
    Ok(true)
}

/// `envv use` — pin, show or clear the context for this directory.
pub fn cmd_use(
    access: Option<&crate::access::Access>,
    project_name: Option<&str>,
    env_name: Option<&str>,
    show: bool,
    clear_it: bool,
) -> CliResult {
    let cwd = std::env::current_dir()
        .map_err(|e| CliError::from(format!("Cannot read the working directory: {e}")))?;

    if clear_it {
        let existed = clear(&cwd)?;
        crate::out::ok(
            "use.clear",
            serde_json::json!({ "cleared": existed, "dir": cwd.display().to_string() }),
            || {
                if existed {
                    println!("Removed {} from {}", FILE_NAME, cwd.display());
                } else {
                    println!("No {} here — nothing to clear.", FILE_NAME);
                }
            },
        );
        return Ok(());
    }

    if show || (project_name.is_none() && env_name.is_none()) {
        let found = load_from(&cwd)?;
        let env_project = std::env::var("ENVV_PROJECT").ok().filter(|v| !v.is_empty());
        let env_env = std::env::var("ENVV_ENV").ok().filter(|v| !v.is_empty());
        crate::out::ok(
            "use.show",
            serde_json::json!({
                "file": found.as_ref().map(|(p, _)| p.display().to_string()),
                "project": found.as_ref().and_then(|(_, c)| c.project.clone()),
                "environment": found.as_ref().and_then(|(_, c)| c.environment.clone()),
                "env_project": env_project,
                "env_environment": env_env,
            }),
            || match &found {
                Some((path, c)) => {
                    println!("{}", path.display());
                    println!("  project      {}", c.project.as_deref().unwrap_or("—"));
                    println!("  environment  {}", c.environment.as_deref().unwrap_or("—"));
                    // Stated because it is the confusing case: the file is right
                    // there and something else is winning.
                    if env_project.is_some() || env_env.is_some() {
                        println!("\nENVV_PROJECT / ENVV_ENV are set and take precedence.");
                    }
                }
                None => println!("No {FILE_NAME} found in this directory or any parent."),
            },
        );
        return Ok(());
    }

    // Validated before it is written, not on every later command. A context
    // that names a project the vault does not have would otherwise be an error
    // the user meets tomorrow, in a command that has nothing to do with it.
    if let (Some(name), Some(a)) = (project_name, access) {
        let vault = a.load_vault()?;
        if resolve_in_vault(&vault, name).is_none() {
            return Err(CliError::not_found(format!(
                "No project matches '{name}'. Run `envv project ls` to see what exists."
            )));
        }
    }

    let existing = load_from(&cwd)?
        .filter(|(p, _)| p.parent() == Some(cwd.as_path()))
        .map(|(_, c)| c)
        .unwrap_or_default();

    let ctx = Context {
        version: 1,
        // Each half is set independently: `envv use --env staging` in a
        // directory already pinned to a project must not silently unpin it.
        project: project_name.map(str::to_string).or(existing.project),
        environment: env_name.map(str::to_string).or(existing.environment),
    };
    let path = save(&cwd, &ctx)?;

    crate::out::ok(
        "use",
        serde_json::json!({
            "file": path.display().to_string(),
            "project": ctx.project,
            "environment": ctx.environment,
        }),
        || {
            println!("Wrote {}", path.display());
            println!("Commands run here now default to this project and environment.");
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("envv-ctx-{tag}-{nanos}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn finds_a_context_in_a_parent_directory() {
        // The case the feature exists for: `envv get` run from deep inside a
        // checkout whose context sits at the top.
        let root = scratch("parent");
        let deep = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        save(
            &root,
            &Context {
                version: 1,
                project: Some("web".into()),
                environment: None,
            },
        )
        .unwrap();
        let (path, ctx) = load_from(&deep).unwrap().expect("found");
        assert_eq!(path, root.join(FILE_NAME));
        assert_eq!(ctx.project.as_deref(), Some("web"));
    }

    #[test]
    fn the_nearest_file_wins() {
        let root = scratch("nearest");
        let inner = root.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        save(
            &root,
            &Context {
                version: 1,
                project: Some("outer".into()),
                environment: None,
            },
        )
        .unwrap();
        save(
            &inner,
            &Context {
                version: 1,
                project: Some("inner".into()),
                environment: None,
            },
        )
        .unwrap();
        let (_, ctx) = load_from(&inner).unwrap().unwrap();
        assert_eq!(ctx.project.as_deref(), Some("inner"));
    }

    #[test]
    fn a_malformed_file_is_an_error_not_a_silent_none() {
        // Ignoring it would run every command unscoped in a directory the user
        // believes is pinned.
        let dir = scratch("broken");
        std::fs::write(dir.join(FILE_NAME), "{ not json").unwrap();
        let err = load_from(&dir).unwrap_err();
        assert!(format!("{err}").contains("not valid context JSON"));
    }

    #[test]
    fn the_file_holds_no_secret_material() {
        // The property that lets this file be 0644 and committed to a repo.
        let dir = scratch("fields");
        save(
            &dir,
            &Context {
                version: 1,
                project: Some("web".into()),
                environment: Some("prod".into()),
            },
        )
        .unwrap();
        let raw = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        // Compared as a set: serde_json's map preserves insertion order only
        // with the `preserve_order` feature, which this workspace does not
        // enable. The assertion is about *which* fields exist, not their order.
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["environment", "project", "version"]);
    }

    #[test]
    fn an_explicit_flag_beats_everything() {
        assert_eq!(project(Some("flag")).unwrap().as_deref(), Some("flag"));
    }

    #[test]
    fn resolve_in_vault_matches_id_or_name_substring() {
        let vault = serde_json::json!({
            "projects": [{ "id": "web-app", "name": "Web App" }]
        });
        assert_eq!(
            resolve_in_vault(&vault, "web-app").as_deref(),
            Some("web-app")
        );
        assert_eq!(
            resolve_in_vault(&vault, "web ap").as_deref(),
            Some("web-app")
        );
        assert!(resolve_in_vault(&vault, "database").is_none());
    }
}
