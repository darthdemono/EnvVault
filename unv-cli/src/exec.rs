//! `unv exec` — run a command with secrets in its environment.
//!
//! This is the command that makes "an agent never touches a key" true rather
//! than aspirational. The orchestrator decides *what to run*; the values travel
//! vault → child process without passing through stdout, a file, or the agent's
//! context. What comes back is the child's own output and exit status.
//!
//! ```text
//! unv exec --project Stack -- ./deploy.sh
//! unv exec --entry GitHub=GH_TOKEN -- gh pr list
//! ```

use crate::access::Access;
use crate::data;
use crate::error::{CliError, CliResult};
use crate::out;
use crate::refs::Resolver;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub struct ExecOpts<'a> {
    /// Resolve every `env_file` chunk of this project into the environment.
    pub project: Option<&'a str>,
    /// `PROVIDER` or `PROVIDER=VAR_NAME`, repeatable.
    pub entries: &'a [String],
    /// `POOL` or `POOL=VAR_NAME`, repeatable.
    ///
    /// Each takes the next usable key from that pool and advances its cursor, so
    /// two runs of the same command use two different credentials. This is the
    /// materialising path for a pool: the value reaches the child process and
    /// never stdout, which is the only way to use a pooled key without anyone —
    /// including an orchestrating agent — reading it.
    pub pools: &'a [String],
    /// Prefix applied to every variable name.
    pub prefix: Option<&'a str>,
    /// Start from an empty environment instead of inheriting this process's.
    pub clean: bool,
}

/// Build the variable set without running anything.
pub fn build_env(access: &Access, opts: &ExecOpts<'_>) -> CliResult<BTreeMap<String, String>> {
    let (env, files) = build_env_and_files(access, opts)?;
    if !files.is_empty() {
        return Err(CliError::invalid(
            "This selection holds a file-shaped credential, which has to be written to disk \
             before it means anything. Use `unv exec` (which writes it to a temp file and \
             removes it afterwards) or `unv file write`.",
        ));
    }
    Ok(env)
}

/// A variable name and the file-shaped entry whose path it will hold.
pub type PendingFile = (String, Value);

/// The environment, plus the files that still have to be written before it is complete.
pub type EnvAndFiles = (BTreeMap<String, String>, Vec<PendingFile>);

/// The variables, plus the file-shaped entries that still need materialising.
///
/// Split out because a file-shaped credential's *value* is a path that does not
/// exist yet: only `run` knows how long the child lives, and therefore how long
/// the temp file may (E17).
pub fn build_env_and_files(access: &Access, opts: &ExecOpts<'_>) -> CliResult<EnvAndFiles> {
    let vault = access.load_vault()?;
    // Materialising: these values are going into a child process, not to stdout.
    let r = Resolver::materialising(&vault);
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut files: Vec<PendingFile> = Vec::new();

    if let Some(p) = opts.project {
        let pi = data::find_project_index(&vault, p)?;
        let project = data::projects(&vault)[pi].clone();
        let out_env = crate::exporters::export_project_env(&project, &r);
        if !out_env.had_chunks {
            return Err(CliError::not_found(format!(
                "Project '{p}' has no env_file chunks to load"
            )));
        }
        if !out_env.unresolved.is_empty() {
            // A blank secret in a child process fails somewhere far from here,
            // usually as an authentication error against a third party. Refuse.
            return Err(CliError::not_found(format!(
                "{} unresolved reference(s) in '{p}': {}",
                out_env.unresolved.len(),
                out_env.unresolved.join(", ")
            )));
        }
        for line in out_env.text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                env.insert(k.to_string(), v.to_string());
            }
        }
    }

    for spec in opts.entries {
        let (query, explicit) = match spec.split_once('=') {
            Some((q, v)) => (q, Some(v.to_string())),
            None => (spec.as_str(), None),
        };
        let idx = data::find_entry_index(&vault, query)?;
        let entry = &data::entries(&vault)[idx];
        // `--entry Provider=VAR:field` selects a field other than the secret.
        // With no `=VAR`, the name comes from the **template** (Phase 23), so a
        // variable injected here is spelled exactly as an export of the same
        // entry would spell it — before this it came from a second normaliser
        // that saw only the query string and therefore knew nothing about the
        // entry's version or label.
        let (var, field) = match explicit {
            Some(v) => match v.split_once(':') {
                Some((v, f)) => (v.to_string(), f.to_string()),
                None => (v, "api_key".to_string()),
            },
            None => (
                crate::envfile::primary_name(entry, None, false),
                "api_key".to_string(),
            ),
        };
        // A **file-shaped** credential is consumed by pointing at it (E17), so
        // what belongs in the child's environment is a path — never the bytes.
        // The file is written to a temp path here and removed after the child
        // exits; see `run`, which owns the lifetime.
        if field == "api_key" && crate::filecred::contents_of(entry).is_some() {
            files.push((var, entry.clone()));
            continue;
        }
        let value = crate::refs::entry_field(entry, &field).ok_or_else(|| {
            CliError::not_found(format!("'{query}' has no value in field '{field}'"))
        })?;
        env.insert(var, value);
    }

    for spec in opts.pools {
        let (name, var) = match spec.split_once('=') {
            Some((n, v)) => (n, v.to_string()),
            // No explicit variable name: derive one from the pool name the same
            // way a bare --entry derives one from the provider, so
            // `--pool github-ci` becomes GITHUB_CI.
            None => (spec.as_str(), crate::envfile::env_name_from_text(spec)),
        };
        let (var, field) = match var.split_once(':') {
            Some((v, f)) => (v.to_string(), f.to_string()),
            None => (var, "api_key".to_string()),
        };
        let picked = crate::pool::select(access, &vault, name)?;
        let entry = &data::entries(&vault)[picked.idx];
        let value = crate::refs::entry_field(entry, &field).ok_or_else(|| {
            CliError::not_found(format!(
                "'{}' from pool '{name}' has no value in field '{field}'",
                picked.label()
            ))
        })?;
        env.insert(var, value);
    }

    if env.is_empty() && files.is_empty() {
        return Err(CliError::invalid(
            "Nothing to load — pass --project, --entry and/or --pool",
        ));
    }

    if let Some(prefix) = opts.prefix {
        env = env
            .into_iter()
            .map(|(k, v)| (format!("{prefix}{k}"), v))
            .collect();
        files = files
            .into_iter()
            .map(|(k, e)| (format!("{prefix}{k}"), e))
            .collect();
    }
    Ok((env, files))
}

/// The manifest an orchestrator is allowed to see: names and fingerprints.
pub fn manifest(env: &BTreeMap<String, String>) -> Value {
    let vars: Vec<Value> = env
        .iter()
        .map(|(k, v)| json!({ "name": k, "fingerprint": out::fingerprint(v), "length": v.chars().count() }))
        .collect();
    json!({ "count": vars.len(), "variables": vars })
}

/// Load the variables and run `argv`, returning the child's exit code.
pub fn run(access: &Access, opts: &ExecOpts<'_>, argv: &[String]) -> CliResult<i32> {
    let Some((program, args)) = argv.split_first() else {
        return Err(CliError::invalid(
            "No command given — use `unv exec … -- <command>`",
        ));
    };
    let (mut env, files) = build_env_and_files(access, opts)?;

    // File-shaped credentials are written to a temp directory, their paths go
    // into the child's environment, and the directory is removed when this
    // function returns (E17). `TempDir`'s `Drop` is what guarantees the last
    // part — an explicit delete after `status()` would be skipped on a panic and
    // on every early return above it, leaving a decrypted credential in `/tmp`.
    let scratch = if files.is_empty() {
        None
    } else {
        Some(crate::filecred::ScratchDir::new()?)
    };
    if let Some(dir) = &scratch {
        for (var, entry) in &files {
            let (contents, ext) = crate::filecred::contents_of(entry)
                .ok_or_else(|| CliError::invalid("File-shaped entry lost its contents"))?;
            let path = dir.write(&format!("{var}.{ext}"), &contents)?;
            env.insert(var.clone(), path.display().to_string());
        }
    }

    if out::dry_run() {
        let m = manifest(&env);
        out::ok(
            "exec",
            json!({ "command": argv, "env": m, "executed": false }),
            || {
                println!("Would run: {}", argv.join(" "));
                println!(
                    "With {} variable(s): {}",
                    env.len(),
                    env.keys().cloned().collect::<Vec<_>>().join(", ")
                );
            },
        );
        return Ok(0);
    }

    // The values are about to enter a child's environment: note which vault
    // secrets, so a later compromise of this machine can be scoped.
    crate::matlog::note(
        "exec",
        &argv.join(" "),
        &env.values().cloned().collect::<Vec<_>>().join("\n"),
    );

    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    if opts.clean {
        cmd.env_clear();
        // A few variables have to survive or the child cannot run at all.
        // On Windows that is more than PATH: without SYSTEMROOT, anything
        // touching the CRT or winsock fails with errors that name none of this.
        const KEEP_UNIX: &[&str] = &["PATH", "HOME", "LANG", "TERM"];
        const KEEP_WINDOWS: &[&str] = &[
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "SYSTEMDRIVE",
            "WINDIR",
            "TEMP",
            "TMP",
            "COMSPEC",
            "USERPROFILE",
        ];
        let keep = if cfg!(windows) {
            KEEP_WINDOWS
        } else {
            KEEP_UNIX
        };
        for key in keep {
            if let Some(value) = std::env::var_os(key) {
                cmd.env(key, value);
            }
        }
    }
    for (k, v) in &env {
        cmd.env(k, v);
    }

    let status = cmd
        .status()
        .map_err(|e| CliError::not_found(format!("Cannot run '{program}': {e}")))?;
    // The child's exit code is the useful signal, so it becomes ours. A caller
    // scripting `unv exec … -- pytest` gets pytest's result, not a wrapper's.
    Ok(status.code().unwrap_or(1))
}
