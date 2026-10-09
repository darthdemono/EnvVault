//! Phase 34 — the filesystem half of a node: hash a target, apply bytes to it
//! transactionally, and keep the last few versions.
//!
//! The rules, in the order they matter:
//!
//! 1. The bytes must hash to what the hub said they hash to, **before anything
//!    is touched**. Phase 37's approval token binds to that hash.
//! 2. The write is temp file in the same directory, `fsync`, rename. A reader
//!    sees the old file or the new one, never half of either.
//! 3. The previous file is copied aside first and the last [`KEEP_VERSIONS`]
//!    are kept.
//! 4. `validate` runs against the file in place. Failing it restores the
//!    previous file and does not reload.
//! 5. `reload` runs last. Failing it restores the previous file and does not
//!    try again: the service is in a state only the operator can judge.
//!
//! Commands come from the node's own config and nowhere else.

use crate::nodes::Target;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const KEEP_VERSIONS: usize = 3;
/// How long `validate` or `reload` may run.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Hash of the file at `path`: `Ok(None)` when it does not exist.
pub fn hash_file(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(sha256_hex(&b))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Runs `cmd` through the platform shell and returns `Ok(())` on exit 0.
/// The error carries a few scrubbed lines of output, never the file's content.
fn run(cmd: &str, content: &str, timeout: Duration) -> Result<(), String> {
    #[cfg(windows)]
    let mut c = {
        let mut c = Command::new("cmd");
        c.args(["/C", cmd]);
        c
    };
    #[cfg(not(windows))]
    let mut c = {
        let mut c = Command::new("sh");
        c.args(["-c", cmd]);
        c
    };
    let mut child = c
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start '{cmd}': {e}"))?;
    let start = Instant::now();
    let status = loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(s) => break s,
            None if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "'{cmd}' did not finish in {}s",
                    timeout.as_secs().max(1)
                ));
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    if status.success() {
        return Ok(());
    }
    let mut text = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.by_ref().take(8192).read_to_string(&mut text);
    }
    if text.trim().is_empty() {
        if let Some(mut o) = child.stdout.take() {
            let _ = o.by_ref().take(8192).read_to_string(&mut text);
        }
    }
    Err(format!(
        "'{cmd}' exited {}: {}",
        status.code().map_or("by signal".into(), |c| c.to_string()),
        scrub(&text, content)
    ))
}

/// The last three lines of `output`, each cut to 200 characters, with any line
/// that is also a line of the file being applied replaced. A validator that
/// echoes the offending line of a config would otherwise put a secret into an
/// error that travels to the hub and into its audit log.
pub fn scrub(output: &str, content: &str) -> String {
    let file_lines: std::collections::HashSet<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| l.len() >= 8)
        .collect();
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let tail = &lines[lines.len().saturating_sub(3)..];
    tail.iter()
        .map(|l| {
            if file_lines.contains(l) || file_lines.iter().any(|f| l.contains(f)) {
                "[a line of the file elided]".to_string()
            } else {
                l.chars().take(200).collect()
            }
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn versions_dir(state_dir: &Path, id: &str) -> PathBuf {
    state_dir.join("versions").join(id)
}

fn write_atomic(
    path: &Path,
    bytes: &[u8],
    mode_from: Option<&std::fs::Metadata>,
) -> Result<(), String> {
    use std::io::Write;
    let dir = path.parent().ok_or("target has no parent directory")?;
    let name = path.file_name().ok_or("target has no file name")?;
    let tmp = dir.join(format!(".{}.envv-node.tmp", name.to_string_lossy()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        // Keep the mode the operator gave the file; a new one is private.
        opts.mode(mode_from.map_or(0o600, |m| m.mode() & 0o7777));
    }
    #[cfg(not(unix))]
    let _ = mode_from;
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("cannot write beside {}: {e}", path.display()))?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot replace {}: {e}", path.display())
    })?;
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn restore(
    path: &Path,
    previous: &Option<Vec<u8>>,
    meta: Option<&std::fs::Metadata>,
) -> Result<(), String> {
    match previous {
        Some(b) => write_atomic(path, b, meta),
        None => std::fs::remove_file(path).map_err(|e| e.to_string()),
    }
}

fn keep_version(state_dir: &Path, id: &str, bytes: &[u8]) -> Result<(), String> {
    let dir = versions_dir(state_dir, id);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let name = format!("{secs:012}-{}", &sha256_hex(bytes)[..8]);
    let p = dir.join(name);
    // 0600 through the same helper: a kept copy of wg0.conf is as secret as
    // wg0.conf.
    write_atomic(&p, bytes, None)?;
    let mut all: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            !p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        })
        .collect();
    all.sort();
    while all.len() > KEEP_VERSIONS {
        let _ = std::fs::remove_file(all.remove(0));
    }
    Ok(())
}

/// The versions kept for a target, oldest first.
pub fn kept_versions(state_dir: &Path, id: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(versions_dir(state_dir, id))
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

#[derive(Debug, PartialEq)]
pub enum Applied {
    /// The file already had these bytes.
    Unchanged,
    Written,
}

/// Applies `content` to `target`. See the module comment for the contract.
pub fn apply(
    target: &Target,
    content: &[u8],
    expected_sha: &str,
    state_dir: &Path,
) -> Result<Applied, String> {
    if target.mode != "push" || !target.apply {
        return Err(format!(
            "target '{}' is not set to apply; the node's config decides that, not the hub",
            target.id
        ));
    }
    if sha256_hex(content) != expected_sha {
        return Err(
            "content does not match the hash the hub announced; nothing was written".into(),
        );
    }
    let text = String::from_utf8_lossy(content).into_owned();
    let path = &target.path;
    let meta = std::fs::metadata(path).ok();
    let previous = match std::fs::read(path) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if previous.as_deref() == Some(content) {
        return Ok(Applied::Unchanged);
    }
    if let Some(p) = &previous {
        keep_version(state_dir, &target.id, p)?;
    }
    write_atomic(path, content, meta.as_ref())?;

    if let Some(v) = &target.validate {
        if let Err(e) = run(v, &text, COMMAND_TIMEOUT) {
            return Err(match restore(path, &previous, meta.as_ref()) {
                Ok(()) => format!("validate failed, previous file restored: {e}"),
                Err(r) => {
                    format!("validate failed AND restoring the previous file failed ({r}): {e}")
                }
            });
        }
    }
    if let Some(r) = &target.reload {
        if let Err(e) = run(r, &text, COMMAND_TIMEOUT) {
            return Err(match restore(path, &previous, meta.as_ref()) {
                Ok(()) => format!(
                    "reload failed, previous file restored and the service was not reloaded again: {e}"
                ),
                Err(x) => format!("reload failed AND restoring the previous file failed ({x}): {e}"),
            });
        }
    }
    Ok(Applied::Written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("envv-apply-{tag}-{n}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn target(dir: &Path, validate: Option<&str>, reload: Option<&str>) -> Target {
        Target {
            id: "t".into(),
            path: dir.join("app.conf"),
            project: "p".into(),
            exporter: "nginx".into(),
            mode: "push".into(),
            apply: true,
            validate: validate.map(String::from),
            reload: reload.map(String::from),
            require_approval: false,
        }
    }

    #[test]
    fn a_hash_mismatch_writes_nothing() {
        let d = scratch("hash");
        let t = target(&d, None, None);
        let e = apply(&t, b"new", &sha256_hex(b"other"), &d).unwrap_err();
        assert!(e.contains("does not match"));
        assert!(!t.path.exists());
    }

    #[test]
    fn apply_is_refused_unless_the_nodes_own_config_allows_it() {
        let d = scratch("noapply");
        let mut t = target(&d, None, None);
        t.apply = false;
        assert!(apply(&t, b"x", &sha256_hex(b"x"), &d)
            .unwrap_err()
            .contains("not set to apply"));
        t.apply = true;
        t.mode = "pull".into();
        assert!(apply(&t, b"x", &sha256_hex(b"x"), &d).is_err());
        assert!(!t.path.exists());
    }

    #[test]
    fn writes_the_file_and_keeps_the_previous_one() {
        let d = scratch("write");
        let t = target(&d, None, None);
        std::fs::write(&t.path, "old").unwrap();
        assert_eq!(
            apply(&t, b"new", &sha256_hex(b"new"), &d).unwrap(),
            Applied::Written
        );
        assert_eq!(std::fs::read_to_string(&t.path).unwrap(), "new");
        let kept = kept_versions(&d, "t");
        assert_eq!(kept.len(), 1);
        assert_eq!(std::fs::read_to_string(&kept[0]).unwrap(), "old");
        // Applying the same bytes again is a no-op, not another version.
        assert_eq!(
            apply(&t, b"new", &sha256_hex(b"new"), &d).unwrap(),
            Applied::Unchanged
        );
        assert_eq!(kept_versions(&d, "t").len(), 1);
    }

    #[test]
    fn only_the_last_three_versions_are_kept() {
        let d = scratch("keep");
        let t = target(&d, None, None);
        std::fs::write(&t.path, "v0").unwrap();
        for i in 1..=6 {
            let c = format!("v{i}");
            // Distinct seconds are not guaranteed; the hash in the name keeps
            // the files distinct and the sort stable enough for a count.
            apply(&t, c.as_bytes(), &sha256_hex(c.as_bytes()), &d).unwrap();
        }
        assert_eq!(kept_versions(&d, "t").len(), KEEP_VERSIONS);
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_validate_restores_the_old_file_and_never_reloads() {
        let d = scratch("validate");
        let marker = d.join("reloaded");
        let t = target(
            &d,
            Some("echo bad config >&2; exit 1"),
            Some(&format!("touch {}", marker.display())),
        );
        std::fs::write(&t.path, "old").unwrap();
        let e = apply(&t, b"new", &sha256_hex(b"new"), &d).unwrap_err();
        assert!(e.contains("validate failed, previous file restored"), "{e}");
        assert!(e.contains("bad config"), "{e}");
        assert_eq!(std::fs::read_to_string(&t.path).unwrap(), "old");
        assert!(!marker.exists(), "reload ran after a failed validate");
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_validate_on_a_new_file_removes_it() {
        let d = scratch("validate-new");
        let t = target(&d, Some("exit 3"), None);
        assert!(apply(&t, b"new", &sha256_hex(b"new"), &d).is_err());
        assert!(!t.path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_reload_restores_the_old_file() {
        let d = scratch("reload");
        let t = target(&d, Some("true"), Some("exit 2"));
        std::fs::write(&t.path, "old").unwrap();
        let e = apply(&t, b"new", &sha256_hex(b"new"), &d).unwrap_err();
        assert!(e.contains("reload failed, previous file restored"), "{e}");
        assert_eq!(std::fs::read_to_string(&t.path).unwrap(), "old");
    }

    #[cfg(unix)]
    #[test]
    fn validate_sees_the_new_file_in_place() {
        let d = scratch("inplace");
        let t = target(
            &d,
            Some(&format!("grep -q NEW {}", d.join("app.conf").display())),
            None,
        );
        std::fs::write(&t.path, "old").unwrap();
        assert!(apply(&t, b"NEW", &sha256_hex(b"NEW"), &d).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_runaway_command_is_killed_at_the_timeout() {
        let t0 = Instant::now();
        let e = run("sleep 30", "", Duration::from_millis(300)).unwrap_err();
        assert!(e.contains("did not finish"), "{e}");
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "waited for the command"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_files_mode_is_kept_and_a_new_one_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("mode");
        let t = target(&d, None, None);
        std::fs::write(&t.path, "old").unwrap();
        std::fs::set_permissions(&t.path, std::fs::Permissions::from_mode(0o640)).unwrap();
        apply(&t, b"new", &sha256_hex(b"new"), &d).unwrap();
        assert_eq!(
            std::fs::metadata(&t.path).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let t2 = Target {
            id: "u".into(),
            path: d.join("fresh.conf"),
            ..t
        };
        apply(&t2, b"x", &sha256_hex(b"x"), &d).unwrap();
        assert_eq!(
            std::fs::metadata(&t2.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // The kept copy of a secret file is private too.
        let kept = kept_versions(&d, "t");
        assert_eq!(
            std::fs::metadata(&kept[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn scrub_elides_a_line_of_the_file_and_keeps_the_rest() {
        let content = "server {\n  secret_token abcdef123456;\n}\n";
        let out = scrub(
            "nginx: [emerg] unknown directive in conf:2\nsecret_token abcdef123456;\n",
            content,
        );
        assert!(!out.contains("abcdef123456"));
        assert!(out.contains("unknown directive"));
        assert!(out.contains("elided"));
    }

    #[test]
    fn a_missing_file_has_no_hash_and_a_present_one_does() {
        let d = scratch("hashfile");
        assert_eq!(hash_file(&d.join("nope")).unwrap(), None);
        std::fs::write(d.join("f"), "abc").unwrap();
        assert_eq!(
            hash_file(&d.join("f")).unwrap().unwrap(),
            sha256_hex(b"abc")
        );
    }
}
