//! File-shaped credentials — Phase 23, E17.
//!
//! The twin of `src/ts/file-cred.ts`.
//!
//! A GCP service-account JSON, an Apple `.p8`, an mTLS bundle and a `kubeconfig`
//! are consumed by *pointing at them*:
//! `GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/sa.json`. Copy-to-clipboard is the
//! wrong verb for all of them, and pasting a 2 KB JSON blob into a `.env`
//! produces a variable the library tries to `open()` as a path.
//!
//! Two fields had each solved half of it: `blob_ref` held a path and not the
//! file, so a fresh machine had the reference and not the credential;
//! `certificate_data` held the PEM and no path, so exporting it for a consumer
//! that wants a file had nowhere to write. This separates **what is stored**
//! from **how it is delivered**, and lets one entry do both.
//!
//! Writing the file *is* the delivery, so every path here is materialising by
//! construction and the Phase 14 rule needs no special case.

use serde_json::Value;

/// The cap on stored file contents.
///
/// A service-account JSON is ~2.3 KB and an embedded icon is already allowed
/// 96 KB. A `kubeconfig` with several clusters or a full chain bundle is a
/// different promise, and **refusing above the cap beats silently storing a
/// truncated credential** — which fails at deploy time with an error about
/// malformed JSON rather than about a vault.
pub const BLOB_MAX_BYTES: usize = 128 * 1024;

fn s<'a>(e: &'a Value, k: &str) -> &'a str {
    e.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// True when this entry's payload is a file rather than a string.
pub fn is_file_shaped(entry: &Value) -> bool {
    !s(entry, "blob_data").is_empty()
        || !s(entry, "certificate_data").is_empty()
        || !s(entry, "cert_key_data").is_empty()
        || !s(entry, "mount_path").is_empty()
}

/// A file extension guessed from the content's own shape, not from a name.
pub fn guess_ext(text: &str) -> &'static str {
    let t = text.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        "json"
    } else if t.starts_with("-----BEGIN") {
        "pem"
    } else if t.lines().any(|l| {
        l.starts_with("apiVersion:") || l.starts_with("kind:") || l.starts_with("clusters:")
    }) {
        "yaml"
    } else {
        "txt"
    }
}

/// The contents this entry would write, and the extension they want.
///
/// `blob_data` first: it is the general case E17 added. `certificate_data` is
/// the pre-existing shape and is kept working rather than migrated — a
/// certificate entry that has worked for twenty phases must not need editing to
/// keep working.
pub fn contents_of(entry: &Value) -> Option<(String, &'static str)> {
    for (field, ext) in [
        ("blob_data", ""),
        ("certificate_data", "pem"),
        ("cert_key_data", "key"),
    ] {
        let v = s(entry, field);
        if !v.is_empty() {
            let ext = if ext.is_empty() { guess_ext(v) } else { ext };
            return Some((v.to_string(), ext));
        }
    }
    None
}

/// The `.env` line a file-shaped entry contributes: the **path**, never the bytes.
///
/// `None` without a `mount_path`, because the honest answer to "what variable
/// does this set" is nothing until the user has said where the file goes.
/// Emitting the contents instead is the mistake this item exists to stop.
pub fn env_line(entry: &Value, name: &str) -> Option<String> {
    let path = s(entry, "mount_path");
    if path.is_empty() {
        None
    } else {
        Some(format!("{name}={path}"))
    }
}

/// A 0700 temporary directory that deletes itself.
///
/// `Drop` rather than an explicit cleanup call, because an explicit one is
/// skipped on a panic and on every early return above it — and what would be
/// left behind is a decrypted credential sitting in `/tmp` with nothing to say
/// it is there. Best effort on removal: a child that is still holding the file
/// open can make it fail, and there is nothing useful to do about that beyond
/// not pretending it succeeded.
pub struct ScratchDir {
    path: std::path::PathBuf,
}

impl ScratchDir {
    pub fn new() -> Result<Self, crate::error::CliError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("envv-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).map_err(|e| {
            crate::error::CliError::from(format!("Cannot create {}: {e}", path.display()))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self { path })
    }

    /// Write one file into the directory, 0600, and return its path.
    ///
    /// The name is sanitised: it comes from a variable name, which comes from
    /// vault data, and a `../` in it would write outside the directory this
    /// exists to confine.
    pub fn write(
        &self,
        name: &str,
        contents: &str,
    ) -> Result<std::path::PathBuf, crate::error::CliError> {
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = self.path.join(safe);
        crate::fmt::write_secret_file(&path, contents)?;
        Ok(path)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
