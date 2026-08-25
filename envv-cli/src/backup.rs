//! Encrypted backup (`.vaultbak`) — byte-compatible with the desktop app's
//! WebCrypto implementation in `src/ts/import-export.ts`.
//!
//! Envelope: `{ magic: "ENVVBAK1", kdf: {name, hash, iters}, salt, iv, ct }`,
//! all base64. PBKDF2-SHA256 → AES-256-GCM. The backup password is deliberately
//! *not* the master password: this file is meant to leave the machine.

use crate::access::Access;
use crate::error::{CliError, CliResult};
use crate::fmt::confirm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use rand::RngCore;
use serde_json::{json, Value};

const BAK_MAGIC: &str = "ENVVBAK1";
const PBKDF2_ITERS: u32 = 210_000;
/// Same floor the app enforces, and for the same reason: this one file is the
/// whole vault, so it must not be the weakest link in the chain.
const MIN_PASSWORD: usize = 12;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn derive(password: &str, salt: &[u8], iters: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, iters, &mut key);
    key
}

fn ask_password(provided: Option<&str>, confirm_twice: bool) -> CliResult<String> {
    if let Some(p) = provided {
        return Ok(p.to_string());
    }
    let pw = rpassword::prompt_password("Backup password: ")
        .map_err(|e| CliError::from(e.to_string()))?;
    if confirm_twice {
        let again =
            rpassword::prompt_password("Repeat: ").map_err(|e| CliError::from(e.to_string()))?;
        if pw != again {
            return Err("Passwords do not match".into());
        }
    }
    Ok(pw)
}

pub fn export(access: &Access, path: &std::path::Path, password: Option<&str>) -> CliResult {
    let pw = ask_password(password, true)?;
    if pw.chars().count() < MIN_PASSWORD {
        return Err(CliError::invalid(format!(
            "Backup password must be at least {MIN_PASSWORD} characters"
        )));
    }
    let vault = access.load_vault()?;

    let mut salt = [0u8; 16];
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut iv);

    let key = derive(&pw, &salt, PBKDF2_ITERS);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| CliError::from(e.to_string()))?;
    let plain = serde_json::to_vec(&vault).map_err(|e| CliError::from(e.to_string()))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &plain,
                aad: b"",
            },
        )
        .map_err(|_| CliError::from("Encryption failed"))?;

    let envelope = json!({
        "magic": BAK_MAGIC,
        "kdf": { "name": "PBKDF2", "hash": "SHA-256", "iters": PBKDF2_ITERS },
        "salt": b64().encode(salt),
        "iv":   b64().encode(iv),
        "ct":   b64().encode(&ct),
    });
    std::fs::write(
        path,
        serde_json::to_string(&envelope).map_err(|e| CliError::from(e.to_string()))?,
    )
    .map_err(|e| CliError::from(format!("Cannot write {}: {e}", path.display())))?;
    let n = vault
        .get("api_keys")
        .and_then(|v| v.as_array())
        .map_or(0, |a| a.len());
    crate::out::ok(
        "backup.export",
        json!({ "path": path.display().to_string(), "entries": n, "kdf_iters": PBKDF2_ITERS }),
        || println!("Encrypted backup of {n} entries → {}", path.display()),
    );
    Ok(())
}

pub fn import(
    access: &Access,
    path: &std::path::Path,
    password: Option<&str>,
    yes: bool,
) -> CliResult {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CliError::from(format!("Cannot read {}: {e}", path.display())))?;
    let env: Value =
        serde_json::from_str(&raw).map_err(|_| CliError::invalid("Not a valid backup file"))?;
    if env.get("magic").and_then(|v| v.as_str()) != Some(BAK_MAGIC) {
        return Err("Unrecognised backup format".into());
    }
    let pw = ask_password(password, false)?;

    let dec = |k: &str| -> CliResult<Vec<u8>> {
        b64()
            .decode(env.get(k).and_then(|v| v.as_str()).unwrap_or(""))
            .map_err(|_| CliError::invalid(format!("Corrupt backup: bad {k}")))
    };
    let salt = dec("salt")?;
    let iv = dec("iv")?;
    let ct = dec("ct")?;
    // Honour the iteration count recorded in the envelope — a backup written with
    // any other count would otherwise fail to decrypt and be reported as a wrong
    // password.
    let iters = env
        .get("kdf")
        .and_then(|k| k.get("iters"))
        .and_then(|v| v.as_u64())
        .filter(|n| *n > 0)
        .map(|n| n as u32)
        .unwrap_or(PBKDF2_ITERS);

    let key = derive(&pw, &salt, iters);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| CliError::from(e.to_string()))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: b"" })
        .map_err(|_| CliError::denied("Decryption failed — wrong password or corrupt file"))?;
    let data: Value = serde_json::from_slice(&plain).map_err(|e| CliError::from(e.to_string()))?;
    let count = data
        .get("api_keys")
        .and_then(|v| v.as_array())
        .ok_or("Backup is missing api_keys")?
        .len();

    let current = access.load_vault().ok();
    let current_n = current
        .as_ref()
        .and_then(|v| v.get("api_keys"))
        .and_then(|v| v.as_array())
        .map_or(0, |a| a.len());
    if !confirm(
        &format!(
            "Replace the current vault ({current_n} entries) with this backup ({count} entries)?"
        ),
        yes,
    )? {
        println!("Cancelled.");
        return Ok(());
    }

    let restored = json!({
        "api_keys": data.get("api_keys").cloned().unwrap_or(json!([])),
        "user_categories": data.get("user_categories").cloned().unwrap_or(json!([])),
        "projects": data.get("projects").cloned().unwrap_or(json!([{
            "id": "Universal", "name": "Universal",
            "description": "All keys belong here by default"
        }])),
    });
    access.save(&restored)?;
    crate::out::ok(
        "backup.import",
        json!({ "path": path.display().to_string(), "entries": count, "replaced": true }),
        || println!("Restored {count} entries from {}", path.display()),
    );
    Ok(())
}

// ── Archive: the vault file and its salt, together ───────────────────────────

const ARCHIVE_MAGIC: &str = "ENVVARC1";

/// Encrypted archive of the raw vault **and its salt**.
///
/// This is not the same job as [`export`]. A `.vaultbak` holds the decrypted
/// vault re-encrypted under a fresh backup password, so restoring it needs no
/// salt at all — a new one is generated and the master password re-derives
/// against it. An archive is the other half: a byte copy of `vault.db` paired
/// with the 16 bytes that make it openable.
///
/// It exists because of what *cannot* be built. The salt is CSPRNG output,
/// written once, derived from nothing and duplicated nowhere; if it is lost the
/// database is unopenable by anyone, including the person who knows the master
/// password. No `--repair` can reconstruct it, and a command that appeared to
/// offer that would be discovered as a lie at the worst possible moment. So the
/// answer is to make losing it hard: one file that carries both, with a
/// manifest that proves they belong together.
pub fn archive(path: &std::path::Path, password: Option<&str>) -> CliResult {
    let pw = ask_password(password, true)?;
    if pw.chars().count() < MIN_PASSWORD {
        return Err(CliError::invalid(format!(
            "Archive password must be at least {MIN_PASSWORD} characters"
        )));
    }
    let db_path = crate::access::default_db_path();
    let salt_path = crate::access::default_salt_path();
    let db = std::fs::read(&db_path)
        .map_err(|e| CliError::unavailable(format!("Cannot read {}: {e}", db_path.display())))?;
    let salt = std::fs::read(&salt_path)
        .map_err(|e| CliError::unavailable(format!("Cannot read {}: {e}", salt_path.display())))?;

    // The manifest is what makes a mispairing detectable. Restoring a database
    // with the wrong salt derives the wrong key and reports "wrong password" for
    // a password that is entirely correct — a failure that sends people looking
    // in exactly the wrong place.
    let manifest = json!({
        "db_sha256":   crate::out::raw_sha256_hex(&db),
        "salt_sha256": crate::out::raw_sha256_hex(&salt),
        "db_bytes":    db.len(),
        "created_at":  vault_core::iso_now(),
        "version":     env!("CARGO_PKG_VERSION"),
    });

    let mut kdf_salt = [0u8; 16];
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut kdf_salt);
    rand::thread_rng().fill_bytes(&mut iv);
    let key = derive(&pw, &kdf_salt, PBKDF2_ITERS);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| CliError::from(e.to_string()))?;

    let plain = json!({
        "db":       b64().encode(&db),
        "salt":     b64().encode(&salt),
        "manifest": manifest.clone(),
    });
    let plain = serde_json::to_vec(&plain).map_err(|e| CliError::from(e.to_string()))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &plain,
                aad: ARCHIVE_MAGIC.as_bytes(),
            },
        )
        .map_err(|_| CliError::from("Encryption failed"))?;

    let envelope = json!({
        "magic": ARCHIVE_MAGIC,
        "kdf":   { "name": "PBKDF2", "hash": "SHA-256", "iters": PBKDF2_ITERS },
        "salt":  b64().encode(kdf_salt),
        "iv":    b64().encode(iv),
        "ct":    b64().encode(&ct),
    });
    std::fs::write(
        path,
        serde_json::to_string(&envelope).map_err(|e| CliError::from(e.to_string()))?,
    )
    .map_err(|e| CliError::from(format!("Cannot write {}: {e}", path.display())))?;
    // The archive is the vault. Anything that can read it can open the vault
    // with the archive password alone, so it gets the same mode as the session
    // file rather than whatever the umask happened to be.
    crate::session::restrict(path)?;

    crate::out::ok(
        "backup archive",
        json!({
            "path": path.display().to_string(),
            "manifest": manifest,
        }),
        || {
            println!("Archived vault + salt → {}", path.display());
            println!("Keep the archive password somewhere the archive is not.");
        },
    );
    Ok(())
}

/// Restore a `.vaultarc` written by [`archive`].
///
/// Refuses to overwrite an existing vault without `--force`: the failure mode
/// this guards against is restoring last month's archive over a live vault, and
/// unlike a lost salt that one *is* preventable.
pub fn restore_archive(
    path: &std::path::Path,
    password: Option<&str>,
    force: bool,
    assume_yes: bool,
) -> CliResult {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CliError::not_found(format!("Cannot read {}: {e}", path.display())))?;
    let env: Value = serde_json::from_str(&raw)
        .map_err(|_| CliError::invalid("Not an archive file (invalid JSON)"))?;
    if env.get("magic").and_then(|m| m.as_str()) != Some(ARCHIVE_MAGIC) {
        return Err(CliError::invalid(format!(
            "Not an EnvVault archive. A `.vaultbak` holds vault contents and is \
             restored with `envv backup import`; an archive ({ARCHIVE_MAGIC}) holds \
             the database file and its salt."
        )));
    }
    let dec = |k: &str| -> CliResult<Vec<u8>> {
        b64()
            .decode(env.get(k).and_then(|v| v.as_str()).unwrap_or(""))
            .map_err(|_| CliError::invalid(format!("Archive field '{k}' is not valid base64")))
    };
    let kdf_salt = dec("salt")?;
    let iv = dec("iv")?;
    let ct = dec("ct")?;
    let iters = env
        .get("kdf")
        .and_then(|k| k.get("iters"))
        .and_then(|i| i.as_u64())
        .unwrap_or(PBKDF2_ITERS as u64) as u32;

    let pw = ask_password(password, false)?;
    let key = derive(&pw, &kdf_salt, iters);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| CliError::from(e.to_string()))?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &ct,
                aad: ARCHIVE_MAGIC.as_bytes(),
            },
        )
        .map_err(|_| CliError::denied("Wrong archive password, or the archive is corrupt"))?;
    let body: Value = serde_json::from_slice(&plain)
        .map_err(|_| CliError::invalid("Archive payload is not JSON"))?;

    let db = b64()
        .decode(body.get("db").and_then(|v| v.as_str()).unwrap_or(""))
        .map_err(|_| CliError::invalid("Archive database is not valid base64"))?;
    let salt = b64()
        .decode(body.get("salt").and_then(|v| v.as_str()).unwrap_or(""))
        .map_err(|_| CliError::invalid("Archive salt is not valid base64"))?;

    // Verify before writing, not after. A corrupt archive that has already
    // overwritten a working vault is the one outcome worse than a failed restore.
    if let Some(m) = body.get("manifest") {
        let want_db = m.get("db_sha256").and_then(|v| v.as_str()).unwrap_or("");
        let want_salt = m.get("salt_sha256").and_then(|v| v.as_str()).unwrap_or("");
        if !want_db.is_empty() && crate::out::raw_sha256_hex(&db) != want_db {
            return Err(CliError::invalid(
                "Archive database does not match its manifest checksum — the file is damaged",
            ));
        }
        if !want_salt.is_empty() && crate::out::raw_sha256_hex(&salt) != want_salt {
            return Err(CliError::invalid(
                "Archive salt does not match its manifest checksum — the file is damaged",
            ));
        }
    }
    if salt.len() != 16 {
        return Err(CliError::invalid(format!(
            "Archive salt is {} bytes, expected 16",
            salt.len()
        )));
    }

    let db_path = crate::access::default_db_path();
    let salt_path = crate::access::default_salt_path();
    if db_path.exists() && !force {
        return Err(CliError::conflict(format!(
            "{} already exists. Restoring would replace the vault on this machine.\n\
             Re-run with --force if that is what you want.",
            db_path.display()
        )));
    }
    if db_path.exists() && !assume_yes {
        confirm(
            &format!("Replace the vault at {}?", db_path.display()),
            false,
        )?;
    }
    if let Some(dir) = db_path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| CliError::from(format!("Cannot create {}: {e}", dir.display())))?;
    }
    // Salt first. If writing the database then fails, a salt without a database
    // is recoverable — you restore again. A database without its salt is not.
    std::fs::write(&salt_path, &salt)
        .map_err(|e| CliError::from(format!("Cannot write {}: {e}", salt_path.display())))?;
    crate::session::restrict(&salt_path)?;
    std::fs::write(&db_path, &db)
        .map_err(|e| CliError::from(format!("Cannot write {}: {e}", db_path.display())))?;
    crate::session::restrict(&db_path)?;

    crate::out::ok(
        "backup restore-archive",
        json!({
            "db_path":   db_path.display().to_string(),
            "salt_path": salt_path.display().to_string(),
            "db_bytes":  db.len(),
        }),
        || {
            println!("Restored {} ({} bytes)", db_path.display(), db.len());
            println!("Unlock it with the master password the archive was made under.");
        },
    );
    Ok(())
}
