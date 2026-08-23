//! Encrypted backup (`.vaultbak`) — byte-compatible with the desktop app's
//! WebCrypto implementation in `src/ts/import-export.ts`.
//!
//! Envelope: `{ magic: "ENVVBAK1", kdf: {name, hash, iters}, salt, iv, ct }`,
//! all base64. PBKDF2-SHA256 → AES-256-GCM. The backup password is deliberately
//! *not* the master password: this file is meant to leave the machine.

use crate::access::Access;
use crate::fmt::confirm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use rand::RngCore;
use serde_json::{json, Value};
use crate::error::{CliError, CliResult};

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
    let pw = rpassword::prompt_password("Backup password: ").map_err(|e| CliError::from(e.to_string()))?;
    if confirm_twice {
        let again = rpassword::prompt_password("Repeat: ").map_err(|e| CliError::from(e.to_string()))?;
        if pw != again {
            return Err("Passwords do not match".into());
        }
    }
    Ok(pw)
}

pub fn export(access: &Access, path: &std::path::Path, password: Option<&str>) -> CliResult {
    let pw = ask_password(password, true)?;
    if pw.chars().count() < MIN_PASSWORD {
        return Err(CliError::invalid(format!("Backup password must be at least {MIN_PASSWORD} characters")));
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
        .encrypt(Nonce::from_slice(&iv), Payload { msg: &plain, aad: b"" })
        .map_err(|_| CliError::from("Encryption failed"))?;

    let envelope = json!({
        "magic": BAK_MAGIC,
        "kdf": { "name": "PBKDF2", "hash": "SHA-256", "iters": PBKDF2_ITERS },
        "salt": b64().encode(salt),
        "iv":   b64().encode(iv),
        "ct":   b64().encode(&ct),
    });
    std::fs::write(path, serde_json::to_string(&envelope).map_err(|e| CliError::from(e.to_string()))?)
        .map_err(|e| CliError::from(format!("Cannot write {}: {e}", path.display())))?;
    let n = vault.get("api_keys").and_then(|v| v.as_array()).map_or(0, |a| a.len());
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
    let env: Value = serde_json::from_str(&raw).map_err(|_| CliError::invalid("Not a valid backup file"))?;
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
        &format!("Replace the current vault ({current_n} entries) with this backup ({count} entries)?"),
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
