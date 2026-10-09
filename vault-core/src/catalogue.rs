//! The provider catalogue: a signed, public table of issuer key prefixes that
//! `unv enrich` consults before the table compiled into the binary.
//!
//! The compiled table can only be updated by a release. This one is published
//! as a static file, fetched **whole** (a per-provider request would tell the
//! host which providers you hold credentials for), cached locally and verified
//! on **every load**, not only on download.
//!
//! Enrichment writes into the vault, so a tampered catalogue could mislabel
//! secret types or point a card at an attacker's URL. Hence:
//!
//! - an Ed25519 signature over the exact payload bytes, checked against
//!   [`PINNED_KEY_HEX`], which lives in the binary;
//! - `generated_at` may never go backwards (replaying an old, valid file);
//! - every field is shape-checked after the signature, because a correctly
//!   signed typo is still a typo: prefixes under 3 characters would match
//!   nearly every secret, and non-`https` URLs never reach a card.
//!
//! The catalogue holds no secrets and no user data. See ADR-0139.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const SCHEMA: u32 = 1;

/// Where the scheduled `docs.yml` run publishes the signed catalogue. Not yet
/// verified against a live Pages deployment.
pub const DEFAULT_URL: &str = "https://darthdemono.github.io/EnvVault/catalogue/catalogue.json";

/// Ed25519 public key the catalogue must be signed with. The private half is
/// the `CATALOGUE_SIGNING_KEY` Actions secret; rotating it means a release.
pub const PINNED_KEY_HEX: &str = "12d80743bd61b75e2a355ff299e64a8cfb46da855ad1be3f669156d6cd89ba9a";

fn pinned_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    hex::decode_to_slice(PINNED_KEY_HEX, &mut k).expect("PINNED_KEY_HEX is 64 hex digits");
    k
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provider {
    pub prefix: String,
    pub issuer: String,
    pub secret_type: String,
    pub icon: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Taxonomy axes (Phase 24.5), applied by `enrich` as suggestions only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts_as: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<String>,
    /// Where to revoke or rotate it: proposed into the entry's `console_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console_url: Option<String>,
    /// Reference links. Carried for the catalogue's readers; not applied to entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_url: Option<String>,
    /// Where the prefix is published and when somebody last checked it there
    /// (Phase 31.3). Optional so older clients and older entries still parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Catalogue {
    pub schema: u32,
    /// RFC 3339 UTC, fixed width, so string order is time order.
    pub generated_at: String,
    pub providers: Vec<Provider>,
}

/// On the wire: the payload is a JSON **string**, so the signature covers the
/// exact bytes the publisher signed and no re-serialisation can disturb it.
#[derive(Serialize, Deserialize)]
struct Signed {
    payload: String,
    signature: String,
}

fn https(u: &Option<String>) -> bool {
    u.as_deref()
        .is_none_or(|s| s.starts_with("https://") && s.len() < 300)
}

fn validate(c: &Catalogue) -> Result<(), String> {
    if c.schema != SCHEMA {
        return Err(format!("unsupported catalogue schema {}", c.schema));
    }
    if c.generated_at.len() != 20 || !c.generated_at.ends_with('Z') {
        return Err("generated_at must be YYYY-MM-DDTHH:MM:SSZ".into());
    }
    if c.providers.is_empty() || c.providers.len() > 20_000 {
        return Err("provider count out of range".into());
    }
    for p in &c.providers {
        let ok_prefix = p.prefix.len() >= 3
            && p.prefix.len() <= 64
            && p.prefix.bytes().all(|b| b.is_ascii_graphic());
        if !ok_prefix {
            return Err(format!("unusable prefix `{}`", p.prefix.escape_debug()));
        }
        if p.issuer.is_empty() || p.issuer.len() > 80 || p.icon.len() > 64 {
            return Err(format!("bad issuer/icon for `{}`", p.prefix));
        }
        if crate::secret_types::find(&p.secret_type).is_none() {
            return Err(format!("unknown secret type `{}`", p.secret_type));
        }
        if !(https(&p.api_url)
            && https(&p.docs_url)
            && https(&p.rotate_url)
            && https(&p.revoke_url))
        {
            return Err(format!("non-https URL for `{}`", p.prefix));
        }
        if !(https(&p.console_url)) {
            return Err(format!("non-https console URL for `{}`", p.prefix));
        }
        const ACTS: [&str; 6] = [
            "anonymous",
            "user",
            "service",
            "bot",
            "installation",
            "admin",
        ];
        const EXPO: [&str; 3] = ["publishable", "server_only", "verify_only"];
        if p.acts_as.as_deref().is_some_and(|v| !ACTS.contains(&v))
            || p.exposure.as_deref().is_some_and(|v| !EXPO.contains(&v))
        {
            return Err(format!("unknown axis value for `{}`", p.prefix));
        }
        if p.environment.as_deref().is_some_and(|e| e.len() > 24) {
            return Err(format!("bad environment for `{}`", p.prefix));
        }
    }
    Ok(())
}

/// Check signature and shape. Does not look at the cache.
pub fn verify(raw: &[u8], key: &[u8; 32]) -> Result<Catalogue, String> {
    let signed: Signed =
        serde_json::from_slice(raw).map_err(|e| format!("not a catalogue: {e}"))?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(signed.signature.trim())
        .map_err(|_| "signature is not base64".to_string())?;
    let sig =
        Signature::from_slice(&sig).map_err(|_| "signature has the wrong length".to_string())?;
    let vk = VerifyingKey::from_bytes(key).map_err(|e| e.to_string())?;
    vk.verify(signed.payload.as_bytes(), &sig)
        .map_err(|_| "signature does not match the pinned key".to_string())?;
    let c: Catalogue = serde_json::from_str(&signed.payload).map_err(|e| e.to_string())?;
    validate(&c)?;
    Ok(c)
}

/// Publisher side: sign `c` with a 32-byte Ed25519 seed. Used by
/// `unv catalogue sign` in the scheduled workflow.
pub fn sign(c: &Catalogue, seed: &[u8; 32]) -> Result<String, String> {
    validate(c)?;
    let payload = serde_json::to_string(c).map_err(|e| e.to_string())?;
    let sig = SigningKey::from_bytes(seed).sign(payload.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    serde_json::to_string_pretty(&Signed { payload, signature }).map_err(|e| e.to_string())
}

pub fn cache_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("UNV_CATALOGUE_FILE") {
        return Some(PathBuf::from(p));
    }
    dirs::data_dir().map(|d| d.join("io.unenverse").join("catalogue.json"))
}

/// The cached catalogue, re-verified now. A bad or missing file is `None`, so
/// enrichment falls back to the compiled table instead of failing.
pub fn load_cached() -> Option<Catalogue> {
    let raw = std::fs::read(cache_path()?).ok()?;
    verify(&raw, &pinned_key()).ok()
}

/// Verify `raw` against the pinned key, refuse a rollback, and cache it
/// atomically (0600). Returns the accepted catalogue.
pub fn store(raw: &[u8]) -> Result<Catalogue, String> {
    store_with(raw, &pinned_key())
}

fn store_with(raw: &[u8], key: &[u8; 32]) -> Result<Catalogue, String> {
    let c = verify(raw, key)?;
    if let Some(old) = load_cached_with(key) {
        if c.generated_at < old.generated_at {
            return Err(format!(
                "refusing to roll back: cached catalogue is {}, offered one is {}",
                old.generated_at, c.generated_at
            ));
        }
    }
    let path = cache_path().ok_or("no data directory")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, raw).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(c)
}

fn load_cached_with(key: &[u8; 32]) -> Option<Catalogue> {
    verify(&std::fs::read(cache_path()?).ok()?, key).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7; 32];

    fn key() -> [u8; 32] {
        SigningKey::from_bytes(&SEED).verifying_key().to_bytes()
    }

    fn cat(at: &str) -> Catalogue {
        Catalogue {
            schema: 1,
            generated_at: at.into(),
            providers: vec![Provider {
                prefix: "zz_".into(),
                issuer: "Zed".into(),
                secret_type: "api_key".into(),
                icon: "zed".into(),
                api_url: Some("https://api.zed.example".into()),
                environment: None,
                acts_as: None,
                exposure: None,
                console_url: None,
                docs_url: None,
                rotate_url: None,
                revoke_url: None,
                verified_on: None,
                source_url: None,
            }],
        }
    }

    #[test]
    fn the_pinned_key_is_a_valid_point() {
        assert!(VerifyingKey::from_bytes(&pinned_key()).is_ok());
    }

    #[test]
    fn signed_catalogue_verifies_and_tampering_does_not() {
        let good = sign(&cat("2026-10-08T00:00:00Z"), &SEED).unwrap();
        assert!(verify(good.as_bytes(), &key()).is_ok());
        let bad = good.replace("Zed", "Zex");
        assert!(verify(bad.as_bytes(), &key()).is_err());
        assert!(verify(good.as_bytes(), &pinned_key()).is_err(), "wrong key");
    }

    #[test]
    fn a_signed_but_overbroad_prefix_is_refused() {
        let mut c = cat("2026-10-08T00:00:00Z");
        c.providers[0].prefix = "s".into();
        assert!(sign(&c, &SEED).is_err());
        let mut c = cat("2026-10-08T00:00:00Z");
        c.providers[0].api_url = Some("http://evil.example".into());
        assert!(sign(&c, &SEED).is_err());
    }

    #[test]
    fn an_unknown_axis_value_is_refused() {
        let mut c = cat("2026-10-08T00:00:00Z");
        c.providers[0].exposure = Some("public_ish".into());
        assert!(sign(&c, &SEED).is_err());
        c.providers[0].exposure = Some("publishable".into());
        c.providers[0].acts_as = Some("bot".into());
        assert!(sign(&c, &SEED).is_ok());
    }

    #[test]
    fn rollback_is_refused() {
        let dir = std::env::temp_dir().join(format!("unv-cat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("UNV_CATALOGUE_FILE", dir.join("c.json"));
        let new = sign(&cat("2026-10-08T00:00:00Z"), &SEED).unwrap();
        let old = sign(&cat("2026-10-07T00:00:00Z"), &SEED).unwrap();
        store_with(new.as_bytes(), &key()).unwrap();
        assert!(store_with(old.as_bytes(), &key())
            .unwrap_err()
            .contains("roll back"));
        store_with(new.as_bytes(), &key()).unwrap();
        std::env::remove_var("UNV_CATALOGUE_FILE");
        std::fs::remove_dir_all(dir).ok();
    }
    #[test]
    fn the_shipped_catalogue_file_parses_and_every_sourced_entry_is_complete() {
        let list: Vec<Provider> =
            serde_json::from_str(include_str!("../../catalogue/providers.json")).unwrap();
        let mut seen = std::collections::HashSet::new();
        for p in &list {
            assert!(
                seen.insert(p.prefix.clone()),
                "duplicate prefix {}",
                p.prefix
            );
            assert_eq!(
                p.verified_on.is_some(),
                p.source_url.is_some(),
                "{}: verified_on and source_url go together",
                p.prefix
            );
            if let Some(u) = &p.source_url {
                assert!(
                    u.starts_with("https://"),
                    "{}: source must be https",
                    p.prefix
                );
                assert!(p.prefix.len() >= 4, "{}: too short to be safe", p.prefix);
            }
        }
    }
}
