//! The secret-type registry — Phase 24.5.
//!
//! Sixteen new types on top of the existing ten would be ~190 edit sites done
//! the way `cookie` was added in Phase 23 — sixteen more chances to forget one
//! of them, the "two lists of secret fields" defect multiplied. So a type is a
//! **descriptor** read from one JSON file, `secret-types.json` at the repo
//! root, compiled into this binary with `include_str!` and imported as plain
//! JSON by the TypeScript side (`src/ts/secret-types.ts`) — one file, not a
//! twin, so it needs a schema test rather than a parity fixture.
//!
//! A descriptor only ever *chooses*; the code that validates, renders and
//! masks a value still lives where it always did. Adding a type here does not
//! add a form field, a card body or a validator — see the CLAUDE.md note this
//! module's doc comment quotes: "land the shape now, behavior later", the same
//! call Phase 24.1 made for `composite` and `bundle`.

use serde::{Deserialize, Serialize};

const RAW: &str = include_str!("../../secret-types.json");

/// What a rotation of this type actually is. `none` is not "never rotates" —
/// it is "there is nothing here for the rotation nag to be actionable about",
/// the same reasoning E13 gives for a browser session's cadence field.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rotation {
    Rotate,
    Reissue,
    VerifySession,
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretTypeDescriptor {
    pub id: String,
    pub label: String,
    pub group: String,
    /// Which field `unv get`/Copy treats as the whole value, or `None` when
    /// the type has no single primary (`env_var`, `file_blob`, every
    /// bundle-shaped type whose payload lives in named `extra_vars`).
    pub primary: Option<String>,
    pub rotation: Rotation,
    /// Whether `enrich --online` may contact the issuer for this type. `cookie`
    /// and `tracker` are `false` for the same reason E11 refuses a session:
    /// probing is *using* the credential, and for these that risk is a session
    /// hijack detector rather than a rate limit.
    pub probe: bool,
    /// Whether `extra_vars` mask **whole**, per-value `public` flags ignored —
    /// E5's rule for `cookie`, extended here to every type whose payload is
    /// only useful as a set (`recovery_codes`, `crypto_wallet`, `secure_note`,
    /// `tracker`'s passkey/announce URL).
    pub mask_whole: bool,
    /// The FIDO CXF credential type this maps onto for import/export
    /// (`cxf.rs`), or `custom-fields` when nothing in the CXF spec matches —
    /// still lossless, since `custom-fields` round-trips through UnENVerse's
    /// own extension the way Phase 24.5's design requires.
    pub cxf: Option<String>,
    /// Output formats `unv emit` / the card's Copy menu offer, implemented in
    /// `type_emit.rs`. A test asserts this and `type_emit::formats_for` agree.
    #[serde(default)]
    pub emitters: Vec<String>,
}

#[derive(Deserialize)]
struct RegistryFile {
    #[allow(dead_code)]
    version: u32,
    types: Vec<SecretTypeDescriptor>,
}

/// Parses the embedded registry. Called once by [`registry`]; kept separate
/// so a schema test can call it directly and get a `Result` instead of a
/// panic.
pub fn parse() -> Result<Vec<SecretTypeDescriptor>, String> {
    let file: RegistryFile = serde_json::from_str(RAW).map_err(|e| e.to_string())?;
    Ok(file.types)
}

/// The full registry. Panics on a malformed embedded file — that is a build
/// defect, not a runtime one, since the JSON is compiled in rather than read
/// from disk.
pub fn registry() -> Vec<SecretTypeDescriptor> {
    parse().expect("secret-types.json failed to parse — this is a build-time defect")
}

/// One type's descriptor, or `None` for a type the running build has never
/// heard of — the A11 case, handled here the same way it is handled
/// everywhere else: absence is a fact to check, not a reason to guess.
pub fn find(id: &str) -> Option<SecretTypeDescriptor> {
    registry().into_iter().find(|t| t.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_registry_parses() {
        let types = parse().expect("secret-types.json must parse");
        assert!(types.len() >= 26, "expected at least the 10 + 16 types");
    }

    #[test]
    fn every_id_is_unique() {
        let types = registry();
        let mut seen = std::collections::HashSet::new();
        for t in &types {
            assert!(seen.insert(t.id.clone()), "duplicate id {}", t.id);
        }
    }

    #[test]
    fn every_existing_secret_type_is_registered() {
        // The ten types that predate this registry must still resolve, or a
        // caller that switches from a hardcoded match to `find()` would
        // silently lose coverage for one of them.
        for id in [
            "api_key",
            "password",
            "certificate",
            "env_var",
            "connection_string",
            "ssh_key",
            "file_blob",
            "cookie",
            "composite",
            "bundle",
        ] {
            assert!(find(id).is_some(), "missing descriptor for {id}");
        }
    }

    #[test]
    fn find_is_none_for_an_unknown_type() {
        assert!(find("from_the_future").is_none());
    }
}
