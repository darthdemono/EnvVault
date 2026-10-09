//! `--pgp-public` through the real binary (Phase 24.5, `gpg_key`): the expiry and
//! fingerprint the vault records are what `gpg --list-keys --with-colons` says
//! about the same key, and nothing secret is involved.

use serde_json::Value;
use std::process::Command;

fn unv(dir: &std::path::Path, args: &[&str]) -> (Option<i32>, Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_unv"))
        .env_remove("UNV_SERVER_URL")
        .env_remove("ENVV_SERVER_URL")
        .env_remove("UNV_ENV_FILE")
        .env_remove("ENVV_ENV_FILE")
        .env("UNV_PASSWORD", "correct-horse-battery")
        .args([
            "--db-path",
            dir.join("vault.db").to_str().unwrap(),
            "--init",
            "--yes",
            "--json",
        ])
        .args(args)
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    let json =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap_or(Value::Null);
    (out.status.code(), json, text)
}

#[test]
fn a_gpg_key_entry_takes_its_expiry_and_fingerprint_from_the_key() {
    let dir = std::env::temp_dir().join(format!("envv-pgp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vault-core/tests/fixtures");
    let ed = fixtures.join("pgp-ed25519.asc");
    let (code, _, text) = unv(
        &dir,
        &[
            "entry",
            "add",
            "Release signing",
            "--type",
            "gpg_key",
            "--pgp-public",
            ed.to_str().unwrap(),
        ],
    );
    assert_eq!(code, Some(0), "{text}");
    let (_, got, _) = unv(&dir, &["get", "Release signing"]);
    let e = &got["data"]["entries"][0];
    // The sooner of the primary (2y) and the encryption subkey (1y).
    assert_eq!(e["expires_at"], "2027-10-09T09:43:34Z", "{got}");
    let var = |k: &str| {
        e["extra_vars"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["key"] == k)
            .map(|v| v["value"].clone())
            .unwrap_or(Value::Null)
    };
    assert_eq!(
        var("fingerprint"),
        "899144971A1F3431B729FE0AFF605C48E0B8A0D4",
        "public values print"
    );
    assert_eq!(var("user_ids"), "Test User <test@example.com>");

    // Pointing it at a key that never expires clears the date; at a non-key it
    // changes nothing and says why.
    let rsa = fixtures.join("pgp-rsa-never.asc");
    let (code, _, text) = unv(
        &dir,
        &[
            "entry",
            "set",
            "Release signing",
            "--pgp-public",
            rsa.to_str().unwrap(),
        ],
    );
    assert_eq!(code, Some(0), "{text}");
    let (_, got, _) = unv(&dir, &["get", "Release signing"]);
    assert!(got["data"]["entries"][0]["expires_at"].is_null(), "{got}");
    let junk = dir.join("junk.txt");
    std::fs::write(&junk, "not a key").unwrap();
    let (code, j, _) = unv(
        &dir,
        &[
            "entry",
            "set",
            "Release signing",
            "--pgp-public",
            junk.to_str().unwrap(),
        ],
    );
    assert_eq!(code, Some(10), "{j}");
}
