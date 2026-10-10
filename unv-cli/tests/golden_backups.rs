//! Golden `.vaultbak` and `.vaultarc` files (roadmap R01, project phase 43).
//!
//! The fixtures in `fixtures/backups-0.42.x/` were written by the 0.42.4 build
//! from the vault in `vault-core/tests/fixtures/vault-0.42.x/`. Restoring them
//! must keep working across dependency upgrades; if it stops, the envelope or
//! the database format moved and a migration is owed, not a new fixture.
//!
//! One test function per mode on purpose: `access::set_paths` is a write-once
//! `OnceLock` (see `archive.rs`), and the ignored generator runs alone.
//!
//! Regenerate only on purpose:
//! `cargo test -p unv-cli --test golden_backups -- --ignored generate`

use std::path::{Path, PathBuf};
use unv_cli::{access, backup};

const PW: &str = "golden-fixture-password";
const BAK_PW: &str = "golden-backup-password-1";

fn core_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../vault-core/tests/fixtures/vault-0.42.x")
}

fn bak_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/backups-0.42.x")
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("unv-golden-bak-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn open_local(pw: &str) -> access::Access {
    access::open_access(&access::AuthOpts {
        server: None,
        password: Some(pw),
        user: None,
        token: None,
        session_token: None,
        totp: None,
        init: false,
    })
    .expect("open local vault")
}

#[test]
fn old_backups_restore() {
    let dir = temp("restore");
    let db = dir.join("vault.db");
    let salt = dir.join("vault.salt");
    access::set_paths(Some(db.clone()), None);

    // ── .vaultarc: both files gone, one archive brings them back ─────────────
    backup::restore_archive(
        &bak_fixture().join("golden.vaultarc"),
        Some(BAK_PW),
        false,
        true,
    )
    .expect("0.42.x archive must restore");
    assert!(db.exists() && salt.exists());
    let key = vault_core::derive_key(PW, &std::fs::read(&salt).unwrap()).unwrap();
    let conn = vault_core::open_db(&db, &key).expect("master password opens restored vault");
    assert!(vault_core::verify_vault_integrity(&conn).unwrap());
    let v = vault_core::load_vault(&conn).unwrap().unwrap();
    assert_eq!(v["api_keys"].as_array().unwrap().len(), 3);
    drop(conn);

    // ── .vaultbak: replaces the vault contents from the envelope ─────────────
    // Start from an emptied vault so the count proves the import did the work.
    let acc = open_local(PW);
    acc.save(&serde_json::json!({ "api_keys": [], "projects": [], "user_categories": [] }))
        .unwrap();
    assert_eq!(
        acc.load_vault().unwrap()["api_keys"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    backup::import(
        &acc,
        &bak_fixture().join("golden.vaultbak"),
        Some(BAK_PW),
        true,
    )
    .expect("0.42.x backup must import");
    let v = acc.load_vault().unwrap();
    assert_eq!(v["api_keys"].as_array().unwrap().len(), 3);

    // ── Control: the wrong password is refused, nothing is replaced ──────────
    let err = backup::import(
        &acc,
        &bak_fixture().join("golden.vaultbak"),
        Some("not-the-backup-password"),
        true,
    )
    .unwrap_err();
    assert_eq!(err.code, unv_cli::error::Code::Denied, "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Writes the fixtures. Ignored: run by hand on the build being pinned.
#[test]
#[ignore]
fn generate() {
    let dir = temp("gen");
    let db = dir.join("vault.db");
    std::fs::copy(core_fixture().join("vault.db"), &db).unwrap();
    std::fs::copy(core_fixture().join("vault.salt"), dir.join("vault.salt")).unwrap();
    access::set_paths(Some(db), None);
    let acc = open_local(PW);
    std::fs::create_dir_all(bak_fixture()).unwrap();
    let _ = std::fs::remove_file(bak_fixture().join("golden.vaultbak"));
    let _ = std::fs::remove_file(bak_fixture().join("golden.vaultarc"));
    backup::export(&acc, &bak_fixture().join("golden.vaultbak"), Some(BAK_PW)).unwrap();
    backup::archive(&bak_fixture().join("golden.vaultarc"), Some(BAK_PW)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
