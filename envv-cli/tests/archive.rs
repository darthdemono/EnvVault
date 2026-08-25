//! `backup archive` / `restore-archive` — the vault file and its salt together.
//!
//! The property under test is the one the feature exists for: a machine that has
//! lost both `vault.db` and `vault.salt` can be brought back from one file, and
//! the original master password still opens the result. Everything else here is
//! a refusal that must happen *before* anything is overwritten.
//!
//! **One test function on purpose.** `access::set_paths` is a write-once
//! `OnceLock`, so the first test to call it fixes the vault location for the
//! whole process; separate `#[test]` functions run in parallel threads of that
//! one process and would silently operate on each other's files. Sequencing the
//! scenarios here is the honest way to test a program that has a single global
//! vault path — the alternative is four tests that pass only in the order the
//! scheduler happens to pick.

use envv_cli::{access, backup};

const PW: &str = "correct-horse-battery";
const ARC_PW: &str = "archive-password-1234";

fn make_vault(db: &std::path::Path, salt: &std::path::Path) {
    let key = vault_core::derive_key(PW, &vault_core::read_or_create_salt(salt).unwrap()).unwrap();
    let conn = vault_core::open_db(db, &key).unwrap();
    vault_core::init_schema(&conn).unwrap();
    vault_core::save_vault(
        &conn,
        serde_json::json!({ "api_keys": [{ "provider": "Stripe", "api_key": "sk_live_x" }] }),
        vault_core::SaveCtx {
            actor: None,
            expect_version: None,
        },
    )
    .unwrap();
}

#[test]
fn archive_round_trip_and_every_refusal() {
    let dir = std::env::temp_dir().join(format!("envv-archive-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("vault.db");
    let salt = dir.join("vault.salt");
    access::set_paths(Some(db.clone()), None);
    make_vault(&db, &salt);

    let arc = dir.join("v.vaultarc");
    backup::archive(&arc, Some(ARC_PW)).expect("archive");
    assert!(arc.exists());

    // ── 1. Restoring over a live vault needs --force ─────────────────────────
    // Losing this month's vault to last month's archive is preventable, unlike
    // losing a salt.
    let err = backup::restore_archive(&arc, Some(ARC_PW), false, true).unwrap_err();
    assert_eq!(err.code, envv_cli::error::Code::Conflict, "{err}");

    // ── 2. A damaged archive is refused, and writes nothing ──────────────────
    // A restore that half-succeeds is worse than one that refuses: the vault it
    // replaced is already gone.
    let before = std::fs::read(&db).unwrap();
    let corrupt = dir.join("corrupt.vaultarc");
    let mut env: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&arc).unwrap()).unwrap();
    let ct = env["ct"].as_str().unwrap().to_string();
    env["ct"] = serde_json::json!(format!("{}AAAAAAAA", &ct[..ct.len() - 8]));
    std::fs::write(&corrupt, serde_json::to_string(&env).unwrap()).unwrap();
    let err = backup::restore_archive(&corrupt, Some(ARC_PW), true, true).unwrap_err();
    assert_eq!(err.code, envv_cli::error::Code::Denied, "{err}");
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "a failed restore must leave the existing vault untouched"
    );

    // ── 3. The wrong password is denied, not "corrupt file" ──────────────────
    let err =
        backup::restore_archive(&arc, Some("not-the-archive-password"), true, true).unwrap_err();
    assert_eq!(err.code, envv_cli::error::Code::Denied, "{err}");

    // ── 4. A .vaultbak names the command that does handle it ─────────────────
    let bak = dir.join("v.vaultbak");
    std::fs::write(&bak, r#"{"magic":"ENVVBAK1","salt":"","iv":"","ct":""}"#).unwrap();
    let err = backup::restore_archive(&bak, Some(ARC_PW), true, true).unwrap_err();
    assert!(err.to_string().contains("backup import"), "{err}");

    // ── 5. The disaster it exists for ────────────────────────────────────────
    // Both files gone. Nothing can recompute the salt — that is the whole reason
    // this command exists, so deleting it is the point of the test.
    std::fs::remove_file(&db).unwrap();
    std::fs::remove_file(&salt).unwrap();
    backup::restore_archive(&arc, Some(ARC_PW), false, true).expect("restore");
    assert!(db.exists() && salt.exists(), "both files must come back");

    let key = vault_core::derive_key(PW, &std::fs::read(&salt).unwrap()).unwrap();
    let conn = vault_core::open_db(&db, &key)
        .expect("the original master password must still open the restored vault");
    let loaded = vault_core::load_vault(&conn)
        .unwrap()
        .expect("vault has data");
    assert_eq!(loaded["api_keys"][0]["provider"], "Stripe");

    let _ = std::fs::remove_dir_all(&dir);
}
