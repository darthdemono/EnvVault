//! A v1 vault (the whole document in one row) opened by the real binary
//! (Phase 30): it converts, keeps every entry and its history, leaves a backup,
//! and `envv doctor` says what it found.

use serde_json::{json, Value};
use std::process::Command;

fn envv(dir: &std::path::Path, args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_envv"))
        .env_remove("ENVV_SERVER_URL")
        .env_remove("ENVV_ENV_FILE")
        .env_remove("ENVV_PROJECT")
        .env("ENVV_PASSWORD", "correct-horse-battery")
        .args([
            "--db-path",
            dir.join("vault.db").to_str().unwrap(),
            "--yes",
            "--json",
        ])
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
fn a_v1_vault_is_converted_by_the_cli_and_nothing_is_lost() {
    let dir = std::env::temp_dir().join(format!("envv-storage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Build a v1 vault by hand: the blob table, no rows, no schema stamp beyond 1.
    let salt = vault_core::read_or_create_salt(&dir.join("vault.salt")).unwrap();
    let key = vault_core::derive_key("correct-horse-battery", &salt).unwrap();
    {
        let conn = vault_core::open_db(&dir.join("vault.db"), &key).unwrap();
        vault_core::init_schema(&conn).unwrap();
        let doc = json!({
            "api_keys": [{
                "id": "e1", "provider": "GitHub", "api_key": "ghp_current",
                "version_history": [{ "value": "ghp_old", "saved_at": "2026-01-01T00:00:00Z" }]
            }],
            "projects": [], "user_categories": []
        });
        conn.execute(
            "INSERT INTO vault (id, data) VALUES (1, ?1)",
            [doc.to_string()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('schema_version', '1')",
            [],
        )
        .unwrap();
    }

    let (code, text) = envv(&dir, &["entry", "ls"]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("GitHub"), "{text}");
    assert!(
        dir.join("vault.db.v1.bak").exists(),
        "the conversion is backed up first"
    );

    // History survived, in its own table now.
    let (code, text) = envv(&dir, &["entry", "history", "GitHub", "--reveal"]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("ghp_old"), "{text}");

    // And the vault is stored as rows from here on.
    {
        let conn = vault_core::open_db(&dir.join("vault.db"), &key).unwrap();
        let blobs: i64 = conn
            .query_row("SELECT COUNT(*) FROM vault", [], |r| r.get(0))
            .unwrap();
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vault_rows WHERE kind = 'entry'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!((blobs, rows), (0, 1));
    }

    let (code, text) = envv(&dir, &["doctor"]);
    assert_eq!(code, Some(0), "{text}");
    let j: Value = serde_json::from_str(text.trim()).unwrap_or(Value::Null);
    let storage = j["data"]["findings"]
        .as_array()
        .and_then(|a| a.iter().find(|f| f["check"] == "storage"))
        .cloned()
        .unwrap_or(Value::Null);
    assert!(storage.to_string().contains("1 entry rows"), "{text}");
    assert!(
        storage.to_string().contains("pre-conversion backup"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
