//! `envv reset-vault` (Phase 33.5): refuses without `--yes` off a terminal, and
//! removes exactly the vault and its salt.
use std::process::{Command, Stdio};

fn envv(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_envv"))
        .env_remove("ENVV_SERVER_URL")
        .env_remove("ENVV_ENV_FILE")
        .env("ENVV_PASSWORD", "scratch-pass-123456")
        .stdin(Stdio::null())
        .arg("--db-path")
        .arg(dir.join("vault.db"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn reset_needs_confirmation_and_removes_only_the_vault() {
    let dir = std::env::temp_dir().join(format!("envv-reset-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    assert!(envv(&dir, &["--init", "entry", "add", "A", "--key", "k"])
        .status
        .success());
    std::fs::write(dir.join("vault.db.v1.bak"), b"backup").unwrap();

    let refused = envv(&dir, &["reset-vault"]);
    assert_eq!(refused.status.code(), Some(8), "no terminal, no --yes");
    assert!(dir.join("vault.db").exists());

    assert!(envv(&dir, &["reset-vault", "--dry-run"]).status.success());
    assert!(dir.join("vault.db").exists(), "dry run removes nothing");

    assert!(envv(&dir, &["reset-vault", "--yes"]).status.success());
    assert!(!dir.join("vault.db").exists());
    assert!(!dir.join("vault.salt").exists());
    assert!(
        dir.join("vault.db.v1.bak").exists(),
        "a backup is not the vault"
    );
    std::fs::remove_dir_all(dir).ok();
}
