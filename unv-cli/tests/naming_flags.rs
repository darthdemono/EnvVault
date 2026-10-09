//! `--env-case` / `--env-prefix` (Phase 33.5): the CLI side of the app's copy
//! settings. The same entry must export under the names the app's copy would
//! use, and the defaults must not move.
use std::process::{Command, Stdio};

fn unv(dir: &std::path::Path, args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_unv"))
        .env_remove("UNV_SERVER_URL")
        .env_remove("UNV_SERVER_URL")
        .env_remove("UNV_ENV_FILE")
        .env_remove("UNV_ENV_FILE")
        .env_remove("UNV_ENV_CASE")
        .env_remove("UNV_ENV_CASE")
        .env_remove("UNV_ENV_PREFIX")
        .env_remove("UNV_ENV_PREFIX")
        .env("UNV_PASSWORD", "scratch-pass-123456")
        .stdin(Stdio::null())
        .arg("--db-path")
        .arg(dir.join("vault.db"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn case_and_prefix_change_exported_names_and_nothing_else() {
    let dir = std::env::temp_dir().join(format!("unv-naming-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    unv(
        &dir,
        &["--init", "entry", "add", "Spotify", "--key", "abc123"],
    );
    unv(&dir, &["entry", "set", "Spotify", "--env-prefixes", "ND"]);

    let plain = unv(&dir, &["--reveal", "export", "--format", "dotenv"]);
    assert!(
        plain.contains("SPOTIFY=abc123"),
        "default names unchanged: {plain}"
    );

    let lower = unv(
        &dir,
        &[
            "--reveal",
            "--env-case",
            "lower",
            "export",
            "--format",
            "dotenv",
        ],
    );
    assert!(lower.contains("spotify=abc123"), "{lower}");

    let prefixed = unv(
        &dir,
        &["--reveal", "--env-prefix", "export", "--format", "dotenv"],
    );
    assert!(prefixed.contains("ND_SPOTIFY=abc123"), "{prefixed}");

    let profile = unv(
        &dir,
        &[
            "--reveal",
            "--env-case",
            "lower",
            "--env-prefix",
            "get",
            "Spotify",
            "--profile",
            "basic",
        ],
    );
    assert!(profile.contains("nd_spotify=abc123"), "{profile}");
    std::fs::remove_dir_all(dir).ok();
}
