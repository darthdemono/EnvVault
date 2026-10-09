//! `unv diff` and `unv entry add --template` (Phase 33.6).
use std::process::{Command, Stdio};

fn unv(dir: &std::path::Path, args: &[&str]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_unv"))
        .env_remove("UNV_SERVER_URL")
        .env_remove("UNV_SERVER_URL")
        .env_remove("UNV_ENV_FILE")
        .env_remove("UNV_ENV_FILE")
        .env("UNV_PASSWORD", "scratch-pass-123456")
        .stdin(Stdio::null())
        .arg("--db-path")
        .arg(dir.join("vault.db"))
        .args(args)
        .output()
        .unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr),
    )
}

#[test]
fn template_prefills_flags_override_and_diff_redacts() {
    let dir = std::env::temp_dir().join(format!("unv-diff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let (ok, ls) = unv(&dir, &["template", "ls"]);
    assert!(ok && ls.contains("github-pat"), "{ls}");
    assert!(!unv(&dir, &["--init", "entry", "add", "X", "--preset", "nope"]).0);

    assert!(
        unv(
            &dir,
            &[
                "--init",
                "entry",
                "add",
                "Mine",
                "--preset",
                "github-pat",
                "--key",
                "secret-one"
            ]
        )
        .0
    );
    assert!(
        unv(
            &dir,
            &[
                "entry",
                "add",
                "Other",
                "--preset",
                "github-pat",
                "--key",
                "secret-two",
                "--url",
                "https://example.org"
            ]
        )
        .0
    );

    let (_, got) = unv(&dir, &["--reveal", "get", "Mine", "--field", "api_url"]);
    assert!(
        got.contains("https://api.github.com"),
        "template default applied: {got}"
    );
    let (_, got) = unv(&dir, &["--reveal", "get", "Other", "--field", "api_url"]);
    assert!(
        got.contains("https://example.org"),
        "explicit flag wins: {got}"
    );
    let (_, name) = unv(&dir, &["--reveal", "get", "Mine", "--field", "provider"]);
    assert!(name.contains("Mine"), "entry keeps the name given: {name}");

    let (ok, d) = unv(&dir, &["diff", "Mine", "Other"]);
    assert!(ok);
    assert!(
        !d.contains("secret-one") && !d.contains("secret-two"),
        "redacted: {d}"
    );
    assert!(d.contains("sha256:"), "fingerprints shown: {d}");
    assert!(d.contains("~ API URL"), "changed field marked: {d}");
    let (_, rev) = unv(&dir, &["--reveal", "diff", "Mine", "Other"]);
    assert!(rev.contains("secret-one") && rev.contains("secret-two"));
    assert!(!unv(&dir, &["diff", "Mine", "Mine"]).0);
    std::fs::remove_dir_all(dir).ok();
}
