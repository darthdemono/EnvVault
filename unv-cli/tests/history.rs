//! Phase 35 through the real binary: a save snapshots the rendered config, a
//! rotation diffs as a changed fingerprint, the real values need --reveal or
//! --out, pruning leaves a verifiable history, and tampering is caught.

#![cfg(unix)]

use std::process::{Command, Output};

const ONE: &str = "history-secret-ONE-aaaa";
const TWO: &str = "history-secret-TWO-bbbb";

fn scratch() -> std::path::PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("envv-history-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn unv(dir: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_unv"));
    c.env_remove("UNV_SERVER_URL")
        .env_remove("ENVV_SERVER_URL")
        .env_remove("UNV_ENV_FILE")
        .env_remove("ENVV_ENV_FILE")
        .env("UNV_PASSWORD", "correct-horse-battery")
        .args([
            "--db-path",
            dir.join("vault.db").to_str().unwrap(),
            "--init",
            "--yes",
        ]);
    c
}

fn run(dir: &std::path::Path, args: &[&str]) -> Output {
    unv(dir).args(args).output().unwrap()
}

fn all(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)
}

fn ok(dir: &std::path::Path, args: &[&str]) -> String {
    let o = run(dir, args);
    assert!(o.status.success(), "unv {args:?}: {}", all(&o));
    all(&o)
}

fn setup(dir: &std::path::Path) {
    ok(dir, &["entry", "add", "Stripe", "--key", ONE]);
    ok(dir, &["project", "add", "web", "--type", "generic"]);
    ok(
        dir,
        &[
            "project", "chunk", "add", "web", "app.env", "--type", "env_file",
        ],
    );
    ok(
        dir,
        &[
            "project",
            "chunk",
            "set",
            "web",
            "app.env",
            "STRIPE_KEY=${Stripe/api_key}",
            "MODE=live",
        ],
    );
}

#[test]
fn a_save_is_snapshotted_and_a_rotation_diffs_as_a_changed_fingerprint() {
    let dir = scratch();
    setup(&dir);
    let ls = ok(&dir, &["history", "ls", "web"]);
    assert!(ls.contains("env"), "no snapshot after the saves: {ls}");

    ok(&dir, &["entry", "set", "Stripe", "--key", TWO]);
    let diff = ok(&dir, &["history", "diff", "web"]);
    assert!(
        diff.contains("-STRIPE_KEY=") && diff.contains("+STRIPE_KEY="),
        "{diff}"
    );
    assert!(
        !diff.contains(ONE) && !diff.contains(TWO),
        "a default diff carried a secret: {diff}"
    );

    // --reveal prints the real values; --out writes them 0600.
    let real = ok(&dir, &["--reveal", "history", "diff", "web"]);
    assert!(real.contains(ONE) && real.contains(TWO), "{real}");
    let out = dir.join("diff.txt");
    ok(
        &dir,
        &["history", "diff", "web", "--out", out.to_str().unwrap()],
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(std::fs::read_to_string(&out).unwrap().contains(TWO));
}

#[test]
fn show_masks_by_default_and_json_carries_no_secret_either() {
    let dir = scratch();
    setup(&dir);
    let list = ok(&dir, &["--json", "history", "ls", "web"]);
    let seq = serde_json::from_str::<serde_json::Value>(&list).unwrap()["data"]["snapshots"][0]
        ["seq"]
        .as_i64()
        .unwrap()
        .to_string();
    let shown = ok(&dir, &["--json", "history", "show", &seq]);
    assert!(!shown.contains(ONE), "{shown}");
    let revealed = ok(&dir, &["--reveal", "history", "show", &seq]);
    assert!(revealed.contains(ONE));
}

#[test]
fn identical_saves_do_not_pile_up_snapshots() {
    let dir = scratch();
    setup(&dir);
    let count = |d: &std::path::Path| {
        let v: serde_json::Value =
            serde_json::from_str(&ok(d, &["--json", "history", "ls", "web"])).unwrap();
        v["data"]["snapshots"].as_array().unwrap().len()
    };
    let before = count(&dir);
    ok(
        &dir,
        &[
            "entry",
            "set",
            "Stripe",
            "--desc",
            "unrelated to any config",
        ],
    );
    assert_eq!(
        count(&dir),
        before,
        "a save that changed no rendered config recorded one"
    );
}

#[test]
fn prune_verify_policy_and_tampering() {
    let dir = scratch();
    setup(&dir);
    ok(&dir, &["entry", "set", "Stripe", "--key", TWO]);
    assert!(ok(&dir, &["history", "verify"]).contains("intact"));
    assert!(ok(&dir, &["history", "policy", "--keep", "5", "--days", "30"]).contains("30 days"));
    // Nothing is older than 30 days, so nothing is pruned, with or without --yes.
    assert!(ok(&dir, &["history", "prune", "--yes"]).contains("0 snapshot"));
    assert!(ok(&dir, &["history", "policy", "--disable"]).contains("off"));
    ok(
        &dir,
        &["entry", "set", "Stripe", "--key", "history-secret-THREE"],
    );
    let v: serde_json::Value =
        serde_json::from_str(&ok(&dir, &["--json", "history", "stats"])).unwrap();
    let n = v["data"]["snapshots"].as_i64().unwrap();
    ok(&dir, &["history", "policy", "--enable"]);
    ok(
        &dir,
        &["entry", "set", "Stripe", "--key", "history-secret-FOUR"],
    );
    let v: serde_json::Value =
        serde_json::from_str(&ok(&dir, &["--json", "history", "stats"])).unwrap();
    assert_eq!(
        v["data"]["snapshots"].as_i64().unwrap(),
        n + 1,
        "history was off for one save and on for the next"
    );

    // Tamper with a stored snapshot behind the binary's back: verify must say so
    // and exit with the invalid code.
    let key = {
        // The CLI derives the key from the password and salt beside the db.
        let salt = std::fs::read(dir.join("vault.salt")).unwrap();
        vault_core::derive_key("correct-horse-battery", &salt).unwrap()
    };
    let conn = vault_core::open_db(&dir.join("vault.db"), &key).unwrap();
    conn.execute(
        "UPDATE config_snapshots SET content = 'evil' WHERE seq = 1",
        [],
    )
    .unwrap();
    drop(conn);
    let o = run(&dir, &["history", "verify"]);
    assert_eq!(o.status.code(), Some(10), "{}", all(&o));
    assert!(all(&o).contains("#1 content does not match"));
}
