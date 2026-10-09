//! Phase 36 through the real binary, for the local half of blast radius: what
//! `unv exec` and `--out` hand to this machine is logged by name, never by
//! value, and a later rotation takes the entry off the list to rotate.

#![cfg(unix)]

use std::process::{Command, Output};

const ONE: &str = "blast-secret-ONE-aaaaaaaa";
const TWO: &str = "blast-secret-TWO-bbbbbbbb";

fn scratch() -> std::path::PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("envv-blast-{}-{n}", std::process::id()));
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
        .env("XDG_STATE_HOME", dir.join("state"))
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

fn ok(dir: &std::path::Path, args: &[&str]) -> String {
    let o = run(dir, args);
    let text = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "unv {args:?}: {text}");
    text
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
        ],
    );
}

#[test]
fn exec_and_out_are_logged_by_name_and_a_rotation_clears_the_to_do_list() {
    let dir = scratch();
    setup(&dir);
    ok(&dir, &["exec", "--project", "web", "--", "true"]);
    ok(
        &dir,
        &[
            "project",
            "export",
            "web",
            "--out",
            dir.join("out.env").to_str().unwrap(),
        ],
    );
    // Another way the real value reaches a file here: the history's own --out.
    // (Snapshot #1 is the empty chunk from before the reference was set, which
    // holds no secret, so take the newest.)
    let ls: serde_json::Value =
        serde_json::from_str(&ok(&dir, &["--json", "history", "ls", "web"])).unwrap();
    let newest = ls["data"]["snapshots"][0]["seq"]
        .as_i64()
        .unwrap()
        .to_string();
    ok(
        &dir,
        &[
            "history",
            "show",
            &newest,
            "--out",
            dir.join("old.env").to_str().unwrap(),
        ],
    );

    let report = ok(&dir, &["blast-radius", "--host", "local"]);
    assert!(
        report.contains("ROTATE") && report.contains("Stripe"),
        "{report}"
    );
    assert!(
        report.contains("unv entry rotate 'Stripe' --generate"),
        "{report}"
    );
    assert!(
        !report.contains(ONE),
        "the report carried a value: {report}"
    );

    // The log file itself holds names and fingerprints, never values, and is private.
    let log = dir
        .join("state")
        .join("envv")
        .join("materialisations.jsonl");
    let raw = std::fs::read_to_string(&log).unwrap();
    assert!(!raw.contains(ONE), "the log holds a value");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let json: serde_json::Value =
        serde_json::from_str(&ok(&dir, &["--json", "blast-radius", "--host", "local"])).unwrap();
    assert_eq!(
        json["data"]["deployments"], 3,
        "exec, the export and the history file: {json}"
    );
    assert_eq!(json["data"]["entries"][0]["times"], 3);

    // Rotate: the value that reached this machine is no longer the live one.
    ok(&dir, &["entry", "set", "Stripe", "--key", TWO]);
    let after = ok(&dir, &["blast-radius", "--host", "local"]);
    assert!(
        after.contains("rotated") && !after.contains("ROTATE"),
        "{after}"
    );
    assert!(
        after.contains("Nothing in the vault needs rotating"),
        "{after}"
    );
}

#[test]
fn a_command_that_received_no_secret_leaves_no_record() {
    let dir = scratch();
    setup(&dir);
    ok(
        &dir,
        &[
            "entry",
            "add",
            "Other",
            "--key",
            "another-unrelated-key-1234",
        ],
    );
    ok(&dir, &["exec", "--entry", "Other", "--", "true"]);
    // That exec did hand a secret out (Other's). A pure listing does not.
    ok(&dir, &["list"]);
    let json: serde_json::Value =
        serde_json::from_str(&ok(&dir, &["--json", "blast-radius", "--host", "local"])).unwrap();
    assert_eq!(json["data"]["deployments"], 1, "only the exec: {json}");
    let names: Vec<&str> = json["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["provider"].as_str())
        .collect();
    assert_eq!(names, vec!["Other"], "Stripe was never handed out: {json}");
}

#[test]
fn since_narrows_the_window() {
    let dir = scratch();
    setup(&dir);
    ok(&dir, &["exec", "--project", "web", "--", "true"]);
    let none = ok(
        &dir,
        &[
            "blast-radius",
            "--host",
            "local",
            "--since",
            "2999-01-01T00:00:00Z",
        ],
    );
    assert!(
        none.contains("Nothing in the vault needs rotating"),
        "{none}"
    );
}

#[test]
fn a_revealed_get_is_logged_and_a_masked_one_is_not() {
    let dir = scratch();
    setup(&dir);
    let count = |dir: &std::path::Path| -> serde_json::Value {
        serde_json::from_str(&ok(dir, &["--json", "blast-radius", "--host", "local"])).unwrap()
    };
    // Masked by default: nothing reached this machine.
    ok(&dir, &["get", "Stripe"]);
    let json = count(&dir);
    assert_eq!(json["data"]["deployments"], 0, "{json}");
    // --reveal prints the real value, so it is a materialisation like --out.
    let shown = ok(&dir, &["--reveal", "get", "Stripe"]);
    assert!(shown.contains(ONE));
    let json = count(&dir);
    assert_eq!(json["data"]["deployments"], 1, "{json}");
    assert_eq!(json["data"]["entries"][0]["provider"], "Stripe");
    // The record names the entry and a fingerprint, never the value.
    let log = std::fs::read_to_string(dir.join("state/envv/materialisations.jsonl")).unwrap();
    assert!(!log.contains(ONE), "the log holds a value: {log}");
}
