//! Phase 38 through the real binary: a Prometheus project is created (behind the
//! experimental flag), grown from its descriptor, exported with secrets masked on
//! stdout and real in a file, and checked by `unv check`.

#![cfg(unix)]

use std::process::{Command, Output};

const SECRET: &str = "stack-cli-secret-9876543210";

fn scratch() -> std::path::PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("envv-stack-{}-{n}", std::process::id()));
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

fn text(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)
}

fn ok(dir: &std::path::Path, args: &[&str]) -> String {
    let o = run(dir, args);
    assert!(o.status.success(), "unv {args:?}: {}", text(&o));
    text(&o)
}

#[test]
fn a_prometheus_project_is_created_grown_exported_masked_and_checked() {
    let dir = scratch();
    ok(&dir, &["entry", "add", "PromPw", "--key", SECRET]);

    // Experimental until CI has fed the real software its output.
    let refused = run(&dir, &["project", "add", "mon", "--type", "prometheus"]);
    assert!(!refused.status.success());
    assert!(
        text(&refused).contains("--experimental"),
        "{}",
        text(&refused)
    );

    ok(
        &dir,
        &[
            "project",
            "add",
            "mon",
            "--type",
            "prometheus",
            "--experimental",
        ],
    );
    let chunks = ok(&dir, &["--json", "project", "chunk", "ls", "mon"]);
    assert!(
        chunks.contains("prom_global") && chunks.contains("prom_scrape"),
        "{chunks}"
    );

    // A chunk added from the CLI has the descriptor's defaults.
    ok(
        &dir,
        &[
            "project",
            "chunk",
            "add",
            "mon",
            "app",
            "--type",
            "prom_scrape",
        ],
    );
    ok(
        &dir,
        &[
            "project",
            "chunk",
            "set",
            "mon",
            "app",
            "targets=app:8443",
            "scheme=https",
            "username=scraper",
            "password=${PromPw}",
        ],
    );

    // stdout is masked: no secret, a fingerprint where the password is.
    let shown = ok(&dir, &["project", "export", "mon"]);
    assert!(!shown.contains(SECRET), "{shown}");
    assert!(
        shown.contains("job_name: app") && shown.contains("sha256:"),
        "{shown}"
    );
    assert!(shown.contains("scrape_configs:"), "{shown}");

    // A file gets the real thing.
    let out = dir.join("prometheus.yml");
    ok(
        &dir,
        &["project", "export", "mon", "--out", out.to_str().unwrap()],
    );
    let written = std::fs::read_to_string(&out).unwrap();
    assert!(
        written.contains(&format!("password: {SECRET}")),
        "{written}"
    );
    assert!(!written.contains("${"), "{written}");

    // The descriptor's own rules reach `unv check`.
    ok(
        &dir,
        &[
            "project",
            "chunk",
            "add",
            "mon",
            "app2",
            "--type",
            "prom_scrape",
        ],
    );
    ok(
        &dir,
        &[
            "project",
            "chunk",
            "set",
            "mon",
            "app2",
            "username=only-a-user",
            "targets=",
        ],
    );
    let check = run(&dir, &["--json", "check", "mon"]);
    let t = text(&check);
    assert!(t.contains("stack-prometheus-job-without-targets"), "{t}");
    assert!(t.contains("stack-prometheus-basic-auth-incomplete"), "{t}");
}

#[test]
fn the_export_format_flag_accepts_the_adapters_and_refuses_nonsense() {
    let dir = scratch();
    ok(
        &dir,
        &[
            "project",
            "add",
            "graf",
            "--type",
            "grafana",
            "--experimental",
        ],
    );
    let g = ok(&dir, &["project", "export", "graf", "--format", "grafana"]);
    assert!(
        g.contains("apiVersion: 1") && g.contains("datasources:"),
        "{g}"
    );
    let bad = run(&dir, &["project", "export", "graf", "--format", "grafaana"]);
    assert_eq!(bad.status.code(), Some(2), "{}", text(&bad));
}

#[test]
fn describe_lists_the_new_types() {
    let o = Command::new(env!("CARGO_BIN_EXE_unv"))
        .arg("describe")
        .output()
        .unwrap();
    let d = String::from_utf8_lossy(&o.stdout).to_string();
    for t in [
        "prometheus",
        "grafana",
        "homepage",
        "prom_scrape",
        "grafana_datasource",
        "homepage_service",
    ] {
        assert!(d.contains(t), "describe does not mention {t}");
    }
}
