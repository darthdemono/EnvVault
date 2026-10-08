//! `envv check` through the real binary (Phase 29). The rule logic is unit-tested
//! in `vault-core/src/config_check.rs`; this pins what only the command can show:
//! the envelope, `--fail-on` exit codes, and that a secret field's value never
//! appears in the report.

use serde_json::Value;
use std::process::Command;

fn envv(dir: &std::path::Path, args: &[&str]) -> (Option<i32>, Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_envv"))
        .env_remove("ENVV_SERVER_URL")
        .env_remove("ENVV_ENV_FILE")
        .env_remove("ENVV_PROJECT")
        .env("ENVV_PASSWORD", "correct-horse-battery")
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
    let json = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .or_else(|_| serde_json::from_str(String::from_utf8_lossy(&out.stderr).trim()))
        .unwrap_or(Value::Null);
    (out.status.code(), json, text)
}

#[test]
fn reports_cross_chunk_findings_and_fails_on_request() {
    let dir = std::env::temp_dir().join(format!("envv-check-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let must = |args: &[&str]| {
        let (code, _, text) = envv(&dir, args);
        assert_eq!(code, Some(0), "{args:?}: {text}");
    };
    must(&["project", "add", "Mixed", "--type", "generic"]);
    must(&[
        "project",
        "chunk",
        "add",
        "Mixed",
        "web",
        "--type",
        "docker_service",
    ]);
    must(&[
        "project",
        "chunk",
        "add",
        "Mixed",
        "edge",
        "--type",
        "nginx_location",
    ]);
    must(&[
        "project",
        "chunk",
        "set",
        "Mixed",
        "edge",
        "proxy_pass=http://api:8080",
    ]);
    must(&["project", "chunk", "add", "Mixed", "a", "--type", "wg_peer"]);
    must(&["project", "chunk", "add", "Mixed", "b", "--type", "wg_peer"]);
    must(&[
        "project",
        "chunk",
        "set",
        "Mixed",
        "a",
        "AllowedIPs=10.0.0.2/32",
    ]);
    must(&[
        "project",
        "chunk",
        "set",
        "Mixed",
        "b",
        "AllowedIPs=10.0.0.2/32",
    ]);
    // A secret-typed field that must never appear in the report.
    must(&[
        "project",
        "chunk",
        "add",
        "Mixed",
        "pg",
        "--type",
        "pg_connection",
    ]);
    must(&[
        "project",
        "chunk",
        "set",
        "Mixed",
        "pg",
        "password=hunter2-SECRET",
        "--secret",
    ]);

    let (code, j, text) = envv(&dir, &["check", "Mixed"]);
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(j["command"], "check");
    let rules: Vec<&str> = j["data"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    assert!(
        rules.contains(&"nginx-proxy-pass-unknown-service"),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"wireguard-allowed-ips-duplicate"),
        "{rules:?}"
    );
    assert_eq!(j["data"]["errors"], 1);
    assert!(
        !text.contains("hunter2"),
        "a secret value leaked into the report"
    );

    // Warnings alone do not fail the default run, but --fail-on does.
    let (code, j, _) = envv(&dir, &["check", "Mixed", "--fail-on", "error"]);
    assert_eq!(code, Some(10));
    assert_eq!(j["error"]["code"], "invalid");
    assert!(j["error"]["details"]["findings"].is_array());

    // A clean project exits 0 even with --fail-on warning.
    must(&["project", "add", "Clean", "--type", "generic"]);
    let (code, _, text) = envv(&dir, &["check", "Clean", "--fail-on", "warning"]);
    assert_eq!(code, Some(0), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
