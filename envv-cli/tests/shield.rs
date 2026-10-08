//! Real CLI coverage for the two outward-redaction commands.

#![cfg(unix)]

use std::process::{Command, Output};

const SECRET: &str = "phase26-known-secret";

fn scratch() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("envv-shield-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn command(dir: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_envv"));
    command
        .env_remove("ENVV_SERVER_URL")
        .env_remove("ENVV_ENV_FILE")
        .env("ENVV_PASSWORD", "correct-horse-battery")
        .args([
            "--db-path",
            dir.join("vault.db").to_str().unwrap(),
            "--init",
            "--yes",
        ]);
    command
}

fn text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr)
}

#[test]
fn shield_and_exposure_scan_redact_exact_vault_values() {
    let dir = scratch();
    let added = command(&dir)
        .args(["entry", "add", "Example", "--key", SECRET])
        .output()
        .unwrap();
    assert!(added.status.success(), "{}", text(&added));

    let shielded = command(&dir)
        .env("ENVV_PHASE_26_SECRET", SECRET)
        .args([
            "shield",
            "--",
            "sh",
            "-c",
            "printf '%s\\n' \"$ENVV_PHASE_26_SECRET\"; printf '%s\\n' \"$ENVV_PHASE_26_SECRET\" >&2; exit 23",
        ])
        .output()
        .unwrap();
    let shielded_text = text(&shielded);
    assert_eq!(shielded.status.code(), Some(23), "{shielded_text}");
    assert!(!shielded_text.contains(SECRET), "{shielded_text}");
    assert_eq!(
        shielded_text
            .matches(&envv_cli::out::fingerprint(SECRET))
            .count(),
        2,
        "{shielded_text}"
    );

    let exposed = dir.join("app.env");
    std::fs::write(&exposed, format!("safe=true\nTOKEN={SECRET}\n")).unwrap();
    let refused = command(&dir)
        .args(["scan", "--exposed", exposed.to_str().unwrap()])
        .output()
        .unwrap();
    let refused_text = text(&refused);
    assert!(!refused.status.success());
    assert!(!refused_text.contains(SECRET), "{refused_text}");
    assert!(refused_text.contains("Pass --out"), "{refused_text}");

    let report = dir.join("exposed.report");
    let scanned = command(&dir)
        .args([
            "scan",
            "--exposed",
            exposed.to_str().unwrap(),
            "--out",
            report.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(scanned.status.success(), "{}", text(&scanned));
    let report_text = std::fs::read_to_string(&report).unwrap();
    assert!(!report_text.contains(SECRET), "{report_text}");
    assert!(report_text.contains(&format!("{}:2:", exposed.display())));
    assert!(report_text.contains(&envv_cli::out::fingerprint(SECRET)));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&report).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
