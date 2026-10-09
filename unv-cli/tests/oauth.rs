//! `unv oauth refresh` against a mock issuer on localhost, through the real
//! binary. The properties that matter: the rotated refresh token is in the vault
//! by the time the command succeeds, the issuer's error text is not echoed, and
//! https is required for anything that is not localhost.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

fn mock_issuer(response: &'static str) -> (String, std::thread::JoinHandle<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/token", l.local_addr().unwrap());
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = s.read(&mut buf).unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let body = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        );
        s.write_all(body.as_bytes()).unwrap();
        req
    });
    (url, h)
}

fn unv(dir: &std::path::Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_unv"))
        .env_remove("UNV_SERVER_URL")
        .env_remove("UNV_SERVER_URL")
        .env_remove("UNV_ENV_FILE")
        .env_remove("UNV_ENV_FILE")
        .env("UNV_PASSWORD", "correct-horse-battery")
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
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
fn refresh_stores_the_rotated_token_before_reporting_and_never_echoes_secrets() {
    let dir = std::env::temp_dir().join(format!("unv-oauth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let (url, issuer) = mock_issuer(
        r#"{"access_token":"NEW-ACCESS","refresh_token":"NEW-REFRESH","expires_in":3600}"#,
    );
    let token_var = format!("token_url={url}");
    let (ok, o) = unv(
        &dir,
        &[
            "entry",
            "add",
            "Slack",
            "--type",
            "oauth_client",
            "--var",
            &token_var,
            "--var",
            "client_id=cid",
            "--var",
            "client_secret=csecret",
            "--var",
            "refresh_token=OLD-REFRESH",
        ],
    );
    assert!(ok, "{o}");

    let (ok, o) = unv(&dir, &["oauth", "refresh", "Slack"]);
    assert!(ok, "{o}");
    assert!(o.contains("rotated"), "{o}");
    assert!(
        !o.contains("NEW-ACCESS") && !o.contains("NEW-REFRESH"),
        "tokens must stay redacted: {o}"
    );

    let req = issuer.join().unwrap();
    assert!(req.contains("grant_type=refresh_token") && req.contains("refresh_token=OLD-REFRESH"));
    assert!(req.contains("client_secret=csecret"));

    // The new refresh token is what the vault holds now.
    let (ok, o) = unv(&dir, &["get", "Slack", "--reveal"]);
    assert!(ok, "{o}");
    assert!(o.contains("NEW-REFRESH") && o.contains("NEW-ACCESS"), "{o}");
    // The replaced token is kept in version_history (E8), which is the point:
    // a rotation that went wrong is recoverable.
    assert!(
        o.contains("OLD-REFRESH") && o.contains("version_history"),
        "{o}"
    );

    // Plain http to a non-local host is refused before anything is sent.
    let (ok, _) = unv(
        &dir,
        &[
            "entry",
            "set",
            "Slack",
            "--var",
            "token_url=http://issuer.example/token",
        ],
    );
    assert!(ok);
    let (ok, o) = unv(&dir, &["oauth", "refresh", "Slack"]);
    assert!(!ok && o.contains("https"), "{o}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_issuer_error_is_named_and_the_stored_token_survives() {
    let dir = std::env::temp_dir().join(format!("unv-oauth-err-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (url, issuer) =
        mock_issuer(r#"{"error":"invalid_grant","error_description":"leaky detail"}"#);
    let token_var = format!("token_url={url}");
    let (ok, o) = unv(
        &dir,
        &[
            "entry",
            "add",
            "Gh",
            "--type",
            "oauth_client",
            "--var",
            &token_var,
            "--var",
            "client_id=c",
            "--var",
            "refresh_token=KEEP-ME",
        ],
    );
    assert!(ok, "{o}");
    let (ok, o) = unv(&dir, &["oauth", "refresh", "Gh"]);
    issuer.join().unwrap();
    assert!(
        !ok && o.contains("invalid_grant") && !o.contains("leaky detail"),
        "{o}"
    );
    let (_, o) = unv(&dir, &["get", "Gh", "--reveal"]);
    assert!(
        o.contains("KEEP-ME"),
        "a refused refresh must not touch the stored token: {o}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
