//! The guarantees an automated caller depends on.
//!
//! The claim this CLI makes is narrow and testable: *a caller can drive every
//! command without a secret value entering its output*. These tests pin the
//! mechanisms that make it true, because each of them is one careless
//! `println!` away from being false.
//!
//! `out::mode()` defaults to `reveal: false`, so redaction is active here with
//! no setup — the same default a caller gets.

use envv_cli::refs::Resolver;
use envv_cli::{agentio, exporters, out, render};
use serde_json::{json, Value};

fn vault() -> Value {
    json!({
        "api_keys": [
            {
                "id": "e1", "provider": "GitHub", "api_key": "ghp_live_secret_value",
                "api_secret": "second_secret", "api_url": "https://api.github.com",
                "price_type": "free", "secretType": "api_key",
                "categories": [], "projectIds": ["Universal"], "scopes": [],
                "extra_vars": [
                    { "key": "REGION", "value": "eu-west-1", "secret": false },
                    { "key": "SIGNING", "value": "hidden_signing_key", "secret": true }
                ],
                "version_history": [
                    { "value": "ghp_previous_secret", "saved_at": "2026-01-01T00:00:00Z" }
                ]
            },
            {
                "id": "e2", "provider": "Mirror", "api_key": "ghp_live_secret_value",
                "price_type": "free", "secretType": "api_key",
                "categories": [], "projectIds": ["Universal"], "scopes": []
            }
        ],
        "user_categories": [],
        "projects": [
            { "id": "Universal", "name": "Universal" },
            {
                "id": "stack", "name": "Stack", "project_type": "docker",
                "chunks": [{
                    "id": "c1", "name": "app.env", "chunk_type": "env_file",
                    "fields": [
                        { "key": "TOKEN", "value": "${GitHub}", "field_type": "secret", "secret": true },
                        { "key": "INLINE", "value": "literal_password_here", "field_type": "secret", "secret": true },
                        { "key": "PORT", "value": "3000", "field_type": "var" }
                    ]
                }]
            },
            {
                "id": "vpn", "name": "VPN", "project_type": "wireguard",
                "chunks": [{
                    "id": "c2", "name": "Interface", "chunk_type": "wg_interface",
                    "fields": [
                        { "key": "PrivateKey", "value": "${GitHub}", "field_type": "secret", "secret": true },
                        { "key": "Address", "value": "10.0.0.1/24", "field_type": "var" }
                    ]
                }]
            }
        ]
    })
}

fn project(v: &Value, id: &str) -> Value {
    v["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("fixture has no project {id}"))
        .clone()
}

fn resolver(v: &Value, redact: bool) -> Resolver {
    Resolver::from_parts(
        v["api_keys"].as_array().unwrap().clone(),
        v["projects"].as_array().unwrap().clone(),
        "api_key",
        redact,
    )
}

// ── Fingerprints ──────────────────────────────────────────────────────────────

#[test]
fn fingerprints_are_stable_and_comparable() {
    let a = out::fingerprint("secret-one");
    assert_eq!(
        a,
        out::fingerprint("secret-one"),
        "same value must fingerprint the same"
    );
    assert_ne!(a, out::fingerprint("secret-two"));
    assert!(a.starts_with("sha256:"));
    // 48 bits of hex: enough to compare, useless to authenticate with.
    assert_eq!(a.len(), "sha256:".len() + 12);
}

#[test]
fn an_empty_value_is_marked_not_hashed() {
    // "unset" and "set to something" must never look alike, or a caller cannot
    // tell a missing credential from a present one.
    assert_eq!(out::fingerprint(""), "empty");
    assert_ne!(out::fingerprint(" "), "empty");
}

#[test]
fn a_fingerprint_never_contains_the_value() {
    let secret = "correct-horse-battery-staple";
    let fp = out::fingerprint(secret);
    assert!(!fp.contains(secret));
    assert!(!fp.contains(&secret[..8]));
}

// ── Entry redaction ───────────────────────────────────────────────────────────

#[test]
fn entry_redaction_masks_every_secret_field() {
    let v = vault();
    let safe = out::redact_entry(&v["api_keys"][0]);
    let text = serde_json::to_string(&safe).unwrap();

    for leaked in [
        "ghp_live_secret_value",
        "second_secret",
        "hidden_signing_key",
        "ghp_previous_secret",
    ] {
        assert!(
            !text.contains(leaked),
            "redacted entry still contains {leaked}: {text}"
        );
    }
    // Locating information survives, or the redacted view cannot tell you which
    // entry you are looking at.
    assert_eq!(safe["provider"], json!("GitHub"));
    assert_eq!(safe["api_url"], json!("https://api.github.com"));
    // A non-secret extra_var is data, not a credential.
    assert!(text.contains("eu-west-1"));
    assert_eq!(safe["api_key"]["redacted"], json!(true));
    assert_eq!(
        safe["api_key"]["length"],
        json!("ghp_live_secret_value".len())
    );
}

#[test]
fn identical_secrets_fingerprint_identically_across_entries() {
    // This is what makes the redacted view *useful*: a caller can find reuse and
    // detect drift without ever reading a value.
    let v = vault();
    let a = out::redact_entry(&v["api_keys"][0]);
    let b = out::redact_entry(&v["api_keys"][1]);
    assert_eq!(a["api_key"]["fingerprint"], b["api_key"]["fingerprint"]);
}

#[test]
fn project_redaction_keeps_references_visible() {
    let v = vault();
    let safe = out::redact_project(&project(&v, "stack"));
    let text = serde_json::to_string(&safe).unwrap();

    assert!(
        !text.contains("literal_password_here"),
        "literal secret leaked: {text}"
    );
    // A `${ref}` is a pointer, not a secret — leaving it readable is exactly
    // what lets an agent wire configs together blind.
    assert!(
        text.contains("${GitHub}"),
        "reference was masked; the wiring is now invisible"
    );
}

#[test]
fn an_env_file_chunk_is_masked_whole_regardless_of_field_flags() {
    // `PORT=3000` is not a secret, and it is masked anyway. That is deliberate:
    // `chunk set` writes `field_type: var` by default, so a real password added
    // that way carries no secret flag at all. Trusting the flag inside a `.env`
    // means the first unflagged password is the one that leaks.
    let v = vault();
    let safe = out::redact_project(&project(&v, "stack"));
    let text = serde_json::to_string(&safe).unwrap();
    assert!(
        !text.contains("3000"),
        "an env_file value escaped redaction: {text}"
    );
}

#[test]
fn ordinary_config_text_outside_a_env_file_stays_readable() {
    // The redacted view has to remain useful for deciding what a config *is*.
    let v = vault();
    let safe = out::redact_project(&project(&v, "vpn"));
    let text = serde_json::to_string(&safe).unwrap();
    assert!(
        text.contains("10.0.0.1/24"),
        "a non-secret wg field was masked: {text}"
    );
    assert!(!text.contains("ghp_live_secret_value"));
}

// ── Exporters ─────────────────────────────────────────────────────────────────

#[test]
fn a_redacting_export_carries_no_secret() {
    let v = vault();
    let wg = exporters::export_wireguard(&project(&v, "vpn"), &resolver(&v, true));
    assert!(
        !wg.contains("ghp_live_secret_value"),
        "wg export leaked the key:\n{wg}"
    );
    assert!(wg.contains("sha256:"));
    // Structure stays legible, which is the point of masking rather than refusing.
    assert!(wg.contains("[Interface]"));
    assert!(wg.contains("Address = 10.0.0.1/24"));
}

#[test]
fn a_materialising_export_carries_the_real_value() {
    // The same call with redaction off is what `--out` uses. If this stops
    // producing real values, every generated config silently breaks.
    let v = vault();
    let wg = exporters::export_wireguard(&project(&v, "vpn"), &resolver(&v, false));
    assert!(wg.contains("PrivateKey = ghp_live_secret_value"));
}

#[test]
fn a_redacting_env_export_masks_literals_too() {
    // Everything in a .env is secret material by construction, so a literal
    // value gets the same treatment as a resolved reference.
    let v = vault();
    let env = exporters::export_project_env(&project(&v, "stack"), &resolver(&v, true));
    assert!(
        !env.text.contains("literal_password_here"),
        "leaked:\n{}",
        env.text
    );
    assert!(!env.text.contains("ghp_live_secret_value"));
    assert!(env.text.contains("TOKEN=sha256:"));
}

// ── Templates ─────────────────────────────────────────────────────────────────

#[test]
fn render_substitutes_mid_line_references() {
    let v = vault();
    let out = render::render("Authorization: Bearer ${GitHub}\n", &resolver(&v, false));
    assert_eq!(out.text, "Authorization: Bearer ghp_live_secret_value\n");
    assert_eq!(out.resolved, 1);
    assert!(out.unresolved.is_empty());
}

#[test]
fn render_escapes_double_dollar() {
    // A rendered compose file needs to keep its own ${VAR} syntax, so `$${…}`
    // has to survive as a literal rather than being resolved or dropped.
    let v = vault();
    let out = render::render("image: ${GitHub}\nport: $${PORT}\n", &resolver(&v, false));
    assert!(out.text.contains("port: ${PORT}"));
    assert_eq!(out.resolved, 1);
}

#[test]
fn render_reports_unresolved_rather_than_inventing() {
    let v = vault();
    let out = render::render("x: ${NoSuchEntry}", &resolver(&v, false));
    assert_eq!(out.unresolved, vec!["${NoSuchEntry}".to_string()]);
    // The literal stays in place: a blank would look like a valid empty value,
    // and a config with a blank secret fails far from here.
    assert!(out.text.contains("${NoSuchEntry}"));
}

#[test]
fn render_to_stdout_is_redacted() {
    let v = vault();
    let out = render::render("token: ${GitHub}", &resolver(&v, true));
    assert!(!out.text.contains("ghp_live_secret_value"));
    assert!(out.text.contains("sha256:"));
}

// ── The contract document ─────────────────────────────────────────────────────

/// A stand-in command tree. This test is about the shape of the document, not
/// the real command list — `describe` is generated from whatever `clap`
/// definition it is handed, so it cannot describe a flag that does not exist.
#[derive(clap::Parser)]
#[command(name = "envv", about = "test double")]
struct DummyCli {
    /// Emit JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: DummySub,
}

#[derive(clap::Subcommand)]
enum DummySub {
    /// A command with an argument.
    Entry {
        provider: String,
        #[arg(long, value_parser = ["a", "b"])]
        kind: Option<String>,
    },
    /// A command with none.
    Status,
}

#[test]
fn describe_documents_every_exit_code_and_the_flags_that_exist() {
    use clap::CommandFactory;
    let doc = agentio::describe(&DummyCli::command());

    let codes = doc["exit_codes"]
        .as_object()
        .expect("exit_codes is an object");
    for expected in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"] {
        assert!(
            codes.contains_key(expected),
            "exit code {expected} is undocumented"
        );
    }
    assert!(doc["secret_handling"]["materialisation"].is_array());
    assert!(doc["envelope"]["success"].is_object());

    let subs = doc["command"]["subcommands"]
        .as_array()
        .expect("subcommands");
    let entry = subs
        .iter()
        .find(|c| c["name"] == json!("entry"))
        .expect("entry command");
    assert_eq!(entry["path"], json!("envv entry"));
    let args = entry["args"].as_array().unwrap();
    let kind = args
        .iter()
        .find(|a| a["id"] == json!("kind"))
        .expect("--kind described");
    assert_eq!(
        kind["values"],
        json!(["a", "b"]),
        "possible values must reach the caller"
    );
    assert_eq!(kind["takes_value"], json!(true));
    let provider = args.iter().find(|a| a["id"] == json!("provider")).unwrap();
    assert_eq!(provider["kind"], json!("positional"));
}

// ── Phase 17: the pin must have no way around it ─────────────────────────────

/// There must be exactly one place an HTTP client is built.
///
/// This is the test that keeps 1.2 fixed. The CLI shipped for four phases with
/// three bare `reqwest::blocking::Client::new()` calls, each of which silently
/// used the platform CA store and could not reach a self-signed server. Adding
/// a fourth would reopen the hole without failing any behavioural test, because
/// the wrong client works perfectly against a server with a real certificate.
#[test]
fn no_http_client_is_constructed_outside_the_tls_module() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&src).expect("read src/") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name == "tls.rs" {
            continue; // the one legitimate builder lives here
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        for (n, line) in text.lines().enumerate() {
            // Skip doc comments: tls.rs's rationale quotes the pattern by name,
            // and so does the module doc that explains why this test exists.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if line.contains("Client::new()") || line.contains("Client::builder()") {
                offenders.push(format!("{name}:{}", n + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "HTTP clients built outside tls::build_client(): {offenders:?}\n\
         Every client must carry the TLS policy, or --fingerprint silently does nothing there."
    );
}

/// A fingerprint is normalised the same way wherever it enters the program.
///
/// `openssl x509 -fingerprint` prints upper case with colons; the app and this
/// CLI store lower-case hex. A pin that only matches in one of those forms is a
/// pin that fails for every user who copied it from the tool that prints it.
#[test]
fn pasted_fingerprint_forms_all_normalise_to_one_value() {
    use vault_core::tls::normalize_fingerprint;
    let canonical = "a".repeat(64);
    let upper = canonical.to_ascii_uppercase();
    let colons: String = upper
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join(":");
    for form in [
        canonical.clone(),
        upper.clone(),
        colons.clone(),
        format!("sha256:{colons}"),
        format!("  {upper}  "),
    ] {
        assert_eq!(normalize_fingerprint(&form), canonical, "form: {form}");
    }
}

/// A truncated pin is refused before any connection is attempted.
#[test]
fn a_short_fingerprint_is_rejected_as_input_not_as_a_network_error() {
    let err = envv_cli::tls::configure(Some("deadbeef"), None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("64 hex"), "{msg}");
    // Must be an input error, never `unavailable` — a caller retrying an
    // `unavailable` would loop forever on a typo.
    assert_eq!(err.code, envv_cli::error::Code::Invalid);
}
