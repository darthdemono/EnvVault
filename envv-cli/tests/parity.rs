//! The Rust half of the exporter parity check.
//!
//! `tests/cli-parity.test.ts` pins the TypeScript exporters against the golden
//! files in `tests/fixtures/parity/`; this pins the Rust ones against the same
//! bytes. Two implementations of one config format drift silently — the app
//! writes a working wg0.conf and the CLI writes a subtly different one — and the
//! only cheap defence is making both assert the same fixture.
//!
//! If this fails after an intentional change, regenerate with
//! `PARITY_UPDATE=1 npx vitest run tests/cli-parity.test.ts` and read the diff.

use envv_cli::exporters;
use envv_cli::refs::Resolver;
use serde_json::Value;
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("parity")
}

fn vault() -> Value {
    let raw = std::fs::read_to_string(fixtures().join("vault.json")).expect("fixture vault");
    serde_json::from_str(&raw).expect("fixture parses")
}

fn golden(name: &str) -> String {
    std::fs::read_to_string(fixtures().join(name)).unwrap_or_else(|e| panic!("golden {name}: {e}"))
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

fn chunk(p: &Value, chunk_type: &str) -> Value {
    p["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["chunk_type"].as_str() == Some(chunk_type))
        .unwrap_or_else(|| panic!("project has no {chunk_type} chunk"))
        .clone()
}

/// The fixture is written for the default `envCopyField`; passing it explicitly
/// keeps the test independent of whatever settings.json is on the machine.
const ENV_FIELD: &str = "api_key";

/// A resolver that produces real values, as an export to a file does. The
/// goldens are the deployable text, so redaction is off here by construction.
fn resolver(v: &Value) -> Resolver {
    Resolver::from_parts(
        v["api_keys"].as_array().unwrap().clone(),
        v["projects"].as_array().unwrap().clone(),
        ENV_FIELD,
        false,
    )
}

#[test]
fn wireguard_matches_the_app() {
    let v = vault();
    let out = exporters::export_wireguard(&project(&v, "vpn"), &resolver(&v));
    assert_eq!(out, golden("wireguard.conf"));
}

#[test]
fn docker_compose_matches_the_app() {
    let v = vault();
    let c = exporters::export_docker_compose(&project(&v, "stack"), &resolver(&v));
    assert_eq!(c.yaml, golden("compose.yaml"));
    assert_eq!(c.env_file, golden("compose.env"));
}

#[test]
fn nginx_matches_the_app() {
    let v = vault();
    let out = exporters::export_nginx(&project(&v, "edge"), &resolver(&v));
    assert_eq!(out, golden("nginx.conf"));
}

#[test]
fn chunk_text_matches_the_app() {
    let v = vault();
    let r = resolver(&v);
    let stack = project(&v, "stack");
    let vpn = project(&v, "vpn");
    let edge = project(&v, "edge");

    for (chunk_value, name) in [
        (chunk(&stack, "env_file"), "chunk-env.txt"),
        (chunk(&vpn, "wg_interface"), "chunk-wg-interface.txt"),
        (chunk(&stack, "docker_service"), "chunk-docker-service.txt"),
        (chunk(&edge, "nginx_upstream"), "chunk-nginx-upstream.txt"),
    ] {
        let out = exporters::chunk_to_string(&chunk_value, &r);
        assert_eq!(out, golden(name), "{name}");
    }
}

/// A disabled chunk is documented as excluded from exports, and both sides must
/// agree — the fixture's VPN project carries one whose key is `NEVER_EXPORTED`.
#[test]
fn disabled_chunks_are_never_exported() {
    let v = vault();
    let out = exporters::export_wireguard(&project(&v, "vpn"), &resolver(&v));
    assert!(
        !out.contains("NEVER_EXPORTED"),
        "disabled peer leaked into wg0.conf:\n{out}"
    );
}

/// Every `${…}` must be resolved by the time a config file is written; a literal
/// placeholder in a wg0.conf or an nginx.conf is a failed deploy.
#[test]
fn no_placeholders_survive_export() {
    let v = vault();
    let r = resolver(&v);
    for (p, label) in [
        (project(&v, "vpn"), "wireguard"),
        (project(&v, "edge"), "nginx"),
    ] {
        let out = if label == "wireguard" {
            exporters::export_wireguard(&p, &r)
        } else {
            exporters::export_nginx(&p, &r)
        };
        assert!(
            !out.contains("${"),
            "{label} export still holds a placeholder:\n{out}"
        );
    }
}

/// The iCalendar feed, pinned against the same golden file the TypeScript suite
/// writes.
///
/// `now` is fixed for the reason the TypeScript side documents: a DTSTAMP from
// ── The seven that used to be TypeScript-only ─────────────────────────────────
//
// These goldens existed since Phase 18 and were asserted from `chunk-ops.ts`
// alone, so "one format, two implementations, one golden file" covered 4 of 11.
// The CLI meanwhile fell back to `.env` for all seven, which is how
// `envv project export my-lb` on an haproxy project wrote something that was not
// an haproxy config. Both halves now assert the identical bytes.

#[test]
fn apache_matches_the_app() {
    let v = vault();
    let out = exporters::export_apache(&project(&v, "apache"), &resolver(&v));
    assert_eq!(out, golden("apache.conf"));
}

#[test]
fn haproxy_matches_the_app() {
    let v = vault();
    let out = exporters::export_haproxy(&project(&v, "haproxy"), &resolver(&v));
    assert_eq!(out, golden("haproxy.cfg"));
}

#[test]
fn ansible_matches_the_app() {
    let v = vault();
    let out = exporters::export_ansible(&project(&v, "ansible"), &resolver(&v));
    assert_eq!(out, golden("ansible.yml"));
}

#[test]
fn postgres_matches_the_app() {
    let v = vault();
    let out = exporters::export_postgres(&project(&v, "pg"), &resolver(&v));
    assert_eq!(out, golden("pgpass"));
}

#[test]
fn kubernetes_matches_the_app() {
    let v = vault();
    let out = exporters::export_k8s(&project(&v, "k8s"), &resolver(&v));
    assert_eq!(out, golden("k8s.yaml"));
}

#[test]
fn ssh_config_matches_the_app() {
    let v = vault();
    let out = exporters::export_ssh_config(&project(&v, "ssh"), &resolver(&v));
    assert_eq!(out, golden("ssh_config"));
}

#[test]
fn traefik_matches_the_app() {
    let v = vault();
    let out = exporters::export_traefik(&project(&v, "traefik"), &resolver(&v));
    assert_eq!(out, golden("traefik.yaml"));
}

/// The same two properties `tests/cli-parity.test.ts` asserts directly rather
/// than only through the goldens, so a regenerated fixture cannot quietly bless
/// a regression on the Rust side either.
#[test]
fn every_exporter_resolves_every_ref() {
    // Invariant 5. A `${…}` reaching a real config file is a broken deploy: a
    // .pgpass whose password is the literal string `${PgProd/password}` fails to
    // authenticate and names nothing useful in the error.
    let v = vault();
    let r = resolver(&v);
    let cases: Vec<(&str, String)> = vec![
        ("k8s", exporters::export_k8s(&project(&v, "k8s"), &r)),
        ("ssh", exporters::export_ssh_config(&project(&v, "ssh"), &r)),
        (
            "traefik",
            exporters::export_traefik(&project(&v, "traefik"), &r),
        ),
        (
            "apache",
            exporters::export_apache(&project(&v, "apache"), &r),
        ),
        (
            "haproxy",
            exporters::export_haproxy(&project(&v, "haproxy"), &r),
        ),
        (
            "ansible",
            exporters::export_ansible(&project(&v, "ansible"), &r),
        ),
        (
            "postgres",
            exporters::export_postgres(&project(&v, "pg"), &r),
        ),
    ];
    for (name, out) in cases {
        assert!(
            !out.contains("${"),
            "{name} emitted an unresolved reference:\n{out}"
        );
    }
}

#[test]
fn disabled_chunks_are_excluded() {
    // Disabling a chunk greys the card out. Exporting it anyway means the
    // deployed file still lists something the user believes they removed —
    // which for a WireGuard peer means the tunnel keeps trusting it.
    let v = vault();
    let r = resolver(&v);
    for (name, out, needle) in [
        (
            "k8s",
            exporters::export_k8s(&project(&v, "k8s"), &r),
            "must-not-appear",
        ),
        (
            "ssh",
            exporters::export_ssh_config(&project(&v, "ssh"), &r),
            "gone.example.com",
        ),
        (
            "postgres",
            exporters::export_postgres(&project(&v, "pg"), &r),
            "old.internal",
        ),
    ] {
        assert!(!out.contains(needle), "{name} exported a disabled chunk");
    }
}

/// Every project type exports as its own format.
///
/// The defect this pins (review-01 §3.2): the default-format match named three
/// types and sent the other eight to `env`. `envv project export my-lb` on an
/// haproxy project therefore wrote a `.env` that was not `haproxy.cfg`, or died
/// with "Project 'my-lb' has no env_file chunks" — a message naming neither the
/// cause nor the fix, on project types Phase 18 had already graduated to stable.
#[test]
fn every_project_type_has_its_own_default_format() {
    use envv_cli::chunks::{default_format_for, EXPORT_FORMATS};
    for (ptype, expected) in [
        ("wireguard", "wireguard"),
        ("docker", "compose"),
        ("nginx", "nginx"),
        ("apache", "apache"),
        ("haproxy", "haproxy"),
        ("ansible", "ansible"),
        ("postgres", "postgres"),
        ("kubernetes", "k8s"),
        ("ssh_config", "ssh"),
        ("traefik", "traefik"),
        ("generic", "env"),
    ] {
        let got = default_format_for(ptype);
        assert_eq!(got, expected, "{ptype} must default to {expected}");
        assert!(
            EXPORT_FORMATS.contains(&got),
            "{ptype} defaults to {got}, which --format will not accept"
        );
    }
    // A type from a newer build falls back to .env rather than panicking or
    // exporting nothing. The vault is untrusted input and `project_type` is a
    // union erased at runtime.
    assert_eq!(default_format_for("some_future_type"), "env");
}

/// The `${Provider/field}` alias table, asserted through the real resolution
/// path rather than by reading the table.
///
/// This is a fourth twin pair and it had already drifted silently — `PASSWORD`,
/// `PASS` and `PWD` were in `FIELD_ALIASES` and missing from `canonical_field`,
/// so a `${…/password}` reference resolved in the app and came out as literal
/// text from the CLI. Found by the seven exporter goldens the moment they were
/// asserted from both sides, which is exactly what the parity harness is for.
#[test]
fn field_aliases_match_the_app() {
    let raw = golden("field-aliases.json");
    let doc: Value = serde_json::from_str(&raw).expect("alias fixture parses");
    let aliases = doc["aliases"].as_object().expect("aliases object");

    // Every field holds its own name, so a resolved reference reports which
    // field it landed on.
    let entry = serde_json::json!({
        "provider":     "E",
        "api_key":      "api_key",
        "api_secret":   "api_secret",
        "username":     "username",
        "api_url":      "api_url",
        "email":        "email",
        "key_id":       "key_id",
    });
    let r = Resolver::from_parts(vec![entry], vec![], ENV_FIELD, false);

    for (alias, expected) in aliases {
        let expected = expected.as_str().expect("expected field name");
        let got = r.or_literal(&format!("${{E/{alias}}}"));
        assert_eq!(
            got, expected,
            "${{E/{alias}}} must resolve to {expected}, got {got}"
        );
    }
}

/// the wall clock makes the fixture stale within a second and makes byte
/// equality between the two implementations impossible even when they agree.
#[test]
fn calendar_ics() {
    let v = vault();
    let entries: Vec<Value> = v["api_keys"].as_array().unwrap().clone();
    let ics = envv_cli::calendar::build_ics(
        &entries,
        &envv_cli::calendar::IcsOptions {
            now: "2026-08-26T12:00:00Z".to_string(),
            calendar_name: "EnvVault".to_string(),
            ..Default::default()
        },
    );
    assert_eq!(ics, golden("calendar.ics"));
}

/// No value from the fixture vault appears in the feed it produces.
///
/// Asserted against the real fixture rather than a toy entry, because the file
/// is handed to a calendar service that this project has no relationship with.
#[test]
fn calendar_carries_no_secret_value() {
    let v = vault();
    let entries: Vec<Value> = v["api_keys"].as_array().unwrap().clone();
    let ics = envv_cli::calendar::build_ics(&entries, &envv_cli::calendar::IcsOptions::default());
    for e in &entries {
        for field in ["api_key", "api_secret"] {
            if let Some(val) = e.get(field).and_then(|x| x.as_str()) {
                if !val.is_empty() {
                    assert!(
                        !ics.contains(val),
                        "{field} of {} leaked into the calendar",
                        e["provider"]
                    );
                }
            }
        }
    }
}
