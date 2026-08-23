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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("tests").join("fixtures").join("parity")
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
    assert!(!out.contains("NEVER_EXPORTED"), "disabled peer leaked into wg0.conf:\n{out}");
}

/// Every `${…}` must be resolved by the time a config file is written; a literal
/// placeholder in a wg0.conf or an nginx.conf is a failed deploy.
#[test]
fn no_placeholders_survive_export() {
    let v = vault();
    let r = resolver(&v);
    for (p, label) in [(project(&v, "vpn"), "wireguard"), (project(&v, "edge"), "nginx")] {
        let out = if label == "wireguard" {
            exporters::export_wireguard(&p, &r)
        } else {
            exporters::export_nginx(&p, &r)
        };
        assert!(!out.contains("${"), "{label} export still holds a placeholder:\n{out}");
    }
}
