//! The Rust half of the stack-adapter check (Phase 38).
//!
//! `tests/stack.test.ts` pins the TypeScript interpreter against the golden
//! files in `tests/fixtures/parity/`; this pins the Rust one against the same
//! bytes. Prometheus, Grafana and Homepage are descriptors read by both, and two
//! readings of one grammar drift exactly as two exporters do.
//!
//! After an intentional change: `PARITY_UPDATE=1 npx vitest run tests/stack.test.ts`
//! and read the diff.

use unv_cli::{chunks, exporters, refs::Resolver};
use serde_json::{json, Value};
use std::path::PathBuf;
use vault_core::config_check;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("parity")
}

fn vault() -> Value {
    let raw = std::fs::read_to_string(fixtures().join("stack-vault.json")).expect("fixture vault");
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

fn resolver(v: &Value, redact: bool) -> Resolver {
    Resolver::from_parts(
        v["api_keys"].as_array().cloned().unwrap_or_default(),
        v["projects"].as_array().cloned().unwrap_or_default(),
        "api_key",
        redact,
    )
}

#[test]
fn prometheus_matches_the_app() {
    let v = vault();
    let out = exporters::export_stack("prometheus", &project(&v, "prom"), &resolver(&v, false));
    assert_eq!(out, golden("stack-prometheus.yml"));
}

#[test]
fn grafana_matches_the_app() {
    let v = vault();
    let out = exporters::export_stack("grafana", &project(&v, "graf"), &resolver(&v, false));
    assert_eq!(out, golden("stack-grafana.yml"));
}

#[test]
fn homepage_matches_the_app() {
    let v = vault();
    let out = exporters::export_stack("homepage", &project(&v, "home"), &resolver(&v, false));
    assert_eq!(out, golden("stack-homepage.yaml"));
}

#[test]
fn the_cli_render_path_reaches_the_same_bytes_by_project_type() {
    let v = vault();
    for (project_id, exporter, file) in [
        ("prom", "prometheus", "stack-prometheus.yml"),
        ("graf", "grafana", "stack-grafana.yml"),
        ("home", "homepage", "stack-homepage.yaml"),
    ] {
        let ptype = project(&v, project_id)["project_type"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(chunks::default_format_for(&ptype), exporter, "{ptype}");
        assert_eq!(
            chunks::render_project_as(&v, project_id, exporter, false).unwrap(),
            golden(file),
            "{exporter}"
        );
    }
}

/// The redacting resolver is what stdout gets. No secret, referenced or typed
/// in, may reach it, and each masked value must be a fingerprint.
#[test]
fn the_redacted_render_carries_no_secret_and_fingerprints_the_secret_fields() {
    let mut v = vault();
    // A literal secret typed straight into a field, no reference involved.
    v["projects"][0]["chunks"][1]["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .for_each(|f| {
            if f["key"] == "password" {
                f["value"] = json!("typed-in-literal-SECRET");
            }
            if f["key"] == "username" {
                f["value"] = json!("scraper");
            }
        });
    for (id, exporter) in [
        ("prom", "prometheus"),
        ("graf", "grafana"),
        ("home", "homepage"),
    ] {
        let out = exporters::export_stack(exporter, &project(&v, id), &resolver(&v, true));
        for secret in [
            "424242",
            "tok_prom_abc123",
            "rw-pass-xyz",
            "glsa_graf_token_9",
            "pg-password-7",
            "jf-api-key-1",
            "sonarr-key-22",
            "typed-in-literal-SECRET",
        ] {
            assert!(!out.contains(secret), "{exporter} leaked {secret}:\n{out}");
        }
        assert!(
            out.contains("sha256:"),
            "{exporter} showed no fingerprint:\n{out}"
        );
    }
    let prom = exporters::export_stack("prometheus", &project(&v, "prom"), &resolver(&v, true));
    assert!(
        prom.contains("username: scraper"),
        "a non-secret field stays readable:\n{prom}"
    );
}

#[test]
fn the_fixture_projects_are_clean_under_their_own_rules() {
    let v = vault();
    let names: Vec<String> = v["api_keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["provider"].as_str().map(String::from))
        .collect();
    for id in ["prom", "graf", "home"] {
        let found = config_check::check_project(&project(&v, id), &names);
        assert!(
            found.is_empty(),
            "{id}: {:?}",
            found
                .iter()
                .map(|f| (f.rule, &f.message))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn check_project_runs_an_adapters_rules_and_the_unresolved_reference_rule() {
    let mut v = vault();
    // Two jobs with one name, and a reference to something the vault does not hold.
    v["projects"][0]["chunks"][2]["name"] = json!("prometheus");
    v["projects"][0]["chunks"][3]["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .for_each(|f| {
            if f["key"] == "password" {
                f["value"] = json!("${Ghost}");
            }
        });
    let names: Vec<String> = vec!["PromToken".into()];
    let rules: Vec<&str> = config_check::check_project(&project(&v, "prom"), &names)
        .iter()
        .map(|f| f.rule)
        .collect();
    assert!(
        rules.contains(&"stack-prometheus-duplicate-job"),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"stack-prometheus-unresolved-ref"),
        "{rules:?}"
    );
}

#[test]
fn a_chunk_added_from_the_cli_has_its_descriptors_defaults_and_secret_flags() {
    let spec = vault_core::stack::adapter("prometheus")
        .unwrap()
        .chunk_spec("prom_scrape")
        .unwrap();
    let c = vault_core::stack::new_chunk(spec, "job", "id-1".into());
    let field = |k: &str| {
        c["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["key"] == k)
            .unwrap()
            .clone()
    };
    assert_eq!(field("targets")["value"], "localhost:9090");
    assert_eq!(field("password")["field_type"], "secret");
}
