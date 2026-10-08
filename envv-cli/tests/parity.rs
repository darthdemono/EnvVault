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
    // field it landed on. The metadata fields carry values too, so the
    // deny-list assertion below is exercised rather than satisfied by absence.
    let entry = serde_json::json!({
        "provider":         "E",
        "api_key":          "api_key",
        "api_secret":       "api_secret",
        "username":         "username",
        "api_url":          "api_url",
        "email":            "email",
        "key_id":           "key_id",
        "mount_path":       "mount_path",
        "id":               "b3f1c0de-0000-4000-8000-000000000001",
        "categories":       ["categories"],
        "projectIds":       ["Universal"],
        "version_history":  [{ "value": "old", "saved_at": "2026-01-01T00:00:00Z" }],
    });
    let fb = &doc["extra_var_fallback"];
    let fb_provider = fb["provider"].as_str().expect("fallback provider");
    let fallback_entry = serde_json::json!({
        "provider":   fb_provider,
        "api_key":    "api_key",
        "id":         "b3f1c0de-0000-4000-8000-000000000002",
        "extra_vars": [{ "key": fb["var_key"], "value": fb["value"] }],
    });
    let r = Resolver::from_parts(vec![entry, fallback_entry], vec![], ENV_FIELD, false);

    for (alias, expected) in aliases {
        let expected = expected.as_str().expect("expected field name");
        let got = r.or_literal(&format!("${{E/{alias}}}"));
        assert_eq!(
            got, expected,
            "${{E/{alias}}} must resolve to {expected}, got {got}"
        );
    }

    // Phase 21: entry metadata is not addressable. `ID` used to fall through to
    // `_ => field`, so `${E/ID}` returned `entry.id` — a UUID — and the CLI
    // wrote it into a rendered config while the app left the reference literal.
    // An unresolved reference comes back as its own text.
    for field in doc["unresolvable"]
        .as_array()
        .expect("unresolvable list")
        .iter()
        .map(|f| f.as_str().expect("field name"))
    {
        let reference = format!("${{E/{field}}}");
        assert_eq!(
            r.or_literal(&reference),
            reference,
            "${{E/{field}}} must not resolve to anything"
        );
    }

    // ...and an empty built-in falls through to extra_vars, as the app does.
    let fb_field = fb["field"].as_str().expect("fallback field");
    assert_eq!(
        r.or_literal(&format!("${{{fb_provider}/{fb_field}}}")),
        fb["value"].as_str().expect("fallback value"),
    );
}

/// the wall clock makes the fixture stale within a second and makes byte
/// equality between the two implementations impossible even when they agree.
#[test]
fn calendar_ics() {
    let v = vault();
    let entries: Vec<Value> = v["api_keys"].as_array().unwrap().clone();
    let ics = vault_core::calendar::build_ics(
        &entries,
        &vault_core::calendar::IcsOptions {
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
    let ics =
        vault_core::calendar::build_ics(&entries, &vault_core::calendar::IcsOptions::default());
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

/// The env-name template and `.env` quoting — Phase 23, step 1.
///
/// A fifth twin pair, and the third in this project that existed as two
/// implementations before anybody wrote a fixture for it. There were in fact
/// *three* name builders before this — `dotenvKey` (provider + key_id), `envKey`
/// in `import-export.ts` (provider only) and `data::env_key` here (provider
/// only) — so one entry exported under two different names depending on which
/// button you pressed.
///
/// The quoting half asserts the **round trip** rather than only the bytes:
/// `parse(write(v)) == v` is the property a `.env` has to have, and it was false
/// for every value containing a space, a `#`, a quote or a newline.
#[test]
fn env_names_and_quoting_match_the_app() {
    use envv_cli::envfile::{env_name, quote_env_value, unquote_env_value, NameCase, NameOpts};

    let doc: Value = serde_json::from_str(&golden("env-names.json")).expect("fixture parses");

    for c in doc["names"].as_array().expect("names array") {
        let why = c["why"].as_str().unwrap_or("");
        let opts = NameOpts {
            role: c.get("role").and_then(|r| r.as_str()),
            case: c.get("case").and_then(|x| x.as_str()).map(NameCase::parse),
            include_prefix: c
                .get("includePrefix")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
        };
        assert_eq!(
            env_name(&c["entry"], &opts),
            c["expect"].as_str().unwrap(),
            "{why}"
        );
    }

    for c in doc["roles"].as_array().expect("roles array") {
        let why = c["why"].as_str().unwrap_or("");
        assert_eq!(
            envv_cli::envfile::primary_name(&c["entry"], None, false),
            c["primary"].as_str().unwrap(),
            "primary: {why}"
        );
        assert_eq!(
            envv_cli::envfile::secret_name(&c["entry"], None, false),
            c["secret"].as_str().unwrap(),
            "secret: {why}"
        );
    }

    for c in doc["quoting"].as_array().expect("quoting array") {
        let why = c["why"].as_str().unwrap_or("");
        let value = c["value"].as_str().unwrap();
        assert_eq!(
            quote_env_value(value),
            c["written"].as_str().unwrap(),
            "write: {why}"
        );
        assert_eq!(
            unquote_env_value(&quote_env_value(value)),
            value,
            "round trip: {why}"
        );
    }

    for c in doc["unquoting"].as_array().expect("unquoting array") {
        assert_eq!(
            unquote_env_value(c["raw"].as_str().unwrap()),
            c["expect"].as_str().unwrap(),
            "{}",
            c["why"].as_str().unwrap_or("")
        );
    }
}

/// E9 — the reference grammar and the name template share a syntactic position.
///
/// `${SPOTIFY_V2}` can mean provider `SPOTIFY` with `key_id` `V2` (the legacy
/// split) or the `SPOTIFY` entry whose version is 2 (the template). Where both
/// exist and disagree the reference is **refused**: a plausible-looking wrong
/// value written into a rendered config is the Phase 21 defect class, and the
/// honest answer is the one every exporter already reports.
#[test]
fn reference_lookup_matches_the_app() {
    let doc: Value = serde_json::from_str(&golden("env-names.json")).expect("fixture parses");
    let section = &doc["reference_lookup"];
    let entries: Vec<Value> = section["entries"].as_array().expect("entries").clone();

    for c in section["cases"].as_array().expect("cases") {
        let why = c["why"].as_str().unwrap_or("");
        let found = envv_cli::refs::find_entry(&entries, c["ref"].as_str().unwrap());
        let got = found
            .and_then(|e| e.get("account_name"))
            .and_then(|v| v.as_str());
        assert_eq!(got, c["expect"].as_str(), "{why}");
    }
}

/// Phase 23, step 2: a role declared on the entry beats the alias table.
///
/// `primary_role: "id"` says the primary value *is* a client id, so `${X/ID}`
/// must answer with `api_key` rather than with the `key_id` beside it — which is
/// what the Phase 21 alias arm resolves to for an entry that declares no role,
/// and what it still resolves to for every such entry. Roles also make the
/// no-primary shapes addressable: Twilio's two halves are an Account SID and an
/// Auth Token, and naming them by the issuer's own words is the point.
#[test]
fn declared_roles_beat_the_alias_table() {
    let doc: Value = serde_json::from_str(&golden("field-aliases.json")).expect("fixture parses");

    let ra = &doc["role_aware"];
    for c in ra["cases"].as_array().expect("cases") {
        let got = envv_cli::refs::entry_field(&ra["entry"], c["field"].as_str().unwrap());
        assert_eq!(
            got.as_deref(),
            c["expect"].as_str(),
            "{}",
            c["why"].as_str().unwrap_or("")
        );
    }

    let ri = &doc["role_aware_id"];
    let got = envv_cli::refs::entry_field(&ri["entry"], ri["field"].as_str().unwrap());
    assert_eq!(
        got.as_deref(),
        ri["expect"].as_str(),
        "{}",
        ri["_why"].as_str().unwrap_or("")
    );
}

/// `${bundle:…}` references — Phase 24.1. Pinned by `bundle-refs.json`.
#[test]
fn bundle_references_resolve_like_the_app() {
    let doc: Value = serde_json::from_str(&golden("bundle-refs.json")).expect("fixture parses");
    let entries = doc["entries"].as_array().expect("entries").clone();
    for c in doc["cases"].as_array().expect("cases") {
        let inner = c["ref"].as_str().unwrap();
        let got = envv_cli::refs::resolve_ref(&entries, &[], inner, "api_key", 0);
        assert_eq!(
            got.as_deref(),
            c["expect"].as_str(),
            "{}",
            c["why"].as_str().unwrap_or("")
        );
    }
}

/// Copy profiles — Phase 23, step 3. A sixth twin pair.
///
/// It exists twice because the app's Copy button puts the text on the clipboard
/// with no Rust in the loop, and `envv get --profile` writes the same text from
/// the terminal. A copy that differs between the two is a `.env` whose contents
/// depend on which half of the product the user reached for.
#[test]
fn copy_profiles_match_the_app() {
    use envv_cli::profile::{build, CopyOpts, MetadataStyle, Profile};

    let doc: Value = serde_json::from_str(&golden("copy-profiles.json")).expect("fixture parses");

    let opts_of = |c: &Value| CopyOpts {
        profile: Profile::parse(c["profile"].as_str().unwrap()),
        metadata: MetadataStyle::parse(c["metadataStyle"].as_str().unwrap()),
        ..Default::default()
    };
    let expect_of = |c: &Value| {
        c["expect"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    };

    for c in doc["cases"].as_array().expect("cases") {
        assert_eq!(
            build(&doc["entry"], &opts_of(c)),
            expect_of(c),
            "{}",
            c["why"].as_str().unwrap_or("")
        );
    }

    let sp = &doc["sparse"];
    assert_eq!(
        build(&sp["entry"], &opts_of(sp)),
        expect_of(sp),
        "an entry with no primary value emits no empty primary line"
    );
}

/// How a credential is sent — Phase 23, E16. A seventh twin pair.
///
/// The app's "Copy as request header" builds the header with no Rust in the
/// loop and `envv curl` builds the same one from the terminal; a header that
/// differs between them is a request that works from one half of the product and
/// 401s from the other, with the API explaining neither.
///
/// Shell quoting is pinned here too: every interpolated value is vault data
/// (invariant 4), and one of them is routinely a cookie jar full of semicolons.
#[test]
fn auth_schemes_match_the_app() {
    use envv_cli::authreq::{curl_for, header_for, query_for, shell_quote, url_for};

    let doc: Value = serde_json::from_str(&golden("auth-request.json")).expect("fixture parses");

    for c in doc["cases"].as_array().expect("cases") {
        let why = c["why"].as_str().unwrap_or("");
        let e = &c["entry"];

        let got = header_for(e).map(|(n, v)| serde_json::json!([n, v]));
        assert_eq!(got.unwrap_or(Value::Null), c["header"], "header: {why}");
        assert_eq!(
            query_for(e).map(Value::String).unwrap_or(Value::Null),
            c["query"],
            "query: {why}"
        );
        let url_in = c["url_in"].as_str().unwrap_or("");
        if !url_in.is_empty() {
            assert_eq!(
                url_for(e, url_in),
                c["url_out"].as_str().unwrap(),
                "url: {why}"
            );
        }
        let target = if url_in.is_empty() {
            None
        } else {
            Some(url_in)
        };
        assert_eq!(
            curl_for(e, target),
            c["curl"].as_str().unwrap(),
            "curl: {why}"
        );
    }

    for c in doc["shell_quote"].as_array().expect("shell_quote") {
        assert_eq!(
            shell_quote(c["value"].as_str().unwrap()),
            c["expect"].as_str().unwrap(),
            "{}",
            c["why"].as_str().unwrap_or("")
        );
    }
}

/// Session cookies — Phase 23, step 5. An eighth twin pair.
///
/// The form splits a pasted `document.cookie` as it is typed, so an IPC round
/// trip per keystroke is not an option — the same reason the TOTP seed parser
/// exists twice.
#[test]
fn cookie_parsing_matches_the_app() {
    use envv_cli::cookies::*;

    let doc: Value = serde_json::from_str(&golden("cookies.json")).expect("fixture parses");

    fn norm(c: &Cookie) -> Value {
        serde_json::json!({
            "name": c.name,
            "value": c.value,
            "domain": c.domain.clone().map(Value::String).unwrap_or(Value::Null),
            "path": c.path.clone().map(Value::String).unwrap_or(Value::Null),
            "secure": c.secure,
            "http_only": c.http_only,
            "expires": c.expires,
        })
    }
    fn expected(list: &Value) -> Vec<Value> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name": e["name"],
                    "value": e["value"],
                    "domain": e.get("domain").cloned().unwrap_or(Value::Null),
                    "path": e.get("path").cloned().unwrap_or(Value::Null),
                    "secure": e.get("secure").and_then(|v| v.as_bool()).unwrap_or(false),
                    "http_only": e.get("http_only").and_then(|v| v.as_bool()).unwrap_or(false),
                    "expires": e.get("expires").and_then(|v| v.as_i64()).unwrap_or(0),
                })
            })
            .collect()
    }
    fn from_fixture(list: &Value) -> Vec<Cookie> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|e| Cookie {
                name: e["name"].as_str().unwrap_or("").to_string(),
                value: e["value"].as_str().unwrap_or("").to_string(),
                domain: e.get("domain").and_then(|v| v.as_str()).map(str::to_string),
                path: e.get("path").and_then(|v| v.as_str()).map(str::to_string),
                secure: e.get("secure").and_then(|v| v.as_bool()).unwrap_or(false),
                http_only: e
                    .get("http_only")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                expires: e.get("expires").and_then(|v| v.as_i64()).unwrap_or(0),
            })
            .collect()
    }

    for (key, parse) in [
        (
            "parse_header",
            parse_cookie_header as fn(&str) -> Vec<Cookie>,
        ),
        ("parse_txt", parse_cookies_txt),
        ("parse_json", parse_cookie_json),
    ] {
        for c in doc[key].as_array().expect("cases") {
            let got: Vec<Value> = parse(c["raw"].as_str().unwrap()).iter().map(norm).collect();
            assert_eq!(
                got,
                expected(&c["expect"]),
                "{}",
                c["why"].as_str().unwrap_or("")
            );
        }
    }

    for c in doc["to_header"].as_array().expect("to_header") {
        assert_eq!(
            to_cookie_header(&from_fixture(&c["cookies"])),
            c["expect"].as_str().unwrap(),
            "{}",
            c["why"].as_str().unwrap_or("")
        );
    }
    for c in doc["to_txt"].as_array().expect("to_txt") {
        assert_eq!(
            to_cookies_txt(&from_fixture(&c["cookies"])).expect("writable"),
            c["expect"].as_str().unwrap(),
            "{}",
            c["why"].as_str().unwrap_or("")
        );
    }
    for c in doc["to_txt_refused"].as_array().expect("to_txt_refused") {
        let jar = from_fixture(&c["cookies"]);
        let missing: Vec<String> = c["missing"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            missing_txt_attributes(&jar),
            missing,
            "{}",
            c["why"].as_str().unwrap_or("")
        );
        assert!(
            to_cookies_txt(&jar).is_err(),
            "{}",
            c["why"].as_str().unwrap_or("")
        );
    }
}
