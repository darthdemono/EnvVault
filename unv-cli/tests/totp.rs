//! Stored third-party TOTP seeds — the Rust half of the parser's parity, plus
//! the redaction guarantees the seed depends on (Phase 22).
//!
//! Cases live in `tests/fixtures/parity/totp-seeds.json` at the repository root,
//! and `tests/totp.test.ts` asserts the TypeScript parser against the identical
//! file. Reviewing two parsers for agreement does not work; the fixture is what
//! turns a divergence into a test failure instead of a URI that means one thing
//! in the app and another in the CLI.
//!
//! Code generation is deliberately **not** duplicated — there is one HMAC in
//! this project and `vault-core/src/totp.rs` owns it, with the RFC 6238 vectors
//! beside it. Nothing here re-derives a code.

use serde_json::{json, Value};
use unv_cli::out;
use vault_core::totp::{self, Params, Stored};

fn table() -> Value {
    // CARGO_MANIFEST_DIR is unv-cli/; the fixture is shared with the frontend
    // suite and lives at the workspace root.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("unv-cli has a parent directory")
        .join("tests/fixtures/parity/totp-seeds.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("fixture is valid JSON")
}

#[test]
fn parse_matches_the_golden_table() {
    let t = table();
    let cases = t["parse"].as_array().expect("parse cases");
    assert!(!cases.is_empty(), "fixture has no parse cases");

    for c in cases {
        let input = c["in"].as_str().expect("case has a string input");
        let got = totp::parse_seed(input);

        if c["out"].is_null() {
            assert!(
                got.is_err(),
                "{input:?} must be refused, got {got:?} — the TypeScript twin \
                 throws for this case"
            );
            continue;
        }

        let want = &c["out"];
        let stored = got.unwrap_or_else(|e| panic!("{input:?} should parse, got error {e}"));
        assert_eq!(
            stored.secret,
            want["secret"].as_str().expect("secret"),
            "secret for {input:?}"
        );
        assert_eq!(
            stored.params.algorithm.as_str(),
            want["algorithm"].as_str().expect("algorithm"),
            "algorithm for {input:?}"
        );
        assert_eq!(
            u64::from(stored.params.digits),
            want["digits"].as_u64().expect("digits"),
            "digits for {input:?}"
        );
        assert_eq!(
            stored.params.period,
            want["period"].as_u64().expect("period"),
            "period for {input:?}"
        );
        assert_eq!(
            stored.params.kind.as_str(),
            want["kind"].as_str().expect("kind"),
            "kind for {input:?}"
        );
        assert_eq!(
            stored.params.counter,
            want["counter"].as_u64().expect("counter"),
            "counter for {input:?}"
        );
        assert_eq!(
            stored.issuer.as_deref(),
            want["issuer"].as_str(),
            "issuer for {input:?}"
        );
        assert_eq!(
            stored.account.as_deref(),
            want["account"].as_str(),
            "account for {input:?}"
        );
    }
}

#[test]
fn uri_matches_the_golden_table() {
    let t = table();
    for c in t["uri"].as_array().expect("uri cases") {
        let st = &c["stored"];
        let stored = Stored {
            secret: st["secret"].as_str().expect("secret").to_string(),
            params: Params::from_fields(
                st.get("kind").and_then(|v| v.as_str()),
                st["algorithm"].as_str(),
                st["digits"].as_u64(),
                st["period"].as_u64(),
                st.get("counter").and_then(|v| v.as_u64()),
            ),
            issuer: None,
            account: None,
        };
        assert_eq!(
            stored.to_uri(
                c["issuer_fallback"].as_str().expect("issuer fallback"),
                c["account_fallback"].as_str().expect("account fallback"),
            ),
            c["out"].as_str().expect("expected uri"),
        );
    }
}

#[test]
fn every_uri_the_builder_writes_parses_back_to_the_same_seed() {
    // The exported URI is what a user scans into a replacement phone. One that
    // does not read back is a lockout discovered at the worst possible moment.
    let t = table();
    for c in t["uri"].as_array().expect("uri cases") {
        let uri = c["out"].as_str().expect("expected uri");
        let back = totp::parse_seed(uri).unwrap_or_else(|e| panic!("{uri} must parse back: {e}"));
        let st = &c["stored"];
        assert_eq!(back.secret, st["secret"].as_str().expect("secret"));
        assert_eq!(
            back.params.algorithm.as_str(),
            st["algorithm"].as_str().expect("algorithm")
        );
        assert_eq!(
            u64::from(back.params.digits),
            st["digits"].as_u64().unwrap()
        );
        assert_eq!(back.params.period, st["period"].as_u64().unwrap());
    }
}

// ── Redaction (Phase 14's rule, applied to the seed) ─────────────────────────

fn entry_with_seed() -> Value {
    json!({
        "id": "e1", "provider": "GitHub", "api_key": "ghp_live_secret_value",
        "totp_secret": "JBSWY3DPEHPK3PXP", "totp_algorithm": "SHA256",
        "price_type": "free", "secretType": "api_key",
        "categories": [], "projectIds": ["Universal"], "scopes": []
    })
}

#[test]
fn the_stored_seed_is_masked_in_agent_output() {
    // A seed grants a login by itself and, unlike an API key, nothing about it
    // expires. It is in SECRET_FIELDS for the same reason api_key is, and this
    // test fails the moment somebody takes it out.
    let redacted = out::redact_entry(&entry_with_seed());
    let seed = &redacted["totp_secret"];
    assert_eq!(
        seed["redacted"],
        json!(true),
        "the seed must not appear in stdout: {redacted}"
    );
    assert!(
        !serde_json::to_string(&redacted)
            .unwrap()
            .contains("JBSWY3DPEHPK3PXP"),
        "no part of the redacted entry may carry the seed: {redacted}"
    );
    // The parameters are not secret and stay readable — they are how a caller
    // tells two seeds apart without holding either.
    assert_eq!(redacted["totp_algorithm"], json!("SHA256"));
}

#[test]
fn the_seeds_fingerprint_is_stable_and_carries_none_of_it() {
    // Same guarantee the other secrets have: equal fingerprints mean equal
    // seeds, so a caller can spot a duplicate or a drift without reading one.
    let a = out::redact_entry(&entry_with_seed());
    let b = out::redact_entry(&entry_with_seed());
    let fp = a["totp_secret"]["fingerprint"]
        .as_str()
        .expect("fingerprint");
    assert_eq!(fp, b["totp_secret"]["fingerprint"].as_str().unwrap());
    assert!(fp.starts_with("sha256:"), "{fp}");
    assert!(!fp.contains("JBSWY3DP"), "{fp}");

    let mut other = entry_with_seed();
    other["totp_secret"] = json!("MZXW6YTBOI");
    assert_ne!(
        fp,
        out::redact_entry(&other)["totp_secret"]["fingerprint"]
            .as_str()
            .unwrap(),
        "two different seeds must not fingerprint alike"
    );
}

/// The third parity table: what an entry's four stored fields *mean*.
///
/// These were read three different ways in Rust alone before
/// [`Params::from_fields`] existed — `unv totp code` clamped out-of-range
/// values, `unv totp ls` printed them raw, and the desktop app's
/// `entry_totp_code` did neither and answered an out-of-range `digits` with an
/// error where the CLI answered with a code. One entry, three answers, none of
/// them reported. `tests/totp.test.ts` asserts `totpParamsOf` against this same
/// file.
#[test]
fn params_from_fields_matches_the_golden_table() {
    let t = table();
    let cases = t["params"].as_array().expect("params cases");
    assert!(!cases.is_empty(), "fixture has no params cases");

    for c in cases {
        let e = &c["entry"];
        let got = Params::from_fields(
            e.get("totp_kind").and_then(|v| v.as_str()),
            e.get("totp_algorithm").and_then(|v| v.as_str()),
            e.get("totp_digits").and_then(|v| v.as_u64()),
            e.get("totp_period").and_then(|v| v.as_u64()),
            e.get("totp_counter").and_then(|v| v.as_u64()),
        );
        let want = &c["out"];
        assert_eq!(
            got.algorithm.as_str(),
            want["algorithm"].as_str().expect("algorithm"),
            "algorithm for {e}"
        );
        assert_eq!(
            u64::from(got.digits),
            want["digits"].as_u64().expect("digits"),
            "digits for {e}"
        );
        assert_eq!(
            got.period,
            want["period"].as_u64().expect("period"),
            "period for {e}"
        );
        assert_eq!(
            got.kind.as_str(),
            want["kind"].as_str().expect("kind"),
            "kind for {e}"
        );
        assert_eq!(
            got.counter,
            want["counter"].as_u64().expect("counter"),
            "counter for {e}"
        );
        // Whatever it read, it must be usable: the point of falling back rather
        // than refusing is that a card never goes permanently blank over one
        // mistyped number.
        got.validate()
            .unwrap_or_else(|e| panic!("from_fields produced unusable params: {e}"));
    }
}

/// `unv get X --field totp_secret` must mask, exactly as `--field api_key` does.
///
/// It did not. There were two lists of "which fields hold secret material" —
/// `out::SECRET_FIELDS`, used when a whole entry is printed, and a second copy
/// in `entries.rs` used by the single-field path and by `pool next --field`.
/// Phase 22 added `totp_secret` to the first and not the second, so the same
/// seed masked in `unv get GitHub` and printed in clear in
/// `unv get GitHub --field totp_secret`, which is the form an agent or a script
/// reaches for. The second list is gone; this pins the property rather than the
/// list, so re-introducing a copy fails here too.
#[test]
fn every_secret_field_is_recognised_through_the_name_the_cli_takes() {
    assert!(
        out::SECRET_FIELDS.contains(&"totp_secret"),
        "a stored authenticator seed grants a login on its own and nothing about \
         it expires — it is secret material"
    );
    for field in out::SECRET_FIELDS {
        // The single-field path tests `SECRET_FIELDS.contains(canonical_field(f))`,
        // so a canonical form absent from the list is a value that prints in
        // clear while the same value inside a whole-entry dump is masked.
        let canonical = unv_cli::refs::canonical_field(field);
        assert!(
            out::SECRET_FIELDS.contains(&canonical),
            "--field {field} canonicalises to {canonical}, which is not treated \
             as secret"
        );
    }
}

/// The masking a `--field` read applies carries none of the value it describes.
#[test]
fn a_masked_seed_reveals_nothing_about_the_seed() {
    let seed = "JBSWY3DPEHPK3PXP";
    let masked = out::masked(seed);
    assert!(masked.starts_with("sha256:"), "got {masked}");
    assert!(!masked.contains(seed));
    assert!(!masked.to_uppercase().contains(&seed[..8]));
    // Stable per value: equal fingerprints mean equal seeds, which is what makes
    // a redacted `totp ls` useful for spotting a duplicate enrollment.
    assert_eq!(masked, out::masked(seed));
    assert_ne!(masked, out::masked("GEZDGNBVGY3TQOJQ"));
}
