//! The Rust half of the rate-limit parser's cross-implementation parity.
//!
//! Cases live in `tests/fixtures/parity/rate-limit.json` at the repository
//! root, and `tests/ratelimit.test.ts` asserts the TypeScript parser against
//! the identical file. Reviewing two parsers for agreement does not work; the
//! fixture is what makes a divergence a test failure instead of a subtly
//! different answer in the CLI and the app.

use envv_cli::ratelimit::{self, Period};
use serde_json::{json, Value};

fn table() -> Value {
    // CARGO_MANIFEST_DIR is envv-cli/; the fixture is shared with the frontend
    // suite and lives at the workspace root.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("envv-cli has a parent directory")
        .join("tests/fixtures/parity/rate-limit.json");
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
        let got = ratelimit::parse(input);

        if c["out"].is_null() {
            assert!(
                got.is_none(),
                "{input:?} should not parse, got {got:?} — the TypeScript twin \
                 returns null for this case"
            );
            continue;
        }

        let want_count = c["out"]["count"].as_u64().expect("count");
        let want_period = c["out"]["period"].as_str().expect("period");
        let (count, period) =
            got.unwrap_or_else(|| panic!("{input:?} should parse to {want_count}/{want_period}"));
        assert_eq!(count, want_count, "count for {input:?}");
        assert_eq!(period.as_str(), want_period, "period for {input:?}");
    }
}

#[test]
fn format_matches_the_golden_table() {
    let t = table();
    for c in t["format"].as_array().expect("format cases") {
        let count = c["count"].as_u64().expect("count");
        let period = Period::from_canonical(c["period"].as_str().expect("period"))
            .expect("fixture names a real period");
        assert_eq!(
            ratelimit::format(Some(count), Some(period)),
            c["out"].as_str().expect("expected output")
        );
    }
}

#[test]
fn everything_format_writes_parse_reads_back() {
    // A format that cannot read its own output is how the legacy string and the
    // structured pair drift apart across a save.
    for p in Period::ALL {
        let text = ratelimit::format(Some(42), Some(p));
        assert_eq!(
            ratelimit::parse(&text),
            Some((42, p)),
            "{text} must round-trip"
        );
    }
}

#[test]
fn format_needs_both_halves() {
    // A count with no period is a number, not a rate limit. Emitting "100/"
    // would produce a legacy string that parses back to None.
    assert_eq!(ratelimit::format(Some(100), None), "");
    assert_eq!(ratelimit::format(None, Some(Period::Hour)), "");
    assert_eq!(ratelimit::format(None, None), "");
}

#[test]
fn normalize_migrates_a_legacy_string() {
    let n = ratelimit::normalize(&json!({ "rate_limit": "100/min" }));
    assert_eq!(n.count, Some(100));
    assert_eq!(n.period, Some(Period::Minute));
    assert_eq!(n.legacy.as_deref(), Some("100/minute"));
}

#[test]
fn normalize_keeps_text_it_cannot_parse() {
    // Regression: the first version discarded anything unparseable, so an entry
    // saying "varies by endpoint" lost the only description of its limit on the
    // next save.
    let n = ratelimit::normalize(&json!({ "rate_limit": "varies by endpoint" }));
    assert_eq!(n.count, None);
    assert_eq!(n.legacy.as_deref(), Some("varies by endpoint"));
    assert_eq!(n.note.as_deref(), Some("varies by endpoint"));
}

#[test]
fn structured_wins_over_a_stale_legacy_string() {
    // Regression: precedence the other way round meant a number set by
    // `entry set --rate-limit-count` was reverted on the next read.
    let n = ratelimit::normalize(&json!({
        "rate_limit": "100/min",
        "rate_limit_count": 5000,
        "rate_limit_period": "hour",
    }));
    assert_eq!(n.count, Some(5000));
    assert_eq!(n.period, Some(Period::Hour));
    assert_eq!(n.legacy.as_deref(), Some("5000/hour"));
}

#[test]
fn a_parseable_limit_clears_a_stale_note() {
    // Regression: the note is derived from unparseable text, but it used to be
    // carried forward unconditionally. Setting `--rate-limit "100 req/min"` on
    // an entry that previously said "varies by endpoint" left BOTH — the card
    // showed "100/minute" with a note beside it flatly contradicting it.
    let n = ratelimit::normalize(&json!({
        "rate_limit": "100 req/min",
        "rate_limit_note": "varies by endpoint",
    }));
    assert_eq!(n.count, Some(100));
    assert_eq!(
        n.note, None,
        "a readable limit leaves the note nothing to say"
    );

    // Same when the structured pair is what wins.
    let n = ratelimit::normalize(&json!({
        "rate_limit_count": 60,
        "rate_limit_period": "minute",
        "rate_limit_note": "varies by endpoint",
    }));
    assert_eq!(n.note, None);
}

#[test]
fn half_a_limit_is_no_limit() {
    assert_eq!(
        ratelimit::normalize(&json!({ "rate_limit_count": 100 })).count,
        None
    );
    assert_eq!(
        ratelimit::normalize(&json!({ "rate_limit_period": "hour" })).period,
        None
    );
}

#[test]
fn a_period_outside_the_enum_is_refused() {
    // Vault JSON is untrusted input: a remote server or an imported backup can
    // put anything in this field.
    let n = ratelimit::normalize(&json!({
        "rate_limit_count": 10,
        "rate_limit_period": "fortnight",
    }));
    assert_eq!(n.count, None);
    assert_eq!(n.period, None);
}

#[test]
fn apply_removes_absent_fields_instead_of_writing_null() {
    // `entry set --rate-limit ""` must leave an entry indistinguishable from one
    // that never had a limit, or the health scan and the UI each have to
    // special-case a null they cannot tell from an absent field.
    let mut e = json!({
        "provider": "X",
        "rate_limit": "100/min",
        "rate_limit_count": 100,
        "rate_limit_period": "minute",
        "rate_limit_note": "old",
    });
    ratelimit::apply(&mut e, &ratelimit::Normalized::default());
    let obj = e.as_object().unwrap();
    for k in [
        "rate_limit",
        "rate_limit_count",
        "rate_limit_period",
        "rate_limit_note",
    ] {
        assert!(
            !obj.contains_key(k),
            "{k} should have been removed, not nulled"
        );
    }
    assert_eq!(obj.get("provider").and_then(Value::as_str), Some("X"));
}
