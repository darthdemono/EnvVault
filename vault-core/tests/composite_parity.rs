//! The Rust half of composite-secret rendering's parity, pinned against
//! `tests/fixtures/parity/composite.json` (repository root) — identical
//! cases are asserted from `tests/composite.test.ts` on the TypeScript side.
//! Reviewing two renderers for agreement does not work; the fixture is what
//! turns a divergence into a test failure.

use serde_json::Value;
use vault_core::composite::{render, Kind, Part};

fn table() -> Value {
    // CARGO_MANIFEST_DIR is vault-core/; the fixture is shared with the
    // frontend suite and lives at the workspace root.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vault-core has a parent directory")
        .join("tests/fixtures/parity/composite.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("fixture is valid JSON")
}

#[test]
fn render_matches_the_golden_table() {
    let t = table();
    let cases = t["render"].as_array().expect("render cases");
    assert!(!cases.is_empty(), "fixture has no render cases");

    for c in cases {
        let why = c["_why"].as_str().unwrap_or("(no _why)");
        let template = c["template"].as_str().expect("case has a template");
        let kind = Kind::parse(c["kind"].as_str().expect("case has a kind"));
        let parts: Vec<Part> = c["parts"]
            .as_object()
            .expect("case has a parts object")
            .iter()
            .map(|(k, v)| Part {
                key: k.clone(),
                value: v.as_str().expect("part value is a string").to_string(),
            })
            .collect();

        let got = render(template, &parts, kind);

        if let Some(out) = c.get("out") {
            let r = got.unwrap_or_else(|e| panic!("{why}: expected Ok, got Err({e})"));
            assert_eq!(r.text, out["text"].as_str().unwrap(), "{why}: text");
            let used: Vec<String> = out["used"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            assert_eq!(r.used, used, "{why}: used");
            let unused: Vec<String> = out["unused"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            assert_eq!(r.unused, unused, "{why}: unused");
        } else {
            let err = got
                .err()
                .unwrap_or_else(|| panic!("{why}: expected Err, got Ok"));
            let expected_kind = c["error"]["kind"]
                .as_str()
                .expect("error case names a kind");
            match (&err, expected_kind) {
                (
                    vault_core::composite::RenderError::UnfilledPlaceholder(name),
                    "unfilled_placeholder",
                ) => {
                    assert_eq!(name, c["error"]["name"].as_str().unwrap(), "{why}: name");
                }
                (vault_core::composite::RenderError::UnbalancedBrace(at), "unbalanced_brace") => {
                    assert_eq!(*at as u64, c["error"]["at"].as_u64().unwrap(), "{why}: at");
                }
                (
                    vault_core::composite::RenderError::ControlCharacterInPart(name),
                    "control_character_in_part",
                ) => {
                    assert_eq!(name, c["error"]["name"].as_str().unwrap(), "{why}: name");
                }
                _ => panic!("{why}: got {err:?}, fixture expected kind \"{expected_kind}\""),
            }
        }
    }
}
