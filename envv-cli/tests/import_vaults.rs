//! Importing from Bitwarden, 1Password and Proton Pass.
//!
//! The fixtures are deliberately awkward: each carries at least one item the
//! importer must *skip* and say so, because "0 skipped" on an export containing
//! credit cards would mean the reader had quietly mangled them.

use envv_cli::import_vaults::{read_bitwarden, read_onepassword, read_proton, Incoming};
use serde_json::Value;

fn load(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&p).expect("read fixture")).expect("parse")
}

fn by_name<'a>(items: &'a [Incoming], name: &str) -> &'a Incoming {
    items
        .iter()
        .find(|i| i.provider == name)
        .unwrap_or_else(|| panic!("no imported item called {name}"))
}

// ── Bitwarden ────────────────────────────────────────────────────────────────

#[test]
fn bitwarden_logins_notes_and_the_things_it_must_skip() {
    let (items, skipped) = read_bitwarden(&load("bitwarden.json"));

    // A card and a login with no password. Both must be counted, not silently
    // dropped: a user reading "imported 3" of a 5-item export needs to know.
    assert_eq!(skipped, 2, "card and password-less login must be skipped");
    assert_eq!(items.len(), 3);

    let gh = by_name(&items, "GitHub");
    assert_eq!(gh.username.as_deref(), Some("octocat"));
    assert_eq!(gh.url.as_deref(), Some("https://github.com"));
    assert_eq!(
        gh.folder.as_deref(),
        Some("Work"),
        "folder id must resolve to its name"
    );
    assert!(gh.totp.is_some());

    // Type comes from the value's shape, not from the vendor's category.
    assert_eq!(
        by_name(&items, "Postgres prod").secret_type,
        "connection_string"
    );
    assert_eq!(by_name(&items, "Deploy key").secret_type, "ssh_key");
}

#[test]
fn a_bitwarden_secure_note_moves_its_body_into_the_value() {
    // The note *is* the secret. Leaving it in `notes` as well would print it in
    // the entry list, where nothing redacts a notes field.
    let (items, _) = read_bitwarden(&load("bitwarden.json"));
    let key = by_name(&items, "Deploy key");
    assert!(key.secret.contains("OPENSSH PRIVATE KEY"));
    assert!(
        key.notes.is_none(),
        "the secret must not remain in the note"
    );
}

// ── 1Password ────────────────────────────────────────────────────────────────

#[test]
fn onepassword_reads_fields_by_purpose_and_by_label() {
    let (items, skipped) = read_onepassword(&load("onepassword.json"));
    assert_eq!(skipped, 1, "the item with no fields has nothing to import");
    assert_eq!(items.len(), 3);

    let stripe = by_name(&items, "Stripe");
    assert_eq!(stripe.username.as_deref(), Some("billing@example.com"));
    assert_eq!(
        stripe.secret_type, "api_key",
        "sk_live_ is an issuer prefix"
    );
    assert_eq!(stripe.notes.as_deref(), Some("live key, rotate quarterly"));

    // No PASSWORD field at all — the token is found by its label.
    let token = by_name(&items, "API token only");
    assert!(token.secret.starts_with("glpat-"));

    // A field labelled "One-time password" is a TOTP, not the password.
    let graf = by_name(&items, "Grafana");
    assert_eq!(graf.secret, "correct horse battery staple");
    assert!(graf.totp.as_deref().unwrap().starts_with("otpauth://"));
}

// ── Proton Pass ──────────────────────────────────────────────────────────────

#[test]
fn proton_skips_trashed_items_and_unsupported_types() {
    let (items, skipped) = read_proton(&load("proton.json")).expect("plaintext export");
    // A trashed login and a credit card. Importing someone's deleted
    // credentials back into a live vault is the opposite of what they asked for.
    assert_eq!(skipped, 2);
    assert_eq!(items.len(), 2);
    assert!(
        !items.iter().any(|i| i.provider == "Deleted thing"),
        "state 2 is the trash"
    );

    let dobj = by_name(&items, "DigitalOcean");
    // itemUsername is empty, so itemEmail is the identity.
    assert_eq!(dobj.username.as_deref(), Some("ops@example.com"));
    assert_eq!(dobj.folder.as_deref(), Some("Personal"));
    assert_eq!(dobj.secret_type, "api_key");

    assert_eq!(by_name(&items, "Root CA").secret_type, "certificate");
}

#[test]
fn an_encrypted_proton_export_is_refused_rather_than_read_as_empty() {
    // This is the trap: an encrypted export is perfectly valid JSON with no
    // readable items, so a naive reader reports "0 credentials found" for a file
    // that is full of them — and the user concludes their vault was empty.
    let doc: Value = serde_json::json!({ "encrypted": true, "vaults": {} });
    let err = read_proton(&doc).unwrap_err();
    assert!(err.contains("encrypted"), "{err}");
    assert!(
        err.contains("Encrypt export"),
        "the message must say how to fix it: {err}"
    );
}

#[test]
fn something_that_is_not_a_proton_export_says_so() {
    let err = read_proton(&serde_json::json!({ "items": [] })).unwrap_err();
    assert!(err.contains("does not look like"), "{err}");
}
