//! Importing from Bitwarden, 1Password and Proton Pass.
//!
//! The fixtures are deliberately awkward: each carries at least one item the
//! importer must *skip* and say so, because "0 skipped" on an export containing
//! credit cards would mean the reader had quietly mangled them.

use serde_json::Value;
use unv_cli::import_vaults::{read_bitwarden, read_onepassword, read_proton, Incoming};

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

// ── Nextcloud config.php ─────────────────────────────────────────────────────

fn nextcloud(name: &str) -> (Value, Vec<String>) {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    unv_cli::import_vaults::source_value("nextcloud", &std::fs::read_to_string(p).unwrap())
        .expect("parse")
}

#[test]
fn a_real_sqlite_nextcloud_yields_its_two_instance_secrets_and_nothing_else() {
    // Written by a Nextcloud 29 container's installer, not by hand.
    let (doc, warnings) = nextcloud("nextcloud-config.php");
    assert!(warnings.is_empty(), "{warnings:?}");
    let (items, skipped) = unv_cli::import_vaults::read_nextcloud(&doc);
    assert_eq!(skipped, 0);
    let names: Vec<&str> = items.iter().map(|i| i.provider.as_str()).collect();
    assert_eq!(
        names,
        [
            "Nextcloud passwordsalt (oc8u6g4icnd8)",
            "Nextcloud secret (oc8u6g4icnd8)"
        ]
    );
    assert!(items.iter().all(|i| i.secret_type == "password"));
}

#[test]
fn a_full_nextcloud_config_yields_database_smtp_redis_and_object_store_secrets() {
    let (doc, warnings) = nextcloud("nextcloud-full.php");
    assert_eq!(
        warnings.len(),
        1,
        "the getenv() licence key is reported: {warnings:?}"
    );
    let (items, skipped) = unv_cli::import_vaults::read_nextcloud(&doc);
    assert_eq!(skipped, 1, "and counted as skipped");
    let db = by_name(&items, "Nextcloud database (ocabc123)");
    assert_eq!(db.username.as_deref(), Some("nc"));
    assert_eq!(db.secret, "EXAMPLE_DB_cccccccccccc");
    assert_eq!(db.notes.as_deref(), Some("mysql at db:3306 / nextcloud"));
    assert_eq!(
        by_name(&items, "Nextcloud SMTP (ocabc123)")
            .username
            .as_deref(),
        Some("mailer@example.com")
    );
    assert_eq!(
        by_name(&items, "Nextcloud Redis (ocabc123)").secret,
        "EXAMPLE_REDIS_eeeeeeeeeeee"
    );
    let s3 = by_name(&items, "Nextcloud object store (ocabc123)");
    assert_eq!(s3.username.as_deref(), Some("EXAMPLE_S3KEY"));
    assert_eq!(s3.secret_type, "api_key");
    assert_eq!(s3.notes.as_deref(), Some("bucket nc-data"));
    assert_eq!(s3.url.as_deref(), Some("https://cloud.example.com"));
    assert_eq!(items.len(), 6);
}

#[test]
fn importing_a_nextcloud_config_twice_changes_nothing_the_second_time() {
    use unv_cli::import_vaults::{plan_import, ImportOpts};
    let (doc, _) = nextcloud("nextcloud-full.php");
    let opts = ImportOpts {
        apply: false,
        project: None,
        category: None,
        keep_folders: true,
    };
    let vault = serde_json::json!({ "api_keys": [], "projects": [], "user_categories": [] });
    let first = plan_import(&vault, "nextcloud", &doc, &opts).unwrap();
    assert_eq!(first.created, 6);
    let mut after = vault.clone();
    after["api_keys"] = serde_json::json!(first.entries);
    let second = plan_import(&after, "nextcloud", &doc, &opts).unwrap();
    assert_eq!(
        (second.created, second.updated, second.unchanged),
        (0, 0, 6)
    );
    // The preview is fingerprints only.
    assert!(!serde_json::to_string(&first.preview)
        .unwrap()
        .contains("EXAMPLE_DB"));
}

// ── TOTP seeds land in `totp_secret`, not in notes (roadmap R01) ─────────────

fn plan(vendor: &str, fixture: &str) -> Vec<Value> {
    use unv_cli::import_vaults::{plan_import, ImportOpts};
    let opts = ImportOpts {
        apply: false,
        project: None,
        category: None,
        keep_folders: false,
    };
    let vault = serde_json::json!({ "api_keys": [], "projects": [], "user_categories": [] });
    plan_import(&vault, vendor, &load(fixture), &opts)
        .expect("plan")
        .entries
}

fn entry<'a>(entries: &'a [Value], provider: &str) -> &'a Value {
    entries
        .iter()
        .find(|e| e["provider"] == provider)
        .unwrap_or_else(|| panic!("no entry {provider}"))
}

#[test]
fn bitwarden_totp_becomes_a_seed_and_the_notes_stay_as_exported() {
    let entries = plan("bitwarden", "bitwarden.json");
    let gh = entry(&entries, "GitHub");
    assert_eq!(gh["totp_secret"], "JBSWY3DPEHPK3PXP");
    // Before the fix the seed was appended to the notes as plain text.
    let notes = gh["notes"].as_str().unwrap_or("");
    assert!(!notes.contains("TOTP secret imported"), "{notes}");
    assert!(!notes.contains("JBSWY3DPEHPK3PXP"), "{notes}");
    // An item with no TOTP gets no seed field.
    assert!(entries
        .iter()
        .filter(|e| e["provider"] != "GitHub")
        .any(|e| e.get("totp_secret").is_none()));
}

#[test]
fn onepassword_and_proton_totp_uris_become_seeds() {
    let op = plan("onepassword", "onepassword.json");
    let seeds: Vec<_> = op
        .iter()
        .filter_map(|e| e["totp_secret"].as_str())
        .collect();
    assert!(!seeds.is_empty(), "1Password one-time password was dropped");
    assert!(op.iter().all(|e| !e["notes"]
        .as_str()
        .unwrap_or("")
        .contains("TOTP secret imported")));

    let pr = plan("proton", "proton.json");
    assert!(pr.iter().any(|e| e.get("totp_secret").is_some()));
}

#[test]
fn an_unusable_totp_value_is_kept_in_the_notes_not_lost() {
    use unv_cli::import_vaults::{plan_import, ImportOpts};
    let mut doc = load("bitwarden.json");
    doc["items"][0]["login"]["totp"] = serde_json::json!("not a seed !!");
    let opts = ImportOpts {
        apply: false,
        project: None,
        category: None,
        keep_folders: false,
    };
    let vault = serde_json::json!({ "api_keys": [], "projects": [], "user_categories": [] });
    let out = plan_import(&vault, "bitwarden", &doc, &opts)
        .unwrap()
        .entries;
    let gh = entry(&out, "GitHub");
    assert!(gh.get("totp_secret").is_none());
    assert!(gh["notes"].as_str().unwrap().contains("not a seed !!"));
}
