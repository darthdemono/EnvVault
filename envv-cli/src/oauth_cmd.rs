//! `envv oauth refresh` — Phase 24.5. Exchanges an `oauth_client` entry's refresh
//! token for a new access token at the issuer's `token_url`.
//!
//! **This is an online act, opt-in and named as such**: it sends the refresh
//! token and client secret to the entry's own `token_url`, the same trade as
//! `enrich --online` (a credential goes only to its issuer). It confirms first.
//!
//! **Order is the whole design.** Some issuers (Slack's `xoxe`, GitHub Apps'
//! `ghr_`) *rotate* the refresh token: the moment the response is sent, the old
//! one is dead. So the new refresh token is written to the vault **before** the
//! access token is shown or used. If that write fails, the new token is dumped
//! to a `0600` recovery file and the command says where, because a crash between
//! "issuer rotated it" and "we stored it" is a permanent lockout.

use crate::access::Access;
use crate::data::{self, entries_mut, find_entry_index};
use crate::error::{CliError, CliResult};
use crate::fmt::confirm;
use crate::out;
use serde_json::{json, Value};
use vault_core::oauth::{apply_grant, parse_grant};

pub fn refresh(access: &Access, query: &str, yes: bool) -> CliResult {
    let mut vault = access.load_vault()?;
    let idx = find_entry_index(&vault, query)?;
    let entry = data::entries(&vault)[idx].clone();
    if data::secret_type_of(&entry) != "oauth_client" {
        return Err(CliError::invalid(format!(
            "'{query}' is not an oauth_client entry"
        )));
    }
    let (token_url, form) =
        vault_core::oauth::refresh_request(&entry).map_err(CliError::invalid)?;
    let host = vault_core::oauth::refresh_host(&token_url);
    if !confirm(
        &format!("Send this entry's refresh token and client secret to {host}?"),
        yes,
    )? {
        println!("Cancelled.");
        return Ok(());
    }

    let resp = crate::tls::build_issuer_client(std::time::Duration::from_secs(20))?
        .post(&token_url)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .map_err(|e| {
            CliError::unavailable(format!("could not reach {host}: {}", e.without_url()))
        })?;
    let status = resp.status();
    let body: Value = resp.json().unwrap_or(Value::Null);
    if !status.is_success() && body.get("error").is_none() {
        return Err(CliError::denied(format!("{host} answered HTTP {status}")));
    }
    let grant = parse_grant(&body).map_err(CliError::denied)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let rotated = apply_grant(&mut entries_mut(&mut vault)[idx], &grant, now);

    // Store first. Only after the vault holds the new refresh token is the
    // access token reported.
    if let Err(e) = access.save(&vault) {
        if let Some(r) = grant.refresh_token.as_deref().filter(|_| rotated) {
            let dir = std::env::temp_dir();
            let path = dir.join(format!(
                "envv-oauth-recovery-{}.json",
                vault_core::new_uuid()
            ));
            let wrote = std::fs::write(
                &path,
                json!({ "entry": query, "refresh_token": r }).to_string(),
            )
            .and_then(|()| vault_core::restrict_to_owner(&path).map_err(std::io::Error::other));
            return Err(CliError::from(match wrote {
                Ok(()) => format!(
                    "The issuer ROTATED the refresh token but the vault write failed ({e}). \
                     The new token is in {} (0600). Put it back into the entry, then delete the file.",
                    path.display()
                ),
                Err(_) => format!(
                    "The issuer rotated the refresh token and neither the vault nor a recovery file \
                     could be written ({e}). Re-authorise the app at the issuer."
                ),
            }));
        }
        return Err(e);
    }
    out::ok(
        "oauth.refresh",
        json!({
            "entry": query, "rotated_refresh_token": rotated,
            "expires_in": grant.expires_in,
            "access_token": out::masked_json(&grant.access_token),
        }),
        || {
            println!(
                "Refreshed '{query}'{}; access token stored{}",
                if rotated {
                    " (refresh token rotated and stored first)"
                } else {
                    ""
                },
                grant
                    .expires_in
                    .map_or(String::new(), |s| format!(", valid {s}s"))
            )
        },
    );
    Ok(())
}
