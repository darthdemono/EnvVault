//! OAuth refresh-token grants, shared by `envv oauth refresh` and the desktop
//! app's "Refresh access token" (Phase 24.5). Pure over JSON: the HTTP call is
//! the caller's (the CLI's blocking client, the app's pinned `remote_request`),
//! so there is exactly one reading of what an issuer's answer means and one rule
//! for what gets stored.

use crate::type_emit::var;
use serde_json::{json, Value};

pub fn set_var(entry: &mut Value, key: &str, value: &str, secret: bool) {
    let vars = entry
        .as_object_mut()
        .expect("entry is an object")
        .entry("extra_vars")
        .or_insert_with(|| json!([]));
    let vars = vars.as_array_mut().expect("extra_vars is an array");
    match vars
        .iter_mut()
        .find(|v| v.get("key").and_then(Value::as_str) == Some(key))
    {
        Some(slot) => slot["value"] = json!(value),
        None => vars.push(json!({ "key": key, "value": value, "secret": secret })),
    }
}

/// The request an `oauth_client` entry makes to refresh itself: the `token_url`
/// and the form fields. Refuses plain http except to localhost, and an entry with
/// no refresh token, before anything is sent.
pub fn refresh_request(entry: &Value) -> Result<(String, Vec<(String, String)>), String> {
    let url = var(entry, "token_url").to_string();
    if !(url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost"))
    {
        return Err("token_url must be https:// (plain http is allowed for localhost only)".into());
    }
    let refresh = var(entry, "refresh_token");
    if refresh.is_empty() {
        return Err("the entry holds no refresh_token".into());
    }
    let mut form = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("refresh_token".to_string(), refresh.to_string()),
        ("client_id".to_string(), var(entry, "client_id").to_string()),
    ];
    for (field, name) in [("client_secret", "client_secret"), ("scopes", "scope")] {
        let v = var(entry, field);
        if !v.is_empty() {
            form.push((name.to_string(), v.to_string()));
        }
    }
    Ok((url, form))
}

/// The host a refresh would contact, for the confirmation prompt.
pub fn refresh_host(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .and_then(|r| r.split('/').next())
        .unwrap_or("")
}

/// What the token endpoint said, reduced to what is stored.
#[derive(Debug, PartialEq)]
pub struct Grant {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
}

pub fn parse_grant(body: &Value) -> Result<Grant, String> {
    if let Some(err) = body.get("error").and_then(Value::as_str) {
        // Names the issuer's error code, never echoes the response body.
        return Err(format!("the issuer refused the refresh: {err}"));
    }
    let access = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("the response has no access_token")?;
    Ok(Grant {
        access_token: access.to_string(),
        refresh_token: body
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from),
        expires_in: body.get("expires_in").and_then(Value::as_i64),
    })
}

/// Stores a grant on the entry. Returns whether the refresh token rotated.
pub fn apply_grant(entry: &mut Value, g: &Grant, now_unix: i64) -> bool {
    let rotated = g
        .refresh_token
        .as_deref()
        .is_some_and(|r| r != var(entry, "refresh_token"));
    if let Some(r) = &g.refresh_token {
        set_var(entry, "refresh_token", r, true);
    }
    set_var(entry, "access_token", &g.access_token, true);
    if let Some(secs) = g.expires_in {
        let at = crate::pool::iso_at(now_unix + secs);
        set_var(entry, "access_expires_at", &at, false);
    }
    rotated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_emit::var;

    fn entry() -> Value {
        json!({"secretType":"oauth_client","provider":"Slack","extra_vars":[
            {"key":"refresh_token","value":"old-r","secret":true}]})
    }

    #[test]
    fn a_rotated_refresh_token_replaces_the_old_one_and_is_reported() {
        let g =
            parse_grant(&json!({"access_token":"a1","refresh_token":"new-r","expires_in":3600}))
                .unwrap();
        let mut e = entry();
        assert!(apply_grant(&mut e, &g, 1_700_000_000));
        assert_eq!(var(&e, "refresh_token"), "new-r");
        assert_eq!(var(&e, "access_token"), "a1");
        assert_eq!(var(&e, "access_expires_at"), "2023-11-14T23:13:20Z");
    }

    #[test]
    fn an_unrotated_response_keeps_the_stored_refresh_token() {
        let g = parse_grant(&json!({"access_token":"a2"})).unwrap();
        let mut e = entry();
        assert!(!apply_grant(&mut e, &g, 0));
        assert_eq!(var(&e, "refresh_token"), "old-r");
        assert_eq!(var(&e, "access_expires_at"), "");
    }

    #[test]
    fn issuer_errors_are_named_without_echoing_the_body() {
        let err = parse_grant(
            &json!({"error":"invalid_grant","error_description":"secret-bearing text"}),
        )
        .unwrap_err();
        assert!(err.contains("invalid_grant") && !err.contains("secret-bearing"));
        assert!(parse_grant(&json!({})).is_err());
    }
}
