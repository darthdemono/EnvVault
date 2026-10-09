//! The CLI's TLS policy — set once from the global flags, read by the one
//! function that builds an HTTP client.
//!
//! Before Phase 17 this file did not exist and the CLI called
//! `reqwest::blocking::Client::new()` in three places, which meant two things,
//! both bad. It could not reach a self-signed `unv-server` at all, and it
//! linked a *different* TLS stack from the desktop app: `reqwest`'s default
//! features pull in native-tls, while `src-tauri` has always used rustls. One
//! product, two trust decisions, neither aware of the other.
//!
//! The verifiers live in `vault_core::tls` so the app and the CLI share them.
//! This module is only the policy plumbing: what the user asked for, and the
//! single builder that honours it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

use crate::error::{CliError, CliResult};
use vault_core::tls::{self, TlsPolicy};

/// The policy in force. A `RwLock`, not a `OnceLock`: `--tofu` learns a
/// fingerprint *during* the command and must then pin the very next request with
/// it. A write-once cell silently refuses that second write, and the login goes
/// out under plain CA validation — succeeding against a real certificate and
/// failing against the self-signed server the flag exists for.
static POLICY: RwLock<TlsPolicy> = RwLock::new(TlsPolicy::Ca);

/// Whether the user named a policy on the command line. An explicit flag
/// outranks anything remembered or learned, or the flag would quietly do
/// nothing.
static EXPLICIT: AtomicBool = AtomicBool::new(false);

/// Set the policy from the global flags. Called once, before anything connects.
///
/// `--fingerprint` and `--ca-cert` are mutually exclusive: they are two different
/// answers to "who do you trust", and silently letting one win would leave the
/// user believing they had the other.
pub fn configure(fingerprint: Option<&str>, ca_cert: Option<&std::path::Path>) -> CliResult {
    let policy = match (fingerprint, ca_cert) {
        (Some(_), Some(_)) => {
            return Err(CliError::invalid(
                "--fingerprint and --ca-cert cannot be combined: pin the leaf certificate \
                 or trust a CA, not both",
            ))
        }
        (Some(fp), None) => {
            let n = tls::normalize_fingerprint(fp);
            // 64 hex characters. Catching a truncated paste here beats a
            // handshake failure that reads like the server is unreachable.
            if n.len() != 64 || !n.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(CliError::invalid(format!(
                    "--fingerprint must be a SHA-256 as 64 hex characters (got {} characters)",
                    n.len()
                )));
            }
            TlsPolicy::Pin(n)
        }
        (None, Some(path)) => {
            let pem = std::fs::read(path)
                .map_err(|e| CliError::invalid(format!("Cannot read {}: {e}", path.display())))?;
            TlsPolicy::PrivateCa(tls::certs_from_pem(&pem).map_err(CliError::invalid)?)
        }
        (None, None) => TlsPolicy::Ca,
    };
    if fingerprint.is_some() || ca_cert.is_some() {
        EXPLICIT.store(true, Ordering::Relaxed);
    }
    *POLICY.write().unwrap() = policy;
    Ok(())
}

/// Adopt a fingerprint remembered from a previous `unv login --tofu`.
///
/// Only takes effect when the user gave no explicit policy — an explicit
/// `--fingerprint` or `--ca-cert` on this invocation always wins over a stored
/// pin, or the flag would silently do nothing.
pub fn adopt_remembered(fingerprint: &str) {
    if EXPLICIT.load(Ordering::Relaxed) {
        return;
    }
    *POLICY.write().unwrap() = TlsPolicy::Pin(tls::normalize_fingerprint(fingerprint));
}

fn policy() -> TlsPolicy {
    POLICY.read().unwrap().clone()
}

/// The only place an HTTP client is constructed.
///
/// Every request the CLI makes comes from here. A second `Client::new()`
/// anywhere in this crate is a hole in the pin, so there is a test asserting
/// there isn't one.
pub fn build_client() -> CliResult<reqwest::blocking::Client> {
    let cfg = tls::client_config(&policy()).map_err(CliError::from)?;
    reqwest::blocking::Client::builder()
        .use_preconfigured_tls(cfg)
        .build()
        .map_err(|e| CliError::from(format!("Cannot build HTTPS client: {e}")))
}

/// The client a node agent uses to reach its hub (Phase 34): the configured
/// pin, TLS 1.3 only, no redirects (a redirect would carry a signed request to
/// somewhere the pin never saw), and a timeout longer than the hub's longest
/// held beat.
pub fn build_node_client(timeout: std::time::Duration) -> CliResult<reqwest::blocking::Client> {
    let cfg = tls::client_config_tls13(&policy()).map_err(CliError::from)?;
    reqwest::blocking::Client::builder()
        .use_preconfigured_tls(cfg)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CliError::from(format!("Cannot build HTTPS client: {e}")))
}

/// The client a hub uses to dial a listening node (Phase 34.1): this node's
/// certificate, by the SHA-256 recorded at enrollment, TLS 1.3 only, no redirects.
/// Not the globally configured pin - the hub talks to many nodes, each with its own.
pub fn build_pinned_node_client(
    fingerprint: &str,
    timeout: std::time::Duration,
) -> CliResult<reqwest::blocking::Client> {
    let cfg = tls::client_config_tls13(&tls::TlsPolicy::Pin(fingerprint.to_string()))
        .map_err(CliError::from)?;
    reqwest::blocking::Client::builder()
        .use_preconfigured_tls(cfg)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CliError::from(format!("Cannot build HTTPS client: {e}")))
}

/// A node's answer to a hub's request (Phase 34.1).
pub struct Dialed {
    pub status: u16,
    /// Response headers, names lower-cased.
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
}

/// One hub-signed POST to a listening node, pinned to its certificate. The hub
/// crate calls this rather than naming an HTTP client: the signature is made by
/// the caller (`ts` and `sig` are the `x-hub-ts` and `x-hub-sig` values).
pub fn hub_post(
    fingerprint: &str,
    base: &str,
    path: &str,
    ts: i64,
    sig: &str,
    body: &[u8],
) -> Result<Dialed, String> {
    let client = build_pinned_node_client(fingerprint, std::time::Duration::from_secs(30))
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(format!("{base}{path}"))
        .header("content-type", "application/json")
        .header("x-hub-ts", ts.to_string())
        .header("x-hub-sig", sig)
        .body(body.to_vec())
        .send()
        .map_err(|e| {
            // The verifier's message is in the source chain, not Display.
            let mut m = e.to_string();
            let mut src: Option<&dyn std::error::Error> = std::error::Error::source(&e);
            while let Some(s) = src {
                m.push_str("; ");
                m.push_str(&s.to_string());
                src = s.source();
            }
            m
        })?;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            Some((
                k.as_str().to_ascii_lowercase(),
                v.to_str().ok()?.to_string(),
            ))
        })
        .collect();
    // A node's answer is a beat; bound it so a hostile address cannot stream.
    let body = resp.bytes().map_err(|e| e.to_string())?;
    if body.len() > 8 * 1024 * 1024 {
        return Err("the node's answer is over 8 MiB".into());
    }
    Ok(Dialed {
        status,
        headers,
        body: body.to_vec(),
    })
}

/// Turn a transport failure into an error whose code says what to do about it.
///
/// A certificate that fails the pin and a server that is switched off are the
/// same `reqwest::Error` variant, and reporting both as `unavailable` (7) is
/// actively harmful: 7 is the code an agent retries. It would sit in a loop
/// against a MITM, and the operator would read "cannot reach server" while the
/// server was up and answering.
///
/// A refused certificate is `denied` (5) — an authorisation failure, because
/// that is what it is.
pub fn classify_connect_error(err: &reqwest::Error, base: &str) -> CliError {
    // The verifier's message reaches us through the source chain, not Display.
    let mut chain = err.to_string();
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(err);
    while let Some(e) = src {
        chain.push_str("; ");
        chain.push_str(&e.to_string());
        src = std::error::Error::source(e);
    }
    let lower = chain.to_ascii_lowercase();

    if lower.contains("fingerprint does not match") {
        return CliError::denied(format!(
            "{base} presented a certificate that does not match the pinned fingerprint.\n\
             Either the server's certificate was replaced, or something is impersonating it.\n\
             If you know it rotated: `unv logout --server {base}`, then log in again with --tofu."
        ));
    }
    if lower.contains("invalid peer certificate")
        || lower.contains("unknownissuer")
        || lower.contains("certificate")
    {
        return CliError::denied(format!(
            "{base} presented a certificate this machine does not trust.\n\
             For a self-signed unv-server, pin it: `unv login --server {base} --tofu`,\n\
             or pass --ca-cert with the CA that issued it."
        ));
    }
    CliError::unavailable(format!("Cannot reach server: {err}"))
}

/// A client for **third-party issuers**, not for `unv-server`.
///
/// `enrich --online` talks to github.com, api.openai.com and six others. Those
/// need ordinary CA validation and must *never* inherit the pin: a fingerprint
/// pins one certificate, and the one the user pinned belongs to their own
/// server. Passing it here would mean every enrichment failed the handshake —
/// and if it somehow did not, it would mean the pin was not being enforced.
///
/// So this deliberately ignores the configured policy. It is the single
/// exception, it is named for what it is, and the guard test in `tests/agent.rs`
/// points at this function rather than allowing the whole file.
pub fn build_public_client(
    timeout: std::time::Duration,
    user_agent: &str,
) -> CliResult<reqwest::blocking::Client> {
    let cfg = tls::client_config(&TlsPolicy::Ca).map_err(CliError::from)?;
    reqwest::blocking::Client::builder()
        .use_preconfigured_tls(cfg)
        .timeout(timeout)
        .user_agent(user_agent.to_string())
        .build()
        .map_err(|e| CliError::from(format!("Cannot build HTTPS client: {e}")))
}

/// A client for a credential's **issuer** (an OAuth `token_url`): ordinary CA
/// validation, like [`build_public_client`], and **no redirects**. A redirect from
/// a token endpoint would forward the refresh token and client secret in the
/// follow-up request to wherever it points.
pub fn build_issuer_client(timeout: std::time::Duration) -> CliResult<reqwest::blocking::Client> {
    let cfg = tls::client_config(&TlsPolicy::Ca).map_err(CliError::from)?;
    reqwest::blocking::Client::builder()
        .use_preconfigured_tls(cfg)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CliError::from(format!("Cannot build HTTPS client: {e}")))
}

/// Learn a server's certificate fingerprint without sending credentials.
///
/// The trust-on-first-use bootstrap, and the reason it is sound is that it is
/// confined to one unauthenticated `GET /api/status`. Nothing has been verified
/// when this returns — the fingerprint is shown so a human can decide.
pub fn probe(base: &str) -> CliResult<String> {
    let (cfg, seen) = tls::capturing_config().map_err(CliError::from)?;
    let client = reqwest::blocking::Client::builder()
        .use_preconfigured_tls(cfg)
        .build()
        .map_err(|e| CliError::from(e.to_string()))?;
    client
        .get(format!("{}/api/status", base.trim_end_matches('/')))
        .send()
        .map_err(|e| CliError::unavailable(format!("Cannot reach {base}: {e}")))?;
    let captured = seen.lock().unwrap().clone();
    captured
        .ok_or_else(|| CliError::from("Server presented no TLS certificate (is it plain HTTP?)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `POLICY` and `EXPLICIT` are process-wide, and `cargo test` runs these in
    /// parallel threads of one process. Without this, whichever test sets an
    /// explicit policy first makes the adoption test fail — and it fails
    /// intermittently, which is worse than failing.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn isolated() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        EXPLICIT.store(false, Ordering::Relaxed);
        *POLICY.write().unwrap() = TlsPolicy::Ca;
        g
    }

    #[test]
    fn fingerprint_and_ca_cert_are_mutually_exclusive() {
        let _serial = isolated();
        let err = configure(Some(&"a".repeat(64)), Some(std::path::Path::new("/x"))).unwrap_err();
        assert!(err.to_string().contains("cannot be combined"));
    }

    #[test]
    fn a_truncated_fingerprint_is_refused_before_any_connection() {
        let _serial = isolated();
        // The realistic paste error. Without this it surfaces as a handshake
        // failure that reads like the server is down.
        let err = configure(Some("ab:cd:ef"), None).unwrap_err();
        assert!(err.to_string().contains("64 hex characters"), "{err}");
    }

    /// A pin learned by --tofu must actually take effect on the next request.
    ///
    /// This is the regression test for the first implementation, which stored the
    /// policy in a `OnceLock`: the probe learned the right fingerprint, the
    /// adopt call was silently dropped, and login then failed against the very
    /// server it had just fingerprinted.
    #[test]
    fn an_adopted_fingerprint_replaces_the_default_policy() {
        let _serial = isolated();
        let fp = "b".repeat(64);
        configure(None, None).unwrap();
        adopt_remembered(&fp);
        match policy() {
            TlsPolicy::Pin(p) => assert_eq!(p, fp),
            other => panic!("adopt did not take effect: {other:?}"),
        }
    }

    #[test]
    fn a_full_fingerprint_in_pasted_form_is_accepted() {
        let _serial = isolated();
        let colonised = "AB".repeat(32);
        let with_colons: String = colonised
            .as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect::<Vec<_>>()
            .join(":");
        assert!(configure(Some(&with_colons), None).is_ok());
    }
}
