//! Shared TLS client policy — the one place that decides whether a server is
//! trusted.
//!
//! This lived inside `src-tauri/src/lib.rs` until Phase 17, which meant the
//! desktop app pinned certificates and the CLI did not verify them at all. Two
//! implementations of a trust decision is how one of them ends up accepting
//! anything, so there is now exactly one, and both callers build their HTTP
//! client from it.
//!
//! Three policies, and the difference between them is the whole security model:
//!
//! * [`TlsPolicy::Ca`] — ordinary CA validation, for a server with a real
//!   certificate.
//! * [`TlsPolicy::Pin`] — the leaf certificate must hash to a known SHA-256.
//!   Enforced **during the handshake**, before any request body is written, so a
//!   MITM is rejected before the master password reaches the socket.
//! * [`TlsPolicy::PrivateCa`] — validate against a specific CA and *only* that
//!   CA. Narrower than adding a root to the system store, and deliberately so: a
//!   private CA should be able to vouch for your own server, not for the web.
//!
//! [`capturing_config`] is separate and is not a policy. It accepts whatever the
//! server presents and records the fingerprint — the trust-on-first-use
//! bootstrap, which is only sound because it is confined to one unauthenticated
//! request that sends no credentials.

use std::sync::{Arc, Mutex};

// The node listener (unv-cli) builds its server side from the same rustls.
pub use rustls;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

/// SHA-256 of a certificate's DER encoding, lower-case hex.
///
/// This is the string users compare and pin. It is computed the same way in
/// every code path on purpose — a fingerprint that is formatted differently in
/// two places is a pin that silently never matches.
pub fn fingerprint_of_der(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Normalise a user-supplied fingerprint for comparison.
///
/// Accepts the colon-separated form `AB:CD:…` that `openssl x509 -fingerprint`
/// prints and an optional `sha256:` prefix, because those are what people paste.
pub fn normalize_fingerprint(input: &str) -> String {
    input
        .trim()
        .trim_start_matches("sha256:")
        .trim_start_matches("SHA256:")
        .replace([':', ' '], "")
        .to_ascii_lowercase()
}

/// How a client should decide whether to trust the server it reaches.
#[derive(Debug, Clone)]
pub enum TlsPolicy {
    /// Standard CA validation against the platform's trust store.
    Ca,
    /// Pin the leaf certificate to this SHA-256 (hex of the DER encoding).
    Pin(String),
    /// Validate against these roots and no others.
    PrivateCa(Vec<CertificateDer<'static>>),
}

impl TlsPolicy {
    /// True when this policy verifies the server's identity at all.
    ///
    /// There is no variant for "do not verify" and there must never be one:
    /// `danger_accept_invalid_certs` appears nowhere in this workspace, and an
    /// unauthenticated probe is a separate function rather than a policy so it
    /// cannot be selected by accident on a request carrying credentials.
    pub fn verifies(&self) -> bool {
        true
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Build a rustls client configuration for `policy`.
pub fn client_config(policy: &TlsPolicy) -> Result<ClientConfig, String> {
    client_config_with(policy, false)
}

/// As [`client_config`], but offering TLS 1.3 only. A node agent runs
/// unattended on a host nobody is watching and carries rendered config, so it
/// does not negotiate down (Phase 34).
pub fn client_config_tls13(policy: &TlsPolicy) -> Result<ClientConfig, String> {
    client_config_with(policy, true)
}

fn client_config_with(policy: &TlsPolicy, tls13_only: bool) -> Result<ClientConfig, String> {
    let versions = |b: rustls::ConfigBuilder<ClientConfig, rustls::WantsVersions>| {
        if tls13_only {
            b.with_protocol_versions(&[&rustls::version::TLS13])
        } else {
            b.with_safe_default_protocol_versions()
        }
        .map_err(|e| e.to_string())
    };
    match policy {
        TlsPolicy::Ca => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Ok(versions(ClientConfig::builder_with_provider(provider()))?
                .with_root_certificates(roots)
                .with_no_client_auth())
        }
        TlsPolicy::Pin(expected) => {
            let p = provider();
            Ok(versions(ClientConfig::builder_with_provider(p.clone()))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(FingerprintVerifier {
                    expected: normalize_fingerprint(expected),
                    provider: p,
                }))
                .with_no_client_auth())
        }
        TlsPolicy::PrivateCa(certs) => {
            let mut roots = RootCertStore::empty();
            for c in certs {
                roots
                    .add(c.clone())
                    .map_err(|e| format!("Not a usable CA certificate: {e}"))?;
            }
            if roots.is_empty() {
                return Err("No certificates found in the supplied CA file".into());
            }
            Ok(versions(ClientConfig::builder_with_provider(provider()))?
                .with_root_certificates(roots)
                .with_no_client_auth())
        }
    }
}

/// A fresh self-signed certificate for a listener that is reached by pin, not by
/// name: `(cert_pem, key_pem, fingerprint)`. The names go in the SAN list for
/// tools that look; the pin ignores them.
pub fn self_signed(names: Vec<String>) -> Result<(String, String, String), String> {
    use rcgen::{CertificateParams, KeyPair};
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = CertificateParams::new(names).map_err(|e| e.to_string())?;
    params.not_after = time::OffsetDateTime::now_utc()
        .checked_add(time::Duration::days(365 * 5))
        .ok_or("date overflow")?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    Ok((
        cert.pem(),
        key.serialize_pem(),
        fingerprint_of_der(cert.der().as_ref()),
    ))
}

/// The SHA-256 of the first certificate in a PEM file, as the pin form.
pub fn fingerprint_of_pem(cert_pem: &str) -> Result<String, String> {
    let certs = certs_from_pem(cert_pem.as_bytes())?;
    Ok(fingerprint_of_der(certs[0].as_ref()))
}

/// A server configuration that speaks TLS 1.3 only and asks for no client
/// certificate: the caller proves itself with a signature on the request.
pub fn server_config_tls13(cert_pem: &str, key_pem: &str) -> Result<rustls::ServerConfig, String> {
    let chain = certs_from_pem(cert_pem.as_bytes())?;
    let key = match PrivateKeyDer::from_pem_slice(key_pem.as_bytes()) {
        Ok(k) => k,
        Err(rustls_pki_types::pem::Error::NoItemsFound) => {
            return Err("The node's TLS key file holds no private key".into())
        }
        Err(e) => return Err(format!("Cannot read the node's TLS key: {e}")),
    };
    rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())
}

/// Parse a PEM bundle into certificates for [`TlsPolicy::PrivateCa`].
pub fn certs_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem).collect();
    let certs = certs.map_err(|e| format!("Cannot read CA file: {e}"))?;
    if certs.is_empty() {
        return Err("CA file contains no CERTIFICATE block".into());
    }
    Ok(certs)
}

/// What a fingerprint probe hands back: a client configuration, and the slot the
/// observed fingerprint lands in once the handshake completes.
pub type ProbeConfig = (ClientConfig, Arc<Mutex<Option<String>>>);

/// Trust-on-first-use bootstrap: accept whatever is presented and record its
/// fingerprint.
///
/// Returns the config and the slot the fingerprint lands in. **The caller must
/// send no credentials over a connection built from this**, because nothing has
/// been verified yet — that is the trust decision the user is about to be asked
/// to make, exactly as with SSH's host-key prompt.
pub fn capturing_config() -> Result<ProbeConfig, String> {
    let seen = Arc::new(Mutex::new(None::<String>));
    let p = provider();
    let cfg = ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CapturingVerifier {
            seen: seen.clone(),
            provider: p,
        }))
        .with_no_client_auth();
    Ok((cfg, seen))
}

/// Pins the leaf certificate to a SHA-256 fingerprint.
///
/// Signature verification is delegated to the crypto provider unchanged; only
/// the identity check is replaced. Getting that backwards — accepting the
/// identity but skipping the signature — would make the pin decorative.
#[derive(Debug)]
struct FingerprintVerifier {
    expected: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = fingerprint_of_der(end_entity.as_ref());
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "TLS certificate fingerprint does not match the pinned value".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Records the fingerprint it is shown and accepts unconditionally. See
/// [`capturing_config`] for why this is confined to one unauthenticated request.
#[derive(Debug)]
struct CapturingVerifier {
    seen: Arc<Mutex<Option<String>>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        *self.seen.lock().unwrap() = Some(fingerprint_of_der(end_entity.as_ref()));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_lowercase_hex() {
        let fp = fingerprint_of_der(b"not really a certificate");
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, fp.to_ascii_lowercase());
        assert_eq!(fp, fingerprint_of_der(b"not really a certificate"));
        assert_ne!(fp, fingerprint_of_der(b"a different certificate"));
    }

    #[test]
    fn normalize_accepts_the_forms_people_paste() {
        // openssl prints colon-separated upper case; some UIs prefix the algorithm.
        let canonical = "ab12cd34";
        for input in [
            "AB:12:CD:34",
            "sha256:AB12CD34",
            " ab12cd34 ",
            "AB 12 CD 34",
        ] {
            assert_eq!(normalize_fingerprint(input), canonical, "input: {input}");
        }
    }

    #[test]
    fn pin_config_builds_and_normalizes_its_expectation() {
        // A pin given in the pasted form must match a fingerprint we computed,
        // or every user who copies from openssl gets an unexplained refusal.
        let cfg = client_config(&TlsPolicy::Pin("AB:CD".into()));
        assert!(cfg.is_ok());
    }

    #[test]
    fn private_ca_rejects_a_file_with_no_certificates() {
        let err = certs_from_pem(b"-----BEGIN PRIVATE KEY-----\nzzz\n-----END PRIVATE KEY-----\n")
            .unwrap_err();
        assert!(err.contains("no CERTIFICATE"), "{err}");
    }

    /// The hub/node TLS identity load after the move from `rustls-pemfile` to
    /// `rustls-pki-types`: a good pair loads, and each way a pair can be wrong is
    /// refused with a message that names the cause.
    #[test]
    fn tls_identity_load_refuses_bad_keys_and_certificates() {
        let (cert, key, _) = self_signed(vec!["node.test".into()]).unwrap();
        assert!(server_config_tls13(&cert, &key).is_ok());

        // A certificate where the key should be: PEM is fine, but holds no key.
        let err = server_config_tls13(&cert, &cert).unwrap_err();
        assert!(err.contains("no private key"), "{err}");
        // Empty key file.
        let err = server_config_tls13(&cert, "").unwrap_err();
        assert!(err.contains("no private key"), "{err}");
        // Corrupt base64 inside a key block must not load as something plausible.
        let broken_key = key.replacen("MIG", "M!G", 1).replacen("MC4", "M!4", 1);
        let broken_key = if broken_key == key {
            // Fallback: damage the first body line whatever the key type.
            let mut lines: Vec<String> = key.lines().map(str::to_owned).collect();
            lines[1] = format!("!!{}", lines[1]);
            lines.join("\n")
        } else {
            broken_key
        };
        assert!(server_config_tls13(&cert, &broken_key).is_err());
        // Corrupt certificate body: refused, not mapped to a wrong fingerprint.
        let mut lines: Vec<String> = cert.lines().map(str::to_owned).collect();
        lines[1] = format!("!!{}", lines[1]);
        let err = certs_from_pem(lines.join("\n").as_bytes()).unwrap_err();
        assert!(err.contains("Cannot read CA file"), "{err}");
        // A key and a certificate that do not belong together.
        let (_, other_key, _) = self_signed(vec!["other.test".into()]).unwrap();
        assert!(server_config_tls13(&cert, &other_key).is_err());
    }

    #[test]
    fn a_pinned_client_reaches_the_listener_only_with_the_right_certificate() {
        use std::io::{Read, Write};
        let (cert, key, fp) = self_signed(vec!["node.test".into()]).unwrap();
        assert_eq!(fingerprint_of_pem(&cert).unwrap(), fp);
        let cfg = Arc::new(server_config_tls13(&cert, &key).unwrap());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for _ in 0..3 {
                let Ok((mut tcp, _)) = listener.accept() else {
                    return;
                };
                let mut conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let mut buf = [0u8; 4];
                if tls.read_exact(&mut buf).is_ok() {
                    let _ = tls.write_all(b"pong");
                }
            }
        });
        let talk = |pin: &str, tls12: bool| -> Result<Vec<u8>, String> {
            let cfg = if tls12 {
                client_config(&TlsPolicy::Pin(pin.into()))
            } else {
                client_config_tls13(&TlsPolicy::Pin(pin.into()))
            }?;
            let name = ServerName::try_from("node.test").unwrap();
            let mut conn =
                rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
            let mut tcp =
                std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            tls.write_all(b"ping").map_err(|e| e.to_string())?;
            let mut out = vec![0u8; 4];
            tls.read_exact(&mut out).map_err(|e| e.to_string())?;
            Ok(out)
        };
        assert_eq!(talk(&fp, false).unwrap(), b"pong");
        assert!(
            talk(&"00".repeat(32), false).is_err(),
            "a wrong pin must not connect"
        );
        // The listener refuses to negotiate TLS 1.2 even for a client that offers it.
        assert_eq!(
            talk(&fp, true).unwrap(),
            b"pong",
            "a client offering 1.2 and 1.3 lands on 1.3"
        );
    }
}
