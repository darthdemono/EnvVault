//! Cryptographic key and certificate generators.
//!
//! Every generator here takes an [`crate::entropy::Source`]. That is the whole
//! reason this module changed in Phase 17: the CLI's secret and password
//! generators used `rand::thread_rng()` while these two used `OsRng`, so there
//! was no single seam an entropy source could attach to. There is one now, and
//! the source reaches the key material rather than being applied to it
//! afterwards — `rcgen` and `ssh-key` both generate their own keys, so bytes
//! have to go *in*, not be mixed in after the fact.

use crate::entropy::{EntropyRng, Source};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use time::Duration;

/// PKCS#8 v1 prefix for an Ed25519 private key: SEQUENCE, version 0,
/// AlgorithmIdentifier 1.3.101.112, OCTET STRING wrapping the 32-byte seed.
///
/// Fixed because the structure is fixed — every Ed25519 PKCS#8 key differs only
/// in its last 32 bytes. Building it here is what lets our entropy decide the
/// certificate key, since `rcgen::KeyPair::generate` takes no RNG.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Generates a self-signed X.509 certificate and private key PEM pair.
///
/// Returns `{"cert_pem": "...", "key_pem": "..."}`.
pub fn generate_certificate(
    common_name: &str,
    validity_days: u32,
    source: &Source,
) -> Result<serde_json::Value, String> {
    let key_pair = if source.is_external() {
        // Our bytes become the key. `KeyPair::generate()` would use ring's own
        // RNG and quietly ignore the source the user selected.
        let mut seed = [0u8; 32];
        crate::entropy::fill(source, "cert-ed25519", &mut seed)?;
        let mut der = Vec::with_capacity(48);
        der.extend_from_slice(&ED25519_PKCS8_PREFIX);
        der.extend_from_slice(&seed);
        KeyPair::from_pkcs8_der_and_sign_algo(&der.into(), &rcgen::PKCS_ED25519)
            .map_err(|e| e.to_string())?
    } else {
        KeyPair::generate().map_err(|e| e.to_string())?
    };
    let mut params =
        CertificateParams::new(vec![common_name.to_string()]).map_err(|e| e.to_string())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.not_after =
        time::OffsetDateTime::now_utc() + Duration::days(validity_days.max(1) as i64);
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "cert_pem": cert.pem(),
        "key_pem":  key_pair.serialize_pem(),
        "entropy_source": source.label(),
    }))
}

/// Generates an Ed25519 SSH key pair in OpenSSH format.
///
/// Returns `{"public_key": "...", "private_key": "..."}`.
pub fn generate_ssh_keypair(comment: &str, source: &Source) -> Result<serde_json::Value, String> {
    use ssh_key::{Algorithm, LineEnding, PrivateKey};

    // Fail before generating rather than during: `RngCore::fill_bytes` cannot
    // return an error, so a device that disappears mid-generation can only
    // panic. Checking here turns the common case (device not plugged in) into a
    // clean message.
    if let crate::entropy::Availability::Missing(why) = source.availability() {
        return Err(format!("Entropy source {source} is unavailable: {why}"));
    }
    let mut rng = EntropyRng::new(source.clone(), "ssh-ed25519");
    let mut private_key =
        PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(|e| e.to_string())?;
    private_key.set_comment(comment);
    let public_key_str = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| e.to_string())?;
    let private_key_str = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "public_key":  public_key_str,
        "private_key": private_key_str.to_string(),
        "entropy_source": source.label(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cert_from_our_own_entropy_is_still_a_valid_cert() {
        // The PKCS#8 wrapping is hand-built, so this asserts the bytes rcgen
        // accepts are the bytes we produced — a wrong prefix would fail here
        // rather than in the field.
        let src = Source::File {
            path: "/dev/urandom".into(),
        };
        if src.availability() != crate::entropy::Availability::Ready {
            return;
        }
        let v = generate_certificate("example.test", 30, &src).expect("generate");
        assert!(v["cert_pem"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(v["key_pem"].as_str().unwrap().contains("PRIVATE KEY"));
        assert_eq!(v["entropy_source"], "file:/dev/urandom");
    }

    #[test]
    fn ssh_keys_differ_between_generations() {
        let a = generate_ssh_keypair("a", &Source::Os).unwrap();
        let b = generate_ssh_keypair("b", &Source::Os).unwrap();
        assert_ne!(a["private_key"], b["private_key"]);
    }

    #[test]
    fn an_unavailable_source_refuses_before_generating() {
        let src = Source::File {
            path: "/nonexistent/device".into(),
        };
        assert!(generate_ssh_keypair("x", &src).is_err());
        assert!(generate_certificate("x.test", 30, &src).is_err());
    }
}
