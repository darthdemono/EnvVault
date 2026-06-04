//! Cryptographic key and certificate generators.

use rcgen::{CertificateParams, DnType, DistinguishedName, KeyPair};
use time::Duration;

/// Generates a self-signed X.509 certificate and private key PEM pair.
///
/// Returns `{"cert_pem": "...", "key_pem": "..."}`.
pub fn generate_certificate(common_name: &str, validity_days: u32) -> Result<serde_json::Value, String> {
    let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = CertificateParams::new(vec![common_name.to_string()])
        .map_err(|e| e.to_string())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.not_after = time::OffsetDateTime::now_utc()
        + Duration::days(validity_days.max(1) as i64);
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "cert_pem": cert.pem(),
        "key_pem":  key_pair.serialize_pem()
    }))
}

/// Generates an Ed25519 SSH key pair in OpenSSH format.
///
/// Returns `{"public_key": "...", "private_key": "..."}`.
pub fn generate_ssh_keypair(comment: &str) -> Result<serde_json::Value, String> {
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    let mut private_key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|e| e.to_string())?;
    private_key.set_comment(comment);
    let public_key_str = private_key.public_key().to_openssh()
        .map_err(|e| e.to_string())?;
    let private_key_str = private_key.to_openssh(LineEnding::LF)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "public_key":  public_key_str,
        "private_key": private_key_str.to_string()
    }))
}
