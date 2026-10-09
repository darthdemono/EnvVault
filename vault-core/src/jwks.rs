//! The public half of a `signing_key` as a JSON Web Key Set (Phase 24.5).
//!
//! A service that signs tokens publishes its *public* keys at a `jwks_uri`, and a
//! rotation needs the old and the new key listed together for as long as tokens
//! signed by the old one are still in flight - which is why the entry has a
//! first-class "previous key" slot. This turns what the vault holds (a PEM or a
//! JWK) into the document a verifier fetches.
//!
//! **Only public material is ever produced.** A JWK that arrives with private
//! members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) has them stripped, and a PEM that
//! is a private key is refused rather than derived from: publishing the wrong
//! half is the one mistake a key set cannot take back. Nothing is verified or
//! generated here; keys are re-encoded, never operated on.
//!
//! PEM `PUBLIC KEY` (SPKI) is read for RSA, EC (P-256, P-384, P-521), Ed25519 and
//! X25519; `RSA PUBLIC KEY` (PKCS#1) for RSA. A key without a `kid` gets its RFC
//! 7638 thumbprint, which is what a verifier would compute for it anyway.

use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// One DER element: `(tag, contents, rest)`.
fn tlv(b: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    let (&tag, b) = b.split_first().ok_or("Truncated key (DER)")?;
    let (&l0, b) = b.split_first().ok_or("Truncated key (DER)")?;
    let (len, b) = if l0 < 0x80 {
        (usize::from(l0), b)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 || b.len() < n {
            return Err("Unsupported DER length".into());
        }
        let len = b[..n]
            .iter()
            .fold(0usize, |a, &x| (a << 8) | usize::from(x));
        (len, &b[n..])
    };
    if b.len() < len {
        return Err("Truncated key (DER)".into());
    }
    Ok((tag, &b[..len], &b[len..]))
}

fn pem_body(text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let i = text.find(&begin)? + begin.len();
    let j = text[i..].find(&end)? + i;
    let b64: String = text[i..j].lines().map(str::trim).collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()
}

/// An unsigned big-endian integer without its DER sign byte.
fn uint(contents: &[u8]) -> &[u8] {
    match contents {
        [0, rest @ ..] if !rest.is_empty() => rest,
        c => c,
    }
}

fn rsa_jwk(seq: &[u8]) -> Result<Value, String> {
    let (_, n, rest) = tlv(seq)?;
    let (_, e, _) = tlv(rest)?;
    Ok(json!({ "kty": "RSA", "n": b64u(uint(n)), "e": b64u(uint(e)) }))
}

/// A JWK from a PEM public key.
fn jwk_from_pem(text: &str) -> Result<Value, String> {
    if text.contains("PRIVATE KEY-----") {
        return Err(
            "That is a private key. Put the public key in the entry: a key set publishes the public half only.".into(),
        );
    }
    if let Some(der) = pem_body(text, "RSA PUBLIC KEY") {
        let (tag, seq, _) = tlv(&der)?;
        if tag != 0x30 {
            return Err("Not an RSA public key".into());
        }
        return rsa_jwk(seq);
    }
    let der = pem_body(text, "PUBLIC KEY")
        .ok_or("Expected a PEM `PUBLIC KEY` (or `RSA PUBLIC KEY`) block, or a JWK in JSON")?;
    let (tag, spki, _) = tlv(&der)?;
    if tag != 0x30 {
        return Err("Not a SubjectPublicKeyInfo".into());
    }
    let (tag, alg, rest) = tlv(spki)?;
    if tag != 0x30 {
        return Err("Not a SubjectPublicKeyInfo".into());
    }
    let (tag, bits, _) = tlv(rest)?;
    if tag != 0x03 || bits.first() != Some(&0) {
        return Err("Unsupported key bit string".into());
    }
    let key = &bits[1..];
    let (_, oid, params) = tlv(alg)?;
    const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
    const X25519: &[u8] = &[0x2b, 0x65, 0x6e];
    match oid {
        RSA => {
            let (tag, seq, _) = tlv(key)?;
            if tag != 0x30 {
                return Err("Not an RSA public key".into());
            }
            rsa_jwk(seq)
        }
        EC => {
            let (_, curve, _) = tlv(params)?;
            let (name, size): (&str, usize) = match curve {
                [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => ("P-256", 32),
                [0x2b, 0x81, 0x04, 0x00, 0x22] => ("P-384", 48),
                [0x2b, 0x81, 0x04, 0x00, 0x23] => ("P-521", 66),
                _ => return Err("Only the P-256, P-384 and P-521 curves are supported".into()),
            };
            if key.len() != 1 + 2 * size || key[0] != 4 {
                return Err("Only uncompressed EC points are supported".into());
            }
            Ok(json!({
                "kty": "EC", "crv": name,
                "x": b64u(&key[1..=size]), "y": b64u(&key[1 + size..]),
            }))
        }
        ED25519 | X25519 if key.len() == 32 => Ok(json!({
            "kty": "OKP",
            "crv": if oid == ED25519 { "Ed25519" } else { "X25519" },
            "x": b64u(key),
        })),
        _ => Err("Unsupported key type (RSA, EC P-256/384/521, Ed25519 and X25519 are)".into()),
    }
}

const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];

/// A public JWK from either spelling the vault might hold, with no private members.
pub fn public_jwk(text: &str) -> Result<Value, String> {
    let t = text.trim();
    if t.starts_with('{') {
        let mut v: Value =
            serde_json::from_str(t).map_err(|e| format!("The JWK is not JSON: {e}"))?;
        let o = v.as_object_mut().ok_or("A JWK is a JSON object")?;
        if !o.contains_key("kty") {
            return Err("The JWK has no `kty`".into());
        }
        for m in PRIVATE_MEMBERS {
            o.remove(m);
        }
        return Ok(v);
    }
    jwk_from_pem(t)
}

/// The RFC 7638 thumbprint of a public JWK, which is the `kid` a verifier would
/// derive and the one used when the entry names none.
pub fn thumbprint(jwk: &Value) -> Result<String, String> {
    let members: &[&str] = match jwk.get("kty").and_then(Value::as_str) {
        Some("RSA") => &["e", "kty", "n"],
        Some("EC") => &["crv", "kty", "x", "y"],
        Some("OKP") => &["crv", "kty", "x"],
        _ => return Err("Only RSA, EC and OKP keys have a thumbprint here".into()),
    };
    let mut m = Map::new();
    for k in members {
        let v = jwk
            .get(*k)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("The JWK has no `{k}`"))?;
        m.insert((*k).into(), json!(v));
    }
    // serde_json's map is ordered by key, which is the order RFC 7638 asks for.
    let canonical = serde_json::to_string(&Value::Object(m)).map_err(|e| e.to_string())?;
    Ok(b64u(&Sha256::digest(canonical.as_bytes())))
}

/// `use` for a `usage` word the entry holds.
fn use_for(usage: &str) -> &'static str {
    match usage.trim().to_ascii_lowercase().as_str() {
        "encrypt" | "enc" | "decrypt" => "enc",
        _ => "sig",
    }
}

/// One entry of the key set: the key with its `kid`, `alg` and `use`.
pub fn entry_jwk(key: &str, kid: &str, alg: &str, usage: &str) -> Result<Value, String> {
    let mut jwk = public_jwk(key)?;
    let o = jwk.as_object_mut().ok_or("A JWK is a JSON object")?;
    if !kid.is_empty() {
        o.insert("kid".into(), json!(kid));
    } else if !o.contains_key("kid") {
        let t = thumbprint(&Value::Object(o.clone()))?;
        o.insert("kid".into(), json!(t));
    }
    if !alg.is_empty() {
        o.insert("alg".into(), json!(alg));
    }
    o.entry("use").or_insert_with(|| json!(use_for(usage)));
    Ok(jwk)
}

/// The key set for a `signing_key` entry: the current key and, while a rotation is
/// open, the previous one. `None` for a part that is empty.
pub fn key_set(
    current: (&str, &str, &str),
    previous: (&str, &str),
    alg: &str,
    usage: &str,
) -> Result<Value, String> {
    let mut keys = Vec::new();
    if current.0.trim().is_empty() {
        return Err("`public_key` is empty; fill it in before emitting".into());
    }
    keys.push(entry_jwk(current.0, current.1, alg, usage)?);
    if !previous.0.trim().is_empty() {
        let k = entry_jwk(previous.0, previous.1, alg, usage)?;
        if k["kid"] == keys[0]["kid"] {
            return Err(
                "The previous key has the same key id as the current one; a verifier could not tell them apart"
                    .into(),
            );
        }
        keys.push(k);
    }
    Ok(json!({ "keys": keys }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public keys made by Python's `cryptography` package, with the JWK and the
    /// RFC 7638 thumbprint it computed for each: a second implementation, not this
    /// one agreeing with itself.
    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/jwk-vectors.json")).unwrap()
    }

    #[test]
    fn every_supported_key_type_comes_out_as_the_jwk_an_independent_implementation_made() {
        let v = vectors();
        for name in ["rsa", "p256", "p384", "p521", "ed25519", "x25519"] {
            let pem = v[name]["pem"].as_str().unwrap();
            let got = public_jwk(pem).unwrap();
            assert_eq!(got, v[name]["jwk"], "{name}");
            assert_eq!(
                thumbprint(&got).unwrap(),
                v[name]["kid"].as_str().unwrap(),
                "{name}"
            );
        }
        // PKCS#1 spelling of the RSA key.
        assert_eq!(
            public_jwk(v["rsa"]["pkcs1"].as_str().unwrap()).unwrap(),
            v["rsa"]["jwk"]
        );
    }

    #[test]
    fn the_thumbprint_matches_the_rfc_8037_example() {
        let k =
            json!({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
        assert_eq!(
            thumbprint(&k).unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn private_material_never_reaches_the_set() {
        // A JWK pasted with its private members: they are dropped.
        let with_d =
            json!({"kty":"OKP","crv":"Ed25519","x":"AAAA","d":"SECRETSECRET","k":"x"}).to_string();
        let k = public_jwk(&with_d).unwrap();
        assert!(k.get("d").is_none() && k.get("k").is_none());
        assert!(!k.to_string().contains("SECRETSECRET"));
        // A private PEM is refused, not derived from.
        let err =
            public_jwk("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----").unwrap_err();
        assert!(err.contains("private key"), "{err}");
        let err =
            public_jwk("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")
                .unwrap_err();
        assert!(err.contains("private key"), "{err}");
    }

    #[test]
    fn a_rotation_lists_both_keys_and_refuses_two_with_one_id() {
        let v = vectors();
        let a = v["ed25519"]["pem"].as_str().unwrap();
        let b = v["p256"]["pem"].as_str().unwrap();
        let set = key_set((a, "", ""), (b, ""), "EdDSA", "sign").unwrap();
        let keys = set["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys[0]["kid"], v["ed25519"]["kid"],
            "no kid given: the thumbprint"
        );
        assert_eq!(keys[0]["use"], "sig");
        assert_eq!(keys[0]["alg"], "EdDSA");
        assert_eq!(keys[1]["crv"], "P-256");
        // Only the current key while no rotation is open.
        assert_eq!(
            key_set((a, "k1", ""), ("", ""), "", "").unwrap()["keys"][0]["kid"],
            "k1"
        );
        assert_eq!(
            key_set((a, "k1", ""), ("", ""), "", "").unwrap()["keys"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // The same id twice is a key set a verifier cannot use.
        assert!(key_set((a, "same", ""), (b, "same"), "", "").is_err());
        assert!(key_set(("", "", ""), ("", ""), "", "").is_err());
        assert_eq!(entry_jwk(a, "", "", "encrypt").unwrap()["use"], "enc");
    }

    #[test]
    fn garbage_is_an_error_and_never_a_panic() {
        for bad in [
            "",
            "hello",
            "{",
            "[]",
            "{\"a\":1}",
            "-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----",
        ] {
            assert!(public_jwk(bad).is_err(), "{bad:?}");
        }
        for n in 0..200u32 {
            let der: Vec<u8> = (0..40u32)
                .map(|i| (i.wrapping_mul(n + 7) & 0xff) as u8)
                .collect();
            let pem = format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                base64::engine::general_purpose::STANDARD.encode(der)
            );
            let _ = public_jwk(&pem);
        }
    }
}
