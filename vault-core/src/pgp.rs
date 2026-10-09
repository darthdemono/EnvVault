//! What an OpenPGP key says about itself: fingerprint, key id, user ids and, the
//! reason this exists, **when it expires** (Phase 24.5, `gpg_key`).
//!
//! The expiry of a key is not in the key packet. It is a subpacket (type 9, "key
//! expiration time", seconds after the key's creation) of the *self-signature*
//! that binds a user id or the key itself, so reading it means walking the
//! signature packets. This reads v4 public and secret key blocks, ASCII-armoured
//! or binary, and refuses what it does not understand (v5/v6 keys, partial-length
//! packets) rather than guessing: an expiry that is wrong is worse than none.
//!
//! Nothing here verifies a signature. The file is the user's own key and the
//! answer is metadata for a reminder; a forged self-signature could only make the
//! reminder wrong, never grant anything. Secret key material is never read: a
//! secret-key packet's public portion is parsed and the rest is skipped.

use base64::Engine;
use sha1::{Digest, Sha1};

/// One key or subkey.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyInfo {
    /// Upper-case hex, 40 characters.
    pub fingerprint: String,
    /// The last 16 hex characters of the fingerprint.
    pub key_id: String,
    /// Seconds since the epoch.
    pub created: i64,
    /// Seconds since the epoch; `None` for a key that does not expire.
    pub expires: Option<i64>,
    /// OpenPGP public-key algorithm number (1 RSA, 17 DSA, 18 ECDH, 19 ECDSA, 22 EdDSA).
    pub algorithm: u8,
    pub revoked: bool,
}

/// A primary key with its user ids and subkeys.
#[derive(Debug, Clone, PartialEq)]
pub struct PgpInfo {
    pub primary: KeyInfo,
    pub user_ids: Vec<String>,
    pub subkeys: Vec<KeyInfo>,
}

impl PgpInfo {
    /// The earliest expiry among the primary key and its subkeys that are not
    /// revoked: what a reminder should count down to.
    pub fn soonest_expiry(&self) -> Option<i64> {
        std::iter::once(&self.primary)
            .chain(self.subkeys.iter())
            .filter(|k| !k.revoked)
            .filter_map(|k| k.expires)
            .min()
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for an epoch second, the form `expires_at` holds.
pub fn iso(epoch: i64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp(epoch)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

const MAX_PACKETS: usize = 4096;

/// Armoured text or raw bytes to the packet stream.
fn dearmor(input: &[u8]) -> Result<Vec<u8>, String> {
    let Ok(text) = std::str::from_utf8(input) else {
        return Ok(input.to_vec()); // binary keyring
    };
    if !text.contains("-----BEGIN PGP") {
        return Ok(input.to_vec());
    }
    let mut body = String::new();
    let mut in_block = false;
    let mut in_headers = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("-----BEGIN PGP") {
            in_block = true;
            in_headers = true;
            continue;
        }
        if l.starts_with("-----END PGP") {
            break;
        }
        if !in_block {
            continue;
        }
        if in_headers {
            if l.is_empty() {
                in_headers = false;
            }
            continue;
        }
        if l.starts_with('=') {
            continue; // the CRC-24 line
        }
        body.push_str(l);
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| format!("The armour is not valid base64: {e}"))
}

struct Packet<'a> {
    tag: u8,
    body: &'a [u8],
}

fn packets(data: &[u8]) -> Result<Vec<Packet<'_>>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if out.len() >= MAX_PACKETS {
            return Err("The key has too many packets to read".into());
        }
        let b = data[i];
        if b & 0x80 == 0 {
            return Err("Not an OpenPGP packet stream".into());
        }
        i += 1;
        let (tag, len) = if b & 0x40 != 0 {
            let tag = b & 0x3f;
            let first = *data.get(i).ok_or("Truncated packet header")?;
            i += 1;
            let len = match first {
                0..=191 => usize::from(first),
                192..=223 => {
                    let second = *data.get(i).ok_or("Truncated packet header")?;
                    i += 1;
                    ((usize::from(first) - 192) << 8) + usize::from(second) + 192
                }
                255 => {
                    let n = data.get(i..i + 4).ok_or("Truncated packet header")?;
                    i += 4;
                    u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize
                }
                _ => return Err("Partial-length packets are not supported".into()),
            };
            (tag, len)
        } else {
            let tag = (b >> 2) & 0x0f;
            let len = match b & 3 {
                0 => {
                    let n = *data.get(i).ok_or("Truncated packet header")?;
                    i += 1;
                    usize::from(n)
                }
                1 => {
                    let n = data.get(i..i + 2).ok_or("Truncated packet header")?;
                    i += 2;
                    usize::from(u16::from_be_bytes([n[0], n[1]]))
                }
                2 => {
                    let n = data.get(i..i + 4).ok_or("Truncated packet header")?;
                    i += 4;
                    u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize
                }
                _ => return Err("Indeterminate-length packets are not supported".into()),
            };
            (tag, len)
        };
        let body = data
            .get(i..i.checked_add(len).ok_or("Packet length overflows")?)
            .ok_or("A packet runs past the end of the data")?;
        i += len;
        out.push(Packet { tag, body });
    }
    Ok(out)
}

/// Length in bytes of the public-key material after the algorithm byte, which is
/// what a fingerprint covers and a secret key's private part follows.
fn public_material_len(algo: u8, m: &[u8]) -> Result<usize, String> {
    let mpi = |at: usize| -> Result<usize, String> {
        let h = m.get(at..at + 2).ok_or("Truncated key material")?;
        let bits = usize::from(u16::from_be_bytes([h[0], h[1]]));
        Ok(2 + bits.div_ceil(8))
    };
    let mut at = 0;
    match algo {
        1..=3 => {
            for _ in 0..2 {
                at += mpi(at)?; // n, e
            }
        }
        16 | 20 => {
            for _ in 0..3 {
                at += mpi(at)?; // p, g, y
            }
        }
        17 => {
            for _ in 0..4 {
                at += mpi(at)?; // p, q, g, y
            }
        }
        18 | 19 | 22 => {
            let oid_len = usize::from(*m.first().ok_or("Truncated key material")?);
            at += 1 + oid_len;
            at += mpi(at)?;
            if algo == 18 {
                // KDF parameters: a length byte, then that many bytes.
                let kl = usize::from(*m.get(at).ok_or("Truncated key material")?);
                at += 1 + kl;
            }
        }
        25 | 27 | 28 => {
            // X25519, Ed25519, X448 etc. in the native (RFC 9580) forms: fixed size.
            at += match algo {
                25 | 27 => 32,
                _ => 56,
            };
        }
        a => return Err(format!("Public-key algorithm {a} is not supported")),
    }
    if at > m.len() {
        return Err("Truncated key material".into());
    }
    Ok(at)
}

fn key_from_packet(body: &[u8]) -> Result<KeyInfo, String> {
    let version = *body.first().ok_or("Empty key packet")?;
    if version != 4 {
        return Err(format!(
            "Version {version} keys are not supported; only v4 (what gpg has made by default for years)"
        ));
    }
    if body.len() < 6 {
        return Err("Truncated key packet".into());
    }
    let created = i64::from(u32::from_be_bytes([body[1], body[2], body[3], body[4]]));
    let algorithm = body[5];
    let n = public_material_len(algorithm, &body[6..])?;
    let public = &body[..6 + n];
    let mut h = Sha1::new();
    h.update([0x99]);
    h.update((public.len() as u16).to_be_bytes());
    h.update(public);
    let fingerprint = hex::encode_upper(h.finalize());
    Ok(KeyInfo {
        key_id: fingerprint[24..].to_string(),
        fingerprint,
        created,
        expires: None,
        algorithm,
        revoked: false,
    })
}

/// The hashed subpackets of a v4 signature that matter here.
struct SigFacts {
    sig_type: u8,
    created: i64,
    key_expiry: Option<u32>,
}

fn signature_facts(body: &[u8]) -> Option<SigFacts> {
    if body.first() != Some(&4) || body.len() < 6 {
        return None;
    }
    let sig_type = body[1];
    let hashed_len = usize::from(u16::from_be_bytes([body[4], body[5]]));
    let hashed = body.get(6..6 + hashed_len)?;
    let (mut created, mut key_expiry) = (0i64, None);
    let mut i = 0;
    while i < hashed.len() {
        let first = usize::from(hashed[i]);
        i += 1;
        let len = match first {
            0..=191 => first,
            192..=254 => {
                let second = usize::from(*hashed.get(i)?);
                i += 1;
                ((first - 192) << 8) + second + 192
            }
            _ => {
                let n = hashed.get(i..i + 4)?;
                i += 4;
                u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize
            }
        };
        let sp = hashed.get(i..i.checked_add(len)?)?;
        i += len;
        let (&ty, data) = sp.split_first()?;
        match ty & 0x7f {
            2 if data.len() == 4 => {
                created = i64::from(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
            9 if data.len() == 4 => {
                key_expiry = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
            _ => {}
        }
    }
    Some(SigFacts {
        sig_type,
        created,
        key_expiry,
    })
}

/// Reads the first primary key in `input` (armoured or binary) with its user ids
/// and subkeys.
pub fn inspect(input: &[u8]) -> Result<PgpInfo, String> {
    let data = dearmor(input)?;
    let pk = packets(&data)?;
    let mut primary: Option<KeyInfo> = None;
    let mut user_ids: Vec<String> = Vec::new();
    let mut subkeys: Vec<KeyInfo> = Vec::new();
    // What the next signature packet refers to.
    enum Target {
        Primary,
        Subkey,
        Other,
    }
    let mut target = Target::Other;
    // Newest self-signature wins for the primary key's expiry.
    let mut primary_sig_at = i64::MIN;
    let mut sub_sig_at: Vec<i64> = Vec::new();

    for p in &pk {
        match p.tag {
            5 | 6 => {
                if primary.is_some() {
                    break; // a second primary key starts a different certificate
                }
                primary = Some(key_from_packet(p.body)?);
                target = Target::Primary;
            }
            7 | 14 if primary.is_some() => {
                subkeys.push(key_from_packet(p.body)?);
                sub_sig_at.push(i64::MIN);
                target = Target::Subkey;
            }
            13 if primary.is_some() => {
                user_ids.push(String::from_utf8_lossy(p.body).into_owned());
                target = Target::Primary;
            }
            2 => {
                let Some(f) = signature_facts(p.body) else {
                    continue;
                };
                match (&target, f.sig_type) {
                    // Certification of a user id, or a direct-key signature.
                    (Target::Primary, 0x10..=0x13 | 0x1f) => {
                        if let Some(k) = primary.as_mut() {
                            if f.created >= primary_sig_at {
                                primary_sig_at = f.created;
                                k.expires = f
                                    .key_expiry
                                    .filter(|s| *s > 0)
                                    .map(|s| k.created + i64::from(s));
                            }
                        }
                    }
                    (Target::Primary, 0x20) => {
                        if let Some(k) = primary.as_mut() {
                            k.revoked = true;
                        }
                    }
                    // Subkey binding.
                    (Target::Subkey, 0x18) => {
                        if let (Some(k), Some(at)) = (subkeys.last_mut(), sub_sig_at.last_mut()) {
                            if f.created >= *at {
                                *at = f.created;
                                k.expires = f
                                    .key_expiry
                                    .filter(|s| *s > 0)
                                    .map(|s| k.created + i64::from(s));
                            }
                        }
                    }
                    (Target::Subkey, 0x28) => {
                        if let Some(k) = subkeys.last_mut() {
                            k.revoked = true;
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    let primary = primary.ok_or("No OpenPGP key found")?;
    Ok(PgpInfo {
        primary,
        user_ids,
        subkeys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made by `gpg --quick-generate-key "Test User <test@example.com>" ed25519 sign 2y`
    // then `--quick-add-key … cv25519 encr 1y`, exported with `--export --armor`; the
    // expected values are what `gpg --list-keys --with-colons` printed for it.
    const KEY: &str = include_str!("../tests/fixtures/pgp-ed25519.asc");

    #[test]
    fn reads_the_fingerprint_user_ids_and_both_expiries_exactly_as_gpg_does() {
        let k = inspect(KEY.as_bytes()).unwrap();
        assert_eq!(
            k.primary.fingerprint,
            "899144971A1F3431B729FE0AFF605C48E0B8A0D4"
        );
        assert_eq!(k.primary.key_id, "FF605C48E0B8A0D4");
        assert_eq!(k.primary.created, 1_791_539_014);
        assert_eq!(k.primary.expires, Some(1_854_611_014));
        assert_eq!(k.primary.algorithm, 22);
        assert_eq!(k.user_ids, ["Test User <test@example.com>"]);
        assert_eq!(k.subkeys.len(), 1);
        assert_eq!(
            k.subkeys[0].fingerprint,
            "829CE5E113EE851675808E8E231B4410DF551005"
        );
        assert_eq!(k.subkeys[0].expires, Some(1_823_075_014));
        assert_eq!(k.subkeys[0].algorithm, 18);
        // The reminder counts down to the sooner of the two.
        assert_eq!(k.soonest_expiry(), Some(1_823_075_014));
        assert_eq!(iso(1_823_075_014), "2027-10-09T09:43:34Z");
    }

    #[test]
    fn a_key_that_never_expires_has_no_expiry_and_binary_input_reads_the_same() {
        let k = inspect(include_bytes!("../tests/fixtures/pgp-rsa-never.asc")).unwrap();
        assert_eq!(k.primary.expires, None);
        assert_eq!(k.soonest_expiry(), None);
        assert_eq!(k.primary.algorithm, 1);
        assert_eq!(
            k.primary.fingerprint,
            "6719ED3DEC650A98E29B79B3C3AEA629EABC5467"
        );
        assert_eq!(k.primary.key_id, "C3AEA629EABC5467");
        // The binary form of the same key.
        let armoured =
            std::str::from_utf8(include_bytes!("../tests/fixtures/pgp-rsa-never.asc")).unwrap();
        let body: String = armoured
            .lines()
            .skip_while(|l| !l.trim().is_empty())
            .skip(1)
            .take_while(|l| !l.starts_with('=') && !l.starts_with("-----"))
            .collect();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap();
        assert_eq!(inspect(&raw).unwrap().primary, k.primary);
    }

    #[test]
    fn refuses_what_it_cannot_read_instead_of_guessing() {
        assert!(inspect(b"hello").is_err());
        assert!(inspect(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!notbase64\n-----END PGP PUBLIC KEY BLOCK-----").is_err());
        // A v5 key packet.
        let v5 = [0xc6u8, 0x04, 5, 0, 0, 0];
        assert!(inspect(&v5).unwrap_err().contains("Version 5"));
        // A truncated stream and a partial-length header.
        assert!(inspect(&[0xc6, 0x05, 4]).is_err());
        assert!(inspect(&[0xc6, 0xe0, 4]).is_err());
        // Garbage that begins like a packet must not panic.
        for n in 0..64u8 {
            let junk: Vec<u8> = (0..32u8).map(|i| 0x80 | i.wrapping_mul(n)).collect();
            let _ = inspect(&junk);
        }
    }
}
