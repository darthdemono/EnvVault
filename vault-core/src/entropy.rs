//! Entropy sources for secret generation.
//!
//! The point of this module is a rule that is easy to state and easy to get
//! wrong: **hardware entropy is mixed in, never consumed raw.**
//!
//! A physical source can be absent, unplugged mid-read, wedged returning
//! constant bytes, counterfeit, or deliberately backdoored. If its output were
//! used directly, anyone who controlled the device would control every key
//! generated on that machine — strictly worse than the OS RNG the feature was
//! meant to improve on. Mixing means the result is at least as good as
//! `getrandom` no matter what the device does:
//!
//! ```text
//! output = HKDF-SHA256(ikm = os_bytes ‖ device_bytes, salt = domain, info = purpose)
//! ```
//!
//! Three consequences, all deliberate:
//!
//! * **The default never changes.** [`Source::Os`] is what every generator uses
//!   unless a caller asks for something else.
//! * **Absence fails closed.** A selected device that cannot be read is an
//!   error, not a quiet fallback — otherwise the user believes they used the
//!   token and did not, which is the one outcome worse than not having the
//!   feature.
//! * **Generation only.** The vault salt, the Argon2 salt and backup IVs stay on
//!   the OS RNG. A salt that depends on a device turns a lost device into a lost
//!   vault, and this module exists to reduce risk, not to add a new way to lose
//!   everything.

use std::fmt;
use std::io::Read;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Domain separator, so bytes produced here can never collide with bytes some
/// other part of the program derives from the same inputs.
const HKDF_SALT: &[u8] = b"envvault/entropy/v1";

/// Where the extra entropy comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// The operating system CSPRNG (`getrandom`). The default, and the floor
    /// that mixing guarantees every other variant stays above.
    Os,
    /// A character device or file — `/dev/random`, an rng-tools device, a
    /// hardware RNG exposed as a node. Read with a timeout, because
    /// `/dev/random` can block and a generator pane that hangs forever is a bug
    /// report, not a security feature.
    File { path: std::path::PathBuf },
}

impl Source {
    /// Parse the `--entropy-source` argument.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        match spec {
            "os" | "" => Ok(Source::Os),
            other => match other.split_once(':') {
                Some(("file", p)) if !p.is_empty() => Ok(Source::File {
                    path: std::path::PathBuf::from(p),
                }),
                Some(("file", _)) => Err("file: needs a path, e.g. file:/dev/random".into()),
                // Named rather than ignored. "pkcs11 is not built in" is a
                // different problem from "pkcs11 is not a thing", and a user who
                // typed it deserves to know which.
                Some(("pkcs11", _)) | Some(("tpm", _)) => Err(format!(
                    "Entropy source '{other}' is not available in this build. \
                     Available: os, file:PATH"
                )),
                _ => Err(format!(
                    "Unknown entropy source '{other}'. Available: os, file:PATH"
                )),
            },
        }
    }

    /// True when this source contributes bytes from outside the OS CSPRNG.
    pub fn is_external(&self) -> bool {
        !matches!(self, Source::Os)
    }

    /// Human label, also what the CLI reports in its output metadata so a caller
    /// can tell how a secret was produced.
    pub fn label(&self) -> String {
        match self {
            Source::Os => "os".into(),
            Source::File { path } => format!("file:{}", path.display()),
        }
    }

    /// Whether this machine can actually use the source right now.
    pub fn availability(&self) -> Availability {
        match self {
            Source::Os => Availability::Ready,
            Source::File { path } => {
                if !path.exists() {
                    Availability::Missing(format!("{} does not exist", path.display()))
                } else if std::fs::File::open(path).is_err() {
                    Availability::Missing(format!("{} is not readable", path.display()))
                } else {
                    Availability::Ready
                }
            }
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Result of probing a source without using it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Ready,
    Missing(String),
}

/// Read `buf.len()` bytes from the source itself, before mixing.
fn read_external(source: &Source, buf: &mut [u8], timeout: Duration) -> Result<(), String> {
    match source {
        Source::Os => unreachable!("Os is never read as an external source"),
        Source::File { path } => {
            // A blocking source must fail loudly rather than hang. The thread is
            // detached deliberately: it may be parked in a blocking read on
            // /dev/random that no timeout can interrupt, and leaking one thread
            // beats wedging the caller.
            let (tx, rx) = std::sync::mpsc::channel();
            let p = path.clone();
            let n = buf.len();
            std::thread::spawn(move || {
                let mut out = vec![0u8; n];
                let r = std::fs::File::open(&p).and_then(|mut f| f.read_exact(&mut out));
                let _ = tx.send(r.map(|_| out).map_err(|e| e.to_string()));
            });
            match rx.recv_timeout(timeout) {
                Ok(Ok(bytes)) => {
                    buf.copy_from_slice(&bytes);
                    Ok(())
                }
                Ok(Err(e)) => Err(format!("Cannot read {}: {e}", path.display())),
                Err(_) => Err(format!(
                    "{} produced no bytes within {:?}. A blocking source such as \
                     /dev/random may be waiting for the entropy pool to refill.",
                    path.display(),
                    timeout
                )),
            }
        }
    }
}

/// NIST SP 800-90B repetition-count test.
///
/// Catches the realistic hardware failure: a device that has stopped and is
/// returning the same byte forever. Cheap, and necessary *because* of the
/// mixing — HKDF would turn a constant input into perfectly random-looking
/// output, so without this check a dead device is indistinguishable from a
/// working one and the user keeps believing they have hardware entropy.
fn repetition_count_ok(bytes: &[u8]) -> bool {
    // Cutoff for 8-bit samples at the usual α = 2^-30 with a conservative
    // 1 bit/byte min-entropy assumption.
    const CUTOFF: usize = 32;
    let mut run = 1usize;
    for w in bytes.windows(2) {
        if w[0] == w[1] {
            run += 1;
            if run >= CUTOFF {
                return false;
            }
        } else {
            run = 1;
        }
    }
    true
}

/// NIST SP 800-90B adaptive-proportion test, single window.
///
/// Catches a source that is not stuck but is badly biased — one value dominating
/// the window.
fn adaptive_proportion_ok(bytes: &[u8]) -> bool {
    const WINDOW: usize = 512;
    const CUTOFF: usize = 410; // ~80% of the window
    if bytes.len() < WINDOW {
        return true; // too little data to judge; the repetition test still applies
    }
    for chunk in bytes.chunks(WINDOW) {
        if chunk.len() < WINDOW {
            break;
        }
        let mut counts = [0usize; 256];
        for &b in chunk {
            counts[b as usize] += 1;
            if counts[b as usize] >= CUTOFF {
                return false;
            }
        }
    }
    true
}

/// Run both health tests, naming which one failed.
pub fn health_check(bytes: &[u8]) -> Result<(), String> {
    if !repetition_count_ok(bytes) {
        return Err(
            "Entropy source failed the repetition-count test — it is returning the same \
             byte repeatedly, which is what a stopped or disconnected device looks like."
                .into(),
        );
    }
    if !adaptive_proportion_ok(bytes) {
        return Err(
            "Entropy source failed the adaptive-proportion test — its output is heavily \
             biased toward one value."
                .into(),
        );
    }
    Ok(())
}

fn hkdf_sha256(ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), String> {
    // Extract
    let mut mac = HmacSha256::new_from_slice(HKDF_SALT).map_err(|e| e.to_string())?;
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();

    // Expand
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    let mut written = 0;
    while written < out.len() {
        let mut mac = HmacSha256::new_from_slice(&prk).map_err(|e| e.to_string())?;
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize().into_bytes().to_vec();
        let take = (out.len() - written).min(t.len());
        out[written..written + take].copy_from_slice(&t[..take]);
        written += take;
        counter = counter
            .checked_add(1)
            .ok_or_else(|| "HKDF output length exceeds one round".to_string())?;
    }
    Ok(())
}

/// Fill `buf` with random bytes from `source`, mixed with OS entropy.
///
/// `purpose` is HKDF `info` — a label such as `"secret"` or `"ssh-ed25519"`, so
/// two generators asking for bytes in the same instant cannot receive the same
/// stream.
pub fn fill(source: &Source, purpose: &str, buf: &mut [u8]) -> Result<(), String> {
    use rand::RngCore;

    // OS bytes always, and always first. Even in the external case they are the
    // floor under the result.
    let mut os_bytes = vec![0u8; buf.len().max(32)];
    rand::rngs::OsRng.fill_bytes(&mut os_bytes);

    if !source.is_external() {
        buf.copy_from_slice(&os_bytes[..buf.len()]);
        return Ok(());
    }

    if let Availability::Missing(why) = source.availability() {
        return Err(format!("Entropy source {source} is unavailable: {why}"));
    }

    // Read enough to health-test meaningfully even for a short request. A 16-byte
    // secret is not enough data to judge a device on.
    let probe_len = buf.len().max(1024);
    let mut dev_bytes = vec![0u8; probe_len];
    read_external(source, &mut dev_bytes, Duration::from_secs(10))?;
    health_check(&dev_bytes)?;

    let mut ikm = Vec::with_capacity(os_bytes.len() + dev_bytes.len());
    ikm.extend_from_slice(&os_bytes);
    ikm.extend_from_slice(&dev_bytes);
    hkdf_sha256(&ikm, purpose.as_bytes(), buf)
}

/// A `RngCore` view over a [`Source`], for crates that generate keys themselves.
///
/// `ssh-key` and the certificate path take an RNG rather than bytes, so the
/// mixing has to reach them through this rather than being applied afterwards.
pub struct EntropyRng {
    source: Source,
    purpose: &'static str,
}

impl EntropyRng {
    pub fn new(source: Source, purpose: &'static str) -> Self {
        Self { source, purpose }
    }
}

impl rand::RngCore for EntropyRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // `RngCore::fill_bytes` cannot fail, and a key generator that silently
        // produced weak bytes on a device error would be indefensible. Panicking
        // is wrong too — so the fallible path is `try_fill_bytes`, and this one
        // falls back to the OS RNG only for `Source::Os`, where there is nothing
        // to fall back *from*.
        if let Err(e) = self.try_fill_bytes(dest) {
            panic!("entropy source failed during key generation: {e}");
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        fill(&self.source, self.purpose, dest)
            .map_err(|e| rand::Error::new(std::io::Error::other(e)))
    }
}

impl rand::CryptoRng for EntropyRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_is_the_default_and_parses_from_nothing() {
        assert_eq!(Source::parse("").unwrap(), Source::Os);
        assert_eq!(Source::parse("os").unwrap(), Source::Os);
        assert!(!Source::Os.is_external());
    }

    #[test]
    fn unbuilt_backends_say_so_rather_than_being_unknown() {
        // "not available in this build" and "not a thing" are different problems.
        let err = Source::parse("pkcs11:0").unwrap_err();
        assert!(err.contains("not available in this build"), "{err}");
        let err = Source::parse("banana").unwrap_err();
        assert!(err.contains("Unknown entropy source"), "{err}");
    }

    #[test]
    fn a_missing_device_fails_closed_and_produces_nothing() {
        // The whole feature turns on this test. A user who selected a device and
        // got OS bytes anyway believes something false about their key.
        let src = Source::File {
            path: "/nonexistent/entropy/device".into(),
        };
        let mut buf = [0u8; 32];
        let err = fill(&src, "test", &mut buf).unwrap_err();
        assert!(err.contains("unavailable"), "{err}");
        assert_eq!(buf, [0u8; 32], "no bytes may be written on failure");
    }

    #[test]
    fn a_stuck_device_is_caught_before_mixing_hides_it() {
        // HKDF turns constant input into random-looking output, so without the
        // health check a dead device is indistinguishable from a working one.
        assert!(health_check(&[0x41; 4096]).is_err());
        assert!(health_check(&[7u8; 64]).is_err());
    }

    #[test]
    fn a_biased_but_unstuck_device_is_caught_too() {
        let mut bytes = vec![0xAAu8; 512];
        for (i, b) in bytes.iter_mut().enumerate() {
            if i % 7 == 0 {
                *b = i as u8; // breaks runs, keeps the bias
            }
        }
        assert!(health_check(&bytes).is_err());
    }

    #[test]
    fn real_random_bytes_pass_the_health_tests() {
        use rand::RngCore;
        let mut bytes = vec![0u8; 4096];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        assert!(health_check(&bytes).is_ok());
    }

    #[test]
    fn mixing_changes_when_either_input_changes() {
        // Both directions. If only one is tested, a mix that ignores the device
        // still passes — and that is precisely the bug worth catching.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hkdf_sha256(b"os-part-1device-part", b"secret", &mut a).unwrap();
        hkdf_sha256(b"os-part-2device-part", b"secret", &mut b).unwrap();
        assert_ne!(a, b, "changing the OS half must change the output");

        hkdf_sha256(b"os-part-1device-part", b"secret", &mut a).unwrap();
        hkdf_sha256(b"os-part-1device-XXXX", b"secret", &mut b).unwrap();
        assert_ne!(a, b, "changing the device half must change the output");
    }

    #[test]
    fn purpose_separates_streams() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hkdf_sha256(b"identical-input", b"secret", &mut a).unwrap();
        hkdf_sha256(b"identical-input", b"ssh-ed25519", &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_file_source_produces_usable_bytes() {
        let src = Source::File {
            path: "/dev/urandom".into(),
        };
        if src.availability() != Availability::Ready {
            return; // not every CI box has it; the failure path is tested above
        }
        let mut buf = [0u8; 32];
        fill(&src, "test", &mut buf).expect("read /dev/urandom");
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn hkdf_fills_more_than_one_block() {
        let mut long = [0u8; 100];
        hkdf_sha256(b"input", b"info", &mut long).unwrap();
        assert!(long.iter().any(|&b| b != 0));
        // Second 32-byte block must differ from the first, or the counter is
        // not being fed into the expand step.
        assert_ne!(long[0..32], long[32..64]);
    }
}
