//! Generators — the Tools panel's secret / password / certificate / SSH panes.
//!
//! None of these touch the vault, so they work with no password and no server.
//! Pipe the output into `envv entry set --key-stdin` to store it.

use crate::error::{CliError, CliResult};
use vault_core::entropy::Source;

/// The entropy source selected by `--entropy-source`, for callers deep enough
/// that threading it through every signature would be noise (`entry add
/// --generate`, `entry rotate --generate`).
///
/// A `RwLock` rather than a `OnceLock` for the same reason the TLS policy is:
/// write-once cells silently drop the second write, and a flag that silently
/// does nothing is worse than one that errors.
static SOURCE: std::sync::RwLock<Option<Source>> = std::sync::RwLock::new(None);

/// Validate and remember `--entropy-source`. Called once, before any command.
///
/// Validating here rather than at first use means a typo fails immediately
/// instead of after the user has already been prompted for a password.
pub fn configure(spec: Option<&str>) -> CliResult {
    let Some(spec) = spec else { return Ok(()) };
    let src = Source::parse(spec).map_err(CliError::invalid)?;
    // Availability is checked now as well: "your YubiKey is not plugged in" is
    // something to learn before generating, not during.
    if let vault_core::entropy::Availability::Missing(why) = src.availability() {
        return Err(CliError::unavailable(format!(
            "Entropy source {src} is unavailable: {why}"
        )));
    }
    *SOURCE.write().unwrap() = Some(src);
    Ok(())
}

/// The configured source, or the OS CSPRNG.
pub fn current() -> Source {
    SOURCE.read().unwrap().clone().unwrap_or(Source::Os)
}

/// Every source this build knows about, with whether it works on this machine.
pub fn list_sources() -> Vec<serde_json::Value> {
    use vault_core::entropy::Availability;
    let candidates = [
        Source::Os,
        Source::File {
            path: "/dev/random".into(),
        },
        Source::File {
            path: "/dev/hwrng".into(),
        },
    ];
    candidates
        .iter()
        .map(|s| {
            let (ready, detail) = match s.availability() {
                Availability::Ready => (true, String::new()),
                Availability::Missing(w) => (false, w),
            };
            serde_json::json!({
                "id": s.label(),
                "ready": ready,
                "hardware": s.is_external(),
                "detail": detail,
            })
        })
        .collect()
}

/// Random bytes rendered as hex, base64 or base64url — the "Secret generator" pane.
pub fn secret(bytes: usize, format: &str, source: &Source) -> CliResult<String> {
    let mut buf = vec![0u8; bytes];
    vault_core::entropy::fill(source, "secret", &mut buf).map_err(CliError::from)?;
    Ok(match format {
        "hex" => buf.iter().map(|b| format!("{b:02x}")).collect(),
        "base64url" => b64(&buf)
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string(),
        "base64" => b64(&buf),
        other => {
            return Err(CliError::invalid(format!(
                "Unknown format '{other}' (hex, base64, base64url)"
            )))
        }
    })
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub struct PwOpts {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    pub no_ambiguous: bool,
}

/// Character sets and entropy maths identical to the password pane, so a CLI and
/// UI password of the same settings are drawn from the same alphabet.
pub fn password(o: &PwOpts, source: &Source) -> CliResult<(String, f64)> {
    let mut chars = String::new();
    if o.upper {
        chars += if o.no_ambiguous {
            "ABCDEFGHJKLMNPQRSTUVWXYZ"
        } else {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        };
    }
    if o.lower {
        chars += if o.no_ambiguous {
            "abcdefghjkmnpqrstuvwxyz"
        } else {
            "abcdefghijklmnopqrstuvwxyz"
        };
    }
    if o.digits {
        chars += if o.no_ambiguous {
            "23456789"
        } else {
            "0123456789"
        };
    }
    if o.symbols {
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?";
    }
    if chars.is_empty() {
        return Err(CliError::invalid("Select at least one character set"));
    }
    let alphabet: Vec<char> = chars.chars().collect();
    // Draw the whole password's worth of randomness in one call rather than per
    // character: an external source is read and health-tested per call, and
    // doing that once per character would read a hardware device twenty times
    // for one password.
    let mut pool = vec![0u8; o.length * 8];
    vault_core::entropy::fill(source, "password", &mut pool).map_err(CliError::from)?;
    let mut cursor = 0usize;
    let mut next_u32 = move |pool: &[u8]| -> u32 {
        let mut b = [0u8; 4];
        // The pool is sized generously for rejection sampling; wrapping is a
        // last resort rather than an expected path.
        for i in 0..4 {
            b[i] = pool[(cursor + i) % pool.len()];
        }
        cursor = (cursor + 4) % pool.len();
        u32::from_le_bytes(b)
    };
    let pwd: String = (0..o.length)
        .map(|_| {
            // Rejection sampling: `next_u32() % len` biases toward the first
            // (2^32 mod len) characters, which is exactly the kind of quiet
            // weakening nobody notices in a password generator.
            let n = alphabet.len() as u32;
            let limit = u32::MAX - (u32::MAX % n) - 1;
            loop {
                let r = next_u32(&pool);
                if r <= limit {
                    return alphabet[(r % n) as usize];
                }
            }
        })
        .collect();
    let entropy = o.length as f64 * (alphabet.len() as f64).log2();
    Ok((pwd, entropy))
}

pub fn certificate(common_name: &str, days: u32, source: &Source) -> CliResult<serde_json::Value> {
    vault_core::generate_certificate(common_name, days, source).map_err(CliError::from)
}

pub fn ssh_keypair(comment: &str, source: &Source) -> CliResult<serde_json::Value> {
    vault_core::generate_ssh_keypair(comment, source).map_err(CliError::from)
}
