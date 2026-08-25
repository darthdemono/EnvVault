//! Generators — the Tools panel's secret / password / certificate / SSH panes.
//!
//! None of these touch the vault, so they work with no password and no server.
//! Pipe the output into `envv entry set --key-stdin` to store it.

use crate::error::{CliError, CliResult};
use rand::RngCore;

/// Random bytes rendered as hex, base64 or base64url — the "Secret generator" pane.
pub fn secret(bytes: usize, format: &str) -> CliResult<String> {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
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
pub fn password(o: &PwOpts) -> CliResult<(String, f64)> {
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
    let mut rng = rand::thread_rng();
    let pwd: String = (0..o.length)
        .map(|_| {
            // Rejection sampling: `next_u32() % len` biases toward the first
            // (2^32 mod len) characters, which is exactly the kind of quiet
            // weakening nobody notices in a password generator.
            let n = alphabet.len() as u32;
            let limit = u32::MAX - (u32::MAX % n) - 1;
            loop {
                let r = rng.next_u32();
                if r <= limit {
                    return alphabet[(r % n) as usize];
                }
            }
        })
        .collect();
    let entropy = o.length as f64 * (alphabet.len() as f64).log2();
    Ok((pwd, entropy))
}

pub fn certificate(common_name: &str, days: u32) -> CliResult<serde_json::Value> {
    vault_core::generate_certificate(common_name, days).map_err(CliError::from)
}

pub fn ssh_keypair(comment: &str) -> CliResult<serde_json::Value> {
    vault_core::generate_ssh_keypair(comment).map_err(CliError::from)
}
