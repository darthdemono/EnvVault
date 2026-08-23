//! Terminal formatting helpers and the destructive-action confirm prompt.

use std::io::{IsTerminal, Write};
use crate::error::{CliError, CliResult};

/// Pad or ellipsise `s` to exactly `width` display columns.
pub fn cell(s: &str, width: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() > width {
        let cut: String = chars[..width.saturating_sub(1)].iter().collect();
        format!("{cut}…")
    } else {
        format!("{s:width$}")
    }
}

pub fn fmt_entries(entries: &[serde_json::Value]) {
    println!("{:<30} {:<20} {:<16} {:<12}", "Provider", "Account", "Type", "Expires");
    println!("{}", "-".repeat(82));
    for e in entries {
        let provider = e.get("provider").and_then(|v| v.as_str()).unwrap_or("—");
        let account = e.get("account_name").and_then(|v| v.as_str()).unwrap_or("—");
        let stype = e.get("secretType").and_then(|v| v.as_str()).unwrap_or("api_key");
        let expires = e.get("expires_at").and_then(|v| v.as_str()).unwrap_or("—");
        let exp: String = expires.chars().take(12).collect();
        println!("{} {} {} {}", cell(provider, 30), cell(account, 20), cell(stype, 16), exp);
    }
}

/// Ask before doing something irreversible.
///
/// `assume_yes` is the `--yes` flag. A non-tty stdin (a pipe, a cron job) is
/// refused rather than silently confirmed: a script that forgot `--yes` must
/// fail loudly, not delete.
pub fn confirm(question: &str, assume_yes: bool) -> CliResult<bool> {
    if assume_yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::new(
            crate::error::Code::NeedsConfirmation,
            format!("{question} — refusing without a terminal; pass --yes to confirm"),
        ));
    }
    print!("{question} [y/N] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(|e| CliError::from(e.to_string()))?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Read a value from stdin when the caller passed `-` or used a `--stdin` flag.
pub fn read_stdin() -> CliResult<String> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).map_err(|e| CliError::from(e.to_string()))?;
    Ok(buf.trim_end_matches('\n').to_string())
}

/// Write `content` to `path`, or to stdout when `path` is `None`.
pub fn emit(content: &str, path: Option<&std::path::Path>) -> CliResult {
    match path {
        Some(p) => {
            std::fs::write(p, content).map_err(|e| CliError::from(format!("Cannot write {}: {e}", p.display())))?;
            eprintln!("Wrote {}", p.display());
            Ok(())
        }
        None => {
            print!("{content}");
            if !content.ends_with('\n') {
                println!();
            }
            Ok(())
        }
    }
}
