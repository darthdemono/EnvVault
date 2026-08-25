//! `envv render` — substitute `${…}` references in an arbitrary template.
//!
//! The exporters cover the config formats EnvVault models. This covers
//! everything else: a systemd unit, a Helm values file, a CI config. The
//! template is ordinary text an agent can write and read freely — it holds
//! *references*, never values — and the substitution happens on the way to a
//! file.

use crate::access::Access;
use crate::error::{CliError, CliResult};
use crate::out;
use crate::refs::Resolver;
use serde_json::json;

pub struct RenderResult {
    pub text: String,
    pub resolved: usize,
    pub unresolved: Vec<String>,
}

/// Replace every `${…}` occurrence in `template`.
///
/// Unlike a chunk field — which is a reference only when the *whole* value is
/// `${…}` — a template can hold references mid-line, so this scans for them
/// anywhere. `$${…}` escapes a literal `${…}` for templates that need one.
pub fn render(template: &str, r: &Resolver) -> RenderResult {
    let mut out_text = String::with_capacity(template.len());
    let mut resolved = 0usize;
    let mut unresolved: Vec<String> = Vec::new();

    let bytes: Vec<char> = template.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        // `$${…}` → literal `${…}`, so a rendered file can still contain the
        // syntax (a compose file's own ${VAR}, for instance).
        if bytes[i] == '$'
            && i + 1 < bytes.len()
            && bytes[i + 1] == '$'
            && i + 2 < bytes.len()
            && bytes[i + 2] == '{'
        {
            out_text.push('$');
            i += 2;
            continue;
        }
        if bytes[i] == '$' && i + 1 < bytes.len() && bytes[i + 1] == '{' {
            if let Some(end) = (i + 2..bytes.len()).find(|&j| bytes[j] == '}') {
                let inner: String = bytes[i + 2..end].iter().collect();
                let whole = format!("${{{inner}}}");
                let res = r.resolve(&whole);
                match res.value {
                    Some(v) if !res.unresolved => {
                        resolved += 1;
                        out_text.push_str(&if r.redact { out::masked(&v) } else { v });
                    }
                    _ => {
                        unresolved.push(whole.clone());
                        out_text.push_str(&whole);
                    }
                }
                i = end + 1;
                continue;
            }
        }
        out_text.push(bytes[i]);
        i += 1;
    }

    RenderResult {
        text: out_text,
        resolved,
        unresolved,
    }
}

pub fn cmd_render(
    access: &Access,
    template_path: Option<&std::path::Path>,
    out_path: Option<&std::path::Path>,
    strict: bool,
) -> CliResult {
    let template = match template_path {
        Some(p) if p.as_os_str() != "-" => std::fs::read_to_string(p)
            .map_err(|e| CliError::not_found(format!("Cannot read {}: {e}", p.display())))?,
        _ => crate::fmt::read_stdin()?,
    };
    let vault = access.load_vault()?;
    // Same rule as `project export`: a file gets real values, stdout gets
    // fingerprints unless the caller explicitly asked to reveal.
    let r = if out_path.is_some() {
        Resolver::materialising(&vault)
    } else {
        Resolver::for_output(&vault)
    };

    let result = render(&template, &r);
    if strict && !result.unresolved.is_empty() {
        return Err(CliError::not_found(format!(
            "{} unresolved reference(s): {}",
            result.unresolved.len(),
            result.unresolved.join(", ")
        ))
        .with_details(json!({ "unresolved": result.unresolved })));
    }

    if out::dry_run() && out_path.is_some() {
        out::ok(
            "render",
            json!({
                "resolved": result.resolved,
                "unresolved": result.unresolved,
                "bytes": result.text.len(),
                "written": false,
            }),
            || {
                println!(
                    "Would write {} bytes to {}",
                    result.text.len(),
                    out_path.unwrap().display()
                )
            },
        );
        return Ok(());
    }

    match out_path {
        Some(p) => {
            std::fs::write(p, &result.text)
                .map_err(|e| CliError::from(format!("Cannot write {}: {e}", p.display())))?;
            out::ok(
                "render",
                json!({
                    "path": p.display().to_string(),
                    "resolved": result.resolved,
                    "unresolved": result.unresolved,
                    "bytes": result.text.len(),
                    "written": true,
                }),
                || {
                    eprintln!(
                        "Wrote {} ({} reference(s) resolved)",
                        p.display(),
                        result.resolved
                    );
                },
            );
        }
        None => {
            if out::is_json() {
                out::ok(
                    "render",
                    json!({
                        "text": result.text,
                        "redacted": r.redact,
                        "resolved": result.resolved,
                        "unresolved": result.unresolved,
                    }),
                    || {},
                );
            } else {
                print!("{}", result.text);
                if !result.text.ends_with('\n') {
                    println!();
                }
            }
        }
    }
    for u in &result.unresolved {
        eprintln!("# WARN unresolved ref: {u}");
    }
    Ok(())
}
