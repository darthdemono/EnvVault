//! `envv template ls|show` — the presets `envv entry add --preset` and the
//! app's Templates pane share (`vault_core::templates`, Phase 33.6). Compiled-in
//! public reference data, so it needs no vault and no password.

use crate::error::{CliError, CliResult};
use crate::out;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand)]
pub enum TemplateCmd {
    /// List the presets.
    Ls,
    /// Show what a preset pre-fills and which fields it expects.
    Show { id: String },
}

pub fn run(cmd: &TemplateCmd) -> CliResult {
    match cmd {
        TemplateCmd::Ls => {
            let all = vault_core::templates::list();
            let rows: Vec<_> = all
                .iter()
                .map(|t| json!({ "id": t.id, "name": t.name, "category": t.category, "type": t.secret_type }))
                .collect();
            out::ok("template.ls", json!({ "templates": rows }), || {
                for t in &all {
                    println!("{:<18} {:<14} {}", t.id, t.category, t.name);
                }
            });
        }
        TemplateCmd::Show { id } => {
            let t = vault_core::templates::find(id)
                .ok_or_else(|| CliError::not_found(format!("No template '{id}'")))?;
            out::ok(
                "template.show",
                json!({
                    "id": t.id, "name": t.name, "type": t.secret_type,
                    "defaults": t.defaults, "required": t.required_fields, "hints": t.hints,
                }),
                || {
                    println!("{} ({})", t.name, t.secret_type);
                    for (k, v) in &t.defaults {
                        println!("  {k} = {v}");
                    }
                    for f in &t.required_fields {
                        let hint = t.hints.get(f).and_then(|h| h.as_str()).unwrap_or("");
                        println!("  needs {f}  {hint}");
                    }
                },
            );
        }
    }
    Ok(())
}
