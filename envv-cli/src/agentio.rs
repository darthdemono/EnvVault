//! `envv describe` — the machine-readable contract.
//!
//! An agent that has to guess a CLI's flags spends its first three attempts
//! learning them from error messages. This emits the whole command tree, the
//! exit codes, the output envelope and the redaction rules as one JSON
//! document, generated from the same `clap` definition the binary runs on — so
//! it cannot describe a flag that does not exist.

use clap::{ArgAction, Command};
use serde_json::{json, Value};

fn arg_json(arg: &clap::Arg) -> Value {
    let takes_value = !matches!(
        arg.get_action(),
        ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Help | ArgAction::Version | ArgAction::Count
    );
    let possible: Vec<String> = arg
        .get_possible_values()
        .iter()
        .map(|p| p.get_name().to_string())
        .collect();
    let mut v = json!({
        "id": arg.get_id().as_str(),
        "kind": if arg.is_positional() { "positional" } else { "flag" },
        "takes_value": takes_value,
        "required": arg.is_required_set(),
        "repeatable": matches!(arg.get_action(), ArgAction::Append),
        "global": arg.is_global_set(),
    });
    if let Some(long) = arg.get_long() {
        v["long"] = json!(format!("--{long}"));
    }
    if let Some(short) = arg.get_short() {
        v["short"] = json!(format!("-{short}"));
    }
    if let Some(help) = arg.get_help() {
        v["help"] = json!(help.to_string());
    }
    if let Some(env) = arg.get_env() {
        v["env"] = json!(env.to_string_lossy());
    }
    if !possible.is_empty() {
        v["values"] = json!(possible);
    }
    if let Some(def) = arg.get_default_values().first() {
        v["default"] = json!(def.to_string_lossy());
    }
    v
}

fn command_json(cmd: &Command, path: &str) -> Value {
    let name = cmd.get_name().to_string();
    let full = if path.is_empty() { name.clone() } else { format!("{path} {name}") };
    let args: Vec<Value> = cmd
        .get_arguments()
        .filter(|a| a.get_id() != "help" && a.get_id() != "version")
        .map(arg_json)
        .collect();
    let subs: Vec<Value> = cmd.get_subcommands().map(|c| command_json(c, &full)).collect();

    let mut v = json!({ "name": name, "path": full, "args": args });
    if let Some(about) = cmd.get_about() {
        v["about"] = json!(about.to_string());
    }
    if let Some(long) = cmd.get_long_about() {
        v["description"] = json!(long.to_string());
    }
    if !subs.is_empty() {
        v["subcommands"] = json!(subs);
    }
    v
}

/// The full contract document.
pub fn describe(cmd: &Command) -> Value {
    json!({
        "tool": "envv",
        "version": env!("CARGO_PKG_VERSION"),
        "contract": 1,
        "summary": "Local-first secrets manager. Every command works against the local \
                    SQLCipher vault or a remote envv-server (--server).",
        "envelope": {
            "note": "Pass --json to any command. stdout is then exactly one JSON document.",
            "success": { "ok": true, "command": "<command.path>", "data": "<command-specific>" },
            "failure": { "ok": false, "error": { "code": "<code>", "message": "<text>", "details": "<optional object>" } },
            "dry_run": "Mutating commands accept --dry-run; the envelope then carries \"dry_run\": true and nothing is written.",
        },
        "exit_codes": {
            "0":  "ok",
            "1":  "error — unclassified failure",
            "2":  "usage — bad arguments (clap)",
            "3":  "not_found — no such entry, project, chunk, user or class",
            "4":  "ambiguous — the name matched several things; error.details.candidates lists them",
            "5":  "denied — authentication failed or the session lacks the permission",
            "6":  "conflict — already exists, or a concurrent write won",
            "7":  "unavailable — vault or server unreachable, or locked",
            "8":  "needs_confirmation — destructive command without --yes on a non-tty",
            "9":  "redacted — output would contain secrets; use --out or --reveal",
            "10": "invalid — well-formed request, invalid input",
        },
        "secret_handling": {
            "default": "Secret values are redacted on stdout. A redacted value is \
                        {\"redacted\":true,\"fingerprint\":\"sha256:<12 hex>\",\"length\":n} in JSON, \
                        and `sha256:<12 hex>` in text.",
            "fingerprints": "Stable per value: equal fingerprints mean equal secrets, so a caller \
                             can detect drift and duplication without ever reading a value.",
            "reveal": "--reveal prints real values. Intended for a human at a terminal.",
            "materialisation": [
                "envv exec --project P -- <cmd>  — values enter the child process's environment only",
                "envv project export P --out FILE — real values are written to FILE, never to stdout",
                "envv render tpl --out FILE       — same rule for arbitrary templates",
                "envv entry add X --generate      — the secret is created and stored without ever being printed",
            ],
            "authentication": [
                "--password-command 'pass show envv' — password comes from a keyring helper",
                "--password-file FILE               — password read from a 0600 file",
                "envv login --server URL            — a human authenticates once; later commands reuse the session",
            ],
        },
        "conventions": {
            "lookup": "Entries resolve by exact provider, then unique case-insensitive substring. \
                       An ambiguous name is refused (exit 4), never guessed. Disambiguate with 'provider:key_id'.",
            "idempotency": "`entry set --create` and `project add --if-missing` are safe to re-run.",
            "confirmation": "Destructive commands need --yes when stdin is not a terminal.",
        },
        "command": command_json(cmd, ""),
    })
}
