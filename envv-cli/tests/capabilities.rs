//! Phase 33: the UI/CLI capability map, checked mechanically (invariant 10).
//!
//! `tests/fixtures/parity/capabilities.json` classifies every CLI leaf command
//! (taken live from `envv describe`) and every registered Tauri command into a
//! capability, and says which half has it. This test fails when:
//!
//! - a CLI command or Tauri command exists that no capability mentions (someone
//!   added a capability to one half and did not decide about the other);
//! - the map names a command, element id, pane or file that does not exist;
//! - a status contradicts its evidence (`both` with an empty side, `gap-ui` that
//!   has a Tauri command, `exempt` with no written reason).
//!
//! A `gap-ui` or `gap-cli` is a tracked, named gap, not a failure: it carries its
//! phase in `note`, and shrinks as the 33.x sub-phases land.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn leaves(node: &Value, out: &mut BTreeSet<String>) {
    let subs = node["subcommands"].as_array().cloned().unwrap_or_default();
    if subs.is_empty() {
        let path = &node["path"];
        let p = match path {
            Value::String(s) => s.clone(),
            Value::Array(a) => a
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" "),
            _ => node["name"].as_str().unwrap_or("").to_string(),
        };
        out.insert(p);
    }
    for s in &subs {
        leaves(s, out);
    }
}

fn walk_ts(dir: &std::path::Path) -> String {
    let mut out = String::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.push_str(&walk_ts(&p));
        } else if p.extension().is_some_and(|x| x == "ts") {
            out.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
        }
    }
    out
}

fn tauri_commands() -> BTreeSet<String> {
    let src = read("src-tauri/src/lib.rs");
    let start = src.find("generate_handler![").expect("generate_handler!");
    let body = &src[start..];
    let end = body.find(']').unwrap();
    body[..end]
        .split("commands::")
        .skip(1)
        .map(|s| {
            s.chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .collect()
}

#[test]
fn the_capability_map_matches_both_halves() {
    let out = Command::new(env!("CARGO_BIN_EXE_envv"))
        .arg("describe")
        .output()
        .expect("run envv describe");
    let doc: Value = serde_json::from_slice(&out.stdout).expect("describe is JSON");
    let mut cli = BTreeSet::new();
    leaves(&doc["command"], &mut cli);
    let tauri = tauri_commands();
    let html = format!("{}{}", read("index.html"), read("src/ts/tools-markup.ts"));

    let map: Value =
        serde_json::from_str(&read("tests/fixtures/parity/capabilities.json")).unwrap();
    let caps = map["capabilities"].as_array().unwrap();

    // A command counts as "the UI has it" only if the frontend actually invokes it.
    let ts_src: String = walk_ts(&root().join("src/ts"));
    let invoked =
        |cmd: &str| ts_src.contains(&format!("'{cmd}'")) || ts_src.contains(&format!("\"{cmd}\""));

    let mut problems: Vec<String> = Vec::new();
    let mut claimed_cli: Vec<String> = Vec::new();
    let mut claimed_tauri: Vec<String> = Vec::new();
    let mut gaps: Vec<String> = Vec::new();

    for c in caps {
        let id = c["id"].as_str().unwrap();
        let status = c["status"].as_str().unwrap();
        let list = |k: &str| -> Vec<String> {
            c[k].as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect()
        };
        let (c_cli, c_ui, c_tauri) = (list("cli"), list("ui"), list("tauri"));
        let c_flags = list("cli_flags");
        let describe_text = String::from_utf8_lossy(&out.stdout);
        for f in &c_flags {
            if !describe_text.contains(f.as_str()) {
                problems.push(format!("{id}: flag `{f}` is not in `envv describe`"));
            }
        }
        let note = c["note"].as_str().unwrap_or("");

        for x in &c_cli {
            if !cli.contains(x) {
                problems.push(format!("{id}: `{x}` is not a CLI command"));
            }
        }
        for x in &c_tauri {
            if !tauri.contains(x) {
                problems.push(format!("{id}: `{x}` is not a registered Tauri command"));
            } else if id == "unused-ipc" && invoked(x) {
                problems.push(format!(
                    "{id}: `{x}` is now invoked by the frontend; move it to a real capability"
                ));
            } else if id != "unused-ipc" && !invoked(x) {
                problems.push(format!(
                    "{id}: `{x}` is claimed as UI evidence but no file in src/ts invokes it"
                ));
            }
        }
        for e in &c_ui {
            let ok = match e.split_once(':') {
                Some(("id", v)) => html.contains(&format!("id=\"{v}\"")),
                Some(("tool", v)) => html.contains(&format!("data-tool=\"{v}\"")),
                Some(("src", v)) => root().join(v).exists(),
                _ => false,
            };
            if !ok {
                problems.push(format!("{id}: UI evidence `{e}` does not exist"));
            }
        }
        let has_ui = !c_ui.is_empty() || !c_tauri.is_empty();
        match status {
            "both" if (c_cli.is_empty() && c_flags.is_empty()) || !has_ui => {
                problems.push(format!("{id}: `both` needs a CLI command and UI evidence"))
            }
            "gap-ui" if c_cli.is_empty() || !c_tauri.is_empty() => problems.push(format!(
                "{id}: `gap-ui` needs CLI commands and no Tauri command"
            )),
            "gap-cli" if !c_cli.is_empty() || !has_ui => problems.push(format!(
                "{id}: `gap-cli` needs UI evidence and no CLI command"
            )),
            "exempt" if note.len() < 20 => {
                problems.push(format!("{id}: an exemption needs a written reason"))
            }
            "both" | "gap-ui" | "gap-cli" | "exempt" => {}
            other => problems.push(format!("{id}: unknown status `{other}`")),
        }
        if status.starts_with("gap") {
            if !note.contains("Phase 33") && !note.contains("Phase 24") {
                problems.push(format!("{id}: a gap must name the phase that closes it"));
            }
            gaps.push(format!("{status} {id}"));
        }
        claimed_cli.extend(c_cli);
        claimed_tauri.extend(c_tauri);
    }

    let mut seen = BTreeSet::new();
    for x in &claimed_cli {
        if !seen.insert(x.clone()) {
            problems.push(format!("`{x}` is claimed by two capabilities"));
        }
    }
    for x in &cli {
        if !claimed_cli.contains(x) {
            problems.push(format!(
                "CLI command `{x}` belongs to no capability: add it to the map as both, a gap, or an exemption"
            ));
        }
    }
    for x in &tauri {
        if !claimed_tauri.contains(x) {
            problems.push(format!(
                "Tauri command `{x}` belongs to no capability: add it to the map as both, a gap, or an exemption"
            ));
        }
    }

    eprintln!("open gaps ({}): {}", gaps.len(), gaps.join(", "));
    assert!(
        problems.is_empty(),
        "capability map problems:\n{}",
        problems.join("\n")
    );
}
