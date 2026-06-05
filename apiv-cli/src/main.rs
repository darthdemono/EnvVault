//! `apiv` — API Vault CLI.
//!
//! Works in two modes:
//! - **Local**: reads the Tauri app's SQLCipher DB directly
//!   (`~/.local/share/io.apivault/vault.db`).
//! - **Remote**: connects to a running `apiv-server` via HTTP.
//!
//! Set `APIV_SERVER_URL` or pass `--server` to switch to remote mode.
//! Password is read from `APIV_PASSWORD` env var or prompted interactively.

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::path::PathBuf;
use vault_core::{
    derive_key, get_expiring_entries, load_audit, load_vault,
    open_db, read_or_create_salt, save_vault, VaultKey,
};

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "apiv",
    version = "0.4.0",
    about   = "API Vault CLI — manage secrets from the terminal",
    long_about = "Local mode reads the Tauri desktop app vault directly.\n\
                  Remote mode (--server / $APIV_SERVER_URL) connects to apiv-server."
)]
struct Cli {
    /// Remote apiv-server URL, e.g. http://localhost:8743.
    /// If set, all commands go through the server instead of the local DB.
    #[arg(long, env = "APIV_SERVER_URL", global = true)]
    server: Option<String>,

    /// Vault password (avoid in scripts — prefer APIV_PASSWORD env var or interactive prompt).
    #[arg(long, env = "APIV_PASSWORD", global = true, hide_env_values = true)]
    password: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List vault entries (table view).
    List {
        /// Filter by project ID or name.
        #[arg(long)]
        project: Option<String>,
        /// Filter by secret type (api_key, password, env_var, …).
        #[arg(long)]
        r#type: Option<String>,
    },
    /// Print full details of a single entry.
    Get {
        /// Provider name (case-insensitive substring match).
        provider: String,
    },
    /// Export vault entries.
    Export {
        /// Output format: dotenv (default), yaml, json.
        #[arg(long, default_value = "dotenv")]
        format: String,
        /// Only export entries belonging to this project.
        #[arg(long)]
        project: Option<String>,
    },
    /// List entries expiring within N days (default: 30).
    RotateCheck {
        #[arg(long, default_value_t = 30)]
        days: u32,
    },
    /// Import entries from a .env file (creates env_var entries).
    Import {
        /// Path to the .env file.
        file: PathBuf,
    },
    /// Show the append-only audit log.
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Generate shell completion scripts.
    Completions {
        /// Target shell (bash, zsh, fish, elvish, powershell).
        shell: Shell,
    },
    /// Watch a .env file for changes and sync into the vault.
    Watch {
        /// Path to the .env file to watch.
        file: PathBuf,
        /// Project ID to assign new env_var entries to.
        #[arg(long)]
        project: Option<String>,
    },
}

// ── Path resolution (local mode) ──────────────────────────────────────────────

/// Returns the default vault.db path: `~/.local/share/io.apivault/vault.db`.
fn default_db_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("~/.local/share"))
        .join("io.apivault")
        .join("vault.db")
}

/// Returns the default vault.salt path alongside vault.db.
fn default_salt_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("~/.local/share"))
        .join("io.apivault")
        .join("vault.salt")
}

// ── Password helper ───────────────────────────────────────────────────────────

fn get_password(provided: Option<&str>) -> String {
    provided
        .map(|s| s.to_string())
        .unwrap_or_else(|| rpassword::prompt_password("Vault password: ").unwrap_or_default())
}

// ── Local key derivation ──────────────────────────────────────────────────────

fn local_key(password: &str) -> Result<VaultKey, String> {
    let salt_path = default_salt_path();
    let salt = read_or_create_salt(&salt_path)?;
    let key  = derive_key(password, &salt)?;
    // Verify
    open_db(&default_db_path(), &key).map(|_| key)
}

// ── Remote HTTP client ────────────────────────────────────────────────────────

struct RemoteClient {
    base: String,
    client: reqwest::blocking::Client,
    token: String,
}

impl RemoteClient {
    fn connect(base: &str, password: &str) -> Result<Self, String> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("{base}/api/unlock"))
            .json(&serde_json::json!({ "password": password }))
            .send()
            .map_err(|e| format!("Cannot reach server: {e}"))?;
        if !resp.status().is_success() {
            let msg = resp.json::<serde_json::Value>().ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
                .unwrap_or_else(|| "Authentication failed".into());
            return Err(msg);
        }
        let token = resp.json::<serde_json::Value>()
            .map_err(|e| e.to_string())?
            .get("token").and_then(|t| t.as_str()).unwrap_or("").to_string();
        Ok(Self { base: base.to_string(), client, token })
    }

    fn get_vault(&self) -> Result<serde_json::Value, String> {
        self.client
            .get(format!("{}/api/vault", self.base))
            .bearer_auth(&self.token)
            .send().map_err(|e| e.to_string())?
            .json().map_err(|e| e.to_string())
    }

    fn get_expiring(&self, days: u32) -> Result<Vec<serde_json::Value>, String> {
        self.client
            .get(format!("{}/api/vault/expiring?days={days}", self.base))
            .bearer_auth(&self.token)
            .send().map_err(|e| e.to_string())?
            .json().map_err(|e| e.to_string())
    }

    fn get_audit(&self) -> Result<Vec<serde_json::Value>, String> {
        self.client
            .get(format!("{}/api/audit", self.base))
            .bearer_auth(&self.token)
            .send().map_err(|e| e.to_string())?
            .json().map_err(|e| e.to_string())
    }

    fn save_vault(&self, data: &serde_json::Value) -> Result<(), String> {
        let status = self.client
            .put(format!("{}/api/vault", self.base))
            .bearer_auth(&self.token)
            .json(data)
            .send().map_err(|e| e.to_string())?
            .status();
        if status.is_success() { Ok(()) } else { Err(format!("Save failed: {status}")) }
    }
}

// ── Data access abstraction ───────────────────────────────────────────────────

enum Access {
    Local(VaultKey),
    Remote(RemoteClient),
}

impl Access {
    fn load_vault(&self) -> Result<serde_json::Value, String> {
        match self {
            Access::Local(key) => {
                let conn = open_db(&default_db_path(), key)?;
                load_vault(&conn)?.ok_or_else(|| "Vault is empty".into())
            }
            Access::Remote(c) => c.get_vault(),
        }
    }

    fn expiring(&self, days: u32) -> Result<Vec<serde_json::Value>, String> {
        match self {
            Access::Local(key) => {
                let conn = open_db(&default_db_path(), key)?;
                get_expiring_entries(&conn, days)
            }
            Access::Remote(c) => c.get_expiring(days),
        }
    }

    fn save(&self, data: &serde_json::Value) -> Result<(), String> {
        match self {
            Access::Local(key) => {
                let conn = open_db(&default_db_path(), key)?;
                save_vault(&conn, data.clone())
            }
            Access::Remote(c) => c.save_vault(data),
        }
    }
}

fn open_access(server: Option<&str>, password: Option<&str>) -> Result<Access, String> {
    if let Some(base) = server {
        let pw = get_password(password);
        Ok(Access::Remote(RemoteClient::connect(base, &pw)?))
    } else {
        if !default_db_path().exists() {
            return Err(format!(
                "No vault found at {}\nMake sure API Vault desktop app has been run at least once.",
                default_db_path().display()
            ));
        }
        let pw  = get_password(password);
        let key = local_key(&pw)?;
        Ok(Access::Local(key))
    }
}

// ── Formatting helpers ────────────────────────────────────────────────────────

fn cell(s: &str, width: usize) -> String {
    if s.len() > width { format!("{:.w$}…", s, w = width - 1) } else { format!("{:width$}", s) }
}

fn fmt_entries(entries: &[serde_json::Value]) {
    println!("{:<30} {:<20} {:<16} {:<12}",
        "Provider", "Account", "Type", "Expires");
    println!("{}", "-".repeat(82));
    for e in entries {
        let provider = e.get("provider").and_then(|v| v.as_str()).unwrap_or("—");
        let account  = e.get("account_name").and_then(|v| v.as_str()).unwrap_or("—");
        let stype    = e.get("secretType").and_then(|v| v.as_str()).unwrap_or("api_key");
        let expires  = e.get("expires_at").and_then(|v| v.as_str()).unwrap_or("—");
        println!("{} {} {} {}",
            cell(provider, 30), cell(account, 20), cell(stype, 16), &expires[..expires.len().min(12)]);
    }
}

fn dotenv_export(entries: &[serde_json::Value]) -> String {
    entries.iter().map(|e| {
        let p = (e.get("provider").and_then(|v| v.as_str()).unwrap_or("UNKNOWN"))
            .to_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_");
        let k = e.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
        format!("{p}={k}")
    }).collect::<Vec<_>>().join("\n")
}

fn yaml_export(entries: &[serde_json::Value]) -> String {
    let mut out = String::from("# API Vault Export\n");
    for e in entries {
        let p = (e.get("provider").and_then(|v| v.as_str()).unwrap_or("UNKNOWN"))
            .to_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_");
        let k = e.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
        out.push_str(&format!("{p}: \"{k}\"\n"));
    }
    out
}

// ── Command handlers ──────────────────────────────────────────────────────────

fn cmd_list(access: &Access, project: Option<&str>, type_filter: Option<&str>) -> Result<(), String> {
    let vault = access.load_vault()?;
    let mut entries: Vec<serde_json::Value> = vault
        .get("api_keys").and_then(|v| v.as_array()).cloned().unwrap_or_default();

    if let Some(proj) = project {
        let proj_lc = proj.to_lowercase();
        let projects: Vec<serde_json::Value> = vault
            .get("projects").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let matching_ids: Vec<&str> = projects.iter()
            .filter(|p| p.get("name").and_then(|n| n.as_str())
                .map_or(false, |n| n.to_lowercase().contains(&proj_lc)))
            .filter_map(|p| p.get("id").and_then(|i| i.as_str()))
            .collect();
        entries.retain(|e| {
            e.get("projectIds").and_then(|v| v.as_array()).map_or(false, |ids|
                ids.iter().any(|id| matching_ids.contains(&id.as_str().unwrap_or(""))))
        });
    }

    if let Some(t) = type_filter {
        entries.retain(|e| {
            e.get("secretType").and_then(|v| v.as_str()).unwrap_or("api_key") == t
        });
    }

    if entries.is_empty() {
        println!("No entries found.");
    } else {
        fmt_entries(&entries);
        println!("\n{} entries", entries.len());
    }
    Ok(())
}

fn cmd_get(access: &Access, provider: &str) -> Result<(), String> {
    let vault = access.load_vault()?;
    let entries: Vec<serde_json::Value> = vault
        .get("api_keys").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let provider_lc = provider.to_lowercase();
    let found: Vec<_> = entries.iter()
        .filter(|e| e.get("provider").and_then(|v| v.as_str())
            .map_or(false, |p| p.to_lowercase().contains(&provider_lc)))
        .collect();
    if found.is_empty() {
        eprintln!("No entry matching '{provider}'");
    } else {
        for e in &found {
            println!("{}", serde_json::to_string_pretty(e).unwrap_or_default());
        }
    }
    Ok(())
}

fn cmd_export(access: &Access, format: &str, project: Option<&str>) -> Result<(), String> {
    let vault = access.load_vault()?;
    let mut entries: Vec<serde_json::Value> = vault
        .get("api_keys").and_then(|v| v.as_array()).cloned().unwrap_or_default();

    if let Some(proj) = project {
        let proj_lc = proj.to_lowercase();
        let projects: Vec<serde_json::Value> = vault
            .get("projects").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let matching_ids: Vec<&str> = projects.iter()
            .filter(|p| p.get("name").and_then(|n| n.as_str())
                .map_or(false, |n| n.to_lowercase().contains(&proj_lc)))
            .filter_map(|p| p.get("id").and_then(|i| i.as_str()))
            .collect();
        entries.retain(|e| {
            e.get("projectIds").and_then(|v| v.as_array()).map_or(false, |ids|
                ids.iter().any(|id| matching_ids.contains(&id.as_str().unwrap_or(""))))
        });
    }

    let output = match format {
        "yaml"  => yaml_export(&entries),
        "json"  => serde_json::to_string_pretty(&entries).unwrap_or_default(),
        _       => dotenv_export(&entries),
    };
    println!("{output}");
    Ok(())
}

fn cmd_rotate_check(access: &Access, days: u32) -> Result<(), String> {
    let entries = access.expiring(days)?;
    if entries.is_empty() {
        println!("No secrets expiring within {days} days.");
        return Ok(());
    }
    println!("{} secret(s) expiring within {days} days:\n", entries.len());
    fmt_entries(&entries);
    Ok(())
}

fn cmd_import(access: &Access, file: &PathBuf) -> Result<(), String> {
    let raw = std::fs::read_to_string(file)
        .map_err(|e| format!("Cannot read {}: {e}", file.display()))?;

    let mut new_entries: Vec<serde_json::Value> = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        if let Some((key, val)) = trimmed.split_once('=') {
            let key = key.trim();
            let val = val.trim().trim_matches('"').trim_matches('\'');
            new_entries.push(serde_json::json!({
                "provider":   key,
                "api_key":    val,
                "price_type": "local",
                "secretType": "env_var",
                "categories": [],
                "projectIds": ["Universal"],
                "scopes":     [],
            }));
        }
    }

    if new_entries.is_empty() {
        println!("No KEY=VALUE pairs found in file.");
        return Ok(());
    }

    let mut vault = access.load_vault()?;
    let existing = vault.get_mut("api_keys").and_then(|v| v.as_array_mut());
    let n = new_entries.len();
    if let Some(arr) = existing {
        arr.extend(new_entries);
    }
    access.save(&vault)?;
    println!("Imported {n} entries from {}", file.display());
    Ok(())
}

fn cmd_audit(access: &Access, limit: usize) -> Result<(), String> {
    match access {
        Access::Local(key) => {
            let conn = open_db(&default_db_path(), key)?;
            let rows = load_audit(&conn)?;
            let rows_to_show = rows.iter().take(limit);
            println!("{:<6} {:<10} {:<25} {:<22} {}",
                "ID", "Action", "Provider", "Timestamp", "Hash prefix");
            println!("{}", "-".repeat(80));
            for r in rows_to_show {
                let hash_prefix = r.entry_hash.as_deref()
                    .map(|h| &h[..h.len().min(12)])
                    .unwrap_or("—");
                println!("{:<6} {:<10} {:<25} {:<22} {}",
                    r.id,
                    &r.action,
                    r.entry_provider.as_deref().unwrap_or("—"),
                    &r.timestamp,
                    hash_prefix,
                );
            }
        }
        Access::Remote(c) => {
            let rows = c.get_audit()?;
            for r in rows.iter().take(limit) {
                println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
            }
        }
    }
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::List { project, r#type } => {
            open_access(cli.server.as_deref(), cli.password.as_deref())
                .and_then(|a| cmd_list(&a, project.as_deref(), r#type.as_deref()))
        }
        Commands::Get { provider } => {
            open_access(cli.server.as_deref(), cli.password.as_deref())
                .and_then(|a| cmd_get(&a, provider))
        }
        Commands::Export { format, project } => {
            open_access(cli.server.as_deref(), cli.password.as_deref())
                .and_then(|a| cmd_export(&a, format, project.as_deref()))
        }
        Commands::RotateCheck { days } => {
            open_access(cli.server.as_deref(), cli.password.as_deref())
                .and_then(|a| cmd_rotate_check(&a, *days))
        }
        Commands::Import { file } => {
            open_access(cli.server.as_deref(), cli.password.as_deref())
                .and_then(|a| cmd_import(&a, file))
        }
        Commands::Audit { limit } => {
            open_access(cli.server.as_deref(), cli.password.as_deref())
                .and_then(|a| cmd_audit(&a, *limit))
        }
        // Completions (item 13): generate shell completion scripts
        Commands::Completions { shell } => {
            generate(*shell, &mut Cli::command(), "apiv", &mut std::io::stdout());
            Ok(())
        }
        // Watch (item 14): sync .env file changes into vault
        Commands::Watch { file, project } => {
            open_access(cli.server.as_deref(), cli.password.as_deref())
                .and_then(|a| cmd_watch(&a, file, project.as_deref()))
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn cmd_watch(access: &Access, file: &PathBuf, project: Option<&str>) -> Result<(), String> {
    use notify::{Event, RecursiveMode, Watcher, recommended_watcher};
    use std::sync::mpsc::channel;

    if !file.exists() {
        return Err(format!("File not found: {}", file.display()));
    }

    println!("Watching {} for changes (Ctrl-C to stop)…", file.display());

    let (tx, rx) = channel::<notify::Result<Event>>();
    let mut watcher = recommended_watcher(tx).map_err(|e| e.to_string())?;
    watcher.watch(file, RecursiveMode::NonRecursive).map_err(|e| e.to_string())?;

    for event in rx {
        match event {
            Ok(ev) if ev.kind.is_modify() || ev.kind.is_create() => {
                println!("[{}] Change detected — syncing…", vault_core::iso_now());
                if let Err(e) = cmd_import(access, file) {
                    eprintln!("Sync error: {e}");
                } else {
                    println!("Synced OK");
                }
            }
            Ok(_) => {}
            Err(e) => eprintln!("Watch error: {e}"),
        }
    }
    Ok(())
}
