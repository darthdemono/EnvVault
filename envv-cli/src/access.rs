//! Vault access: local SQLCipher DB or a remote `envv-server`, behind one enum.
//!
//! Every command takes an [`Access`] rather than a connection, so the same code
//! path serves `envv list` and `envv --server https://… list`.

use crate::error::{CliError, CliResult};
use std::path::PathBuf;
use std::sync::OnceLock;
use vault_core::{derive_key, open_db, read_or_create_salt, VaultKey};

// ── Path resolution (local mode) ──────────────────────────────────────────────

/// Overrides set once from `--db-path` / `--salt-path`, before anything reads them.
static DB_PATH: OnceLock<PathBuf> = OnceLock::new();
static SALT_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Point local mode at a different vault. Call before any command runs; a second
/// call is ignored, so the flags cannot be changed mid-run.
pub fn set_paths(db: Option<PathBuf>, salt: Option<PathBuf>) {
    if let Some(p) = db {
        // The salt lives beside the db unless told otherwise. Deriving it here
        // rather than defaulting to the app's salt matters: pairing a vault with
        // the wrong salt derives the wrong key and reports "wrong password" for
        // a password that is perfectly correct.
        let inferred = p.with_file_name("vault.salt");
        let _ = DB_PATH.set(p);
        if salt.is_none() {
            let _ = SALT_PATH.set(inferred);
        }
    }
    if let Some(p) = salt {
        let _ = SALT_PATH.set(p);
    }
}

/// The platform's application-data directory, or a clear failure.
///
/// Deliberately without a fallback path. The previous one was
/// `PathBuf::from("~/.local/share")`, and nothing in `std::fs` expands `~`: it
/// created a directory literally *named* `~` under the current working
/// directory, so the vault was written somewhere the next invocation would not
/// look — which presents to the user as having lost every secret. On Windows it
/// was worse still, resolving against whichever drive the shell happened to be
/// on.
///
/// Reported through the normal envelope so a `--json` caller still gets
/// something it can parse, and exits `unavailable` (7) like any other
/// "the vault cannot be reached" condition.
fn data_dir_or_exit() -> PathBuf {
    match dirs::data_dir() {
        Some(dir) => dir,
        None => {
            let e = CliError::unavailable(
                "Cannot determine this platform's data directory (no $XDG_DATA_HOME \
                 or $HOME on Unix, no %APPDATA% on Windows). \
                 Pass --db-path and --salt-path explicitly.",
            );
            if crate::out::is_json() {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&e.to_json()).unwrap_or_default()
                );
            } else {
                eprintln!("Error: {}", e.message);
            }
            std::process::exit(e.code as i32);
        }
    }
}

/// Returns the vault.db path: `--db-path`, else `io.envvault/vault.db` under the
/// platform data directory (`~/.local/share` on Linux, `%APPDATA%` on Windows).
pub fn default_db_path() -> PathBuf {
    DB_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| data_dir_or_exit().join("io.envvault").join("vault.db"))
}

/// Returns the vault.salt path: `--salt-path`, else the one beside vault.db.
pub fn default_salt_path() -> PathBuf {
    SALT_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| data_dir_or_exit().join("io.envvault").join("vault.salt"))
}

// ── Password helper ───────────────────────────────────────────────────────────

pub fn get_password(provided: Option<&str>) -> String {
    get_password_for(provided, None)
}

/// Prompt for a password, naming whose it is.
///
/// A sub-user's password is not the vault master password, and prompting for
/// "Vault password" while authenticating `alice` invites someone to type the
/// master password into a form that sends it to a server as a sub-user
/// credential. Naming the subject is the whole fix.
pub fn get_password_for(provided: Option<&str>, user: Option<&str>) -> String {
    if let Some(p) = provided {
        return p.to_string();
    }
    let prompt = match user {
        Some(u) => format!("Password for {u}: "),
        None => "Vault password: ".to_string(),
    };
    rpassword::prompt_password(prompt).unwrap_or_default()
}

// ── Local key derivation ──────────────────────────────────────────────────────

fn local_key(password: &str) -> CliResult<VaultKey> {
    let salt_path = default_salt_path();
    // Before deriving anything: a database with no salt must be reported as
    // exactly that, not silently given a fresh salt that will never open it.
    vault_core::check_salt_pairing(&default_db_path(), &salt_path)?;
    let salt = read_or_create_salt(&salt_path)?;
    let key = derive_key(password, &salt)?;
    // Verify: opening with the wrong key fails here rather than at the first read.
    let conn = open_db(&default_db_path(), &key)?;
    vault_core::init_schema(&conn)?;
    Ok(key)
}

// ── Remote HTTP client ────────────────────────────────────────────────────────

pub struct RemoteClient {
    pub base: String,
    pub client: reqwest::blocking::Client,
    pub token: String,
}

impl RemoteClient {
    pub fn connect(base: &str, password: &str) -> CliResult<Self> {
        let client = crate::tls::build_client()?;
        let resp = client
            .post(format!("{base}/api/unlock"))
            .json(&serde_json::json!({ "password": password }))
            .send()
            .map_err(|e| crate::tls::classify_connect_error(&e, base))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp));
        }
        let token = resp
            .json::<serde_json::Value>()
            .map_err(|e| CliError::from(e.to_string()))?
            .get("token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        Ok(Self {
            base: base.to_string(),
            client,
            token,
        })
    }

    /// Authenticate as a named sub-user (`/api/auth`) instead of the vault owner.
    ///
    /// The desktop app's "Open to LAN" host refuses `/api/unlock` outright, and a
    /// scoped user has no business sending the master password anywhere — so this
    /// is the only way the CLI reaches either.
    pub fn connect_as_user(base: &str, username: &str, password: &str) -> CliResult<Self> {
        let body = serde_json::json!({ "username": username, "password": password });
        Self::auth(base, &body)
    }

    /// Exchange a long-lived API token for a session token.
    ///
    /// `/api/auth` is the only door: `extract_session` looks the Bearer value up
    /// in the live-session map, so sending the API token itself as a Bearer is a
    /// 401 every time.
    pub fn connect_with_api_token(base: &str, api_token: &str) -> CliResult<Self> {
        Self::auth(base, &serde_json::json!({ "token": api_token }))
    }

    /// Adopt an existing session token (from `envv login`).
    ///
    /// Fallible now that the client carries a TLS policy: a bad `--ca-cert` has
    /// to surface here rather than at the first request, where it would read as
    /// the server being unreachable.
    pub fn with_session(base: &str, session_token: &str) -> CliResult<Self> {
        Ok(Self {
            base: base.to_string(),
            client: crate::tls::build_client()?,
            token: session_token.to_string(),
        })
    }

    /// Cheapest possible proof that this session is still accepted.
    ///
    /// `GET /api/ping` is authenticated and slides the idle deadline, so it both
    /// answers the question and is the thing worth doing anyway.
    pub fn ping(&self) -> CliResult<()> {
        self.get_json("/api/ping").map(|_| ())
    }

    fn auth(base: &str, body: &serde_json::Value) -> CliResult<Self> {
        let client = crate::tls::build_client()?;
        let resp = client
            .post(format!("{base}/api/auth"))
            .json(body)
            .send()
            .map_err(|e| crate::tls::classify_connect_error(&e, base))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp));
        }
        let token = resp
            .json::<serde_json::Value>()
            .map_err(|e| CliError::from(e.to_string()))?
            .get("token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        Ok(Self {
            base: base.to_string(),
            client,
            token,
        })
    }

    /// Turn a failed HTTP response into a classified error.
    ///
    /// The status carries the meaning an agent needs to branch on — 403 is
    /// "this session lacks the permission", not "something went wrong" — so it
    /// is mapped here rather than left for a caller to grep out of a message.
    fn err_body(resp: reqwest::blocking::Response) -> CliError {
        use crate::error::Code;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let msg = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or(body);
        let code = match status.as_u16() {
            401 | 403 => Code::Denied,
            404 => Code::NotFound,
            409 => Code::Conflict,
            400 | 422 => Code::Invalid,
            429 | 503 => Code::Unavailable,
            _ => Code::Error,
        };
        CliError::new(code, format!("Server error {status}: {msg}"))
            .with_details(serde_json::json!({ "http_status": status.as_u16() }))
    }

    /// GET a JSON endpoint. `path` starts with `/`.
    pub fn get_json(&self, path: &str) -> CliResult<serde_json::Value> {
        let resp = self
            .client
            .get(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
            .send()
            .map_err(|e| CliError::from(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp));
        }
        resp.json().map_err(|e| CliError::from(e.to_string()))
    }

    /// Send a body-carrying request (POST/PUT/DELETE) and return the parsed JSON,
    /// or `Null` when the server answers 204.
    pub fn send_json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> CliResult<serde_json::Value> {
        let mut req = self
            .client
            .request(method, format!("{}{}", self.base, path))
            .bearer_auth(&self.token);
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().map_err(|e| CliError::from(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp));
        }
        let text = resp.text().unwrap_or_default();
        if text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| CliError::from(e.to_string()))
    }

    pub fn get_vault(&self) -> CliResult<serde_json::Value> {
        let resp = self
            .client
            .get(format!("{}/api/vault", self.base))
            .bearer_auth(&self.token)
            .send()
            .map_err(|e| CliError::from(e.to_string()))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(
                serde_json::json!({ "api_keys": [], "user_categories": [], "projects": [] }),
            );
        }
        if !status.is_success() {
            return Err(Self::err_body(resp));
        }
        resp.json().map_err(|e| CliError::from(e.to_string()))
    }

    pub fn get_expiring(&self, days: u32) -> CliResult<Vec<serde_json::Value>> {
        let v = self.get_json(&format!("/api/vault/expiring?days={days}"))?;
        Ok(v.as_array().cloned().unwrap_or_default())
    }

    pub fn get_audit(&self) -> CliResult<Vec<serde_json::Value>> {
        let v = self.get_json("/api/audit")?;
        Ok(v.as_array().cloned().unwrap_or_default())
    }

    pub fn save_vault(&self, data: &serde_json::Value) -> CliResult {
        self.send_json(reqwest::Method::PUT, "/api/vault", Some(data))
            .map(|_| ())
    }
}

// ── Data access abstraction ───────────────────────────────────────────────────

pub enum Access {
    Local(VaultKey),
    Remote(RemoteClient),
}

impl Access {
    pub fn load_vault(&self) -> CliResult<serde_json::Value> {
        match self {
            Access::Local(key) => {
                let conn = open_db(&default_db_path(), key)?;
                vault_core::load_vault(&conn)
                    .map_err(CliError::from)?
                    .ok_or_else(|| CliError::not_found("Vault is empty"))
            }
            Access::Remote(c) => c.get_vault(),
        }
    }

    /// Like [`Access::load_vault`] but yields an empty vault rather than erroring
    /// when nothing has been written yet — the shape every mutating command wants.
    pub fn load_vault_or_empty(&self) -> CliResult<serde_json::Value> {
        match self.load_vault() {
            Ok(v) => Ok(v),
            Err(e) if e.message == "Vault is empty" => Ok(serde_json::json!({
                "api_keys": [],
                "user_categories": [],
                "projects": [{ "id": "Universal", "name": "Universal",
                               "description": "All keys belong here by default" }],
            })),
            Err(e) => Err(e),
        }
    }

    pub fn expiring(&self, days: u32) -> CliResult<Vec<serde_json::Value>> {
        match self {
            Access::Local(key) => {
                let conn = open_db(&default_db_path(), key)?;
                vault_core::get_expiring_entries(&conn, days).map_err(CliError::from)
            }
            Access::Remote(c) => c.get_expiring(days),
        }
    }

    pub fn save(&self, data: &serde_json::Value) -> CliResult {
        // `--dry-run` stops here, at the single write point, rather than at each
        // command. A command that forgets to check the flag therefore cannot
        // write anyway — the guarantee holds for commands not yet written.
        if crate::out::dry_run() {
            return Ok(());
        }
        match self {
            Access::Local(key) => {
                let conn = open_db(&default_db_path(), key)?;
                // Local CLI access is by definition the master-password holder.
                let actor = vault_core::ensure_owner_user(&conn).ok();
                // Single-process CLI use; nothing else is writing this vault in
                // the same instant, so an unconditional write is correct here.
                vault_core::save_vault(
                    &conn,
                    data.clone(),
                    vault_core::SaveCtx {
                        actor: actor.as_deref(),
                        ..Default::default()
                    },
                )
                .map(|_| ())
                .map_err(CliError::from)
            }
            Access::Remote(c) => c.save_vault(data),
        }
    }

    /// The remote client, when this access is a remote one.
    pub fn remote(&self) -> Option<&RemoteClient> {
        match self {
            Access::Remote(c) => Some(c),
            Access::Local(_) => None,
        }
    }

    /// Open the local SQLCipher connection, or explain why a command that needs
    /// direct DB access cannot run against a remote server.
    pub fn conn(&self) -> CliResult<vault_core::SqlConnection> {
        match self {
            Access::Local(key) => open_db(&default_db_path(), key).map_err(CliError::from),
            Access::Remote(_) => Err(CliError::invalid(
                "This command needs direct database access and cannot run in remote mode",
            )),
        }
    }
}

/// How the caller wants to authenticate. Owner (master password) is the default;
/// `--user`/`--token` switch to the scoped paths, which are remote-only.
pub struct AuthOpts<'a> {
    pub server: Option<&'a str>,
    pub password: Option<&'a str>,
    pub user: Option<&'a str>,
    pub token: Option<&'a str>,
    /// A session token cached by `envv login`. Used only when no other
    /// credential was supplied, so an explicit flag always wins.
    pub session_token: Option<&'a str>,
    /// Create the local vault if it does not exist yet (`--init`).
    pub init: bool,
}

pub fn open_access(opts: &AuthOpts<'_>) -> CliResult<Access> {
    if let Some(base) = opts.server {
        if let Some(session) = opts.session_token {
            // Already a session token: adopt it directly rather than trading it
            // for another one. Its validity is proven by the first real request.
            return Ok(Access::Remote(RemoteClient::with_session(base, session)?));
        }
        if let Some(tok) = opts.token {
            return Ok(Access::Remote(RemoteClient::connect_with_api_token(
                base, tok,
            )?));
        }
        if let Some(username) = opts.user {
            let pw = get_password_for(opts.password, Some(username));
            return Ok(Access::Remote(RemoteClient::connect_as_user(
                base, username, &pw,
            )?));
        }
        let pw = get_password(opts.password);
        return Ok(Access::Remote(RemoteClient::connect(base, &pw)?));
    }
    if opts.user.is_some() || opts.token.is_some() {
        return Err(CliError::invalid(
            "--user / --token require --server (they authenticate against envv-server)",
        ));
    }
    if !default_db_path().exists() && !opts.init {
        return Err(CliError::unavailable(format!(
            "No vault found at {}\nMake sure EnvVault desktop app has been run at least once, or pass --init to create one here.",
            default_db_path().display()
        )));
    }
    if opts.init {
        if let Some(parent) = default_db_path().parent() {
            std::fs::create_dir_all(parent).map_err(|e| CliError::from(e.to_string()))?;
        }
    }
    let pw = get_password(opts.password);
    let key = local_key(&pw)?;
    Ok(Access::Local(key))
}
