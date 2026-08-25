//! `envv` — EnvVault CLI.
//!
//! Works in two modes:
//! - **Local**: reads the Tauri app's SQLCipher DB directly
//!   (`~/.local/share/io.envvault/vault.db`).
//! - **Remote**: connects to a running `envv-server` via HTTP.
//!
//! Set `ENVV_SERVER_URL` or pass `--server` to switch to remote mode. Password is
//! read from `ENVV_PASSWORD`, or prompted. `--user` / `--token` authenticate as a
//! scoped sub-user instead of the vault owner (remote only).
//!
//! Everything the desktop UI can do to vault *data* is reachable here: entries,
//! projects, chunks, categories, tags, users/classes/tokens/permissions,
//! generators, backups, the health scan and audit-chain verification. Config
//! export covers the four stable project types; the experimental ones stay in the
//! app rather than existing as a second implementation that can drift.

use envv_cli::error::{CliError, CliResult};
use envv_cli::{
    access, agentio, backup, chunks, data, enrich, entries, envfile, exec, fmt, gen, out, pool,
    projects, render, scan, session, users_cmd,
};

use access::{open_access, Access, AuthOpts};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use entries::EntryFields;
use std::path::PathBuf;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "envv",
    // Single source of truth: the crate version in Cargo.toml. Never hardcode.
    version,
    about = "EnvVault CLI — manage secrets from the terminal",
    long_about = "Local mode reads the Tauri desktop app vault directly.\n\
                  Remote mode (--server / $ENVV_SERVER_URL) connects to envv-server."
)]
struct Cli {
    /// Remote envv-server URL, e.g. http://localhost:8743.
    /// If set, all commands go through the server instead of the local DB.
    #[arg(long, env = "ENVV_SERVER_URL", global = true)]
    server: Option<String>,

    /// Vault password (avoid in scripts — prefer ENVV_PASSWORD env var or interactive prompt).
    #[arg(long, env = "ENVV_PASSWORD", global = true, hide_env_values = true)]
    password: Option<String>,

    /// Authenticate as this sub-user instead of the vault owner (requires --server).
    ///
    /// The field is `as_user`, not `user`: a `global = true` argument shares its
    /// id with any subcommand argument of the same name, so a plain `user` id
    /// made `envv user token ls deploy` set this flag to "deploy" and refuse to
    /// run without --server.
    #[arg(
        long = "user",
        value_name = "USERNAME",
        env = "ENVV_USER",
        global = true
    )]
    as_user: Option<String>,

    /// Authenticate with an API token instead of a password (requires --server).
    #[arg(
        long = "token",
        value_name = "TOKEN",
        env = "ENVV_TOKEN",
        global = true,
        hide_env_values = true
    )]
    api_token: Option<String>,

    /// Skip confirmation prompts on destructive commands.
    #[arg(long, short = 'y', global = true)]
    yes: bool,

    /// Use this vault.db instead of the desktop app's (local mode only).
    #[arg(long, env = "ENVV_DB_PATH", global = true)]
    db_path: Option<PathBuf>,

    /// Use this vault.salt. Defaults to `vault.salt` beside --db-path.
    #[arg(long, env = "ENVV_SALT_PATH", global = true)]
    salt_path: Option<PathBuf>,

    /// Create the local vault if it does not exist (use with --db-path).
    #[arg(long, global = true)]
    init: bool,

    /// Emit a machine-readable envelope on stdout: {"ok":true,"command":…,"data":…}.
    #[arg(long, global = true)]
    json: bool,

    /// Print real secret values instead of `sha256:…` fingerprints.
    ///
    /// Redaction is the default so that an agent driving this CLI never takes a
    /// secret into its context. `--out <file>` and `envv exec` move real values
    /// without printing them; this flag is for a human at a terminal.
    #[arg(long, global = true)]
    reveal: bool,

    /// Report what a mutating command would change, and write nothing.
    #[arg(long, global = true)]
    dry_run: bool,

    /// Read the vault password from this file (first line).
    #[arg(long, env = "ENVV_PASSWORD_FILE", global = true)]
    password_file: Option<PathBuf>,

    /// Read ENVV_PASSWORD (and ENVV_SERVER_URL) from a Docker-style .env file.
    ///
    /// This is the same file `docker compose` reads to start envv-server, so a
    /// containerised server and the CLI driving it share exactly one copy of the
    /// password — owned by the compose stack, never pasted into a command line.
    #[arg(long, env = "ENVV_ENV_FILE", global = true)]
    env_file: Option<PathBuf>,

    /// Run this command and use its stdout as the vault password.
    ///
    /// Keeps the password out of argv, out of the environment, and out of an
    /// orchestrator's context — `--password-command "pass show envv"`.
    #[arg(long, env = "ENVV_PASSWORD_COMMAND", global = true)]
    password_command: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

// clippy::large_enum_variant — the `Entry` variant carries the whole `EntryCmd`
// subcommand tree and is ~800 bytes against a ~145-byte median. Boxing it is
// clippy's suggested fix and the wrong one here: `#[command(subcommand)]` on a
// `Box<EntryCmd>` is not part of clap's derive contract, and this enum is
// constructed exactly once per process, from argv, and immediately matched. The
// size costs one stack frame at startup.
#[allow(clippy::large_enum_variant)]
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
        /// Filter by tag.
        #[arg(long)]
        tag: Option<String>,
        /// Filter by environment (production, staging, development, testing).
        #[arg(long)]
        env: Option<String>,
        /// Filter by category.
        #[arg(long)]
        category: Option<String>,
        /// Free-text search over provider, account and descriptions.
        #[arg(long, short = 'q')]
        search: Option<String>,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Print full details of a single entry.
    Get {
        /// Provider name (case-insensitive substring match), or provider:key_id.
        ///
        /// Optional only because --pool names the entry instead; one of the two
        /// is required.
        provider: Option<String>,
        /// Print just this field (api_key, username, url, … or an extra_vars key).
        #[arg(long)]
        field: Option<String>,
        /// Take the next key from this pool instead of naming an entry.
        ///
        /// Advances the pool's cursor, so two calls hand back two different
        /// keys. Skips members that `envv pool report --limited` put on cooldown.
        #[arg(long, conflicts_with = "provider")]
        pool: Option<String>,
    },
    /// Export vault entries.
    Export {
        /// Output format: dotenv (default), yaml, json, k8s, tfvars.
        #[arg(long, default_value = "dotenv")]
        format: String,
        /// Only export entries belonging to this project.
        #[arg(long)]
        project: Option<String>,
        /// Name for the generated Kubernetes Secret (k8s format only).
        #[arg(long, default_value = "envvault")]
        name: String,
        /// Write to this file instead of stdout.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
    /// List entries expiring within N days (default: 30).
    RotateCheck {
        #[arg(long, default_value_t = 30)]
        days: u32,
    },
    /// Import entries from a .env file (creates/updates env_var entries).
    Import {
        /// Path to the .env file, or a full-vault JSON export with --json.
        file: PathBuf,
        /// Assign imported variables to this project.
        #[arg(long)]
        project: Option<String>,
        /// Assign imported variables to this category.
        #[arg(long)]
        category: Option<String>,
        /// Environment to stamp on imported variables.
        #[arg(long)]
        env: Option<String>,
        /// Billing model recorded on new entries.
        #[arg(long, default_value = "local")]
        price: String,
        /// Append a second entry for a key that already exists instead of updating it.
        #[arg(long)]
        allow_duplicates: bool,
        /// Treat the file as a full-vault JSON export and replace the vault with it.
        #[arg(long)]
        json: bool,
    },
    /// Show the append-only audit log, or verify its hash chain.
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Recompute the tamper-evident hash chain instead of printing rows.
        #[arg(long)]
        verify: bool,
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
        /// Project to assign new env_var entries to.
        #[arg(long)]
        project: Option<String>,
        /// Category to assign new env_var entries to.
        #[arg(long)]
        category: Option<String>,
    },
    /// Resolve a project's env_file chunks into a deployable .env (${refs} resolved).
    Env {
        /// Project ID (exact) or name (substring match).
        project: String,
        /// Write to this file instead of stdout.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
    /// Create, edit and delete secret entries.
    /// Key pools — several interchangeable credentials for one service.
    ///
    /// Membership is explicit: an entry joins with `entry set <p> --pool <name>`.
    /// Cursor, cooldowns and use counts are per-machine and live outside the
    /// vault, so a pool read never writes to it.
    Pool {
        #[command(subcommand)]
        cmd: PoolCmd,
    },
    Entry {
        #[command(subcommand)]
        cmd: EntryCmd,
    },
    /// Projects, their config chunks and their exports.
    Project {
        #[command(subcommand)]
        cmd: ProjectCmd,
    },
    /// Categories (the flat, slash-nested tags in the sidebar).
    Category {
        #[command(subcommand)]
        cmd: CategoryCmd,
    },
    /// List every tag in the vault with its entry count.
    Tags,
    /// Generators: secrets, passwords, certificates, SSH keys.
    Gen {
        #[command(subcommand)]
        cmd: GenCmd,
    },
    /// Encrypted vault backups (.vaultbak), readable by the desktop app.
    Backup {
        #[command(subcommand)]
        cmd: BackupCmd,
    },
    /// Health scan — weak, expiring, duplicated and stale-reference secrets.
    Scan {
        /// Lowest severity to report: high, med, low (default: low = everything).
        #[arg(long, default_value = "low", value_parser = ["high", "med", "low"])]
        severity: String,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Where this CLI is pointed and what the vault holds.
    Status,
    /// Vault users.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// User classes (role templates).
    Class {
        #[command(subcommand)]
        cmd: ClassCmd,
    },
    /// Permission expressions for users and classes.
    Perm {
        #[command(subcommand)]
        cmd: PermCmd,
    },
    /// Run a command with secrets in its environment — they never reach stdout.
    Exec {
        /// Load every env_file chunk of this project.
        #[arg(long)]
        project: Option<String>,
        /// PROVIDER, PROVIDER=VAR, or PROVIDER=VAR:field. Repeatable.
        #[arg(long = "entry")]
        entries: Vec<String>,
        /// POOL, POOL=VAR, or POOL=VAR:field. Repeatable.
        ///
        /// Takes the next usable key from the pool and advances its cursor, so
        /// consecutive runs use different credentials. The value reaches the
        /// child's environment and never stdout.
        #[arg(long = "pool")]
        pools: Vec<String>,
        /// Prefix every variable name.
        #[arg(long)]
        prefix: Option<String>,
        /// Do not inherit this process's environment (PATH is kept).
        #[arg(long)]
        clean: bool,
        /// The command to run, after `--`.
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Substitute ${refs} in a template file (use `-` for stdin).
    Render {
        /// Template path, or `-` for stdin.
        template: Option<PathBuf>,
        /// Write here instead of stdout. Only a file receives real values.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
        /// Fail if any reference cannot be resolved.
        #[arg(long)]
        strict: bool,
    },
    /// Infer and fill entry metadata from names and public key prefixes.
    Enrich {
        /// Write the proposals. Without it, nothing is changed.
        #[arg(long)]
        apply: bool,
        /// Also replace fields that already have a value.
        #[arg(long)]
        force: bool,
        /// Only consider entries whose provider contains this text.
        #[arg(long)]
        only: Option<String>,
        /// Ask each issuer about its own credential — who it belongs to, its
        /// scopes, its expiry, its rate limit.
        ///
        /// This sends the secret over TLS to the service that issued it, and to
        /// nowhere else. It also reveals dead credentials: an issuer answering
        /// 401 is the only reliable way to learn a stored key was revoked.
        #[arg(long)]
        online: bool,
        /// Per-request timeout for --online, in seconds.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
    /// Print the machine-readable contract: commands, flags, exit codes, schemas.
    Describe,
    /// Authenticate once and cache the session (remote servers).
    ///
    /// Pass --user NAME to sign in as a sub-user; without it you authenticate as
    /// the vault owner. Sessions are cached per server *and* per user, so you can
    /// hold several identities against one server and pick one with --user.
    Login,
    /// Show which identity this CLI would use, and whether its session still works.
    Whoami,
    /// Forget cached sessions.
    Logout {
        /// Forget every server, not just this one.
        #[arg(long)]
        all: bool,
    },
    /// List the cached sessions: which servers, which users, which is default.
    Sessions,
}

#[derive(Subcommand)]
enum EntryCmd {
    /// List entries (same filters as `envv list`).
    Ls {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        r#type: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        env: Option<String>,
        #[arg(long)]
        category: Option<String>,
        #[arg(long, short = 'q')]
        search: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print one entry, or one of its fields.
    Get {
        provider: String,
        #[arg(long)]
        field: Option<String>,
    },
    /// Create a new entry.
    Add {
        /// Provider name — the entry's display name and reference target.
        provider: String,
        #[command(flatten)]
        fields: EntryFields,
        /// Do nothing if an entry with this provider already exists.
        #[arg(long)]
        if_missing: bool,
    },
    /// Change fields on an existing entry.
    Set {
        /// Provider name, or provider:key_id.
        provider: String,
        #[command(flatten)]
        fields: EntryFields,
        /// Create the entry when it does not exist yet (idempotent upsert).
        #[arg(long)]
        create: bool,
    },
    /// Rename an entry, rewriting every ${ref} that points at it.
    Rename { provider: String, new_name: String },
    /// Delete an entry.
    Rm { provider: String },
    /// Add or remove tags.
    Tag {
        provider: String,
        /// Tag to add. Repeatable.
        #[arg(long = "add")]
        add: Vec<String>,
        /// Tag to remove. Repeatable.
        #[arg(long = "remove")]
        remove: Vec<String>,
    },
    /// Pin an entry to the top of every view.
    Pin {
        provider: String,
        /// Unpin instead.
        #[arg(long)]
        off: bool,
    },
    /// Mark an entry as known-leaked (a critical health issue until rotated).
    Compromise {
        provider: String,
        /// Clear the flag instead.
        #[arg(long)]
        off: bool,
    },
    /// Record a rotation, optionally storing the new secret.
    Rotate {
        provider: String,
        /// The new secret value.
        #[arg(long)]
        key: Option<String>,
        /// Read the new secret from stdin.
        #[arg(long, conflicts_with = "key")]
        stdin: bool,
        /// Generate the replacement. It is stored and never printed — the only
        /// rotation an orchestrator can perform without holding the secret.
        #[arg(long, conflicts_with_all = ["key", "stdin"])]
        generate: bool,
    },
    /// Show previous values of an entry's secret.
    History { provider: String },
    /// Restore a previous value by its position in `entry history`.
    Restore { provider: String, version: usize },
}

#[derive(Subcommand)]
enum PoolCmd {
    /// List every pool in the vault with member counts and cooldowns.
    Ls,
    /// Show each member of one pool: use count and whether it is cooling.
    Show { pool: String },
    /// Take the next usable key and advance the cursor.
    ///
    /// Redacted like every other stdout path — `--reveal` opts in, and
    /// `envv exec --pool` uses the value without anyone reading it.
    Next {
        pool: String,
        /// Print a field other than the secret.
        #[arg(long)]
        field: Option<String>,
    },
    /// Report a key as rate limited (or recovered).
    ///
    /// `envv exec` hands the secret to a child process and never sees the
    /// child's HTTP responses, so the CLI cannot detect a 429 by itself. The
    /// caller — which did see it — reports it.
    Report {
        pool: String,
        /// Which member, as `provider:key_id` or a key id. Defaults to the one
        /// this machine took most recently.
        member: Option<String>,
        /// Put the member on cooldown (the default action).
        #[arg(long, conflicts_with = "ok")]
        limited: bool,
        /// Clear the member's cooldown instead.
        #[arg(long)]
        ok: bool,
        /// How long to cool down: 30s, 15m, 2h, 1d. Default 15m.
        #[arg(long = "for")]
        for_dur: Option<String>,
    },
    /// Forget a pool's cursor, cooldowns and counts on this machine.
    Reset { pool: String },
}

#[derive(Subcommand)]
enum ProjectCmd {
    /// List projects with entry and chunk counts.
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// Print a project as JSON, chunks included.
    Show { project: String },
    /// Create a project, with starter chunks for its type.
    Add {
        /// Name. Slash segments nest: "Acme/Web" creates "Acme" if absent.
        name: String,
        /// Pin the project id instead of deriving it from the name.
        ///
        /// The id is what entries, permission rules and scope values point at.
        /// A slug set here survives later renames.
        #[arg(long)]
        slug: Option<String>,
        /// generic (default), wireguard, docker, nginx — or an experimental type with --experimental.
        #[arg(long = "type", default_value = "generic", value_parser = data::ALL_PROJECT_TYPES)]
        ptype: String,
        #[arg(long)]
        desc: Option<String>,
        /// Allow the untested project types (kubernetes, traefik, apache, …).
        #[arg(long)]
        experimental: bool,
        /// Do nothing if a project with this id already exists.
        #[arg(long)]
        if_missing: bool,
    },
    /// Rename a project, carrying its sub-projects and entry links.
    ///
    /// A project whose slug was pinned keeps it; pass --slug to change the id
    /// itself, which remaps every entry that points at the old one.
    Rename {
        project: String,
        /// New display name. Omit to change only the slug.
        new_name: Option<String>,
        /// New slug (project id).
        #[arg(long)]
        slug: Option<String>,
    },
    /// Delete a project; sub-projects are promoted to top level.
    Rm { project: String },
    /// Export a project's config in its native format.
    Export {
        project: String,
        /// wireguard, compose, nginx, env, json. Defaults to the project's type.
        #[arg(long)]
        format: Option<String>,
        /// Write to this file instead of stdout (compose also writes .env beside it).
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
    /// Config chunks inside a project.
    Chunk {
        #[command(subcommand)]
        cmd: ChunkCmd,
    },
}

#[derive(Subcommand)]
enum ChunkCmd {
    /// List a project's chunks.
    Ls { project: String },
    /// Print a chunk as its native config text (or raw JSON with --raw).
    Show {
        project: String,
        chunk: String,
        #[arg(long)]
        raw: bool,
    },
    /// Add an empty chunk.
    Add {
        project: String,
        name: String,
        #[arg(long = "type", value_parser = chunks::CHUNK_TYPES)]
        ctype: String,
    },
    /// Delete a chunk.
    Rm { project: String, chunk: String },
    /// Rename a chunk, rewriting ${chunk:…} references to it.
    Rename {
        project: String,
        chunk: String,
        new_name: String,
    },
    /// Set fields as key=value pairs.
    Set {
        project: String,
        chunk: String,
        /// key=value. Repeatable.
        pairs: Vec<String>,
        /// Field type recorded for new fields.
        #[arg(long = "field-type", default_value = "var", value_parser = chunks::FIELD_TYPES)]
        field_type: String,
        /// Mark the field as secret (masked in the UI).
        #[arg(long)]
        secret: bool,
        /// Add another field with this key instead of replacing the existing one
        /// (nginx takes repeated directives such as two `listen` lines).
        #[arg(long)]
        append: bool,
    },
    /// Remove fields by key.
    Unset {
        project: String,
        chunk: String,
        keys: Vec<String>,
    },
    /// Exclude a chunk from exports without deleting it.
    Disable { project: String, chunk: String },
    /// Re-include a disabled chunk.
    Enable { project: String, chunk: String },
}

#[derive(Subcommand)]
enum CategoryCmd {
    Ls,
    Add {
        name: String,
    },
    Rename {
        name: String,
        new_name: String,
    },
    /// Delete a category and its slash-nested children.
    Rm {
        name: String,
    },
}

#[derive(Subcommand)]
enum GenCmd {
    /// Random bytes as hex / base64 / base64url.
    Secret {
        #[arg(long, default_value_t = 32)]
        bytes: usize,
        #[arg(long, default_value = "hex", value_parser = ["hex", "base64", "base64url"])]
        format: String,
    },
    /// A password from the selected character sets.
    Password {
        #[arg(long, default_value_t = 24)]
        length: usize,
        /// Exclude uppercase letters.
        #[arg(long)]
        no_upper: bool,
        /// Exclude lowercase letters.
        #[arg(long)]
        no_lower: bool,
        /// Exclude digits.
        #[arg(long)]
        no_digits: bool,
        /// Include symbols.
        #[arg(long)]
        symbols: bool,
        /// Drop visually ambiguous characters (0/O, 1/l/I).
        #[arg(long)]
        no_ambiguous: bool,
    },
    /// A self-signed certificate and its private key.
    Cert {
        /// Common name (hostname).
        common_name: String,
        #[arg(long, default_value_t = 365)]
        days: u32,
        /// Store as a new certificate entry with this provider name.
        #[arg(long)]
        save_as: Option<String>,
    },
    /// An ed25519 SSH keypair.
    Ssh {
        #[arg(long, default_value = "")]
        comment: String,
        /// Store as a new ssh_key entry with this provider name.
        #[arg(long)]
        save_as: Option<String>,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    /// Write an encrypted .vaultbak the desktop app can restore.
    Export {
        file: PathBuf,
        /// Backup password (min 12 chars). Prompted when omitted.
        #[arg(long, hide_env_values = true)]
        backup_password: Option<String>,
    },
    /// Restore a .vaultbak, replacing the current vault.
    Import {
        file: PathBuf,
        #[arg(long, hide_env_values = true)]
        backup_password: Option<String>,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// Create a user. Prompts for a password unless --no-password.
    Add {
        username: String,
        #[arg(long, hide_env_values = true)]
        user_password: Option<String>,
        /// Token-only user — no password login.
        #[arg(long)]
        no_password: bool,
    },
    Rm {
        user: String,
    },
    Rename {
        user: String,
        new_name: String,
    },
    /// Set or clear a user's password.
    Passwd {
        user: String,
        /// Clear the password, leaving token-only auth.
        #[arg(long)]
        clear: bool,
    },
    /// Assign a class, or remove the current one with --none.
    Class {
        user: String,
        class: Option<String>,
        #[arg(long)]
        none: bool,
    },
    /// API tokens for a user.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    Ls {
        user: String,
    },
    /// Mint a token. Write it to a file with --out so it never reaches stdout.
    New {
        user: String,
        #[arg(long)]
        desc: Option<String>,
        /// ISO-8601 expiry.
        #[arg(long)]
        expires: Option<String>,
        /// Write the token to this file (0600) instead of printing it.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
    Revoke {
        user: String,
        token_id: String,
    },
}

#[derive(Subcommand)]
enum ClassCmd {
    Ls {
        #[arg(long)]
        json: bool,
    },
    Add {
        name: String,
        #[arg(long, default_value = "")]
        desc: String,
        #[arg(long)]
        manage_users: bool,
        #[arg(long)]
        manage_classes: bool,
        #[arg(long)]
        delete_projects: bool,
    },
    /// Replace a class's name, description and capabilities.
    Set {
        class: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        desc: Option<String>,
        #[arg(long)]
        manage_users: bool,
        #[arg(long)]
        manage_classes: bool,
        #[arg(long)]
        delete_projects: bool,
    },
    Rm {
        class: String,
    },
}

#[derive(Subcommand)]
enum PermCmd {
    /// Show the read/write expressions for a user or class.
    Show {
        #[arg(value_parser = ["user", "class"])]
        kind: String,
        subject: String,
    },
    /// Set the read and/or write expression. An empty value denies everything.
    ///
    /// Syntax: `project:Alpha AND NOT category:secret`, `tag:shared OR type:certificate`.
    /// Fields: vault, project, category, tag, env, type. Operators: AND, OR, NOT, ().
    Set {
        #[arg(value_parser = ["user", "class"])]
        kind: String,
        subject: String,
        #[arg(long)]
        read: Option<String>,
        #[arg(long)]
        write: Option<String>,
    },
    /// Parse an expression without storing it.
    Check { expression: String },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    out::init(out::Mode {
        json: cli.json,
        reveal: cli.reveal,
        dry_run: cli.dry_run,
    });

    // `completions` and `describe` write a document and must never ask for a
    // password — they are the two commands a caller runs *before* it has one.
    match &cli.command {
        Commands::Completions { shell } => {
            generate(*shell, &mut Cli::command(), "envv", &mut std::io::stdout());
            return;
        }
        Commands::Describe => {
            let doc = agentio::describe(&Cli::command());
            println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
            return;
        }
        _ => {}
    }
    // Neither do the generators, unless they are asked to save into the vault.
    if let Commands::Gen { cmd } = &cli.command {
        if let Some(result) = run_gen_offline(cmd) {
            finish(result);
            return;
        }
    }

    finish(run(&cli));
}

fn run(cli: &Cli) -> CliResult {
    access::set_paths(cli.db_path.clone(), cli.salt_path.clone());

    // A compose `.env` supplies both halves of a local server connection, and an
    // explicit flag always wins over it.
    let dotenv = match cli.env_file.as_deref() {
        Some(path) => session::read_dotenv(path)?,
        None => Vec::new(),
    };
    let dotenv_get = |key: &str| {
        dotenv
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };

    let password = session::resolve_password(
        cli.password.as_deref(),
        cli.password_file.as_deref(),
        cli.password_command.as_deref(),
    )?
    .or_else(|| dotenv_get("ENVV_PASSWORD"));

    let server = cli.server.clone().or_else(|| dotenv_get("ENVV_SERVER_URL"));

    // A cached session stands in for a password, so an agent can run every
    // command in this CLI without ever holding a credential.
    //
    // `--user` used to disable this, which made the documented flow fail in the
    // most confusing way available: `envv login --user alice` cached a session,
    // and then `envv --user alice list` ignored it and prompted for a password
    // every single time — while dropping `--user` worked. Sessions are filed by
    // subject now, so naming the subject selects one instead of suppressing it.
    //
    // An explicit `--token` or password still wins: passing a credential is an
    // instruction to use it.
    let cached = server
        .as_deref()
        .filter(|_| cli.api_token.is_none() && password.is_none())
        .and_then(|url| session::load(url, cli.as_user.as_deref()));

    let auth = AuthOpts {
        server: server.as_deref(),
        password: password.as_deref(),
        user: cli.as_user.as_deref(),
        token: cli.api_token.as_deref(),
        session_token: cached.as_deref(),
        init: cli.init,
    };

    match &cli.command {
        Commands::Login => return cmd_login(cli, password.as_deref()),
        Commands::Whoami => return cmd_whoami(cli),
        Commands::Sessions => return cmd_sessions(),
        Commands::Logout { all } => return cmd_logout(cli, *all),
        _ => {}
    }

    let access = open_access(&auth)?;
    let result = dispatch(cli, &access);

    // A cached session that the server no longer knows is not a permissions
    // problem the caller can fix by retrying — drop it and say so, or every
    // later command fails the same way with the same unhelpful 401.
    if let (Err(e), Some(server), true) = (&result, server.as_deref(), cached.is_some()) {
        if e.code == envv_cli::error::Code::Denied {
            // Clear only the identity that was actually used. Dropping every
            // session for the server because one expired would log the other
            // cached users out too, which they would discover one at a time.
            let subject = cli.as_user.clone().or_else(|| {
                session::describe(server)?
                    .get("default")?
                    .as_str()
                    .map(String::from)
            });
            let _ = session::clear(server, subject.as_deref());
            let as_who = subject
                .as_deref()
                .filter(|s| *s != session::OWNER_SUBJECT)
                .map(|s| format!(" --user {s}"))
                .unwrap_or_default();
            return Err(CliError::denied(format!(
                "{}\nThe cached session was rejected and has been cleared — run `envv login --server {server}{as_who}` again.",
                e.message
            )));
        }
    }
    result
}

fn finish(result: CliResult) {
    match result {
        Ok(()) => {}
        Err(e) => {
            if out::is_json() {
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

// ── login / logout ────────────────────────────────────────────────────────────

fn cmd_login(cli: &Cli, password: Option<&str>) -> CliResult {
    let Some(server) = cli.server.as_deref() else {
        return Err(CliError::invalid(
            "`envv login` caches a session for a remote server — pass --server URL.\n\
             Local vaults have no session to cache; use --password-command instead.",
        ));
    };
    // Authenticating here is exactly what `open_access` would do; the difference
    // is that the resulting session token is kept, so nothing after this needs a
    // credential.
    let auth = AuthOpts {
        server: Some(server),
        password,
        user: cli.as_user.as_deref(),
        token: cli.api_token.as_deref(),
        session_token: None,
        init: false,
    };
    let access = open_access(&auth)?;
    let Some(remote) = access.remote() else {
        return Err(CliError::invalid("login is only meaningful in remote mode"));
    };
    // `<owner>` rather than "owner": this is a key in the session file alongside
    // real usernames, and a sub-user actually named "owner" must not be able to
    // occupy the owner's slot.
    let subject = cli.as_user.as_deref().unwrap_or(session::OWNER_SUBJECT);
    session::save(server, &remote.token, subject)?;
    let label = if subject == session::OWNER_SUBJECT {
        "the vault owner"
    } else {
        subject
    };
    out::ok(
        "login",
        serde_json::json!({
            "server": server,
            "subject": subject,
            "session_file": session::session_path().display().to_string(),
        }),
        || {
            println!("Logged in to {server} as {label}");
            println!("Session cached in {}", session::session_path().display());
        },
    );
    Ok(())
}

/// Who this CLI would authenticate as, and whether that still works.
///
/// Exists because every other answer to "who am I?" was indirect: the session
/// file is redacted on principle, and the only way to find out was to run a
/// command and see whose data came back. A scoped user seeing fewer entries than
/// expected cannot tell a permission problem from being logged in as the wrong
/// person.
fn cmd_whoami(cli: &Cli) -> CliResult {
    let Some(server) = cli.server.as_deref() else {
        out::ok(
            "whoami",
            serde_json::json!({ "mode": "local", "subject": "owner" }),
            || {
                println!("Local vault at {}", access::default_db_path().display());
                println!("Authenticated as the vault owner (by deriving the key).");
            },
        );
        return Ok(());
    };

    let entry = session::describe(server);
    let subject = cli
        .as_user
        .clone()
        .or_else(|| entry.as_ref()?.get("default")?.as_str().map(String::from));

    let Some(subject) = subject else {
        return Err(CliError::denied(format!(
            "No cached session for {server}. Run: envv login --server {server} [--user NAME]"
        )));
    };
    let Some(token) = session::load(server, Some(&subject)) else {
        return Err(CliError::denied(format!(
            "No cached session for {subject} at {server}. Run: envv login --server {server} --user {subject}"
        )));
    };

    // Prove the session rather than describe it. A cached token that the server
    // has since rejected looks identical on disk to a working one, and reporting
    // a dead session as a live identity is worse than reporting nothing.
    let client = access::RemoteClient::with_session(server, &token);
    let live = client.ping().is_ok();

    let created = entry
        .as_ref()
        .and_then(|e| {
            e.get("subjects")?
                .get(&subject)?
                .get("created_at")?
                .as_str()
        })
        .unwrap_or("unknown")
        .to_string();
    let others: Vec<String> = entry
        .as_ref()
        .and_then(|e| {
            e.get("subjects")?
                .as_object()
                .map(|m| m.keys().cloned().collect())
        })
        .unwrap_or_default();

    out::ok(
        "whoami",
        serde_json::json!({
            "mode": "remote",
            "server": server,
            "subject": subject,
            "session_valid": live,
            "created_at": created,
            "cached_subjects": others,
        }),
        || {
            let label = if subject == session::OWNER_SUBJECT {
                "the vault owner"
            } else {
                &subject
            };
            println!("{label} @ {server}");
            println!(
                "Session cached {created}, {}",
                if live {
                    "valid"
                } else {
                    "REJECTED — log in again"
                }
            );
            if others.len() > 1 {
                println!("Other cached identities here: {}", others.join(", "));
            }
        },
    );
    Ok(())
}

fn cmd_logout(cli: &Cli, all: bool) -> CliResult {
    if all {
        session::clear_all()?;
        out::ok("logout", serde_json::json!({ "cleared": "all" }), || {
            println!("Cleared every cached session")
        });
        return Ok(());
    }
    let Some(server) = cli.server.as_deref() else {
        return Err(CliError::invalid(
            "Pass --server URL, or --all to clear every session",
        ));
    };
    // `--user alice` forgets only alice; without it the server's every identity
    // goes. Logging one person out of a shared workstation must not silently log
    // everyone else out too.
    let subject = cli.as_user.as_deref();
    session::clear(server, subject)?;
    out::ok(
        "logout",
        serde_json::json!({ "cleared": server, "subject": subject }),
        || match subject {
            Some(u) => println!("Cleared the cached session for {u} at {server}"),
            None => println!("Cleared every cached session for {server}"),
        },
    );
    Ok(())
}

/// Every cached identity, without the tokens.
///
/// The session file is 0600 and holds live bearer credentials; this prints who
/// is cached where, which is the part a human needs and the part that is safe to
/// put on a terminal.
fn cmd_sessions() -> CliResult {
    let all = session::list_all();
    let mut rows: Vec<serde_json::Value> = Vec::new();
    if let Some(obj) = all.as_object() {
        for (url, entry) in obj {
            let default = entry.get("default").and_then(|d| d.as_str()).unwrap_or("");
            if let Some(subs) = entry.get("subjects").and_then(|s| s.as_object()) {
                for (subject, meta) in subs {
                    rows.push(serde_json::json!({
                        "server": url,
                        "subject": subject,
                        "default": subject == default,
                        "created_at": meta.get("created_at").cloned().unwrap_or(serde_json::Value::Null),
                    }));
                }
            }
        }
    }
    out::ok(
        "sessions",
        serde_json::json!({ "sessions": rows, "session_file": session::session_path().display().to_string() }),
        || {
            if rows.is_empty() {
                println!("No cached sessions. Run: envv login --server URL [--user NAME]");
                return;
            }
            for r in &rows {
                let mark = if r["default"].as_bool() == Some(true) {
                    "*"
                } else {
                    " "
                };
                println!(
                    "{mark} {:<24} {:<40} {}",
                    r["subject"].as_str().unwrap_or(""),
                    r["server"].as_str().unwrap_or(""),
                    r["created_at"].as_str().unwrap_or("")
                );
            }
            println!("\n* = used when --user is omitted");
        },
    );
    Ok(())
}

/// Generators that need no vault. Returns `None` when the command asked to save,
/// which does need one.
fn run_gen_offline(cmd: &GenCmd) -> Option<CliResult> {
    match cmd {
        GenCmd::Secret { bytes, format } => Some(gen::secret(*bytes, format).map(|v| {
            emit_generated("gen.secret", &v);
        })),
        GenCmd::Password { length, no_upper, no_lower, no_digits, symbols, no_ambiguous } => {
            let opts = gen::PwOpts {
                length: *length,
                upper: !no_upper,
                lower: !no_lower,
                digits: !no_digits,
                symbols: *symbols,
                no_ambiguous: *no_ambiguous,
            };
            Some(gen::password(&opts).map(|(pw, entropy)| {
                out::ok(
                    "gen.password",
                    serde_json::json!({
                        "value": if out::revealing() { serde_json::json!(pw) } else { out::masked_json(&pw) },
                        "entropy_bits": entropy.round(),
                    }),
                    || {
                        if out::revealing() {
                            println!("{pw}");
                        } else {
                            println!("{}", out::masked(&pw));
                            eprintln!("Redacted. Use --reveal to print it, or `envv entry add NAME --generate --generate-format password` to store it directly.");
                        }
                        eprintln!("{entropy:.0} bits of entropy");
                    },
                );
            }))
        }
        GenCmd::Cert { save_as: Some(_), .. } | GenCmd::Ssh { save_as: Some(_), .. } => None,
        GenCmd::Cert { common_name, days, .. } => Some(gen::certificate(common_name, *days).map(|v| {
            let cert = v.get("cert_pem").and_then(|c| c.as_str()).unwrap_or("").to_string();
            let key = v.get("key_pem").and_then(|c| c.as_str()).unwrap_or("").to_string();
            out::ok(
                "gen.cert",
                serde_json::json!({
                    "cert_pem": if out::revealing() { serde_json::json!(cert) } else { out::masked_json(&cert) },
                    "key_pem":  if out::revealing() { serde_json::json!(key)  } else { out::masked_json(&key)  },
                }),
                || {
                    if out::revealing() {
                        print!("{cert}{key}");
                    } else {
                        println!("cert {}", out::masked(&cert));
                        println!("key  {}", out::masked(&key));
                        eprintln!("Redacted. Use --reveal, or --save-as NAME to store it in the vault.");
                    }
                },
            );
        })),
        GenCmd::Ssh { comment, .. } => Some(gen::ssh_keypair(comment).map(|v| {
            let pubkey = v.get("public_key").and_then(|c| c.as_str()).unwrap_or("").to_string();
            let private = v.get("private_key_openssh").and_then(|c| c.as_str()).unwrap_or("").to_string();
            out::ok(
                "gen.ssh",
                serde_json::json!({
                    // A public key is public: printing it is the point.
                    "public_key": pubkey,
                    "private_key": if out::revealing() { serde_json::json!(private) } else { out::masked_json(&private) },
                }),
                || {
                    println!("{pubkey}");
                    if out::revealing() {
                        print!("{private}");
                    } else {
                        println!("private {}", out::masked(&private));
                        eprintln!("Redacted. Use --reveal, or --save-as NAME to store it in the vault.");
                    }
                },
            );
        })),
    }
}

fn emit_generated(command: &str, value: &str) {
    out::ok(
        command,
        serde_json::json!({
            "value": if out::revealing() { serde_json::json!(value) } else { out::masked_json(value) },
        }),
        || {
            if out::revealing() {
                println!("{value}");
            } else {
                println!("{}", out::masked(value));
                eprintln!("Redacted. Use --reveal to print it, or store it directly with `envv entry add NAME --generate`.");
            }
        },
    );
}

fn dispatch(cli: &Cli, a: &Access) -> CliResult {
    let yes = cli.yes;
    match &cli.command {
        Commands::Completions { .. }
        | Commands::Describe
        | Commands::Login
        | Commands::Whoami
        | Commands::Sessions
        | Commands::Logout { .. } => Ok(()),

        Commands::List {
            project,
            r#type,
            tag,
            env,
            category,
            search,
            json,
        } => entries::cmd_list(
            a,
            project.as_deref(),
            r#type.as_deref(),
            tag.as_deref(),
            env.as_deref(),
            category.as_deref(),
            search.as_deref(),
            *json,
        ),
        Commands::Get {
            provider,
            field,
            pool: pool_name,
        } => match (provider, pool_name) {
            (_, Some(name)) => pool::cmd_next(a, name, field.as_deref()),
            (Some(p), None) => entries::cmd_get(a, p, field.as_deref()),
            // clap cannot express "exactly one of a positional and a flag", so
            // the check lives here. `invalid` rather than a usage error: the
            // command was well-formed, it just did not say which entry.
            (None, None) => Err(CliError::invalid(
                "Name an entry, or pass --pool <name> to take the next key from a pool",
            )),
        },
        Commands::Export {
            format,
            project,
            name,
            out,
        } => envfile::export_vault(a, format, project.as_deref(), name, out.as_deref()),
        Commands::RotateCheck { days } => {
            let list = a.expiring(*days)?;
            let safe = out::redact_entries(&list);
            out::ok(
                "rotate-check",
                serde_json::json!({ "days": days, "count": safe.len(), "entries": safe }),
                || {
                    if list.is_empty() {
                        println!("No secrets expiring within {days} days.");
                    } else {
                        println!("{} secret(s) expiring within {days} days:\n", list.len());
                        fmt::fmt_entries(&list);
                    }
                },
            );
            Ok(())
        }
        Commands::Import {
            file,
            project,
            category,
            env,
            price,
            allow_duplicates,
            json,
        } => {
            if *json {
                envfile::import_json(a, file, yes)
            } else {
                envfile::import(
                    a,
                    file,
                    &envfile::ImportOpts {
                        project: project.as_deref(),
                        category: category.as_deref(),
                        environment: env.as_deref(),
                        price,
                        allow_duplicates: *allow_duplicates,
                    },
                )
            }
        }
        Commands::Audit { limit, verify } => {
            if *verify {
                scan::cmd_verify(a)
            } else {
                cmd_audit(a, *limit)
            }
        }
        Commands::Watch {
            file,
            project,
            category,
        } => envfile::watch(
            a,
            file,
            &envfile::ImportOpts {
                project: project.as_deref(),
                category: category.as_deref(),
                environment: None,
                price: "local",
                allow_duplicates: false,
            },
        ),
        Commands::Env { project, out } => chunks::export(a, project, Some("env"), out.as_deref()),

        Commands::Exec {
            project,
            entries: entry_specs,
            pools: pool_specs,
            prefix,
            clean,
            argv,
        } => {
            let opts = exec::ExecOpts {
                project: project.as_deref(),
                entries: entry_specs,
                pools: pool_specs,
                prefix: prefix.as_deref(),
                clean: *clean,
            };
            let code = exec::run(a, &opts, argv)?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Commands::Render {
            template,
            out,
            strict,
        } => render::cmd_render(a, template.as_deref(), out.as_deref(), *strict),

        Commands::Pool { cmd } => match cmd {
            PoolCmd::Ls => pool::cmd_ls(a),
            PoolCmd::Show { pool: name } => pool::cmd_show(a, name),
            PoolCmd::Next { pool: name, field } => pool::cmd_next(a, name, field.as_deref()),
            PoolCmd::Report {
                pool: name,
                member,
                limited,
                ok,
                for_dur,
            } => pool::cmd_report(
                a,
                name,
                member.as_deref(),
                // `--limited` is the default action: reporting a key and saying
                // nothing else means it just failed. `--ok` is the only way to
                // clear a cooldown, so silence can never accidentally do that.
                !*ok || *limited,
                for_dur.as_deref(),
            ),
            PoolCmd::Reset { pool: name } => pool::cmd_reset(a, name),
        },

        Commands::Entry { cmd } => match cmd {
            EntryCmd::Ls {
                project,
                r#type,
                tag,
                env,
                category,
                search,
                json,
            } => entries::cmd_list(
                a,
                project.as_deref(),
                r#type.as_deref(),
                tag.as_deref(),
                env.as_deref(),
                category.as_deref(),
                search.as_deref(),
                *json,
            ),
            EntryCmd::Get { provider, field } => entries::cmd_get(a, provider, field.as_deref()),
            EntryCmd::Add {
                provider,
                fields,
                if_missing,
            } => entries::cmd_add(a, provider, fields, *if_missing),
            EntryCmd::Set {
                provider,
                fields,
                create,
            } => entries::cmd_set(a, provider, fields, *create),
            EntryCmd::Rename { provider, new_name } => entries::cmd_rename(a, provider, new_name),
            EntryCmd::Rm { provider } => entries::cmd_rm(a, provider, yes),
            EntryCmd::Tag {
                provider,
                add,
                remove,
            } => entries::cmd_tag(a, provider, add, remove),
            EntryCmd::Pin { provider, off } => entries::cmd_flag(a, provider, "pinned", !*off),
            EntryCmd::Compromise { provider, off } => {
                entries::cmd_flag(a, provider, "compromised", !*off)
            }
            EntryCmd::Rotate {
                provider,
                key,
                stdin,
                generate,
            } => entries::cmd_rotate(a, provider, key.as_deref(), *stdin, *generate),
            EntryCmd::History { provider } => entries::cmd_history(a, provider),
            EntryCmd::Restore { provider, version } => {
                entries::cmd_restore(a, provider, *version, yes)
            }
        },

        Commands::Project { cmd } => match cmd {
            ProjectCmd::Ls { json } => projects::cmd_ls(a, *json),
            ProjectCmd::Show { project } => projects::cmd_show(a, project),
            ProjectCmd::Add {
                name,
                ptype,
                desc,
                slug,
                experimental,
                if_missing,
            } => projects::cmd_add(
                a,
                name,
                ptype,
                desc.as_deref(),
                slug.as_deref(),
                *experimental,
                *if_missing,
            ),
            ProjectCmd::Rename {
                project,
                new_name,
                slug,
            } => {
                if new_name.is_none() && slug.is_none() {
                    return Err(CliError::invalid(
                        "Nothing to change — give a new name, --slug, or both",
                    ));
                }
                projects::cmd_rename(a, project, new_name.as_deref(), slug.as_deref())
            }
            ProjectCmd::Rm { project } => projects::cmd_rm(a, project, yes),
            ProjectCmd::Export {
                project,
                format,
                out,
            } => chunks::export(a, project, format.as_deref(), out.as_deref()),
            ProjectCmd::Chunk { cmd } => match cmd {
                ChunkCmd::Ls { project } => chunks::ls(a, project),
                ChunkCmd::Show {
                    project,
                    chunk,
                    raw,
                } => chunks::show(a, project, chunk, *raw),
                ChunkCmd::Add {
                    project,
                    name,
                    ctype,
                } => chunks::add(a, project, name, ctype),
                ChunkCmd::Rm { project, chunk } => chunks::rm(a, project, chunk, yes),
                ChunkCmd::Rename {
                    project,
                    chunk,
                    new_name,
                } => chunks::rename(a, project, chunk, new_name),
                ChunkCmd::Set {
                    project,
                    chunk,
                    pairs,
                    field_type,
                    secret,
                    append,
                } => chunks::set(a, project, chunk, pairs, field_type, *secret, *append),
                ChunkCmd::Unset {
                    project,
                    chunk,
                    keys,
                } => chunks::unset(a, project, chunk, keys),
                ChunkCmd::Disable { project, chunk } => chunks::toggle(a, project, chunk, true),
                ChunkCmd::Enable { project, chunk } => chunks::toggle(a, project, chunk, false),
            },
        },

        Commands::Category { cmd } => match cmd {
            CategoryCmd::Ls => projects::cat_ls(a),
            CategoryCmd::Add { name } => projects::cat_add(a, name),
            CategoryCmd::Rename { name, new_name } => projects::cat_rename(a, name, new_name),
            CategoryCmd::Rm { name } => projects::cat_rm(a, name, yes),
        },

        Commands::Tags => entries::cmd_tags(a),

        Commands::Gen { cmd } => match cmd {
            GenCmd::Cert {
                common_name,
                days,
                save_as,
            } => {
                let v = gen::certificate(common_name, *days)?;
                let provider = save_as.as_deref().unwrap_or(common_name);
                let fields = EntryFields {
                    secret_type: Some("certificate".into()),
                    cert: v.get("cert_pem").and_then(|c| c.as_str()).map(String::from),
                    cert_key: v.get("key_pem").and_then(|c| c.as_str()).map(String::from),
                    cert_issuer: Some("EnvV".into()),
                    key: Some(
                        v.get("cert_pem")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string(),
                    ),
                    generate_bytes: 32,
                    generate_format: "base64url".into(),
                    ..Default::default()
                };
                entries::cmd_add(a, provider, &fields, false)
            }
            GenCmd::Ssh { comment, save_as } => {
                let v = gen::ssh_keypair(comment)?;
                let provider = save_as.as_deref().unwrap_or("ssh-key");
                let fields = EntryFields {
                    secret_type: Some("ssh_key".into()),
                    key: v
                        .get("private_key_openssh")
                        .and_then(|c| c.as_str())
                        .map(String::from),
                    notes: v
                        .get("public_key")
                        .and_then(|c| c.as_str())
                        .map(String::from),
                    generate_bytes: 32,
                    generate_format: "base64url".into(),
                    ..Default::default()
                };
                entries::cmd_add(a, provider, &fields, false)
            }
            // The offline generators were handled before the vault was opened.
            _ => Ok(()),
        },

        Commands::Backup { cmd } => match cmd {
            BackupCmd::Export {
                file,
                backup_password,
            } => backup::export(a, file, backup_password.as_deref()),
            BackupCmd::Import {
                file,
                backup_password,
            } => backup::import(a, file, backup_password.as_deref(), yes),
        },

        Commands::Enrich {
            apply,
            force,
            only,
            online,
            timeout,
        } => enrich::cmd_enrich(
            a,
            &enrich::EnrichOpts {
                apply: *apply,
                force: *force,
                only: only.as_deref(),
                online: *online,
                timeout_secs: *timeout,
            },
        ),
        Commands::Scan { severity, json } => scan::cmd_scan(a, severity, *json),
        Commands::Status => scan::cmd_status(a),

        Commands::User { cmd } => match cmd {
            UserCmd::Ls { json } => users_cmd::user_ls(a, *json),
            UserCmd::Add {
                username,
                user_password,
                no_password,
            } => users_cmd::user_add(a, username, user_password.as_deref(), *no_password),
            UserCmd::Rm { user } => users_cmd::user_rm(a, user, yes),
            UserCmd::Rename { user, new_name } => users_cmd::user_rename(a, user, new_name),
            UserCmd::Passwd { user, clear } => users_cmd::user_passwd(a, user, *clear),
            UserCmd::Class { user, class, none } => {
                let target = if *none { None } else { class.as_deref() };
                if target.is_none() && !*none {
                    return Err(CliError::invalid(
                        "Name a class, or pass --none to unassign",
                    ));
                }
                users_cmd::user_class(a, user, target)
            }
            UserCmd::Token { cmd } => match cmd {
                TokenCmd::Ls { user } => users_cmd::token_ls(a, user),
                TokenCmd::New {
                    user,
                    desc,
                    expires,
                    out,
                } => users_cmd::token_new(
                    a,
                    user,
                    desc.as_deref(),
                    expires.as_deref(),
                    out.as_deref(),
                ),
                TokenCmd::Revoke { user, token_id } => {
                    users_cmd::token_revoke(a, user, token_id, yes)
                }
            },
        },

        Commands::Class { cmd } => match cmd {
            ClassCmd::Ls { json } => users_cmd::class_ls(a, *json),
            ClassCmd::Add {
                name,
                desc,
                manage_users,
                manage_classes,
                delete_projects,
            } => users_cmd::class_add(
                a,
                name,
                desc,
                &users_cmd::ClassCaps {
                    manage_users: *manage_users,
                    manage_classes: *manage_classes,
                    delete_projects: *delete_projects,
                },
            ),
            ClassCmd::Set {
                class,
                name,
                desc,
                manage_users,
                manage_classes,
                delete_projects,
            } => users_cmd::class_set(
                a,
                class,
                name.as_deref(),
                desc.as_deref(),
                &users_cmd::ClassCaps {
                    manage_users: *manage_users,
                    manage_classes: *manage_classes,
                    delete_projects: *delete_projects,
                },
            ),
            ClassCmd::Rm { class } => users_cmd::class_rm(a, class, yes),
        },

        Commands::Perm { cmd } => match cmd {
            PermCmd::Show { kind, subject } => users_cmd::perm_show(a, kind, subject),
            PermCmd::Set {
                kind,
                subject,
                read,
                write,
            } => users_cmd::perm_set(a, kind, subject, read.as_deref(), write.as_deref()),
            PermCmd::Check { expression } => users_cmd::perm_check(expression),
        },
    }
}

fn cmd_audit(access: &Access, limit: usize) -> CliResult {
    let rows: Vec<serde_json::Value> = match access {
        Access::Local(_) => {
            let conn = access.conn()?;
            vault_core::load_audit(&conn)
                .map_err(CliError::from)?
                .into_iter()
                .take(limit)
                .map(|r| {
                    serde_json::json!({
                        "id": r.id, "action": r.action, "entry_provider": r.entry_provider,
                        "timestamp": r.timestamp, "details": r.details,
                        "entry_hash": r.entry_hash, "prev_hash": r.prev_hash, "actor": r.actor,
                    })
                })
                .collect()
        }
        Access::Remote(c) => c.get_audit()?.into_iter().take(limit).collect(),
    };

    out::ok(
        "audit",
        serde_json::json!({ "count": rows.len(), "rows": rows }),
        || {
            println!(
                "{:<6} {:<10} {:<25} {:<22} Hash prefix",
                "ID", "Action", "Provider", "Timestamp"
            );
            println!("{}", "-".repeat(80));
            for r in &rows {
                let hash_prefix = r
                    .get("entry_hash")
                    .and_then(|h| h.as_str())
                    .map(|h| h.chars().take(12).collect::<String>())
                    .unwrap_or_else(|| "—".into());
                println!(
                    "{:<6} {:<10} {:<25} {:<22} {}",
                    r.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
                    r.get("action").and_then(|v| v.as_str()).unwrap_or(""),
                    r.get("entry_provider")
                        .and_then(|v| v.as_str())
                        .unwrap_or("—"),
                    r.get("timestamp").and_then(|v| v.as_str()).unwrap_or(""),
                    hash_prefix,
                );
            }
        },
    );
    Ok(())
}
