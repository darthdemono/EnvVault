//! `unv` — UnENVerse CLI.
//!
//! Works in two modes:
//! - **Local**: reads the Tauri app's SQLCipher DB directly
//!   (`~/.local/share/io.envvault/vault.db`).
//! - **Remote**: connects to a running `unv-server` via HTTP.
//!
//! Set `UNV_SERVER_URL` or pass `--server` to switch to remote mode. Password is
//! read from `UNV_PASSWORD`, or prompted. `--user` / `--token` authenticate as a
//! scoped sub-user instead of the vault owner (remote only).
//!
//! Everything the desktop UI can do to vault *data* is reachable here: entries,
//! projects, chunks, categories, tags, users/classes/tokens/permissions,
//! generators, backups, the health scan and audit-chain verification. Config
//! export covers the four stable project types; the experimental ones stay in the
//! app rather than existing as a second implementation that can drift.

use envv_cli::error::{CliError, CliResult};
use envv_cli::{
    access, agentio, backup, blast_cmd, bundle_cmd, check_cmd, chunks, cxf_cmd, data, doctor,
    emit_cmd, enrich, entries, envfile, exec, feed_cmd, fmt, gen, history_cmd, import_vaults,
    node_cmd, oauth_cmd, out, pool, projects, render, scan, session, session_cmd, shield, uid_cmd,
    users_cmd,
};
use vault_core::calendar;

use access::{open_access, Access, AuthOpts};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use entries::EntryFields;
use std::path::PathBuf;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "unv",
    // Single source of truth: the crate version in Cargo.toml. Never hardcode.
    version,
    about = "UnENVerse CLI — manage secrets from the terminal",
    long_about = "Local mode reads the Tauri desktop app vault directly.\n\
                  Remote mode (--server / $UNV_SERVER_URL) connects to unv-server."
)]
struct Cli {
    /// Remote unv-server URL, e.g. http://localhost:8743.
    /// If set, all commands go through the server instead of the local DB.
    #[arg(long, env = "UNV_SERVER_URL", global = true)]
    server: Option<String>,

    /// Vault password (avoid in scripts — prefer UNV_PASSWORD env var or interactive prompt).
    #[arg(long, env = "UNV_PASSWORD", global = true, hide_env_values = true)]
    password: Option<String>,

    /// Authenticate as this sub-user instead of the vault owner (requires --server).
    ///
    /// The field is `as_user`, not `user`: a `global = true` argument shares its
    /// id with any subcommand argument of the same name, so a plain `user` id
    /// made `unv user token ls deploy` set this flag to "deploy" and refuse to
    /// run without --server.
    #[arg(
        long = "user",
        value_name = "USERNAME",
        env = "UNV_USER",
        global = true
    )]
    as_user: Option<String>,

    /// Second-factor code for a `--user` login whose account has TOTP enabled.
    ///
    /// Only the password path takes one. Token auth deliberately skips it —
    /// requiring a code from CI, where no human is present to read a phone, is a
    /// regression this project has already shipped once.
    #[arg(long, value_name = "CODE", env = "UNV_TOTP", global = true)]
    totp: Option<String>,

    /// Authenticate with an API token instead of a password (requires --server).
    #[arg(
        long = "token",
        value_name = "TOKEN",
        env = "UNV_TOKEN",
        global = true,
        hide_env_values = true
    )]
    api_token: Option<String>,

    /// Pin the server's TLS certificate to this SHA-256 (hex, or the colon form
    /// `openssl x509 -fingerprint` prints).
    ///
    /// Without a pin or a --ca-cert, a self-signed server is refused: there is
    /// no --insecure, because the point of this flag is that the master password
    /// never reaches a server whose identity was not established first.
    #[arg(long, value_name = "SHA256", env = "UNV_FINGERPRINT", global = true)]
    fingerprint: Option<String>,

    /// Trust this CA certificate (PEM) — and only this one — for --server.
    #[arg(long, value_name = "FILE", env = "UNV_CA_CERT", global = true)]
    ca_cert: Option<PathBuf>,

    /// Where random bytes come from: `os` (default) or `file:PATH`.
    ///
    /// An external source is **mixed** with OS entropy, never used raw — a
    /// device that is wedged or hostile can then only fail to improve the
    /// result, not degrade it. A selected source that is unavailable is an
    /// error, not a silent fallback.
    #[arg(long, value_name = "SPEC", env = "UNV_ENTROPY_SOURCE", global = true)]
    entropy_source: Option<String>,

    /// On `unv login`: learn and pin the server's certificate on first contact.
    ///
    /// The probe is unauthenticated and sends no credentials. Refused if this
    /// server already has a pin.
    #[arg(long, global = true)]
    tofu: bool,

    /// Skip confirmation prompts on destructive commands.
    #[arg(long, short = 'y', global = true)]
    yes: bool,

    /// Use this vault.db instead of the desktop app's (local mode only).
    #[arg(long, env = "UNV_DB_PATH", global = true)]
    db_path: Option<PathBuf>,

    /// Use this vault.salt. Defaults to `vault.salt` beside --db-path.
    #[arg(long, env = "UNV_SALT_PATH", global = true)]
    salt_path: Option<PathBuf>,

    /// Create the local vault if it does not exist (use with --db-path).
    #[arg(long, global = true)]
    init: bool,

    /// Emit a machine-readable envelope on stdout: {"ok":true,"command":…,"data":…}.
    #[arg(long, global = true)]
    json: bool,

    /// Case of generated variable names in copies and exports: upper (default),
    /// preserve, or lower. The CLI side of the app's "copy case" setting.
    #[arg(long, global = true, env = "UNV_ENV_CASE", value_parser = ["upper", "preserve", "lower"])]
    env_case: Option<String>,

    /// Put the entry's first env prefix in front of generated names in copies and
    /// exports. The CLI side of the app's "include consumer prefix" setting.
    #[arg(long, global = true, env = "UNV_ENV_PREFIX")]
    env_prefix: bool,

    /// Print real secret values instead of `sha256:…` fingerprints.
    ///
    /// Redaction is the default so that an agent driving this CLI never takes a
    /// secret into its context. `--out <file>` and `unv exec` move real values
    /// without printing them; this flag is for a human at a terminal.
    #[arg(long, global = true)]
    reveal: bool,

    /// Report what a mutating command would change, and write nothing.
    #[arg(long, global = true)]
    dry_run: bool,

    /// Read the vault password from this file (first line).
    #[arg(long, env = "UNV_PASSWORD_FILE", global = true)]
    password_file: Option<PathBuf>,

    /// Read UNV_PASSWORD (and UNV_SERVER_URL) from a Docker-style .env file.
    ///
    /// This is the same file `docker compose` reads to start unv-server, so a
    /// containerised server and the CLI driving it share exactly one copy of the
    /// password — owned by the compose stack, never pasted into a command line.
    #[arg(long, env = "UNV_ENV_FILE", global = true)]
    env_file: Option<PathBuf>,

    /// Run this command and use its stdout as the vault password.
    ///
    /// Keeps the password out of argv, out of the environment, and out of an
    /// orchestrator's context — `--password-command "pass show unv"`.
    #[arg(long, env = "UNV_PASSWORD_COMMAND", global = true)]
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
        /// Filter by secret type — comma-separated, OR-combined (e.g. `cookie,composite`).
        /// `2fa`/`totp` and `pool` are virtual: seed-carrying and pool-membership.
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
        /// keys. Skips members that `unv pool report --limited` put on cooldown.
        #[arg(long, conflicts_with = "provider")]
        pool: Option<String>,
        /// Emit `.env` lines at this profile instead of the entry document.
        ///
        /// `basic` is the values; `extended` adds version, expiry, rate limit,
        /// scopes, environment, account and pool; `full` adds the nine fields
        /// that describe a credential rather than drive it. The text carries
        /// real values, so it follows the same rule as `unv export`: refused to
        /// stdout unless `--reveal`, written by `--out`.
        #[arg(long, value_parser = ["basic", "extended", "full"])]
        profile: Option<String>,
        /// Where profile metadata goes: `#` comments (default) or variables.
        #[arg(long, value_parser = ["comment", "var"], requires = "profile")]
        metadata: Option<String>,
        /// Write the profile text to a file, 0600, instead of stdout.
        #[arg(long = "out", requires = "profile")]
        out_file: Option<PathBuf>,
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
        /// For `--format dotenv`: how much of each entry to emit.
        ///
        /// `full` is refused vault-wide the same way a plaintext export to
        /// stdout is: every entry's purposes, projects, tags and rotation dates
        /// in one file is a map of what matters in the vault. Name a project, or
        /// use `unv get <entry> --profile full` for one entry.
        #[arg(long, value_parser = ["basic", "extended", "full"])]
        profile: Option<String>,
        /// Where profile metadata goes: `#` comments (default) or variables.
        #[arg(long, value_parser = ["comment", "var"], requires = "profile")]
        metadata: Option<String>,
    },
    /// Build a `curl` command that sends one entry's credential.
    ///
    /// Reads `auth_scheme` / `auth_param`, so the header, the basic pair or the
    /// query parameter is the one that service actually wants — which is the
    /// thing the vault did not know before Phase 23 and the user had to
    /// remember.
    ///
    /// The command contains the real credential, so it follows the same rule as
    /// every other materialising path: redacted to stdout, written in full by
    /// `--out`. `unv curl X -- https://…` names the URL; without one it uses the
    /// entry's `api_url`.
    Curl {
        /// Provider name, or provider:key_id.
        provider: String,
        /// Write the command to a file (0600) instead of stdout.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
        /// The URL to call. Defaults to the entry's api_url.
        #[arg(last = true)]
        url: Vec<String>,
    },
    /// Write a file-shaped credential to disk, and print the variable that names it.
    ///
    /// A GCP service-account JSON, an Apple `.p8`, an mTLS bundle and a
    /// `kubeconfig` are consumed by *pointing at them*, so materialising to a
    /// path is the only correct verb — copying the contents produces something no
    /// consumer wants, and pasting them into a `.env` produces a variable the
    /// library tries to open as a path.
    ///
    /// The file is written 0600. Without `--out` it goes to the entry's
    /// `mount_path`.
    File {
        #[command(subcommand)]
        cmd: FileCmd,
    },
    /// Read a stored browser session out in the format the tool you are using wants.
    ///
    /// Every one of these is a **materialising** path — the output is a live
    /// session — so the Phase 14 rule applies unchanged: redacted to stdout,
    /// written in full by `--out`.
    Cookie {
        #[command(subcommand)]
        cmd: CookieCmd,
    },
    /// A one-shot iCalendar (.ics) export, or a subscribable feed served by
    /// `unv-server` (Phase 24.3).
    Calendar {
        #[command(subcommand)]
        cmd: CalendarCmd,
    },
    /// The unique-ID registry (Phase 24.4). Server-side only — refused against
    /// a local vault with no `--server`.
    Uid {
        #[command(subcommand)]
        cmd: UidCmd,
    },
    /// Which credentials were on a machine, and when (Phase 36): the entries to
    /// rotate, only those whose exposed value is still live, and one command that
    /// rotates exactly them. `--host NODE` asks the hub; `--host local` reads this
    /// machine's materialisation log.
    BlastRadius {
        #[arg(long)]
        host: String,
        /// Only deployments at or after this ISO date.
        #[arg(long)]
        since: Option<String>,
    },
    /// The config time machine (Phase 35): a snapshot of every rendered config
    /// whenever a save changes it, diffable, verifiable and pruned by policy.
    /// Stdout shows secrets as fingerprints; `--reveal` or `--out` shows them.
    History {
        #[command(subcommand)]
        cmd: HistoryCmd,
    },
    /// Nodes (Phase 34): agents on other hosts that observe, and when told to
    /// apply, config files rendered from this vault. `token`, `ls`, `show`,
    /// `revoke`, `pull` and `accept` manage them on a hub (`unv-server --nodes`);
    /// `enroll`, `run` and `check` run on the managed host.
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// FIDO Credential Exchange (CXF) import/export (Phase 24.5).
    Cxf {
        #[command(subcommand)]
        cmd: CxfCmd,
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
    /// Write a credential in the file its tool reads: `.npmrc`, `pypirc`,
    /// Docker `config.json`, a DSN, libpq variables, a Wi-Fi QR string.
    ///
    /// With no `--as`, lists the formats the entry's type offers. The output
    /// holds the credential, so it follows `export`'s rule: refused to stdout
    /// unless `--reveal`, written 0600 by `--out`.
    Emit {
        entry: String,
        #[arg(long = "as")]
        format: Option<String>,
        #[arg(long, short = 'o')]
        out: Option<std::path::PathBuf>,
    },
    /// Compare two entries field by field. Secrets show as fingerprints unless
    /// `--reveal`, so equal and different are answerable without reading either.
    Diff { a: String, b: String },
    /// Entry presets for common services: list them or show what one pre-fills.
    Template {
        #[command(subcommand)]
        cmd: envv_cli::template_cmd::TemplateCmd,
    },
    /// Delete the local vault and its salt (the app's Settings -> Reset).
    ///
    /// Needs no password, since it exists for when the password is lost. Asks for
    /// confirmation, refuses without a terminal unless `--yes`, and honours
    /// `--dry-run`. A `.v1.bak` backup is left alone.
    ResetVault,
    /// The signed provider catalogue `enrich` reads before its compiled table.
    Catalogue {
        #[command(subcommand)]
        cmd: envv_cli::catalogue_cmd::CatalogueCmd,
    },
    /// OAuth clients: exchange a refresh token for a new access token.
    Oauth {
        #[command(subcommand)]
        cmd: OauthCmd,
    },
    /// Single-use recovery codes: status, the next one, and marking one used.
    Codes {
        #[command(subcommand)]
        cmd: CodesCmd,
    },
    /// Bundles: one card for several entries that belong together.
    Bundle {
        #[command(subcommand)]
        cmd: BundleCmd,
    },
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
    /// Cross-chunk checks on a project's config: an nginx proxy_pass to a service
    /// that is not defined, two WireGuard peers claiming one network, a Traefik
    /// middleware that does not exist, and three more. Prints names, never values.
    Check {
        /// Project to check. Defaults to `unv use` / $UNV_PROJECT, else every project.
        project: Option<String>,
        /// Exit 10 when a finding at this severity or worse exists (for CI).
        #[arg(long, value_parser = ["error", "warning"])]
        fail_on: Option<String>,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Resolve an nginx `proxy_pass` host against the services of every project,
        /// not just its own. Widens the evidence a rule may use, so it is opt-in.
        #[arg(long)]
        all_projects: bool,
    },
    /// Health scan — weak, expiring, duplicated and stale-reference secrets.
    Scan {
        /// Lowest severity to report: high, med, low (default: low = everything).
        #[arg(long, default_value = "low", value_parser = ["high", "med", "low"])]
        severity: String,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Scan a file or directory for plaintext values held by this vault.
        #[arg(long, value_name = "PATH")]
        exposed: Option<PathBuf>,
        /// Write an exposure report here. Required with --exposed.
        #[arg(long, short = 'o', requires = "exposed")]
        out: Option<PathBuf>,
    },
    /// Where this CLI is pointed and what the vault holds.
    Status,
    /// Import from another password manager (Bitwarden, 1Password, Proton Pass) or a
    /// Nextcloud `config.php`.
    ///
    /// Preview by default — nothing is written without `--apply`, and the
    /// preview shows fingerprints rather than values.
    ImportVault {
        /// Which product the file came from.
        #[arg(value_parser = ["bitwarden", "onepassword", "proton", "nextcloud"])]
        vendor: String,
        /// The exported JSON file.
        file: PathBuf,
        /// Actually write. Without it this is a dry run.
        #[arg(long)]
        apply: bool,
        /// Assign imported entries to this project.
        #[arg(long)]
        project: Option<String>,
        /// Put every imported entry in this category.
        #[arg(long)]
        category: Option<String>,
        /// Use the source folder / vault name as the category.
        #[arg(long)]
        keep_folders: bool,
    },
    /// Pin a project and environment to this directory (writes `.envv.json`).
    ///
    /// Later commands run here inherit them, so `--project` stops being typed
    /// on every line. An explicit flag still wins, and `UNV_PROJECT` /
    /// `UNV_ENV` sit between the two — which is the order CI needs.
    ///
    /// The file names things; it never holds a value, so it is safe to commit.
    Use {
        /// Project id or name to pin. Omit to show the current context.
        project: Option<String>,
        /// Environment to pin (production, staging, development, testing).
        #[arg(long)]
        env: Option<String>,
        /// Print the context in effect and where it came from.
        #[arg(long)]
        show: bool,
        /// Remove `.envv.json` from this directory.
        #[arg(long)]
        clear: bool,
    },
    /// Check the vault: database integrity, salt, file modes, audit chain, pools.
    ///
    /// Exits non-zero when something is actually wrong, so a script can branch
    /// on it. There is deliberately no `--repair` for a missing salt: nothing
    /// can reconstruct 16 bytes of CSPRNG output, and a flag that appeared to
    /// offer it would be discovered as a lie during a restore.
    Doctor {
        /// Repair what can be repaired safely — currently: backfill missing
        /// entry ids.
        ///
        /// An entry written before stable ids existed falls back to
        /// `provider|account_name|key_id` for RBAC scoping and version history,
        /// so two entries differing only by their Phase 23 `label` would collide
        /// there. Adding `label` to that tuple would silently re-target scoping
        /// on every pre-id vault; backfilling the id does not.
        #[arg(long)]
        fix: bool,
    },
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
    /// Run a command while replacing known vault values in its text output.
    ///
    /// Explicit only: it changes a program's stdout and stderr, so scripts keep
    /// their normal output unless they deliberately choose this wrapper.
    Shield {
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
    /// Authenticator codes from seeds this vault holds for other services.
    ///
    /// Not to be confused with `unv user totp`, which is UnENVerse's *own*
    /// second factor for a sub-user login. This one is the Bitwarden/1Password
    /// shape: the vault stores a seed some website issued, and hands you the six
    /// digits that website is about to ask for.
    Totp {
        #[command(subcommand)]
        cmd: EntryTotpCmd,
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

/// File-shaped credentials — the ones where the variable names a path (E17).
#[derive(Subcommand)]
enum FileCmd {
    /// Write the credential to disk and print the `.env` line that names it.
    Write {
        provider: String,
        /// Where to write it. Defaults to the entry's `mount_path`.
        #[arg(long, short = 'o')]
        out: Option<std::path::PathBuf>,
    },
}

/// The four shapes a stored browser session is consumed in.
///
/// All four are materialising paths: the output *is* the session, so each is
/// redacted to stdout and written in full only by `--out` — the same rule
/// `unv export` follows, for the same reason.
#[derive(Subcommand)]
enum CookieCmd {
    /// The `Cookie:` header value — what a request actually sends.
    Header {
        provider: String,
        #[arg(long, short = 'o')]
        out: Option<std::path::PathBuf>,
    },
    /// A `curl` command carrying the jar and its User-Agent.
    Curl {
        provider: String,
        #[arg(long, short = 'o')]
        out: Option<std::path::PathBuf>,
    },
    /// Netscape `cookies.txt`, for `curl -b` and `yt-dlp --cookies`.
    ///
    /// **Refused when the jar has no domain and no path.** The format needs them
    /// per cookie, and a file `yt-dlp` silently ignores is worse than no file —
    /// the user discovers it as "the download is not logged in", with nothing
    /// pointing at the file. Re-export from the browser as JSON or cookies.txt.
    Txt {
        provider: String,
        #[arg(long, short = 'o')]
        out: Option<std::path::PathBuf>,
    },
    /// The browser-extension array shape, so a jar round-trips back into a browser.
    Json {
        provider: String,
        #[arg(long, short = 'o')]
        out: Option<std::path::PathBuf>,
    },
    /// Import a DevTools capture into a web-session entry.
    ///
    /// `--from curl` (DevTools "Copy as cURL", bash or cmd), `powershell`, `har`,
    /// `set-cookie`, `firefox` (a profile's `cookies.sqlite`) or `auto`. FILE is
    /// `-` for stdin. Only the chosen origin's cookies and headers are kept; an
    /// `Authorization` header and other hosts' cookies are dropped and reported by
    /// name. Without `--entry` this is a preview and writes nothing. Chrome is
    /// refused by name: its cookies are not readable from outside the browser.
    Import {
        file: String,
        #[arg(long, default_value = "auto")]
        from: String,
        /// Scope a HAR to one origin (required when it touches several).
        #[arg(long)]
        origin: Option<String>,
        /// Host to read from a Firefox `cookies.sqlite`.
        #[arg(long)]
        host: Option<String>,
        /// Write into this web-session entry (preview only when omitted).
        #[arg(long)]
        entry: Option<String>,
        /// Create the entry if it does not exist.
        #[arg(long)]
        create: bool,
    },
}

/// `unv calendar export` writes a one-shot .ics; `unv calendar feed` manages
/// subscribable feed URLs served by `unv-server`.
#[derive(Subcommand)]
enum CalendarCmd {
    /// Write an iCalendar (.ics) feed of every date the vault knows.
    ///
    /// Creation dates, expiries and rotation deadlines, in the one format every
    /// calendar reads. UIDs are stable per entry and per kind, so re-importing
    /// updates the existing events instead of duplicating them.
    ///
    /// The file carries secret NAMES and dates. It carries no values and no
    /// fingerprints — a fingerprint is stable per value, so a feed full of them
    /// would tell whoever holds two feeds which secrets match.
    Export {
        /// Which events to include: created, expires, rotation. Repeatable;
        /// defaults to all three.
        #[arg(long = "kind", value_name = "KIND")]
        kinds: Vec<String>,
        /// Only include entries in this project.
        #[arg(long)]
        project: Option<String>,
        /// Write to this file instead of stdout.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
        /// Calendar display name (X-WR-CALNAME).
        #[arg(long, default_value = "UnENVerse")]
        name: String,
    },
    #[command(subcommand)]
    Feed(FeedCmd),
}

/// A per-user subscribable `.ics` URL, token-addressed and revocable — never
/// carrying a value. Requires `--server`; a local vault has nothing to serve
/// it from.
#[derive(Subcommand)]
enum FeedCmd {
    /// Mint a feed. The token is shown **once** — `unv-server` stores only its
    /// hash — so this refuses to print it without `--reveal`/`--out`, the same
    /// rule as `user token new`.
    New {
        /// Which events to include: created, expires, rotation. Repeatable;
        /// defaults to all three.
        #[arg(long = "kind", value_name = "KIND")]
        kinds: Vec<String>,
        /// Display name for the calendar (X-WR-CALNAME) and for `feed ls`.
        #[arg(long, default_value = "UnENVerse")]
        name: String,
        /// Include account names in event titles/descriptions. Off by default —
        /// an account name is often an email address.
        #[arg(long)]
        include_account_names: bool,
        /// Write the full feed URL to this file (0600) instead of stdout.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
    /// List feeds. The owner sees every feed; a sub-user sees only their own.
    Ls,
    /// Revoke a feed by id. Irreversible — the URL stops working immediately.
    Revoke {
        id: String,
        #[arg(long)]
        yes: bool,
    },
}

/// The config time machine (Phase 35, ADR-0141).
#[derive(Subcommand)]
enum HistoryCmd {
    /// List snapshots, newest first. Shows names, times and hashes, never content.
    Ls {
        /// A project name or id.
        project: Option<String>,
        #[arg(long)]
        exporter: Option<String>,
        /// Only snapshots at or after this ISO date.
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// Show one snapshot. Fingerprinted unless `--reveal`; `--out FILE` writes the
    /// real file (0600).
    Show {
        seq: i64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Unified diff between two snapshots of one config; by default the newest
    /// two. A rotated secret shows as a changed fingerprint.
    Diff {
        project: Option<String>,
        #[arg(long)]
        exporter: Option<String>,
        #[arg(long)]
        from: Option<i64>,
        #[arg(long)]
        to: Option<i64>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Compare a stored snapshot with a file on this machine - typically a node's
    /// live config fetched with `unv node pull`. Without `--reveal` only the names
    /// of the differing lines are shown, never what follows them.
    DiffFile {
        file: PathBuf,
        project: Option<String>,
        #[arg(long)]
        exporter: Option<String>,
        /// Which snapshot; the newest of the config when omitted.
        #[arg(long)]
        seq: Option<i64>,
    },
    /// Record a snapshot of every config that changed, now.
    Snapshot { project: Option<String> },
    /// Delete snapshots that are both beyond the newest `--keep` and older than
    /// `--days`, leaving a checkpoint. Deletes the only record of what was deployed then.
    Prune {
        #[arg(long)]
        keep: Option<i64>,
        #[arg(long)]
        days: Option<i64>,
    },
    /// Recompute every hash and chain and check each checkpoint against the audit chain.
    Verify,
    /// Show or change the retention policy and whether history is on.
    Policy {
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        #[arg(long)]
        disable: bool,
        #[arg(long)]
        keep: Option<i64>,
        #[arg(long)]
        days: Option<i64>,
    },
    /// Which snapshot a file's SHA-256 came from (e.g. the hash a node reports).
    Where { sha256: String },
    /// Snapshot count, size and oldest.
    Stats,
}

/// Nodes (Phase 34, ADR-0140).
#[derive(Subcommand)]
enum NodeCmd {
    /// Mint a single-use enrollment token for a new node (hub, owner only).
    Token {
        #[command(subcommand)]
        cmd: NodeTokenCmd,
    },
    /// List enrolled nodes and each target's status (hub).
    Ls,
    /// One node in full: key fingerprint, host, and every target (hub).
    Show { node: String },
    /// Stop a node receiving config. Files already written stay where they are.
    Revoke { node: String },
    /// Fetch a pull target's file from the node. Written with `--out` (0600);
    /// there is no stdout form, because the file is the node's own and holds its
    /// secrets.
    ///
    /// With `--into-chunk` the file is read back into an `env_file` chunk of the
    /// target's project instead of being written (`.env`-style targets only; the
    /// other formats' parsers live in the app). A preview unless `--apply`, and a
    /// field that holds a `${reference}` is never overwritten with the literal.
    Pull {
        node: String,
        target: String,
        #[arg(long, required_unless_present = "into_chunk")]
        out: Option<PathBuf>,
        /// Read the file into this `env_file` chunk of the target's project.
        #[arg(long, conflicts_with = "out")]
        into_chunk: Option<String>,
        /// With `--into-chunk`: write the change (otherwise it is only previewed).
        #[arg(long, requires = "into_chunk")]
        apply: bool,
        /// Seconds to wait for the node's next beat.
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
    /// Record a pull target's current file as accepted into the vault, so it
    /// reads `in_sync` until it changes again.
    Accept { node: String, target: String },
    /// Hold every push to a node for a human (`required`), or stop (`none`).
    Policy {
        node: String,
        #[arg(long)]
        approval: String,
    },
    /// Approver devices: the key on this machine whose signature a node set to
    /// `device` approval (and configured with `approver = "…"`) accepts as yours.
    Approver {
        #[command(subcommand)]
        cmd: ApproverCmd,
    },
    /// Pushes waiting for a human, with `--all` the decided ones too.
    Approvals {
        node: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Approve one held push. Shows the diff against what the node has and the
    /// hash being approved first (secrets as fingerprints unless `--reveal`);
    /// `--yes` skips the question for someone who has looked. The approval is for
    /// those exact bytes and lapses in an hour.
    Approve { approval: String },
    /// Reject one held push; the same bytes are not asked about again.
    Reject { approval: String },
    /// On the managed host: spend an enrollment token and save this node's
    /// identity. Nothing is read from the vault.
    Enroll {
        /// The hub, `https://…` (or `http://` to the loopback).
        #[arg(long)]
        hub: String,
        /// Read the token from this file (it never appears in argv).
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Read the token from standard input.
        #[arg(long)]
        token_stdin: bool,
        /// The hub certificate's SHA-256, as `unv-server --tls` prints it.
        #[arg(long)]
        hub_fingerprint: Option<String>,
        /// Learn the hub's certificate and ask you to confirm it by eye.
        #[arg(long)]
        tofu: bool,
        /// Replace an existing identity (revoke the old node on the hub first).
        #[arg(long)]
        force: bool,
        /// Listen for the hub instead of dialling it (a node with a public
        /// address): bind here, e.g. `0.0.0.0:9443`. Needs `--advertise`.
        #[arg(long, requires = "advertise")]
        listen: Option<String>,
        /// The `https://host:port` the hub should dial. A certificate for this node
        /// is generated and pinned by the hub at enrollment.
        #[arg(long, requires = "listen")]
        advertise: Option<String>,
        #[arg(long, env = "UNV_NODE_DIR")]
        state_dir: Option<PathBuf>,
    },
    /// On the managed host: beat to the hub and carry out what this node's own
    /// config allows. Runs until stopped. A node enrolled with `--listen` waits
    /// for the hub to dial it instead.
    Run {
        #[arg(long)]
        config: PathBuf,
        /// One beat, then exit (cron, tests).
        #[arg(long)]
        once: bool,
        #[arg(long, env = "UNV_NODE_DIR")]
        state_dir: Option<PathBuf>,
    },
    /// Validate a node config and show what it would report. Contacts no one.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ApproverCmd {
    /// This machine's approver public key and fingerprint (the key is made on
    /// first use, 0600). Put the public key in a node's config as `approver`.
    Show,
    /// Tell the hub this machine's key counts as your approval (hub, owner only).
    Register {
        #[arg(long)]
        label: String,
    },
    /// Devices the hub accepts.
    Ls,
    /// Stop accepting a device, by (at least 8 characters of) its fingerprint.
    Rm { fingerprint: String },
}

#[derive(Subcommand)]
enum NodeTokenCmd {
    /// The token is a one-time credential: written to `--out` (0600), or printed
    /// only with `--reveal`.
    New {
        /// Node name; becomes its identity on the hub.
        name: String,
        /// A project this node may be sent. Repeatable; at least one.
        #[arg(long = "project", required = true)]
        projects: Vec<String>,
        /// How long the token lives: `90s`, `15m`, `2h`, `1d`.
        #[arg(long, default_value = "15m")]
        ttl: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

/// The unique-ID registry's surface (Phase 24.4). Every subcommand is
/// server-side only.
#[derive(Subcommand)]
enum UidCmd {
    /// Advisory only: "unique right now". `register`/`mint` are the operations
    /// that actually reserve a value.
    Check {
        values: Vec<String>,
        #[arg(long, default_value = "none")]
        normalise: String,
    },
    /// Record values minted elsewhere. Fails closed per value on a collision —
    /// nothing else in the batch is rolled back.
    Register {
        values: Vec<String>,
        #[arg(long, default_value = "none")]
        normalise: String,
        #[arg(long)]
        namespace: Option<String>,
        #[arg(long)]
        generator: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Generate in-process, check, retry up to 3 times on collision, register,
    /// and return the value that was actually stored.
    Mint {
        /// Number of hex characters in the generated candidate.
        #[arg(long, default_value_t = 32)]
        length: usize,
        #[arg(long)]
        namespace: Option<String>,
        #[arg(long)]
        generator: Option<String>,
    },
    /// One value → issued/unknown plus the metadata the caller may see.
    Lookup {
        value: String,
        #[arg(long, default_value = "none")]
        normalise: String,
    },
    /// Delete registry rows before a date. **Deletes the only evidence an ID
    /// was issued** — a pruned ID can be issued again undetected. Dry-run first.
    Prune {
        /// ISO-8601 date; rows older than this are deleted.
        before: String,
        #[arg(long)]
        namespace: Option<String>,
        #[arg(long)]
        generator: Option<String>,
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Row count, size on disk, oldest entry.
    Stats,
}

/// FIDO Credential Exchange — the format password managers are converging on
/// for moving credentials between products.
#[derive(Subcommand)]
enum CxfCmd {
    /// Read a CXF file. Every item is appended as one or more new entries —
    /// see `vault_core::cxf`'s module doc for the one-credential-vs-several
    /// (bundle) rule and why this is append-only rather than merge-aware.
    Import {
        file: PathBuf,
        /// Put new entries in this project as well as Universal.
        #[arg(long)]
        project: Option<String>,
        /// Tag new entries with this category.
        #[arg(long)]
        category: Option<String>,
    },
    /// Write every entry as a CXF document. Materialising by construction —
    /// refused without --out, the same Phase 14 rule every export here obeys.
    Export {
        #[arg(long, short = 'o')]
        out: PathBuf,
        /// Only entries whose provider name contains this (case-insensitive).
        #[arg(long)]
        provider: Option<String>,
    },
}

#[derive(Subcommand)]
enum EntryCmd {
    /// List entries (same filters as `unv list`).
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
        /// Pre-fill from a preset (see `unv template ls`); explicit flags override
        /// it. Not `--template`: that flag is a composite's `{part}` template.
        #[arg(long)]
        preset: Option<String>,
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
    /// Record that a stored browser session still works.
    ///
    /// The session equivalent of `rotate`. Rotating a cookie means logging in
    /// again in a browser, which nothing here can do — so a session flagged
    /// never-rotated stays flagged forever, and a nag with no available fix is
    /// how a health scan trains people to ignore it (Phase 23, E13). This is the
    /// check that *is* actionable: open the site, confirm you are still signed
    /// in, and stamp it.
    Verify {
        provider: String,
        /// Clear the stamp instead — say the session is no longer known good.
        #[arg(long)]
        off: bool,
    },
    /// Show previous values of an entry's secret.
    History { provider: String },
    /// Restore a previous value by its position in `entry history`.
    Restore { provider: String, version: usize },
}

/// `unv totp …` — stored third-party authenticator seeds.
///
/// Named `EntryTotpCmd` because `TotpCmd` is taken by `unv user totp`, and the
/// two must never be confused: that one enrolls a factor on an UnENVerse login,
/// this one reads a seed the vault holds for somebody else's login.
#[derive(Subcommand)]
enum EntryTotpCmd {
    /// Print the current code for an entry.
    ///
    /// The code prints in the clear. It is derived rather than stored, it is six
    /// digits, and it is dead in under thirty seconds — the seed it came from is
    /// redacted like every other secret. See the module docs in
    /// `envv-cli/src/totp_cmd.rs` for why this exemption is written down.
    Code {
        /// Provider name, or provider:key_id.
        provider: String,
        /// Also print the code that replaces this one.
        ///
        /// Off by default: the next code is a second working credential with a
        /// longer life than the one on screen, so printing both by default puts
        /// two live codes in every transcript instead of one.
        #[arg(long)]
        next: bool,
    },
    /// List the entries that carry a seed. Names and parameters, never codes.
    Ls,
    /// Guided add: attach a seed to an existing entry (matched by exact
    /// provider name) or create a bare `password`-typed one with an empty
    /// primary. Mirrors the desktop Authenticator panel's "Add 2FA" form.
    ///
    /// Refuses when the target already carries a seed — `unv entry set
    /// NAME --totp-stdin` is the re-enroll-on-purpose path.
    Add {
        /// Provider name — matched exactly against an existing entry, or used
        /// to create one.
        name: String,
        /// Base32 seed or a whole otpauth:// URI.
        #[arg(long)]
        seed: Option<String>,
        /// Read the seed from stdin (never appears in `ps`). Prefer this.
        #[arg(long, conflicts_with = "seed")]
        seed_stdin: bool,
        /// Only used when creating a new entry.
        #[arg(long)]
        account: Option<String>,
        #[arg(long, value_parser = ["totp", "hotp", "steam"])]
        kind: Option<String>,
        /// The next counter an `hotp` seed will use.
        #[arg(long)]
        counter: Option<u64>,
    },
    /// Advance a counter-based (HOTP) seed to its next position.
    ///
    /// Counter-based codes do not expire — each one stands until it is used, and
    /// the service moves on only when it accepts one. Reading a code therefore
    /// does *not* advance it: a copy that missed, or a second look at the same
    /// card, would otherwise walk the counter past the service's and break the
    /// factor. This is the explicit "I used it" action.
    Advance {
        /// Provider name, or provider:key_id.
        provider: String,
        /// How many positions to move. Negative values are refused; use
        /// `entry set --totp-counter N` to resynchronise backwards.
        #[arg(long, default_value_t = 1)]
        by: u64,
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Write the otpauth:// URI, for enrolling a replacement phone.
    ///
    /// The URI contains the seed, so it is refused to stdout without --reveal
    /// and written in full by --out — the same rule `unv export` follows.
    Uri {
        /// Provider name, or provider:key_id.
        provider: String,
        /// Write to this file (0600) instead of stdout.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
    /// Forget an entry's seed. The old value stays in `entry history`.
    Rm {
        /// Provider name, or provider:key_id.
        provider: String,
    },
    /// Import seeds from another authenticator app's export.
    ///
    /// Reads Ente Auth (and any otpauth:// list), Aegis, 2FAS, andOTP,
    /// Bitwarden and Google Authenticator's otpauth-migration:// payload. The
    /// format is detected from the file; --format overrides the guess.
    ///
    /// An *encrypted* export is refused by name rather than decrypted — export
    /// again without a password, import, then delete the plaintext file.
    ///
    /// An entry that already holds a different seed is reported and left alone.
    /// A second factor is not recoverable once overwritten, and pointing a stale
    /// export at a re-enrolled vault is exactly how that happens.
    Import {
        /// The export file.
        file: PathBuf,
        /// Skip detection: otpauth (also: ente), aegis, 2fas, andotp, bitwarden, google.
        #[arg(long)]
        format: Option<String>,
        /// Put new entries in this project as well as Universal.
        #[arg(long)]
        project: Option<String>,
        /// Tag new entries with this category.
        #[arg(long)]
        category: Option<String>,
        /// Replace a seed that is already there and differs. The old value
        /// still lands in `entry history`.
        #[arg(long)]
        force: bool,
    },
    /// Write every stored seed in a format another authenticator reads.
    ///
    /// The file is nothing but seeds, so it follows the same rule as
    /// `unv backup export`: refused to stdout unless --reveal, written 0600
    /// by --out.
    Export {
        /// otpauth (also: ente — its plain export is an otpauth list), aegis, 2fas.
        #[arg(long, default_value = "otpauth")]
        format: String,
        /// Write to this file (0600) instead of stdout.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
        /// Only entries whose provider contains this text.
        #[arg(long)]
        only: Option<String>,
    },
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
    /// `unv exec --pool` uses the value without anyone reading it.
    Next {
        pool: String,
        /// Print a field other than the secret.
        #[arg(long)]
        field: Option<String>,
    },
    /// Report a key as rate limited (or recovered).
    ///
    /// `unv exec` hands the secret to a child process and never sees the
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
        #[arg(long = "type", default_value = "generic", value_parser = clap::builder::PossibleValuesParser::new(data::all_project_types()))]
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
        /// Output format. Defaults to the exporter for the project's own type —
        /// all eleven of them, not the four that used to be wired up.
        #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(envv_cli::chunks::export_formats()))]
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
        #[arg(long = "type", value_parser = clap::builder::PossibleValuesParser::new(chunks::all_chunk_types()))]
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
enum OauthCmd {
    /// Refresh an `oauth_client` entry's access token at its `token_url`.
    ///
    /// ONLINE: sends the refresh token and client secret to that URL (https only;
    /// no redirects). If the issuer rotates the refresh token, the new one is
    /// stored in the vault before anything is reported.
    Refresh { entry: String },
}

#[derive(Subcommand)]
enum CodesCmd {
    /// How many codes are left. Prints no codes.
    Status { entry: String },
    /// The next unused code. Reading does not consume it; `use` does.
    Next { entry: String },
    /// Mark a code used (the first unused one when CODE is omitted).
    Use { entry: String, code: Option<String> },
}

#[derive(Subcommand)]
enum BundleCmd {
    /// List bundles with their member slots and local variable names.
    Ls,
    /// Create a bundle; each `--member SLOT=ENTRY` joins an existing entry.
    New {
        name: String,
        #[arg(long = "member")]
        members: Vec<String>,
        /// Import a Python config module as bundle-local variables (assignment
        /// subset only; nothing is executed).
        #[arg(long)]
        import: Option<PathBuf>,
    },
    /// Add an existing entry to a bundle under a slot name.
    Add {
        bundle: String,
        entry: String,
        #[arg(long)]
        slot: String,
    },
    /// Detach the member in a slot; the entry itself is kept.
    Remove { bundle: String, slot: String },
    /// Return every member to the grid. Deletes nothing.
    Dissolve { bundle: String },
    /// Delete the bundle AND all of its member entries.
    Delete { bundle: String },
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
    /// List entropy sources and whether each one works on this machine.
    ///
    /// Exists because "is my hardware source usable?" must be answerable
    /// *without* generating a key with it.
    Sources,
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
    /// Archive the vault database **and its salt** into one encrypted file.
    ///
    /// Different job from `export`: a .vaultbak holds vault contents and needs
    /// no salt to restore. An archive is the answer to losing `vault.salt`,
    /// which is unrecoverable — nothing can reconstruct 16 bytes of CSPRNG
    /// output, so the only defence is not to store it apart from the database.
    Archive {
        file: PathBuf,
        /// Archive password (min 12 chars). Prompted when omitted.
        #[arg(long, hide_env_values = true)]
        backup_password: Option<String>,
    },
    /// Restore a vault + salt archive written by `backup archive`.
    RestoreArchive {
        file: PathBuf,
        #[arg(long, hide_env_values = true)]
        backup_password: Option<String>,
        /// Replace an existing vault on this machine.
        #[arg(long)]
        force: bool,
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
    /// Require a write to match EVERY scope, not any one of them.
    ///
    /// The default is any-match, which makes read and write nearly the same
    /// privilege for a scoped user. Strict mode is the narrower rule: an entry
    /// must satisfy all of the subject's scopes before it can be changed.
    StrictWrite {
        /// User name or id.
        user: String,
        /// Turn it off again.
        #[arg(long)]
        off: bool,
    },
    /// API tokens for a user.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Second factor (TOTP) for a sub-user.
    ///
    /// Sub-users only: the vault owner authenticates by deriving the SQLCipher
    /// key, so there is no login for a second factor to gate.
    Totp {
        #[command(subcommand)]
        cmd: TotpCmd,
    },
}

#[derive(Subcommand)]
enum TotpCmd {
    /// Show whether a user is enrolled and whether the factor is enabled.
    Status { user: String },
    /// Phase one: mint a secret. Does **not** enable the factor.
    ///
    /// Enabling here would lock out anyone whose authenticator did not take the
    /// manually-typed secret; `confirm` is what turns it on.
    Enroll {
        user: String,
        /// Write the secret and otpauth URI to this file (0600) instead of
        /// printing them.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
    /// Phase two: prove the authenticator works, which enables the factor.
    Confirm { user: String, code: String },
    /// Remove the factor and destroy the secret.
    Disable { user: String },
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

/// The command tree is large enough that parsing it and walking it for
/// `describe` overflows Windows' 1 MB main-thread stack in a debug build (Linux
/// gives the main thread 8 MB): the process died with no output, which the
/// capability test saw as an empty `describe`. Everything runs on a thread with an
/// explicit stack instead of relying on the platform default.
fn main() {
    // Variables set before the rename (`ENVV_*`) keep working.
    vault_core::compat::adopt_legacy_env();
    let worker = std::thread::Builder::new()
        .name("unv".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(real_main)
        .expect("cannot start the main worker thread");
    if worker.join().is_err() {
        // A panic has already printed its message; keep the conventional code.
        std::process::exit(101);
    }
}

fn real_main() {
    let cli = Cli::parse();

    // `error` by default, and the default is the whole point: this binary's
    // stdout is a machine-readable contract, and its stderr is what a human or
    // an agent reads when something failed. Logs go to stderr (see
    // `vault_core::telemetry`), so `UNV_LOG=debug unv get X --json | jq`
    // still parses. Raise it with `UNV_LOG` when diagnosing.
    vault_core::telemetry::init("unv", "error");
    tracing::debug!(json = cli.json, dry_run = cli.dry_run, "cli start");

    out::init(out::Mode {
        json: cli.json,
        reveal: cli.reveal,
        dry_run: cli.dry_run,
    });

    // Establish who we trust before any client exists. An explicit flag always
    // wins; otherwise a pin remembered by `unv login --tofu` for this server
    // applies, so pinning survives across invocations without repeating the
    // 64-character flag every time.
    if let Err(e) = envv_cli::tls::configure(cli.fingerprint.as_deref(), cli.ca_cert.as_deref()) {
        finish(Err(e));
        return;
    }
    // Validated here so a typo or an unplugged device fails before the user has
    // been prompted for a password.
    if let Err(e) = gen::configure(cli.entropy_source.as_deref()) {
        finish(Err(e));
        return;
    }
    if cli.fingerprint.is_none() && cli.ca_cert.is_none() {
        if let Some(server) = cli.server.as_deref() {
            if let Some(fp) = session::fingerprint(server) {
                envv_cli::tls::adopt_remembered(&fp);
            }
        }
    }

    // `completions` and `describe` write a document and must never ask for a
    // password — they are the two commands a caller runs *before* it has one.
    match &cli.command {
        Commands::Completions { shell } => {
            generate(*shell, &mut Cli::command(), "unv", &mut std::io::stdout());
            return;
        }
        Commands::Describe => {
            let doc = agentio::describe(&Cli::command());
            println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
            return;
        }
        _ => {}
    }
    // Nor do the preset listings: compiled-in public reference data.
    if let Commands::Template { cmd } = &cli.command {
        finish(envv_cli::template_cmd::run(cmd));
        return;
    }
    // Nor does a reset: it exists for the vault whose password is gone.
    if matches!(&cli.command, Commands::ResetVault) {
        access::set_paths(cli.db_path.clone(), cli.salt_path.clone());
        finish(envv_cli::reset_cmd::run(cli.yes, cli.dry_run));
        return;
    }
    // Nor does the agent half of `node`: it runs on a host that has no vault.
    if let Commands::Node { cmd } = &cli.command {
        if let Some(r) = run_node_agent_side(cmd) {
            finish(r);
            return;
        }
    }
    // Nor does the catalogue: public reference data, no vault involved.
    if let Commands::Catalogue { cmd } = &cli.command {
        finish(envv_cli::catalogue_cmd::run(cmd));
        return;
    }
    // Neither do the generators, unless they are asked to save into the vault.
    if let Commands::Gen {
        cmd: GenCmd::Sources,
    } = &cli.command
    {
        let sources = gen::list_sources();
        out::ok(
            "gen.sources",
            serde_json::json!({ "sources": sources }),
            || {
                for s in &sources {
                    let id = s["id"].as_str().unwrap_or("?");
                    let ready = s["ready"].as_bool().unwrap_or(false);
                    let detail = s["detail"].as_str().unwrap_or("");
                    let mark = if ready { "available" } else { "unavailable" };
                    println!("{id:<24} {mark} {detail}");
                }
                println!("\nExternal sources are mixed with OS entropy, never used raw.");
            },
        );
        return;
    }
    if let Commands::Gen { cmd } = &cli.command {
        if let Some(result) = run_gen_offline(cmd) {
            finish(result);
            return;
        }
    }

    finish(run(&cli));
}

/// The `node` subcommands that run on the managed host. `None` means the
/// command is a hub command and needs a connection.
fn run_node_agent_side(cmd: &NodeCmd) -> Option<CliResult> {
    let dir = |d: &Option<PathBuf>| d.clone().unwrap_or_else(envv_cli::node_agent::default_dir);
    Some(match cmd {
        NodeCmd::Enroll {
            hub,
            token_file,
            token_stdin,
            hub_fingerprint,
            tofu,
            force,
            listen,
            advertise,
            state_dir,
        } => (|| {
            let token = match (token_file, token_stdin) {
                (Some(_), true) => {
                    return Err(CliError::invalid("Pass --token-file or --token-stdin, not both"))
                }
                (Some(p), false) => std::fs::read_to_string(p)
                    .map_err(|e| CliError::not_found(format!("{}: {e}", p.display())))?,
                (None, true) => fmt::read_stdin()?,
                (None, false) => {
                    return Err(CliError::invalid(
                        "Give the enrollment token with --token-file or --token-stdin (never argv: it would show in `ps`)",
                    ))
                }
            };
            node_cmd::enroll(
                &dir(state_dir),
                hub,
                token.trim(),
                hub_fingerprint.as_deref(),
                *tofu,
                *force,
                listen.as_deref().zip(advertise.as_deref()),
            )
        })(),
        NodeCmd::Run {
            config,
            once,
            state_dir,
        } => node_cmd::run(&dir(state_dir), config, *once),
        NodeCmd::Check { config } => node_cmd::check(config),
        _ => return None,
    })
}

fn run(cli: &Cli) -> CliResult {
    access::set_paths(cli.db_path.clone(), cli.salt_path.clone());
    envv_cli::envfile::set_naming(
        cli.env_case
            .as_deref()
            .map(envv_cli::envfile::NameCase::parse),
        cli.env_prefix,
    );

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
    .or_else(|| dotenv_get("UNV_PASSWORD"));

    let server = cli.server.clone().or_else(|| dotenv_get("UNV_SERVER_URL"));

    // A cached session stands in for a password, so an agent can run every
    // command in this CLI without ever holding a credential.
    //
    // `--user` used to disable this, which made the documented flow fail in the
    // most confusing way available: `unv login --user alice` cached a session,
    // and then `unv --user alice list` ignored it and prompted for a password
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
        totp: cli.totp.as_deref(),
        init: cli.init,
    };

    match &cli.command {
        Commands::Login => return cmd_login(cli, password.as_deref()),
        Commands::Whoami => return cmd_whoami(cli),
        Commands::Sessions => return cmd_sessions(),
        Commands::Logout { all } => return cmd_logout(cli, *all),
        // Restoring an archive works on files, not on an open vault — and the
        // state it exists for is precisely "there is no vault here". Requiring
        // one first made the command refuse with "No vault found", which is the
        // problem the user is running it to solve.
        // `doctor` on a vault that will not open is the case it exists for, so it
        // must survive `open_access` failing rather than inheriting its error.
        Commands::Doctor { fix } => {
            return match open_access(&auth) {
                Ok(a) => doctor::run(Some(&a), None, *fix),
                Err(e) => doctor::run(None, Some(e.to_string()), *fix),
            }
        }
        // Showing or clearing a context touches no vault, and the state it is
        // most needed in — a directory pinned to a vault that is gone, or one
        // whose file is malformed — is exactly the state where opening one
        // fails. Requiring an unlock first would make `--clear` unusable in the
        // situation it exists to get out of.
        Commands::Use {
            project,
            env,
            show,
            clear,
        } if *show || *clear || (project.is_none() && env.is_none()) => {
            return envv_cli::context::cmd_use(
                None,
                project.as_deref(),
                env.as_deref(),
                *show,
                *clear,
            )
        }
        Commands::Backup {
            cmd:
                BackupCmd::RestoreArchive {
                    file,
                    backup_password,
                    force,
                },
        } => return backup::restore_archive(file, backup_password.as_deref(), *force, cli.yes),
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
                "{}\nThe cached session was rejected and has been cleared — run `unv login --server {server}{as_who}` again.",
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
            "`unv login` caches a session for a remote server — pass --server URL.\n\
             Local vaults have no session to cache; use --password-command instead.",
        ));
    };
    // Trust on first use, and only on first use. The probe sends no credentials;
    // the fingerprint it learns is pinned for every request that follows,
    // including the authentication two lines below. Refusing to re-TOFU over an
    // existing pin is the whole value of the mechanism — a certificate that
    // changed underneath you is exactly what pinning exists to notice.
    let mut learned: Option<String> = None;
    if cli.tofu {
        if cli.fingerprint.is_some() || cli.ca_cert.is_some() {
            return Err(CliError::invalid(
                "--tofu learns a fingerprint; --fingerprint and --ca-cert supply one. Pick one.",
            ));
        }
        if let Some(existing) = session::fingerprint(server) {
            return Err(CliError::denied(format!(
                "{server} already has a pinned certificate ({}…). If it genuinely \n\
                 rotated, run `unv logout --server {server}` first — but if it did not, \n\
                 something is presenting a different certificate.",
                &existing[..16.min(existing.len())]
            )));
        }
        let fp = envv_cli::tls::probe(server)?;
        envv_cli::tls::adopt_remembered(&fp);
        learned = Some(fp);
    }
    // Authenticating here is exactly what `open_access` would do; the difference
    // is that the resulting session token is kept, so nothing after this needs a
    // credential.
    let auth = AuthOpts {
        server: Some(server),
        password,
        user: cli.as_user.as_deref(),
        token: cli.api_token.as_deref(),
        session_token: None,
        totp: cli.totp.as_deref(),
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
    // Written only after authentication succeeded: a fingerprint stored for a
    // server we never actually reached would pin us to whatever answered.
    if let Some(fp) = &learned {
        session::save_fingerprint(server, fp)?;
    }
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
            "pinned_fingerprint": learned,
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
/// `unv calendar` — an iCalendar feed of every date in the vault.
///
/// Unlike the `.env` and config exporters, this one may write to stdout under
/// the default redacting policy, and that is a deliberate exception rather than
/// an oversight. Those exporters are refused because a masked `.env` still
/// *looks* deployable; an `.ics` contains no values to mask in the first place.
/// It carries names and dates, which `unv list` already prints.
fn cmd_calendar(
    a: &Access,
    kinds: &[String],
    project: Option<&str>,
    out_path: Option<&std::path::Path>,
    name: &str,
) -> CliResult {
    let vault = a.load_vault()?;
    let list = match project {
        Some(p) => envv_cli::data::entries_in_project(&vault, p),
        None => envv_cli::data::entries(&vault),
    };

    let selected = if kinds.is_empty() {
        vec![
            calendar::EventKind::Created,
            calendar::EventKind::Expires,
            calendar::EventKind::Rotation,
        ]
    } else {
        let mut out = Vec::new();
        for k in kinds {
            match calendar::EventKind::parse(k) {
                Some(kind) => {
                    if !out.contains(&kind) {
                        out.push(kind);
                    }
                }
                None => {
                    return Err(CliError::invalid(format!(
                        "Unknown --kind '{k}'. Supported: created, expires, rotation."
                    )))
                }
            }
        }
        out
    };

    let ics = calendar::build_ics(
        &list,
        &calendar::IcsOptions {
            kinds: selected,
            calendar_name: name.to_string(),
            ..Default::default()
        },
    );
    let events = calendar::event_count(&ics);

    // An empty calendar is not an error — a vault where nothing has a date is a
    // perfectly ordinary vault — but silently writing a file with no events in
    // it looks like the command failed, so say so.
    if events == 0 {
        out::ok(
            "calendar",
            serde_json::json!({ "events": 0, "written": out_path.map(|p| p.display().to_string()) }),
            || println!("No entry has any of the selected dates — nothing to put in a calendar."),
        );
        return Ok(());
    }

    match out_path {
        Some(path) => {
            // Written here rather than through `fmt::emit`, which prints its own
            // "Wrote <path>" to stderr — two success messages for one action.
            std::fs::write(path, &ics).map_err(|e| {
                envv_cli::error::CliError::from(format!("Cannot write {}: {e}", path.display()))
            })?;
            out::ok(
                "calendar",
                serde_json::json!({ "events": events, "written": path.display().to_string() }),
                || println!("Wrote {events} event(s) → {}", path.display()),
            );
            Ok(())
        }
        // Straight to stdout, unwrapped: piping into a file or into a calendar
        // import is the point, and a JSON envelope around 4 KB of escaped ICS
        // would be unusable for either.
        None => fmt::emit(&ics, None),
    }
}

/// `--project` with the per-directory context applied.
///
/// A name that came from a context file or from `UNV_PROJECT` is validated
/// against the vault before it is used, and an explicit flag is not — the flag
/// is checked by the command itself, and duplicating that here would report the
/// same problem twice in different words.
///
/// The validation exists because an unresolvable context is invisible
/// otherwise: `unv list` in a directory pinned to a deleted project would
/// simply list everything, which looks exactly like a vault with no scoping at
/// all. Invariant 7, one directory at a time.
fn scoped_project(a: &Access, explicit: Option<&str>) -> Result<Option<String>, CliError> {
    let resolved = envv_cli::context::project(explicit)?;
    let (Some(name), true) = (
        resolved.as_deref(),
        envv_cli::context::is_from_context(explicit),
    ) else {
        return Ok(resolved);
    };
    let vault = a.load_vault()?;
    if envv_cli::context::resolve_in_vault(&vault, name).is_none() {
        return Err(CliError::not_found(format!(
            "This directory is pinned to project '{name}', which is not in the vault.\n\
             Run `unv use <project>` to point it somewhere real, or `unv use --clear`."
        )));
    }
    Ok(resolved)
}

/// `--env` with the per-directory context applied.
///
/// Not validated against anything: the environment is a free-text field on an
/// entry, so "matches nothing" is an ordinary answer rather than a stale
/// reference.
fn scoped_env(explicit: Option<&str>) -> Result<Option<String>, CliError> {
    envv_cli::context::environment(explicit)
}

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
            "No cached session for {server}. Run: unv login --server {server} [--user NAME]"
        )));
    };
    let Some(token) = session::load(server, Some(&subject)) else {
        return Err(CliError::denied(format!(
            "No cached session for {subject} at {server}. Run: unv login --server {server} --user {subject}"
        )));
    };

    // Prove the session rather than describe it. A cached token that the server
    // has since rejected looks identical on disk to a working one, and reporting
    // a dead session as a live identity is worse than reporting nothing.
    let client = access::RemoteClient::with_session(server, &token)?;
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
                println!("No cached sessions. Run: unv login --server URL [--user NAME]");
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
        // Handled before this point, in `main`, because it needs no vault and no
        // generation at all.
        GenCmd::Sources => Some(Ok(())),
        GenCmd::Secret { bytes, format } => Some(gen::secret(*bytes, format, &gen::current()).map(|v| {
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
            Some(gen::password(&opts, &gen::current()).map(|(pw, entropy)| {
                out::ok(
                    "gen.password",
                    serde_json::json!({
                        "value": if out::revealing() { serde_json::json!(pw) } else { out::masked_json(&pw) },
                        "entropy_bits": entropy.round(),
                        "entropy_source": gen::current().label(),
                    }),
                    || {
                        if out::revealing() {
                            println!("{pw}");
                        } else {
                            println!("{}", out::masked(&pw));
                            eprintln!("Redacted. Use --reveal to print it, or `unv entry add NAME --generate --generate-format password` to store it directly.");
                        }
                        eprintln!("{entropy:.0} bits of entropy");
                    },
                );
            }))
        }
        GenCmd::Cert { save_as: Some(_), .. } | GenCmd::Ssh { save_as: Some(_), .. } => None,
        GenCmd::Cert { common_name, days, .. } => Some(gen::certificate(common_name, *days, &gen::current()).map(|v| {
            let cert = v.get("cert_pem").and_then(|c| c.as_str()).unwrap_or("").to_string();
            let key = v.get("key_pem").and_then(|c| c.as_str()).unwrap_or("").to_string();
            out::ok(
                "gen.cert",
                serde_json::json!({
                    "cert_pem": if out::revealing() { serde_json::json!(cert) } else { out::masked_json(&cert) },
                    "key_pem":  if out::revealing() { serde_json::json!(key)  } else { out::masked_json(&key)  },
                    "entropy_source": gen::current().label(),
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
        GenCmd::Ssh { comment, .. } => Some(gen::ssh_keypair(comment, &gen::current()).map(|v| {
            let pubkey = v.get("public_key").and_then(|c| c.as_str()).unwrap_or("").to_string();
            let private = v.get("private_key_openssh").and_then(|c| c.as_str()).unwrap_or("").to_string();
            out::ok(
                "gen.ssh",
                serde_json::json!({
                    // A public key is public: printing it is the point.
                    "public_key": pubkey,
                    "entropy_source": gen::current().label(),
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

/// Emit a generated secret.
///
/// `entropy_source` is part of the envelope on purpose: an agent that asked for
/// hardware entropy must be able to confirm it got it, and "the flag was
/// accepted" is not the same claim as "the bytes came from there".
fn emit_generated(command: &str, value: &str) {
    out::ok(
        command,
        serde_json::json!({
            "value": if out::revealing() { serde_json::json!(value) } else { out::masked_json(value) },
            "entropy_source": gen::current().label(),
        }),
        || {
            if out::revealing() {
                println!("{value}");
            } else {
                println!("{}", out::masked(value));
                eprintln!("Redacted. Use --reveal to print it, or store it directly with `unv entry add NAME --generate`.");
            }
        },
    );
}

fn dispatch(cli: &Cli, a: &Access) -> CliResult {
    let yes = cli.yes;
    match &cli.command {
        Commands::Completions { .. }
        | Commands::Describe
        | Commands::Catalogue { .. }
        | Commands::ResetVault
        | Commands::Template { .. }
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
        } => {
            let project = scoped_project(a, project.as_deref())?;
            let env = scoped_env(env.as_deref())?;
            entries::cmd_list(
                a,
                project.as_deref(),
                r#type.as_deref(),
                tag.as_deref(),
                env.as_deref(),
                category.as_deref(),
                search.as_deref(),
                *json,
            )
        }
        Commands::Get {
            provider,
            field,
            pool: pool_name,
            profile,
            metadata,
            out_file,
        } => match (provider, pool_name) {
            (_, Some(name)) => pool::cmd_next(a, name, field.as_deref()),
            (Some(p), None) if profile.is_some() => entries::cmd_get_profile(
                a,
                p,
                profile.as_deref().unwrap(),
                metadata.as_deref(),
                out_file.as_deref(),
            ),
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
            profile,
            metadata,
        } => {
            let project = scoped_project(a, project.as_deref())?;
            envfile::export_vault(
                a,
                format,
                project.as_deref(),
                name,
                out.as_deref(),
                profile.as_deref(),
                metadata.as_deref(),
            )
        }
        Commands::File { cmd } => match cmd {
            FileCmd::Write { provider, out } => {
                entries::cmd_file_write(a, provider, out.as_deref())
            }
        },
        Commands::Cookie { cmd } => match cmd {
            CookieCmd::Header { provider, out } => {
                entries::cmd_cookie(a, provider, "header", out.as_deref())
            }
            CookieCmd::Curl { provider, out } => {
                entries::cmd_cookie(a, provider, "curl", out.as_deref())
            }
            CookieCmd::Txt { provider, out } => {
                entries::cmd_cookie(a, provider, "txt", out.as_deref())
            }
            CookieCmd::Json { provider, out } => {
                entries::cmd_cookie(a, provider, "json", out.as_deref())
            }
            CookieCmd::Import {
                file,
                from,
                origin,
                host,
                entry,
                create,
            } => session_cmd::import(
                a,
                &session_cmd::ImportArgs {
                    from,
                    file,
                    origin: origin.as_deref(),
                    host: host.as_deref(),
                    entry: entry.as_deref(),
                    create: *create,
                },
            ),
        },
        Commands::Curl { provider, out, url } => {
            entries::cmd_curl(a, provider, url.first().map(String::as_str), out.as_deref())
        }
        Commands::Calendar { cmd } => match cmd {
            CalendarCmd::Export {
                kinds,
                project,
                out: out_path,
                name,
            } => {
                let project = scoped_project(a, project.as_deref())?;
                cmd_calendar(a, kinds, project.as_deref(), out_path.as_deref(), name)
            }
            CalendarCmd::Feed(feed_cmd) => match feed_cmd {
                FeedCmd::New {
                    kinds,
                    name,
                    include_account_names,
                    out: out_path,
                } => feed_cmd::new(a, kinds, name, *include_account_names, out_path.as_deref()),
                FeedCmd::Ls => feed_cmd::ls(a),
                FeedCmd::Revoke { id, yes } => feed_cmd::revoke(a, id, *yes),
            },
        },
        Commands::Uid { cmd } => match cmd {
            UidCmd::Check { values, normalise } => uid_cmd::check(a, values, normalise),
            UidCmd::Register {
                values,
                normalise,
                namespace,
                generator,
                note,
            } => uid_cmd::register(
                a,
                values,
                normalise,
                namespace.as_deref(),
                generator.as_deref(),
                note.as_deref(),
            ),
            UidCmd::Mint {
                length,
                namespace,
                generator,
            } => uid_cmd::mint(a, *length, namespace.as_deref(), generator.as_deref()),
            UidCmd::Lookup { value, normalise } => uid_cmd::lookup(a, value, normalise),
            UidCmd::Prune {
                before,
                namespace,
                generator,
                actor,
                dry_run,
                yes,
            } => uid_cmd::prune(
                a,
                before,
                namespace.as_deref(),
                generator.as_deref(),
                actor.as_deref(),
                *dry_run,
                *yes,
            ),
            UidCmd::Stats => uid_cmd::stats(a),
        },
        Commands::BlastRadius { host, since } => blast_cmd::run(a, host, since.as_deref()),
        Commands::History { cmd } => match cmd {
            HistoryCmd::Ls {
                project,
                exporter,
                since,
                limit,
            } => history_cmd::ls(
                a,
                project.as_deref(),
                exporter.as_deref(),
                since.as_deref(),
                *limit,
            ),
            HistoryCmd::Show { seq, out } => history_cmd::show(a, *seq, out.as_deref()),
            HistoryCmd::DiffFile {
                file,
                project,
                exporter,
                seq,
            } => history_cmd::diff_file(a, project.as_deref(), exporter.as_deref(), *seq, file),
            HistoryCmd::Diff {
                project,
                exporter,
                from,
                to,
                out,
            } => history_cmd::diff(
                a,
                project.as_deref(),
                exporter.as_deref(),
                *from,
                *to,
                out.as_deref(),
            ),
            HistoryCmd::Snapshot { project } => history_cmd::snapshot(a, project.as_deref()),
            HistoryCmd::Prune { keep, days } => history_cmd::prune(a, *keep, *days, yes),
            HistoryCmd::Verify => history_cmd::verify(a),
            HistoryCmd::Policy {
                enable,
                disable,
                keep,
                days,
            } => history_cmd::policy(
                a,
                if *enable {
                    Some(true)
                } else if *disable {
                    Some(false)
                } else {
                    None
                },
                *keep,
                *days,
            ),
            HistoryCmd::Where { sha256 } => history_cmd::which(a, sha256),
            HistoryCmd::Stats => history_cmd::stats(a),
        },
        Commands::Node { cmd } => match cmd {
            NodeCmd::Token {
                cmd:
                    NodeTokenCmd::New {
                        name,
                        projects,
                        ttl,
                        out,
                    },
            } => node_cmd::token_new(
                a,
                name,
                projects,
                Some(node_cmd::parse_ttl(ttl)?),
                out.as_deref(),
            ),
            NodeCmd::Ls => node_cmd::ls(a),
            NodeCmd::Show { node } => node_cmd::show(a, node),
            NodeCmd::Revoke { node } => node_cmd::revoke(a, node, yes),
            NodeCmd::Pull {
                node,
                target,
                out,
                into_chunk,
                apply,
                timeout,
            } => node_cmd::pull(
                a,
                node,
                target,
                out.as_deref(),
                into_chunk.as_deref(),
                *apply,
                *timeout,
            ),
            NodeCmd::Accept { node, target } => node_cmd::accept(a, node, target),
            NodeCmd::Policy { node, approval } => node_cmd::policy(a, node, approval),
            NodeCmd::Approver { cmd } => match cmd {
                ApproverCmd::Show => node_cmd::approver_show(),
                ApproverCmd::Register { label } => node_cmd::approver_register(a, label),
                ApproverCmd::Ls => node_cmd::approver_ls(a),
                ApproverCmd::Rm { fingerprint } => node_cmd::approver_rm(a, fingerprint, yes),
            },
            NodeCmd::Approvals { node, all } => node_cmd::approvals(a, node.as_deref(), *all),
            NodeCmd::Approve { approval } => node_cmd::decide(a, approval, true, yes),
            NodeCmd::Reject { approval } => node_cmd::decide(a, approval, false, yes),
            // Agent-side commands are handled before a connection exists.
            NodeCmd::Enroll { .. } | NodeCmd::Run { .. } | NodeCmd::Check { .. } => Ok(()),
        },
        Commands::Cxf { cmd } => match cmd {
            CxfCmd::Import {
                file,
                project,
                category,
            } => cxf_cmd::cmd_import(a, file, project.as_deref(), category.as_deref()),
            CxfCmd::Export { out, provider } => cxf_cmd::cmd_export(a, out, provider.as_deref()),
        },
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
                let project = scoped_project(a, project.as_deref())?;
                let env = scoped_env(env.as_deref())?;
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
        } => {
            let project = scoped_project(a, project.as_deref())?;
            envfile::watch(
                a,
                file,
                &envfile::ImportOpts {
                    project: project.as_deref(),
                    category: category.as_deref(),
                    environment: None,
                    price: "local",
                    allow_duplicates: false,
                },
            )
        }
        Commands::Env { project, out } => chunks::export(a, project, Some("env"), out.as_deref()),

        Commands::Exec {
            project,
            entries: entry_specs,
            pools: pool_specs,
            prefix,
            clean,
            argv,
        } => {
            let project = scoped_project(a, project.as_deref())?;
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
        Commands::Shield { argv } => {
            let code = shield::run(a, argv)?;
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

        Commands::Totp { cmd } => match cmd {
            EntryTotpCmd::Code { provider, next } => {
                envv_cli::totp_cmd::cmd_code(a, provider, *next)
            }
            EntryTotpCmd::Ls => envv_cli::totp_cmd::cmd_ls(a),
            EntryTotpCmd::Add {
                name,
                seed,
                seed_stdin,
                account,
                kind,
                counter,
            } => {
                let fields = EntryFields {
                    totp: seed.clone(),
                    totp_stdin: *seed_stdin,
                    totp_kind: kind.clone(),
                    totp_counter: *counter,
                    ..Default::default()
                };
                entries::cmd_totp_add(a, name, account.as_deref(), &fields)
            }
            EntryTotpCmd::Advance {
                provider,
                by,
                yes: cmd_yes,
            } => envv_cli::totp_cmd::cmd_advance(a, provider, *by, yes || *cmd_yes),
            EntryTotpCmd::Uri { provider, out } => {
                envv_cli::totp_cmd::cmd_uri(a, provider, out.as_ref())
            }
            EntryTotpCmd::Rm { provider } => envv_cli::totp_cmd::cmd_rm(a, provider, yes),
            EntryTotpCmd::Import {
                file,
                format,
                project,
                category,
                force,
            } => envv_cli::totp_cmd::cmd_import(
                a,
                file,
                format.as_deref(),
                project.as_deref(),
                category.as_deref(),
                *force,
            ),
            EntryTotpCmd::Export { format, out, only } => {
                envv_cli::totp_cmd::cmd_export(a, format, out.as_ref(), only.as_deref())
            }
        },
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
            } => {
                let project = scoped_project(a, project.as_deref())?;
                let env = scoped_env(env.as_deref())?;
                entries::cmd_list(
                    a,
                    project.as_deref(),
                    r#type.as_deref(),
                    tag.as_deref(),
                    env.as_deref(),
                    category.as_deref(),
                    search.as_deref(),
                    *json,
                )
            }
            EntryCmd::Get { provider, field } => entries::cmd_get(a, provider, field.as_deref()),
            EntryCmd::Add {
                provider,
                fields,
                if_missing,
                preset,
            } => entries::cmd_add(a, provider, fields, *if_missing, preset.as_deref()),
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
            EntryCmd::Verify { provider, off } => entries::cmd_verify(a, provider, *off),
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

        Commands::Emit { entry, format, out } => {
            emit_cmd::emit(a, entry, format.as_deref(), out.as_deref())
        }
        Commands::Oauth { cmd } => match cmd {
            OauthCmd::Refresh { entry } => oauth_cmd::refresh(a, entry, yes),
        },
        Commands::Codes { cmd } => match cmd {
            CodesCmd::Status { entry } => emit_cmd::codes_status(a, entry),
            CodesCmd::Next { entry } => emit_cmd::codes_next(a, entry),
            CodesCmd::Use { entry, code } => emit_cmd::codes_use(a, entry, code.as_deref()),
        },

        Commands::Bundle { cmd } => match cmd {
            BundleCmd::Ls => bundle_cmd::ls(a),
            BundleCmd::New {
                name,
                members,
                import,
            } => bundle_cmd::new(a, name, members, import.as_deref()),
            BundleCmd::Add {
                bundle,
                entry,
                slot,
            } => bundle_cmd::add(a, bundle, entry, slot),
            BundleCmd::Remove { bundle, slot } => bundle_cmd::remove(a, bundle, slot),
            BundleCmd::Dissolve { bundle } => bundle_cmd::dissolve(a, bundle, yes),
            BundleCmd::Delete { bundle } => bundle_cmd::delete(a, bundle, yes),
        },

        Commands::Gen { cmd } => match cmd {
            GenCmd::Cert {
                common_name,
                days,
                save_as,
            } => {
                let v = gen::certificate(common_name, *days, &gen::current())?;
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
                entries::cmd_add(a, provider, &fields, false, None)
            }
            GenCmd::Ssh { comment, save_as } => {
                let v = gen::ssh_keypair(comment, &gen::current())?;
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
                entries::cmd_add(a, provider, &fields, false, None)
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
            BackupCmd::Archive {
                file,
                backup_password,
            } => backup::archive(file, backup_password.as_deref()),
            BackupCmd::RestoreArchive {
                file,
                backup_password,
                force,
            } => backup::restore_archive(file, backup_password.as_deref(), *force, yes),
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
        Commands::Diff { a: left, b: right } => envv_cli::diff_cmd::run(a, left, right),
        Commands::Check {
            project,
            fail_on,
            json,
            all_projects,
        } => check_cmd::run(
            a,
            project.as_deref(),
            fail_on.as_deref(),
            *json,
            *all_projects,
        ),
        Commands::Scan {
            severity,
            json,
            exposed,
            out,
        } => match exposed {
            Some(path) => scan::cmd_exposed(a, path, out.as_deref()),
            None => scan::cmd_scan(a, severity, *json),
        },
        Commands::ImportVault {
            vendor,
            file,
            apply,
            project,
            category,
            keep_folders,
        } => {
            let project = scoped_project(a, project.as_deref())?;
            import_vaults::run(
                a,
                vendor,
                file,
                &import_vaults::ImportOpts {
                    apply: *apply,
                    project: project.as_deref(),
                    category: category.as_deref(),
                    keep_folders: *keep_folders,
                },
            )
        }
        Commands::Use {
            project,
            env,
            show,
            clear,
        } => envv_cli::context::cmd_use(Some(a), project.as_deref(), env.as_deref(), *show, *clear),
        Commands::Status => scan::cmd_status(a),
        Commands::Doctor { fix } => doctor::run(Some(a), None, *fix),

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
            UserCmd::StrictWrite { user, off } => users_cmd::set_strict(a, "user", user, !*off),
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
            UserCmd::Totp { cmd } => match cmd {
                TotpCmd::Status { user } => users_cmd::totp_status(a, user),
                TotpCmd::Enroll { user, out } => users_cmd::totp_enroll(a, user, out.as_deref()),
                TotpCmd::Confirm { user, code } => users_cmd::totp_confirm(a, user, code),
                TotpCmd::Disable { user } => users_cmd::totp_disable(a, user, yes),
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
