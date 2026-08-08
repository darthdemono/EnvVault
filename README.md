# EnvVault

A local-first desktop secrets manager built with Tauri 2. Stores API keys, passwords, certificates, SSH keys, and structured project configs inside an SQLCipher-encrypted database. No cloud, no telemetry, no plaintext on disk.

---

## Features

### Secret Management
- **7 secret types**: API key, password, certificate (X.509), SSH key, environment variable, connection string, file blob
- **Per-entry metadata**: provider, account, description, URL, scopes, rate limit, expiry date, last rotated, environment tag (production / staging / development / testing)
- **Version history**: last 50 values auto-saved per entry when the key changes
- **Append-only audit log**: every add, update, and delete written to `vault_audit` with timestamp
- **Tags**: free-form labels on entries, searchable, rendered as color-coded chips on cards
- **Pinned entries**: `pinned` flag floats entries to top of all sorted views; SVG pin badge on card

### Organisation
- **Projects**: named containers for secrets, supports slash-delimited sub-project hierarchy
- **Categories**: flat tags with visual slash grouping
- **Environments**: filter entries by environment across any project
- **Tag sidebar filter**: click a tag chip in the sidebar to filter all entries to that tag
- **WireGuard projects**: structured interface + peer chunks, two-column layout, exports `wg0.conf`
- **Docker projects**: service / network / volume / env_file chunks; aggregate services card with nested YAML-like display; exports `docker-compose.yaml` + `.env`
- **Nginx projects**: full nginx config import (`parseNginxConf`), smart field display (listen badges, server name badges, return redirect badges, SSL cert panel), `nginx_key` chunk for PEM cert/key display
- **Apache projects**: `apache_vhost` / `apache_directory` chunks, import + export to httpd config
- **HAProxy projects**: `haproxy_global` / `haproxy_frontend` / `haproxy_backend` chunks, import + export to haproxy.cfg
- **Ansible projects**: `ansible_vars` / `ansible_task` chunks, export to YAML vars + task list
- **PostgreSQL projects**: `pg_connection` / `pg_role` chunks, export to `.pgpass` format
- **Kubernetes / SSH Config / Traefik**: additional structured project types
- **`${REF_NAME}` field linking**: fields can reference vault entries by name; resolved at render time with green (found) / amber (missing) status badges
- **Chunk notes + disable**: per-chunk freetext notes; disabled chunks are greyed out and excluded from all exports

### Security
- **Encryption**: SQLCipher AES-256-CBC, key never written to disk
- **KDF (master)**: Argon2id (m=65536, t=3, p=1), 16-byte random salt
- **Sub-user passwords**: Argon2id PHC (m=32768, t=2, p=1); legacy SHA-256 hashes auto-upgraded on next login
- **Vault integrity check**: SHA-256 of vault data stored in `vault_meta`, verified on every unlock
- **WAL mode**: SQLite WAL journal for concurrent reads
- **Auto-lock**: configurable timer (default 60 min, 0 = never), 1-minute warning toast, activity-based timer reset (mousemove / keydown / mousedown / touchstart)
- **Re-lock overlay**: dedicated mid-session lock screen with context message (auto / manual / visibility); separate from the startup unlock modal
- **Rate limiter**: 10 failures per IP per 60-second window; counter increments on auth failure only (not on structural errors); IP from real socket address, not `X-Forwarded-For`

### Built-in Tools
- **Random key generator**: 32/64-byte hex
- **Certificate generator**: self-signed X.509 via `rcgen`
- **SSH keypair generator**: Ed25519 via `ssh-key`
- **Health dashboard**: scans for weak (<12 char), expired, expiring-soon (30d), never-rotated, and undescribed secrets
- **Secret Diff**: field-by-field table compare of two vault entries (secrets masked)
- **Expiry Calendar**: month grid with color-coded dots (red = expired, amber = ≤30d, green = safe); prev/next month navigation
- **Cron Explainer**: 5-field cron parse + named shortcuts (`@daily` etc.) + next 5 fire times
- **CIDR Calculator**: network / broadcast / hosts / subnet mask from CIDR notation
- **JSON / YAML Formatter**: Format (JSON 2-space pretty-print), Validate (parse error reporting), Minify (flow style); backed by `js-yaml` round-trip
- **Import**: `.env` files, Bitwarden JSON, 1Password JSON, raw vault JSON
- **Export**: `.env`, YAML, JSON — per-entry or bulk
- **Secret templates**: 10 predefined templates (GitHub PAT, AWS Access Key, Stripe, PostgreSQL DSN, OpenAI, Cloudflare, SSH Key Pair, TLS Certificate, env variable, Docker Registry)
- **Regex search**: `/pattern/flags` syntax in the search bar
- **Form draft autosave**: add/edit modal drafts persisted to `sessionStorage` on every keystroke; restored on reopen

### Multi-User (RBAC)
- Users table with hashed passwords (Argon2id); owner = vault creator
- **API tokens**: per-user bearer tokens for CLI/server access
- **User classes**: named role templates (Admin, Moderator, Viewer + custom), each with capability flags and permission rules
- **Capabilities**: `manage_users`, `manage_classes`, `delete_projects`
- **Permission expressions**: boolean rules over entries — `AND` / `OR` / `NOT` with parentheses
  - Terms are `field:glob` over `vault`, `project`, `category`, `tag`, `env`, `type`
  - e.g. `project:Alpha AND NOT category:secret`, `(project:web OR project:api) AND env:production`
  - One rule for read, one for write, per user and per class
  - `field:*` means "no constraint on that field"; a specific `project:` term is never satisfied by the `Universal` catch-all
  - Malformed expressions **deny** — they are rejected on save and fail closed if they somehow reach evaluation
- Effective permissions = class expression **AND** individual expression (a class exclusion cannot be undone individually); write implies read

### Remote Server
- Axum 0.8 HTTP server (`envv-server`) binding `127.0.0.1:8743` by default
- **TLS**: `--tls` flag enables HTTPS; `--cert` / `--key` for BYO PEM; auto-generates self-signed cert (valid 3 years for `localhost` + `127.0.0.1`) via `rcgen` if absent
- **Cert fingerprint**: `GET /api/status` includes `cert_fingerprint` (SHA-256 of DER cert); desktop app uses TOFU model for self-signed cert pinning; warns on rotation
- **TLS proxy command**: Tauri `remote_request` command routes HTTPS calls through Rust/reqwest (bypasses WebKit TLS restrictions for self-signed certs)
- Rate limiting: 10 failed attempts per IP per 60-second window on auth endpoints
- Bearer token auth; sessions expire after an idle timeout (`--session-ttl-mins`, default 480)
- Remote vault panel in the desktop app: save multiple connections, connect/disconnect, server status
- Keep-alive ping: 90-second interval on connected sessions (`GET /api/ping`)
- Remote-first login: server URL in the unlock modal switches to remote mode

### CLI (`envv`)
```
envv [--server URL] [--password PWD] <command>

list          [--project NAME] [--type TYPE]
get           <provider>
export        [--format dotenv|yaml|json] [--project NAME]
rotate-check  [--days 30]
import        <file.env>
audit         [--limit 50]
completions   <bash|zsh|fish|elvish|powershell>
watch         <file.env> [--project ID]
```

`watch` monitors a `.env` file for changes and auto-syncs to the vault. `completions` generates shell completion scripts via `clap_complete`.

---

## Using the App

### First Run
On first launch EnvVault creates a new vault. Enter a master password (minimum 12 characters) and confirm it. The password is never stored — it is run through Argon2id to derive the encryption key that opens the SQLCipher database. If you forget it there is no recovery; delete `vault.db` + `vault.salt` to start over.

### Layout
The app has three main areas:

```
┌─────────────────────────────────────────────────────┐
│  Header: search · sort · expand-all · copy-all · +  │
├──────┬──────────────────────────────────────────────┤
│      │                                              │
│ Side │  Main workspace                              │
│ bar  │  (secrets grid, project config view,         │
│      │   or tool pane)                              │
│      │                                              │
├──────┴──────────────────────────────────────────────┤
│  Activity bar (left): Secrets · Tools · Users · Remote │
└─────────────────────────────────────────────────────┘
```

- **Activity bar** — switches between the four main panels. Position (left / right) and order are configurable in Settings → Layout.
- **Sidebar** — shows Projects (structured) and Categories (flat tags). Click any item to filter. Click again to deselect. Drag the resize handle to adjust width (140–420 px). Toggle with `B` or the hamburger button.
- **Header** — search bar, sort picker, Expand All / Collapse All, Copy All (dropdown: .env / YAML / JSON), Add button.

### Adding a Secret
1. Press `Ctrl+N` or click **+** in the header.
2. Select secret type at the top of the form (API key, password, certificate, SSH key, env var, connection string, file blob).
3. Fill in Provider (required) and Key/Value. Click **Generate** next to the key field for type-aware generation (X.509 cert, Ed25519 keypair, or 32-byte hex).
4. Assign to Projects and Categories, set environment tag, expiry date, scopes, etc.
5. Click **Save**. The form draft auto-saves to `sessionStorage` on every keystroke — reopening the modal restores it.

### Secret Cards
Each card in the grid shows provider, account, environment badge, and masked key(s).

| Action | How |
|--------|-----|
| Copy key | Click card header or the copy icon next to the key |
| Copy .env line | Click the `.env` badge button in the card footer |
| Reveal / hide | Eye icon next to the key field |
| Expand details | Chevron (▾) or click the card header area |
| Edit | Pencil icon in footer |
| Duplicate | Two-page icon in footer |
| Mark rotated | ↺ icon in footer (updates `last_rotated_at`) |
| Pin to top | Pin icon in footer (pinned entries always sort first) |
| Delete | Trash icon in footer (with undo toast, 5 s) |
| Right-click | Context menu: Copy Provider / Copy Key / Copy Secret / Copy .env / Edit / Duplicate / Delete |

Cards show a **colored left border** based on expiry: red = expired or ≤7 days, amber = ≤30 days, green = has expiry and safe.

### Searching and Filtering
- Type in the search bar to filter by provider, account, description, tags, and URL.
- Use `/pattern/flags` syntax for regex search (e.g. `/^AWS/i`).
- Click a **Project** or **Category** in the sidebar to scope results.
- Click a **tag chip** in the sidebar Tags section to filter by that tag.
- Click an **environment** badge (production / staging / development / testing) in the sidebar to filter by environment.
- Sort order: **A–Z** (default), Price Type, Category, Expiry. Select from the sort button in the header.

### Projects (Structured Config)
Projects are named containers for structured config, separate from the flat secrets grid.

**Creating a project:**
1. Click **+** in the Projects section of the sidebar.
2. Enter a name — use `/` for hierarchy (e.g. `infra/k8s`; ancestor nodes are auto-created).
3. Select a project type.

**Project types and what they do:**

| Type | Chunks | Export |
|------|--------|--------|
| Generic | Any key/value chunks | — |
| WireGuard | `wg_interface`, `wg_peer` | `wg0.conf` |
| Docker | `docker_service`, `docker_network`, `docker_volume`, `env_file` | `docker-compose.yaml` + `.env` |
| Nginx | `nginx_server`, `nginx_location`, `nginx_key` (PEM) | nginx site config |
| Apache | `apache_vhost`, `apache_directory` | httpd config |
| HAProxy | `haproxy_global`, `haproxy_frontend`, `haproxy_backend` | haproxy.cfg |
| Ansible | `ansible_vars`, `ansible_task` | YAML vars + task list |
| PostgreSQL | `pg_connection`, `pg_role` | `.pgpass` |
| Kubernetes | `k8s_deployment`, `k8s_service` | Kubernetes YAML |
| SSH Config | `ssh_host` | `~/.ssh/config` |
| Traefik | `traefik_router`, `traefik_service` | Traefik dynamic config |

**Working with chunks:**
- Click **Edit** on a chunk card to edit its fields in a modal.
- Click **Copy** on a chunk card header to copy the entire chunk in its native format (e.g. WireGuard `[Interface]` block, nginx `server { … }`, env `KEY=value` lines).
- Use `${REF_NAME}` in any field value to reference a vault entry by provider name. Green badge = resolved; amber = not found.
- Chunks can have **Notes** (freetext) and can be **Disabled** (excluded from exports, greyed out in the UI).

**Nginx import:** In an nginx project, click **Import site config** in the project header → paste or load from file. The parser handles `server {}`, nested `location {}` blocks, and multi-word directives. SSL cert fields are auto-linked to matching vault certificate entries.

**Docker import:** Paste a `docker-compose.yaml` via the Import button in the services card header. All services, networks, volumes, and environment files are imported as chunks.

### Categories
Categories are free-form text tags attached to entries (distinct from Projects). They appear in the sidebar and can be used to filter. Use `/` in a category name for visual grouping (e.g. `cloud/aws`, `cloud/gcp`) — these are display-only, not a real hierarchy.

### Tools Panel
Switch to **Tools** in the activity bar. Available tools:

| Tool | What it does |
|------|-------------|
| Key Generator | 32 / 64 byte random hex |
| Certificate Generator | Self-signed X.509 via `rcgen` |
| SSH Keypair | Ed25519 via `ssh-key` |
| Health Dashboard | Scans for weak, expired, expiring-soon, never-rotated, undescribed secrets |
| Secret Diff | Field-by-field compare of two vault entries (secrets masked) |
| Expiry Calendar | Month grid with color-coded expiry dots |
| Cron Explainer | Parse 5-field cron expressions + next 5 fire times |
| CIDR Calculator | Network / broadcast / hosts / mask from CIDR |
| JSON / YAML Formatter | Format, validate, or minify JSON / YAML |
| Import | `.env`, Bitwarden JSON, 1Password JSON, raw vault JSON |
| Templates | 10 predefined templates (GitHub PAT, AWS, Stripe, PostgreSQL DSN, OpenAI, …) |
| Bulk Operations | Select mode → bulk delete or bulk export `.env` |

### Settings
Press `S` or click the gear icon. Tabs:

- **Appearance** — theme (Dark / Midnight / Dracula / Nord / Catppuccin / Light / System), accent color
- **Layout** — card size, grid columns, panel order, activity bar position/style
- **Security** — auto-lock timeout (0 = never), mask keys by default
- **Data** — default export format, expiry warning days, custom CSS
- **Remote** — saved remote vault connections
- **Advanced** — vault file path display

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+K` | Focus search bar |
| `Ctrl+N` | Add new secret |
| `Esc` | Clear search / close modal |
| `S` | Open settings (when not in a text field) |
| `B` | Toggle sidebar (when not in a text field) |
| `?` | Show this shortcuts reference |

In prompt dialogs: `Enter` to confirm, `Esc` to cancel. In multi-line prompts: `Ctrl+Enter` to confirm.

### Auto-Lock
The vault locks automatically after the configured idle timeout (default 60 minutes). Any mouse or keyboard activity resets the timer. One minute before lock a dismissible warning toast appears.

When locked mid-session a **re-lock overlay** appears (separate from the startup screen) showing why it locked (auto / manual / background). Enter your password to resume — no need to re-enter server URL or username.

The vault also locks when the window is hidden (minimize / alt-tab), unless connected to a remote vault (remote sessions use bearer tokens that would be lost on lock).

---

## Architecture

```
Tauri 2 desktop app
├── Frontend: TypeScript + Vite → dist/  (served as static files)
├── Backend:  Rust (#[tauri::command] via window.__TAURI__.invoke)
└── Database: SQLCipher (AES-256-CBC) via rusqlite

Cargo workspace
├── vault-core/     shared Rust library (KDF, DB, users, RBAC, generators)
├── envv-server/    Axum HTTP server binary
├── envv-cli/       CLI binary
└── src-tauri/      Tauri desktop app (thin wrappers over vault-core)
```

**Encryption flow:**
```
Password + 16-byte random salt  →  Argon2id  →  32-byte key (memory only)
                                                        ↓
                                        SQLCipher DB (AES-256-CBC)
                                        PRAGMA key = "x'<hex>'"
```

**File paths on Linux:**
- DB: `~/.local/share/io.envvault/vault.db`
- Salt: `~/.local/share/io.envvault/vault.salt`
- Settings: `~/.config/io.envvault/settings.json` (plain JSON, not encrypted)

> **Migration note (API Vault → EnvVault):** The application identifier changed from `io.apivault` to `io.envvault`. Existing users must move their vault files manually before launching the renamed build, otherwise EnvVault will prompt for a new vault:
> ```bash
> mv ~/.local/share/io.apivault ~/.local/share/io.envvault
> mv ~/.config/io.apivault ~/.config/io.envvault
> ```

---

## Building

### Prerequisites

```bash
# Fedora / Nobara
sudo dnf install openssl-devel perl-FindBin perl-IPC-Cmd patchelf fuse fuse-libs

# Required in ~/.bashrc
export APPIMAGE_EXTRACT_AND_RUN=1
export NO_STRIP=1
```

Requires: Rust 1.85+ (rustup), Node v22+, `cargo-tauri` v2, `mold` linker.

### Development

```bash
npm run dev          # Vite dev server (UI hot-reload only)
cargo tauri dev      # Full Tauri window with hot-reload
```

### Type checking

```bash
npx tsc --noEmit
cargo check
```

### Production build

```bash
source ~/.bashrc
cargo tauri build                                         # desktop AppImage
cargo build --release -p envv-server -p envv-cli         # server + CLI binaries
```

### Running server and CLI

```bash
# HTTP (local use)
./target/release/envv-server --port 8743

# HTTPS with auto-generated self-signed cert
./target/release/envv-server --port 8743 --tls

# HTTPS with BYO cert
./target/release/envv-server --port 8743 --tls --cert /path/to/cert.pem --key /path/to/key.pem

./target/release/envv list
./target/release/envv completions bash >> ~/.bash_completion
ENVV_PASSWORD=mypassword ./target/release/envv --server http://localhost:8743 export --format dotenv
```

---

## Remote Server API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/unlock` | — | `{password}` → `{token}` (rate-limited, integrity-checked) |
| DELETE | `/api/unlock` | token | Lock vault, invalidate token |
| GET | `/api/status` | — | `{unlocked, vault_exists, cert_fingerprint}` |
| POST | `/api/auth` | — | `{username, password}` or `{token}` → `{token}` |
| GET | `/api/ping` | token | Keep-alive: `{ok, ts}` |
| GET | `/api/vault` | token | Full `VaultData` |
| PUT | `/api/vault` | token | Save `VaultData` |
| GET | `/api/vault/expiring?days=30` | token | Expiring entries |
| GET | `/api/audit` | token | Audit log |
| GET/POST/DELETE | `/api/users/…` | owner | User management |
| GET | `/api/stats` | — | Public instance stats (secrets, users, sessions) |
| GET | `/api/openapi.json` | — | OpenAPI spec |

---

## Docker

```bash
# Build and start
docker compose up -d

# With a pre-built image
docker run -d \
  --name envv-server \
  -p 8743:8743 \
  -v envv_data:/data \
  envv-server:0.6.0
```

Data persists in the `envv_data` volume at `/data/vault.db` and `/data/vault.salt`. After starting, unlock the vault via the API:

```bash
curl -X POST http://localhost:8743/api/unlock \
  -H 'Content-Type: application/json' \
  -d '{"password":"your-master-password"}'
```

Set `ENVV_PASSWORD` in the container environment to auto-unlock on startup (Docker / CI use case).

To change the port, pass `--port <N>` via `command:` in `docker-compose.yml` or as extra args to `docker run`.

---

## Dashboard Widgets

`GET /api/stats` returns live counts with no authentication:

```json
{
  "secrets_stored": 42,
  "users_total": 5,
  "users_connected": 2,
  "vault_unlocked": true
}
```

Counts are 0 when the vault is locked.

### Homepage (gethomepage.dev)

Add to your `services.yaml`:

```yaml
- EnvVault:
    icon: mdi-lock-outline
    href: http://your-server:8743
    widget:
      type: customapi
      url: http://your-server:8743/api/stats
      mappings:
        - field: secrets_stored
          label: Secrets
          format: number
        - field: users_total
          label: Users
          format: number
        - field: users_connected
          label: Connected
          format: number
```

### Homarr

Add a "Custom API" tile:

- **API URL**: `http://your-server:8743/api/stats`
- Add three fields mapped to `secrets_stored`, `users_total`, `users_connected`

---

## Themes

6 built-in themes plus `system` (follows OS `prefers-color-scheme`): Dark, Midnight, Dracula, Nord, Catppuccin, Light.

---

### Phase 8 — auth model and permissions

**The owner is now a real user row.** It was the magic string `"owner"` — no row,
no class, absent from the user list, and unnameable in an audit entry. It is now
an actual record with `is_owner = 1` and, deliberately, **`password_hash = NULL`**:
storing a hash of the master password there would be an offline oracle for the
vault key. Ownership is still proven by deriving the SQLCipher key, and the row
can never be logged into via `/api/auth`.

**Username enumeration oracle closed.** `verify_user_password` returned `Err` for
a user with no password (→ HTTP 500) but `Ok(None)` for a nonexistent user (→ 401),
and only the 401 path incremented the rate limiter. The 500-vs-401 difference
revealed which usernames existed, unthrottled. Both are now ordinary credential
failures.

**Lock actually locks.** `DELETE /api/unlock` removed only the caller's session,
while every user session held its *own copy* of the vault key — so an owner
"locking" left everyone else reading and writing indefinitely. An owner lock is
now global: all sessions dropped, all keys zeroized. A non-owner lock remains a
personal logout.

**Audit log records who, not just what.** `save_vault` takes an actor, and
`vault_audit` gained an `actor` column bound into the hash chain, so attribution
cannot be rewritten undetected. Two chain formats coexist — v2
(`action|provider|timestamp|actor|prev`) for new rows, v1 for rows written
before the column — and the verifier tries v2 then falls back, so existing logs
still verify. Read events are no longer logged: every `GET /api/vault` wrote a
row, so polling clients grew the table without bound, and pruning it would have
broken the very chain that makes the log tamper-evident.

**Write scoping relaxed to ANY-match.** Write previously required *every* scope an
entry declared to be covered, which made project-scoped grants unusable since
almost every entry also carries a category. One matching category or project is
now enough — the same rule reads already used. A `scope_value` of `*` is treated
as an unconditional match for its type, so wildcards reach unfiled entries and
`project:*` and `category:*` behave identically. Note the consequence: for scoped
users, "can see it" and "can edit it" are now close to the same thing; vault
scope remains the real privilege boundary.

**Removed:** the `chunk` secret type. It was in the dropdown but *could never be
saved* — `dynamicSecretFields` hid its key input while `saveModal` still required
`api_key`. Its content lived in `extra_vars`, which ordinary cards render anyway,
so existing entries are relabelled to `env_var` on load with nothing lost. Project
`SecretChunk`s (WireGuard, Docker, nginx) are a different concept and untouched.

**Users panel is gated.** On a purely local vault it wrote accounts into the
desktop's own `vault.db`, which `envv-server` never reads — they could never
authenticate anywhere. It now appears only when connected to a remote vault, or
(from Phase 9) when serving over LAN.

**Also:** `productName` corrected from the stale `API-Vault`; the crossed DOM ids
renamed (`#project-tree` held categories, `#category-list` held projects); and the
`types.ts` comments that claimed a UI-label inversion which does not exist.

### Phase 9 — permission expressions

Permissions were a flat list of `(scope_type, scope_value, permission)` rows,
which could only ever mean "any of these matches". They are now boolean
expressions:

```
project:Alpha AND NOT category:secret
(project:web OR project:api) AND env:production
tag:shared OR type:certificate
```

Precedence is `NOT` > `AND` > `OR`; parentheses override. `&&`, `||` and `!` are
accepted as aliases and operators are case-insensitive. Adjacency is *not*
implicit AND — an operator is always required, so an expression can never quietly
mean something other than it reads.

Matchable fields: `vault`, `project` (id or display name), `category`, `tag`,
`env`, `type`.

**Composition.** A user's class expression is ANDed with their individual one, so
a class-level exclusion is a real boundary rather than a suggestion. Absent
expressions are *not* treated as "no restriction": with AND that would give a
user holding no permissions at all full access, so no expression at all means no
grant. Write implies read, so the effective read rule is `read OR write`.

**Migration.** Existing rows are compiled once into equivalent OR-chains — read
from every row, write from write rows — reproducing the previous read behaviour
exactly. The migration is guarded by a marker in `vault_meta`, so deliberately
clearing every expression does not resurrect the old rules on the next start, and
it runs after class seeding so the built-in Admin/Moderator/Viewer classes are
themselves compiled.

**Failure mode is deny.** `set_permission_expr` parses before storing, so a
malformed rule is rejected at the API with a 400 rather than saved as something
that silently denies everything. Stored text is re-parsed on every evaluation
rather than trusted, so a row edited outside the app also fails closed.

**Editor.** The Users and Classes panels now show a read box and a write box with
live syntax validation, a predicate builder that inserts terms from the values
actually present in your vault, and a "matches N of M entries" preview. The
preview is advisory — `vault-core` re-parses and re-evaluates everything, and is
the only thing that decides real access.

### Phase 10 — Open to LAN

Serve the vault you already have open to your local network, straight from the
desktop app. Minecraft-style: it exists while the app does and closes when you
lock or quit. Docker remains the option for something always-on.

`envv-server` is now a library; the binary is a thin CLI wrapper around it and
the desktop hosts the **same router in-process**. One vault file, one master
password, no subprocess to supervise — and no possibility of the two drifting
apart in what they expose.

**Peers sign in as users.** `POST /api/unlock` is refused while hosting, so the
master password never crosses the network and no peer can arrive as tier-3
owner. The host's key is adopted directly into an owner session in memory, which
is why nobody re-enters a password. Starting is refused outright when no
password-capable user exists yet — the app sends you to the Users panel rather
than advertising a server nobody can log into.

**Defaults.** Binds `0.0.0.0` on port **8744** (stepping forward if taken, so a
Docker `envv-server` on 8743 can coexist), with self-signed TLS on. The
certificate is persisted and reused — regenerating per launch would change the
fingerprint every time and break every peer's pin. The fingerprint is shown in
the UI for peers to pin via the existing Phase 6 pinning path.

**Locking.** Auto-lock and lock-on-hide are suspended while serving: peers are
mid-request and the host not touching the keyboard is no reason to cut them off.
Because that would otherwise leave the vault decrypted indefinitely on an
unattended machine, the server closes itself after **8 hours with no peer
traffic**, which re-arms normal auto-lock. An explicit lock stops the server and
disconnects everyone, behind a confirmation naming how many peers are connected.
Every teardown path zeroizes the keys held by peer sessions.

**Users panel** becomes visible whenever you are hosting, since local accounts
now mean something.

### Phase 10.1 — closing the lost-update window

Opening the vault to the LAN made the desktop and its peers concurrent writers on
the same database. The desktop wrote the whole blob unconditionally, so a peer's
edit landing between the desktop's last load and its next save was silently
overwritten — no error, no warning, the change simply gone.

**The check now lives inside `save_vault`.** `SaveCtx { actor, expect_version }`
carries the version the caller last read, and the comparison happens inside the
same `BEGIN IMMEDIATE` transaction as the write. Putting it there rather than in
each caller fixes two problems at once: a caller that reads, compares and then
writes has a race between the compare and the write (which is what the server's
`If-Match` handling was), and a caller that simply forgets is silently
unprotected (which is what the desktop was).

`SaveCtx` is a struct rather than two positional `Option<&str>` arguments because
swapping an actor id for a version hash would disable the concurrency check while
still compiling and still passing every test.

**Audit writes moved inside the transaction.** They previously ran before it, so
a rejected or failed write still appended audit rows describing changes that
never happened. There is a test asserting a refused write leaves no trace — no
audit rows, no version change, integrity intact.

**Version identity.** The version is the `data_hash` that `save_vault` already
stored, so it is by construction the hash of exactly the bytes on disk. The GET
ETag now reads that same stored value instead of re-hashing the parsed JSON;
re-serialising a `Value` happens to reproduce the stored bytes today, but relying
on it would make every `If-Match` request 409 the moment it stopped being true.

**Read ordering.** Where a handler needs both the version and the data it
describes, the version is read first. Mis-pairing that way can only pin an older
version than the data, which fails the compare-and-swap and retries. The other
order passes the check while merging against a stale base — the clobber itself.

**On conflict the desktop asks.** There is no safe automatic answer: silently
picking a winner is how data goes missing. You get the choice between keeping
your version (an explicit unconditional overwrite) and reloading theirs, with the
cost of each spelled out.

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Tauri wrapper, static frontend | Complete |
| 2 | SQLCipher + Argon2id encrypted storage | Complete |
| 3 | TypeScript + Vite, Projects groundwork, structured project types | Complete |
| 4 | Remote vault server + CLI | Complete |
| 5 | Multi-user RBAC, user classes, remote panel, health dashboard | Complete |
| 5.1 | Security hardening (Argon2id sub-users, rate limiter, CORS) | Complete |
| 6 | TLS on server, cert pinning, tag sidebar filter, YAML formatter, re-lock overlay | Complete |
| 7 | Correctness pass: stable entry ids, audit log viewer, offline fonts, tests + CI | Complete |
| 8 | Auth model simplification, audit attribution, permission scoping | Complete |
| 9 | Permission expression language (AND / OR / NOT) | Complete |
| 10 | Open to LAN — host your vault from the desktop app | Complete |
| 10.1 | Lost-update fix: compare-and-swap on every vault write | Complete |

### Phase 7 — correctness and hygiene

**Data integrity**
- Every entry now carries a stable `id`. It is the single identity used for audit
  attribution, `version_history` and RBAC write scoping. Previously `save_vault`
  keyed on `provider|account_name` while the RBAC merge keyed on
  `provider|account_name|key_id`, so the two disagreed and history could be
  attributed to the wrong entry. Existing vaults are backfilled on first load.
- `escAttr()` now escapes `&`. It did not, so any secret containing an
  entity-like sequence (`&amp;`, `&lt;`) was HTML-decoded on read-back and
  **copy-to-clipboard returned the wrong value**.

**Security**
- The desktop app no longer seeds an `admin` sub-user whose password hash is the
  master password — that turned the sub-user login into an oracle for the vault
  password. Sub-users are a server-side concept; create them explicitly.
- Server sessions now expire (`--session-ttl-mins`, default 480). Any
  authenticated request slides the deadline, which is what `GET /api/ping` is
  for. Previously sessions lived until process restart, so a leaked token was
  valid indefinitely.
- TLS fingerprints are parsed with `rustls-pemfile`. The previous hand-rolled
  base64 decoder mapped invalid characters to zero, producing a plausible but
  wrong fingerprint that clients would then pin to.

**Removed**
- TOTP/2FA, end to end. It had no UI and was never reachable.
- The Settings "Quick Connect" pane. Saving settings ran `applyRemoteConfig()`,
  which reassigned the vault store from an unchecked toggle — so opening and
  closing Settings while connected to a remote **silently disconnected it**.
  Remote connections are managed solely in the Remote panel.
- Google Fonts CDN. Syne and JetBrains Mono are vendored via `@fontsource` and
  bundled into `dist/`, so the app makes no outbound request for type and renders
  correctly offline. CSP tightened to `font-src 'self'`.

**Added**
- Audit log viewer (Tools → Audit Log) with hash-chain verification. The chain
  had been written since Phase 3 but nothing ever displayed it.
- 36 unit tests over the crypto, storage and RBAC logic in `vault-core`, plus a
  GitHub Actions workflow running `cargo test`, `cargo check`, `tsc --noEmit`
  and `vite build`.

**Fixed**
- Keep-alive pings read a non-existent `_token` field and went out as `Bearer `,
  so the keep-alive never kept anything alive.
- Remote status checks used bare `fetch()`, bypassing the TLS-pinning proxy and
  reporting "Unreachable" for any HTTPS server with a self-signed cert.
- Expand/reveal state was keyed by array index, so it jumped to neighbouring
  cards after any delete; revealed secrets also silently re-masked on re-render.
- Locking on window-hide is now opt-in (Settings → Security). It used to fire on
  every alt-tab.
- Cron explainer: month names were off by one, and `nextFireTimes` brute-forced
  10 000 consecutive minutes so it could not see past ~7 days.
- `Exporter.yaml` produced invalid YAML for values containing quotes; it now uses
  js-yaml.
- Card grid rendering was O(n²) (`indexOf` per card).
