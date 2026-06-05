# API Vault

A local-first desktop secrets manager built with Tauri 2. Stores API keys, passwords, certificates, SSH keys, and structured project configs inside an SQLCipher-encrypted database. No cloud, no telemetry, no plaintext on disk.

---

## Features

### Secret Management
- **7 secret types**: API key, password, certificate (X.509), SSH key, environment variable, connection string, file blob
- **Per-entry metadata**: provider, account, description, URL, scopes, rate limit, expiry date, last rotated, environment tag (production / staging / development / testing)
- **Version history**: last 50 values auto-saved per entry when the key changes
- **Append-only audit log**: every add, update, and delete written to `vault_audit` with timestamp
- **Tags**: free-form labels on entries, searchable

### Organisation
- **Projects**: named containers for secrets, supports slash-delimited sub-project hierarchy
- **Categories**: flat tags with visual slash grouping
- **Environments**: filter entries by environment across any project
- **WireGuard projects**: structured interface + peer chunks, exports `wg0.conf`
- **Docker projects**: service / network / volume / env_file chunks, exports `docker-compose.yaml` + `.env`
- **`${REF_NAME}` field linking**: fields can reference vault entries by name; resolved at render time with green/amber status badges

### Security
- **Encryption**: SQLCipher AES-256-CBC, key never written to disk
- **KDF**: Argon2id (m=65536, t=3, p=1), 16-byte random salt
- **Vault integrity check**: SHA-256 of vault data stored in `vault_meta`, verified on every unlock
- **WAL mode**: SQLite WAL journal for concurrent reads
- **Auto-lock**: configurable timer (default 60 min, 0 = never), 1-minute warning toast, lock on minimize

### Built-in Tools
- **Random key generator**: 32/64-byte hex
- **Certificate generator**: self-signed X.509 via `rcgen`
- **SSH keypair generator**: Ed25519 via `ssh-key`
- **Health dashboard**: scans for weak (<12 char), expired, expiring-soon (30d), never-rotated, and undescribed secrets
- **Import**: `.env` files, Bitwarden JSON, 1Password JSON, raw vault JSON
- **Export**: `.env`, YAML, JSON — per-entry or bulk
- **Secret templates**: 10 predefined templates (GitHub PAT, AWS Access Key, Stripe, PostgreSQL DSN, OpenAI, Cloudflare, SSH Key Pair, TLS Certificate, env variable, Docker Registry)
- **Regex search**: `/pattern/flags` syntax in the search bar

### Multi-User (RBAC)
- Users table with hashed passwords; owner = vault creator
- **API tokens**: per-user bearer tokens for CLI/server access
- **User classes**: named role templates (Admin, Moderator, Viewer + custom), each with capability flags and permission rules
- **Capabilities**: `manage_users`, `manage_classes`, `delete_projects`
- **Permission scopes**: `vault | project | category` × `read | write`, with glob support (`project-*`)
- **TOTP 2FA**: RFC 6238, HMAC-SHA1, ±1 window clock skew tolerance
- Effective permissions = class permissions ∪ individual permissions (write supersedes read)

### Remote Server
- Axum 0.8 HTTP server (`apiv-server`) binding `127.0.0.1:8743`
- Rate limiting: 10 failed attempts per IP per 60-second window on auth endpoints
- Bearer token auth; TOTP field required if enabled for that user
- Remote vault panel in the desktop app: save multiple connections, connect/disconnect, server status
- Remote-first login: server URL in the unlock modal switches to remote mode

### CLI (`apiv`)
```
apiv [--server URL] [--password PWD] <command>

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

## Architecture

```
Tauri 2 desktop app
├── Frontend: TypeScript + Vite → dist/  (served as static files)
├── Backend:  Rust (#[tauri::command] via window.__TAURI__.invoke)
└── Database: SQLCipher (AES-256-CBC) via rusqlite

Cargo workspace
├── vault-core/     shared Rust library (KDF, DB, users, TOTP, generators)
├── apiv-server/    Axum HTTP server binary
├── apiv-cli/       CLI binary
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
- DB: `~/.local/share/io.apivault/vault.db`
- Salt: `~/.local/share/io.apivault/vault.salt`
- Settings: `~/.config/io.apivault/settings.json` (plain JSON, not encrypted)

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
cargo build --release -p apiv-server -p apiv-cli         # server + CLI binaries
```

### Running server and CLI

```bash
./target/release/apiv-server --port 8743
./target/release/apiv list
./target/release/apiv completions bash >> ~/.bash_completion
APIV_PASSWORD=mypassword ./target/release/apiv --server http://localhost:8743 export --format dotenv
```

---

## Remote Server API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/unlock` | — | `{password}` → `{token}` (rate-limited) |
| DELETE | `/api/unlock` | token | Lock vault, invalidate token |
| GET | `/api/status` | — | `{unlocked, vault_exists}` |
| POST | `/api/auth` | — | `{username, password, totp_code?}` → `{token}` |
| GET | `/api/ping` | token | Keep-alive: `{ok, ts}` |
| GET | `/api/vault` | token | Full `VaultData` |
| PUT | `/api/vault` | token | Save `VaultData` |
| GET | `/api/vault/expiring?days=30` | token | Expiring entries |
| GET | `/api/audit` | token | Audit log |
| GET/POST/DELETE | `/api/users/…` | owner | User management |
| POST/DELETE | `/api/users/{id}/totp` | owner | TOTP enable/disable |
| GET | `/api/openapi.json` | — | OpenAPI spec |

---

## Themes

6 built-in themes plus `system` (follows OS `prefers-color-scheme`): Dark, Midnight, Dracula, Nord, Catppuccin, Light.

---

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Tauri wrapper, static frontend | ✅ |
| 2 | SQLCipher + Argon2id encrypted storage | ✅ |
| 3 | TypeScript + Vite, Projects groundwork, structured project types | ✅ |
| 4 | Remote vault server + CLI | ✅ |
| 5 | Multi-user RBAC, user classes, TOTP, remote panel, health dashboard | ✅ |
| 6 | TLS on server, session persistence, tag editor UI | Planned |
