# EnvVault

EnvVault is a secrets manager that runs on your machine and talks to nothing else. API keys, passwords, X.509 certificates, SSH keys and whole structured configs live in a SQLCipher database encrypted with a key derived from your master password. No cloud account, no telemetry, no plaintext file sitting on disk waiting to be read.

It ships as three things that share one storage engine:

| | What it is |
| --- | --- |
| **The desktop app** | A Tauri 2 window. This is where you look at and edit secrets. |
| **`envv`** | A CLI built so that an automated caller can drive the whole vault without a single secret value entering its output. |
| **`envv-server`** | An optional HTTP/HTTPS server, so the desktop app and the CLI on other machines can reach one vault. |

Current version **0.6.0**. The version in `src-tauri/tauri.conf.json` is the authoritative one; `package.json`, the four `Cargo.toml` files and the git tag are all checked against it by the `meta` job in `.github/workflows/build.yml`.

---

## Contents

- [What it does](#what-it-does)
- [Install](#install)
- [First run](#first-run)
- [The desktop app](#the-desktop-app)
- [Secrets](#secrets)
- [Projects, chunks and exports](#projects-chunks-and-exports)
- [Tools](#tools)
- [Settings, shortcuts and auto-lock](#settings-shortcuts-and-auto-lock)
- [The CLI](#the-cli)
- [The server](#the-server)
- [Open to LAN](#open-to-lan)
- [Concurrent writes](#concurrent-writes)
- [Docker](#docker)
- [Multiple users](#multiple-users)
- [Permission expressions](#permission-expressions)
- [The security model](#the-security-model)
- [Where your files live](#where-your-files-live)
- [Building from source](#building-from-source)
- [Continuous integration](#continuous-integration)
- [What is not finished](#what-is-not-finished)
- [How it got here](#how-it-got-here)
- [License](#license)

---

## What it does

Everything below is implemented and in the shipping build. The sections after this one explain each in full.

### Storage and crypto

- **SQLCipher (AES-256-CBC) database**, keyed by Argon2id (m=65536, t=3, p=1) over your master password and a 16-byte random salt. The 32-byte key lives in a `Mutex<Option<[u8;32]>>` in Rust and is zeroized on lock. It is never written to disk.
- **Encrypted `.vaultbak` backups** — PBKDF2-SHA256 → AES-256-GCM, written and read by both the desktop app and the CLI.
- **Per-entry version history**, appended automatically whenever a secret's value changes, capped at 50 revisions, restorable from the UI or `envv entry restore`.
- **Append-only audit log** in the same database, bound into a **hash chain** (`entry_hash`/`prev_hash`), so a row cannot be altered or removed without the chain failing verification. `envv audit --verify` and Tools → Audit Log both check it. The chain has two formats — v2 includes the acting user, v1 predates that column — and the verifier tries v2 then falls back, so old logs still verify.
- **Compare-and-swap on every write.** The version the caller last read travels with the save and is compared inside the same `BEGIN IMMEDIATE` transaction as the write, so a concurrent edit cannot be silently clobbered.

### Secrets

- Seven secret types: **API key, password, certificate, SSH key, environment variable, connection string, file reference** — each with its own form, its own required fields and its own type-aware generator. Full breakdown under [Secrets](#secrets).
- Certificates carry their private key alongside them (`cert_key_data`); PEM blocks are re-wrapped to 64 columns on import so a single-line paste is still valid PEM.
- Environment-variable entries carry a display subtype — string, multiline, secret, boolean, number, IP, CIDR, port, URL, date, JSON.
- Metadata per entry: account, description, URL, scopes, environment (dev/staging/prod), expiry, price/plan type, tags, pinned flag, compromised flag, `last_rotated_at`, custom icon.
- **Custom icons**: either a [Simple Icons](https://simpleicons.org) slug from a ~300-entry registry, or an uploaded image file. One field holds both, so nothing can end up with a slug and a file that disagree.
- **Generators** built in: 32/64-byte hex secrets, passwords, self-signed X.509 pairs (`rcgen`), Ed25519 SSH keypairs (`ssh-key`).
- **Forty issuer signatures recognised on sight** — `ghp_`, `sk-ant-`, `AKIA`, `xoxb-`, `sk_live_` and the rest — plus structural typing for PEM blocks, JWTs and eleven database URI schemes.
- **Ten prefilled templates** and importers for `.env`, Bitwarden, 1Password and raw vault JSON.
- **Search** across provider, account, description, tags and URL, with regular expressions when you wrap the query in slashes.
- **Filters** by project, category, tag, environment and name prefix, all stackable, all clearable with one key.
- **Bulk mode** for multi-select delete and multi-select `.env` export.
- **Five-second undo** on delete, with a `beforeunload` guard so quitting mid-undo warns you.

### Projects and configuration

- **Projects hold typed chunks** — 29 chunk types across 11 project types — that render back into real config files: `wg0.conf`, `docker-compose.yaml` + `.env`, nginx sites, Kubernetes manifests, SSH config, Traefik, Apache, HAProxy, Ansible vars and PostgreSQL connection blocks.
- **`${ref}` interpolation.** Any chunk field can point at a vault entry (`${GitHub}`, `${GitHub/account}`, `${chunk:name}`). References are stored unresolved and resolved at copy/export time, so the config stays a template and the secret stays in one place.
- **Chunks can be disabled** — greyed out in the UI and excluded from every export.
- **Importers** that turn an existing file into chunks: nginx site configs (including nested `location {}` and multi-word directives) and `docker-compose.yaml`.
- **Custom project slugs** that survive a rename or a sub-project promotion.
- Slash-nested hierarchy for both projects and categories, with cascading renames and deletes.

### The CLI

- **Redacted by default.** Every stdout path masks values as `sha256:<12 hex>`; fingerprints are stable per value, so equal fingerprints mean equal secrets and you can detect drift without reading anything.
- **Materialisation paths that skip stdout**: `--out FILE`, `envv exec -- cmd`, `envv render tpl --out FILE`.
- **Secrets that are never seen at all**: `entry add --generate`, `entry rotate --generate`, `user token new --out FILE`.
- **A JSON envelope and eleven stable exit codes**, so a script can branch on the failure rather than grep the message.
- **`envv describe`** — the entire command tree, flags, exit codes and redaction rules as one JSON document, generated from the same `clap` definition the binary runs on.
- **`envv enrich`** — fills the metadata an imported `.env` never has, from entry names and public issuer prefixes; `--online` asks the issuer itself.
- **Password input that never touches argv**: `--password-file`, `--password-command`, `--env-file`, `ENVV_PASSWORD`.
- **Cached sessions** (`envv login`), so a human authenticates once and automation runs unattended.
- **Idempotent provisioning**: `--if-missing`, `--create`, `--dry-run` enforced at the single write point.
- Shell completions for bash, zsh, fish, elvish and PowerShell.
- **`envv watch`** — keeps a `.env` on disk and the vault in sync, upserting by provider instead of appending a duplicate copy on every save.

### The server, and sharing

- **HTTP or HTTPS**, with a self-signed certificate generated on demand or your own via `--cert`/`--key`.
- **Real certificate pinning** in the desktop app — SHA-256 of the leaf compared *during the handshake*, before the master password goes over the wire — with a trust-on-first-use bootstrap that sends no credentials.
- **Session tokens with a sliding idle expiry** (`--session-ttl-mins`, default 480).
- **Rate limiting on failures only**, counted from the real socket address rather than `X-Forwarded-For`.
- **CORS restricted to an explicit allow-list**, not `permissive()`.
- **Open to LAN** — the desktop app hosts the vault it already has open, in-process, on the same router `envv-server` runs. Self-signed TLS on by default, peers sign in as users, and the master password never crosses the network.
- **A public `/api/stats`** for dashboard widgets (Homepage, Homarr) that needs no auth and returns no secrets.
- **An OpenAPI document** at `/api/openapi.json`.

### Multi-user

- Users, API tokens, and **classes** as named permission templates.
- **Boolean permission expressions** over entry fields — `project:Alpha AND NOT category:secret` — with a live editor, a predicate builder that offers the values actually in your vault, and a "matches N of M entries" preview.
- Argon2id password hashing for sub-users, with transparent upgrade of legacy SHA-256 hashes on next login.
- The vault owner is a real user row with `password_hash = NULL`, so ownership is proven only by deriving the key.

### The application itself

- **Seven themes** — dark, midnight, dracula, nord, catppuccin, light, and system (follows your OS) — plus a custom CSS box.
- **Layout that persists**: sidebar width and collapsed state, activity-bar side, card size, column count, sort order, recent searches, last view. Every persisted id is validated against the loaded vault on read, so a deleted project cannot leave you staring at an empty grid under a filter you have no memory of setting.
- **Window size, position and maximized state persist** across restarts — but visibility deliberately does not, or hiding to the tray and quitting would restore an invisible window.
- **Auto-lock** on idle, with a warning toast, and opt-in lock on window hide.
- **A dedicated re-lock screen** that tells you why it locked and asks only for the password.
- **Offline by construction**: Syne and JetBrains Mono are vendored via `@fontsource` and bundled, so the app renders correctly with no network and CSP can stay at `font-src 'self'`.
- Ten prefilled entry templates — GitHub PAT, AWS access key, Stripe, PostgreSQL DSN, OpenAI and so on.
- Import from `.env`, Bitwarden JSON, 1Password JSON and raw vault JSON.

---

## Install

### From a release

Grab the artefact for your platform from the [Releases](../../releases) page.

| File | Platform |
| --- | --- |
| `*.AppImage` | Any Linux distribution. SQLCipher and OpenSSL are compiled in, so it does not care what your package manager ships. |
| `*.deb` | Debian, Ubuntu |
| `*.rpm` | Fedora, RHEL, Nobara |
| `*-setup.exe` | Windows. Fetches WebView2 during install if the machine lacks it. |
| `envv-*-linux-x86_64.tar.gz` | `envv` and `envv-server`, no GUI toolkit required |
| `envv-*-windows-x86_64.zip` | The same two, for Windows |

Every asset carries a keyless Sigstore signature. If you want to check that a download actually came out of this repository's CI and not from somewhere else:

```bash
cosign verify-blob \
  --certificate <asset>.pem \
  --signature   <asset>.sig \
  --certificate-identity-regexp 'https://github.com/.*/EnvVault/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  <asset>
```

`SHA256SUMS` is in the release too, if you only want to confirm the bytes.

### From source

See [Building from source](#building-from-source) at the bottom.

---

## First run

On first launch the app asks you to create a master password. Minimum twelve characters, and it means it — this is a secrets manager, and eight characters of `hunter2` is not a serious answer to the question.

That password is never stored anywhere. It goes through Argon2id (m=65536, t=3, p=1) with a 16-byte random salt to derive a 32-byte key, and that key opens the SQLCipher database. The key lives in memory and is zeroed when you lock.

So what happens if you forget it? Nothing good. There is no recovery, no reset link, no support address that can help you. The only thing you can do is delete `vault.db` and `vault.salt` and start an empty vault. Write the password down somewhere real.

**N.B.** The salt is as load-bearing as the database. A `vault.db` paired with the wrong `vault.salt` derives the wrong key and reports "wrong password" for a password that is perfectly correct. When you back up one, back up both. The CLI's `--db-path` infers the salt beside it for exactly this reason.

---

## The desktop app

### Layout

```
┌─────────────────────────────────────────────────────────┐
│  Header: search · sort · expand all · copy all · +      │
├──────┬──────────────────────────────────────────────────┤
│  A   │                                                  │
│  c   │  Sidebar        Main workspace                   │
│  t   │  Projects       (secret cards, project config,   │
│  i   │  Categories      or a tool pane)                 │
│  v   │  Tags                                            │
│  .   │  Environments                                    │
└──────┴──────────────────────────────────────────────────┘
```

- **Activity bar** switches between Secrets, Tools, Users and Remote Vaults. Its side and its icon style are configurable in Settings → Layout.
- **Sidebar** filters. Click a project, category, tag or environment to scope the grid; click it again to clear. Drag its edge to resize between 140 and 420 px, double-click the edge to reset. `B` toggles it.
- **Header** searches, sorts, expands and adds.

Sidebar width, collapsed state, sort mode, the last view and your recent searches all survive a restart. Every one of those is validated against the vault that actually loads — a filter pointing at a project you deleted is dropped rather than applied, because the alternative is opening the app to an empty grid with every secret present, invisible, behind a filter you did not set. `Shift+Esc` clears every filter at once if you ever get there anyway.

### Adding a secret

1. Press `Ctrl+N`, or click **+**.
2. Pick the secret type at the top of the form. There are seven: API key, password, certificate, SSH key, environment variable, connection string, file reference.
3. Fill in the provider — that is the only required field — and the key.
4. **Generate** beside the key field is type-aware. On a certificate entry it produces a self-signed X.509 pair, on an SSH key entry an Ed25519 keypair, and on anything else 32 bytes of hex.
5. Assign projects, categories, an environment tag, an expiry date, scopes.
6. Save.

The form autosaves a draft to `sessionStorage` on every keystroke, so closing the modal by accident does not cost you the typing.

### What a card can do

| Action | How |
| --- | --- |
| Copy the key | Click the card header, or the copy icon beside the key |
| Copy a `.env` line | The `.env` badge in the footer |
| Reveal or hide | The eye icon |
| Expand | The chevron, or the header area |
| Edit / Duplicate | Pencil / two-page icon in the footer |
| Mark as rotated | The `↺` icon — stamps `last_rotated_at` |
| Pin | The pin icon. Pinned entries sort first in every view. |
| Mark compromised | Flags the entry and surfaces it in the health scan |
| View history | Previous values with timestamps, restorable |
| Delete | Trash icon, with a five-second undo toast |
| Everything at once | Right-click for the context menu |

The coloured left border tracks expiry: red for expired or within seven days, amber for within thirty, green for an expiry that is comfortably away.

### Searching

Type in the search bar and it matches provider, account, description, tags and URL. For anything more precise, wrap a regular expression in slashes — `/^AWS_/i` works, flags included.

---

## Secrets

### The seven types

Pick the type at the top of the add form and the rest of the form changes with it. The type is not cosmetic — it decides which fields exist, what **Generate** produces, how the card renders, and how the `.env` export names the value.

| Type | Identified by | The secret field | Extra fields | Generate produces |
| --- | --- | --- | --- | --- |
| **API key** | Provider (`GitHub`) | API Key | Account, a second *secret*/client-secret field, scopes, plan type, rate limit | 32 bytes of hex |
| **Password** | Service or app (`Gmail`) | Password | Username, strength meter | A random password |
| **Certificate** | Site or domain (`example.com`) | Fullchain PEM | Private key (`cert_key_data`), issuer, expiry | A self-signed X.509 pair via `rcgen` |
| **SSH key** | Host or service (`github.com`) | Private key, OpenSSH format | Username, account | An Ed25519 keypair via `ssh-key` |
| **Environment variable** | Variable name (`DATABASE_URL`) | Value | Subtype (see below) | 32 bytes of hex |
| **Connection string** | Service (`PostgreSQL`) | DSN or URI | — | 32 bytes of hex |
| **File reference** | Name (`config.yaml`) | — | Path or reference on disk (`blob_ref`) | — |

Notes on the ones with sharp edges:

- **Certificate** and **file reference** have no `api_key` at all. The form hides the field and the save path validates `certificate_data` / `blob_ref` instead, so neither can be saved half-formed.
- **Certificates keep their private key in the same entry.** A cert without its key is not deployable, and storing them apart is how they get separated. PEM pasted as a single line is re-wrapped to 64 columns on read, because a single-line PEM is not valid PEM and most tools reject it silently.
- **A file reference stores a path, not the file.** It is a pointer for things too large or too machine-specific to live in a vault — a kubeconfig, a keytab, a service-account JSON on a build agent.

There was an eighth, `chunk`, and it is gone. It appeared in the dropdown but could never be saved: the form hid its key input while the save path still required `api_key`. Its content lived in `extra_vars`, which ordinary cards render anyway, so existing entries are relabelled `env_var` on load with nothing lost. Project chunks are a different concept and untouched.

### Environment-variable subtypes

An `env_var` entry carries a subtype that drives display and validation:

```
string   multiline   secret   boolean   number
ip       cidr        port     url       date      json
```

`secret` is the one that matters operationally — it masks by default and marks the value for redaction. The rest are display hints: `multiline` gets a textarea rather than an input, `json` gets the formatter, `cidr` and `ip` render alongside the CIDR calculator.

### What every entry carries, regardless of type

| Field | For |
| --- | --- |
| `id` | Stable identity. Version history, audit attribution and write scoping all key on it — never on a position in an array. |
| `provider` | The only required field |
| `account_name` | Which account the credential belongs to |
| `api_description`, `api_url` | Free text, and a link (only ever rendered as one for `http(s):`) |
| `projectIds` | Which projects it belongs to; always includes `Universal` |
| `categories`, `tags` | Flat labels and chips, both sidebar-filterable |
| `environment` | `development` / `staging` / `testing` / `production` |
| `expires_at` | Drives the card's colour band, the expiry calendar and `rotate-check` |
| `last_rotated_at` | Stamped by the ↺ button and by `entry rotate` |
| `rotation_days` | A rotation cadence. Set it and the health scan flags the entry once it is overdue. |
| `price_type` | `free` / `paid` / `local` / `conditional` |
| `scopes`, `rate_limit` | Filled by hand, or by `envv enrich --online` from the issuer |
| `pinned` | Sorts first in every view |
| `compromised` | Flags the entry and surfaces it in the security audit |
| `custom_icon` | A Simple Icons slug **or** a `data:` image URI |
| `version_history` | Up to 50 previous values with timestamps, restorable |
| `extra_vars` | Arbitrary key/value pairs the card renders |

### Templates

Ten prefilled shapes, in Tools → Templates. Each one sets the type, the icon, sensible defaults and per-field hints, so a GitHub PAT does not need you to remember that the API base is `api.github.com`.

| Template | Type | Category |
| --- | --- | --- |
| GitHub PAT | API key | Dev Tools |
| AWS Access Key | API key | Cloud |
| Cloudflare API Token | API key | Cloud |
| Stripe API Key | API key | Payments |
| OpenAI API Key | API key | AI |
| Docker Registry | API key | Dev Tools |
| PostgreSQL DSN | Connection string | Database |
| SSH Key Pair | SSH key | Infrastructure |
| TLS Certificate | Certificate | Security |
| `.env` Variable | Environment variable | Config |

### Secrets EnvVault recognises on sight

`envv enrich` types a secret from the **public** prefix its issuer stamps on it, with no network call. Forty signatures, matched longest-first so `sk-ant-` cannot be swallowed by `sk-`:

| Issuer | Prefixes |
| --- | --- |
| GitHub | `ghp_`, `gho_`, `ghs_`, `github_pat_` |
| GitLab | `glpat-` |
| OpenAI | `sk-proj-`, `sk-` |
| Anthropic | `sk-ant-` |
| xAI | `xai-` |
| Groq | `gsk_` |
| NVIDIA | `nvapi-` |
| Replicate | `r8_` |
| Pinecone | `pcsk_` |
| HuggingFace | `hf_` |
| Tavily | `tvly-` |
| AWS | `AKIA`, `ASIA` |
| Google | `AIza`, `ya29.` |
| DigitalOcean | `dop_v1_`, `doo_v1_` |
| Slack | `xoxb-`, `xoxp-`, `xapp-` |
| Stripe | `sk_live_`, `sk_test_`, `pk_live_`, `pk_test_`, `rk_live_` |
| Shopify | `shpat_` |
| Docker Hub | `dckr_pat_` |
| npm | `npm_` |
| PyPI | `pypi-` |
| SendGrid | `SG.` |
| Mailgun | `key-` |
| Figma | `fig_` |
| MongoDB Atlas | `atlasv1.` |
| Linear | `lin_api_` |
| Notion | `ntn_`, `secret_` |

Stripe's prefixes carry more than an issuer: `sk_live_` *proves* the key is production and `sk_test_` proves it is not, so `enrich` fills `environment` from the prefix rather than guessing from the entry's name.

It also types secrets structurally, with no issuer involved:

| Shape | Becomes |
| --- | --- |
| `-----BEGIN CERTIFICATE` | `certificate` |
| `-----BEGIN … PRIVATE KEY` | `ssh_key` or a certificate key |
| `ssh-rsa `, `ssh-ed25519 `, `ecdsa-sha2-` | `ssh_key` |
| `eyJ` with exactly two dots | A JWT |
| `postgres://` `postgresql://` `mysql://` `mongodb://` `mongodb+srv://` `redis://` `rediss://` `amqp://` `amqps://` `mssql://` `clickhouse://` | `connection_string` |

That last row exists because **`secretType` is `api_key` on every entry ever written**, including every variable imported from a `.env`. Without the structural pass, an imported `postgres://` URL stays classified as an API key forever.

Eight of those issuers will also answer questions about their own credentials when you pass `--online` — GitHub, GitLab, Slack, Stripe, DigitalOcean, npm, OpenAI and Anthropic — filling the account, scopes, expiry and rate limit from the real response. See [`envv enrich`](#envv-enrich).

### Importing existing secrets

| Source | Via |
| --- | --- |
| `.env` files | Tools → Import, or `envv import`, or `envv watch` to keep one in sync |
| Bitwarden JSON export | Tools → Import |
| 1Password JSON export | Tools → Import |
| Raw vault JSON | Tools → Import |
| Encrypted `.vaultbak` | Tools → Backup, or `envv backup import` |
| `docker-compose.yaml` | A Docker project's config view — becomes chunks, not entries |
| An nginx site config | An nginx project's config view — likewise |

`.env` import upserts by provider. It used to append unconditionally, which meant `envv watch` added a complete copy of the file to the vault on every save; `--allow-duplicates` restores the old behaviour if you actually wanted it.

### Icons

The icon picker offers a ~300-entry Simple Icons registry, a letter-avatar fallback, and **Upload file…** for your own image. PNG, JPEG, GIF, WebP, BMP and ICO are accepted up to 96 KB encoded; the file is typed by its **magic bytes**, not its extension, and validated again when the vault is read rather than only when you pick it. SVG is refused, permanently, because it is a script container and a vault is untrusted input.

One field holds either a slug or a `data:` URI, so an entry can never carry a slug and a file that disagree. Agent-facing CLI output never dumps an embedded icon; it collapses to `{embedded, mime, bytes, fingerprint}`.

---

## Projects, chunks and exports

A project is a container for structured configuration, and it is a different thing from a category. Categories are flat labels you attach to secrets. Projects hold **chunks**: typed fragments of a config file that EnvVault knows how to render back into that file.

Create one with **+** in the Projects section. Use `/` in the name for hierarchy (`infra/k8s` creates `infra` as a parent if it does not exist). A project whose id differs from the slug of its name has a **pinned slug**, and renaming it or promoting it out of a parent preserves that slug.

Four project types are tested end to end and available by default:

| Type | Chunks | Exports to |
| --- | --- | --- |
| Generic | Any key/value chunk | — |
| WireGuard | `wg_interface`, `wg_peer` | `wg0.conf` |
| Docker | `docker_service`, `docker_network`, `docker_volume`, `env_file` | `docker-compose.yaml` + `.env` |
| Nginx | `nginx_server`, `nginx_upstream`, `nginx_location`, `nginx_key` | an nginx site config |

Seven more exist — Kubernetes, SSH config, Traefik, Apache, HAProxy, Ansible and PostgreSQL — but they are behind **Settings → Advanced → experimental project types**, off by default, because they have not been exercised end to end and I would rather you knew that before you deployed something they produced.

Turning the flag back off hides those types from the *creation* menu and nothing else. Projects you already made keep working, keep exporting, and stay reachable. Hiding the config view of an existing project would strand its chunks in the vault with no way to reach them, which is worse than an untested exporter.

The 29 chunk types in full:

```
wg_interface     wg_peer
docker_service   docker_network   docker_volume   env_file
nginx_server     nginx_upstream   nginx_location  nginx_key
k8s_deployment   k8s_service      k8s_configmap   k8s_secret   k8s_ingress
ssh_host
traefik_router   traefik_service  traefik_middleware
apache_vhost     apache_directory
haproxy_global   haproxy_frontend haproxy_backend
ansible_vars     ansible_task
pg_connection    pg_role
generic
```

### `${refs}`

Any chunk field can reference a vault entry by name. Write `${GitHub}` to pull in that entry's key, `${GitHub/account}` for a specific field, `${GitHub_KeyId}` to disambiguate, or `${chunk:name}` to point at another chunk. The card shows a green badge when the reference resolves and an amber one when it does not, and the security-audit tool lists every reference that has gone stale.

References are resolved at **copy and export time**, not stored resolved. That is the point: the config in the project stays a template, and the secret stays in one place. Renaming an entry rewrites every reference that pointed at it.

One deliberate exception: `docker_service` keeps `${VAR}` literal, because Compose substitutes it from the `.env` written beside it.

Chunks also take freetext notes, and can be **disabled**. A disabled chunk is greyed out in the UI and excluded from every export.

> This one was a real bug and worth stating plainly. Before Phase 13, four of the exporters checked the disabled flag and four did not. Disabling a WireGuard peer greyed out its card and still wrote the peer into `wg0.conf` — so the tunnel kept trusting a peer the user believed they had removed. If you disabled a peer or a Compose service before 0.6.0 and exported, re-export. The fix corrects the next export; it cannot reach the file already on your server.

The same fixture that caught it caught a second one: the nginx exporter never resolved `${…}` at all, so a starter template's `ssl_certificate ${example_cert}` reached nginx as literal text and the server refused to start — while copying the identical chunk from its card resolved correctly.

**Importing:** nginx projects take a pasted or loaded site config and parse `server {}`, nested `location {}` and multi-word directives. Docker projects take a `docker-compose.yaml`. In both cases the result is chunks you can edit.

### Two implementations, one golden file

Every exporter exists twice — `src/ts/chunk-ops.ts` for the app, `envv-cli/src/exporters.rs` for the CLI. Two implementations of one file format drift silently, so both assert against the same golden files in `tests/fixtures/parity/`, from both sides. Reviewing two implementations for agreement does not work; the fixture found the two live bugs above the first time it ran.

---

## Tools

Switch to Tools in the activity bar.

| Tool | What it does |
| --- | --- |
| Key generator | 32 or 64 bytes of hex |
| Certificate generator | Self-signed X.509, via `rcgen` |
| SSH keypair | Ed25519, via `ssh-key` |
| Health dashboard | Finds weak (under 12 characters), expired, expiring within 30 days, never-rotated and undescribed secrets |
| Security audit | Duplicate values, compromised entries, stale `${refs}` |
| Secret diff | Field-by-field comparison of two entries, values masked |
| Expiry calendar | A month grid with colour-coded dots |
| Audit log | The append-only log, with hash-chain verification |
| Cron explainer | Parses a 5-field expression and shows the next five fire times |
| CIDR calculator | Network, broadcast, host count and mask |
| JSON / YAML formatter | Format, validate or minify, backed by `js-yaml` |
| Import | `.env`, Bitwarden JSON, 1Password JSON, raw vault JSON |
| Templates | Ten prefilled shapes — GitHub PAT, AWS access key, Stripe, PostgreSQL DSN, OpenAI, and so on |
| Bulk operations | Select mode, then bulk delete or bulk `.env` export |
| Backup | Encrypted `.vaultbak` export and restore |

---

## Settings, shortcuts and auto-lock

### Settings

Press `S` or click the gear. Five tabs:

| Tab | Holds |
| --- | --- |
| **Appearance** | Seven themes — dark, midnight, dracula, nord, catppuccin, light, and system, which follows your OS |
| **Layout** | Card size, column count, activity bar placement and icon style |
| **Security** | Auto-lock timeout, lock on window hide, mask keys by default |
| **Data** | Export format, expiry warning window, custom CSS |
| **Advanced** | Vault path, experimental project types |

### Keyboard shortcuts

| Key | Action |
| --- | --- |
| `Ctrl+K` | Focus the search bar |
| `Ctrl+N` | Add a secret |
| `Esc` | Clear search, or close the modal |
| `Shift+Esc` | Clear every active filter |
| `S` | Settings |
| `B` | Toggle the sidebar |
| `?` | The shortcut list |

### Auto-lock

The vault locks itself after 60 idle minutes by default; set the timeout to 0 in Settings → Security to disable it. Mouse and keyboard activity resets the clock, and a dismissible toast warns you a minute out.

Locking mid-session brings up a dedicated re-lock screen rather than the startup one — it tells you *why* it locked (idle, manual, or the window was hidden) and asks for the password only. You do not re-enter a server URL to get back into a session you never left. Locking also clears any pending undo, since a pending undo closes over a deleted entry including its secret.

Locking when the window is hidden is **opt-in**, in Settings → Security. It used to fire on every alt-tab, which is not security, it is an annoyance with a security-shaped excuse.

Auto-lock and lock-on-hide are both suspended while you are [serving to the LAN](#open-to-lan).

### Window state

Size, position and maximized state persist across restarts. Visibility deliberately does not: the tray handler hides the window, so saving visibility would mean hide-to-tray plus quit restores an *invisible* window on next launch, and the app appears to start and do nothing with only the tray icon as a way back. The plugin also skips restoring a position no connected monitor intersects, so unplugging a second display cannot strand the window off-screen.

---

## The CLI

`envv` does everything the app does, and it is built around one rule:

> The caller decides *what happens*. Values move from the vault to their target without passing through the caller's output.

That rule exists because the CLI is meant to be driven by scripts, by CI, and by automated tooling whose logs are not as private as people assume. Five mechanisms enforce it.

### 1. Redaction is the default

Every stdout path masks stored values as `sha256:<12 hex>`. In JSON it is `{"redacted":true,"fingerprint":"sha256:…","length":n}`. `--reveal` opts back in, and it is meant for a human at a terminal.

The fingerprint is what makes this useful rather than merely safe. It is stable per value, so **equal fingerprints mean equal secrets**. You can detect that staging and production drifted apart, or that two entries hold the same key, without reading either one. An empty value fingerprints as the literal string `empty`, never as a hash, because "unset" and "set to something" must not look alike.

Two rules that are easy to get wrong, and are therefore enforced rather than documented:

- **`env_file` chunks are masked whole**, with per-field type flags ignored. `chunk set` writes `field_type: var` by default, so a real password added that way carries no secret flag at all. Trusting the flag inside a `.env` means the first unflagged password is the one that leaks.
- **A `${ref}` is never masked.** It is a pointer, not a secret, and leaving it readable is exactly what lets a script wire configs together blind.

### 2. Ways to get the real value out

```bash
envv export --project Alpha --out .env  # real values to the file, nothing to stdout
envv exec -- terraform apply           # secrets enter the child's environment
envv render deploy.tpl --out app.conf  # substitutes ${refs} into a template
```

None of those three print a value. This is enforced by construction, not by discipline: `Resolver::for_output` redacts, `Resolver::materialising` does not, and an exporter cannot obtain a real value without being handed the latter.

A vault-wide `envv export` to stdout is **refused**, with exit code 9. Not masked — refused. A masked `.env` file looks deployable and is not, and handing someone a file that fails silently at 3 a.m. is worse than handing them an error now. Give it `--out` and it writes real values to the file. Project-scoped exports mask instead of refusing, since their structure is worth reading.

`envv exec --clean` starts the child with only the vault's variables. On Windows it keeps `SYSTEMROOT`, `COMSPEC` and `PATHEXT`, because without `SYSTEMROOT` anything touching the CRT or winsock fails with errors that name none of this.

### 3. Secrets that are never seen at all

```bash
envv entry add Stripe --generate       # created inside the process that stores it
envv entry rotate Stripe --generate
envv user token new deploy --out .token
```

You get a fingerprint back. The value never existed anywhere you could read it. `user token new` checks the output policy **before** minting, because the first version minted the token and then refused to print it, leaving a live credential in the database that nobody could read.

### 4. A machine-readable envelope

Pass `--json` to any command and stdout becomes exactly one JSON document:

```json
{"ok": true,  "command": "entry.get", "data": { }}
{"ok": false, "error": {"code": "ambiguous", "message": "…", "details": { }}}
```

Exit codes are stable, so a script can branch on them:

| Code | Exit | Means |
| --- | --- | --- |
| `error` | 1 | Unclassified |
| — | 2 | Bad arguments |
| `not_found` | 3 | No such entry, project, chunk, user or class |
| `ambiguous` | 4 | Matched several; `details.candidates` lists them |
| `denied` | 5 | Authentication failed, or the permission is missing |
| `conflict` | 6 | Already exists, or a concurrent write won |
| `unavailable` | 7 | Vault or server unreachable, or locked |
| `needs_confirmation` | 8 | Destructive, no `--yes`, and no terminal to ask |
| `redacted` | 9 | The output would have contained secrets |
| `invalid` | 10 | Well-formed request, invalid input |

Exit 4 deserves a note. `envv entry rm git` with both GitHub and GitLab in the vault does not guess. It lists both and exits non-zero. Deleting the wrong secret because a substring matched two things is not a failure mode worth accepting for the convenience of typing three letters. Use `provider:key_id` to disambiguate.

Exit 8 is the same reasoning: `confirm()` refuses on a non-terminal instead of assuming yes, so a script that forgot `--yes` fails loudly rather than quietly destroying something.

### 5. `envv describe`

```bash
envv describe | jq
```

The whole command tree, every flag, the exit codes, the envelope and the redaction rules, as one JSON document generated from the same `clap` definition the binary runs on. It cannot describe a flag that does not exist. If you are writing an integration, read this instead of guessing from error messages.

`envv-cli/examples/envv.py` is a wrapper showing the three rules of a correct integration: always `--json`, never read a value (use `exec`/`render`), branch on `error.code`. It is an example, deliberately not a package.

### Commands

```
list          List entries as a table
get           Full details of one entry
export        Export entries (--out for real values)
rotate-check  Entries expiring within N days
import        Import a .env file (upserts by provider; --allow-duplicates to append)
audit         The audit log, or --verify its hash chain
completions   bash | zsh | fish | elvish | powershell
watch         Watch a .env and sync changes into the vault
env           Resolve a project's env_file chunks into a deployable .env
entry         ls get add set rename rm tag pin compromise rotate history restore
project       ls show add rename rm export chunk
project chunk ls show add rm rename set unset disable enable
category      ls add rename rm
tags          Every tag with its entry count
gen           secret | password | cert | ssh
backup        export | import — encrypted .vaultbak, readable by the desktop app
scan          Weak, expiring, duplicated and stale-reference secrets; --verify the audit chain
status        Where this CLI is pointed and what the vault holds
user          ls add rm rename passwd class token
user token    ls new revoke
class         ls add set rm
perm          show set check
exec          Run a command with secrets in its environment
render        Substitute ${refs} in a template file (`-` for stdin)
enrich        Fill entry metadata from names and public key prefixes
describe      The machine-readable contract
login         Authenticate once and cache the session (--user NAME for a sub-user)
whoami        Which identity this CLI would use, and whether its session still works
sessions      Every cached session: server, user, which one is default
logout        Forget a cached session (--user NAME for one, --all for every server)
```

Global flags: `--json`, `--reveal`, `--yes`, `--dry-run`, `--db-path`, `--salt-path`, `--init`, `--server`, `--user`, `--token`, `--password-file`, `--password-command`, `--env-file`.

### Getting the password in without putting it in argv

Anything on a command line ends up in your shell history, in `ps` output, and in any transcript of the session. So there are four other ways:

```bash
export ENVV_PASSWORD=...                        # the environment
envv --password-file  ~/.envv-pw list           # first line of a file
envv --password-command 'pass show envv' list   # stdout of a command
envv --env-file /srv/envv/.env list             # the .env compose already reads
```

`--env-file` is the one to use with a containerised server. It reads `ENVV_PASSWORD` and `ENVV_SERVER_URL` out of the same file `docker compose` uses to start `envv-server`, so exactly one copy of the password exists and the compose stack owns it.

`--password-command` runs through `sh -c` on Unix and `cmd /C` on Windows.

For a remote server, authenticate once and let everything after that run unattended:

```bash
envv login --server https://vault.example.com
envv list                                       # uses the cached session
```

### Signing in as a named user

The owner is whoever can derive the vault key. Everyone else is a sub-user with a
password or an API token, and `--user` is how you become one:

```bash
envv login --server https://vault.example.com                 # as the owner
envv login --server https://vault.example.com --user alice    # as a sub-user
envv --user alice list                                        # uses alice's cached session
envv list                                                     # uses the most recent login
```

Sessions are cached **per server and per user**, so one machine can hold several
identities against one server — an admin login beside a scoped one, or two people
sharing a workstation. The most recent login becomes that server's default, which
is what a bare `envv list` uses.

```bash
envv whoami                     # who you are, and whether the session is still accepted
envv sessions                   # every cached identity; the * is the default
envv logout --user alice        # forget one identity
envv logout                     # forget every identity for this server
envv logout --all               # forget every server
```

`whoami` proves the session rather than describing it — it calls the authenticated
`/api/ping`, because a token the server has since rejected looks identical on disk
to a working one. A scoped user seeing fewer entries than expected otherwise has
no way to tell a permission problem from being signed in as the wrong person.

The session token goes in `sessions.json`, mode 0600, under `$XDG_STATE_HOME/envv/` (or `%LOCALAPPDATA%` on Windows — per-user, not roamed, since a cached session token should not follow you onto another machine). A rejected session clears **only the identity that was used** — expiring one login must not sign the other cached users out — and the error names the exact command to run again, otherwise every later command fails identically with an unhelpful 401 and you spend twenty minutes debugging the wrong thing.

### Idempotency

```bash
envv entry add   GitHub --if-missing
envv entry set   GitHub --create
envv project add Alpha  --if-missing
```

Re-running a provisioning script is not an error, and does not overwrite a secret that is already there.

`--dry-run` is enforced inside the single write point rather than checked by each command, so a command that forgets to look at the flag still cannot write.

### `envv enrich`

An imported `.env` has no metadata. No scopes, no expiry, no account, no idea which of those forty variables is a Stripe key and which is a database URL. `enrich` infers it from the entry name and from the **public** prefix the issuer puts on its credentials — `ghp_`, `sk-ant-`, `AKIA`, `sk_live_`, forty of them — plus structural shapes like PEM blocks, JWTs and database URI schemes. The full signature table is under [Secrets](#secrets-envvault-recognises-on-sight).

```bash
envv enrich                    # preview; changes nothing
envv enrich --apply            # fill the gaps
envv enrich --apply --force    # also overwrite fields that already have values
envv enrich --online --apply   # ask the issuers
```

`--online` sends the secret over TLS to the service that issued it, and nowhere else, then fills `account_name`, `scopes`, `expires_at` and `rate_limit` from the real answer. Live answers overwrite inferred ones for the same field. It is opt-in for exactly that reason.

It also tells you something nothing offline can. A credential that was revoked last month looks identical to a working one in storage. **An issuer answering 401 is the only reliable way to find out.**

Output carries fingerprints and never values, and without `--apply` nothing is written.

---

## The server

`envv-server` serves one vault over HTTP or HTTPS.

```bash
envv-server --port 8743                       # HTTP, loopback only
envv-server --port 8743 --tls                 # HTTPS, self-signed cert generated
envv-server --tls --cert cert.pem --key key.pem   # bring your own
```

| Flag | Default | Notes |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Set to `0.0.0.0` only when you mean it |
| `--port` | `8743` | |
| `--db-path` / `--salt-path` | app data dir | |
| `--tls` | off | Generates a 3-year self-signed cert for `localhost` and `127.0.0.1` if `--cert`/`--key` are absent |
| `--session-ttl-mins` | `480` | Idle minutes before a token expires; any authenticated request resets it. 0 disables expiry. |

Auth is a bearer token. Failed attempts are rate-limited to 10 per IP per 60 seconds, counted from the real socket address rather than `X-Forwarded-For` — a header the client controls is not an identity. Only *failures* count, so a busy legitimate client never rate-limits itself.

Locking is asymmetric on purpose. `DELETE /api/unlock` from the owner is **global**: every session is dropped and every key zeroized. From a non-owner it is a personal logout. The earlier behaviour — remove only the caller's session, while every user session held its own copy of the vault key — meant an owner "locking" left everyone else reading and writing indefinitely.

### Self-signed certificates, and the chicken-and-egg problem

The desktop app pins the server's certificate. When you save a remote vault it compares the SHA-256 of the leaf certificate **during the handshake**, before it sends anything, so a machine-in-the-middle is rejected before your master password goes over the wire. There is no `danger_accept_invalid_certs` anywhere in the codebase.

That creates an obvious problem for a self-signed server: connecting requires a fingerprint you can only get by connecting. The bootstrap is a separate trust-on-first-use step — an unauthenticated `GET /api/status` with a capturing verifier that **sends no credentials** and returns the fingerprint for you to confirm. Everything after that first contact is pinned, and the app warns you if the fingerprint later changes.

Fingerprints are parsed with `rustls-pemfile`. A hand-rolled base64 decoder that maps invalid characters to zero produces a plausible but wrong fingerprint, which clients then pin to — which is worse than no pinning, because it looks like it works.

### API

| Method | Path | Auth | What |
| --- | --- | --- | --- |
| POST | `/api/unlock` | — | `{password}` → `{token}` |
| DELETE | `/api/unlock` | token | Lock (global for the owner, personal otherwise) |
| GET | `/api/status` | — | `{unlocked, vault_exists, cert_fingerprint}` |
| POST | `/api/auth` | — | `{username, password}` or `{token}` → `{token}` |
| GET | `/api/ping` | token | Keep-alive, resets the idle clock |
| GET / PUT | `/api/vault` | token | Read / write the whole `VaultData`; ETag + `If-Match` |
| GET | `/api/vault/expiring?days=30` | token | Expiring entries |
| GET | `/api/audit` | token | The audit log |
| GET/POST/DELETE | `/api/users`, `/api/users/{id}/…` | owner | Users, passwords, classes, tokens, permissions |
| GET/POST/DELETE | `/api/classes`, `/api/classes/{id}/…` | owner | Classes and their permissions |
| GET | `/api/stats` | — | Public counts, 0 while locked |
| GET | `/api/openapi.json` | — | The spec |

Read events are deliberately **not** audited. Every `GET /api/vault` used to write a row, so a polling client grew the table without bound — and pruning it would have broken the very chain that makes the log tamper-evident.

### Dashboard widgets

`GET /api/stats` needs no authentication and returns no secrets:

```json
{"secrets_stored": 42, "users_total": 5, "users_connected": 2, "vault_unlocked": true}
```

For [gethomepage.dev](https://gethomepage.dev), in `services.yaml`:

```yaml
- EnvVault:
    icon: mdi-lock-outline
    href: http://your-server:8743
    widget:
      type: customapi
      url: http://your-server:8743/api/stats
      mappings:
        - { field: secrets_stored,  label: Secrets,   format: number }
        - { field: users_total,     label: Users,     format: number }
        - { field: users_connected, label: Connected, format: number }
```

Homarr wants a Custom API tile pointed at the same URL, with three fields mapped to the same names.

---

## Open to LAN

The desktop app can host the vault it already has open, from the Remote panel, so another machine on the network can reach it without a second server process or a second copy of the database. Minecraft-style: it exists while the app does, and closes when you lock or quit. Docker remains the option for something always-on.

`envv-server` is a library, and the binary is a thin CLI wrapper around it. The desktop hosts **the same router in-process** — one vault file, one master password, no subprocess to supervise, and no possibility of the two drifting apart in what they expose.

**Peers sign in as users.** `POST /api/unlock` is refused while hosting, so the master password never crosses the network and no peer can arrive as owner. The host's key is adopted directly into an owner session in memory, which is why nobody re-enters a password. Starting is refused outright when no password-capable user exists yet — the app sends you to the Users panel rather than advertising a server nobody can log into.

**Defaults.** Binds `0.0.0.0` on port **8744**, stepping forward if it is taken, so a Docker `envv-server` on 8743 can coexist. Self-signed TLS is on. The certificate is persisted and reused, because regenerating it per launch would change the fingerprint every time and break every peer's pin. The fingerprint is shown in the UI for peers to pin through the normal path.

**Locking is suspended while serving.** Peers are mid-request, and the host not touching the keyboard is no reason to cut them off. Because that would otherwise leave the vault decrypted indefinitely on an unattended machine, the server closes itself after **8 hours with no peer traffic**, which re-arms normal auto-lock. An explicit lock stops the server and disconnects everyone, behind a confirmation naming how many peers are connected. Every teardown path zeroizes the keys held by peer sessions.

**It refuses while you are connected to a remote vault.** `lan_start` opens *this* machine's `vault.db`, so pressing it during a remote session published the local vault under the remote's UI. The gate is enforced at the button and again at the call, because a control that is merely hidden is not a control that is prevented. A server that is already running stays visible and stoppable regardless.

The Users panel appears whenever you are hosting or connected to a remote, and is hidden on a purely local vault — local accounts written into the desktop's own `vault.db` are never read by `envv-server`, so they could never authenticate anywhere.

---

## Concurrent writes

Opening the vault to the LAN makes the desktop and its peers concurrent writers on the same database. The desktop used to write the whole blob unconditionally, so a peer's edit landing between the desktop's last load and its next save was silently overwritten. No error, no warning, the change simply gone.

The check now lives **inside `save_vault`**. `SaveCtx { actor, expect_version }` carries the version the caller last read, and the comparison happens inside the same `BEGIN IMMEDIATE` transaction as the write. Putting it there rather than in each caller fixes two problems at once: a caller that reads, compares and then writes has a race between the compare and the write, and a caller that simply forgets is silently unprotected.

`SaveCtx` is a struct rather than two positional `Option<&str>` arguments, because swapping an actor id for a version hash would disable the concurrency check while still compiling and still passing every test.

Audit rows are written **inside** that transaction too. They previously ran before it, so a rejected or failed write still appended audit rows describing changes that never happened.

The version identity is the `data_hash` `save_vault` already stores, so it is by construction the hash of exactly the bytes on disk, and the GET ETag reads that stored value rather than re-hashing parsed JSON. Where a handler needs both the version and the data it describes, the version is read first: mis-pairing that way can only pin an *older* version than the data, which fails the compare-and-swap and retries. The other order passes the check while merging against a stale base — which is the clobber itself.

**On conflict the desktop asks.** There is no safe automatic answer; silently picking a winner is how data goes missing. You get the choice between keeping your version (an explicit unconditional overwrite) and reloading theirs, with the cost of each spelled out.

---

## Docker

```bash
docker compose up -d
```

Data persists in the `envv_data` volume as `/data/vault.db` and `/data/vault.salt`. Unlock over the API, or set `ENVV_PASSWORD` in the container environment to unlock on start:

```bash
curl -X POST http://localhost:8743/api/unlock \
  -H 'Content-Type: application/json' \
  -d '{"password":"your-master-password"}'
```

The compose file sets `mem_limit: 256m`. That is not arbitrary. Argon2id allocates a 64 MB buffer per unlock by design — that cost is the entire point of a memory-hard KDF — and the limit leaves room for two concurrent unlocks without the OOM killer turning a login into a restart.

Idle memory is about 1.3 MiB, down from 4 MiB, from three changes worth knowing if you tune this yourself:

- tokio runs **2 workers** with 1 MB stacks instead of one per CPU (`ENVV_WORKER_THREADS` overrides it);
- `MALLOC_ARENA_MAX=2` stops glibc reserving up to eight 64 MB arenas per core, each of which it never fully returns — **the saving scales with your host's core count**, so a big server benefits far more than a small one;
- `MALLOC_TRIM_THRESHOLD_` returns the Argon2id buffer to the OS at once instead of letting it sit resident for the life of the process.

`shm_size` is 16m. The healthcheck opens the port rather than running `--version`, because a wedged process answers `--version` perfectly well.

---

## Multiple users

The vault owner is whoever can derive the key from the master password. Beyond that you can create users, give them passwords or API tokens, and constrain what they can see.

The owner is a **real user row** with `is_owner = 1` and, deliberately, **`password_hash = NULL`**. Storing a hash of the master password there would be an offline oracle for the vault key. Ownership is still proven by deriving the SQLCipher key, and the row can never be logged into through `/api/auth`. It exists so that the owner can be named in an audit entry and listed with everyone else, which the previous magic string `"owner"` could not do.

Users get capabilities (`manage_users`, `manage_classes`, `delete_projects`) and two permission expressions: one for read, one for write. **Classes** are named templates — Admin, Moderator, Viewer, or your own — holding the same thing, so you set the rule once and assign it.

Sub-user passwords are Argon2id in PHC format. Legacy SHA-256 hashes are upgraded transparently on the user's next successful login, so there is nothing for you to migrate.

The desktop app does **not** seed an `admin` sub-user whose password hash is the master password. That turned the sub-user login into an oracle for the vault password. Create users explicitly.

---

## Permission expressions

A boolean expression over entry fields:

```
project:Alpha AND NOT category:secret
(project:web OR project:api) AND env:production
tag:shared OR type:certificate
```

Terms are `field:glob`, where field is one of `vault`, `project` (id or display name), `category`, `tag`, `env` or `type`. `field:*` means no constraint on that field.

Precedence is `NOT` > `AND` > `OR`; parentheses override. `&&`, `||` and `!` are accepted as aliases and operators are case-insensitive. Adjacency is **not** implicit AND — an operator is always required, so an expression can never quietly mean something other than it reads.

Five rules govern how they combine, and all of them fail towards *less* access:

1. Effective permission is the class expression **AND** the individual one. A class-level exclusion is a real boundary, not a suggestion.
2. **Write implies read**, so the effective read rule is `read OR write`.
3. **No expression is not "no restriction".** With AND, that would give a user holding no permissions at all full access. No expression means no grant.
4. A specific `project:` term is never satisfied by the `Universal` catch-all project.
5. A malformed expression **denies**. `set_permission_expr` parses before storing, so a bad rule is rejected at the API with a 400 rather than saved as something that silently denies everything; stored text is re-parsed on every evaluation rather than trusted, so a row edited outside the app also fails closed.

Write scoping is ANY-match: one matching category or project is enough, the same rule reads already used. Requiring *every* scope an entry declared made project-scoped grants unusable, since almost every entry also carries a category. A `scope_value` of `*` is an unconditional match for its type, so wildcards reach unfiled entries and `project:*` and `category:*` behave identically. Note the consequence: for scoped users, "can see it" and "can edit it" are close to the same thing. **Vault scope remains the real privilege boundary.**

Existing flat `(scope_type, scope_value, permission)` rows are compiled once into equivalent OR-chains, reproducing the previous read behaviour exactly. The migration is guarded by a marker in `vault_meta`, so deliberately clearing every expression does not resurrect the old rules on the next start, and it runs after class seeding so the built-in classes are compiled too.

**The editor.** The Users and Classes panels show a read box and a write box with live syntax validation, a predicate builder that inserts terms from the values actually present in your vault, and a "matches N of M entries" preview. The preview is advisory — `vault-core` re-parses and re-evaluates everything, and is the only thing that decides real access.

---

## The security model

Collected in one place, because the reasoning matters more than the list.

| Layer | What holds |
| --- | --- |
| At rest | SQLCipher AES-256-CBC. The key is derived per-session and never written. |
| Key derivation | Argon2id m=65536, t=3, p=1, 16-byte random salt in a separate file. |
| In memory | `Mutex<Option<[u8;32]>>`, zeroized on lock, on quit, and on every LAN teardown path. |
| Backups | PBKDF2-SHA256 → AES-256-GCM `.vaultbak`. |
| In transit | TLS with leaf-certificate pinning verified during the handshake; TOFU bootstrap sends no credentials. |
| Sub-user auth | Argon2id PHC, sliding-expiry bearer tokens, failure-only rate limiting from the real socket address. |
| Authorization | Boolean expressions, composed with AND, failing closed at every ambiguity. |
| Integrity | Hash-chained append-only audit log, verified on demand. |
| Concurrency | Compare-and-swap inside the write transaction. |
| Output | Redaction by default in the CLI; refusal rather than masking where a masked file would look deployable. |
| Rendering | Every vault field is HTML-escaped. A vault is JSON from a remote someone else runs; TypeScript unions are erased at runtime and prove nothing. Only `http(s):` URLs become links. |
| Assets | Fonts vendored, CSP `font-src 'self'`, no CDN request at runtime. |
| Icons | Typed by magic bytes, size-capped, re-validated on read, SVG refused. |

### Things deliberately removed

- **TOTP/2FA.** It had no UI and was never reachable. A half-wired second factor is worse than none, because people believe in it.
- **The Settings "Quick Connect" pane.** Saving settings ran `applyRemoteConfig()`, which reassigned the vault store from an unchecked toggle — so opening and closing Settings while connected to a remote *silently disconnected it*. Remote connections are managed only in the Remote panel.
- **The Google Fonts CDN.** Syne and JetBrains Mono are vendored and bundled.
- **The `chunk` secret type.** It was in the dropdown but could never be saved: `dynamicSecretFields` hid its key input while `saveModal` still required `api_key`. Its content lived in `extra_vars`, which ordinary cards render anyway, so existing entries are relabelled `env_var` on load with nothing lost. Project `SecretChunk`s are a different concept and untouched.

### Closed oracles

- **Username enumeration.** `verify_user_password` returned `Err` for a user with no password (→ HTTP 500) but `Ok(None)` for a nonexistent user (→ 401), and only the 401 path incremented the rate limiter. The 500-vs-401 difference revealed which usernames existed, unthrottled. Both are now ordinary credential failures.
- **The owner password hash.** See above: `NULL`, on purpose.
- **Indefinite sessions.** They used to live until process restart, so a leaked token was valid forever.

### Correctness bugs that were security bugs

- `escAttr()` did not escape `&`, so any secret containing an entity-like sequence (`&amp;`, `&lt;`) was HTML-decoded on read-back and **copy-to-clipboard returned the wrong value**.
- Entries had no stable id. `save_vault` keyed on `provider|account_name` while the RBAC merge keyed on `provider|account_name|key_id`, so the two disagreed and history could be attributed to the wrong entry. Existing vaults are backfilled on first load.
- Expand and reveal state was keyed by array index, so it jumped to neighbouring cards after any delete, and revealed secrets silently re-masked on re-render.
- Keep-alive pings read a non-existent `_token` field and went out as `Bearer `, so the keep-alive never kept anything alive.
- Remote status checks used bare `fetch()`, bypassing the TLS-pinning proxy and reporting "Unreachable" for any HTTPS server with a self-signed certificate.
- `envv import` appended unconditionally, so `envv watch` added a full copy of the file to the vault on every save. It upserts by provider now.
- Switching between local and remote vaults carried the previous vault's filters, expanded entries and bulk selection across, so the new vault loaded into an empty-looking grid with all its data present and invisible.

---

## Where your files live

On Linux:

| | Path |
| --- | --- |
| Database | `~/.local/share/io.envvault/vault.db` |
| Salt | `~/.local/share/io.envvault/vault.salt` |
| Settings | `~/.config/io.envvault/settings.json` — plain JSON, deliberately not encrypted |
| CLI sessions | `$XDG_STATE_HOME/envv/sessions.json`, mode 0600 |

On Windows the CLI keeps sessions in `%LOCALAPPDATA%` rather than the roaming profile, since a cached session token should not follow you onto another machine.

> **If you used this when it was called API Vault:** the identifier changed from `io.apivault` to `io.envvault`. Move the directories before you launch the renamed build, or it will greet you as a first-time user and offer to create an empty vault.
> ```bash
> mv ~/.local/share/io.apivault ~/.local/share/io.envvault
> mv ~/.config/io.apivault      ~/.config/io.envvault
> ```

---

## Building from source

You need Rust 1.85 or newer, Node 22 or newer, and `cargo-tauri` v2.

```bash
# Fedora / Nobara
sudo dnf install openssl-devel perl-FindBin perl-IPC-Cmd patchelf fuse fuse-libs \
                 webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel librsvg2-devel

# Debian / Ubuntu
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
                 librsvg2-dev patchelf libsqlcipher-dev
```

```bash
npm install
npm run dev            # Vite alone, for UI work
cargo tauri dev        # the real window
```

Building a release:

```bash
export APPIMAGE_EXTRACT_AND_RUN=1   # the AppImage tooling needs FUSE otherwise
export NO_STRIP=1                   # linuxdeploy's strip is too old for .relr.dyn on Fedora

npx tauri build --features vault-core/bundled
cargo build --release -p envv-cli -p envv-server --features vault-core/bundled
```

`vault-core/bundled` compiles SQLCipher and OpenSSL into the binary instead of linking your system's. Use it for anything that has to run on a machine other than the one that built it. An AppImage linked against Fedora's `libsqlcipher0` will not start on a Debian box shipping a different soname, and "works on my distro" is the whole problem a portable bundle exists to solve. For local development, leave it off — it builds in seconds instead of minutes. Windows vendors both unconditionally, since it packages neither.

Bundle targets are `appimage`, `deb`, `rpm` and `nsis`, with rpm dependencies declared and a WebView2 `downloadBootstrapper` for the installer.

### Linux display flags

`configure_linux_webkit()` sets the WebKitGTK environment as **defaults, not overrides**. `GDK_BACKEND=x11` is set only when the session is not Wayland — forcing XWayland breaks fractional scaling and fails outright where XWayland is absent — and anything already in your environment wins, so `WEBKIT_DISABLE_COMPOSITING_MODE=0` is a real escape hatch. The compositing and DMABUF flags stay on by default because they fix blank windows on Nvidia and older Mesa.

### Checks

```bash
npm test               # 671 Vitest tests across 27 files
npm run typecheck      # tsc --noEmit, covering src/ and tests/
npm run test:coverage
cargo test --workspace
cargo test -p envv-cli # exporter parity + the agent-safety guarantees
cargo check -p vault-core --features bundled
```

The frontend tests load the real `index.html` rather than a fixture, deliberately: a recurring failure in this project is JavaScript reaching for an element id that a formatter silently dropped, and a hand-written fixture keeps passing after that happens.

---

## Continuous integration

`.github/workflows/ci.yml` runs two jobs on every push to `main`, every pull request, and on demand.

| Job | Runs on | Does |
| --- | --- | --- |
| **Rust** | `ubuntu-latest` and `windows-latest`, `fail-fast: false` | Builds the frontend (the Tauri crate's build script needs `dist/` to exist), checks `Cargo.lock` is current with `--locked`, then `cargo test --workspace` and `cargo check --workspace --all-targets`. Linux additionally checks the bundled, distro-independent build. |
| **Frontend** | `ubuntu-latest` | `npm ci`, `tsc --noEmit`, `npm test`, `vite build`. |

Two things in there look like noise and are not. `RUSTFLAGS: -D warnings` is set as an environment variable, which makes cargo ignore `.cargo/config.toml` — where this repo passes `-fuse-ld=mold`. Remove that line and every Linux job fails to link, because the runners have no mold. And the matrix runs both platforms without `fail-fast`, so a Windows-only break cannot hide behind a green Linux run.

`.github/workflows/build.yml` handles releases: it checks the version is consistent across `tauri.conf.json`, `package.json` and the four `Cargo.toml` files, builds every bundle target, and signs each artefact with keyless Sigstore.

---

## What is not finished

Every project has a list like this. Most do not publish it.

- **Seven of the eleven project types are experimental** and off by default: Kubernetes, SSH config, Traefik, Apache, HAProxy, Ansible, PostgreSQL. Their exporters work in the UI but have not been exercised end to end against the real software.
- **`envv` cannot pin a certificate.** There is no `--ca-cert` and no custom verifier in the CLI's HTTP path, so a self-signed `envv-server` is reachable from the desktop app but not from the CLI. Use a real certificate, or HTTP over a trusted network.
- **Connecting to a remote leaves the local vault's key resident** in memory for the whole session, with nothing on screen to say so. The LAN gate closes the one path that exploited this. Locking the local vault on switch is the deeper fix and it has not been made, because it would mean re-entering the master password every time you switch back.
- **`chunks/env-link.ts` and `chunks/edit-modal.ts` have no test coverage**, and parts of `render.ts` and `tools.ts` — config-view click handlers, the generator and calculator panes — are untested too.
- **For scoped users, read and write are nearly the same privilege**, following the ANY-match relaxation. Vault scope is the boundary that actually holds.
- **SVG is refused as a custom icon**, permanently and on purpose. It is a script container, and a vault is untrusted input. This one is not going to change.

---

## How it got here

The feature sections above are the current state. This is the order it arrived in, for anyone reading the git history.

| Phase | Delivered |
| --- | --- |
| 1 | Tauri wrapper, static frontend |
| 2 | SQLCipher + Argon2id encrypted storage, unlock flow |
| 3 | TypeScript + Vite, inline-handler elimination, structured project types, audit table, version history |
| 4 | Remote vault server and the first CLI |
| 5 | Multi-user RBAC, user classes, remote panel, health dashboard |
| 5.1 | Security hardening: Argon2id for sub-users, failure-only rate limiting, restricted CORS |
| 6 | TLS on the server, certificate pinning, tag sidebar filter, YAML formatter, re-lock overlay |
| 7 | Correctness pass: stable entry ids, audit log viewer, offline fonts, session expiry, tests and CI |
| 8 | Owner as a real user row, audit attribution, permission scoping, enumeration oracle closed |
| 9 | Permission expression language (AND / OR / NOT) with a live editor |
| 10 | Open to LAN — hosting the vault from the desktop app |
| 10.1 | Lost-update fix: compare-and-swap on every vault write |
| 11 | Frontend test suite and a module-by-module audit; 66 bugs fixed |
| 12 | UX persistence, window state, the LAN wrong-vault gate, experimental project types |
| 13 | CLI parity, exporter golden fixtures — which found the disabled-chunk and nginx-`${ref}` export bugs |
| 14 | The agent-safe CLI: redaction, JSON envelope, exit codes, `describe` |
| 15 | Custom icons, live enrichment, Windows and cross-distro portability, Docker memory |

---

## License

MIT. See [LICENSE](LICENSE).
