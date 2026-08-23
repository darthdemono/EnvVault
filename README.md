# EnvVault

EnvVault is a secrets manager that runs on your machine and talks to nothing else. API keys, passwords, X.509 certificates, SSH keys and whole structured configs live in a SQLCipher database encrypted with a key derived from your master password. No cloud account, no telemetry, no plaintext file sitting on disk waiting to be read.

It ships as three things that share one storage engine:

| | What it is |
| --- | --- |
| **The desktop app** | A Tauri 2 window. This is where you look at and edit secrets. |
| **`envv`** | A CLI built so that an automated caller can drive the whole vault without a single secret value entering its output. |
| **`envv-server`** | An optional HTTP/HTTPS server, so the desktop app and the CLI on other machines can reach one vault. |

---

## Contents

- [Install](#install)
- [First run](#first-run)
- [The desktop app](#the-desktop-app)
- [The CLI](#the-cli)
- [The server](#the-server)
- [Docker](#docker)
- [Multiple users](#multiple-users)
- [Where your files live](#where-your-files-live)
- [Building from source](#building-from-source)
- [What is not finished](#what-is-not-finished)
- [License](#license)

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

**N.B.** The salt is as load-bearing as the database. A `vault.db` paired with the wrong `vault.salt` derives the wrong key and reports "wrong password" for a password that is perfectly correct. When you back up one, back up both.

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
| Delete | Trash icon, with a five-second undo toast |
| Everything at once | Right-click for the context menu |

The coloured left border tracks expiry: red for expired or within seven days, amber for within thirty, green for an expiry that is comfortably away.

### Searching

Type in the search bar and it matches provider, account, description, tags and URL. For anything more precise, wrap a regular expression in slashes — `/^AWS_/i` works, flags included.

### Projects

A project is a container for structured configuration, and it is a different thing from a category. Categories are flat labels you attach to secrets. Projects hold **chunks**: typed fragments of a config file that EnvVault knows how to render back into that file.

Create one with **+** in the Projects section. Use `/` in the name for hierarchy (`infra/k8s` creates `infra` as a parent if it does not exist).

Four project types are tested end to end and available by default:

| Type | Chunks | Exports to |
| --- | --- | --- |
| Generic | Any key/value chunk | — |
| WireGuard | `wg_interface`, `wg_peer` | `wg0.conf` |
| Docker | `docker_service`, `docker_network`, `docker_volume`, `env_file` | `docker-compose.yaml` + `.env` |
| Nginx | `nginx_server`, `nginx_upstream`, `nginx_location`, `nginx_key` | an nginx site config |

Seven more exist — Kubernetes, SSH config, Traefik, Apache, HAProxy, Ansible and PostgreSQL — but they are behind **Settings → Advanced → experimental project types**, off by default, because they have not been exercised end to end and I would rather you knew that before you deployed something they produced.

Turning the flag back off hides those types from the *creation* menu and nothing else. Projects you already made keep working, keep exporting, and stay reachable. Hiding the config view of an existing project would strand its chunks in the vault with no way to reach them, which is worse than an untested exporter.

### Chunks and `${refs}`

Any chunk field can reference a vault entry by name. Write `${GitHub}` to pull in that entry's key, or `${GitHub/account}` for a specific field. The card shows a green badge when the reference resolves and an amber one when it does not.

References are resolved at **copy and export time**, not stored resolved. That is the point: the config in the project stays a template, and the secret stays in one place.

Chunks also take freetext notes, and can be **disabled**. A disabled chunk is greyed out in the UI and excluded from every export.

> This one was a real bug and worth stating plainly. Before Phase 13, four of the exporters checked the disabled flag and four did not. Disabling a WireGuard peer greyed out its card and still wrote the peer into `wg0.conf` — so the tunnel kept trusting a peer the user believed they had removed. If you disabled a peer or a Compose service before 0.6.0 and exported, re-export. The fix corrects the next export; it cannot reach the file already on your server.

**Importing:** nginx projects take a pasted or loaded site config and parse `server {}`, nested `location {}` and multi-word directives. Docker projects take a `docker-compose.yaml`. In both cases the result is chunks you can edit.

### Tools

Switch to Tools in the activity bar.

| Tool | What it does |
| --- | --- |
| Key generator | 32 or 64 bytes of hex |
| Certificate generator | Self-signed X.509, via `rcgen` |
| SSH keypair | Ed25519, via `ssh-key` |
| Health dashboard | Finds weak (under 12 characters), expired, expiring within 30 days, never-rotated and undescribed secrets |
| Secret diff | Field-by-field comparison of two entries, values masked |
| Expiry calendar | A month grid with colour-coded dots |
| Audit log | The append-only log, with hash-chain verification |
| Cron explainer | Parses a 5-field expression and shows the next five fire times |
| CIDR calculator | Network, broadcast, host count and mask |
| JSON / YAML formatter | Format, validate or minify, backed by `js-yaml` |
| Import | `.env`, Bitwarden JSON, 1Password JSON, raw vault JSON |
| Templates | Ten prefilled shapes — GitHub PAT, AWS access key, Stripe, PostgreSQL DSN, OpenAI, and so on |
| Bulk operations | Select mode, then bulk delete or bulk `.env` export |

### Settings

Press `S` or click the gear. Five tabs: **Appearance** (seven themes — dark, midnight, dracula, nord, catppuccin, light, and system, which follows your OS), **Layout** (card size, columns, activity bar placement), **Security** (auto-lock timeout, lock on window hide, mask keys by default), **Data** (export format, expiry warning window, custom CSS) and **Advanced** (vault path, experimental project types).

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

Locking mid-session brings up a dedicated re-lock screen rather than the startup one — it tells you *why* it locked (idle, manual, or the window was hidden) and asks for the password only. You do not re-enter a server URL to get back into a session you never left.

Locking when the window is hidden is **opt-in**, in Settings → Security. It used to fire on every alt-tab, which is not security, it is an annoyance with a security-shaped excuse.

---

## The CLI

`envv` does everything the app does, and it is built around one rule:

> The caller decides *what happens*. Values move from the vault to their target without passing through the caller's output.

That rule exists because the CLI is meant to be driven by scripts, by CI, and by automated tooling whose logs are not as private as people assume. Five mechanisms enforce it.

### 1. Redaction is the default

Every stdout path masks stored values as `sha256:<12 hex>`. In JSON it is `{"redacted":true,"fingerprint":"sha256:…","length":n}`. `--reveal` opts back in, and it is meant for a human at a terminal.

The fingerprint is what makes this useful rather than merely safe. It is stable per value, so **equal fingerprints mean equal secrets**. You can detect that staging and production drifted apart, or that two entries hold the same key, without reading either one. An empty value fingerprints as the literal string `empty`, never as a hash, because "unset" and "set to something" must not look alike.

A `${ref}` is never masked. It is a pointer, not a secret, and leaving it readable is exactly what lets a script wire configs together blind.

### 2. Ways to get the real value out

```bash
envv export --project Alpha --out .env  # real values to the file, nothing to stdout
envv exec -- terraform apply           # secrets enter the child's environment
envv render deploy.tpl --out app.conf  # substitutes ${refs} into a template
```

None of those three print a value.

A vault-wide `envv export` to stdout is **refused**, with exit code 9. Not masked — refused. A masked `.env` file looks deployable and is not, and handing someone a file that fails silently at 3 a.m. is worse than handing them an error now. Give it `--out` and it writes real values to the file. Project-scoped exports mask instead of refusing, since their structure is worth reading.

### 3. Secrets that are never seen at all

```bash
envv entry add Stripe --generate       # created inside the process that stores it
envv entry rotate Stripe --generate
envv user token new deploy --out .token
```

You get a fingerprint back. The value never existed anywhere you could read it.

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

### Commands

```
list          List entries as a table
get           Full details of one entry
export        Export entries (--out for real values)
rotate-check  Entries expiring within N days
import        Import a .env file
audit         The audit log, or --verify its hash chain
completions   bash | zsh | fish | elvish | powershell
watch         Watch a .env and sync changes into the vault
env           Resolve a project's env_file chunks into a deployable .env
entry         ls get add set rename rm tag pin compromise rotate history restore
project       ls show add rename rm export chunk
category      Categories — the flat, slash-nested sidebar tags
tags          Every tag with its entry count
gen           secret | password | cert | ssh
backup        Encrypted .vaultbak export/import, readable by the desktop app
scan          Weak, expiring, duplicated and stale-reference secrets
status        Where this CLI is pointed and what the vault holds
user          ls add rm rename passwd class token
class         User classes
perm          Permission expressions
exec          Run a command with secrets in its environment
render        Substitute ${refs} in a template file (`-` for stdin)
enrich        Fill entry metadata from names and public key prefixes
describe      The machine-readable contract
login         Authenticate once and cache the session
logout        Forget cached sessions
```

### Getting the password in without putting it in argv

Anything on a command line ends up in your shell history, in `ps` output, and in any transcript of the session. So there are four other ways:

```bash
export ENVV_PASSWORD=...                        # the environment
envv --password-file  ~/.envv-pw list           # first line of a file
envv --password-command 'pass show envv' list   # stdout of a command
envv --env-file /srv/envv/.env list             # the .env compose already reads
```

`--env-file` is the one to use with a containerised server. It reads `ENVV_PASSWORD` and `ENVV_SERVER_URL` out of the same file `docker compose` uses to start `envv-server`, so exactly one copy of the password exists and the compose stack owns it.

For a remote server, authenticate once and let everything after that run unattended:

```bash
envv login --server https://vault.example.com
envv list                                       # uses the cached session
```

The session token goes in `sessions.json`, mode 0600, under `$XDG_STATE_HOME/envv/` (or `%LOCALAPPDATA%` on Windows). A rejected session is cleared rather than retried, and the error tells you to log in again — otherwise every later command fails identically with an unhelpful 401 and you spend twenty minutes debugging the wrong thing.

### Idempotency

```bash
envv entry add   GitHub --if-missing
envv entry set   GitHub --create
envv project add Alpha  --if-missing
```

Re-running a provisioning script is not an error, and does not overwrite a secret that is already there.

`--dry-run` is enforced inside the single write point rather than checked by each command, so a command that forgets to look at the flag still cannot write.

### `envv enrich`

An imported `.env` has no metadata. No scopes, no expiry, no account, no idea which of those forty variables is a Stripe key and which is a database URL. `enrich` infers it from the entry name and from the **public** prefix the issuer puts on its credentials — `ghp_`, `sk-ant-`, `AKIA`, `sk_live_`, about forty of them — plus structural shapes like PEM blocks, JWTs and `postgres://` URLs.

```bash
envv enrich                    # preview; changes nothing
envv enrich --apply            # fill the gaps
envv enrich --apply --force    # also overwrite fields that already have values
envv enrich --online --apply   # ask the issuers
```

`--online` sends the secret over TLS to the service that issued it, and nowhere else, then fills `account_name`, `scopes`, `expires_at` and `rate_limit` from the real answer. It is opt-in for exactly that reason.

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

Auth is a bearer token. Failed attempts are rate-limited to 10 per IP per 60 seconds, counted from the real socket address rather than `X-Forwarded-For` — a header the client controls is not an identity.

### Self-signed certificates, and the chicken-and-egg problem

The desktop app pins the server's certificate. When you save a remote vault it compares the SHA-256 of the leaf certificate **during the handshake**, before it sends anything, so a machine-in-the-middle is rejected before your master password goes over the wire.

That creates an obvious problem for a self-signed server: connecting requires a fingerprint you can only get by connecting. The bootstrap is a separate trust-on-first-use step — an unauthenticated `GET /api/status` with a capturing verifier that **sends no credentials** and returns the fingerprint for you to confirm. Everything after that first contact is pinned, and the app warns you if the fingerprint later changes.

### Open to LAN

The desktop app can host the vault it already has open, from the Remote panel, so another machine on the network can reach it without a second server process or a second copy of the database.

It refuses while you are connected to a remote vault. `lan_start` opens *this* machine's `vault.db`, so pressing it during a remote session published the local vault under the remote's UI — a confusing bug with a genuinely bad outcome. The gate is enforced at the button and again at the call.

### API

| Method | Path | Auth | What |
| --- | --- | --- | --- |
| POST | `/api/unlock` | — | `{password}` → `{token}` |
| DELETE | `/api/unlock` | token | Lock, invalidate the token |
| GET | `/api/status` | — | `{unlocked, vault_exists, cert_fingerprint}` |
| POST | `/api/auth` | — | `{username, password}` or `{token}` → `{token}` |
| GET | `/api/ping` | token | Keep-alive, resets the idle clock |
| GET / PUT | `/api/vault` | token | Read / write the whole `VaultData` |
| GET | `/api/vault/expiring?days=30` | token | Expiring entries |
| GET | `/api/audit` | token | The audit log |
| GET/POST/DELETE | `/api/users`, `/api/users/{id}/…` | owner | Users, passwords, classes, tokens, permissions |
| GET/POST/DELETE | `/api/classes`, `/api/classes/{id}/…` | owner | Classes and their permissions |
| GET | `/api/stats` | — | Public counts, 0 while locked |
| GET | `/api/openapi.json` | — | The spec |

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

Idle memory is about 1.3 MiB, down from 4 MiB, from three changes worth knowing if you tune this yourself: tokio runs 2 workers instead of one per CPU (`ENVV_WORKER_THREADS`), `MALLOC_ARENA_MAX=2` stops glibc from reserving up to eight 64 MB arenas per core, and `MALLOC_TRIM_THRESHOLD_` returns the Argon2id buffer to the OS instead of letting it sit resident for the life of the process. The arena saving scales with your host's core count, so a big server benefits more than a small one.

The healthcheck opens the port rather than running `--version`, because a wedged process answers `--version` perfectly well.

---

## Multiple users

The vault owner is whoever can derive the key from the master password. Beyond that you can create users, give them passwords or API tokens, and constrain what they can see.

Users get capabilities (`manage_users`, `manage_classes`, `delete_projects`) and two permission expressions: one for read, one for write. **Classes** are named templates — Admin, Moderator, Viewer, or your own — holding the same thing, so you set the rule once and assign it.

### Permission expressions

A boolean expression over entry fields:

```
project:Alpha AND NOT category:secret
(project:web OR project:api) AND env:production
tag:shared OR type:certificate
```

Terms are `field:glob`, where field is one of `vault`, `project`, `category`, `tag`, `env` or `type`. `field:*` means no constraint on that field.

Four rules govern how they combine, and all four fail towards *less* access:

1. Effective permission is the class expression **AND** the individual one. A class exclusion cannot be undone by an individual grant.
2. Write implies read.
3. A specific `project:` term is never satisfied by the `Universal` catch-all project.
4. A malformed expression **denies**. It is rejected when you save it, and if one somehow reaches evaluation it evaluates to no access rather than to full access.

Sub-user passwords are Argon2id in PHC format. Old SHA-256 hashes from before Phase 5.1 are upgraded transparently on the user's next successful login, so there is nothing for you to migrate.

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

`vault-core/bundled` compiles SQLCipher and OpenSSL into the binary instead of linking your system's. Use it for anything that has to run on a machine other than the one that built it. An AppImage linked against Fedora's `libsqlcipher0` will not start on a Debian box shipping a different soname, and "works on my distro" is the whole problem a portable bundle exists to solve. For local development, leave it off — it builds in seconds instead of minutes.

Checks:

```bash
npm test               # 671 tests
npm run typecheck
cargo test --workspace
cargo test -p envv-cli # exporter parity + the agent-safety guarantees
```

---

## What is not finished

Every project has a list like this. Most do not publish it.

- **Seven of the eleven project types are experimental** and off by default: Kubernetes, SSH config, Traefik, Apache, HAProxy, Ansible, PostgreSQL. Their exporters work in the UI but have not been exercised end to end against the real software.
- **`envv` cannot pin a certificate.** There is no `--ca-cert` and no custom verifier in the CLI's HTTP path, so a self-signed `envv-server` is reachable from the desktop app but not from the CLI. Use a real certificate, or HTTP over a trusted network.
- **Connecting to a remote leaves the local vault's key resident** in memory for the whole session, with nothing on screen to say so. The LAN gate closes the one path that exploited this. Locking the local vault on switch is the deeper fix and it has not been made, because it would mean re-entering the master password every time you switch back.
- **`chunks/env-link.ts` and `chunks/edit-modal.ts` have no test coverage.**
- **SVG is refused as a custom icon**, permanently and on purpose. It is a script container, and a vault is untrusted input. Icon files are typed by magic bytes rather than by their extension for the same reason.

---

## License

MIT. See [LICENSE](LICENSE).
