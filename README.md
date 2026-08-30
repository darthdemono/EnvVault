# EnvVault

EnvVault is a secrets manager that runs on your machine and talks to nothing else. API keys, passwords, X.509 certificates, SSH keys and whole structured configs live in a SQLCipher database encrypted with a key derived from your master password. No cloud account, no telemetry, no plaintext file sitting on disk waiting for someone to read it.

It ships as three programs that share one storage engine:

|                     | What it is                                                                                                      |
| ------------------- | --------------------------------------------------------------------------------------------------------------- |
| **The desktop app** | A Tauri 2 window. This is where you look at and edit secrets.                                                   |
| **`envv`**          | A CLI built so an automated caller can drive the whole vault without a single secret value entering its output. |
| **`envv-server`**   | An optional HTTP/HTTPS server, so the desktop app and the CLI on other machines can reach one vault.            |

Current version **0.8.1**. The version in `src-tauri/tauri.conf.json` is the authoritative one. `package.json`, the four `Cargo.toml` files and the git tag are all checked against it by the `meta` job in `.github/workflows/build.yml`.

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
- [Entropy sources](#entropy-sources)
- [Key pools](#key-pools)
- [Backups, and the one thing you cannot recover](#backups-and-the-one-thing-you-cannot-recover)
- [The server](#the-server)
- [Open to LAN](#open-to-lan)
- [Concurrent writes](#concurrent-writes)
- [Docker](#docker)
- [Multiple users](#multiple-users)
- [Permission expressions](#permission-expressions)
- [The security model](#the-security-model)
- [Where your files live](#where-your-files-live)
- [Building from source](#building-from-source)
- [Development](#development)
- [Continuous integration](#continuous-integration)
- [What is not finished](#what-is-not-finished)
- [How it got here](#how-it-got-here)
- [License](#license)

---

## What it does

Everything listed here is implemented and in the shipping build. The sections after this one explain each of them properly.

### Storage and crypto

- SQLCipher (AES-256-CBC) for the database. The key never touches disk.
- Argon2id (m=65536, t=3, p=1) over your master password and a 16-byte random salt.
- The key lives in one `Mutex<Option<[u8; 32]>>` and is zeroed on lock.
- Argon2id again, with cheaper parameters, for sub-user passwords.
- An append-only audit log bound into a SHA-256 hash chain, so a deleted or edited row is detectable.
- Optional hardware entropy for generated secrets, mixed with the OS CSPRNG and never used raw.

### Secrets

- Seven types: API key, password, certificate, environment variable, connection string, SSH key, file reference.
- Rotation cadences, expiry dates, an overdue badge, and a health scan that finds the ones you forgot.
- Version history per entry, capped at fifty revisions, restorable.
- Tags, categories, projects, environments and prefixes, all filterable from the sidebar.
- About forty issuer signatures recognised on sight, so an imported `.env` stops being an undifferentiated pile of strings.
- Importers for `.env` files, Bitwarden, 1Password and Proton Pass.

### Projects and configuration

- Eleven project types, all of them validated against the software they target.
- Config chunks: a WireGuard peer, a Compose service, an nginx server block, a Kubernetes Secret, and so on.
- `${refs}` that point a config field at a vault entry, so the secret lives in one place and the config points at it.
- Exporters that write a real `wg0.conf`, `docker-compose.yml`, `nginx.conf`, Kubernetes manifest, `ssh_config`, Traefik dynamic config, Apache vhost, HAProxy config, Ansible playbook or `.pgpass`.

### The CLI

- Redaction by default. Stored values print as `sha256:` plus twelve hex characters.
- Materialisation paths that skip stdout completely: `--out`, `envv exec`, `envv render`.
- A JSON envelope and ten stable exit codes, so a script can branch on the failure instead of grepping English.
- `envv describe`, which prints the whole contract as JSON generated from the same clap definition the binary runs on.
- Certificate pinning, so a self-signed `envv-server` is reachable safely.
- `envv doctor`, which checks the things that break quietly.

### The server, and sharing

- HTTP or HTTPS, with a self-signed certificate generated on first start if you do not bring your own.
- Certificate pinning in both clients, enforced during the handshake, before any credential is sent.
- Selective reads, so a scoped user does not download the whole vault to read one value.
- "Open to LAN", which serves the vault straight out of the desktop app.
- Compare-and-swap on every write, so two people editing at once produces a conflict instead of a silent loss.

### Multi-user

- Named sub-users with their own passwords and API tokens.
- Classes, which are named permission templates.
- A permission expression language with `AND`, `OR` and `NOT`.
- Strict write scoping, where a write must satisfy every scope instead of any one of them.
- Capability flags and an authority tier, so a user cannot grant themselves more than they hold.

### The application itself

- Nineteen tool panes: generators, a health scan, an audit viewer, a diff, a formatter, a CIDR calculator, a cron reader and more.
- Themes, an activity bar you can move, a resizable sidebar and a layout that remembers itself.
- Auto-lock, a dedicated re-lock screen, and window state that survives a restart.
- 814 frontend tests and 183 Rust tests, run on Linux and Windows on every push.

---

## Install

### From a release

Grab the artefact for your platform from the [Releases](../../releases) page.

| File                         | Platform                                                                                                            |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `*.AppImage`                 | Any Linux distribution. SQLCipher and OpenSSL are compiled in, so it does not care what your package manager ships. |
| `*.deb`                      | Debian, Ubuntu                                                                                                      |
| `*.rpm`                      | Fedora, RHEL, Nobara                                                                                                |
| `*-setup.exe`                | Windows. Fetches WebView2 during install if the machine lacks it.                                                   |
| `envv-*-linux-x86_64.tar.gz` | `envv` and `envv-server`, no GUI toolkit required                                                                   |
| `envv-*-windows-x86_64.zip`  | The same two, for Windows                                                                                           |

Every asset carries a keyless Sigstore signature. If you want to confirm a download actually came out of this repository's CI and not from somewhere else:

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

On first launch the app asks you to create a master password. Minimum twelve characters, and it means it. This is a secrets manager, and eight characters of `hunter2` is not a serious answer to the question.

That password is never stored anywhere. It goes through Argon2id (m=65536, t=3, p=1) with a 16-byte random salt to derive a 32-byte key, and that key opens the SQLCipher database. The key lives in memory and is zeroed when you lock.

So what happens if you forget it? Nothing good. There is no recovery, no reset link, no support address that can help you. The only thing left is to delete `vault.db` and `vault.salt` and start over with an empty vault. Write the password down somewhere real.

**N.B.** The salt is as load-bearing as the database, and this is the single most common way people lose a vault. `vault.salt` is sixteen bytes of CSPRNG output, written once, derived from nothing, and stored nowhere else. A `vault.db` without it cannot be opened by anyone, including you, and nothing can recompute it. Copying the database to a new machine and leaving the salt behind is a permanent loss that looks like a forgotten password, because every unlock attempt reports "wrong password" for a password that is perfectly correct.

Two things guard against that now. `envv backup archive` writes both files into one encrypted archive, and any attempt to open a database whose salt has gone missing refuses outright instead of silently generating a fresh one. `envv doctor` and `envv status` both tell you where the salt is and remind you to keep it with the database.

---

## The desktop app

### Layout

An activity bar down the left (or the right, if you move it in Settings) switches between Vault, Remote, Users, Tools and Settings. The sidebar next to it filters. The grid holds the cards.

The sidebar filters by category, project, tag, environment and prefix. Categories are flat tags with slash nesting for grouping. Projects are real objects that carry config chunks and a type. Drag the divider to resize the sidebar, double-click it to reset, and press `B` to collapse it entirely. Whatever you leave it as is what you get next launch.

### Adding a secret

`Ctrl+N`, or the button in the header. Pick the type first, because the type decides which fields the form shows. A certificate wants a PEM and its private key. A connection string wants a URL. An API key wants a key and optionally a key id.

Every field that can be generated has a Generate button next to it, and the generator is type-aware. Press it on a password field and you get a password. Press it on a certificate and you get a self-signed certificate with its key.

### What a card can do

Click to expand. The card shows the fields, and the buttons across the top do the rest:

- Copy the secret, with `${refs}` resolved.
- Reveal it, which is off again the next time you open the screen.
- Edit, duplicate, delete (with a five-second undo).
- Pin it to the top of the grid.
- Mark it compromised, which colours it red and puts it at the top of the health scan.
- Rotate it, which stamps `last_rotated_at` and can generate the replacement for you.
- Open its version history and restore an old revision.

### Searching

`Ctrl+K` focuses the search bar. It searches names, usernames, notes, tags and categories. The last eight searches are remembered and offered as a dropdown. `Esc` clears it, `Shift+Esc` clears every active filter at once, which exists because a filter restored from a previous session is one you do not remember setting.

---

## Secrets

### The seven types

| Type                | What it holds                                 |
| ------------------- | --------------------------------------------- |
| `api_key`           | A key, optionally a secret and a key id       |
| `password`          | A password with a username or an email        |
| `certificate`       | A PEM certificate and its private key         |
| `env_var`           | A single environment variable, with a subtype |
| `connection_string` | A database or service URL                     |
| `ssh_key`           | An OpenSSH keypair                            |
| `file_blob`         | A path to a file that lives outside the vault |

The type is not decoration. It decides which fields the form offers, how the card renders, what the generator produces, and how an exporter treats the value.

### Environment-variable subtypes

An `env_var` carries a display hint: string, multiline, secret, boolean, number, ip, cidr, port, url, date or json. It changes how the value is shown and validated. A `port` that is not a number is worth catching before it reaches a config file.

### What every entry carries, regardless of type

Names, usernames, emails, URLs, notes, tags, categories, project membership, environment, an expiry date, a rotation cadence, a price type and a free-text scope list. Beyond those:

- **`purpose`**, which is the justification you gave the issuer when you asked for the credential. Six months later that is the field you actually want.
- **`pool`**, which is explicit key-pool membership. See [Key pools](#key-pools).
- **The rate limit**, stored as a count plus a period rather than as free text, with `rate_limit_note` for anything that is not "n per period". The legacy string is still written so an older build can still read the vault, but nothing should ever parse it directly. `normalizeRateLimit` and `ratelimit::normalize` are the readers, and they migrate on read, because there is no single moment at which "the vault has been migrated" is true.
- **`custom_icon`**, which holds either a Simple Icons slug or a `data:` URI for an uploaded file. One field on purpose, so an entry can never hold a slug and a file that disagree.

### Templates

Ten starter templates for the services people actually store: AWS, GitHub, Stripe, OpenAI, Postgres and so on. They pre-fill the name, the URL, the icon and the fields that service uses. You can save your own.

### Secrets EnvVault recognises on sight

About forty issuer signatures, keyed on the public prefix of the credential: `ghp_`, `glpat-`, `xoxb-`, `sk-ant-`, `sk_live_`, `AKIA`, `dop_v1_`, `npm_` and the rest. It also recognises structural shapes: a PEM block, a JWT, a `postgres://` URL.

`envv enrich` uses those to fill in the metadata an imported `.env` never has. It is a preview by default and only writes with `--apply`, and it only fills gaps unless you pass `--force`.

`envv enrich --online` goes further and asks each issuer about its own credential, filling `account_name`, `scopes`, `expires_at` and `rate_limit` from the real response. Eight issuers answer: GitHub, GitLab, Slack, Stripe, DigitalOcean, npm, OpenAI and Anthropic. It is opt-in because it sends the secret over TLS to the service that issued it. That is a real cost, and it buys you something you cannot get any other way: a 401 from the issuer is the only reliable way to learn that a stored credential has been revoked.

**N.B.** `secretType` is `api_key` for every entry ever written, so "is this field empty?" has to special-case it. Without that, every imported `postgres://` URL stays classified as an API key forever.

### Importing existing secrets

Four importers, all of them preview-first:

| Command                         | Reads                                                     |
| ------------------------------- | --------------------------------------------------------- |
| `envv import FILE`              | A `.env` file, or a full-vault JSON export with `--json`  |
| `envv import-vault bitwarden`   | A Bitwarden JSON export                                   |
| `envv import-vault onepassword` | A 1Password export, either `op item list` JSON or `.1pux` |
| `envv import-vault proton`      | A Proton Pass JSON export                                 |

The vendor importers share three rules. They upsert by identity rather than appending, so running the same import twice creates nothing and changes nothing. They print fingerprints rather than values, because that output goes to stdout like everything else. And they count what they skipped, because a Bitwarden export full of credit cards should not silently report that it imported everything.

Two of them have a trap worth naming. A Bitwarden secure note keeps the secret in the `notes` field, so the importer moves it into the value and clears the note, since nothing redacts a notes field. And a Proton Pass export can be encrypted, in which case it is perfectly valid JSON with no readable items in it. A naive reader reports "0 credentials found" for a file that is full of them. This one refuses and tells you which checkbox to untick.

`envv watch FILE` keeps a `.env` in sync with the vault as you edit it. It upserts by provider, because the first version appended unconditionally and added a full copy of the file to the vault on every save.

### Icons

Around three hundred Simple Icons slugs, searchable, with a letter-avatar fallback. You can also upload your own file: PNG, JPEG, GIF, WebP, BMP or ICO, up to 96 KB encoded, typed by magic bytes rather than by the file extension.

SVG is refused. Permanently, and on purpose. An SVG is a script container and a vault is untrusted input. This one is not going to change.

The uploaded file is validated on read as well as on pick, for the same reason.

---

## Projects, chunks and exports

A project is a real object with a type. Its config lives in **chunks**, and a chunk is a named group of fields: one WireGuard peer, one Compose service, one nginx server block.

Eleven project types ship, and as of Phase 18 all eleven are stable:

| Type         | Exports to                       |
| ------------ | -------------------------------- |
| `generic`    | Nothing in particular            |
| `wireguard`  | `wg0.conf`                       |
| `docker`     | `docker-compose.yml` plus `.env` |
| `nginx`      | `nginx.conf`                     |
| `kubernetes` | Secret and ConfigMap manifests   |
| `ssh_config` | `~/.ssh/config`                  |
| `traefik`    | Traefik dynamic configuration    |
| `apache`     | A vhost fragment                 |
| `haproxy`    | `haproxy.cfg`                    |
| `ansible`    | A playbook, or a vars file       |
| `postgres`   | `.pgpass`                        |

Twenty-nine chunk types sit under those. A chunk can be disabled, which greys the card out and excludes it from every export.

### `${refs}`

A config field can point at a vault entry instead of holding a value:

```
${GitHub}                  the entry's main secret
${GitHub/password}         a named field on it
${GitHub_deploy}           disambiguated by key id
${chunk:api/DATABASE_URL}  a field on another chunk
```

Everything that copies or exports resolves these first. A `${...}` reaching a real `wg0.conf` or a `.pgpass` is a broken deploy, and it fails somewhere else entirely, with an error that names none of this.

There is one deliberate exception. A `docker_service` chunk keeps `${VAR}` as written, because Compose substitutes it from the `.env` file written beside it.

Renaming an entry rewrites every `${ref}` pointing at it. Without that cascade, renaming quietly breaks every config that referred to it, and you find out at deploy time.

### How a project type earns the word "stable"

By having its generated config accepted by the software it targets. Not by round-tripping through a parser we also wrote, because a parser we wrote agreeing with an exporter we wrote proves nothing at all.

| Type       | Evidence                                                                 |
| ---------- | ------------------------------------------------------------------------ |
| wireguard  | Round-trips through `parseWgConf`                                        |
| docker     | Compose schema, plus the `.env` pairing                                  |
| nginx      | Round-trips through `parseNginxConf`                                     |
| kubernetes | Applied to a real k3s cluster, and the value read back out of it         |
| ssh_config | Parsed by OpenSSH, `ssh -G`                                              |
| traefik    | Loaded by Traefik v3, router and middleware both reporting `enabled`     |
| apache     | `httpd -t` returning `Syntax OK`                                         |
| haproxy    | `haproxy -c` returning zero                                              |
| ansible    | `ansible-playbook --syntax-check` returning zero                         |
| postgres   | A real Postgres server authenticating using only the generated `.pgpass` |

`.github/workflows/exporters.yml` runs that matrix. Every job carries a control case that fails the build if the validator accepts nonsense, because a green tick from a validator that accepts anything is worse than no job at all.

That exercise was worth doing. It found two bugs that no fixture could have caught. Six of the seven newer exporters never resolved `${refs}` at all, so an Apache `SSLCertificateFile` pointed at nothing and a `.pgpass` shipped the literal string `${DB/password}` as the password. And `exportAnsible` emitted a mapping immediately followed by a sequence, which is not valid YAML in any parser, so its output could never have been consumed by the tool it was written for.

### Two implementations, one golden file

The config formats exist twice: once in `src/ts/chunk-ops.ts` for the app, once in `envv-cli/src/exporters.rs` for the CLI. Two implementations of one file format drift silently. The app writes a working `wg0.conf`, the CLI writes a subtly different one, and nobody notices until a deploy breaks.

So both sides assert against the same golden files in `tests/fixtures/parity/`. `tests/cli-parity.test.ts` pins the TypeScript output, `envv-cli/tests/parity.rs` pins the Rust output against identical bytes. Change either one and the other fails.

Regenerate deliberately:

```bash
PARITY_UPDATE=1 npx vitest run tests/cli-parity.test.ts
cargo test -p envv-cli
```

The first time that fixture ran it found two live export bugs. Disabled chunks were being exported by the four exporters people actually deploy, so disabling a WireGuard peer greyed the card out and still wrote it into `wg0.conf`, and the tunnel kept trusting a peer the user believed they had removed. And `exportNginx` never resolved `${refs}`, so the starter template's `ssl_certificate ${example_cert}` reached nginx as literal text and the server refused to start, while copying the same chunk from its card resolved perfectly.

---

## Tools

Nineteen panes, reachable from the activity bar.

| Pane                  | What it does                                                        |
| --------------------- | ------------------------------------------------------------------- |
| **Secret generator**  | Random bytes as hex, base64 or base64url                            |
| **Password**          | Character sets, a length slider and a strength meter                |
| **UUID and ULID**     | Both, in bulk                                                       |
| **Hashes**            | SHA-256, SHA-512 and friends over text                              |
| **Certificate**       | Self-signed X.509 with its private key                              |
| **SSH keygen**        | Ed25519 keypairs in OpenSSH format                                  |
| **Token validator**   | Decodes a JWT, identifies an issuer prefix, reports what it can     |
| **Key patterns**      | The issuer signatures this vault recognises on sight                |
| **String tools**      | Base64, URL and hex encoding, case conversion                       |
| **Health scan**       | Weak, expiring, duplicated, compromised and stale-reference secrets |
| **Key pools**         | Cursor, cooldowns and use counts for interchangeable credentials    |
| **Import and export** | `.env`, JSON, and encrypted `.vaultbak` backups                     |
| **Templates**         | The starter templates, and your own                                 |
| **Diff**              | Compare two entries field by field                                  |
| **Audit log**         | The append-only log, and `Verify` for the hash chain                |
| **Expiry calendar**   | What runs out, and when                                             |
| **Cron**              | Reads a cron expression back in English                             |
| **CIDR**              | Subnet maths                                                        |
| **Formatter**         | JSON and YAML, format, validate and minify                          |

The audit viewer reads the whole table, which is fine now and will not be fine forever. See [What is not finished](#what-is-not-finished).

---

## Settings, shortcuts and auto-lock

### Settings

Themes, accent colour, card density, the activity bar side, which sidebar sections appear and in what order, and custom CSS injected after every built-in stylesheet. Under Security: the auto-lock timeout, whether hiding the window locks the vault, and whether the local vault stays unlocked when you switch to a remote.

### Keyboard shortcuts

| Key         | Action                           |
| ----------- | -------------------------------- |
| `Ctrl+K`    | Focus the search bar             |
| `Ctrl+N`    | Add a secret                     |
| `Esc`       | Clear search, or close the modal |
| `Shift+Esc` | Clear every active filter        |
| `S`         | Settings                         |
| `B`         | Toggle the sidebar               |
| `?`         | The shortcut list                |

### Auto-lock

The vault locks itself after 60 idle minutes by default. Set the timeout to 0 in Settings to disable it. Mouse and keyboard activity resets the clock, and a dismissible toast warns you a minute out.

Locking mid-session brings up a dedicated re-lock screen rather than the startup one. It tells you _why_ it locked (idle, manual, or the window was hidden) and asks for the password only. You do not re-enter a server URL to get back into a session you never left. Locking also clears any pending undo, since a pending undo closes over a deleted entry including its secret.

Locking when the window is hidden is opt-in. It used to fire on every alt-tab, which is not security, it is an annoyance with a security-shaped excuse.

Auto-lock and lock-on-hide are both suspended while you are [serving to the LAN](#open-to-lan).

### Window state

Size, position and maximized state persist across restarts. Visibility deliberately does not. The tray handler hides the window, so saving visibility would mean that hiding to the tray and quitting restores an _invisible_ window next launch, and the app appears to start and do nothing with only the tray icon as a way back. The plugin also skips restoring a position that no connected monitor intersects, so unplugging a second display cannot strand the window off-screen.

---

## The CLI

`envv` exists so that an orchestrator, a CI job or an agent can drive the whole vault without a secret value ever entering its output. One rule holds the design together:

> The orchestrator decides _what happens_. Values move from the vault to the target without passing through the orchestrator's context.

Five mechanisms make that true.

### 1. Redaction is the default

Every stdout path masks stored values as `sha256:` plus twelve hex characters. In JSON:

```json
{ "redacted": true, "fingerprint": "sha256:d4291adb444f", "length": 40 }
```

`--reveal` opts back in.

Fingerprints are stable per value, which is what makes the redacted view useful rather than merely safe. Equal fingerprints mean equal secrets, so a caller can detect drift and duplication without reading anything. An empty value fingerprints as `empty` and never as a hash, because "unset" and "set to something" must not look alike.

Two rules that are easy to get wrong:

- **A whole `env_file` chunk is masked, and the per-field flags are ignored.** `chunk set` writes `field_type: var` by default, so a real password added that way carries no secret flag at all. Trusting the flag inside a `.env` means the first unflagged password is the one that leaks.
- **A `${ref}` is never masked.** It is a pointer, not a secret, and leaving it readable is exactly what lets an agent wire configs together blind.

### 2. Ways to get the real value out

Three, and none of them touch stdout:

```bash
envv get GitHub --out token.txt          # straight to a file
envv exec -- ./deploy.sh                 # into the child's environment
envv render nginx.conf.tpl --out /etc/nginx/nginx.conf
```

This is enforced by construction rather than by discipline. `Resolver::for_output` redacts, `Resolver::materialising` does not, and an exporter cannot obtain a real value without being handed the latter.

A vault-wide `export` to stdout is refused outright, with exit code 9, rather than masked. A masked `.env` looks deployable and is not. Project exports mask instead, since their structure is worth reading.

### 3. Secrets that are never seen at all

```bash
envv entry add Stripe --generate
envv entry rotate Stripe --generate
envv user token new deploy --out token.txt
```

The value is created inside the process that stores it, and the caller gets a fingerprint back.

`user token new` checks the output policy _before_ minting. The first version minted the token and then refused to print it, which left a live credential in the database that nobody could read.

### 4. A machine-readable envelope

```json
{ "ok": true,  "command": "entry.add", "data": {  } }
{ "ok": false, "error": { "code": "not_found", "message": "", "details": {} } }
```

| Code                 | Exit | Means                                               |
| -------------------- | ---- | --------------------------------------------------- |
| `error`              | 1    | Unclassified                                        |
|                      | 2    | clap usage error                                    |
| `not_found`          | 3    | No such entry, project, chunk, user or class        |
| `ambiguous`          | 4    | Matched several. `details.candidates` lists them    |
| `denied`             | 5    | Authentication failed, or the permission is missing |
| `conflict`           | 6    | Already exists, or a concurrent write won           |
| `unavailable`        | 7    | Vault or server unreachable, or locked              |
| `needs_confirmation` | 8    | Destructive command, no `--yes`, no tty             |
| `redacted`           | 9    | The output would contain secrets                    |
| `invalid`            | 10   | Well-formed request, invalid input                  |

The difference between 5 and 7 matters more than it looks. A caller retries a 7. If a certificate that fails its pin reported 7, an agent would sit in a loop against a machine-in-the-middle while the operator read "cannot reach server" about a server that was up and answering.

`--dry-run` is enforced inside `Access::save`, which is the single write point, so a command that forgets to check the flag still cannot write.

### 5. `envv describe`

The whole command tree, every flag, the exit codes, the envelope and the redaction rules, as one JSON document generated from the same clap definition the binary runs on. It cannot describe a flag that does not exist. This is what an agent reads instead of guessing from error messages.

```bash
envv describe | jq '.commands[] | select(.name == "entry")'
```

### Certificate pinning

The CLI could not verify a self-signed `envv-server` at all until Phase 17. There was no `--ca-cert`, no custom verifier, and worse: it linked a different TLS stack from the desktop app, since `reqwest`'s default features pull in native-tls while the app has always used rustls. One product, two trust decisions, neither aware of the other.

Both now build from one verifier in `vault-core/src/tls.rs`. Three flags:

```bash
envv --fingerprint <sha256> --server https://vault.lan:8743 list
envv --ca-cert /etc/ssl/private-ca.pem --server https://vault.lan:8743 list
envv login --server https://vault.lan:8743 --tofu
```

`--tofu` is trust on first use. It performs the handshake, prints the fingerprint, sends **no credentials**, and stores the pin beside the session token so every later command is pinned without repeating a 64-character flag. It refuses to run a second time against a server that already has a pin, because a certificate that changed underneath you is exactly what pinning exists to notice.

A fingerprint is accepted in whichever form you paste it. `openssl x509 -fingerprint` prints upper case with colons, this stores lower-case hex, and a pin that only matches one of those is a pin that fails for everyone who copied it from the tool that prints it.

There is no `--insecure`. There is deliberately no variant of the policy meaning "do not verify", and `danger_accept_invalid_certs` appears nowhere in this workspace.

One exception, named for what it is. `enrich --online` talks to github.com and seven others, so it uses `build_public_client`, which always applies ordinary CA validation and never the pin. Applying your server's pin to `api.github.com` would fail every handshake, and if it somehow did not, it would mean the pin was not being enforced at all.

### Commands

| Group                                       | What it covers                                              |
| ------------------------------------------- | ----------------------------------------------------------- |
| `list` `get` `export` `rotate-check`        | Reading                                                     |
| `entry`                                     | Add, set, remove, tag, pin, compromise, rotate, history     |
| `project` `project chunk` `category` `tags` | Structure                                                   |
| `env` `render` `exec`                       | Materialising values without printing them                  |
| `gen`                                       | Secrets, passwords, certificates, SSH keys, entropy sources |
| `import` `import-vault` `watch`             | Getting existing secrets in                                 |
| `backup`                                    | `.vaultbak` and `.vaultarc`                                 |
| `scan` `status` `doctor` `audit`            | Checking                                                    |
| `pool`                                      | Key pools                                                   |
| `user` `user token` `class` `perm`          | Users, tokens, classes, permissions                         |
| `login` `logout` `whoami` `sessions`        | Sessions against a remote                                   |
| `enrich`                                    | Filling in metadata                                         |
| `describe` `completions`                    | The contract, and shell completion                          |

Two behaviours worth knowing before you script against it.

**Lookups refuse ambiguity.** `envv entry rm git` with both GitHub and GitLab present lists both and exits 4. It never guesses. `provider:key_id` disambiguates.

**`confirm()` refuses on a non-tty** rather than assuming yes. A script that forgot `--yes` fails loudly instead of deleting something.

### `envv doctor`

Everything that can be checked about a vault without changing it:

```
[  ok  ] integrity    Database structure is intact
[  ok  ] salt         Present beside vault.db, back both up together
[  ok  ] permissions  Vault, salt, session and pool files are owner-only
[  ok  ] schema       1 entries, 1 projects
[  ok  ] pools        Pool state parses and every member exists
[  ok  ] audit        Hash chain intact across 14 rows
```

Exit 0 when everything passes, 10 when something is actually broken, so a script can branch on it. It runs `PRAGMA integrity_check` rather than just opening the file, since a database can open cleanly and still be corrupt in a page nothing has read yet. It checks file modes and reports "not enforceable" on Windows rather than passing, because a check that always passes proves nothing. It parses `pools.json` and looks for members naming entries that no longer exist. And it verifies the audit chain through the same code path `envv audit --verify` uses, because two implementations of a tamper check is one too many.

It also runs when the vault will not open, which is the case it exists for. An earlier version required an open vault and therefore failed with "no vault found" on exactly the condition it most needed to diagnose.

There is no `--repair` for a missing salt, and there never will be. Nothing can reconstruct sixteen bytes of CSPRNG output. A flag that appeared to offer that would be discovered as a lie during a restore, which is the worst possible moment.

Writing `doctor` immediately found two real defects. The vault database and its salt were being created mode 0644. The contents are encrypted, so that is not a disclosure of secrets, but it hands every local user the ciphertext and an offline-attack head start nobody offered them. Both are 0600 now, WAL sidecars included.

### Getting the password in without putting it in argv

```bash
envv --password-command 'pass show envv' list
envv --password-file /run/secrets/vault-pw list
envv --env-file /srv/envv/.env enrich --online --apply
ENVV_PASSWORD=... envv list
```

`--password-command` uses `cmd /C` on Windows, since there is no `sh`. `--env-file` reads `ENVV_PASSWORD` and `ENVV_SERVER_URL` out of the file `docker compose` already uses, so one copy of the password exists and the compose stack owns it.

### Signing in as a named user

```bash
envv login --server https://vault.lan:8743 --user alice
envv --server https://vault.lan:8743 list      # uses the cached session
envv whoami
envv sessions
envv logout --all
```

Sessions cache in `sessions.json`, mode 0600, filed by subject so naming a subject selects a session rather than suppressing it. A rejected session is cleared and the error tells you to log in again, since otherwise every later command fails identically with an unhelpful 401.

**N.B.** On Windows there is no chmod equivalent and the file inherits the directory ACL. That is a real gap and it is written down rather than papered over.

### Idempotency

```bash
envv entry add Stripe --if-missing
envv entry set Stripe --create
envv project add Web --if-missing
```

Re-running a provisioning script is not an error, and it does not overwrite a secret.

---

## Entropy sources

Every generator can draw from a hardware source instead of the OS CSPRNG alone:

```bash
envv gen sources
envv --entropy-source file:/dev/random gen secret --bytes 32
envv --entropy-source file:/dev/hwrng gen ssh --comment ci@host
```

`os` is the default and stays the default. `file:PATH` covers `/dev/random`, an rng-tools device, or any character device your hardware exposes.

One rule decides whether this feature is safe or actively dangerous:

> Hardware entropy is **mixed in, never consumed raw**. The output is always `HKDF-SHA256(os_bytes || device_bytes)`.

A physical device can be absent, unplugged mid-read, wedged returning one byte forever, counterfeit, or deliberately backdoored. If its output were used directly, anyone controlling the device would control every key generated on that machine, which is strictly worse than the OS RNG the feature was meant to improve on. Mixing means the result is at least as good as `getrandom` no matter what the device does.

Three consequences follow, all deliberate.

**Absence fails closed.** Select a device that is not there and you get exit 7 and a message naming it. There is no silent fallback, because a silent fallback means you believe you used the token and you did not.

**Device output is health-tested before use.** NIST SP 800-90B repetition-count and adaptive-proportion tests run on every read. This is necessary _because_ of the mixing: HKDF turns a constant input into perfectly random-looking output, so without the check a dead device is indistinguishable from a working one and you keep believing you have hardware entropy.

**Generation only.** The vault salt, the Argon2 salt and backup IVs stay on the OS RNG. A salt that depends on a device turns a lost device into a lost vault, and this feature exists to reduce risk, not to add a new way to lose everything.

All four generators report which source produced a value, in the JSON envelope and in `envv describe`, because "the flag was accepted" and "the bytes came from there" are different claims.

PKCS#11 and TPM backends are not built in. Ask for one and you are told that specifically, rather than being told it is an unknown source, because "not compiled in" and "not a thing" are different problems and you deserve to know which.

---

## Key pools

Several interchangeable credentials for one service, rotated when one gets rate limited.

```bash
envv entry set OpenAI-1 --pool openai
envv entry set OpenAI-2 --pool openai
envv pool ls
envv pool next openai
envv pool report openai --limited --for 15m
```

Membership is explicit, via the `pool` field on an entry. Two keys for one provider pooling automatically would turn `envv get GitHub`'s ambiguity refusal into "pick one" everywhere, `entry rm` included.

**The state is not in the vault.** Cursor, cooldowns and use counts live in `pools.json` beside `sessions.json`, mode 0600. `save_vault` appends an audit row per update, so a CI loop would grow the hash chain without bound, and it is a compare-and-swap, so concurrent reads would start returning conflicts. The cursor is therefore per machine, and two runners each start at the first key.

The cursor indexes the **full** member list, not the available subset. Filter first and every index shifts whenever a member goes on or off cooldown, silently changing which key a cursor position means.

Exhaustion is reported, not detected. `envv exec` never sees the child's HTTP responses, so nothing here can notice a 429 on your behalf. You tell it, with `pool report`. When every member is cooling, exit 7, naming the one that frees up first.

The Tools pane reads the same file over IPC rather than reimplementing the format. The app's `app_data_dir` and the CLI's `dirs::data_dir()/io.envvault` resolve to the same directory, and that was verified rather than assumed. If it ever stops being true, the panel silently shows a different vault's cursors.

---

## Backups, and the one thing you cannot recover

Two formats, and they do different jobs. Mixing them up is how people lose vaults.

| Command               | Writes                                          | Restoring needs      |
| --------------------- | ----------------------------------------------- | -------------------- |
| `envv backup export`  | `.vaultbak`: vault contents, re-encrypted       | The backup password  |
| `envv backup archive` | `.vaultarc`: the database file **and its salt** | The archive password |

A `.vaultbak` holds the decrypted vault re-encrypted under a fresh password (PBKDF2-SHA256 into AES-256-GCM), and the desktop app reads the same format. Restoring it generates a new salt and your master password derives against that, so it never needs the original. This is the one to move between machines.

A `.vaultarc` is the answer to losing `vault.salt`. It carries both files plus a manifest holding a SHA-256 of each, so a mispairing is detectable on restore rather than presenting itself as "wrong password" for a correct password.

```bash
envv backup archive vault.vaultarc
envv backup restore-archive vault.vaultarc
```

Restoring refuses to overwrite an existing vault without `--force`, verifies both checksums _before_ writing anything, and writes the salt first. A salt without a database is recoverable, because you restore again. A database without its salt is not.

`restore-archive` deliberately runs without an open vault, since "there is no vault here" is the state it exists for.

Per-entry version history is the third thing in this family: fifty revisions per entry, restorable from the card, written automatically whenever the secret changes.

---

## The server

```bash
envv-server --port 8743
envv-server --port 8743 --tls
envv-server --port 8743 --tls --cert fullchain.pem --key privkey.pem
```

With `--tls` and no certificate given, it generates a self-signed one via `rcgen`, valid three years for `localhost` and `127.0.0.1`, and writes it to the data directory. It prints the SHA-256 fingerprint on startup.

### Self-signed certificates, and the chicken-and-egg problem

Both clients pin. The desktop app compares the SHA-256 of the leaf certificate during the TLS handshake, before any request body is written, so a machine-in-the-middle is rejected before your master password reaches the socket. The CLI does the same thing through the same verifier.

That creates an obvious problem: reaching a self-signed server needs a fingerprint that can only be obtained by reaching it. So both clients have exactly one unauthenticated bootstrap. `probe_cert_fingerprint` in the app, `envv login --tofu` in the CLI. Each performs the handshake and an unauthenticated `GET /api/status`, sends no credentials, and reports the fingerprint so a human can confirm it. Everything after first contact is pinned. It is the same trust decision SSH asks you to make about a host key, and it is confined to the one request where nothing is at stake.

A _changed_ fingerprint is never silently re-pinned. An earlier version overwrote the stored value on every connect, so a pin only held until the first mismatch, which is the one moment it needed to hold.

### API

| Route                        | Method       | Notes                                                   |
| ---------------------------- | ------------ | ------------------------------------------------------- |
| `/api/status`                | GET          | Unauthenticated. Includes `cert_fingerprint`            |
| `/api/unlock`                | POST, DELETE | Owner unlock with the master password                   |
| `/api/auth`                  | POST         | Sub-user login, or an API token exchanged for a session |
| `/api/vault`                 | GET, PUT     | The whole vault, filtered by permission                 |
| `/api/vault/entries`         | GET          | Selective read. Filters, and a batch form               |
| `/api/vault/expiring`        | GET          | Entries expiring within N days                          |
| `/api/audit`                 | GET          | The audit log                                           |
| `/api/users`, `/api/classes` | Various      | User and class management                               |
| `/api/ping`                  | GET          | Authenticated, and slides the idle deadline             |
| `/api/stats`                 | GET          | Four counters, zero while locked                        |

`/api/vault/entries` exists because whole-vault reads are fine for a personal vault and increasingly silly for a large one. A scoped sub-user was downloading a filtered copy of everything to read a single value.

Two properties hold there, and both are easy to lose:

- **Permissions are applied before the filter, never after.** Filtering first and checking later would let a caller learn that an entry exists from the shape of the response.
- **A filter that matches nothing returns an empty list, not a 404.** "No entries in project X" and "no such project X" must look identical from outside, or the endpoint becomes an enumeration oracle for project names.

### Rate limiting

Ten failures per IP per sixty seconds. It counts **failures only**, not requests, and the IP comes from the real socket address rather than the spoofable `X-Forwarded-For`. The map is pruned above a thousand entries, since an unbounded map under IP rotation is a memory leak with a security-shaped excuse.

---

## Open to LAN

The desktop app can serve its own vault to other machines. Remote panel, Start, done. It runs the identical router `envv-server` runs, in-process.

The gate around it matters more than the feature. `lan_start` opens _this machine's_ `vault.db` from Rust's `VaultState`, and connecting to a remote does not lock the local vault. The LAN card lives inside the remote workspace, so pressing it while connected to a remote published the local vault under the remote's UI. It is now unavailable whenever the current store is remote, refused independently inside `startLan()` rather than only hidden, and repainted on both directions of a vault switch. A server that is already running stays visible and stoppable regardless.

`display: none` is a paint-time gate on a delegated click handler. When the consequence is publishing the wrong vault, the refusal belongs at the write as well.

The server closes itself after eight idle hours. Auto-lock is suspended while it runs, because locking the vault out from under your own clients is not security either.

---

## Concurrent writes

Every write is a compare-and-swap. The client sends the version it last read, and the server refuses the write if the stored vault has moved on.

Without that, the desktop wrote the whole blob unconditionally, so while "Open to LAN" was running, a peer's edit landing between your load and your next save was silently overwritten. You would never know. The record simply stopped existing.

The version token is the stored `data_hash` rather than a re-hash of the parsed JSON. Re-serialising a `Value` happens to reproduce the stored bytes today, and relying on that would make every request conflict the moment it stopped being true.

Data and hash are written inside one `BEGIN IMMEDIATE` transaction. Two separate statements meant a crash between them left the two disagreeing.

---

## Docker

```bash
docker run -d -p 8743:8743 \
  -v envv-data:/data \
  -e ENVV_PASSWORD=... \
  ghcr.io/darthdemono/envvault-server:latest
```

Idle RSS is 1.32 MiB on a four-core host, and 1.36 MiB after an Argon2id unlock. It was 3.99 MiB before Phase 15, and the difference is worth explaining because none of it was application code.

- tokio ran one worker per CPU. Now two, tunable with `ENVV_WORKER_THREADS`, with 1 MB stacks.
- `MALLOC_ARENA_MAX=2`. glibc gives each thread up to eight arenas per core, and each reserves a 64 MB heap it never fully returns. The saving scales with the host's core count, which is why this looked fine on a laptop and awful on a build server.
- `MALLOC_TRIM_THRESHOLD_` so the 64 MB Argon2id buffer returns to the OS at once instead of staying resident for the life of the process.

Compose sets `mem_limit: 256m`, which is two concurrent Argon2id unlocks without the OOM killer turning a login into a restart, plus `shm_size: 16m`.

The healthcheck opens the port rather than running `--version`, because a wedged process still answers `--version` perfectly happily. That is still not a real liveness check, and a proper `/api/health` is on the list below.

---

## Multiple users

The owner is the person who knows the master password. Ownership is proven by deriving the SQLCipher key, so there is no hash to federate and never will be.

Everyone else is a sub-user with their own Argon2id password, their own API tokens, and permissions that decide what they can see and change.

```bash
envv user add deploy
envv user token new deploy --expires 30d --out token.txt
envv perm set user deploy --read "project:web" --write "project:web AND env:staging"
envv class add Deployers
envv user class deploy Deployers
```

Classes are named permission templates. A class expression and an individual expression are ANDed, so a class restriction cannot be undone by an individual grant. That AND is also why an absent expression means "no grant" rather than "no restriction": treating absence as true would give a user with no permissions at all `true AND true`, and therefore everything.

Capability flags (`cap_manage_users`, `cap_manage_classes`, `cap_delete_projects`) and an authority tier stop a user granting themselves more than they hold.

---

## Permission expressions

```
project:web
project:web AND env:production
category:infra OR tag:shared
NOT tag:personal
(project:web OR project:api) AND NOT env:production
```

Fields: `project`, `category`, `tag`, `env`, `provider`, `type`. Values glob. There is a live editor in the Users panel that parses as you type, and `envv perm check` parses an expression without storing it.

An unparseable expression denies everything at evaluation time, so saving one would lock a user out silently. `set_permission_expr` parses first and refuses to store what it cannot read.

### Strict write scoping

By default a write satisfies **any** of the subject's scopes, which is how scope joining has always worked and which makes read and write nearly the same privilege for a scoped user.

```bash
envv user strict-write deploy
envv perm show user deploy
```

Under strict mode an entry must satisfy **every** scope before it can be changed. `project:web OR project:api` becomes `project:web AND project:api` at evaluation time.

Three details:

- **Reads are untouched.** Narrowing them too would make the user's own vault appear empty the moment the flag went on, and someone who cannot see an entry cannot review the change they are making.
- **Explicit grouping is left alone.** `(a OR b) AND c` is a rule someone stated precisely. Strictness is about the implicit OR that scope joining introduced, not about second-guessing logic that was already written down.
- **A class can impose it and its members cannot shed it.** If either the user or their class is strict, the user is strict.

It is off by default, and existing users are untouched by the migration. A release that silently tightened permissions would break running deployments in a way nobody could attribute to the upgrade.

`envv perm show` prints the effective expression as well as the stored one, because an operator who has just enabled strict mode and sees an unchanged rule will reasonably conclude the flag did nothing.

---

## The security model

What it protects against: someone with your disk. The database is encrypted at rest, the key is derived from a password that is never stored, and it is zeroed on lock.

What it does not protect against: someone with root on a running machine while the vault is unlocked. The key is in memory, and that is unavoidable for a program that has to decrypt things.

Some specifics that are worth stating plainly.

**The key is zeroed when you switch contexts.** Connecting to a remote used to leave the local vault's key resident for the whole session, with nothing on screen to say so. A locked-looking app whose key was still in memory. It now locks the local vault on switch, which does mean switching back costs a master password. `Settings → Keep the local vault unlocked` restores the old behaviour, off by default, because the safe behaviour should be the default and the convenience is the thing you opt into.

**Files are owner-only.** The database, the salt, `sessions.json` and `pools.json` are all 0600 on Unix, WAL sidecars included. On Windows there is no equivalent and files inherit the directory ACL. `envv doctor` reports that as "not enforceable" rather than passing, because a check that always passes proves nothing.

**The audit log is a hash chain.** Each row hashes its own contents plus the previous row's hash. Editing or deleting a row breaks the chain, and `envv audit --verify` or the Verify button will say where. Two formats coexist, since rows written before actor tracking verify against the older formula.

Reads are deliberately not audited. Every `GET /api/vault` used to write a row, so a polling client grew the table without bound, and pruning it would break the very chain that makes the log tamper-evident. Mutations carry the actor instead, which is bounded by how often the vault actually changes.

**Vault data is untrusted input.** It arrives as JSON from SQLCipher, from a server somebody else runs, or from an imported backup. TypeScript union types are erased at runtime, so every field is escaped before rendering, including ones typed as unions. Only `http:` and `https:` URLs become clickable links, because a `javascript:` URL in an `api_url` field was a real stored-XSS vector.

### Things deliberately removed

- **TOTP.** It existed with anti-replay and was removed in Phase 7 because nothing ever reached it. If it returns it belongs on sub-user login only. The owner authenticates by deriving the key, so there is nothing for a second factor to gate.
- **A global paste hotkey.** `Ctrl+Shift+V` intercepted the system paste shortcut and caused a lock. Gone.
- **Reset from the unlock screen.** A button that destroys the vault should not sit on the screen you see before you have proven you own it.

### Closed oracles

- `/api/vault` returned `200` with `{"api_keys": []}` when no data existed. It returns 404 now, since the first response told an unauthenticated caller the vault existed and was empty.
- `merge_user_vault_write` keyed entries on `provider|account_name` and dropped `key_id`, so two keys from one provider collided and a scoped user could overwrite or delete an entry in a project they had no access to.
- `revoke_token` authorized against the `user_id` in the path while deleting by `token_id`, so a low-privilege user could pass their own path and revoke a higher user's token.
- `verify_totp_code` returned `Ok(true)` when the secret was NULL. It failed open. That is now closed, and the function is gone with the rest of TOTP.
- `/api/vault/expiring` returned full secrets to non-owners.
- `filter_vault_for_user` leaked the complete category taxonomy to users who could see none of it.

### Correctness bugs that were security bugs

Not everything on this list looks like a vulnerability at first glance.

- Comparing legacy SHA-256 password hashes with `==` was a timing attack. It is an XOR fold now.
- Bulk delete used array indices to identify entries. Splicing the array between capturing an index and using it retargets the operation onto a neighbour, so it destroyed the wrong secrets. Everything is id-keyed now, which is the single most repeated lesson in this codebase.
- The four exporters people actually deploy ignored `disabled`, so a WireGuard peer you had disabled still went into `wg0.conf` and the tunnel kept trusting it.
- Six of the newer exporters never resolved `${refs}`, so a `.pgpass` shipped the literal text `${DB/password}` as the password.
- The rate limiter counted every request rather than every failure, so ordinary use locked you out.
- Opening a vault whose salt had gone missing generated a fresh one, which reported "wrong password" forever and destroyed the evidence that anything else had happened.

---

## Where your files live

On Linux:

|              | Path                                                                          |
| ------------ | ----------------------------------------------------------------------------- |
| Database     | `~/.local/share/io.envvault/vault.db`                                         |
| Salt         | `~/.local/share/io.envvault/vault.salt`                                       |
| Settings     | `~/.config/io.envvault/settings.json`, plain JSON, deliberately not encrypted |
| CLI sessions | `$XDG_STATE_HOME/envv/sessions.json`, mode 0600                               |
| Pool state   | Beside the sessions file, mode 0600                                           |

On Windows the CLI keeps sessions in `%LOCALAPPDATA%` rather than the roaming profile, since a cached session token should not follow you onto another machine.

> **If you used this when it was called API Vault:** the identifier changed from `io.apivault` to `io.envvault`. Move the directories before launching the renamed build, or it will greet you as a first-time user and offer to create an empty vault.
>
> ```bash
> mv ~/.local/share/io.apivault ~/.local/share/io.envvault
> mv ~/.config/io.apivault      ~/.config/io.envvault
> ```

---

## Building from source

```bash
# Fedora / Nobara
sudo dnf install webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel \
                 librsvg2-devel patchelf sqlcipher-devel mold

# Debian / Ubuntu
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
                 librsvg2-dev patchelf libsqlcipher-dev mold
```

```bash
npm install
npm run dev          # Vite only, for UI work
cargo tauri dev      # the full window
npm run build        # vite build plus tauri build
```

Two environment variables need to be in your shell profile, not just exported in one terminal:

```bash
export APPIMAGE_EXTRACT_AND_RUN=1
export NO_STRIP=1
```

The first is because GitHub runners and most containers have no FUSE for the AppImage tooling to mount with. The second works around linuxdeploy shipping a `strip` too old for `.relr.dyn` sections on Fedora 43.

Unix links the system SQLCipher by default, because it builds in seconds instead of minutes and that matters far more during development than portability does. Pass `--features vault-core/bundled` to compile SQLCipher and OpenSSL in, which is what release builds do. An AppImage linked against Fedora's `libsqlcipher0` will not start on a Debian box shipping a different soname, and "works on my distro" is the entire problem a portable bundle exists to solve. Windows always vendors, since it packages no system SQLCipher at all.

### Linux display flags

`configure_linux_webkit()` sets display variables as **defaults, not overrides**. `GDK_BACKEND=x11` is set only when the session is not Wayland, since forcing XWayland breaks fractional scaling and fails outright where XWayland is absent. Anything already in your environment wins, so `WEBKIT_DISABLE_COMPOSITING_MODE=0` is a real escape hatch. The compositing and DMABUF flags stay on, because they fix blank windows on Nvidia and older Mesa.

### Checks

```bash
npm run check           # version, format, lint, typecheck, test
npm test                # vitest, once
npm run test:coverage   # with v8 coverage
npm run typecheck       # tsc --noEmit, covers src/ and tests/
npm run lint            # ESLint, type-aware
npm run format:check    # Prettier, what CI runs
npm run lint:rust       # clippy over the workspace
npm run format:rust     # cargo fmt
cargo test --workspace
```

---

## Development

### Linting and formatting

ESLint 10 flat config, type-aware through an explicit `project: ['./tsconfig.json']`. Prettier. `rustfmt.toml`. clippy levels in `[workspace.lints.clippy]`.

Three exclusions are load-bearing, and none of them are laziness.

- **`index.html`** is in `.prettierignore`. A formatter has already silently deleted an element from it once (`#new-category-form`, Phase 3), and the app queries ids that no tool can prove are still present.
- **`tests/fixtures/`** is excluded. Those files _are_ the assertion. Reformatting one makes both parity suites fail against a file that no longer describes any real config format.
- **`docs/`, `site/`, `eslint-suppressions.json`** are generated.

Two ESLint rules are off, with the evidence in the config. `no-unnecessary-type-assertion` and `non-nullable-type-assertion-style` misread the generic DOM helpers: the checker infers the type parameter from the assertion's own context, so every `as HTMLSelectElement` looks redundant. Running `--fix` removed about 170 of them and produced 130-plus TS2339 errors in a tree that had just typechecked clean. A lint rule whose autofix does not typecheck is worse than no rule.

### The lint backlog

237 violations are suppressed in `eslint-suppressions.json`, not fixed. That makes `npm run lint` pass today and fail on anything new. Shrink it with:

```bash
npx eslint --prune-suppressions
```

Never regenerate it with `--suppress-all`. That absorbs real regressions along with the old debt, which defeats the entire point of keeping the file.

### Versioning

The version lives in six files plus `Cargo.lock`.

```bash
npm run version           # print
npm run version 0.7.2     # set
npm run version -- minor  # bump
npm run version:check     # what CI runs
```

`Cargo.lock` is patched textually rather than regenerated, because regenerating needs the registry and the script would then fail offline.

It does not commit, tag or push. Pushing the bump is what cuts the release.

### API documentation

```bash
npm run docs        # Doxygen over src/ts/
npm run docs:rust   # cargo doc over the four crates
```

Two tools because there is no one tool. Doxygen has no Rust front end and rustdoc has no TypeScript one.

**N.B.** Do not put an outer `///` doc on a `pub mod` line when the module file already has `//!` docs. rustdoc merges the two and resolves the combined text in the _parent's_ scope, so every intra-doc link written inside the module fails with "no item named ... in scope", and `-D warnings` turns that into a failed docs build.

---

## Continuous integration

### `ci.yml`, the gate on every push and pull request

A `[ubuntu-latest, windows-latest]` matrix with `fail-fast: false`, because a Windows-only break must not hide behind a green Linux run. It runs version:check, Prettier, ESLint, `tsc --noEmit`, the Vitest suite, `vite build`, `cargo fmt --check`, clippy and `cargo test --workspace`.

### `build.yml`, release when and only when the version goes up

It triggers on a push to `main` and asks one question: does a tag `v<version>` already exist? A README fix stops after the ten-second `meta` job. A version bump builds, signs, publishes and creates the tag.

That check is the only guard, deliberately. Re-runs, empty commits and no-op merges all resolve to the same answer. A `paths-ignore` filter was rejected, since it skips a commit that bumps the version _and_ edits the README.

It also builds a GHCR image for `envv-server`.

**N.B.** Windows vendors OpenSSL, whose `Configure` is a Perl program needing `Locale::Maketext::Simple`. Git for Windows' MSYS perl does not have it. PATH ordering does not settle this, because `shell: bash` is Git bash and its msys runtime injects its own `/usr/bin` during PATH conversion. Both workflows set `OPENSSL_SRC_PERL` outright, which `openssl-src` reads before falling back to PATH.

### `docs.yml`, API references to GitHub Pages

Doxygen at `/ts`, `cargo doc` at `/rust`. Pages has to be enabled by hand (Settings, Pages, Source: GitHub Actions) or `deploy-pages` fails.

### `exporters.yml`, proving the config is real

One job per tool. It regenerates the golden fixtures, fails if they were stale, then feeds each one to the software it targets: k3s, OpenSSH, Traefik, httpd, haproxy, ansible-playbook and a live Postgres.

Every job carries a control case. If the validator accepts deliberate nonsense, the job fails. A validator that accepts anything produces a green tick that means nothing, and a green tick that means nothing is worse than no check, because it converts "unknown" into "fine".

---

## What is not finished

Every project has a list like this. Most do not publish it.

- **There is no structured logging.** No `tracing` anywhere in the workspace. A failure in somebody else's deployment currently leaves `println!` output, and everything else in this section depends on fixing that first.
- **There is no real `/api/health`.** `/api/status` and `/api/stats` exist, and the Docker healthcheck only opens the port, so a wedged process passes it.
- **The rate limiter sends no `Retry-After`,** and errors carry no request id. A script that cannot tell "slow down" from "denied" has to guess, and this CLI is built for callers that should not have to.
- **`envv` collides with an unrelated product of the same name** at envvault.dev, which has an incompatible command tree. Whoever installs both gets whichever `PATH` finds first. This has to be decided before 1.0, because afterwards it is a breaking change.
- **The audit table has no index and is read whole.** It is fine now. It will not be fine forever. Retention is a harder problem than it looks: pruning rows breaks the chain that makes the log tamper-evident, so any scheme needs a checkpoint record attesting to the pruned prefix.
- **237 lint violations are suppressed**, and somebody has to decide whether they ship in a 1.0.
- **Parts of `render.ts` and `tools.ts` are untested**, specifically the config-view click handlers and the generator and calculator panes.
- **SVG is refused as a custom icon.** Permanently and on purpose, listed here only so nobody files it as a bug. It is a script container and a vault is untrusted input.

---

## How it got here

The sections above describe the current state. This is the order it arrived in, for anyone reading the git history.

| Phase | Delivered                                                                                                                              |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | Tauri wrapper, static frontend                                                                                                         |
| 2     | SQLCipher and Argon2id encrypted storage, unlock flow                                                                                  |
| 3     | TypeScript and Vite, inline-handler elimination, structured project types, audit table, version history                                |
| 4     | Remote vault server and the first CLI                                                                                                  |
| 5     | Multi-user RBAC, user classes, remote panel, health dashboard                                                                          |
| 5.1   | Security hardening: Argon2id for sub-users, failure-only rate limiting, restricted CORS                                                |
| 6     | TLS on the server, certificate pinning, tag sidebar filter, YAML formatter, re-lock overlay                                            |
| 7     | Correctness pass: stable entry ids, audit log viewer, offline fonts, session expiry, tests and CI                                      |
| 8     | Owner as a real user row, audit attribution, permission scoping, enumeration oracle closed                                             |
| 9     | Permission expression language with AND, OR and NOT, plus a live editor                                                                |
| 10    | Open to LAN, hosting the vault from the desktop app                                                                                    |
| 10.1  | Lost-update fix: compare-and-swap on every vault write                                                                                 |
| 11    | Frontend test suite and a module-by-module audit. 66 bugs fixed                                                                        |
| 12    | UX persistence, window state, the LAN wrong-vault gate, experimental project types                                                     |
| 13    | CLI parity, exporter golden fixtures, which found the disabled-chunk and nginx `${ref}` export bugs                                    |
| 14    | The agent-safe CLI: redaction, JSON envelope, exit codes, `describe`                                                                   |
| 15    | Custom icons, live enrichment, Windows and cross-distro portability, Docker memory                                                     |
| 16    | ESLint, Prettier and clippy, auto-versioning, release and docs CI, key pools, structured rate limits                                   |
| 17    | CLI certificate pinning on a shared verifier, entropy sources, context zeroize, `backup archive`, strict write scoping                 |
| 18    | `envv doctor`, vendor importers, selective reads, chunk test coverage, and all eleven project types graduated on live-service evidence |

---

## License

MIT. See [LICENSE](LICENSE).
