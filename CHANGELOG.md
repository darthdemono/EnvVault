# Changelog

Release history for EnvVault. Entries below Phase 12 were written as they
landed and are preserved verbatim from the README, where they had been
appended over several phases. Phases 12 through 15 are summarised at the top
from the session records.

The version in `src-tauri/tauri.conf.json` is the authoritative one. Every
other copy — `package.json`, the four `Cargo.toml` files, the git tag — is
checked against it by the `meta` job in `.github/workflows/build.yml`.

---

## 0.6.0 — Phases 12 through 15

**Phase 15 — custom icons, live enrichment, portability.** Entries can carry an
uploaded icon file (PNG/JPEG/GIF/WebP/BMP/ICO, 96 KB encoded, typed by magic
bytes rather than by extension). SVG is refused, because it is script-bearing.
`envv enrich` fills the metadata an imported `.env` never has, inferring from
entry names and public issuer prefixes (`ghp_`, `sk-ant-`, `AKIA`, `sk_live_`,
and about forty more); `--online` asks each issuer about its own credential and
fills the account, scopes, expiry and rate limit from the real answer. A 401
from the issuer is the only reliable way to learn a stored credential was
revoked. Projects can pin a custom slug that survives renaming. Windows now
vendors SQLCipher and OpenSSL, Linux display flags became defaults rather than
overrides, and the server's idle memory went from 3.99 MiB to 1.32 MiB.

**Phase 14 — the agent-safe CLI.** Every stdout path redacts stored values to
`sha256:<12 hex>` by default; `--reveal` opts back in. Fingerprints are stable
per value, so equal fingerprints mean equal secrets and drift is detectable
without reading anything. Real values move through `--out FILE`, `envv exec` and
`envv render` instead. A vault-wide `export` to stdout is refused with exit 9
rather than masked, because a masked `.env` looks deployable and is not. Added
the `{"ok":…}` JSON envelope, eleven stable exit codes, `envv describe`, and
`envv login` session caching.

**Phase 13 — CLI parity.** `envv-cli` became a library plus a thin binary, and
gained `entry`, `project`, `category`, `tags`, `gen`, `backup`, `scan`,
`status`, `user`, `class` and `perm`. The config exporters now exist twice — once
in TypeScript for the app, once in Rust for the CLI — and both assert against the
same golden files in `tests/fixtures/parity/`. Writing that fixture immediately
found two live bugs in the app: disabled chunks were still being exported (a
disabled WireGuard peer stayed in `wg0.conf`, so the tunnel kept trusting a peer
the user believed they had removed), and the nginx exporter never resolved
`${…}` references.

**Phase 12 — persistence and the LAN gate.** Sidebar width, sort order, recent
searches and the last view survive a restart, with every persisted id validated
on read. "Open to LAN" is now blocked while connected to a remote vault: the
button published *this machine's* vault under the remote's UI. Seven of the
eleven project types moved behind an experimental flag, since only four are
tested end to end.

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
