/**
 * @file
 * Data models for EnvVault.
 * @description Defines the structure of vault entries, projects, and application settings
 *              shared between the TypeScript frontend and the persisted JSON format.
 *              These types mirror the JSON blob stored in the SQLCipher `vault` table.
 */

/**
 * Discriminated union of all supported secret kinds.
 *
 * The active variant controls which form fields are shown and which card
 * labels are used.  `api_key` is the default for legacy entries.
 *
 * - `api_key`           – Standard API key or bearer token.
 * - `password`          – Service login password.
 * - `certificate`       – PEM-encoded TLS/SSL certificate.
 * - `env_var`           – Shell environment variable (name + value pair).
 * - `connection_string` – Database or service connection URI.
 * - `ssh_key`           – SSH private key or host fingerprint.
 * - `file_blob`         – Reference path to an on-disk credential file.
 */
export type SecretType =
  | 'api_key'
  | 'password'
  | 'certificate'
  | 'env_var'
  | 'connection_string'
  | 'ssh_key'
  | 'file_blob'
  /**
   * A browser session (Phase 23, step 5).
   *
   * `api_key` holds the cookie string, `api_url` the origin it belongs to,
   * `expires_at` the session expiry and `extra_vars` the individual cookies when
   * the jar is split. `user_agent` is not optional metadata: replay without the
   * matching one usually 401s.
   */
  | 'cookie'
  /**
   * One value with secrets inside it (Phase 24.1).
   *
   * `composite_template` is the shape, with `{name}` holes; each named part is
   * an ordinary `extra_vars` entry (a part IS an extra_var — see
   * `src/ts/composite.ts` for why a second array was rejected). `api_key` is
   * unused for this type; the rendered template is what Copy copies.
   */
  | 'composite'
  /**
   * A bundle — one card holding several whole member entries plus its own
   * local variables (Phase 24.1). Members point back at the bundle via
   * `bundle_id`; the bundle entry itself never lists them, the same shape as
   * `pool`. `extra_vars` holds the bundle's own local variables.
   */
  | 'bundle'
  /**
   * Phase 24.5's sixteen new types. Each is a **descriptor entry** in
   * `secret-types.json` (`src/ts/secret-types.ts`) plus this union member —
   * shape now, per-type form fields and card bodies later, the same call
   * `composite`/`bundle` made in 24.1. Storage for all sixteen is named
   * `extra_vars`, never new top-level `VaultEntry` fields: sixteen types ×
   * ~5 fields each would be ~80 columns for Phase 25 to migrate, and named
   * variables already have masking (E5), history (E8), env names and
   * `${X/NAME}` references for free.
   */
  | 'oauth_client'
  | 'signing_key'
  | 'registry_token'
  | 'database'
  | 'recovery_codes'
  | 'gpg_key'
  | 'age_key'
  | 'local_service'
  | 'tracker'
  | 'usenet_server'
  | 'wifi'
  | 'license_key'
  | 'crypto_wallet'
  | 'passkey'
  | 'secure_note'
  | 'identity_document';

/**
 * The editor/validator/preview an `extra_vars` value gets (Phase 24.1).
 *
 * Never a storage change — see the field doc on `extra_vars[].kind`. Core,
 * colour, template and large-id/bitfield groups landed in 24.1 (the Discord
 * acceptance fixture needs them); the dev-format group is deferred to 24.5,
 * where it lands beside the secret-type registry the descriptors belong to.
 */
export type ValueKind =
  | 'string'
  | 'multiline'
  | 'secret'
  | 'int'
  | 'float'
  | 'hex_int'
  | 'bool'
  | 'url'
  | 'markdown_link'
  | 'email'
  | 'path'
  | 'port'
  | 'ip'
  | 'cidr'
  | 'date'
  | 'datetime'
  | 'duration'
  | 'json'
  | 'list'
  | 'enum'
  | 'colour'
  | 'template'
  | 'large_id'
  | 'bitfield'
  /** The dev-format group (Phase 24.5), landing beside the secret-type
   * registry these editors belong to. */
  | 'regex'
  | 'cron'
  | 'semver'
  | 'timezone'
  | 'locale'
  | 'byte_size'
  | 'percentage';

/**
 * A single stored secret entry.
 *
 * `api_key` holds the primary secret value regardless of `secretType`.
 * Fields irrelevant to a given type are `null` / `undefined` and hidden in the UI.
 * Every entry always belongs to at least the "Universal" category (`projectIds`).
 */
/**
 * The window a {@link VaultEntry.rate_limit_count} applies to.
 *
 * `second` and `minute` are here even though most published limits are hourly
 * or daily, because the ones that bite in practice are per-second burst caps —
 * and because the free-text values already in vaults are overwhelmingly
 * `"n/min"`, which has to survive migration as something.
 */
export type RateLimitPeriod = 'second' | 'minute' | 'hour' | 'day' | 'week' | 'month' | 'year';

export interface VaultEntry {
  /**
   * Stable unique identifier, assigned once on creation and never mutated.
   *
   * This is the entry's identity for every purpose that must survive edits and
   * array reordering: `version_history` attribution, audit rows, RBAC write
   * scoping, and UI expand/reveal state. Optional only so vaults written before
   * this field existed still parse — `finishInit()` backfills a UUID into every
   * entry lacking one, and everything written afterwards always has it.
   */
  id?: string;
  /** Service or provider name (e.g. `"GitHub"`, `"DATABASE_URL"`). Always required. */
  provider: string;
  /** Optional sub-account identifier within the same provider. */
  account_name?: string;
  /** Primary secret value (API key, password, variable value, etc.). */
  api_key: string;
  /** Secondary secret (client secret, shared secret). Used by `api_key` type only. */
  api_secret?: string | null;
  /** Optional key identifier for disambiguation when one provider has multiple keys. */
  key_id?: string | null;
  /** Short human-readable description of what the key is used for. */
  api_description?: string | null;
  /** Longer free-text notes. */
  description?: string | null;
  /** Billing model for the associated service. */
  price_type: 'free' | 'local' | 'paid' | 'conditional';
  /** Deployment context this credential belongs to. */
  environment?: 'production' | 'staging' | 'development' | 'testing' | null;
  /**
   * Category tags this entry carries. Backed by `VaultData.user_categories`,
   * shown in the sidebar's "Categories" section, and matched by RBAC
   * `scope_type: "category"`.
   *
   * (An earlier comment here claimed these were labelled "Projects" in the UI.
   * They are not — the data names, the sidebar headings and the RBAC scope
   * names all agree. Only the DOM element ids were crossed, and those have
   * since been renamed.)
   */
  categories: string[];
  /** Base URL of the service's API. */
  api_url?: string | null;
  /** OAuth or webhook callback URL. */
  callback_url?: string | null;
  /** ISO-8601 expiry date string, or `null` if the credential does not expire. */
  expires_at?: string | null;
  /** OAuth scopes or permission strings granted to this credential. */
  scopes: string[];
  /**
   * Human-readable rate-limit description (e.g. `"100 req/min"`).
   *
   * **Legacy, and kept deliberately.** The structured pair below
   * (`rate_limit_count` + `rate_limit_period`) is what the UI and the health
   * scan read. This string is still written on save, rendered from the pair
   * when the pair is set, so a vault edited by a current build stays readable
   * to an older one — and so an entry whose limit was never expressible as
   * `<n> per <period>` ("varies by endpoint") keeps the text the user wrote.
   *
   * Never parse this field directly. `parseRateLimit()` in `utils.ts` is the
   * one reader, and `envv-cli/src/ratelimit.rs` is its twin.
   */
  rate_limit?: string | null;
  /**
   * The rate limit as a number, paired with {@link rate_limit_period}.
   *
   * `null` means "not known", which is not the same as `0` — a limit of zero
   * would mean the credential is useless, and some services really do issue
   * suspended keys. Both halves must be set for the limit to be considered
   * structured; a count without a period is meaningless and is dropped on read.
   */
  rate_limit_count?: number | null;
  /** The window {@link rate_limit_count} applies to. */
  rate_limit_period?: RateLimitPeriod | null;
  /**
   * Whatever the old free-text `rate_limit` said when it could not be parsed
   * into a count and a period ("varies by endpoint", "see contract").
   *
   * Kept rather than discarded: the text was written by a human who knew
   * something the schema does not express, and silently dropping it on the
   * first save under a new version is data loss the user never asked for.
   */
  rate_limit_note?: string | null;
  /**
   * What this credential was requested for — the justification submitted to the
   * issuer on the application form.
   *
   * Distinct from `api_description` (what it is) and `details` (notes to self).
   * This is the sentence you will be held to if the issuer asks why you have
   * the key, and it is worth recording at the moment you write it, because six
   * months later nobody remembers.
   */
  purpose?: string | null;
  /**
   * Name of the key pool this entry belongs to, or `null` for a standalone key.
   *
   * Several entries sharing a pool name are interchangeable credentials for the
   * same service, held so that a caller can swap between them when one is rate
   * limited. Membership is **explicit**: two keys for the same provider do not
   * pool automatically, because `envv get GitHub` refusing an ambiguous match
   * is the behaviour that stops a command from silently acting on a credential
   * the caller did not mean (see the invariants in CLAUDE.md).
   *
   * Swap state — cursor, cooldowns, use counts — is deliberately NOT stored
   * here. It lives in a per-machine sidecar; see `envv-cli/src/pool.rs`.
   */
  pool?: string | null;
  /** API or SDK version this key was issued for. */
  version?: string | null;
  /**
   * What the primary value **is**, for naming purposes — the `ROLE` segment of
   * the generated environment-variable name.
   *
   * Absent keeps the bare name. Every `.env` already deployed from this app
   * names the primary value `PROVIDER=`, so defaulting this to `'key'` would
   * rename that variable for every existing entry on the next copy, and the user
   * would find out when a service came back up without its credentials.
   *
   * The vocabulary is **open**, not a closed union past the six presets:
   * issuers invent names (`app_id`, `merchant_id`, `tenant`), and a closed union
   * means the escape hatch is `extra_vars` — which is the fragmentation Phase 23
   * exists to remove.
   */
  primary_role?: 'key' | 'id' | 'token' | 'secret' | 'password' | 'value' | (string & {}) | null;
  /** Role of `api_secret`, when the default `SECRET` is wrong. */
  secret_role?: string | null;
  /**
   * The primary value is safe to print — an OAuth client id, a Stripe `pk_`, an
   * AWS access key id. Opts `api_key` out of redaction everywhere (E5).
   */
  primary_public?: boolean;
  /** The same, for `api_secret`. Rare, but an issuer's "secret" is sometimes public. */
  secret_public?: boolean;
  /**
   * **How** this credential is sent (Phase 23, E16).
   *
   * *How to send it* is part of the credential and was nowhere in the model: two
   * entries that look identical are used completely differently, and the user
   * had to remember which service wants `X-Api-Key`, which wants
   * `Authorization: Bearer`, and which wants it in the query string.
   *
   * This is what turns a stored string into a working request, and it is what
   * the curl and cookie exports need anyway.
   */
  auth_scheme?: 'bearer' | 'header' | 'basic' | 'query' | 'cookie' | null;
  /**
   * The header or query-parameter name `auth_scheme` puts the value in.
   *
   * Meaningless for `bearer` (the header is fixed) and for `basic` (the value is
   * the password half). Defaults to `X-Api-Key` for `header` and `api_key` for
   * `query`.
   */
  auth_param?: string | null;
  /**
   * The User-Agent this credential was minted against (Phase 23, step 5).
   *
   * A session cookie replayed without the matching User-Agent usually 401s, so
   * this is not optional metadata — it is half of the credential.
   *
   * It is also a **fingerprint**, so it never appears in `basic` metadata
   * comments or anywhere the redacting resolver writes.
   */
  user_agent?: string | null;
  /**
   * When the user last confirmed this session still works (Phase 23, E13).
   *
   * Rotation is meaningless for a session credential — "rotate" means "log in
   * again in a browser", which this app cannot do — so a cookie flagged
   * never-rotated and overdue forever is a nag with no available fix, and a nag
   * with no available fix trains people to ignore the health scan, which costs
   * more than it gains. This is the check that *is* actionable instead.
   */
  last_verified_at?: string | null;
  /**
   * Storage tokens (`localStorage`/`sessionStorage`) a web session needs
   * alongside its cookies (Phase 24.5). `cookie` generalises from "a cookie
   * jar" to "a web session" without a field rename — every Phase 23 vault
   * still uses the `cookie` id, only the label reads "Web session" now.
   *
   * Never in `basic` metadata or a redacting resolver's output — a storage
   * token is exactly as much a live credential as the cookies beside it.
   */
  storage_tokens?: { origin: string; storage: 'local' | 'session'; key: string; value: string }[];
  /**
   * How a derived header is built for this session — the *arr family's
   * `X-Api-Key`, YouTube's `SAPISIDHASH`, LinkedIn's csrf header copied off a
   * cookie. `source: 'derived'` headers are computed **at copy time**, so a
   * copied header is only good briefly; the UI that renders one says so.
   */
  header_recipe?: {
    name: string;
    source: 'static' | 'cookie' | 'derived';
    static_value?: string;
    cookie_name?: string;
    strip_quotes?: boolean;
    derived_id?: string;
  }[];
  /**
   * API-key taxonomy — orthogonal axes (Phase 24.5), auto-filled from issuer
   * prefixes by `enrich` (gaps only, per the existing rule) and never
   * enforced: `exposure: 'publishable'` *suggests* `primary_public`, never
   * sets it, so a misdetected prefix cannot make redaction print less.
   */
  acts_as?: 'anonymous' | 'user' | 'service' | 'bot' | 'installation' | 'admin' | null;
  reach?: (
    'public_data' | 'own_account' | 'organisation' | 'local_network' | 'billing' | 'infrastructure'
  )[];
  exposure?: 'publishable' | 'server_only' | 'verify_only' | null;
  issuer_kind?: 'saas' | 'self_hosted' | 'local' | null;
  access?: 'read' | 'write' | 'admin' | 'custom' | null;
  /** Where to revoke or rotate this credential. */
  console_url?: string | null;
  ip_allowlist?: string[];
  /**
   * The generated variable name this entry was last copied or exported under
   * (Phase 23, step 6).
   *
   * The only new *persisted* state this phase adds, and it exists for one
   * finding: renaming a provider, version or label silently renames every
   * variable the entry generates, and the `.env` already sitting on a server
   * keeps the old name. That is the `renameProviderRefs()` problem with a wider
   * blast radius, because the stale reference is not in the vault at all — it is
   * in a file on a machine nobody is looking at.
   *
   * Non-secret: a variable name is not a credential.
   */
  last_copied_name?: string | null;
  /**
   * The **contents** of a file-shaped credential (Phase 23, E17).
   *
   * A GCP service-account JSON, an Apple `.p8`, an mTLS bundle and a `kubeconfig`
   * are consumed by *pointing at them*:
   * `GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/sa.json`. Copying the contents to a
   * clipboard produces something no consumer wants, and pasting a 2 KB JSON blob
   * into a `.env` produces a variable the library tries to open as a path.
   *
   * `blob_ref` holds only a path, so a fresh machine has the reference and not
   * the credential; `certificate_data` holds the PEM but has nowhere to write it.
   * This is the storage half, and {@link mount_path} is the delivery half.
   *
   * Capped — see `BLOB_MAX_BYTES`. A service-account JSON is ~2.3 KB and an
   * embedded icon is already allowed 96 KB, so storing content is fine; a
   * `kubeconfig` with several clusters or a full chain bundle is not the same
   * promise, and silently storing a truncated credential is worse than refusing.
   */
  blob_data?: string | null;
  /**
   * Where the consumer expects to find this credential on disk (E17).
   *
   * The delivery half of a file-shaped entry: `envv file write` materialises to
   * it, `${Entry/path}` renders it, and `envv exec` writes a temp file and
   * removes it afterwards. Non-secret — it is a path, not a credential.
   */
  mount_path?: string | null;
  /**
   * The shape of a `composite` entry's rendered value, holes and all —
   * `https://.../{mailbox_id}@.../{calendar_key}/calendar.ics`.
   *
   * Printed, not masked (it is the holes, not the values) — it must still be
   * added to `PUBLIC_FIELDS` deliberately, since fail-closed redaction would
   * otherwise mask it. See `src/ts/composite.ts` for rendering.
   */
  composite_template?: string | null;
  /**
   * What kind of thing a `composite` template is, which decides its encoding
   * and whether Open is offered. Open past the four presets — the same
   * open-vocabulary reasoning as {@link primary_role}.
   */
  composite_kind?: 'link' | 'signed_link' | 'connection' | 'custom' | (string & {}) | null;
  /**
   * The bundle entry's id this entry is a member of (Phase 24.1).
   *
   * Membership is stored **once, on the member** — the same shape as `pool` —
   * so an older build that deletes the bundle entry cannot leave two
   * disagreeing copies of "is this bundled". `null`/absent means unbundled.
   */
  bundle_id?: string | null;
  /**
   * This member's slot name within its bundle — `"discord"`, `"web"`, `"v3"`.
   * Validated like {@link label} (`^[A-Za-z0-9][A-Za-z0-9_-]{0,23}$`), unique
   * within the bundle. Addressed as `${bundle:Name/slot}` and `{slot.field}`
   * inside the bundle's own templates.
   */
  bundle_slot?: string | null;
  /**
   * Sort key with gaps, never identity (invariant 1) — the same shape as a
   * pool cursor position, not an array index.
   */
  bundle_order?: number | null;
  /**
   * On the **bundle** entry itself (`secretType === 'bundle'`): which member's
   * id the card's main Copy button copies. `null` means nothing is copyable
   * from the collapsed card yet.
   */
  bundle_primary?: string | null;
  /**
   * A short namespace token inserted into generated environment-variable names
   * after the version — `SPOTIFY_V2_GAME_ID`.
   *
   * **Not `account_name`.** Account names in real vaults are email addresses,
   * and `SPOTIFY_DARTHDEMONO_GMAIL_COM_ID` is not what anyone wants. Validated
   * at the form to `^[A-Za-z0-9][A-Za-z0-9_-]{0,23}$` so it is always usable as
   * a segment.
   */
  label?: string | null;
  /** Simple Icons slug for a custom provider icon, or `null` to use auto-detection. */
  custom_icon?: string | null;
  /** Additional metadata or usage notes. */
  details?: string | null;
  /** Snapshots of previous `api_key` values. Prepended automatically on save when the value changes. */
  version_history?: { value: string; saved_at: string }[];
  /**
   * Ids of the projects this entry belongs to. Backed by `VaultData.projects`,
   * shown in the sidebar's "Projects" section, and matched by RBAC
   * `scope_type: "project"`.
   *
   * Always contains `"Universal"` — the catch-all every entry carries. A
   * specific project grant is never satisfied by it.
   */
  projectIds: string[];
  /** Discriminates which secret-type-specific fields and form layout apply. */
  secretType?: SecretType;
  /** Username for `password` or `ssh_key` entries. */
  username?: string | null;
  /** Email associated with this credential. */
  email?: string | null;
  /** PEM-encoded certificate content (fullchain). `certificate` entries only. */
  certificate_data?: string | null;
  /** Private key PEM paired with this certificate. */
  cert_key_data?: string | null;
  /** Issuer / CA that provided the certificate (e.g. "Let's Encrypt", "Google", "EnvV"). `certificate` entries only. */
  cert_issuer?: string | null;
  /** File-system path or reference to a credential file. `file_blob` entries only. */
  blob_ref?: string | null;
  /** Sub-type hint for env_var entries (used for display and filtering). */
  env_var_subtype?:
    | 'string'
    | 'multiline'
    | 'secret'
    | 'boolean'
    | 'number'
    | 'ip'
    | 'cidr'
    | 'port'
    | 'url'
    | 'date'
    | 'json';
  /**
   * ISO-8601 timestamp of when this entry was first written to the vault.
   *
   * Optional because vaults written before this field existed have no such
   * record, and there is no honest way to invent one. `backfillCreatedAt()` in
   * `state.ts` infers a date for those from evidence already in the vault —
   * the oldest `version_history` snapshot, or the earliest audit row naming the
   * entry — and leaves it unset when there is none. An entry with no
   * `created_at` renders as "unknown" and is omitted from the calendar feed,
   * which is the truthful answer: stamping "today" onto every pre-existing
   * secret would make the timeline panel and every exported `.ics` repeat a
   * date nobody chose.
   *
   * Never rewritten on edit. This is a creation date, not a modification date;
   * `version_history[0].saved_at` is where "when did it last change" lives.
   */
  created_at?: string | null;
  /** ISO-8601 timestamp of the last manual rotation (set via "Mark as rotated"). */
  last_rotated_at?: string | null;
  /** Rotation cadence in days. When set, health scan flags entries overdue since `last_rotated_at`. */
  rotation_days?: number | null;
  /** Marks a credential as known-leaked / emergency-rotate. Surfaces as a critical health issue. */
  compromised?: boolean;
  /** Free-form tags for quick cross-cutting labelling (separate from categories/projects). */
  tags?: string[];
  /** When true the entry floats to the top of all filtered views. */
  pinned?: boolean;
  /** Extra named fields beyond the fixed schema (e.g. db, port, host for database entries). */
  extra_vars?: {
    key: string;
    value: string;
    secret?: boolean;
    /**
     * Opt this value **out** of redaction everywhere (Phase 23, E5).
     *
     * `extra_vars` are masked by default. `public` is per value and never per
     * type: a client id, a region, an account SID and a publishable key are each
     * safe to print and the secret beside them is not. Without it the `basic`
     * copy profile is either useless (everything masked) or unsafe (nothing).
     */
    public?: boolean;
    /**
     * Overrides the env-name segment derived from `key` (Phase 23 design,
     * finally added in 24.1 alongside composite parts — a part's placeholder
     * name and its generated env-name segment are not always the same word).
     */
    role?: string;
    /** Which copy profile includes this variable. Absent means `'basic'`. */
    tier?: 'basic' | 'extended';
    /**
     * The editor/validator/preview this value gets in the form (Phase 24.1).
     *
     * Storage never changes: every value is a string end to end, whatever the
     * kind. A kind is data about how to *edit* the string, never a coercion —
     * `hex_int` and `large_id` both stay strings so a JSON export can quote a
     * large id without a JS number silently rounding it.
     */
    kind?: ValueKind;
    /**
     * Per-cookie attributes, filled by the paste parser (Phase 23, E14).
     *
     * `cookies.txt` needs a domain, an include-subdomains flag, a path, a secure
     * flag and an expiry for every cookie. A DevTools "Copy all as JSON" and a
     * pasted `cookies.txt` both carry them; a bare `document.cookie` string does
     * not, and the export is **refused** in that case rather than writing a file
     * `yt-dlp` silently ignores.
     */
    attrs?: {
      domain?: string;
      path?: string;
      secure?: boolean;
      http_only?: boolean;
      /** Unix seconds. `0` is a session cookie. */
      expires?: number;
    };
  }[];
  /**
   * Base32 TOTP seed this credential's service issued — the authenticator
   * secret, from which EnvVault generates the six digits you type into that
   * service's login form.
   *
   * **This is the reverse of the Phase 19 TOTP**, which is a second factor on
   * *EnvVault's own* sub-user login and lives in the `users` table, never here.
   * Nothing reads both.
   *
   * Stored normalised: uppercase base32, no spaces, dashes or padding, so two
   * entries holding the same seed typed differently are byte-identical and
   * fingerprint the same. A pasted `otpauth://` URI is split into this field and
   * the three below at the form rather than stored whole — the URI is a
   * container, and keeping it would mean a second field that also holds the
   * secret and has to be masked everywhere this one is.
   *
   * It is a secret in every sense the vault means: masked by
   * `maskKeysByDefault`, in `SECRET_FIELDS` for CLI redaction, and snapshot into
   * `version_history` on change.
   */
  totp_secret?: string | null;
  /**
   * HMAC the issuer generates with. Absent means SHA-1, which is what
   * `otpauth://` means when it omits the parameter and what almost every issuer
   * uses. Written only when the issuer said something else — a field that reads
   * "SHA1" on every entry cannot be told apart from a defaulted one.
   */
  totp_algorithm?: 'SHA1' | 'SHA256' | 'SHA512' | null;
  /** Digits in the generated code. Absent means 6. */
  totp_digits?: number | null;
  /** Seconds a code is valid for. Absent means 30. */
  totp_period?: number | null;
  /**
   * What the seed is: `totp` (time-based, the default when absent), `hotp`
   * (counter-based) or `steam` (Steam Guard's five characters). Phase 22.2.
   */
  totp_kind?: 'totp' | 'hotp' | 'steam' | null;
  /**
   * The next counter an `hotp` seed will use.
   *
   * Written whenever the seed is counter-based, zero included — zero is a real
   * position, not an absent one — and removed for the other kinds. It is state
   * rather than configuration, which is why advancing it is an explicit action.
   */
  totp_counter?: number | null;
  /**
   * Env-var prefixes added by services that consume this credential.
   * For Key type: e.g. ["ND", "SPOTIFYD"] means Navidrome uses ND_LASTFM_APIKEY.
   * For Chunk type: the first prefix IS the chunk's env-namespace identifier (e.g. ["AM"] for AM_JWT_SECRET).
   */
  env_prefixes?: string[];
}

/**
 * A hierarchical category node (UI label: "Category").
 *
 * Slash-delimited names encode a virtual tree: `"Cloud/AWS"` is a child of `"Cloud"`.
 * The reserved entry with `id === "Universal"` is a catch-all; every entry belongs to it.
 */
export interface Project {
  /** Stable, URL-safe, lowercase identifier derived from `name`. */
  id: string;
  /** Display name. Slash-segments indicate hierarchy (e.g. `"Cloud/AWS"`). */
  name: string;
  /** Optional description shown as a tooltip in the category tree. */
  description?: string;
  /** High-level type of the project — drives the special config view. */
  project_type?: ProjectType;
  /** Structured config chunks for WireGuard or Docker projects. */
  chunks?: SecretChunk[];
}

/** Sub-type of a field in a structured config chunk. */
export type ChunkFieldType =
  | 'var'
  | 'env_var'
  | 'secret'
  | 'list'
  | 'multiline'
  | 'port'
  | 'user_id'
  | 'subnet'
  | 'ip'
  | 'endpoint'
  | 'volume_mount'
  | 'cert';

/** A single field within a structured config chunk (WireGuard section, Docker service, etc.). */
export interface ChunkField {
  /** Field key name (e.g. "PrivateKey", "ND_LASTFM_APIKEY"). */
  key: string;
  /** Raw value or "${REF_NAME}" syntax to reference a vault env_var entry. */
  value: string;
  /** How this field is categorised and exported. */
  field_type: ChunkFieldType;
  /**
   * If non-null, this field's value is resolved from the vault entry
   * where `provider === ref_name` and `secretType === 'env_var'`.
   */
  ref_name?: string;
  /** When true the value is masked in the UI. */
  secret?: boolean;
  /** Optional description / comment for this field. */
  description?: string;
}

/** Type of a structured config chunk — determines field schema and export format. */
export type ChunkType =
  | 'wg_interface'
  | 'wg_peer'
  | 'docker_service'
  | 'docker_network'
  | 'docker_volume'
  | 'env_file'
  | 'nginx_server'
  | 'nginx_upstream'
  | 'nginx_location'
  | 'nginx_key'
  | 'k8s_deployment'
  | 'k8s_service'
  | 'k8s_configmap'
  | 'k8s_secret'
  | 'k8s_ingress'
  | 'ssh_host'
  | 'traefik_router'
  | 'traefik_service'
  | 'traefik_middleware'
  | 'apache_vhost'
  | 'apache_directory'
  | 'haproxy_global'
  | 'haproxy_frontend'
  | 'haproxy_backend'
  | 'ansible_vars'
  | 'ansible_task'
  | 'pg_connection'
  | 'pg_role'
  | 'generic';

/** A named section within a structured project config. */
export interface SecretChunk {
  /** Stable UUID-like identifier. */
  id: string;
  /** Display name ("Interface", "Peer — office", "navidrome service", etc.). */
  name: string;
  chunk_type: ChunkType;
  fields: ChunkField[];
  /** Optional freetext notes shown under the chunk header. */
  notes?: string;
  /** When true the chunk is greyed-out and excluded from exports. */
  disabled?: boolean;
  /** Snapshot of resolved env output (KEY→value hash map) at last copy — powers "changed since last copy". */
  last_copied_snapshot?: Record<string, string>;
  /** ISO-8601 timestamp of the last resolved copy. */
  last_copied_at?: string;
}

/** High-level type of a project — drives the special config view. */
export type ProjectType =
  | 'generic'
  | 'wireguard'
  | 'docker'
  | 'nginx'
  | 'kubernetes'
  | 'ssh_config'
  | 'traefik'
  | 'apache'
  | 'haproxy'
  | 'ansible'
  | 'postgres';

/**
 * Project types that have actually been exercised end to end.
 *
 * A type earns its place here by having its generated config **accepted by the
 * software it targets**, not by round-tripping through a parser we also wrote.
 * Phase 18 ran that matrix (`.github/workflows/exporters.yml`, and locally
 * against containers) and every type below passed with a control case proving
 * the validator rejects nonsense:
 *
 * | type       | evidence                                                      |
 * | ---------- | ------------------------------------------------------------- |
 * | wireguard  | round-trip through `parseWgConf`                               |
 * | docker     | Compose schema + `.env` pairing                                |
 * | nginx      | round-trip through `parseNginxConf`                            |
 * | kubernetes | applied to a real k3s cluster; value decoded back out of it    |
 * | ssh_config | parsed by OpenSSH `ssh -G`                                     |
 * | traefik    | loaded by Traefik v3; router and middleware report `enabled`   |
 * | apache     | `httpd -t` → `Syntax OK`                                       |
 * | haproxy    | `haproxy -c` → exit 0                                          |
 * | ansible    | `ansible-playbook --syntax-check` → exit 0                     |
 * | postgres   | a real server authenticated using only the generated `.pgpass` |
 *
 * Two of them only passed *after* a fix the validation itself found: six
 * exporters never resolved `${ref}` (invariant 5), and `exportAnsible` emitted
 * a mapping followed by a sequence — not valid YAML in any parser.
 *
 * The rule for adding one: nothing goes in this list on the strength of a
 * fixture alone. A fixture proves we agree with ourselves.
 */
export const STABLE_PROJECT_TYPES: readonly ProjectType[] = [
  'generic',
  'wireguard',
  'docker',
  'nginx',
  'kubernetes',
  'ssh_config',
  'traefik',
  'apache',
  'haproxy',
  'ansible',
  'postgres',
];

/** Whether a project type is gated behind the experimental setting. */
export function isExperimentalProjectType(t: ProjectType | undefined | null): boolean {
  return !!t && !STABLE_PROJECT_TYPES.includes(t);
}

/**
 * Root data structure persisted to the encrypted SQLCipher database.
 * Serialised as JSON in the single-row `vault` table.
 */
export interface VaultData {
  /** All stored secret entries. */
  api_keys: VaultEntry[];
  /** Ordered list of flat project tag names (UI label: "Projects"). */
  user_categories: string[];
  /**
   * Tree of hierarchical categories (UI label: "Categories").
   * Always contains at least the "Universal" catch-all entry.
   */
  projects: Project[];
}

// ── Multi-user RBAC types (Phase 5) ──────────────────────────────────────────

/** A vault user record returned by the user management API. */
export interface UserInfo {
  id: string;
  username: string;
  has_password: boolean;
  is_owner: boolean;
  created_at: string;
  last_seen_at: string | null;
  class_id: string | null;
  /**
   * True when this user has a *confirmed* second factor. Enrollment alone does
   * not set it — a secret that was never confirmed must not make the account
   * look protected.
   */
  totp_enabled?: boolean;
}

/** A stored API token descriptor (actual token shown only on creation). */
export interface TokenInfo {
  id: string;
  user_id: string;
  description: string | null;
  created_at: string;
  expires_at: string | null;
}

/**
 * A single RBAC permission row.
 *
 * - `scope_type`:  `"vault"` | `"project"` | `"category"`
 * - `scope_value`: `"*"`, `"wg0-*"`, `"Cloud/AWS"`, etc. (glob)
 * - `permission`:  `"read"` | `"write"` (write implies read)
 */
export interface PermissionEntry {
  user_id: string;
  scope_type: 'vault' | 'project' | 'category';
  scope_value: string;
  permission: 'read' | 'write';
}

/** A named user class (role template) with capabilities and permissions. */
export interface UserClass {
  id: string;
  name: string;
  description: string;
  cap_manage_users: boolean;
  cap_manage_classes: boolean;
  cap_delete_projects: boolean;
  created_at: string;
}

/** A permission row scoped to a user class (applies to all members of the class). */
export interface ClassPermission {
  class_id: string;
  scope_type: 'vault' | 'project' | 'category';
  scope_value: string;
  permission: 'read' | 'write';
}

/** A single row from the append-only vault audit log. */
export interface AuditRow {
  id: number;
  action: 'add' | 'update' | 'delete' | string;
  entry_provider: string | null;
  timestamp: string;
  details: string | null;
  entry_hash: string | null;
  prev_hash: string | null;
  /** User id that performed the action; null for rows written before actor tracking. */
  actor: string | null;
}

/** Remote vault server configuration stored in AppSettings. */
export interface RemoteConfig {
  enabled: boolean;
  serverUrl: string;
}

/** A saved remote vault connection (persisted in AppSettings). */
export interface RemoteVaultConfig {
  id: string;
  name: string;
  url: string;
  username: string;
  /** SHA-256 hex fingerprint of the server TLS cert (TOFU pinning). Present only for HTTPS servers. */
  certFingerprint?: string;
  /**
   * ISO timestamp of the last *successful* connection.
   *
   * Written only after authentication succeeds, never on save or on a failed
   * attempt — the unlock screen's server picker sorts on it, and a server you
   * typed once and could not reach must not outrank the one you use daily.
   */
  lastConnectedAt?: string;
}

/**
 * The parts of the grid view worth carrying across a restart.
 *
 * Deliberately not the whole of `st`: expand/reveal/bulk state is per-session
 * and restoring it would un-mask secrets the user never asked to see. Every id
 * in here is validated against the loaded vault before being applied — see
 * `restoreViewState()`.
 */
export interface PersistedView {
  filterType: string;
  filterValue: string;
  envFilter: string;
  tagFilter: string | null;
  prefixFilter: string | null;
  /**
   * Optional because it was added after this interface shipped: a `lastView`
   * written by an earlier build has no such key, and `localStorage` is read
   * back without a migration. `restoreViewState()` guards on it being present
   * *and* still resolving against the loaded vault (invariant 7).
   */
  poolFilter?: string | null;
  /**
   * The type chip bar (Phase 24.2). Optional for the same reason `poolFilter`
   * is: a `lastView` written before this field existed has no such key.
   * `restoreViewState()` drops any entry that is neither `'__totp'`/`'__pool'`
   * nor a `SecretType` actually present in the loaded vault.
   */
  typeChips?: string[];
  projectIds: string[];
}

/**
 * User-configurable application settings.
 *
 * Stored in plain JSON at `app_config_dir/settings.json` (not encrypted),
 * so that they survive a vault reset without needing the master password.
 */
export interface AppSettings {
  /** Active colour theme identifier. 'system' follows the OS preference. */
  theme: 'dark' | 'midnight' | 'dracula' | 'nord' | 'catppuccin' | 'light' | 'system' | string;
  /** Hex accent colour used for highlights and active states (e.g. `"#7364c9"`). */
  accentColor: string;
  /** Visual density of secret cards in the grid. */
  cardSize: 'compact' | 'medium' | 'large';
  /** Number of grid columns, or `"auto"` for responsive `auto-fill`. */
  gridColumns: 'auto' | '2' | '3' | '4' | '5' | '6' | '8';
  /** Prefilled value for the "Account" field when adding a new secret. */
  defaultAccount: string;
  /** Format used by "Copy All" and the single-entry copy button on cards. */
  defaultExportFormat: 'dotenv' | 'yaml' | 'json';
  /** Minutes of inactivity before the vault auto-locks. */
  autoLockMinutes: number;
  /**
   * Lock the vault the instant the window is hidden (alt-tab, minimise).
   *
   * Defaults to `false`: this used to be unconditional, so simply switching
   * windows nuked your session. The inactivity timer already covers walking
   * away from the machine; this is the paranoid opt-in on top.
   */
  lockOnHide: boolean;
  /** Whether secret values are masked (dotted) by default when cards load. */
  maskKeysByDefault: boolean;
  /** Whether to display a warning badge for secrets approaching expiry. */
  showExpiryWarning: boolean;
  /** Days before expiry at which the warning badge first appears. */
  expiryWarningDays: number;
  /** Arbitrary CSS string injected after all built-in styles. */
  customCss: string;
  /**
   * Ordered array of sidebar section keys to display.
   * Sections absent from this array are hidden.
   */
  sidebarSections: (
    'all' | 'price' | 'env' | 'category' | 'project' | 'tags' | 'pools' | 'prefixes'
  )[];
  /** When `true`, the main grid renders section headers grouping cards by secret type. */
  groupByType: boolean;
  /**
   * When `true` (default), entries sharing a key pool collapse into one card
   * in the grid — Phase 24.2. The Key Pools tool pane is unaffected; it always
   * shows every member, because cooldown management needs them all visible.
   */
  groupPools: boolean;
  /** Position of the activity bar. */
  activityBarPosition: 'left' | 'right';
  /** Activity bar display style. */
  activityBarStyle: 'icon' | 'icon-label';
  /** Section keys that are currently collapsed in the secrets sidebar. */
  collapsedSections: (
    'all' | 'price' | 'env' | 'category' | 'project' | 'tags' | 'pools' | 'prefixes'
  )[];
  /** Currently active top-level panel. */
  activePanel: 'secrets' | 'tools' | 'users' | 'remote' | 'auth';
  /** ID of the currently active tool pane (e.g. `'secret-gen'`). */
  activeTool: string;
  /**
   * Whether the Authenticator screen also shows the code that comes next.
   *
   * Off by default: the next code is a second working credential with a longer
   * life than the one on screen, so a panel that always painted one would put
   * two live codes into every screenshot rather than one.
   */
  authShowNext: boolean;
  /** Remote vault server configuration (legacy single-remote). */
  remote?: RemoteConfig;
  /** Saved remote vault connections. */
  remoteSaved: RemoteVaultConfig[];
  /** Ordered list of activity-bar panel IDs (controls display order and visibility). */
  panelOrder: string[];
  /** VaultEntry field used as the resolved value when doing ".env copy". */
  envCopyField: 'api_key' | 'api_secret' | 'key_id';

  // ── Copy (Phase 23) ──────────────────────────────────────────────────────
  /**
   * Case of a generated environment-variable name.
   *
   * `upper` is the shell convention and what every exporter here has always
   * emitted, so lowercase is offered rather than assumed.
   */
  envCopyCase: 'upper' | 'preserve' | 'lower';
  /**
   * Prepend the entry's first consumer prefix (`env_prefixes[0]`) to generated
   * names — `ND_SPOTIFY_ID` rather than `SPOTIFY_ID`.
   *
   * Off by default: a prefix is a fact about *one* consumer of a credential, and
   * turning it on renames every variable the vault generates.
   */
  envIncludePrefix: boolean;
  /**
   * How much of an entry a copy emits — see `src/ts/copy-profile.ts`.
   *
   * A **default, not a wall**: the copy button's caret menu offers the other two
   * plus "Value only" on every card, and the one-off choice made there is
   * deliberately not persisted as the new default. A "give me everything" press
   * must not silently change what the next fifty copies contain.
   */
  copyProfile: 'basic' | 'extended' | 'full';
  /**
   * Whether profile metadata is written as `#` comments or as variables.
   *
   * Comments by default: an `.env` is loaded into a process, and injecting six
   * non-functional variables per credential into every container is a cost the
   * user did not ask for by pressing Copy.
   */
  metadataStyle: 'comment' | 'var';

  // ── Layout persistence ───────────────────────────────────────────────────
  /**
   * Sidebar width in px, or 0 to use the stylesheet default.
   *
   * A number rather than a CSS string so a corrupt settings blob cannot inject
   * arbitrary CSS into `style.width`; it is clamped to the same bounds the drag
   * handle enforces before being applied.
   */
  sidebarWidth: number;
  /** Whether the sidebar is collapsed (the `sidebar-toggle` / Ctrl-B state). */
  sidebarCollapsed: boolean;
  /** Last sort mode chosen in the grid toolbar. */
  lastSortBy: string;

  // ── Search / view persistence ────────────────────────────────────────────
  /** Most-recent-first search strings, capped at RECENT_SEARCH_MAX. */
  recentSearches: string[];
  /** When true, the grid filter/project selection is restored on next launch. */
  rememberFilters: boolean;
  /** Last grid view, restored at launch when `rememberFilters` is set. */
  lastView: PersistedView | null;

  /**
   * Offer the untested project types (Kubernetes, SSH config, Traefik, Apache,
   * HAProxy, Ansible, PostgreSQL) in the create-project picker.
   *
   * Off by default. Gates *creation only* — a project already using one of
   * these keeps its config view and chunks regardless, since hiding the view
   * would leave that data in the vault with no way to reach it.
   */
  experimentalProjectTypes: boolean;
  /**
   * Keep the local vault's key in memory after switching to a remote.
   *
   * Off by default. When off, connecting to a remote zeroizes the local key, so
   * switching back asks for the master password again — the price of the key
   * not being resident, unseen, for the rest of the session.
   */
  keepLocalUnlocked: boolean;
  /**
   * Whether the first-run wizard has been shown.
   *
   * Set when the wizard is finished *or* skipped: re-showing something the user
   * dismissed on purpose is how a welcome screen becomes an obstacle. Settings
   * has a button to run it again deliberately.
   */
  onboardingCompleted: boolean;
}
