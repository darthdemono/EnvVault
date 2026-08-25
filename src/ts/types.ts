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
  | 'file_blob';

/**
 * A single stored secret entry.
 *
 * `api_key` holds the primary secret value regardless of `secretType`.
 * Fields irrelevant to a given type are `null` / `undefined` and hidden in the UI.
 * Every entry always belongs to at least the "Universal" category (`projectIds`).
 */
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
  /** Human-readable rate-limit description (e.g. `"100 req/min"`). */
  rate_limit?: string | null;
  /** API or SDK version this key was issued for. */
  version?: string | null;
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
  extra_vars?: { key: string; value: string; secret?: boolean }[];
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
 * Everything else in `ProjectType` is reachable only with the "experimental
 * project types" setting switched on: the config views, starter chunks and
 * exporters exist but have never been run against a real deployment, and a
 * config this app writes wrong is a broken deploy rather than a cosmetic bug.
 */
export const STABLE_PROJECT_TYPES: readonly ProjectType[] = [
  'generic',
  'wireguard',
  'docker',
  'nginx',
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
  sidebarSections: ('all' | 'price' | 'env' | 'category' | 'project' | 'tags' | 'prefixes')[];
  /** When `true`, the main grid renders section headers grouping cards by secret type. */
  groupByType: boolean;
  /** Position of the activity bar. */
  activityBarPosition: 'left' | 'right';
  /** Activity bar display style. */
  activityBarStyle: 'icon' | 'icon-label';
  /** Section keys that are currently collapsed in the secrets sidebar. */
  collapsedSections: ('all' | 'price' | 'env' | 'category' | 'project' | 'tags' | 'prefixes')[];
  /** Currently active top-level panel. */
  activePanel: 'secrets' | 'tools' | 'users' | 'remote';
  /** ID of the currently active tool pane (e.g. `'secret-gen'`). */
  activeTool: string;
  /** Remote vault server configuration (legacy single-remote). */
  remote?: RemoteConfig;
  /** Saved remote vault connections. */
  remoteSaved: RemoteVaultConfig[];
  /** Ordered list of activity-bar panel IDs (controls display order and visibility). */
  panelOrder: string[];
  /** VaultEntry field used as the resolved value when doing ".env copy". */
  envCopyField: 'api_key' | 'api_secret' | 'key_id';

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
}
