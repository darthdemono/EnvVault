/**
 * @file Data models for API Vault.
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
  /** Flat project tag names (UI label: "Projects"). Backed by `VaultData.user_categories`. */
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
  version_history?: Array<{ value: string; saved_at: string }>;
  /**
   * Hierarchical category IDs (UI label: "Categories") this entry belongs to.
   * Backed by `VaultData.projects`. Always contains `"Universal"`.
   */
  projectIds: string[];
  /** Discriminates which secret-type-specific fields and form layout apply. */
  secretType?: 'api_key' | 'password' | 'certificate' | 'env_var' | 'connection_string' | 'ssh_key' | 'file_blob';
  /** Username for `password` or `ssh_key` entries. */
  username?: string | null;
  /** Email associated with this credential. */
  email?: string | null;
  /** PEM-encoded certificate content. `certificate` entries only. */
  certificate_data?: string | null;
  /** Private key PEM paired with this certificate. */
  cert_key_data?: string | null;
  /** File-system path or reference to a credential file. `file_blob` entries only. */
  blob_ref?: string | null;
  /** Sub-type hint for env_var entries (used for display and filtering). */
  env_var_subtype?: 'string' | 'multiline' | 'secret' | 'boolean' | 'number' | 'ip' | 'cidr' | 'port' | 'url' | 'date' | 'json';
  /** ISO-8601 timestamp of the last manual rotation (set via "Mark as rotated"). */
  last_rotated_at?: string | null;
  /** Free-form tags for quick cross-cutting labelling (separate from categories/projects). */
  tags?: string[];
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
export type ChunkFieldType = 'var' | 'env_var' | 'secret' | 'list' | 'multiline' | 'port' | 'user_id' | 'subnet' | 'ip' | 'endpoint' | 'volume_mount';

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
  | 'k8s_deployment'
  | 'k8s_service'
  | 'k8s_configmap'
  | 'k8s_secret'
  | 'k8s_ingress'
  | 'ssh_host'
  | 'traefik_router'
  | 'traefik_service'
  | 'traefik_middleware'
  | 'generic';

/** A named section within a structured project config. */
export interface SecretChunk {
  /** Stable UUID-like identifier. */
  id: string;
  /** Display name ("Interface", "Peer — office", "navidrome service", etc.). */
  name: string;
  chunk_type: ChunkType;
  fields: ChunkField[];
}

/** High-level type of a project — drives the special config view. */
export type ProjectType = 'generic' | 'wireguard' | 'docker' | 'nginx' | 'kubernetes' | 'ssh_config' | 'traefik';

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
  id:           string;
  username:     string;
  has_password: boolean;
  is_owner:     boolean;
  created_at:   string;
  last_seen_at: string | null;
  class_id:     string | null;
}

/** A stored API token descriptor (actual token shown only on creation). */
export interface TokenInfo {
  id:          string;
  user_id:     string;
  description: string | null;
  created_at:  string;
  expires_at:  string | null;
}

/**
 * A single RBAC permission row.
 *
 * - `scope_type`:  `"vault"` | `"project"` | `"category"`
 * - `scope_value`: `"*"`, `"wg0-*"`, `"Cloud/AWS"`, etc. (glob)
 * - `permission`:  `"read"` | `"write"` (write implies read)
 */
export interface PermissionEntry {
  user_id:     string;
  scope_type:  'vault' | 'project' | 'category';
  scope_value: string;
  permission:  'read' | 'write';
}

/** A named user class (role template) with capabilities and permissions. */
export interface UserClass {
  id:                  string;
  name:                string;
  description:         string;
  cap_manage_users:    boolean;
  cap_manage_classes:  boolean;
  cap_delete_projects: boolean;
  created_at:          string;
}

/** A permission row scoped to a user class (applies to all members of the class). */
export interface ClassPermission {
  class_id:    string;
  scope_type:  'vault' | 'project' | 'category';
  scope_value: string;
  permission:  'read' | 'write';
}

/** A single row from the append-only vault audit log. */
export interface AuditRow {
  id:             number;
  action:         'add' | 'update' | 'delete' | string;
  entry_provider: string | null;
  timestamp:      string;
  details:        string | null;
  entry_hash:     string | null;
  prev_hash:      string | null;
}

/** Remote vault server configuration stored in AppSettings. */
export interface RemoteConfig {
  enabled:    boolean;
  serverUrl:  string;
}

/** A saved remote vault connection (persisted in AppSettings). */
export interface RemoteVaultConfig {
  id:       string;
  name:     string;
  url:      string;
  username: string;
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
  gridColumns: 'auto' | '2' | '3' | '4';
  /** Prefilled value for the "Account" field when adding a new secret. */
  defaultAccount: string;
  /** Format used by "Copy All" and the single-entry copy button on cards. */
  defaultExportFormat: 'dotenv' | 'yaml' | 'json';
  /** Minutes of inactivity before the vault auto-locks. */
  autoLockMinutes: number;
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
  sidebarSections: ('all' | 'price' | 'category' | 'project')[];
  /** When `true`, the main grid renders section headers grouping cards by secret type. */
  groupByType: boolean;
  /** Position of the activity bar. */
  activityBarPosition: 'left' | 'right';
  /** Activity bar display style. */
  activityBarStyle: 'icon' | 'icon-label';
  /** Section keys that are currently collapsed in the secrets sidebar. */
  collapsedSections: ('all' | 'price' | 'category' | 'project')[];
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
}
