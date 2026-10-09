import type { VaultEntry, SecretType } from './types';
import { renderComposite, renderErrorMessage, type CompositeKind } from './composite';
import {
  st,
  Settings,
  triggerRender,
  Exporter,
  persist,
  entryId,
  newEntryId,
  envName,
  primaryEnvName,
  secretEnvName,
  namesGeneratedBy,
  primaryIsOptional,
  entryHasPayload,
} from './state';
import {
  maskKey,
  showToast,
  showConfirm,
  clipboardWrite,
  errorMessage,
  showPromptLarge,
} from './utils';
import { iconHTML, openIconPicker, iconPicker, setIconField, readIconField } from './icons';
import { renameProviderRefs } from './chunk-ops';
import { normalizeRateLimit } from './ratelimit';
import { invokeTauri, isTauri } from './tauri';
import { emittersFor } from './secret-types';
import { showWifiQr } from './wifi-qr';
import { buildCopyText, type CopyProfile, type MetadataStyle } from './copy-profile';
import { authHeaderFor, curlFor } from './auth-request';
import { isFileShaped, fileContentsOf, fileEnvLine } from './file-cred';
import { downloadText } from './import-export';
import {
  cookiesOf,
  cookiesToExtraVars,
  missingTxtAttributes,
  parseAnyCookies,
  toCookieHeader,
  toCookiesTxt,
  toCookieJson,
  toPlaywrightStorageState,
} from './cookies';
import { parseTotpSeed, normalizeB32, TOTP_DEFAULTS } from './totp';
import {
  referencesToBundleMember,
  renameBundleLocalRefs,
  renameBundleRefs,
  resolveBundleTemplate,
} from './bundle-scope';
import {
  generateRandomBytes,
  generatePassword,
  guardEntropy,
  generateApiKeyPattern,
  generateHash,
} from './generators';
import {
  presets as sessionPresets,
  findPreset as findSessionPreset,
  deriveHeaders as deriveSessionHeaders,
} from './session-presets';
import { html, setHtml, type HtmlValue } from './html';

/**
 * Rate-limit text the structured count/period pair cannot express, carried from
 * the entry being edited through to the next save.
 *
 * Module-level state that points at the entry currently in the form, so it has
 * the problem CLAUDE.md's invariants are about: something holds a reference and
 * the thing it points at changes. What clears it is `fillForm`, which every path
 * into the form goes through — `fillForm({})` for a new entry normalises to no
 * note and blanks it. Do not read this without having gone through `fillForm`
 * first, or a note from the last entry edited lands on a different one.
 */
let pendingRateLimitNote = '';

// ── Schema tooltips & category chips ──────────────────────────────────────

export function applySchemaTooltips() {
  if (!st.schema) return;
  const props = st.schema.properties?.api_keys?.items?.properties || {};
  document.querySelectorAll<HTMLElement>('.form-label[data-field]').forEach((el) => {
    const d = props[el.dataset.field!]?.description;
    if (d) el.title = d;
  });
}

export function buildCatChips(selected: string[] = []) {
  const wrap = document.getElementById('f-categories')!;
  setHtml(wrap, '');
  if (!st.vault.user_categories.length) {
    setHtml(
      wrap,
      html`<span style="font-size:10px;color:var(--text3)">No categories — add in sidebar</span>`,
    );
    return;
  }
  st.vault.user_categories.forEach((cat) => {
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = `cat-chip${selected.includes(cat) ? ' selected' : ''}`;
    chip.textContent = cat;
    chip.addEventListener('click', () => chip.classList.toggle('selected'));
    wrap.appendChild(chip);
  });
}

// ── Type config ───────────────────────────────────────────────────────────

export type TypeConfig = {
  providerLabel: string;
  providerPlaceholder: string;
  showAccount: boolean;
  keyLabel: string;
  keyPlaceholder: string;
};

export const TYPE_CONFIG: Record<SecretType, TypeConfig> = {
  api_key: {
    providerLabel: 'Provider',
    providerPlaceholder: 'e.g. GitHub',
    showAccount: true,
    keyLabel: 'API Key',
    keyPlaceholder: 'Your API key or access token',
  },
  password: {
    providerLabel: 'Service / App',
    providerPlaceholder: 'e.g. Gmail',
    showAccount: false,
    keyLabel: 'Password',
    keyPlaceholder: 'Your password',
  },
  env_var: {
    providerLabel: 'Variable Name',
    providerPlaceholder: 'e.g. DATABASE_URL',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: 'Variable value',
  },
  connection_string: {
    providerLabel: 'Service',
    providerPlaceholder: 'e.g. PostgreSQL',
    showAccount: false,
    keyLabel: 'Connection String',
    keyPlaceholder: 'postgresql://user:pass@host/db',
  },
  ssh_key: {
    providerLabel: 'Host / Service',
    providerPlaceholder: 'e.g. github.com',
    showAccount: true,
    keyLabel: 'SSH Key',
    keyPlaceholder: '-----BEGIN OPENSSH PRIVATE KEY-----',
  },
  certificate: {
    providerLabel: 'Site / Domain',
    providerPlaceholder: 'e.g. darthdemono.com',
    showAccount: false,
    keyLabel: 'Fullchain',
    keyPlaceholder: '',
  },
  file_blob: {
    providerLabel: 'Name',
    providerPlaceholder: 'e.g. config.yaml',
    showAccount: false,
    keyLabel: 'File Reference',
    keyPlaceholder: '',
  },
  cookie: {
    providerLabel: 'Site',
    providerPlaceholder: 'e.g. Spotify',
    showAccount: true,
    keyLabel: 'Cookie jar',
    keyPlaceholder: 'sp_dc=…; sp_key=…  — or paste a cookies.txt / JSON export',
  },
  // api_key is unused for both: a composite's value is its rendered template,
  // and a bundle's payload is entirely its members plus its local variables.
  composite: {
    providerLabel: 'Name',
    providerPlaceholder: 'e.g. Outlook Calendar',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  bundle: {
    providerLabel: 'Bundle Name',
    providerPlaceholder: 'e.g. Discord bot',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  // Phase 24.5's sixteen new types. No `<option>` exists for any of them in
  // the type picker yet — these entries exist only to keep `TYPE_CONFIG`
  // exhaustive over `SecretType`, per invariant "shape now, behavior later".
  // Every one stores its payload in `extra_vars`, the same as `env_var`.
  oauth_client: {
    providerLabel: 'Provider',
    providerPlaceholder: 'e.g. Google',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  signing_key: {
    providerLabel: 'Key name',
    providerPlaceholder: 'e.g. Webhook signing key',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  registry_token: {
    providerLabel: 'Registry',
    providerPlaceholder: 'e.g. npm',
    showAccount: true,
    keyLabel: 'Token',
    keyPlaceholder: '',
  },
  database: {
    providerLabel: 'Database',
    providerPlaceholder: 'e.g. Production Postgres',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  recovery_codes: {
    providerLabel: 'Service',
    providerPlaceholder: 'e.g. GitHub recovery codes',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  gpg_key: {
    providerLabel: 'Key name',
    providerPlaceholder: 'e.g. Release signing key',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  age_key: {
    providerLabel: 'Key name',
    providerPlaceholder: 'e.g. Backup encryption key',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  local_service: {
    providerLabel: 'Service',
    providerPlaceholder: 'e.g. Sonarr',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  tracker: {
    providerLabel: 'Site',
    providerPlaceholder: 'e.g. a private tracker',
    showAccount: true,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  usenet_server: {
    providerLabel: 'Provider',
    providerPlaceholder: 'e.g. a Usenet provider',
    showAccount: true,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  wifi: {
    providerLabel: 'Network name (SSID)',
    providerPlaceholder: 'e.g. Home Wi-Fi',
    showAccount: false,
    keyLabel: 'Passphrase',
    keyPlaceholder: '',
  },
  license_key: {
    providerLabel: 'Product',
    providerPlaceholder: 'e.g. an app license',
    showAccount: false,
    keyLabel: 'Key',
    keyPlaceholder: '',
  },
  crypto_wallet: {
    providerLabel: 'Wallet name',
    providerPlaceholder: 'e.g. Cold wallet',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  passkey: {
    providerLabel: 'Site',
    providerPlaceholder: 'e.g. GitHub',
    showAccount: true,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  secure_note: {
    providerLabel: 'Title',
    providerPlaceholder: 'e.g. Recovery instructions',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
  identity_document: {
    providerLabel: 'Document',
    providerPlaceholder: 'e.g. Passport',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: '',
  },
};

// ── Dynamic form fields ───────────────────────────────────────────────────

export function dynamicSecretFields() {
  const type = (document.getElementById('f-secret-type') as HTMLSelectElement).value as SecretType;
  const cfg = TYPE_CONFIG[type] || TYPE_CONFIG.api_key;

  const keyGroup = document.getElementById('f-key-group');
  const keyLabelEl = document.getElementById('f-key-label');
  const secretGroup = document.getElementById('f-secret-group');
  const usernameRow = document.getElementById('f-username-row');
  const certGroup = document.getElementById('f-cert-group');
  const certKeyGroup = document.getElementById('f-cert-key-group');
  const certIssuerGroup = document.getElementById('f-cert-issuer-group');
  const blobGroup = document.getElementById('f-blob-group');
  const accountGroup = document.getElementById('f-account-group');
  const providerLabel = document.getElementById('f-provider-label');
  const providerInput = document.getElementById('f-provider') as HTMLInputElement | null;
  const envvarSubtypeGroup = document.getElementById('f-envvar-subtype-group');

  const showKey =
    type !== 'certificate' && type !== 'file_blob' && type !== 'composite' && type !== 'bundle';
  const showSecret = type === 'api_key';
  const showUser = type === 'password' || type === 'ssh_key';
  // A composite's payload is its template plus its parts (extra_vars); a
  // bundle's is entirely its members and its local variables (extra_vars).
  // Neither has a single primary value the way every other type does.
  const templateGroup = document.getElementById('f-template-group');
  if (templateGroup) templateGroup.style.display = type === 'composite' ? 'flex' : 'none';
  if (type === 'composite') refreshCompositePreview();

  if (keyGroup) keyGroup.style.display = showKey ? 'flex' : 'none';
  if (secretGroup) secretGroup.style.display = showSecret ? 'flex' : 'none';
  if (usernameRow) usernameRow.style.display = showUser ? 'grid' : 'none';
  if (certGroup) certGroup.style.display = type === 'certificate' ? 'flex' : 'none';
  if (certKeyGroup) certKeyGroup.style.display = type === 'certificate' ? 'flex' : 'none';
  if (certIssuerGroup) certIssuerGroup.style.display = type === 'certificate' ? 'flex' : 'none';
  if (blobGroup) blobGroup.style.display = type === 'file_blob' ? 'flex' : 'none';
  if (accountGroup) accountGroup.style.display = cfg.showAccount ? '' : 'none';
  if (envvarSubtypeGroup) envvarSubtypeGroup.style.display = type === 'env_var' ? 'flex' : 'none';
  // The User-Agent is shown for every type but *labelled* as required in
  // practice only on a cookie, where replay without the matching one 401s. It
  // stays visible elsewhere because an API client can have one too and hiding a
  // field is how a stored value becomes unreachable (invariant 7).
  const uaGroup = document.getElementById('f-user-agent-group');
  if (uaGroup) uaGroup.style.display = type === 'cookie' ? 'flex' : 'none';
  const storageTokensGroup = document.getElementById('f-storage-tokens-group');
  if (storageTokensGroup) storageTokensGroup.style.display = type === 'cookie' ? 'flex' : 'none';
  // The mount path is the delivery half of a file-shaped credential (E17): the
  // types whose payload is a file, plus `file_blob`, which held a path and never
  // the file.
  const mountGroup = document.getElementById('f-mount-path-group');
  if (mountGroup)
    mountGroup.style.display = type === 'certificate' || type === 'file_blob' ? 'flex' : 'none';
  // Rotation is meaningless for a session, so the cadence input is hidden for a
  // cookie (E13). Creation-only, like every other gate here: an existing
  // `rotation_days` is carried through by `formToEntry`'s spread rather than
  // being erased by a field the user cannot see.
  const rotationGroup = document.getElementById('f-rotation-days')?.closest('.form-group');
  if (rotationGroup instanceof HTMLElement)
    rotationGroup.style.display = type === 'cookie' ? 'none' : '';

  if (providerLabel) setHtml(providerLabel, html`${cfg.providerLabel} <span class="req">*</span>`);
  if (providerInput) providerInput.placeholder = cfg.providerPlaceholder;
  const keyInput = document.getElementById('f-key') as HTMLInputElement | null;
  if (keyInput && showKey) keyInput.placeholder = cfg.keyPlaceholder;
  if (keyLabelEl && showKey) refreshRequiredMarker(keyLabelEl, keyInput, cfg.keyLabel);
}

/**
 * A5 (2026-09-14): the `*` on the value label, and `aria-required` on the
 * field itself, used to be static — written once by `dynamicSecretFields`
 * from `cfg.keyLabel` and never touched again, so an `env_var` entry with a
 * named variable (or any entry carrying a seed) still showed "required"
 * although `primaryIsOptional` — the one predicate that decides whether the
 * form insists on the primary slot — already said it was not.
 *
 * Reads the form's current state into the shape `primaryIsOptional` expects,
 * so there is exactly one place that answers "is the value optional right
 * now" and this is a consumer of it, not a second copy of the logic.
 */
function refreshRequiredMarker(
  labelEl: HTMLElement,
  keyInput: HTMLInputElement | null,
  label: string,
): void {
  const type = (document.getElementById('f-secret-type') as HTMLSelectElement | null)?.value as
    SecretType | undefined;
  const extra_vars = [
    ...document.querySelectorAll<HTMLInputElement>('#f-extra-vars-list .extra-var-key'),
  ]
    .map((el) => ({ key: el.value.trim() }))
    .filter((v) => v.key);
  const totp_secret =
    (document.getElementById('f-totp') as HTMLInputElement | null)?.value.trim() || undefined;
  const optional = primaryIsOptional({ secretType: type, extra_vars, totp_secret } as VaultEntry);
  setHtml(
    labelEl,
    optional
      ? html`${label} <span class="opt">optional</span>`
      : html`${label} <span class="req">*</span>`,
  );
  if (keyInput) {
    if (optional) keyInput.removeAttribute('aria-required');
    else keyInput.setAttribute('aria-required', 'true');
  }
}

// ── Form to entry & fill form ─────────────────────────────────────────────

/**
 * Read the add/edit form into an entry.
 *
 * **`base` is spread first and the form's values overwrite it** (Phase 23, E4).
 * Before this the function returned a freshly constructed object literal with no
 * spread at all, so every field the form has no input for survived only if the
 * *save path* remembered to re-attach it by name — and it re-attached five.
 * Editing an entry's description therefore erased its `pool`, and every field a
 * later phase adds would be erased the same way, silently, on the first edit.
 *
 * A field the form *does* have an input for is present in the literal even when
 * the input is empty, so clearing a box still clears the field: object spread
 * copies a key whose value is `undefined`.
 */
export function formToEntry(base?: VaultEntry): VaultEntry {
  const getVal = (id: string, fallback = '') => {
    const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null;
    return el?.value?.trim?.() ?? fallback;
  };
  const baseVars = new Map((base?.extra_vars ?? []).map((variable) => [variable.key, variable]));

  const scopes = getVal('f-scopes')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const cats = [...document.querySelectorAll<HTMLElement>('#f-categories .cat-chip.selected')].map(
    (c) => c.textContent!,
  );
  // A11: an unrecognised type leaves the select at `''` (no matching
  // `<option>`) — fall back to the base entry's real value, verbatim, rather
  // than `api_key`. `saveModal` also refuses outright while this is set; this
  // fallback is defence in depth for any other caller of `formToEntry`.
  const secretType = (getVal('f-secret-type') ||
    _unknownSecretType ||
    base?.secretType ||
    'api_key') as SecretType;

  const selectedProjectIds = [
    ...document.querySelectorAll<HTMLElement>('#f-project .project-pick-item.selected'),
  ]
    .map((el) => el.dataset.value!)
    .filter(Boolean);

  return {
    ...base,
    provider: getVal('f-provider'),
    account_name: getVal('f-account') || undefined,
    username: getVal('f-username') || undefined,
    email: getVal('f-email') || undefined,
    api_key: getVal('f-key'),
    api_secret: getVal('f-secret') || undefined,
    key_id: getVal('f-keyid') || undefined,
    primary_role: getVal('f-role') || undefined,
    secret_role: getVal('f-secret-role') || undefined,
    label: getVal('f-label') || undefined,
    auth_scheme: (getVal('f-auth-scheme') as VaultEntry['auth_scheme']) || undefined,
    auth_param: getVal('f-auth-param') || undefined,
    auth_template: getVal('f-auth-template') || undefined,
    user_agent: getVal('f-user-agent') || undefined,
    ...(secretType === 'cookie'
      ? { storage_tokens: parseStorageTokens(getVal('f-storage-tokens')) }
      : {}),
    mount_path: getVal('f-mount-path') || undefined,
    composite_template: secretType === 'composite' ? getVal('f-template') || undefined : undefined,
    composite_kind:
      secretType === 'composite'
        ? ((getVal('f-template-kind') as VaultEntry['composite_kind']) ?? undefined)
        : undefined,
    price_type: getVal('f-price', 'free') as VaultEntry['price_type'],
    environment: (getVal('f-env') as VaultEntry['environment']) || undefined,
    projectIds: selectedProjectIds.includes('Universal')
      ? selectedProjectIds
      : ['Universal', ...selectedProjectIds],
    api_url: getVal('f-apiurl') || undefined,
    callback_url: getVal('f-cburl') || undefined,
    version: getVal('f-version') || undefined,
    // The rate limit is three fields that must agree, so it is read as a unit
    // and normalised rather than field by field. `normalizeRateLimit` also
    // regenerates the legacy `rate_limit` string from the pair, which is what
    // keeps a vault edited here readable to an older build.
    ...(() => {
      const rl = normalizeRateLimit({
        rate_limit_count: getVal('f-ratelimit') ? Number(getVal('f-ratelimit')) : undefined,
        rate_limit_period: getVal('f-ratelimit-period') || undefined,
        // The note is only ever carried, never typed: it holds whatever the old
        // free-text field said when it could not be read as a number and a
        // period, and the form has no input for it.
        rate_limit: pendingRateLimitNote,
      });
      return {
        rate_limit: rl.rate_limit || undefined,
        rate_limit_count: rl.rate_limit_count ?? undefined,
        rate_limit_period: rl.rate_limit_period ?? undefined,
        rate_limit_note: rl.rate_limit_note || undefined,
      };
    })(),
    purpose: getVal('f-purpose') || undefined,
    pool: getVal('f-pool') || undefined,
    expires_at: getVal('f-expires') || undefined,
    rotation_days: getVal('f-rotation-days')
      ? parseInt(getVal('f-rotation-days')) || undefined
      : undefined,
    compromised:
      (document.getElementById('f-compromised') as HTMLInputElement | null)?.checked || undefined,
    scopes,
    api_description: getVal('f-apidesc') || undefined,
    description: getVal('f-desc') || undefined,
    details: getVal('f-details') || undefined,
    custom_icon: readIconField(document.getElementById('f-icon') as HTMLInputElement | null),
    categories: cats,
    tags: getVal('f-tags-input').split(/\s+/).filter(Boolean).length
      ? getVal('f-tags-input').split(/\s+/).filter(Boolean)
      : undefined,
    secretType,
    certificate_data: secretType === 'certificate' ? getVal('f-cert') : undefined,
    cert_key_data: secretType === 'certificate' ? getVal('f-cert-key') || undefined : undefined,
    cert_issuer: secretType === 'certificate' ? getVal('f-cert-issuer') || undefined : undefined,
    blob_ref: secretType === 'file_blob' ? getVal('f-blob') : undefined,
    env_var_subtype:
      secretType === 'env_var'
        ? (getVal('f-envvar-subtype') as VaultEntry['env_var_subtype']) || undefined
        : undefined,
    // The seed and its three parameters are read as a unit and normalised, the
    // same way the rate limit is: a pasted `otpauth://` URI carries all four,
    // and applying them field by field lets a period left over from a previous
    // issuer survive onto a seed that does not use it.
    ...readTotpFields(),
    extra_vars: (() => {
      const rows = [...document.querySelectorAll<HTMLElement>('#f-extra-vars-list .extra-var-row')];
      const result = rows
        .map((row) => {
          const key = row.querySelector<HTMLInputElement>('.extra-var-key')?.value.trim() || '';
          const prior = baseVars.get(key) ?? baseVars.get(row.dataset.originalKey ?? '');
          return {
            ...prior,
            key,
            value: row.querySelector<HTMLInputElement>('.extra-var-value')?.value.trim() || '',
            secret: row.querySelector<HTMLInputElement>('.extra-var-secret')?.checked || false,
            public: row.querySelector<HTMLInputElement>('.extra-var-public')?.checked || undefined,
            // Cookie attributes have no input of their own — nobody hand-types an
            // expiry in Unix seconds — so they ride on the row from the paste
            // parser and are carried through here. Without this they would be lost
            // on the first edit and `cookies.txt` would start refusing.
            attrs: (() => {
              try {
                return row.dataset.cookieAttrs
                  ? (JSON.parse(row.dataset.cookieAttrs) as VaultEntry['extra_vars'] extends
                      (infer R)[] | undefined
                      ? R extends { attrs?: infer A }
                        ? A
                        : never
                      : never)
                  : prior?.attrs;
              } catch {
                return undefined;
              }
            })(),
          };
        })
        .filter((v) => v.key);
      return result.length ? result : undefined;
    })(),
    env_prefixes: (() => {
      const raw = getVal('f-env-prefixes');
      const parts = raw
        .split(/[,\s]+/)
        .map((p) => p.trim().replace(/_+$/, ''))
        .filter(Boolean);
      return parts.length ? parts : undefined;
    })(),
  };
}

function parseStorageTokens(raw: string): NonNullable<VaultEntry['storage_tokens']> {
  if (!raw.trim()) return [];
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error('Browser storage tokens must be a JSON array');
  return parsed.map((item) => {
    if (!item || typeof item !== 'object') throw new Error('Invalid browser storage token');
    const { origin, storage, key, value } = item as Record<string, unknown>;
    if (
      typeof origin !== 'string' ||
      typeof key !== 'string' ||
      !key ||
      typeof value !== 'string' ||
      (storage !== 'local' && storage !== 'session')
    )
      throw new Error('Invalid browser storage token');
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw new Error('Token origin must be an exact http(s) origin');
    }
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.origin !== origin)
      throw new Error('Token origin must be an exact http(s) origin');
    return { origin, storage, key, value };
  });
}

/**
 * The four TOTP fields of the form, as the entry writes them.
 *
 * An unreadable seed is **kept as typed** rather than dropped: `saveModal`
 * refuses the save and says why, and a form that silently discarded the field
 * would leave the user staring at an empty box with no idea it had rejected
 * anything. `validateTotpField` is what decides; this only reads.
 *
 * Parameters equal to the defaults are written as `undefined`, i.e. absent. A
 * `totp_algorithm: 'SHA1'` on every entry cannot be told apart from a defaulted
 * one, and then nothing can say whether the issuer chose it or we did.
 */
function readTotpFields(): Pick<
  VaultEntry,
  'totp_secret' | 'totp_algorithm' | 'totp_digits' | 'totp_period' | 'totp_kind' | 'totp_counter'
> {
  const raw = (document.getElementById('f-totp') as HTMLInputElement | null)?.value?.trim() ?? '';
  const none = {
    totp_secret: undefined,
    totp_algorithm: undefined,
    totp_digits: undefined,
    totp_period: undefined,
    totp_kind: undefined,
    totp_counter: undefined,
  };
  if (!raw) return none;
  let parsed: ReturnType<typeof parseTotpSeed>;
  try {
    parsed = parseTotpSeed(raw);
  } catch {
    // Unusable: carry the text through so the user can fix it. saveModal stops
    // it reaching the vault.
    return { ...none, totp_secret: raw };
  }
  const num = (id: string) => {
    const v = (document.getElementById(id) as HTMLInputElement | null)?.value?.trim() ?? '';
    const n = Number(v);
    return v && Number.isInteger(n) ? n : null;
  };
  const algo =
    ((document.getElementById('f-totp-algorithm') as HTMLSelectElement | null)?.value as
      VaultEntry['totp_algorithm'] | undefined) || parsed.algorithm;
  const digits = num('f-totp-digits') ?? parsed.digits;
  const period = num('f-totp-period') ?? parsed.period;
  const kind =
    ((document.getElementById('f-totp-kind') as HTMLSelectElement | null)?.value as
      VaultEntry['totp_kind'] | undefined) || parsed.kind;
  const counter = num('f-totp-counter') ?? parsed.counter;
  // Steam fixes its own shape, so the three parameter boxes describe nothing for
  // it; writing what they happen to hold would store a seed that validates and
  // produces characters Steam rejects.
  if (kind === 'steam') {
    return {
      ...none,
      totp_secret: parsed.secret,
      totp_kind: 'steam',
    };
  }
  return {
    totp_secret: parsed.secret,
    totp_algorithm: algo === TOTP_DEFAULTS.algorithm ? undefined : algo,
    totp_digits: digits === TOTP_DEFAULTS.digits ? undefined : digits,
    totp_period: period === TOTP_DEFAULTS.period ? undefined : period,
    totp_kind: kind === TOTP_DEFAULTS.kind ? undefined : kind,
    // A counter is state and is written whenever the seed is counter-based,
    // zero included — zero is a real position, not an absent one.
    totp_counter: kind === 'hotp' ? Math.max(0, counter) : undefined,
  };
}

/**
 * Repaint the seed field's status line, and reveal the parameter row when the
 * seed is not on the default settings.
 *
 * The status line is the whole of the feedback: an `otpauth://` URI is 120
 * characters of which four matter, and a form that accepts one silently gives
 * the user no way to know whether it read the right issuer — or read it at all.
 * It never prints the seed.
 */
export function refreshTotpStatus(): void {
  const input = document.getElementById('f-totp') as HTMLInputElement | null;
  const status = document.getElementById('f-totp-status');
  const params = document.getElementById('f-totp-params');
  const kindRow = document.getElementById('f-totp-kind-row');
  const counterWrap = document.getElementById('f-totp-counter-wrap');
  if (!input || !status) return;
  const raw = input.value.trim();
  status.classList.remove('err');
  if (!raw) {
    status.textContent = '';
    if (params) params.hidden = true;
    if (kindRow) kindRow.hidden = true;
    return;
  }
  let parsed;
  try {
    parsed = parseTotpSeed(raw);
  } catch (e) {
    status.textContent = `Not a usable seed: ${(e as Error).message}`;
    status.classList.add('err');
    if (params) params.hidden = false;
    return;
  }
  // Bug 7 (2026-09-15): "some 2FA codes are wrong" traced to this condition.
  // It used to be `raw !== parsed.secret` — true only when the parser had to
  // *rewrite* the input (an otpauth:// URI split apart, or a seed typed with
  // stray spaces/case normalised away). A seed pasted already in its final,
  // normalised form never took this branch, so replacing an entry's seed with
  // an unrelated one left the algorithm/digits/period/kind selects showing
  // whatever the *previous* seed's form session had put there — silently
  // applying a stranger's algorithm to a fresh secret, which produces six
  // confident, wrong digits with nothing on screen explaining why.
  //
  // The correct question is "did the seed *value* change since we last read
  // it", tracked on the input itself so it survives across renders. Every
  // real algorithm/digits/period/kind change for THIS secret (whether from an
  // `otpauth://` URI or the true bare-seed default of SHA1/6/30) is applied
  // exactly once, right when the secret changes — and only then, so a value
  // the user set by hand afterwards (and left the seed alone) is never
  // clobbered by a later, unrelated re-render of this same status line.
  const secretChanged = input.dataset.totpLastSecret !== parsed.secret;
  if (secretChanged) {
    input.dataset.totpLastSecret = parsed.secret;
    input.value = parsed.secret;
    setSelect('f-totp-algorithm', parsed.algorithm);
    setNumber('f-totp-digits', parsed.digits);
    setNumber('f-totp-period', parsed.period);
    // A pasted `otpauth://hotp/` or `//steam/` URI names the kind, and its
    // counter is the half that must survive: a counter-based seed read back at
    // zero is a second factor that fails until the account is resynced.
    setSelect('f-totp-kind', parsed.kind);
    setNumber('f-totp-counter', parsed.counter);
  }
  const kind =
    (document.getElementById('f-totp-kind') as HTMLSelectElement | null)?.value || parsed.kind;
  // The kind row appears as soon as there is a seed to describe: it is how a
  // user creates a counter-based or Steam entry from the app at all, and
  // without it that capability would exist only in the CLI (invariant 10).
  if (kindRow) kindRow.hidden = false;
  if (counterWrap) counterWrap.hidden = kind !== 'hotp';
  if (kind === 'steam') {
    // Steam fixes SHA-1, five characters and a 30-second step. Showing three
    // boxes that change nothing invites the user to set them and wonder why the
    // codes are rejected.
    status.textContent = `Steam Guard · 5 characters${parsed.issuer ? ` · from ${parsed.issuer}` : ''}`;
    if (params) params.hidden = true;
    return;
  }
  const algo =
    (document.getElementById('f-totp-algorithm') as HTMLSelectElement | null)?.value ||
    parsed.algorithm;
  const digits =
    (document.getElementById('f-totp-digits') as HTMLInputElement | null)?.value || parsed.digits;
  const period =
    (document.getElementById('f-totp-period') as HTMLInputElement | null)?.value || parsed.period;
  const from = parsed.issuer ? ` · from ${parsed.issuer}` : '';
  const counter =
    (document.getElementById('f-totp-counter') as HTMLInputElement | null)?.value ||
    String(parsed.counter);
  status.textContent =
    kind === 'hotp'
      ? `${digits} digits · ${algo} · counter-based, next #${counter}${from}`
      : `${digits} digits · ${algo} · every ${period}s${from}`;
  const nonDefault =
    String(algo) !== TOTP_DEFAULTS.algorithm ||
    Number(digits) !== TOTP_DEFAULTS.digits ||
    Number(period) !== TOTP_DEFAULTS.period;
  if (params) params.hidden = !nonDefault;
}

function setSelect(id: string, value: string): void {
  const el = document.getElementById(id) as HTMLSelectElement | null;
  if (el) el.value = value;
}

function setNumber(id: string, value: number): void {
  const el = document.getElementById(id) as HTMLInputElement | null;
  if (el) el.value = String(value);
}

/**
 * Wire the seed field's live feedback and its reveal button.
 *
 * Assigned, never added (invariant 9): `openAdd` runs on every modal open, and
 * `addEventListener` here would stack one handler per open — the failure that
 * shows up as a reveal toggle flipping an even number of times and appearing to
 * do nothing.
 */
export function wireTotpField(): void {
  const input = document.getElementById('f-totp') as HTMLInputElement | null;
  const reveal = document.getElementById('f-totp-reveal') as HTMLButtonElement | null;
  // A5: a seed is one of the shapes `primaryIsOptional` recognises (an
  // imported entry whose password lives elsewhere), so typing or clearing one
  // must re-check whether the primary value is still required.
  const refresh = () => {
    refreshTotpStatus();
    dynamicSecretFields();
  };
  if (input) {
    input.oninput = refresh;
    input.onchange = refresh;
    // A URI arrives by paste, and `paste` fires before the value lands.
    input.onpaste = () => setTimeout(refresh, 0);
  }
  for (const id of [
    'f-totp-algorithm',
    'f-totp-digits',
    'f-totp-period',
    'f-totp-kind',
    'f-totp-counter',
  ]) {
    const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null;
    if (el) el.onchange = () => refreshTotpStatus();
  }
  if (reveal && input) {
    reveal.onclick = () => {
      const showing = input.type === 'text';
      input.type = showing ? 'password' : 'text';
      reveal.setAttribute('aria-pressed', String(!showing));
      reveal.classList.toggle('active', !showing);
    };
  }
}

/**
 * Re-mask the seed field and clear its status.
 *
 * Called on every open, not only on close: a reveal toggle left on shows the
 * seed on every later visit to the form, and the form is opened from a card the
 * user may be showing somebody.
 */
export function resetTotpField(): void {
  const input = document.getElementById('f-totp') as HTMLInputElement | null;
  const reveal = document.getElementById('f-totp-reveal') as HTMLButtonElement | null;
  if (input) input.type = 'password';
  if (reveal) {
    reveal.setAttribute('aria-pressed', 'false');
    reveal.classList.remove('active');
  }
}

/**
 * The real `secretType` of the entry currently open, when this build has no
 * `<option>` for it — `null` in the ordinary case. Read by `formToEntry` (to
 * preserve it rather than defaulting to `api_key`) and by `saveModal` (to
 * refuse outright). Reset on every `fillForm` call, including `openAdd`'s,
 * where it is always `null` — a *new* entry can only ever be a type this form
 * offers.
 */
let _unknownSecretType: string | null = null;

/** A11: shows or hides the "made by a newer UnENVerse" banner and (dis)ables Save. */
function applyUnknownSecretType(rawType: string | null): void {
  _unknownSecretType = rawType;
  const banner = document.getElementById('f-unknown-type-banner');
  const saveBtn = document.getElementById('modal-save') as HTMLButtonElement | null;
  if (banner) {
    banner.hidden = !rawType;
    const p = banner.querySelector('p');
    if (p && rawType)
      p.textContent = `This entry's type ("${rawType}") was made by a newer UnENVerse — update to edit it. Everything else here is safe to view.`;
  }
  if (saveBtn) {
    saveBtn.disabled = !!rawType;
    saveBtn.title = rawType ? 'Update UnENVerse to edit this entry' : '';
  }
}

export function fillForm(entry: Partial<VaultEntry>) {
  (document.getElementById('f-provider') as HTMLInputElement).value = entry.provider || '';
  (document.getElementById('f-account') as HTMLInputElement).value =
    entry.account_name || Settings.get('defaultAccount') || '';
  (document.getElementById('f-username') as HTMLInputElement).value = entry.username || '';
  (document.getElementById('f-email') as HTMLInputElement).value = entry.email || '';
  (document.getElementById('f-key') as HTMLInputElement).value = entry.api_key || '';
  (document.getElementById('f-secret') as HTMLInputElement).value = entry.api_secret || '';
  (document.getElementById('f-keyid') as HTMLInputElement).value = entry.key_id || '';
  const fPrice = document.getElementById('f-price') as HTMLSelectElement;
  fPrice.value = entry.price_type || 'free';
  st.formCustomSelects.get('f-price')?.setValue(entry.price_type || 'free');
  const fEnv = document.getElementById('f-env') as HTMLSelectElement;
  fEnv.value = entry.environment || '';
  st.formCustomSelects.get('f-env')?.setValue(entry.environment || '');
  if (entry.projectIds) {
    document.querySelectorAll<HTMLElement>('#f-project .project-pick-item').forEach((el) => {
      const on = entry.projectIds!.includes(el.dataset.value!);
      el.classList.toggle('selected', on);
      el.setAttribute('aria-selected', String(on));
    });
  }
  (document.getElementById('f-apiurl') as HTMLInputElement).value = entry.api_url || '';
  (document.getElementById('f-cburl') as HTMLInputElement).value = entry.callback_url || '';
  (document.getElementById('f-version') as HTMLInputElement).value = entry.version || '';
  (document.getElementById('f-role') as HTMLInputElement).value = entry.primary_role || '';
  (document.getElementById('f-secret-role') as HTMLInputElement).value = entry.secret_role || '';
  (document.getElementById('f-label') as HTMLInputElement).value = entry.label || '';
  (document.getElementById('f-auth-scheme') as HTMLSelectElement).value = entry.auth_scheme || '';
  (document.getElementById('f-auth-param') as HTMLInputElement).value = entry.auth_param || '';
  (document.getElementById('f-auth-template') as HTMLInputElement).value =
    entry.auth_template || '';
  (document.getElementById('f-user-agent') as HTMLInputElement).value = entry.user_agent || '';
  const storageTokens = document.getElementById('f-storage-tokens') as HTMLTextAreaElement | null;
  if (storageTokens) storageTokens.value = JSON.stringify(entry.storage_tokens ?? [], null, 2);
  (document.getElementById('f-mount-path') as HTMLInputElement).value = entry.mount_path || '';
  const fTemplate = document.getElementById('f-template') as HTMLTextAreaElement | null;
  if (fTemplate) fTemplate.value = entry.composite_template || '';
  const fTemplateKind = document.getElementById('f-template-kind') as HTMLSelectElement | null;
  if (fTemplateKind) fTemplateKind.value = entry.composite_kind || 'link';
  // Normalised on read, not trusted: this entry may have been written by an
  // older build that only had the free-text field, by a remote server, or by an
  // imported backup. `normalizeRateLimit` is the one reader (CLAUDE.md
  // invariant 4 — vault data is untrusted input and the TS union is erased).
  const rl = normalizeRateLimit(entry);
  (document.getElementById('f-ratelimit') as HTMLInputElement).value =
    rl.rate_limit_count == null ? '' : String(rl.rate_limit_count);
  const rlPeriod = document.getElementById('f-ratelimit-period') as HTMLSelectElement | null;
  if (rlPeriod) rlPeriod.value = rl.rate_limit_period || '';
  // Text the number/period pair cannot express is shown beneath the inputs and
  // carried through the next save. Dropping it would lose what the user wrote.
  pendingRateLimitNote = rl.rate_limit_note || '';
  const rlNote = document.getElementById('f-ratelimit-note');
  if (rlNote) {
    rlNote.textContent = pendingRateLimitNote ? `was: ${pendingRateLimitNote}` : '';
    rlNote.hidden = !pendingRateLimitNote;
  }
  const fTotp = document.getElementById('f-totp') as HTMLInputElement | null;
  if (fTotp) {
    fTotp.value = entry.totp_secret || '';
    // Bug 7 (2026-09-15): this entry's own params (or the absent-field
    // defaults, for a new entry) are what `refreshTotpStatus` must treat as
    // "already applied" — see the comment there. Setting it here, before that
    // function ever runs for this opening, is what stops it re-deriving
    // params from the bare seed alone (which can only ever produce SHA1/6/30,
    // never what this entry actually has stored).
    fTotp.dataset.totpLastSecret = normalizeB32(fTotp.value);
  }
  setSelect('f-totp-kind', entry.totp_kind || TOTP_DEFAULTS.kind);
  setNumber('f-totp-counter', entry.totp_counter ?? TOTP_DEFAULTS.counter);
  setSelect('f-totp-algorithm', entry.totp_algorithm || TOTP_DEFAULTS.algorithm);
  setNumber('f-totp-digits', entry.totp_digits || TOTP_DEFAULTS.digits);
  setNumber('f-totp-period', entry.totp_period || TOTP_DEFAULTS.period);
  resetTotpField();
  refreshTotpStatus();
  (document.getElementById('f-purpose') as HTMLInputElement).value = entry.purpose || '';
  (document.getElementById('f-pool') as HTMLInputElement).value = entry.pool || '';
  (document.getElementById('f-expires') as HTMLInputElement).value = entry.expires_at || '';
  const rotEl = document.getElementById('f-rotation-days') as HTMLInputElement | null;
  if (rotEl) rotEl.value = entry.rotation_days ? String(entry.rotation_days) : '';
  const compEl = document.getElementById('f-compromised') as HTMLInputElement | null;
  if (compEl) compEl.checked = !!entry.compromised;
  (document.getElementById('f-scopes') as HTMLInputElement).value = (entry.scopes || []).join(', ');
  (document.getElementById('f-apidesc') as HTMLInputElement).value = entry.api_description || '';
  (document.getElementById('f-desc') as HTMLInputElement).value = entry.description || '';
  (document.getElementById('f-details') as HTMLInputElement).value = entry.details || '';
  setIconField(document.getElementById('f-icon') as HTMLInputElement | null, entry.custom_icon);
  const tagsInput = document.getElementById('f-tags-input') as HTMLInputElement | null;
  if (tagsInput) tagsInput.value = (entry.tags || []).join(' ');
  setHtml(
    document.getElementById('f-icon-preview')!,
    entry.custom_icon ? iconHTML('', entry.custom_icon) : '',
  );
  const stVal = entry.secretType || 'api_key';
  const stSelect = document.getElementById('f-secret-type') as HTMLSelectElement;
  stSelect.value = stVal;
  st.formCustomSelects.get('f-secret-type')?.setValue(stVal);
  // A11 (2026-09-14): a `<select>` handed a value it has no `<option>` for
  // reads back as the empty string — `stSelect.value` silently did not become
  // `stVal`. That is exactly what an entry saved by a newer UnENVerse with a
  // type this build has never heard of looks like (24.1's `composite`, or any
  // of 24.5's sixteen), and saving over it used to rewrite the entry as
  // `api_key` with nobody told. Lock the form instead: preserve the real
  // value verbatim (`formToEntry`'s `base` fallback) and refuse to save.
  applyUnknownSecretType(stSelect.value === stVal ? null : stVal);
  if (entry.secretType === 'certificate') {
    (document.getElementById('f-cert') as HTMLInputElement).value = entry.certificate_data || '';
    (document.getElementById('f-cert-key') as HTMLInputElement).value = entry.cert_key_data || '';
    (document.getElementById('f-cert-issuer') as HTMLInputElement).value = entry.cert_issuer || '';
  }
  if (entry.secretType === 'file_blob')
    (document.getElementById('f-blob') as HTMLInputElement).value = entry.blob_ref || '';
  if (entry.secretType === 'env_var') {
    const envSubtype = document.getElementById('f-envvar-subtype') as HTMLSelectElement | null;
    if (envSubtype) envSubtype.value = entry.env_var_subtype || 'string';
  }
  const extraList = document.getElementById('f-extra-vars-list');
  if (extraList) {
    setHtml(extraList, '');
    for (const xv of entry.extra_vars || []) {
      const row = _makeExtraVarRow(xv.key, xv.value, xv.secret, xv.public);
      row.dataset.originalKey = xv.key;
      if (xv.attrs) row.dataset.cookieAttrs = JSON.stringify(xv.attrs);
      extraList.appendChild(row);
    }
  }
  const pfxInput = document.getElementById('f-env-prefixes') as HTMLInputElement | null;
  if (pfxInput) pfxInput.value = (entry.env_prefixes || []).join(', ');
  dynamicSecretFields();
}

export function populateProjectSelect() {
  const container = document.getElementById('f-project')!;
  const cats = st.vault.projects.filter((p) => p.id !== 'Universal');
  setHtml(
    container,
    html`${cats.map(
      (p) =>
        html`<div
          class="project-pick-item"
          role="option"
          aria-selected="false"
          tabindex="-1"
          data-value="${p.id}"
        >${p.name}</div>`,
    )}`,
  );
  const items = Array.from(container.querySelectorAll<HTMLElement>('.project-pick-item'));
  const toggle = (item: HTMLElement) => {
    const on = item.classList.toggle('selected');
    item.setAttribute('aria-selected', String(on));
  };
  items.forEach((item, i) => {
    item.addEventListener('click', () => toggle(item));
    // This replaced a `<select multiple>` (WebKitGTK renders a ghost native
    // listbox for those), and the native control was keyboard-operable. Space
    // toggles, arrows move — without this, project assignment is mouse-only.
    item.addEventListener('keydown', (e) => {
      if (e.key === ' ' || e.key === 'Enter') {
        e.preventDefault();
        toggle(item);
      } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        const next = items[(i + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length];
        next.tabIndex = 0;
        item.tabIndex = -1;
        next.focus();
      }
    });
  });
  // One item in the list is tabbable; arrows reach the rest. A listbox where
  // every option is a tab stop makes a twenty-project vault twenty Tab presses
  // deep.
  if (items[0]) items[0].tabIndex = 0;
}

// ── The generated-name preview ────────────────────────────────────────────

/**
 * What a `label` may be.
 *
 * Narrow on purpose: it is a *name segment*, so anything that would normalise
 * away (spaces, punctuation, an empty leading character) is refused at the form
 * rather than silently transliterated into something the user did not type.
 */
export const LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,23}$/;

/**
 * Paint the "Generated variable" line under the value field.
 *
 * The template has five inputs feeding it — provider, key id, version, label,
 * role — and before this the only way to find out what they produced was to run
 * a copy and read the file. The value is shown as dots: the point is the
 * **name**, and a form that prints the secret next to it is a form that puts it
 * in a screenshot.
 */
export function updateNamePreview(): void {
  const out = document.getElementById('f-name-preview');
  if (!out) return;
  const get = (id: string) =>
    (document.getElementById(id) as HTMLInputElement | null)?.value.trim() ?? '';

  const draft = {
    provider: get('f-provider'),
    key_id: get('f-keyid') || undefined,
    version: get('f-version') || undefined,
    label: get('f-label') || undefined,
    primary_role: get('f-role') || undefined,
    secret_role: get('f-secret-role') || undefined,
  } as VaultEntry;

  const lines = [`${primaryEnvName(draft)}=••••••`];
  if (get('f-secret')) lines.push(`${secretEnvName(draft)}=••••••`);
  out.textContent = lines.join('\n');

  // A label that cannot be a segment is refused at save, so say so as it is
  // typed rather than at the moment the user presses the button.
  const labelEl = document.getElementById('f-label') as HTMLInputElement | null;
  const bad = !!labelEl?.value.trim() && !LABEL_RE.test(labelEl.value.trim());
  labelEl?.classList.toggle('input-invalid', bad);
  out.classList.toggle('env-name-preview-invalid', bad);

  // E2 — collision, live. Two entries generating one variable name is a silent
  // overwrite in whatever loads the file, and the only moment the user can
  // cheaply avoid it is while they are choosing the name.
  const note = document.getElementById('f-name-collision');
  if (note) {
    const editing = parseInt(
      (document.getElementById('edit-index') as HTMLInputElement | null)?.value ?? '-1',
    );
    const others = (st.vault?.api_keys ?? []).filter((_, i) => i !== editing);
    const mine = new Set(namesGeneratedBy(draft).map((g) => g.name.toUpperCase()));
    const clashes = others.filter((e) =>
      namesGeneratedBy(e).some((g) => mine.has(g.name.toUpperCase())),
    );
    note.textContent = clashes.length
      ? `Also generated by ${clashes
          .slice(0, 3)
          .map((e) => e.provider)
          .join(
            ', ',
          )}${clashes.length > 3 ? ` and ${clashes.length - 3} more` : ''} — a copy of both would overwrite one`
      : '';
    note.hidden = clashes.length === 0;
  }
}

/**
 * Live preview for a `composite` entry's template (Phase 24.1).
 *
 * Reads the same `#f-extra-vars-list` rows `formToEntry` does — parts *are*
 * `extra_vars`, so there is nowhere else this could read from without
 * building a second copy of "what are the current rows" (invariant already
 * established by E4's `formToEntry`).
 */
export function refreshCompositePreview(): void {
  const out = document.getElementById('f-template-preview');
  if (!out) return;
  const template =
    (document.getElementById('f-template') as HTMLTextAreaElement | null)?.value ?? '';
  const kind =
    ((document.getElementById('f-template-kind') as HTMLSelectElement | null)
      ?.value as CompositeKind) || 'link';
  if (!template) {
    out.textContent = '';
    return;
  }
  const parts = [
    ...document.querySelectorAll<HTMLElement>('#f-extra-vars-list .extra-var-row'),
  ].map((row) => ({
    key: row.querySelector<HTMLInputElement>('.extra-var-key')?.value.trim() || '',
    value: row.querySelector<HTMLInputElement>('.extra-var-value')?.value || '',
  }));
  const res = renderComposite(template, parts, kind);
  if (res.ok) {
    out.textContent = res.result.text;
    out.classList.remove('env-name-preview-invalid');
    if (res.result.unused.length) out.textContent += `  (unused: ${res.result.unused.join(', ')})`;
  } else {
    out.textContent = renderErrorMessage(res.error);
    out.classList.add('env-name-preview-invalid');
  }
}

/**
 * The cookie paste helper.
 *
 * Dropping a raw `document.cookie` string, a DevTools "Copy all as JSON" or a
 * `cookies.txt` into the value field and pressing this splits it into one
 * `extra_vars` row per cookie, attributes and all.
 *
 * Splitting is **offered, never automatic**. A jar in one field is a perfectly
 * good way to store a session — it is what the `Cookie:` header wants — and
 * rewriting the user's value the moment they paste is the kind of help that
 * loses a character they had fixed by hand. The status line says what was found
 * and, when the attributes are missing, what that costs.
 */
function refreshCookieSplit(): void {
  const group = document.getElementById('f-cookie-split-group');
  const status = document.getElementById('f-cookie-split-status');
  if (!group || !status) return;
  const isCookie =
    (document.getElementById('f-secret-type') as HTMLSelectElement | null)?.value === 'cookie';
  const raw = (document.getElementById('f-key') as HTMLInputElement | null)?.value ?? '';
  const jar = isCookie ? parseAnyCookies(raw) : [];
  group.style.display = isCookie && jar.length > 0 ? 'flex' : 'none';
  if (!jar.length) return;
  const missing = missingTxtAttributes(jar);
  status.textContent = missing.length
    ? `${jar.length} cookie${jar.length === 1 ? '' : 's'} — no ${missing.join(' or ')}, so cookies.txt cannot be written`
    : `${jar.length} cookie${jar.length === 1 ? '' : 's'}, with domain and path`;
}

interface SessionCapture {
  origin: string | null;
  cookies: {
    name: string;
    value: string;
    domain: string | null;
    path: string | null;
    secure: boolean;
    http_only: boolean;
    expires: number;
  }[];
  headers: [string, string][];
  user_agent: string | null;
  dropped: string[];
}

/** Fills the form from a parsed capture. Replaces the cookie rows (pressing it
 * twice must not duplicate them) and never touches a field the capture lacks. */
function applySessionCapture(cap: SessionCapture): void {
  const list = document.getElementById('f-extra-vars-list');
  if (!list) return;
  setHtml(list, '');
  for (const c of cap.cookies) {
    const row = _makeExtraVarRow(c.name, c.value, true, false);
    const attrs: Record<string, unknown> = {};
    if (c.domain) attrs.domain = c.domain;
    if (c.path) attrs.path = c.path;
    if (c.secure) attrs.secure = true;
    if (c.http_only) attrs.http_only = true;
    if (c.expires) attrs.expires = c.expires;
    if (Object.keys(attrs).length) row.dataset.cookieAttrs = JSON.stringify(attrs);
    list.appendChild(row);
  }
  const ua = document.getElementById('f-user-agent') as HTMLInputElement | null;
  if (ua && cap.user_agent) ua.value = cap.user_agent;
  const url = document.getElementById('f-apiurl') as HTMLInputElement | null;
  if (url && cap.origin && !url.value) url.value = cap.origin;
  dynamicSecretFields();
}

/**
 * How the common self-hosted apps want their API key (Phase 24.5,
 * `local_service`). Only conventions that are stable and widely documented are
 * listed. Jellyfin's `Authorization: MediaBrowser Token="{key}"` needs a value
 * template, which `auth_template` carries. Its primary documentation is a
 * script-rendered page that could not be read for this change; the form is
 * confirmed by several independent client libraries and the server's own mirror
 * of its API documentation, and the older `X-Emby-Token` header is marked
 * deprecated there, which is why it is not offered.
 */
export const LOCAL_SERVICE_PRESETS: {
  id: string;
  label: string;
  scheme: string;
  param: string;
  template?: string;
}[] = [
  {
    id: 'arr',
    label: 'Sonarr / Radarr / Lidarr / Prowlarr (X-Api-Key)',
    scheme: 'header',
    param: 'X-Api-Key',
  },
  { id: 'plex', label: 'Plex (X-Plex-Token header)', scheme: 'header', param: 'X-Plex-Token' },
  {
    id: 'jellyfin',
    label: 'Jellyfin (Authorization: MediaBrowser Token)',
    scheme: 'header',
    param: 'Authorization',
    template: 'MediaBrowser Token="{key}"',
  },
  {
    id: 'homeassistant',
    label: 'Home Assistant (long-lived bearer token)',
    scheme: '',
    param: '',
  },
];

let _localPresetBound = false;

function wireLocalServicePreset(): void {
  const group = document.getElementById('f-local-preset-group');
  const select = document.getElementById('f-local-preset') as HTMLSelectElement | null;
  const type = document.getElementById('f-secret-type') as HTMLSelectElement | null;
  if (!group || !select || !type) return;
  if (select.options.length <= 1) {
    for (const p of LOCAL_SERVICE_PRESETS) select.add(new Option(p.label, p.id));
  }
  const show = () => {
    group.style.display = type.value === 'local_service' ? '' : 'none';
  };
  show();
  if (_localPresetBound) return;
  _localPresetBound = true;
  type.addEventListener('change', show);
  select.addEventListener('change', () => {
    const preset = LOCAL_SERVICE_PRESETS.find((p) => p.id === select.value);
    if (!preset) return;
    (document.getElementById('f-auth-scheme') as HTMLSelectElement).value = preset.scheme;
    (document.getElementById('f-auth-param') as HTMLInputElement).value = preset.param;
    (document.getElementById('f-auth-template') as HTMLInputElement).value = preset.template ?? '';
  });
}

let _pgpBound = false;

/** `gpg_key`: paste the public key, fill the expiry and the public identifiers. */
function wirePgpImport(): void {
  const group = document.getElementById('f-pgp-group');
  const type = document.getElementById('f-secret-type') as HTMLSelectElement | null;
  const show = () => {
    if (group) group.style.display = type?.value === 'gpg_key' ? 'flex' : 'none';
  };
  show();
  if (!_pgpBound) {
    _pgpBound = true;
    type?.addEventListener('change', show);
  }
  const btn = document.getElementById('f-pgp-btn');
  if (!btn) return;
  btn.onclick = () => {
    void (async () => {
      if (!isTauri()) {
        showToast('Reading a key needs the desktop app (or `unv entry set --pgp-public`)', 'err');
        return;
      }
      const raw = await showPromptLarge(
        'Paste the PUBLIC key block (-----BEGIN PGP PUBLIC KEY BLOCK-----)',
      );
      if (!raw?.trim()) return;
      try {
        const k = await invokeTauri<{
          fingerprint: string;
          key_id: string;
          user_ids: string[];
          expires_at: string | null;
        }>('pgp_inspect', { text: raw });
        (document.getElementById('f-expires') as HTMLInputElement).value = k.expires_at ?? '';
        const list = document.getElementById('f-extra-vars-list');
        if (list) {
          // Replace the three it owns, leave any the user added.
          const mine = new Set(['fingerprint', 'key_id', 'user_ids']);
          for (const row of list.querySelectorAll<HTMLElement>('.extra-var-row')) {
            if (mine.has(row.querySelector<HTMLInputElement>('.extra-var-key')?.value ?? '')) {
              row.remove();
            }
          }
          for (const [key, value] of [
            ['fingerprint', k.fingerprint],
            ['key_id', k.key_id],
            ['user_ids', k.user_ids.join('; ')],
          ] as const) {
            if (value) list.appendChild(_makeExtraVarRow(key, value, false, true));
          }
        }
        dynamicSecretFields();
        showToast(
          k.expires_at ? `Key expires ${k.expires_at.slice(0, 10)}` : 'This key does not expire',
          'ok',
        );
      } catch (err) {
        showToast(`Could not read the key: ${errorMessage(err)}`, 'err', 6000);
      }
    })();
  };
}

let _captureBound = false;

function wireCaptureImport(): void {
  const group = document.getElementById('f-capture-group');
  const type = document.getElementById('f-secret-type') as HTMLSelectElement | null;
  const show = () => {
    if (group) group.style.display = type?.value === 'cookie' ? 'flex' : 'none';
  };
  show();
  if (!_captureBound) {
    _captureBound = true;
    type?.addEventListener('change', show);
  }
  const btn = document.getElementById('f-capture-btn');
  if (!btn) return;
  btn.onclick = () => {
    void (async () => {
      if (!isTauri()) {
        showToast('Importing a capture needs the desktop app (or `unv cookie import`)', 'err');
        return;
      }
      const raw = await showPromptLarge('Paste a cURL command, HAR, or Set-Cookie lines');
      if (!raw?.trim()) return;
      try {
        const cap = await invokeTauri<SessionCapture>('session_capture_parse', {
          text: raw,
          origin: null,
        });
        applySessionCapture(cap);
        // S12: say what was left out, by name. Values are never listed.
        showToast(
          `Imported ${cap.cookies.length} cookie${cap.cookies.length === 1 ? '' : 's'}${cap.dropped.length ? `. Dropped: ${cap.dropped.join('; ')}` : ''}`,
          cap.dropped.length ? 'err' : 'ok',
          cap.dropped.length ? 8000 : undefined,
        );
      } catch (err) {
        showToast(`Capture import failed: ${errorMessage(err)}`, 'err', 6000);
      }
    })();
  };
}

let _cookieSplitBound = false;

/** Assignment-guarded (invariant 9): `openModal` runs on every open. */
function wireCookieSplit(): void {
  wireCaptureImport();
  wirePgpImport();
  wireLocalServicePreset();
  if (_cookieSplitBound) return;
  _cookieSplitBound = true;
  document.getElementById('f-key')?.addEventListener('input', refreshCookieSplit);
  document.getElementById('f-secret-type')?.addEventListener('change', refreshCookieSplit);
  const btn = document.getElementById('f-cookie-split-btn');
  if (btn) {
    btn.onclick = () => {
      const raw = (document.getElementById('f-key') as HTMLInputElement).value;
      const jar = parseAnyCookies(raw);
      if (!jar.length) {
        showToast('No cookies found in the value field', 'err', 1800);
        return;
      }
      const list = document.getElementById('f-extra-vars-list');
      if (!list) return;
      // Replaces the rows rather than appending: pressing this twice on one jar
      // must not produce every cookie twice, and the rows it would duplicate are
      // the ones it just wrote.
      setHtml(list, '');
      for (const xv of cookiesToExtraVars(jar)) {
        const row = _makeExtraVarRow(xv.key, xv.value, true, false);
        // The attributes ride on the row so a later save carries them; they have
        // no input of their own because nobody hand-types an expiry in Unix
        // seconds, and `cookies.txt` is the only thing that reads them.
        if (xv.attrs) row.dataset.cookieAttrs = JSON.stringify(xv.attrs);
        list.appendChild(row);
      }
      dynamicSecretFields(); // A5: new named variables can change whether the primary is required
      showToast(`Split into ${jar.length} cookie${jar.length === 1 ? '' : 's'}`, 'ok');
    };
  }
}

let _sessionPresetOptionsBuilt = false;
let _sessionPresetBound = false;

/**
 * Which required cookies (from the currently selected preset) the form's own
 * jar — the primary value plus every `extra_vars` row — does not have yet.
 * Reads the form directly rather than `formToEntry()`, so this can run on
 * every keystroke without constructing a whole entry each time.
 */
function currentJarNames(): Set<string> {
  const raw = (document.getElementById('f-key') as HTMLInputElement | null)?.value ?? '';
  const type = (document.getElementById('f-secret-type') as HTMLSelectElement | null)?.value;
  const names = new Set<string>();
  if (type === 'cookie') {
    for (const c of parseAnyCookies(raw)) names.add(c.name);
  }
  for (const row of document.querySelectorAll<HTMLElement>('#f-extra-vars-list .extra-var-row')) {
    const key = row.querySelector<HTMLInputElement>('.extra-var-key')?.value.trim();
    if (key) names.add(key);
  }
  return names;
}

/** Shows/hides the preset picker and, when one is selected, which of its
 * required cookies the jar is missing. Never edits the jar itself — see the
 * module doc on `session-presets.ts` for why this is informational only. */
function refreshSessionPresetUI(): void {
  const group = document.getElementById('f-session-preset-group');
  const select = document.getElementById('f-session-preset') as HTMLSelectElement | null;
  const status = document.getElementById('f-session-preset-status');
  const copyBtn = document.getElementById(
    'f-session-preset-copy-header',
  ) as HTMLButtonElement | null;
  if (!group || !select || !status) return;

  const isCookie =
    (document.getElementById('f-secret-type') as HTMLSelectElement | null)?.value === 'cookie';
  group.style.display = isCookie ? 'flex' : 'none';
  if (!isCookie) return;

  if (!_sessionPresetOptionsBuilt) {
    _sessionPresetOptionsBuilt = true;
    for (const p of sessionPresets()) {
      const opt = document.createElement('option');
      opt.value = p.id;
      opt.textContent = p.label;
      select.appendChild(opt);
    }
  }

  const preset = findSessionPreset(select.value);
  if (!preset) {
    status.textContent = '';
    if (copyBtn) copyBtn.style.display = 'none';
    return;
  }
  const have = currentJarNames();
  const missing = preset.required_cookies.filter((c) => !have.has(c));
  status.textContent = missing.length
    ? `Missing: ${missing.join(', ')}`
    : `All required cookies present${preset.optional_cookies.length ? ` (optional: ${preset.optional_cookies.join(', ')})` : ''}`;
  if (copyBtn) copyBtn.style.display = preset.header_recipe.length ? '' : 'none';
}

/** Assignment-guarded (invariant 9): `openModal` runs on every open. */
function wireSessionPreset(): void {
  if (_sessionPresetBound) return;
  _sessionPresetBound = true;
  document.getElementById('f-session-preset')?.addEventListener('change', refreshSessionPresetUI);
  document.getElementById('f-key')?.addEventListener('input', refreshSessionPresetUI);
  document.getElementById('f-secret-type')?.addEventListener('change', refreshSessionPresetUI);
  document.getElementById('f-extra-vars-list')?.addEventListener('input', refreshSessionPresetUI);

  document.getElementById('f-session-preset-copy-header')?.addEventListener('click', () => {
    void (async () => {
      const select = document.getElementById('f-session-preset') as HTMLSelectElement | null;
      const preset = findSessionPreset(select?.value ?? '');
      if (!preset) {
        showToast('Pick a provider preset first', 'err', 1800);
        return;
      }
      const entry = formToEntry();
      const headers = await deriveSessionHeaders(entry, preset, entry.api_url ?? undefined);
      if (!headers.length) {
        showToast('Nothing to derive — check the required cookies are present', 'err');
        return;
      }
      const text = headers.map((h) => `${h.name}: ${h.value}`).join('\n');
      await clipboardWrite(text);
      showToast(`Copied ${headers.length} header${headers.length === 1 ? '' : 's'} ✓`, 'ok');
    })();
  });
}

let _extraVarsAddBound = false;

/**
 * Wires the "+ Add variable" button and the delegated key-input listener that
 * refreshes the required-marker (A5).
 *
 * **Bug fix (2026-09-15):** this used to be bound only inside `openAdd()`'s
 * `_draftBound` guard, which conflated "bind the draft auto-save listeners"
 * with "bind the add-variable button" — two unrelated concerns sharing one
 * flag. Since `_draftBound` is set only by `openAdd`, a session whose first
 * modal was an **edit** (double-clicking an existing card, the ordinary way
 * to attach extra variables to something already saved) got a button with no
 * click handler at all: clicking it did nothing, silently, for the rest of
 * that edit and every edit after it until `openAdd()` happened to run once.
 * Reported as "make a template, then can't add variables — have to restart".
 *
 * Moved here and called from `openModal()`, the one function both `openAdd`
 * and `openEdit` already funnel through, with its own guard so it still binds
 * exactly once per page load (invariant 9).
 */
function wireExtraVarsAdd(): void {
  if (_extraVarsAddBound) return;
  _extraVarsAddBound = true;
  document.getElementById('f-extra-vars-add')?.addEventListener('click', () => {
    const row = _makeExtraVarRow();
    document.getElementById('f-extra-vars-list')?.appendChild(row);
    row.querySelector<HTMLInputElement>('.extra-var-key')?.focus();
    dynamicSecretFields(); // A5: a fresh row has no key yet, so this is a no-op until one is typed
  });
  // A5: typing a variable's key can turn the primary value optional (or back)
  // for an `env_var` entry — delegated so it covers every row, present and future.
  document.getElementById('f-extra-vars-list')?.addEventListener('input', (e) => {
    if ((e.target as HTMLElement).classList.contains('extra-var-key')) dynamicSecretFields();
  });
}

let _genPopoverDocListenersBound = false;

/**
 * Wires the generator popover beside the primary-value field's Generate
 * button (A8, 2026-09-15 — "Inject unreachable while the form is open").
 *
 * The Tools panel's four generators sit behind the modal overlay: reaching
 * them while the form is open hits the backdrop and closes the form first,
 * so "generate in Tools, Inject into the open form" was two mutually
 * exclusive states. This popover is the same generators — `generators.ts`,
 * moved out of `tools.ts` so there is one implementation of each rather than
 * a form-shaped copy — reachable without leaving the form.
 *
 * `Use` writes the primary value field, the only field a Generate button has
 * ever targeted here (`quickGenerate`, on the plain button beside this
 * caret). Extending generation to the secret field or a named variable is
 * future scope: neither has a Generate button today, so there is nothing
 * this popover would be replacing there.
 *
 * Assigned, not added (invariant 9). `openModal` runs on every open, and this
 * is called every time — like `wireTotpField`, not like `wireExtraVarsAdd`:
 * every listener here is a property assignment (`.onclick =`, not
 * `addEventListener`), which overwrites rather than stacks, so re-running the
 * whole function on each open is safe and is in fact what keeps it correctly
 * bound to `#f-key-generate-caret` and friends — the *same* static nodes on
 * every open in the real app, but genuinely different nodes from one test to
 * the next (`loadRealIndexHtml()` replaces the document per test). A one-shot
 * guard here would bind once to whichever DOM happened to exist at the first
 * call and silently do nothing on every open after — which is exactly the
 * bug this function shipped with the first time it was written, caught by
 * its own tests rather than by hand.
 *
 * The two `document`-level listeners (outside-click, Escape) are the
 * exception: those genuinely must bind only once — `addEventListener` on
 * `document` would stack one pair per form open, each pair closing the
 * popover redundantly, forever. They are guarded by `_genPopoverDocListenersBound`
 * and, because that guard means they cannot be *rebound* on later opens, they
 * re-query `#f-gen-popover`/`#f-key-generate-caret` by id inside the handler
 * rather than closing over the nodes captured at first bind — so they still
 * find the right element after any later DOM replacement.
 */
function wireGeneratorPopover(): void {
  const caret = document.getElementById('f-key-generate-caret') as HTMLButtonElement | null;
  const popover = document.getElementById('f-gen-popover');
  const fKey = document.getElementById('f-key') as HTMLInputElement | null;
  const output = document.getElementById('gp-output');
  const useBtn = document.getElementById('gp-use-btn') as HTMLButtonElement | null;
  const copyBtn = document.getElementById('gp-copy-btn') as HTMLButtonElement | null;
  const genBtn = document.getElementById('gp-generate-btn') as HTMLButtonElement | null;
  if (!caret || !popover || !fKey || !output || !useBtn || !copyBtn || !genBtn) return;

  let genBytes = 32;
  let activeTab = 'bytes';
  let lastValue = '';

  const setOutput = (v: string) => {
    lastValue = v;
    output.textContent = v;
    useBtn.disabled = !v;
    copyBtn.disabled = !v;
  };

  const close = () => {
    popover.hidden = true;
    caret.setAttribute('aria-expanded', 'false');
  };
  const open = () => {
    popover.hidden = false;
    caret.setAttribute('aria-expanded', 'true');
    setOutput('');
  };

  caret.onclick = (e) => {
    e.stopPropagation();
    if (popover.hidden) open();
    else close();
  };

  if (!_genPopoverDocListenersBound) {
    _genPopoverDocListenersBound = true;
    document.addEventListener('click', (e) => {
      const p = document.getElementById('f-gen-popover');
      const c = document.getElementById('f-key-generate-caret');
      if (!p || p.hidden) return;
      if (e.target === c || p.contains(e.target as Node)) return;
      p.hidden = true;
      c?.setAttribute('aria-expanded', 'false');
    });
    document.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape') return;
      const p = document.getElementById('f-gen-popover');
      const c = document.getElementById('f-key-generate-caret') as HTMLElement | null;
      if (!p || p.hidden) return;
      p.hidden = true;
      c?.setAttribute('aria-expanded', 'false');
      c?.focus();
    });
  }

  // ── Tabs ──
  const tabs = Array.from(popover.querySelectorAll<HTMLButtonElement>('.gen-tab-btn'));
  const panes = Array.from(popover.querySelectorAll<HTMLElement>('.gen-tab-pane'));
  tabs.forEach((btn) => {
    btn.onclick = () => {
      activeTab = btn.dataset.genTab!;
      tabs.forEach((b) => {
        const on = b === btn;
        b.classList.toggle('active', on);
        b.setAttribute('aria-selected', String(on));
      });
      panes.forEach((p) => {
        p.hidden = p.dataset.genPane !== activeTab;
      });
      setOutput('');
    };
  });

  // ── Secret-bytes byte-length toggle ──
  popover.querySelectorAll<HTMLButtonElement>('.gen-byte-btn').forEach((btn) => {
    btn.onclick = () => {
      popover.querySelectorAll('.gen-byte-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      genBytes = parseInt(btn.dataset.bytes!, 10);
    };
  });

  // ── Password length display ──
  const pwLength = document.getElementById('gp-pw-length') as HTMLInputElement | null;
  const pwLenDisplay = document.getElementById('gp-pw-len-display');
  if (pwLength) {
    pwLength.oninput = () => {
      if (pwLenDisplay) pwLenDisplay.textContent = pwLength.value;
    };
  }

  genBtn.onclick = () => {
    void (async () => {
      if (activeTab === 'bytes') {
        const fmt = (document.getElementById('gp-bytes-format') as HTMLSelectElement).value as
          'hex' | 'base64' | 'base64url';
        const out = guardEntropy(
          () => generateRandomBytes(genBytes, fmt),
          (m) => showToast(m, 'err'),
        );
        if (out !== undefined) setOutput(out);
      } else if (activeTab === 'password') {
        const upper = (document.getElementById('gp-pw-upper') as HTMLInputElement).checked;
        const lower = (document.getElementById('gp-pw-lower') as HTMLInputElement).checked;
        const digits = (document.getElementById('gp-pw-digits') as HTMLInputElement).checked;
        const symbols = (document.getElementById('gp-pw-symbols') as HTMLInputElement).checked;
        const noAmbig = (document.getElementById('gp-pw-noambig') as HTMLInputElement).checked;
        const length = parseInt(
          (document.getElementById('gp-pw-length') as HTMLInputElement).value,
          10,
        );
        const pwd = guardEntropy(
          () => generatePassword({ length, upper, lower, digits, symbols, noAmbig }),
          (m) => showToast(m, 'err'),
        );
        if (pwd === undefined) return;
        if (pwd === null) {
          showToast('Select at least one character set', 'err');
          return;
        }
        setOutput(pwd);
      } else if (activeTab === 'apikey') {
        const pattern = (document.getElementById('gp-ak-pattern') as HTMLSelectElement)
          .value as Parameters<typeof generateApiKeyPattern>[0];
        const out = guardEntropy(
          () => generateApiKeyPattern(pattern),
          (m) => showToast(m, 'err'),
        );
        if (out !== undefined) setOutput(out);
      } else if (activeTab === 'hash') {
        const input = (document.getElementById('gp-hash-input') as HTMLTextAreaElement).value;
        const algo = (document.getElementById('gp-hash-algo') as HTMLSelectElement)
          .value as Parameters<typeof generateHash>[1];
        const fmt = (document.getElementById('gp-hash-fmt') as HTMLSelectElement)
          .value as Parameters<typeof generateHash>[2];
        setOutput(await generateHash(input, algo, fmt));
      }
    })();
  };

  copyBtn.onclick = () => {
    if (lastValue) void clipboardWrite(lastValue);
  };
  useBtn.onclick = () => {
    if (!lastValue) return;
    fKey.value = lastValue;
    // The name preview and every other listener on this field only ever hear
    // about a change through a real event — setting `.value` alone leaves
    // them showing what was there before.
    fKey.dispatchEvent(new Event('input', { bubbles: true }));
    close();
    fKey.focus();
    showToast('Generated value applied', 'ok');
  };
}

/**
 * Closes the popover and clears its output. Called on every form open —
 * unlike `wireGeneratorPopover`, which binds its handlers once, this must run
 * every time or a value generated for one entry would still be sitting there,
 * one click from being applied to the next entry this form opens on.
 */
function resetGeneratorPopover(): void {
  const popover = document.getElementById('f-gen-popover');
  if (popover) popover.hidden = true;
  document.getElementById('f-key-generate-caret')?.setAttribute('aria-expanded', 'false');
  const output = document.getElementById('gp-output');
  if (output) output.textContent = '';
  const useBtn = document.getElementById('gp-use-btn') as HTMLButtonElement | null;
  const copyBtn = document.getElementById('gp-copy-btn') as HTMLButtonElement | null;
  if (useBtn) useBtn.disabled = true;
  if (copyBtn) copyBtn.disabled = true;
  // Matches `wireGeneratorPopover`'s fresh `activeTab = 'bytes'` on every
  // call — without this the DOM would still show whichever tab was last
  // clicked while the closure believes it is back on the first one.
  popover?.querySelectorAll<HTMLButtonElement>('.gen-tab-btn').forEach((b) => {
    const on = b.dataset.genTab === 'bytes';
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', String(on));
  });
  popover?.querySelectorAll<HTMLElement>('.gen-tab-pane').forEach((p) => {
    p.hidden = p.dataset.genPane !== 'bytes';
  });
}

let _previewBound = false;

/**
 * Bind the preview to the five inputs that feed it.
 *
 * Assignment on a permanent node, guarded (invariant 9): `openModal` runs on
 * every open, and `addEventListener` here would repaint the preview N times per
 * keystroke after N opens.
 */
function wireNamePreview(): void {
  if (_previewBound) return;
  _previewBound = true;
  for (const id of [
    'f-provider',
    'f-keyid',
    'f-version',
    'f-label',
    'f-role',
    'f-secret-role',
    'f-secret',
  ]) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', updateNamePreview);
  }
  // Composite live preview: the template, its kind, and every extra-var row
  // (parts) — delegated on the list so a row added or removed later is
  // covered without a second binding pass.
  for (const id of ['f-template', 'f-template-kind']) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', refreshCompositePreview);
  }
  document.getElementById('f-extra-vars-list')?.addEventListener('input', refreshCompositePreview);
}

// ── Modal open/close/save ─────────────────────────────────────────────────

export function openModal(title: string, idx: number) {
  document.getElementById('modal-title')!.textContent = title;
  (document.getElementById('edit-index') as HTMLInputElement).value = String(idx);
  document.getElementById('modal-duplicate')!.style.display = idx >= 0 ? 'block' : 'none';
  applySchemaTooltips();
  // Assigned, not added — openModal runs on every open (invariant 9).
  wireTotpField();
  wireNamePreview();
  updateNamePreview();
  wireCookieSplit();
  refreshCookieSplit();
  wireSessionPreset();
  refreshSessionPresetUI();
  wireExtraVarsAdd();
  wireGeneratorPopover();
  resetGeneratorPopover();
  document.getElementById('modal-overlay')!.classList.add('open');
  (document.getElementById('f-provider') as HTMLInputElement).focus();
  populateProjectSelect();
}

const DRAFT_KEY = 'envvault-form-draft';

function _saveDraft() {
  try {
    sessionStorage.setItem(DRAFT_KEY, JSON.stringify(formToEntry()));
  } catch {}
}
let _draftBound = false;

function _makeExtraVarRow(key = '', value = '', secret = false, isPublic = false): HTMLElement {
  const row = document.createElement('div');
  row.className = 'extra-var-row';
  // "public" is the opt-out from redaction, not a display toggle: `extra_vars`
  // are masked by default everywhere (Phase 23, E5), and this is how a client
  // id, a region or an account SID says it is safe to print.
  setHtml(
    row,
    html`
      <input class="form-input mono extra-var-key" placeholder="KEY" value="${key}" />
      <input
        class="form-input mono extra-var-value"
        placeholder="value"
        value="${value}"
        ${secret ? html` type="password"` : ''}
      />
      <label class="extra-var-secret-label" title="Mask value in UI"
        ><input type="checkbox" class="extra-var-secret" ${secret ? ' checked' : ''} />
        secret</label
      >
      <label
        class="extra-var-secret-label"
        title="Safe to print — opts this value out of redaction in the CLI and in copies. Use it for client ids, regions and account SIDs, never for the secret beside them."
        ><input type="checkbox" class="extra-var-public" ${isPublic ? ' checked' : ''} />
        public</label
      >
      <button type="button" class="icon-btn sm extra-var-remove" title="Remove">×</button>
    `,
  );
  const inp = row.querySelector<HTMLInputElement>('.extra-var-value')!;
  row.querySelector<HTMLInputElement>('.extra-var-secret')!.addEventListener('change', (ev) => {
    inp.type = (ev.target as HTMLInputElement).checked ? 'password' : 'text';
  });
  row.querySelector('.extra-var-remove')!.addEventListener('click', () => {
    row.remove();
    dynamicSecretFields(); // A5: removing the only named variable can make the primary required again
  });
  return row;
}

/**
 * Suggested `extra_vars` names for Phase 24.5's sixteen new types — the
 * per-type field tables from the design, without building sixteen bespoke
 * widgets. `[key, secret]`; `secret` pre-ticks the mask checkbox for a name
 * that is realistically going to hold one.
 *
 * Deliberately excludes anything the form already has a dedicated field for:
 * `provider` (name/SSID/site), the primary value (passphrase/key/body),
 * `account_name` (username), `api_secret`, `description` (a note's body).
 */
const SUGGESTED_VARS: Partial<Record<SecretType, [string, boolean][]>> = {
  oauth_client: [
    ['client_id', false],
    ['client_secret', true],
    ['auth_url', false],
    ['token_url', false],
    ['redirect_uri', false],
    ['scopes', false],
    ['refresh_token', true],
    ['access_token', true],
    ['access_expires_at', false],
  ],
  signing_key: [
    ['alg', false],
    ['kid', false],
    ['public_key', false],
    ['usage', false],
    ['previous_key', true],
  ],
  registry_token: [
    ['registry', false],
    ['scope', false],
  ],
  database: [
    ['engine', false],
    ['host', false],
    ['port', false],
    ['database', false],
    ['user', false],
    ['sslmode', false],
  ],
  recovery_codes: [
    ['codes', true],
    ['used_at', false],
  ],
  gpg_key: [
    ['fingerprint', false],
    ['key_id', false],
    ['uids', false],
    ['subkey_expiries', false],
  ],
  age_key: [['recipient', false]],
  local_service: [
    ['base_url', false],
    ['auth_placement', false],
    ['reachability', false],
  ],
  tracker: [
    ['announce_url', true],
    ['rss_url', true],
  ],
  usenet_server: [
    ['host', false],
    ['port', false],
    ['ssl', false],
    ['connections', false],
  ],
  wifi: [
    ['security', false],
    ['hidden', false],
  ],
  license_key: [
    ['licensed_to', false],
    ['email', false],
    ['seats', false],
    ['activations', false],
    ['purchased', false],
    ['maintenance_until', false],
    ['order_id', false],
  ],
  crypto_wallet: [
    ['bip39_passphrase', true],
    ['derivation_path', false],
    ['network', false],
    ['addresses', false],
    ['xpub', false],
  ],
  passkey: [
    ['credential_id', false],
    ['rp_id', false],
    ['user_handle', true],
  ],
  identity_document: [
    ['kind', false],
    ['issuing_country', false],
    ['subdivision', false],
    ['issued', false],
    ['expires', false],
  ],
};

/**
 * Populates `extra_vars` with blank rows named for the type just picked —
 * only when the list is still empty, so this never touches an entry that
 * already has values (editing an existing one, or a type change the user
 * changed their mind about and changed back). A user-driven `change` on the
 * type select is the only caller; `fillForm` sets `.value` directly, which
 * fires no `change` event, so loading an existing entry never triggers this.
 */
export function suggestExtraVarsForType(type: SecretType): void {
  const list = document.getElementById('f-extra-vars-list');
  if (!list || list.children.length > 0) return;
  const suggestions = SUGGESTED_VARS[type];
  if (!suggestions) return;
  for (const [key, secret] of suggestions) {
    list.appendChild(_makeExtraVarRow(key, '', secret, false));
  }
  dynamicSecretFields();
}

export function openAdd(e?: Event) {
  if (e) e.stopPropagation();
  // Restore draft if available (item 11)
  const draft = sessionStorage.getItem(DRAFT_KEY);
  try {
    const parsed: unknown = draft ? JSON.parse(draft) : null;
    if (parsed) {
      const draftEntry =
        typeof parsed === 'object' && parsed !== null ? (parsed as Partial<VaultEntry>) : {};
      fillForm(draftEntry);
      buildCatChips(draftEntry.categories || []);
    } else {
      fillForm({});
      buildCatChips([]);
    }
  } catch {
    fillForm({});
    buildCatChips([]);
  }
  openModal('Add Secret', -1);
  // Bind auto-save draft listeners once — the overlay and its inputs are permanent DOM nodes.
  // (The add-variable button used to be wired here too; it moved to
  // `wireExtraVarsAdd()`, called from `openModal()`, so it binds regardless of
  // whether Add or Edit opens the form first — see that function's doc.)
  if (!_draftBound) {
    const overlay = document.getElementById('modal-overlay')!;
    overlay.querySelectorAll('input, textarea, select').forEach((el) => {
      el.addEventListener('input', _saveDraft);
      el.addEventListener('change', _saveDraft);
    });
    _draftBound = true;
  }
}

function clearDraft() {
  sessionStorage.removeItem(DRAFT_KEY);
}

export function openEdit(e: Event, idx: number) {
  e.stopPropagation();
  fillForm(st.vault.api_keys[idx]);
  buildCatChips(st.vault.api_keys[idx].categories || []);
  openModal('Edit Secret', idx);
}

export function closeModal() {
  document.getElementById('modal-overlay')!.classList.remove('open');
  clearDraft();
}

export async function saveModal() {
  try {
    // A11: belt and braces alongside the disabled Save button — this refuses
    // even if something programmatic reaches `saveModal` directly.
    if (_unknownSecretType) {
      showToast('Update UnENVerse to edit this entry', 'err');
      return;
    }
    const idx = parseInt((document.getElementById('edit-index') as HTMLInputElement).value);
    // The entry being edited is the *base*: every field with no form input rides
    // through by construction rather than by the save path remembering it (E4).
    const old = idx >= 0 ? st.vault.api_keys[idx] : undefined;
    const entry = formToEntry(old);
    const t = entry.secretType || 'api_key';
    if (t === 'bundle') {
      const members = st.vault.api_keys.filter((member) => member.bundle_id === entry.id);
      for (const variable of entry.extra_vars ?? []) {
        if (variable.kind !== 'template') continue;
        const result = resolveBundleTemplate(entry, members, `{${variable.key}}`);
        if (!result.ok && result.error.kind === 'cycle') {
          showToast(`Bundle template cycle: ${result.error.path.join(' → ')}`, 'err', 5000);
          return;
        }
      }
    }
    if (!entry.provider) {
      showToast(`${TYPE_CONFIG[t]?.providerLabel || 'Provider'} is required`, 'err');
      return;
    }
    if (t === 'crypto_wallet' && entry.api_key && isTauri()) {
      // A mistyped word is otherwise discovered when the funds are needed. The
      // check is a warning, not a gate: another wordlist or a non-BIP39 seed is
      // legitimate, and the error never echoes a word.
      try {
        await invokeTauri('bip39_validate', { mnemonic: entry.api_key });
      } catch (err) {
        if (
          !(await showConfirm(
            `This recovery phrase does not validate (${errorMessage(err)}). Save anyway?`,
          ))
        )
          return;
      }
    }
    if (t === 'certificate' && !entry.certificate_data) {
      showToast('Certificate data is required', 'err');
      return;
    }
    if (t === 'file_blob' && !entry.blob_ref) {
      showToast('File path/reference is required', 'err');
      return;
    }
    if (t === 'composite' && !entry.composite_template) {
      showToast('Template is required', 'err');
      return;
    }
    // The primary value is required **unless the entry legitimately has none**
    // (Phase 23, step 4). Three shapes do: an `env_var` entry whose payload is N
    // named variables in `extra_vars`, an entry carrying only an authenticator
    // seed (what an import from Ente or Aegis produces, when the password lives
    // elsewhere), and the two types whose payload is their own field.
    //
    // `primaryIsOptional` is the single predicate — "the primary is never empty"
    // was assumed in more places than it was stated, and each of them
    // re-deriving the rule is how they drift.
    if (!entry.api_key && !primaryIsOptional(entry)) {
      showToast(
        t === 'env_var'
          ? 'Add a value, or at least one named variable below'
          : `${TYPE_CONFIG[t]?.keyLabel || 'Value'} is required`,
        'err',
      );
      return;
    }
    // ...but an entry holding nothing at all is a mistake in every shape.
    if (!entryHasPayload(entry)) {
      showToast('This entry would hold nothing — add a value or a variable', 'err');
      return;
    }
    // A label is a *name segment*, so anything that would normalise away is
    // refused here rather than silently transliterated into a variable name the
    // user never typed.
    if (entry.label && !LABEL_RE.test(entry.label)) {
      showToast(
        'Name label: letters, digits, _ and - only, starting with a letter or digit, max 24',
        'err',
        4500,
      );
      return;
    }
    // E12. `entry_ck` falls back to `provider|account_name|key_id` for an entry
    // with no `id`, so two entries differing only by `label` would collide there
    // — and that tuple is what RBAC scoped writes and `unv entry rm` match on.
    // Adding `label` to the tuple would silently re-target scoping on every
    // pre-`id` vault, so the fix is to backfill the id instead. The app does
    // that in `finishInit()`; an entry written by an older CLI may still lack
    // one, and `unv doctor --fix` is the way to repair those.
    if (entry.label && idx >= 0 && !old?.id) {
      showToast(
        'This entry predates stable ids — run `unv doctor --fix` before giving it a name label',
        'err',
        5000,
      );
      return;
    }
    // **The one thing this phase must not break** (step 6).
    //
    // Renaming a provider, version or label silently renames every environment
    // variable this entry generates — and the `.env` already deployed on a
    // server keeps the old name. That is `renameProviderRefs()`'s problem with a
    // wider blast radius, because the stale reference is not in the vault at
    // all: it is in a file on a machine nobody is looking at.
    //
    // So the before/after names are shown and confirmed, and only when this
    // entry has actually been copied under the old one — `last_copied_name` is
    // the evidence that something out there may be reading it. Asking on every
    // rename of an entry nobody has ever deployed is the kind of confirmation
    // people learn to click through.
    if (old?.last_copied_name) {
      const nowName = primaryEnvName(entry);
      if (nowName !== old.last_copied_name) {
        const ok = await showConfirm(
          `This renames the variable it generates:\n\n    ${old.last_copied_name}  →  ${nowName}\n\n` +
            `Anything already deployed with the old name keeps reading the old name. Rename it?`,
        );
        if (!ok) return;
      }
    }
    // A seed that cannot produce a code must not reach the vault: the entry
    // would then show a permanently blank code with nothing saying why, which
    // is indistinguishable from a bug in the generator.
    if (entry.totp_secret) {
      try {
        parseTotpSeed(entry.totp_secret);
      } catch (err) {
        showToast(`Two-factor seed: ${(err as Error).message}`, 'err', 4000);
        return;
      }
    }
    if (idx >= 0 && old) {
      // `id` is the one field that must exist even when the base had none: it is
      // this entry's identity for audit attribution, version history and RBAC
      // write scoping, and an entry written by an older build may predate it.
      // Everything else the form does not offer — `created_at`,
      // `last_rotated_at`, `version_history`, `pinned` and every field a later
      // phase adds — now arrives through the spread in `formToEntry`.
      st.vault.api_keys[idx] = {
        ...entry,
        id: old.id ?? newEntryId(),
      };
      if (old.secretType === 'bundle') {
        const renamed = new Map<string, string>();
        document
          .querySelectorAll<HTMLElement>('#f-extra-vars-list .extra-var-row[data-original-key]')
          .forEach((row) => {
            const before = row.dataset.originalKey ?? '';
            const after = row.querySelector<HTMLInputElement>('.extra-var-key')?.value.trim() ?? '';
            if (before && after && before !== after) renamed.set(before, after);
          });
        const bundleWithOldName = { ...st.vault.api_keys[idx], provider: old.provider };
        for (const [before, after] of renamed) {
          const moved = renameBundleLocalRefs(
            st.vault.api_keys,
            st.vault.projects,
            bundleWithOldName,
            before,
            after,
          );
          if (moved)
            showToast(`Updated ${moved} bundle reference${moved === 1 ? '' : 's'}`, 'ok', 2500);
        }
      }
      if (old.secretType === 'bundle' && old.provider !== entry.provider) {
        const moved = renameBundleRefs(
          st.vault.api_keys,
          st.vault.projects,
          old.provider,
          entry.provider,
        );
        if (moved)
          showToast(`Updated ${moved} bundle reference${moved === 1 ? '' : 's'}`, 'ok', 2500);
      }
      // Chunk references address entries by provider name, so a rename has to
      // carry them or every `${Provider/field}` pointing here goes stale.
      if (old.provider !== entry.provider || (old.key_id ?? '') !== (entry.key_id ?? '')) {
        const moved = renameProviderRefs(old.provider, old.key_id, entry.provider, entry.key_id);
        if (moved)
          showToast(`Updated ${moved} project reference${moved === 1 ? '' : 's'}`, 'ok', 2500);
      }
    } else {
      st.vault.api_keys.push({
        ...entry,
        id: newEntryId(),
        created_at: new Date().toISOString(),
      });
    }
    void persist();
    closeModal();
    document.getElementById('load-banner')!.style.display = 'none';
    triggerRender();
  } catch (err) {
    showToast('Save failed: ' + errorMessage(err), 'err', 4000);
  }
}

/**
 * Marks an entry as rotated: stamps last_rotated_at, snapshots the current
 * value into version_history (capped 50), resets the rotation clock, and
 * clears the compromised flag. Links three previously separate rotation facts.
 */
export function markAsRotated(idx: number) {
  const entry = st.vault.api_keys[idx];
  if (!entry) return;
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const history = [...(entry.version_history || [])];
  if (entry.api_key) {
    history.unshift({ value: entry.api_key, saved_at: new Date().toISOString() });
    if (history.length > 50) history.length = 50;
  }
  st.vault.api_keys[idx] = {
    ...entry,
    last_rotated_at: today,
    version_history: history,
    compromised: false,
  };
  void persist();
  triggerRender();
  showToast(
    `Rotated ${today}${entry.compromised ? ' — compromised flag cleared' : ''}`,
    'ok',
    2500,
  );
}

export function duplicateKey(e: Event, idx: number) {
  e.stopPropagation();
  // A duplicate is a *new* entry — it must not inherit the source's identity,
  // and that includes its rotation record. Copying version_history handed the
  // new entry a log of *another* entry's previous secret values, which then
  // showed in its history panel and rode along into every future export.
  const copy = {
    ...st.vault.api_keys[idx],
    id: newEntryId(),
    key_id: (st.vault.api_keys[idx].key_id || 'copy') + '_copy',
    version_history: undefined,
    last_rotated_at: undefined,
  };
  st.vault.api_keys.splice(idx + 1, 0, copy);
  void persist();
  triggerRender();
  showToast('Duplicated ✓', 'ok');
}

export async function confirmBundleMemberReferenceBreakage(member: VaultEntry): Promise<boolean> {
  if (!member.bundle_id) return true;
  const bundle = st.vault.api_keys.find(
    (entry) => entry.id === member.bundle_id && entry.secretType === 'bundle',
  );
  if (!bundle) return true;
  const sites = referencesToBundleMember(bundle, member, st.vault.api_keys, st.vault.projects);
  if (!sites.length) return true;
  const detail = sites.map((site) => `• ${site.label}: ${site.template}`).join('\n');
  if (
    !(await showConfirm(
      `Removing this bundle member will break ${sites.length} template reference(s):\n\n${detail}\n\nContinue?`,
    ))
  )
    return false;
  const stillPresent = referencesToBundleMember(
    bundle,
    member,
    st.vault.api_keys,
    st.vault.projects,
  );
  const confirmed = new Set(sites.map((site) => `${site.label}\0${site.template}`));
  if (stillPresent.some((site) => !confirmed.has(`${site.label}\0${site.template}`))) {
    showToast('Bundle references changed while confirming; review them and try again', 'err');
    return false;
  }
  return true;
}

export function deleteKey(e: Event, idx: number) {
  const removed = st.vault.api_keys[idx];
  if (!removed) return;
  if (removed.bundle_id) {
    void (async () => {
      if (!(await confirmBundleMemberReferenceBreakage(removed))) return;
      const currentIdx = removed.id
        ? st.vault.api_keys.findIndex((entry) => entry.id === removed.id)
        : st.vault.api_keys.indexOf(removed);
      if (currentIdx >= 0) deleteKeyNow(e, currentIdx);
    })();
    return;
  }
  deleteKeyNow(e, idx);
}

function deleteKeyNow(e: Event, idx: number) {
  e.stopPropagation();
  const removed = st.vault.api_keys.splice(idx, 1)[0];
  // Anchor the undo to the identity of the entry that followed, not to a raw
  // index. Deleting a second entry before undoing the first shifted every
  // higher position, so the restore landed in the wrong slot.
  const anchorId = st.vault.api_keys[idx]?.id ?? null;
  void persist();
  if (removed?.id) {
    st.expanded.delete(removed.id);
    // Reveal state is keyed by entry id. Left behind, it both grows unbounded
    // and re-reveals the secret if the entry comes back via undo.
    delete st.revealed[`key-${removed.id}`];
    delete st.revealed[`secret-${removed.id}`];
  }
  triggerRender();
  pushUndo(`Deleted "${removed.provider}"`, () => {
    const at = anchorId ? st.vault.api_keys.findIndex((k) => k.id === anchorId) : -1;
    st.vault.api_keys.splice(at >= 0 ? at : st.vault.api_keys.length, 0, removed);
    void persist();
    triggerRender();
  });
}

export function pushUndo(msg: string, fn: () => void) {
  const bar = document.getElementById('undo-bar')!;
  document.getElementById('undo-msg')!.textContent = msg;
  bar.classList.add('visible');
  // Use a unique token so the timeout removes *this* entry, not whatever happens to be last.
  const entry: { fn: () => void; t: ReturnType<typeof setTimeout> } = {
    fn,
    t: 0 as unknown as ReturnType<typeof setTimeout>,
  };
  entry.t = setTimeout(() => {
    const idx = st.undoStack.indexOf(entry);
    if (idx >= 0) st.undoStack.splice(idx, 1);
    if (!st.undoStack.length) bar.classList.remove('visible');
  }, 5000);
  st.undoStack.push(entry);
}

// ── Form helpers ──────────────────────────────────────────────────────────

/**
 * Puts a generated value into the Add/Edit form's secret field.
 *
 * The guard is on the *overlay being open*, not on the field existing. `#f-key`
 * is static markup in `index.html`, so it is in the document whether or not the
 * modal is showing — which meant every "→ Inject" button in the Tools panel
 * reported "Injected into form" with the form closed, wrote the value into a
 * hidden input nobody could see, and then lost it: `openModal` does not read
 * that field, and `closeModal` clears the draft. The user pressed a button, was
 * told it worked, and nothing happened. Same class as invariant 8 — presence in
 * the DOM is not the same as being on screen.
 */
export function injectIntoForm(value: string) {
  const open = document.getElementById('modal-overlay')?.classList.contains('open');
  const fKey = document.getElementById('f-key') as HTMLInputElement | null;
  if (!open || !fKey) {
    showToast('Open the Add/Edit form first, then Inject', 'err');
    return;
  }
  fKey.value = value;
  fKey.focus();
  showToast('Injected into form', 'ok');
}

export async function quickGenerate() {
  const invoke = isTauri() ? invokeTauri : undefined;
  const typeEl = document.getElementById('f-secret-type') as HTMLSelectElement | null;
  const type = typeEl?.value || 'api_key';

  if (type === 'password') {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
    const buf = new Uint32Array(20);
    crypto.getRandomValues(buf);
    const fKey = document.getElementById('f-key') as HTMLInputElement | null;
    if (fKey) {
      fKey.value = Array.from(buf)
        .map((n) => chars[n % chars.length])
        .join('');
      fKey.focus();
    }
    showToast('Password generated', 'ok');
    return;
  }

  if (type === 'ssh_key') {
    if (!invoke) {
      showToast('Tauri not available', 'err');
      return;
    }
    try {
      const result = await invoke<{ public_key: string; private_key: string }>(
        'generate_ssh_keypair',
        { comment: '' },
      );
      const fKey = document.getElementById('f-key') as HTMLInputElement | null;
      if (fKey) {
        fKey.value = result.private_key;
        fKey.focus();
      }
      showToast('SSH key pair generated (private key inserted)', 'ok');
    } catch (e) {
      showToast(String(e), 'err');
    }
    return;
  }

  if (type === 'certificate') {
    if (!invoke) {
      showToast('Tauri not available', 'err');
      return;
    }
    try {
      const result = await invoke<{ cert_pem: string; key_pem: string }>('generate_certificate', {
        commonName: 'localhost',
        validityDays: 365,
      });
      const fCert = document.getElementById('f-cert') as HTMLTextAreaElement | null;
      const fCertKey = document.getElementById('f-cert-key') as HTMLTextAreaElement | null;
      if (fCert) fCert.value = result.cert_pem;
      if (fCertKey) fCertKey.value = result.key_pem;
      showToast('Certificate generated', 'ok');
    } catch (e) {
      showToast(String(e), 'err');
    }
    return;
  }

  // Default: 32 random bytes hex
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  const hex = Array.from(buf)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const fKey = document.getElementById('f-key') as HTMLInputElement | null;
  if (fKey) {
    fKey.value = hex;
    fKey.focus();
  }
  showToast('Value generated', 'ok');
}

// ── Card interactions ─────────────────────────────────────────────────────

export function toggleCard(e: Event, idx: number) {
  e.stopPropagation();
  const entry = st.vault.api_keys[idx];
  if (!entry) return;
  const card = document.querySelector(`.card[data-idx="${idx}"]`);
  card?.classList.toggle('expanded');
  const open = !!card?.classList.contains('expanded');
  // Track by stable id, not array position — see st.expanded.
  if (open) st.expanded.add(entryId(entry));
  else st.expanded.delete(entryId(entry));
  // The class is the paint; aria-expanded is the same fact for a screen reader.
  // This path mutates the card in place instead of re-rendering, so the state
  // computed in `buildCard` never gets a second chance to be right.
  const chevron = card?.querySelector('.card-chevron');
  if (chevron) {
    chevron.setAttribute('aria-expanded', String(open));
    chevron.setAttribute('aria-label', `${open ? 'Collapse' : 'Expand'} ${entry.provider}`);
  }
}

export function toggleReveal(e: Event, field: string, idx: number, value: string) {
  e.stopPropagation();
  const entry = st.vault.api_keys[idx];
  if (!entry) return;
  const key = `${field}-${entryId(entry)}`;
  const el = document.getElementById(`kv-${field}-${idx}`);
  if (!el) return;
  st.revealed[key] = !st.revealed[key];
  el.textContent = st.revealed[key] ? value : maskKey(value);
  el.classList.toggle('revealed', st.revealed[key]);
  const btn = document.getElementById(`reveal-${field}-${idx}`);
  btn?.classList.toggle('active', st.revealed[key]);
  // Same reason as toggleCard: no re-render happens here, so the pressed state
  // has to be written where the class is.
  btn?.setAttribute('aria-pressed', String(!!st.revealed[key]));
}

export function copyField(e: Event, value: string, btn?: HTMLElement) {
  e.stopPropagation();
  clipboardWrite(value)
    .then(() => {
      btn?.classList.add('active');
      setTimeout(() => btn?.classList.remove('active'), 1200);
      showToast('Copied ✓', 'ok', 1500);
    })
    .catch(() => showToast('Copy failed', 'err'));
}

/**
 * Copy one entry at a profile.
 *
 * `profile` absent means "whatever the setting says" — the caret menu passes an
 * explicit one for a single copy and **does not persist it** (Phase 23): a
 * one-off "give me everything" must not silently change what the next fifty
 * copies contain.
 */
export function doCopyEnv(e: Event, idx: number, profile?: CopyProfile | 'value') {
  e.stopPropagation();
  const entry = st.vault.api_keys[idx];
  if (!entry) return;
  const fmt = Settings.get('defaultExportFormat');

  let text: string;
  let label: string;
  if (profile === 'value') {
    // The escape hatch for "I am pasting this into a login box". No name, no
    // header, no quoting — quoting is a `.env` concern and this is not one.
    text = entry.api_key || '';
    label = 'value';
  } else if (fmt === 'yaml' && !profile) {
    text = Exporter.yaml([entry]);
    label = 'YAML';
  } else {
    const p = profile ?? ((Settings.get('copyProfile') || 'basic') as CopyProfile);
    text = buildCopyText(entry, {
      profile: p,
      metadataStyle: (Settings.get('metadataStyle') || 'comment') as MetadataStyle,
      case: Settings.get('envCopyCase'),
      includePrefix: !!Settings.get('envIncludePrefix'),
    });
    label = `.env (${p})`;
  }

  void clipboardWrite(text).then(() => {
    const btn = document.getElementById(`env-btn-${idx}`);
    btn?.classList.add('env-copied');
    setTimeout(() => btn?.classList.remove('env-copied'), 1600);
    showToast(`Copied as ${label} ✓`, 'ok');
    // Stamp what name this went out under (step 6). Without it, "the generated
    // name changed since you last copied" is a question nothing can answer —
    // the stale `.env` is on a machine this app has never seen.
    //
    // Only for a real copy: "Value only" carries no name, so stamping there
    // would claim a deployment that never happened.
    if (profile !== 'value') {
      const name = primaryEnvName(entry);
      if (entry.last_copied_name !== name) {
        entry.last_copied_name = name;
        void persist();
      }
    }
  });
}

/** The caret beside the copy button: the three profiles, the raw value, and the request forms. */
export function openCopyEnvMenu(e: Event, idx: number) {
  e.stopPropagation();
  const el = e.currentTarget as HTMLElement;
  const entry = st.vault.api_keys[idx];
  if (!entry) return;
  const current = (Settings.get('copyProfile') || 'basic') as CopyProfile;
  const mark = (p: CopyProfile) => (p === current ? ' ·' : '');

  const copy = (text: string, what: string) => {
    void clipboardWrite(text).then(() => showToast(`Copied ${what} ✓`, 'ok'));
  };
  const header = authHeaderFor(entry);

  showDropdown(el, [
    { label: `Basic${mark('basic')}`, fn: () => doCopyEnv(e, idx, 'basic') },
    { label: `Extended${mark('extended')}`, fn: () => doCopyEnv(e, idx, 'extended') },
    { label: `Full${mark('full')}`, fn: () => doCopyEnv(e, idx, 'full') },
    '---',
    { label: 'Value only', fn: () => doCopyEnv(e, idx, 'value') },
    // E16: the vault now knows *how* this credential is sent, so it can hand
    // over the thing the user was previously assembling from memory.
    ...(header
      ? [
          {
            label: `Request header (${header.name})`,
            fn: () => copy(`${header.name}: ${header.value}`, 'request header'),
          },
        ]
      : []),
    { label: 'curl command', fn: () => copy(curlFor(entry), 'curl command') },
    // A file-shaped credential is delivered by **writing it**, not by copying
    // it (E17): pasting a 2 KB service-account JSON into a `.env` produces a
    // variable the library tries to `open()` as a path. So the download is the
    // action, and what goes on the clipboard is the line that names the file.
    ...(isFileShaped(entry)
      ? [
          '---' as const,
          {
            label: 'Write to file…',
            fn: () => {
              const f = fileContentsOf(entry);
              if (!f) return;
              const base = envName(entry, { case: 'lower' });
              void downloadText(f.text, `${base}.${f.ext}`, 'File written ✓');
            },
          },
          ...(entry.mount_path
            ? [
                {
                  label: 'Copy the .env line (path, not contents)',
                  fn: () => copy(fileEnvLine(entry, primaryEnvName(entry)) ?? '', 'the .env line'),
                },
              ]
            : []),
        ]
      : []),
    // Per-type output files (Phase 24.5): a registry token as the `.npmrc` it
    // belongs in, a database as its DSN. Produced by Rust — one implementation
    // — so a browser tab, which has no Rust, offers none.
    ...(isTauri() && emittersFor(entry.secretType).length
      ? [
          '---' as const,
          ...emittersFor(entry.secretType).map((format) => ({
            label: `Copy as ${format}`,
            fn: async () => {
              try {
                copy(await invokeTauri<string>('type_emit', { entry, format }), format);
              } catch (err) {
                showToast(errorMessage(err), 'err', 6000);
              }
            },
          })),
        ]
      : []),
    ...(isTauri() && entry.secretType === 'wifi'
      ? [
          {
            label: 'Show Wi-Fi QR code…',
            fn: async () => {
              try {
                const uri = await invokeTauri<string>('type_emit', { entry, format: 'wifi-uri' });
                showWifiQr(uri, entry.provider);
              } catch (err) {
                showToast(errorMessage(err), 'err', 6000);
              }
            },
          },
        ]
      : []),
    // OAuth: an online act, so it confirms and names the host first. The new
    // refresh token is persisted BEFORE anything is shown (a rotating issuer has
    // already invalidated the old one).
    ...(isTauri() && entry.secretType === 'oauth_client'
      ? [
          '---' as const,
          {
            label: 'Refresh access token…',
            fn: async () => {
              const url = entry.extra_vars?.find((v) => v.key === 'token_url')?.value ?? '';
              const host = /^https?:\/\/([^/]+)/.exec(url)?.[1] ?? 'the issuer';
              if (
                !(await showConfirm(
                  `Send this entry's refresh token and client secret to ${host}?`,
                ))
              )
                return;
              try {
                const res = await invokeTauri<{ entry: VaultEntry; rotated: boolean }>(
                  'oauth_refresh',
                  { entry },
                );
                const at = st.vault.api_keys.findIndex((e) => e.id === entry.id);
                if (at < 0) return;
                st.vault.api_keys[at] = res.entry;
                await persist();
                triggerRender();
                showToast(
                  res.rotated ? 'Refreshed; the new refresh token was saved first' : 'Refreshed',
                  'ok',
                );
              } catch (err) {
                showToast(errorMessage(err), 'err', 6000);
              }
            },
          },
        ]
      : []),
    // The cookie forms, on a cookie entry only: five more rows on every card
    // would bury the four that apply to everything.
    ...(entry.secretType === 'cookie'
      ? [
          '---' as const,
          {
            label: 'Cookie header',
            fn: () => copy(toCookieHeader(cookiesOf(entry)), 'cookie header'),
          },
          {
            label: 'cookies.txt (curl -b, yt-dlp)',
            fn: () => {
              try {
                copy(toCookiesTxt(cookiesOf(entry)), 'cookies.txt');
              } catch (err) {
                // Refused, with the reason. Writing a file `yt-dlp` silently
                // ignores is worse than not writing one, and "it did not work"
                // with no explanation is how that turns into a bug report about
                // the download rather than about the jar.
                showToast((err as Error).message, 'err', 7000);
              }
            },
          },
          {
            label: 'Cookie JSON (back into a browser)',
            fn: () => copy(toCookieJson(cookiesOf(entry)), 'cookie JSON'),
          },
          {
            label: 'Playwright storageState JSON',
            fn: () => {
              try {
                copy(toPlaywrightStorageState(entry), 'Playwright storageState');
              } catch (err) {
                showToast((err as Error).message, 'err', 7000);
              }
            },
          },
        ]
      : []),
  ]);
}

export function onIconWrapClick(e: Event, idx: number) {
  e.stopPropagation();
  openIconPickerFor(idx);
}

export function openIconPickerFor(idx: number) {
  const entry = st.vault.api_keys[idx];
  openIconPicker(undefined, undefined, (slug) => {
    st.vault.api_keys[idx] = { ...st.vault.api_keys[idx], custom_icon: slug || undefined };
    void persist();
    triggerRender();
  });
  iconPicker.selected = entry.custom_icon || null;
  (document.getElementById('icon-search') as HTMLInputElement).value = '';
  document.getElementById('icon-picker-overlay')!.classList.add('open');
}

// ── Dropdown ──────────────────────────────────────────────────────────────

export interface DropdownItem {
  /** Plain text is escaped; pass `html`...`` for markup. */
  label: HtmlValue;
  fn: () => void | Promise<void>;
  active?: boolean;
}

const _dropdownCallbacks = new Map<number, DropdownItem['fn']>();
let _dropdownItemId = 0;
let _ddCleanup: (() => void) | null = null;

function _ddClose() {
  if (_ddCleanup) {
    _ddCleanup();
    _ddCleanup = null;
  }
  const dd = document.getElementById('dropdown');
  if (dd) dd.style.display = 'none';
}

export function showDropdown(anchorEl: HTMLElement, items: (DropdownItem | '---')[]) {
  const dd = document.getElementById('dropdown')!;
  // Remove any listeners from a previously open dropdown that was not explicitly closed.
  if (_ddCleanup) {
    _ddCleanup();
    _ddCleanup = null;
  }

  const r = anchorEl.getBoundingClientRect();
  _dropdownCallbacks.clear();

  setHtml(
    dd,
    html`${items.map((item) => {
      if (item === '---') return html`<div class="dropdown-sep"></div>`;
      const id = _dropdownItemId++;
      _dropdownCallbacks.set(id, item.fn);
      return html`<div class="dropdown-item${item.active ? ' active' : ''}" data-ddid="${id}">${item.label}</div>`;
    })}`,
  );

  dd.style.cssText = `display:block;top:${r.bottom + 6}px;right:${document.documentElement.clientWidth - r.right}px;left:auto`;

  const onClick = (e: MouseEvent) => {
    const target = e.target as HTMLElement;
    const item = target.closest<HTMLElement>('[data-ddid]');
    if (item) {
      const id = parseInt(item.dataset.ddid!);
      const fn = _dropdownCallbacks.get(id);
      _ddClose();
      if (fn) void fn();
    }
  };

  const close = (e: MouseEvent) => {
    if (!dd.contains(e.target as Node) && e.target !== anchorEl) {
      _ddClose();
    }
  };

  _ddCleanup = () => {
    dd.removeEventListener('click', onClick);
    document.removeEventListener('click', close);
  };

  dd.addEventListener('click', onClick);
  setTimeout(() => document.addEventListener('click', close), 50);
}

export function showContextMenu(x: number, y: number, items: (DropdownItem | '---')[]) {
  const dd = document.getElementById('dropdown')!;
  if (_ddCleanup) {
    _ddCleanup();
    _ddCleanup = null;
  }

  _dropdownCallbacks.clear();
  setHtml(
    dd,
    html`${items.map((item) => {
      if (item === '---') return html`<div class="dropdown-sep"></div>`;
      const id = _dropdownItemId++;
      _dropdownCallbacks.set(id, item.fn);
      return html`<div class="dropdown-item${item.active ? ' active' : ''}" data-ddid="${id}">${item.label}</div>`;
    })}`,
  );
  dd.style.cssText = `display:block;top:${y}px;left:${x}px;right:auto`;
  requestAnimationFrame(() => {
    const r = dd.getBoundingClientRect();
    if (r.right > window.innerWidth) dd.style.left = `${x - r.width}px`;
    if (r.bottom > window.innerHeight) dd.style.top = `${y - r.height}px`;
  });
  const onClick = (e: MouseEvent) => {
    const item = (e.target as HTMLElement).closest<HTMLElement>('[data-ddid]');
    if (item) {
      const fn = _dropdownCallbacks.get(parseInt(item.dataset.ddid!));
      _ddClose();
      void fn?.();
    }
  };
  const close = (e: MouseEvent) => {
    if (!dd.contains(e.target as Node)) {
      _ddClose();
    }
  };

  _ddCleanup = () => {
    dd.removeEventListener('click', onClick);
    document.removeEventListener('click', close);
  };

  dd.addEventListener('click', onClick);
  setTimeout(() => document.addEventListener('click', close), 50);
}

// ── Custom Select ─────────────────────────────────────────────────────────

export class CustomSelect {
  el: HTMLDivElement;
  select: HTMLSelectElement;
  _btn: HTMLButtonElement;

  constructor(selectEl: HTMLSelectElement) {
    this.select = selectEl;
    const wrap = document.createElement('div');
    wrap.className = 'custom-select-wrap';
    selectEl.parentNode!.insertBefore(wrap, selectEl);
    wrap.appendChild(selectEl);
    selectEl.style.display = 'none';

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'custom-select-btn form-input mono';
    button.textContent = selectEl.options[selectEl.selectedIndex]?.text || '';

    button.addEventListener('click', (e) => {
      e.stopPropagation();
      const items = Array.from(selectEl.options).map((opt, i) => ({
        label: opt.text,
        active: selectEl.selectedIndex === i,
        fn: () => {
          selectEl.selectedIndex = i;
          button.textContent = opt.text;
          selectEl.dispatchEvent(new Event('change'));
        },
      }));
      showDropdown(button, items);
    });

    wrap.appendChild(button);
    this.el = wrap;
    this._btn = button;
  }

  setValue(v: string) {
    const idx = Array.from(this.select.options).findIndex((o) => o.value === v);
    if (idx >= 0) {
      this.select.selectedIndex = idx;
      this._btn.textContent = this.select.options[idx].text;
    }
  }
}
