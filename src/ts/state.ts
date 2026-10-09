import { entropySource, setEntropySource } from './generators';
import type {
  VaultData,
  AppSettings,
  VaultEntry,
  RemoteVaultConfig,
  PersistedView,
  AuditRow,
  Project,
} from './types';
import { dump as yamlDump } from 'js-yaml';
import { hexAlpha, onClipboardWrite, showToast } from './utils';
import { invokeTauri, isTauri } from './tauri';
export { inTauri } from './tauri';

type JsonObject = Record<string, unknown>;

function jsonObject(value: unknown): JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

function jsonError(value: unknown, fallback: string): string {
  const error = jsonObject(value).error;
  return typeof error === 'string' ? error : fallback;
}

// ── VaultStore ─────────────────────────────────────────────────────────────

/** The delta `PATCH /api/vault` and `save_vault_rows` take; see `vault_core::apply_row_patch`. */
export interface VaultPatch {
  put?: VaultEntry[];
  delete?: string[];
  projects_put?: Project[];
  projects_delete?: string[];
  categories?: string[];
}

export interface VaultStore {
  load(): Promise<VaultData | null>;
  save(data: VaultData): Promise<void>;
  /**
   * True once, right after a save that folded in changes another writer had
   * already stored (Phase 30). The caller's copy of the vault is then behind what
   * is stored and must be reloaded before the next edit.
   */
  takeMerged?(): boolean;
  /**
   * Phase 30.1: save only what changed. Resolves `false` when the store cannot
   * (a sub-user's login), so the caller saves the whole document instead.
   */
  saveRows?(patch: VaultPatch): Promise<boolean>;
  /** True when the last save did not reach the store (the failure was already toasted). */
  lastSaveFailed?(): boolean;
  readonly isRemote: boolean;
  readonly vaultId: string;
}

type SidebarSection = AppSettings['sidebarSections'][number];
type Panel = AppSettings['activePanel'];
type CalendarFeed = {
  id: string;
  name?: string;
  kinds?: string[];
  revoked_at?: string | null;
};

export class LocalVaultStore implements VaultStore {
  load(): Promise<VaultData | null> {
    return Promise.resolve().then(() => {
      const raw = sessionStorage.getItem('unenverse');
      if (!raw) return null;
      const data: unknown = JSON.parse(raw);
      return data as VaultData;
    });
  }
  save(data: VaultData): Promise<void> {
    try {
      sessionStorage.setItem('unenverse', JSON.stringify(data));
    } catch {
      showToast('Session storage full — export to save changes', 'err');
    }
    return Promise.resolve();
  }
  readonly isRemote = false;
  readonly vaultId = 'local';
}

/** Thrown when a write was refused because someone else wrote first. */
export class VaultConflictError extends Error {
  /** Names of the entries both writers changed, when the storage layer said. */
  readonly entries: string | null;
  constructor(entries: string | null = null) {
    super('The vault changed since you last loaded it');
    this.name = 'VaultConflictError';
    this.entries = entries;
  }
}

/** The `a, b` list after "both changed:" in a conflict message, if there is one. */
export function conflictEntries(message: string): string | null {
  const i = message.indexOf('both changed: ');
  return i < 0 ? null : message.slice(i + 'both changed: '.length).trim() || null;
}

const MERGED_SUFFIX = '+merged';

export class TauriVaultStore implements VaultStore {
  private invoke = invokeTauri;
  /**
   * Version of the vault as we last read it.
   *
   * Sent with every save as a compare-and-swap. Without it the desktop wrote the
   * whole blob unconditionally, so while "Open to LAN" is running a peer's edit
   * landing between our load and our next save was silently overwritten.
   */
  private lastVersion: string | null = null;

  async unlock(password: string): Promise<boolean> {
    return this.invoke<boolean>('unlock_vault', { password });
  }
  async lock(): Promise<void> {
    return this.invoke<void>('lock_vault');
  }
  async isUnlocked(): Promise<boolean> {
    return this.invoke<boolean>('vault_is_unlocked');
  }
  async exists(): Promise<boolean> {
    return this.invoke<boolean>('vault_exists');
  }
  async reset(): Promise<void> {
    return this.invoke<void>('reset_vault');
  }
  async vaultFilePath(): Promise<string> {
    return this.invoke<string>('get_vault_path').catch(() => '');
  }

  async load(): Promise<VaultData | null> {
    const res = await this.invoke<{
      data: VaultData;
      version: string | null;
    } | null>('load_vault');
    this.lastVersion = res?.version ?? null;
    return res?.data ?? null;
  }

  private merged = false;

  takeMerged(): boolean {
    const m = this.merged;
    this.merged = false;
    return m;
  }

  /** Adopt the version a save returned; a `+merged` marker means our copy is behind. */
  private adopt(v: string): void {
    this.merged = v.endsWith(MERGED_SUFFIX);
    this.lastVersion = this.merged ? v.slice(0, -MERGED_SUFFIX.length) : v;
  }

  async save(data: VaultData): Promise<void> {
    try {
      this.adopt(
        await this.invoke<string>('save_vault', {
          data,
          expectVersion: this.lastVersion,
        }),
      );
    } catch (e) {
      const msg = String(e instanceof Error ? e.message : e);
      if (msg.includes('VAULT_CONFLICT')) throw new VaultConflictError(conflictEntries(msg));
      throw e;
    }
  }

  /** Phase 30.1: save a delta; same compare-and-swap as `save`. */
  async saveRows(patch: VaultPatch): Promise<boolean> {
    try {
      this.adopt(
        await this.invoke<string>('save_vault_rows', {
          patch,
          expectVersion: this.lastVersion,
        }),
      );
    } catch (e) {
      const msg = String(e instanceof Error ? e.message : e);
      if (msg.includes('VAULT_CONFLICT')) throw new VaultConflictError(conflictEntries(msg));
      throw e;
    }
    return true;
  }

  /**
   * Write regardless of what is currently stored, adopting the result as our
   * new base. Only for a user explicitly choosing to overwrite after a conflict.
   */
  async forceSave(data: VaultData): Promise<void> {
    this.adopt(await this.invoke<string>('save_vault', { data, expectVersion: null }));
  }

  readonly isRemote = false;
  readonly vaultId = 'local-native';
}

const _invoke = (command: string, args?: unknown) => invokeTauri(command, args);

/**
 * Thrown when a password was accepted but the account also has a second factor.
 *
 * A distinct type rather than a message match: the string is server-supplied and
 * a caller branching on it would break the moment the wording changed.
 */
export class TotpRequiredError extends Error {
  constructor() {
    super('Second factor required');
    this.name = 'TotpRequiredError';
  }
}

export class RemoteVaultStore implements VaultStore {
  private token = '';
  /** ETag (vault content version) from the last successful load — sent as If-Match to detect drift. */
  private lastVersion = '';
  /** certFingerprint enables TOFU cert pinning when the server runs TLS with a self-signed cert. */
  constructor(
    public readonly baseUrl: string,
    public fingerprint?: string,
  ) {}

  /**
   * Unified fetch that routes through the Tauri `remote_request` command when:
   * - running inside Tauri AND
   * - the URL is https:// (self-signed certs are rejected by WebKit; reqwest bypasses this)
   *
   * Falls back to native `fetch()` for http:// or non-Tauri contexts.
   */
  private async _apiFetch(
    path: string,
    opts: { method?: string; headers?: Record<string, string>; body?: string } = {},
  ): Promise<{
    ok: boolean;
    status: number;
    json: () => Promise<unknown>;
    etag: string | null;
    merged: boolean;
  }> {
    const url = `${this.baseUrl}${path}`;
    const useNative = isTauri() && url.startsWith('https://');

    if (useNative && _invoke) {
      // The proxy hands back the two headers a save needs (ETag, X-Vault-Merged).
      const result = (await _invoke('remote_request', {
        url,
        method: opts.method ?? 'GET',
        headersJson: JSON.stringify(opts.headers ?? {}),
        body: opts.body ?? null,
        fingerprint: this.fingerprint ?? null,
      })) as { status: number; body: string; etag?: string | null; merged?: boolean };
      const ok = result.status >= 200 && result.status < 300;
      return {
        ok,
        status: result.status,
        json: () => {
          const parsed: unknown = JSON.parse(result.body);
          return Promise.resolve(parsed);
        },
        etag: result.etag ?? null,
        merged: result.merged === true,
      };
    }

    const headers: Record<string, string> = {};
    if (opts.headers) Object.assign(headers, opts.headers);
    const r = await fetch(url, { method: opts.method, headers, body: opts.body });
    return {
      ok: r.ok,
      status: r.status,
      json: async () => {
        const parsed: unknown = await r.json();
        return parsed;
      },
      etag: r.headers.get('etag'),
      merged: r.headers.get('x-vault-merged') === '1',
    };
  }

  /**
   * Authenticated REST call for the user/class management panel.
   * Returns parsed JSON, or `null` for 204 No Content. Throws on non-2xx with the server error.
   */
  async api<T = unknown>(path: string, method = 'GET', body?: unknown): Promise<T | null> {
    if (!this.token) throw new Error('Not authenticated');
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}` };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const r = await this._apiFetch(path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(jsonError(err, `Server error ${r.status}`));
    }
    if (r.status === 204) return null;
    return r.json().catch(() => null) as Promise<T | null>;
  }

  async unlock(password: string): Promise<boolean> {
    const r = await this._apiFetch('/api/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(jsonError(body, `Server error ${r.status}`));
    }
    const token = jsonObject(await r.json()).token;
    this.token = typeof token === 'string' ? token : '';
    return !!this.token;
  }

  /**
   * Authenticate as a sub-user.
   *
   * `totp` is sent only when the caller has one. A server whose user has a
   * confirmed second factor answers 401 with `totp_required: true` for a correct
   * password and no code — that is a *prompt*, not a failure, and it is thrown
   * as [`TotpRequiredError`] so the caller can ask for the code and retry rather
   * than telling the user their password was wrong.
   */
  async authUser(username: string, password: string, totp?: string): Promise<boolean> {
    const r = await this._apiFetch('/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, totp: totp ?? null }),
    });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      if (r.status === 401 && jsonObject(body).totp_required === true)
        throw new TotpRequiredError();
      throw new Error(jsonError(body, `Auth failed ${r.status}`));
    }
    const token = jsonObject(await r.json()).token;
    this.token = typeof token === 'string' ? token : '';
    return !!this.token;
  }

  async lock(): Promise<void> {
    if (!this.token) return;
    try {
      await this._apiFetch('/api/unlock', {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${this.token}` },
      });
    } catch {
      /* ignore */
    }
    this.token = '';
  }

  async isUnlocked(): Promise<boolean> {
    if (!this.token) return false;
    try {
      const r = await this._apiFetch('/api/status');
      return r.ok && jsonObject(await r.json()).unlocked === true;
    } catch {
      return false;
    }
  }

  async load(): Promise<VaultData | null> {
    if (!this.token) return null;
    try {
      const r = await this._apiFetch('/api/vault', {
        headers: { Authorization: `Bearer ${this.token}` },
      });
      if (r.ok && r.etag) this.lastVersion = r.etag;
      return r.ok ? ((await r.json()) as VaultData) : null;
    } catch {
      return null;
    }
  }

  private merged = false;

  takeMerged(): boolean {
    const m = this.merged;
    this.merged = false;
    return m;
  }

  async save(data: VaultData): Promise<void> {
    await this.send('PUT', data);
  }

  /**
   * Phase 30.1: send only what changed (`PATCH /api/vault`, owner only). Same
   * If-Match, merge and toasts as `save`. Resolves `false` when the server
   * refuses deltas for this login (a sub-user) so the caller can save whole.
   */
  async saveRows(patch: VaultPatch): Promise<boolean> {
    return (await this.send('PATCH', patch)) !== 'refused';
  }

  private failed = false;

  lastSaveFailed(): boolean {
    return this.failed;
  }

  private async send(method: 'PUT' | 'PATCH', data: unknown): Promise<'ok' | 'refused' | 'failed'> {
    const r = await this.sendRaw(method, data);
    this.failed = r === 'failed';
    return r;
  }

  private async sendRaw(
    method: 'PUT' | 'PATCH',
    data: unknown,
  ): Promise<'ok' | 'refused' | 'failed'> {
    if (!this.token) return 'failed';
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.token}`,
      };
      // Optimistic concurrency: prove we wrote against the version we last read.
      if (this.lastVersion) headers['If-Match'] = this.lastVersion;
      const r = await this._apiFetch('/api/vault', {
        method,
        headers,
        body: JSON.stringify(data),
      });
      if (r.status === 409) {
        const names = conflictEntries(jsonError(await r.json().catch(() => ({})), ''));
        showToast(
          names
            ? `Conflict: you and another writer both changed ${names}. Reload before saving.`
            : 'Conflict: vault changed on server since you loaded it. Reconnect/reload before saving.',
          'err',
          6000,
        );
        return 'failed';
      }
      if (method === 'PATCH' && [403, 404, 405].includes(r.status)) return 'refused';
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        showToast(
          `Remote save failed (${r.status})${jsonError(body, '') ? ': ' + jsonError(body, '') : ''}`,
          'err',
          4000,
        );
        return 'failed';
      }
      // Saved. The server returns the version to send as the next If-Match; when it
      // could not (the pinned-HTTPS proxy surfaces no headers) the next write is
      // unconditional until a load refreshes the token, as before.
      this.lastVersion = r.etag ?? '';
      this.merged = r.merged;
      return 'ok';
    } catch (e) {
      showToast(
        `Remote save failed: ${e instanceof Error ? e.message : 'network error'}`,
        'err',
        4000,
      );
      return 'failed';
    }
  }

  async getExpiring(days: number): Promise<unknown[]> {
    if (!this.token) return [];
    try {
      const r = await this._apiFetch(`/api/vault/expiring?days=${days}`, {
        headers: { Authorization: `Bearer ${this.token}` },
      });
      const data = r.ok ? await r.json() : [];
      return Array.isArray(data) ? (data as unknown[]) : ([] as unknown[]);
    } catch {
      return [];
    }
  }

  async getAuditLog(): Promise<unknown[]> {
    if (!this.token) return [];
    try {
      const r = await this._apiFetch('/api/audit', {
        headers: { Authorization: `Bearer ${this.token}` },
      });
      const data = r.ok ? await r.json() : [];
      return Array.isArray(data) ? (data as unknown[]) : ([] as unknown[]);
    } catch {
      return [];
    }
  }

  /**
   * Keep-alive. Every authenticated request slides the server-side session
   * deadline; this exists so an idle-but-open client does not get expired.
   * Returns false when the session is already gone.
   */
  async ping(): Promise<boolean> {
    if (!this.token) return false;
    try {
      const r = await this._apiFetch('/api/ping', {
        headers: { Authorization: `Bearer ${this.token}` },
      });
      return r.ok;
    } catch {
      return false;
    }
  }

  // ── Calendar feeds (Phase 24.3) ──────────────────────────────────────────

  /**
   * Mints a subscribable `.ics` feed. Returns the full URL, or null on
   * failure — the token is shown to the caller exactly once, so this must
   * never be retried "just to check": a retry after a network hiccup that
   * actually succeeded server-side mints a second, orphaned feed.
   */
  async createCalendarFeed(
    name: string,
    kinds: string[],
    includeAccountNames: boolean,
  ): Promise<string | null> {
    if (!this.token) return null;
    try {
      const r = await this._apiFetch('/api/calendar/feeds', {
        method: 'POST',
        headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, kinds, include_account_names: includeAccountNames }),
      });
      if (!r.ok) return null;
      const path = jsonObject(await r.json()).path;
      return typeof path === 'string' ? `${this.baseUrl}${path}` : null;
    } catch {
      return null;
    }
  }

  async listCalendarFeeds(): Promise<CalendarFeed[]> {
    if (!this.token) return [];
    try {
      const r = await this._apiFetch('/api/calendar/feeds', {
        headers: { Authorization: `Bearer ${this.token}` },
      });
      if (!r.ok) return [];
      const feeds = jsonObject(await r.json()).feeds;
      return Array.isArray(feeds)
        ? feeds.flatMap((feed) => {
            const item = jsonObject(feed);
            if (typeof item.id !== 'string') return [];
            return [
              {
                id: item.id,
                ...(typeof item.name === 'string' ? { name: item.name } : {}),
                ...(Array.isArray(item.kinds) &&
                item.kinds.every((kind) => typeof kind === 'string')
                  ? { kinds: item.kinds }
                  : {}),
                ...(typeof item.revoked_at === 'string' || item.revoked_at === null
                  ? { revoked_at: item.revoked_at }
                  : {}),
              },
            ];
          })
        : [];
    } catch {
      return [];
    }
  }

  async revokeCalendarFeed(id: string): Promise<boolean> {
    if (!this.token) return false;
    try {
      const r = await this._apiFetch(`/api/calendar/feeds/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${this.token}` },
      });
      return r.ok;
    } catch {
      return false;
    }
  }

  /**
   * One authenticated call to the unique-ID registry (`/api/uid/*`, Phase 24.4).
   * Returns the status and parsed body instead of collapsing errors to `null`:
   * a 429 with its `Retry-After`, a 403 for a missing capability and a 404 for a
   * server started without `--uid-registry` are each an answer the pane shows.
   */
  async uidRequest(
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
  ): Promise<{ status: number; body: unknown }> {
    if (!this.token) return { status: 401, body: { error: 'Not connected' } };
    const r = await this._apiFetch(path, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    let parsed: unknown = null;
    try {
      parsed = await r.json();
    } catch {
      // A 204 or an HTML error page has no JSON; the status carries the answer.
    }
    return { status: r.status, body: parsed };
  }

  /** One authenticated call to the node hub (`/api/nodes/*`, Phase 34). Same shape and
   * reasons as {@link RemoteVaultStore.uidRequest}: the status is part of the answer. */
  async nodesRequest(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body?: unknown,
  ): Promise<{ status: number; body: unknown }> {
    if (!this.token) return { status: 401, body: { error: 'Not connected' } };
    const r = await this._apiFetch(path, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    let parsed: unknown = null;
    try {
      parsed = await r.json();
    } catch {
      // 202/204 carry no body; the status is the answer.
    }
    return { status: r.status, body: parsed };
  }

  /** Fetch server status including TLS cert fingerprint (no auth needed). */
  async getStatus(): Promise<{
    unlocked: boolean;
    vault_exists: boolean;
    cert_fingerprint?: string;
  }> {
    try {
      const r = await this._apiFetch('/api/status');
      if (!r.ok) return { unlocked: false, vault_exists: false };
      const status = jsonObject(await r.json());
      return {
        unlocked: status.unlocked === true,
        vault_exists: status.vault_exists === true,
        ...(typeof status.cert_fingerprint === 'string'
          ? { cert_fingerprint: status.cert_fingerprint }
          : {}),
      };
    } catch {
      return { unlocked: false, vault_exists: false };
    }
  }

  readonly isRemote = true;
  get vaultId() {
    return this.baseUrl;
  }
}

// ── Global mutable state bag ───────────────────────────────────────────────
// All modules import `st` and read/write st.xxx directly.
// Using a single object avoids ESM live-binding reassignment restrictions.

export const st = {
  vault: {
    api_keys: [],
    user_categories: [],
    projects: [
      { id: 'Universal', name: 'Universal', description: 'All keys belong here by default' },
    ],
  } as VaultData,
  schema: null as {
    properties?: {
      api_keys?: { items?: { properties?: Record<string, { description?: string }> } };
    };
  } | null,
  store: new LocalVaultStore() as VaultStore,
  filter: { type: 'all', value: '' },
  searchQ: '',
  /**
   * Ids of entries currently expanded in the card grid.
   *
   * Keyed by entry id, never array index: deleting an entry used to shift every
   * higher index by one, so expand/reveal state silently jumped to neighbouring
   * cards after any delete or reorder.
   */
  expanded: new Set<string>(),
  allExpanded: false,
  lockTimer: null as ReturnType<typeof setTimeout> | null,
  undoStack: [] as { fn: () => void; t: ReturnType<typeof setTimeout> }[],
  /** Reveal state keyed `"<field>-<entryId>"` — index-independent, see `expanded`. */
  revealed: {} as Record<string, boolean>,
  currentSelectedProjectIds: ['Universal'] as string[],
  currentSortBy: 'provider',
  formCustomSelects: new Map<string, { setValue(value: string): void }>(),
  /** Active environment filter value; empty string = all environments. */
  currentEnvFilter: '' as string,
  /** ID of the user whose detail is shown in the users workspace. */
  selectedUserId: null as string | null,
  /** ID of the currently connected remote vault (matches RemoteVaultConfig.id). */
  activeRemoteId: null as string | null,
  /** Active tag filter — null means no tag filter applied. */
  activeTagFilter: null as string | null,
  /** Active env-prefix filter — null means no prefix filter applied. */
  activePrefixFilter: null as string | null,
  /**
   * Active key-pool filter — null means no pool filter applied.
   *
   * Holds the pool *name*, which is what `VaultEntry.pool` stores. Names are
   * not ids: renaming a pool means editing every member's `pool` field, and the
   * filter must be dropped on restore when nothing carries it any more
   * (invariant 7) — the same treatment tags get, for the same reason.
   */
  activePoolFilter: null as string | null,
  /**
   * The type chip bar (Phase 24.2) — multi-toggle, OR-combined, above the
   * grid. Holds `SecretType` strings plus one virtual token: `'__totp'`
   * (carries a stored authenticator seed — the replacement for the old
   * `has_totp` single-select filter). Deliberately no pool token: key-pool
   * filtering already has its own sidebar section, and duplicating it here
   * would be the same redundancy this bar exists to remove from the sidebar.
   * A `Set` rather than an array because membership, not order, is what every
   * read site cares about.
   */
  activeTypeChips: new Set<string>(),
  /**
   * Which pool cards are expanded in the grid (Phase 24.2), keyed by pool
   * name. Session-scoped like `expanded` (regular cards) — not persisted,
   * since a pool card defaults to collapsed and there is nothing sensitive to
   * accidentally restore un-collapsed.
   */
  expandedPools: new Set<string>(),
  /** Bundle cards expanded in the current view; never persisted. */
  expandedBundles: new Set<string>(),
  /** Selected member slot for each bundle card. */
  bundleSlotTabs: {} as Record<string, string>,
  /** True while the embedded "Open to LAN" server is serving this vault (Pass 3). */
  lanServerRunning: false,
  /** True after a successful finishInit(); false after lockVault(). Prevents visibility-change from stacking the relock overlay before the vault is ever opened. */
  vaultOpen: false,
  /** True while the card grid is in multi-select mode. */
  bulkMode: false,
  /**
   * Entries ticked in bulk mode, keyed by entry id.
   *
   * Ids, never array indices — for the same reason as `expanded`. This held
   * positions in `api_keys`, so anything that spliced the array between ticking
   * a card and pressing Delete (a single-entry delete, a duplicate, an undo)
   * shifted every higher selection onto its neighbour, and bulk delete then
   * removed the wrong secrets.
   */
  bulkSelected: new Set<string>(),
};

/**
 * Clears every view-scoped selection that can outlive the data it points at.
 *
 * Call this whenever `st.vault` is replaced wholesale — import, backup restore,
 * switching vaults. A project id, tag or category selected against the previous
 * vault will not exist in the new one, and `getFiltered()` then matches nothing:
 * the user imports a backup and is shown an empty grid, with the data present
 * but invisible. `revealed` matters for a second reason — it is keyed by entry
 * id, so an imported entry that happens to reuse an id would render its secret
 * unmasked without the user ever asking.
 */
export function resetViewState(): void {
  st.filter = { type: 'all', value: '' };
  st.searchQ = '';
  st.currentSelectedProjectIds = ['Universal'];
  st.currentEnvFilter = '';
  st.activeTagFilter = null;
  st.activePrefixFilter = null;
  st.activePoolFilter = null;
  st.activeTypeChips.clear();
  st.expandedPools.clear();
  st.expandedBundles.clear();
  st.bundleSlotTabs = {};
  st.expanded.clear();
  st.allExpanded = false;
  st.revealed = {};
  st.bulkMode = false;
  st.bulkSelected.clear();

  // The persisted copy is a reference too. `restoreViewState()` validates before
  // applying, but leaving a previous vault's selection on disk means the *next*
  // launch tries to reapply a filter belonging to a vault the user replaced.
  Settings.set('lastView', null);

  const searchEl = document.getElementById('search') as HTMLInputElement | null;
  if (searchEl) searchEl.value = '';
  document.getElementById('search-clear')?.classList.remove('visible');
}

/**
 * Clears every filter narrowing the grid, without touching the rest of the view.
 *
 * Distinct from `resetViewState()` on purpose: that one is for when the *data*
 * is replaced and expand/reveal/bulk state has to go too. This is the user
 * saying "show me everything again", where dropping their expanded cards and
 * bulk ticks as a side effect would be a surprise.
 */
export function clearAllFilters(): void {
  st.filter = { type: 'all', value: '' };
  st.searchQ = '';
  st.currentSelectedProjectIds = ['Universal'];
  st.currentEnvFilter = '';
  st.activeTagFilter = null;
  st.activePrefixFilter = null;
  st.activePoolFilter = null;
  st.activeTypeChips.clear();

  const searchEl = document.getElementById('search') as HTMLInputElement | null;
  if (searchEl) searchEl.value = '';
  document.getElementById('search-clear')?.classList.remove('visible');
}

// ── Entry identity ─────────────────────────────────────────────────────────

/** Fresh entry identifier. */
export function newEntryId(): string {
  return crypto.randomUUID();
}

/**
 * Guarantees every entry has a unique, stable `id`, in place.
 *
 * Backfills missing ids (vaults written before the field existed) and replaces
 * duplicates — `duplicateKey` shallow-copies an entry, which would otherwise
 * hand two entries the same identity and make the RBAC merge and
 * `version_history` attribution alias them.
 *
 * @returns true when anything was assigned, so callers can persist the migration.
 */
export function ensureEntryIds(entries: VaultEntry[]): boolean {
  const seen = new Set<string>();
  let changed = false;
  for (const e of entries) {
    if (!e.id || seen.has(e.id)) {
      e.id = newEntryId();
      changed = true;
    }
    seen.add(e.id);
  }
  return changed;
}

/**
 * Fills in `created_at` for entries written before the field existed, using
 * evidence already in the vault rather than a guess.
 *
 * The only evidence that actually dates a creation is an `add` row in the audit
 * log, which has been written since Phase 3. Two rules make it safe to use:
 *
 * 1. **The oldest matching row wins.** An entry deleted and re-added would have
 *    two; the first is when the name first appeared.
 * 2. **An ambiguous provider is skipped entirely.** Audit rows identify an
 *    entry by `entry_provider` alone, so two entries sharing a provider cannot
 *    be told apart — and attributing one entry's creation date to its neighbour
 *    is the same class of mistake as identifying an entry by array index. The
 *    CLI refuses ambiguous lookups for exactly this reason; so does this.
 *
 * Everything else stays unset. `version_history` is deliberately not used as a
 * source: its oldest `saved_at` is when a value was *replaced*, which is an
 * upper bound on the creation date and not the date itself. The timeline panel
 * shows that bound as "before <date>" without writing it to the vault, because
 * a stored date is indistinguishable from a known one the moment it is read
 * back by anything else — the CLI, an export, the calendar feed.
 *
 * @returns true when anything was assigned, so the caller can persist.
 */
export function backfillCreatedAt(entries: VaultEntry[], auditRows: AuditRow[]): boolean {
  const missing = entries.filter((e) => !e.created_at);
  if (!missing.length || !auditRows.length) return false;

  const providerCount = new Map<string, number>();
  for (const e of entries) {
    providerCount.set(e.provider, (providerCount.get(e.provider) ?? 0) + 1);
  }

  // Oldest `add` row per provider. Rows arrive newest-first, and `id` is the
  // only reliable ordering — timestamps are strings written by whichever build
  // was running at the time.
  const firstAdd = new Map<string, string>();
  for (const row of [...auditRows].sort((a, b) => a.id - b.id)) {
    if (row.action !== 'add' || !row.entry_provider) continue;
    if (!firstAdd.has(row.entry_provider)) firstAdd.set(row.entry_provider, row.timestamp);
  }

  let changed = false;
  for (const e of missing) {
    if ((providerCount.get(e.provider) ?? 0) !== 1) continue;
    const ts = firstAdd.get(e.provider);
    if (!ts || Number.isNaN(Date.parse(ts))) continue;
    e.created_at = new Date(ts).toISOString();
    changed = true;
  }
  return changed;
}

/**
 * The earliest moment an entry is *known* to have existed, when its creation
 * date is unknown.
 *
 * This is an upper bound, never a creation date, and every caller has to render
 * it as one ("before 4 Mar"). It exists because "unknown" for an entry with ten
 * revisions going back two years is less true than "at least two years old".
 */
export function earliestEvidence(entry: VaultEntry): string | null {
  const stamps = (entry.version_history ?? [])
    .map((v) => v.saved_at)
    .filter((s): s is string => !!s && !Number.isNaN(Date.parse(s)))
    .sort();
  return stamps[0] ?? null;
}

/** Stable id for an entry, assigning one if somehow still absent. */
export function entryId(entry: VaultEntry): string {
  if (!entry.id) entry.id = newEntryId();
  return entry.id;
}

// Phase 36: every copy the app makes goes to the materialisation log, so blast
// radius can say which secrets reached this machine's clipboard. Rust matches the
// text against the vault we hand it and records fingerprints, never values.
onClipboardWrite((text) => {
  if (!isTauri() || !st.vault || text.length > 1 << 20) return;
  invokeTauri('matlog_note', { text, note: 'clipboard', vault: st.vault }).catch(() => undefined);
});

/**
 * The single vault write path.
 *
 * Normalises entry ids before handing the data to the store, so no code path —
 * import, template, chunk link, manual add — can persist an entry without a
 * stable identity. Always use this instead of calling `st.store.save` directly.
 */
export async function persist(): Promise<void> {
  ensureEntryIds(st.vault.api_keys);
  try {
    await saveWholeOrDelta();
    // The save folded in changes another writer had stored: our copy is behind,
    // and the next save from it would be judged against the wrong base.
    if (st.store.takeMerged?.()) {
      await reloadFromStore();
      showToast('Saved, and merged with changes someone else made', 'ok', 3500);
    }
  } catch (err) {
    if (err instanceof VaultConflictError) {
      await resolveSaveConflict(err);
      return;
    }
    showToast(`Save failed: ${err instanceof Error ? err.message : String(err)}`, 'err', 4000);
  }
}

// ── Delta saves (Phase 30.1, ADR-0146) ───────────────────────────────────────────────
//
// Everything in the renderer mutates `st.vault` in place, so there is no list of
// dirty ids to read. Instead `persist` remembers the JSON of each entry and
// project as of the last save that reached the store and sends the difference.
// The snapshot is only trusted while the document and its arrays are the very
// objects it was taken from; anything that replaced one (an import, a reload, a
// filter that reassigned `api_keys`) falls back to the whole-document save,
// which is always correct. An order change falls back too: a delta appends.
// ponytail: stringifying every entry per save is O(vault) on the client but sends
// and merges O(changed); a dirty set maintained at mutation sites would remove it.

interface Synced {
  vault: VaultData;
  store: VaultStore;
  keys: VaultEntry[];
  projects: Project[];
  cats: string[] | undefined;
  entries: Map<string, string>;
  projectJson: Map<string, string>;
  catsJson: string;
}

let synced: Synced | null = null;

/** Forget what the store holds; the next save is a whole-document one. */
export function forgetSynced(): void {
  synced = null;
}

function jsonById(list: { id?: unknown }[]): Map<string, string> | null {
  const m = new Map<string, string>();
  for (const e of list) {
    if (typeof e.id !== 'string' || !e.id || m.has(e.id)) return null;
    m.set(e.id, JSON.stringify(e));
  }
  return m;
}

function snapshotNow(): void {
  const entries = jsonById(st.vault.api_keys);
  const projectJson = jsonById(st.vault.projects);
  synced =
    entries && projectJson
      ? {
          vault: st.vault,
          store: st.store,
          keys: st.vault.api_keys,
          projects: st.vault.projects,
          cats: st.vault.user_categories,
          entries,
          projectJson,
          catsJson: JSON.stringify(st.vault.user_categories ?? []),
        }
      : null;
}

/** True when `now` is `before` minus the deleted ids with new ids appended. */
function orderHolds(before: string[], now: string[], gone: Set<string>): boolean {
  const kept = before.filter((id) => !gone.has(id));
  const known = new Set(before);
  const appended = now.filter((id) => !known.has(id));
  const expect = [...kept, ...appended];
  return expect.length === now.length && expect.every((id, i) => id === now[i]);
}

/** The delta since the last synced state, or `null` when it cannot be trusted. */
export function currentPatch(): VaultPatch | null {
  const sy = synced;
  const v = st.vault;
  if (!sy) return null;
  if (
    sy.vault !== v ||
    sy.store !== st.store ||
    sy.keys !== v.api_keys ||
    sy.projects !== v.projects ||
    sy.cats !== v.user_categories
  ) {
    return null;
  }
  const now = jsonById(v.api_keys);
  const nowP = jsonById(v.projects);
  if (!now || !nowP) return null;
  const gone = new Set([...sy.entries.keys()].filter((id) => !now.has(id)));
  const goneP = new Set([...sy.projectJson.keys()].filter((id) => !nowP.has(id)));
  if (
    !orderHolds([...sy.entries.keys()], [...now.keys()], gone) ||
    !orderHolds([...sy.projectJson.keys()], [...nowP.keys()], goneP)
  ) {
    return null;
  }
  const patch: VaultPatch = {};
  const put = v.api_keys.filter((e) => sy.entries.get(e.id as string) !== now.get(e.id as string));
  if (put.length) patch.put = put;
  if (gone.size) patch.delete = [...gone];
  const putP = v.projects.filter((p) => sy.projectJson.get(p.id) !== nowP.get(p.id));
  if (putP.length) patch.projects_put = putP;
  if (goneP.size) patch.projects_delete = [...goneP];
  const catsJson = JSON.stringify(v.user_categories ?? []);
  if (catsJson !== sy.catsJson) patch.categories = v.user_categories ?? [];
  return patch;
}

async function saveWholeOrDelta(): Promise<void> {
  const store = st.store;
  const patch = store.saveRows ? currentPatch() : null;
  let sent = false;
  if (patch) {
    if (Object.keys(patch).length === 0) return; // nothing changed since the last save
    sent = await store.saveRows!(patch);
  }
  if (!sent) await store.save(st.vault);
  // A save that never reached the store (toasted already) leaves the old snapshot,
  // so the same changes go out again with the next one.
  if (!store.lastSaveFailed?.()) snapshotNow();
}

/**
 * A concurrent writer — almost always a LAN peer — changed the vault between our
 * last read and this save.
 *
 * There is no safe automatic answer: we do not know which change matters more,
 * and silently picking one is how data goes missing. So ask, and make the cost
 * of each option explicit.
 */
async function resolveSaveConflict(err: VaultConflictError): Promise<void> {
  const { showConfirm } = await import('./utils');
  const which = err.entries
    ? `You and the other writer both changed: ${err.entries}.\n\n`
    : 'Someone else changed this vault while you were editing.\n\n';
  const overwrite = await showConfirm(
    which +
      'Changes to other entries were not in conflict and are already kept.\n\n' +
      'OK: keep your version of these entries and overwrite theirs.\n' +
      'Cancel: discard your unsaved change and reload theirs.',
  );

  if (overwrite) {
    const store = st.store as TauriVaultStore;
    if (typeof store.forceSave === 'function') {
      try {
        await store.forceSave(st.vault);
        forgetSynced();
        showToast('Your version saved, overwriting the other change', 'ok', 3500);
        return;
      } catch (e) {
        showToast(`Overwrite failed: ${e instanceof Error ? e.message : String(e)}`, 'err', 4000);
        return;
      }
    }
  }

  if (await reloadFromStore()) {
    showToast('Reloaded the other version — your unsaved change was discarded', 'err', 5000);
  }
}

/** Adopt what is now stored, replacing our copy. `false` when nothing could be loaded. */
async function reloadFromStore(): Promise<boolean> {
  const fresh = await st.store.load();
  if (!fresh) return false;
  forgetSynced();
  st.vault.api_keys = fresh.api_keys;
  st.vault.user_categories = fresh.user_categories || [];
  st.vault.projects = fresh.projects || [{ id: 'Universal', name: 'Universal', description: '' }];
  triggerRender();
  return true;
}

// ── Render callback (breaks potential circular deps) ───────────────────────

let _renderFn: () => void = () => {};
export function setRenderFn(fn: () => void): void {
  _renderFn = fn;
}
export function triggerRender(): void {
  _renderFn();
}

// ── Settings ───────────────────────────────────────────────────────────────

export const DEFAULT_SETTINGS: AppSettings = {
  theme: 'dark',
  accentColor: '#7364c9',
  cardSize: 'medium',
  gridColumns: 'auto',
  defaultAccount: '',
  defaultExportFormat: 'dotenv',
  autoLockMinutes: 60,
  lockOnHide: false,
  maskKeysByDefault: true,
  showExpiryWarning: true,
  expiryWarningDays: 30,
  customCss: '',
  sidebarSections: ['all', 'price', 'env', 'category', 'project', 'tags', 'pools', 'prefixes'],
  groupByType: false,
  groupPools: true,
  groupBundles: true,
  configCheckAll: false,
  dismissedBundleSuggestions: [] as string[],
  activityBarPosition: 'left' as const,
  activityBarStyle: 'icon' as const,
  collapsedSections: [] as ('all' | 'price' | 'env' | 'category' | 'project')[],
  activePanel: 'secrets' as 'secrets' | 'tools' | 'users' | 'remote' | 'auth',
  authShowNext: false,
  activeTool: 'secret-gen',
  remoteSaved: [] as RemoteVaultConfig[],
  panelOrder: ['secrets', 'tools', 'remote', 'users', 'auth'],
  envCopyField: 'api_key' as const,
  envCopyCase: 'upper' as const,
  envIncludePrefix: false,
  copyProfile: 'basic' as const,
  metadataStyle: 'comment' as const,
  sidebarWidth: 0,
  sidebarCollapsed: false,
  lastSortBy: 'provider',
  recentSearches: [] as string[],
  rememberFilters: true,
  lastView: null as PersistedView | null,
  experimentalProjectTypes: false,
  // Off by default: the safe behaviour is the default, and the convenience is
  // the thing you opt into.
  keepLocalUnlocked: false,
  entropySource: 'os',
  onboardingCompleted: false,
};

export const Settings = {
  _data: { ...DEFAULT_SETTINGS } as AppSettings,
  get<K extends keyof AppSettings>(k: K): AppSettings[K] {
    return this._data[k];
  },
  set<K extends keyof AppSettings>(k: K, v: AppSettings[K]) {
    this._data[k] = v;
    this._persist();
  },
  setAll(o: Partial<AppSettings>) {
    Object.assign(this._data, o);
    this._persist();
  },
  getAll(): AppSettings {
    return { ...this._data };
  },
  _persist() {
    localStorage.setItem('unenverse-settings', JSON.stringify(this._data));
  },
  async init() {
    try {
      const r = await fetch('./settings.json');
      if (r.ok) Object.assign(this._data, await r.json());
    } catch {}
    try {
      const s = localStorage.getItem('unenverse-settings');
      if (s) Object.assign(this._data, JSON.parse(s));
    } catch {}
    // One-time migration: env/tags/prefixes became configurable sidebar sections.
    // Earlier installs persisted a list without them — merge them in once so they
    // don't silently vanish, while still honouring later user toggles.
    try {
      if (!localStorage.getItem('unenverse-sb-migrated')) {
        const secs = [...(this._data.sidebarSections || [])];
        const insertAfter = (anchor: SidebarSection, key: SidebarSection) => {
          if (secs.includes(key)) return;
          const at = secs.indexOf(anchor);
          if (at >= 0) secs.splice(at + 1, 0, key);
          else secs.push(key);
        };
        insertAfter('price', 'env');
        if (!secs.includes('tags')) secs.push('tags');
        if (!secs.includes('pools')) secs.push('pools');
        if (!secs.includes('prefixes')) secs.push('prefixes');
        this._data.sidebarSections = secs;
        localStorage.setItem('unenverse-sb-migrated', '1');
        this._persist();
      }
      // Phase 22's Authenticator section, merged in the same way and under its
      // own flag. Reusing the flag above would mean an install that has already
      // run that migration never sees this one — which is how a section ends up
      // present in the markup, listed in the settings editor, and invisible.
      // Phase 22.2's Authenticator *panel*, same shape and its own flag.
      // `applyPanelOrder()` hides any activity-bar button whose panel is not in
      // this list, so an install that predates the panel — which is every
      // install, since the list has been persisted since Phase 12 — had the 2FA
      // tab in the markup, wired, and `display: none`. The panel was
      // unreachable for everyone and nothing said so.
      if (!localStorage.getItem('unenverse-panel-migrated-auth')) {
        const panels = [...(this._data.panelOrder || [])];
        if (!panels.includes('auth')) panels.push('auth');
        this._data.panelOrder = panels;
        localStorage.setItem('unenverse-panel-migrated-auth', '1');
        this._persist();
      }
      // A2 (2026-09-14): reversed. The Authenticator *sidebar section* — added
      // by this same flag — is removed: two surfaces for one feature, and the
      // one that showed nothing (A1) read as the whole feature being broken.
      // The fifth activity-bar panel (`auth`, migrated above) carries
      // everything it did; the `has_totp` grid filter is replaced by 24.2's
      // type chip. `authenticator` is dropped from `sidebarSections` **on
      // every read** (invariant 7), not by a one-time migration, so a section
      // key that outlives the code rendering it can never reappear — and the
      // flag stays set (never cleared, never reused) so nothing ever tries to
      // insert it again.
      if (!localStorage.getItem('unenverse-sb-migrated-totp')) {
        localStorage.setItem('unenverse-sb-migrated-totp', '1');
      }
    } catch {}
    // A2: persisted settings can outlive the Authenticator sidebar surface.
    // Sanitize after both settings sources have been merged, on every load.
    this._data.sidebarSections = (this._data.sidebarSections || []).filter(
      (section) => (section as string) !== 'authenticator',
    );
    this._apply();
  },
  _apply() {
    const d = this._data;
    // The generators' entropy source follows the setting (Phase 33.4). Only when it
    // changed, so the pool is not thrown away on every theme repaint.
    if ((d.entropySource || 'os') !== entropySource()) {
      void setEntropySource(d.entropySource || 'os').catch(() => {
        // The Settings row reports an unusable source when it is chosen; here a
        // failure leaves the pool empty and the generators say so when used.
      });
    }
    // OS theme auto-sync (item 21)
    const resolvedTheme =
      d.theme === 'system'
        ? window.matchMedia('(prefers-color-scheme: dark)').matches
          ? 'dark'
          : 'light'
        : d.theme;
    document.documentElement.setAttribute('data-theme', resolvedTheme);
    document.documentElement.style.setProperty('--accent', d.accentColor);
    document.documentElement.style.setProperty('--accent-dim', hexAlpha(d.accentColor, 0.14));
    document.documentElement.style.setProperty('--accent-mid', hexAlpha(d.accentColor, 0.3));
    applyGridSettings();
    applySidebarOrder();
    applyActivityBar();
    applySidebarLayout();
    import('./settings-panel').then((m) => m.applyPanelOrder()).catch(() => {});
    const styleEl = document.getElementById('custom-style') as HTMLStyleElement | null;
    if (styleEl) styleEl.textContent = d.customCss || '';
  },
};

// ── OS theme watcher (item 21) ─────────────────────────────────────────────
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (Settings.get('theme') === 'system') Settings._apply();
});

// ── Lock on window hide / minimize (item 20) ──────────────────────────────
// The Tauri/browser hides the window — visibilitychange fires.
// We call the imported lockVault lazily to avoid circular deps.
// Opt-in only. Previously any window hide locked the vault as long as auto-lock
// was enabled at all, so alt-tabbing to read a doc threw away your session and
// forced a master-password re-entry. Now the inactivity timer handles walking
// away, and this fires only when the user explicitly asks for it.
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState !== 'hidden') return;
  if (st.store.isRemote || !st.vaultOpen) return;
  // Serving the LAN: peers are mid-request, alt-tabbing must not cut them off.
  if (st.lanServerRunning) return;
  if (!Settings.get('lockOnHide')) return;
  import('./lock').then((m) => m.lockVault('visibility')).catch(() => {});
});

// ── Layout helpers ─────────────────────────────────────────────────────────

export function applyGridSettings() {
  const grid = document.getElementById('card-grid');
  if (!grid) return;
  const size = Settings.get('cardSize');
  // Column width AND card height come from this one setting. The width is set
  // here (CSS cannot repeat(var())); the height and every internal dimension
  // come from the token block cards.css selects on this attribute.
  grid.dataset.cardSize = size;
  const minW = { compact: 280, medium: 360, large: 460 }[size];
  const cols = Settings.get('gridColumns');
  // An explicit column count floors at 0, not at minW. `repeat(8, minmax(360px, 1fr))`
  // demands 2880px of track before gaps and simply overflows the workspace
  // sideways on any normal window — asking for 8 columns has to mean 8 narrower
  // columns, not a horizontal scrollbar. The `min(100%, …)` on the auto branch is
  // the same protection for a window narrower than one card.
  grid.style.gridTemplateColumns =
    cols === 'auto'
      ? `repeat(auto-fill, minmax(min(100%, ${minW}px), 1fr))`
      : `repeat(${cols}, minmax(0, 1fr))`;
}

/** All toggleable/reorderable sidebar section keys, in default order. */
// `authenticator` was removed here in A2 (2026-09-14) — see the migration note
// in `Settings.init()`. The feature lives in the `auth` activity-bar panel now.
export const ALL_SIDEBAR_SECTIONS = [
  'all',
  'price',
  'env',
  'category',
  'project',
  'tags',
  'pools',
  'prefixes',
] as const;
/** Sections whose visibility is also gated on having data (handled by render). */
const DATA_GATED_SECTIONS = ['tags', 'pools', 'prefixes'];

export function isSidebarSectionEnabled(key: string): boolean {
  const sections = Settings.get('sidebarSections') || [...ALL_SIDEBAR_SECTIONS];
  return (sections as string[]).includes(key);
}

export function applySidebarOrder() {
  const sections = Settings.get('sidebarSections') || [...ALL_SIDEBAR_SECTIONS];
  ALL_SIDEBAR_SECTIONS.forEach((key) => {
    const el = document.getElementById(`sidebar-section-${key}`) as HTMLElement | null;
    if (!el) return;
    const idx = (sections as string[]).indexOf(key);
    if (idx >= 0) {
      el.style.order = String(idx);
      el.style.borderTop = idx === 0 ? '' : '1px solid var(--border)';
      el.style.marginTop = idx === 0 ? '' : '6px';
      el.style.paddingTop = idx === 0 ? '' : '6px';
      // Data-gated sections (tags/prefixes) are shown by render only when non-empty.
      if (!DATA_GATED_SECTIONS.includes(key)) el.style.display = '';
    } else {
      el.style.display = 'none';
      el.style.borderTop = '';
      el.style.marginTop = '';
      el.style.paddingTop = '';
    }
  });
  const collapsed = Settings.get('collapsedSections') || [];
  (['all', 'price', 'env', 'category', 'project', 'tags', 'pools', 'prefixes'] as const).forEach(
    (key) =>
      document
        .getElementById(`sidebar-section-${key}`)
        ?.classList.toggle('collapsed', collapsed.includes(key)),
  );
}

// ── Sidebar width / collapse persistence ───────────────────────────────────

/** Drag bounds for the sidebar, also used to sanitise the persisted width. */
export const SIDEBAR_MIN_W = 140;
export const SIDEBAR_MAX_W = 420;

/**
 * Applies the persisted sidebar width and collapsed state.
 *
 * Width is clamped here rather than only at drag time: the value survives in
 * localStorage, so a width written by an older build, a hand-edited settings
 * file or a different screen size can otherwise leave the sidebar at 3px wide
 * with no visible handle to drag it back.
 */
export function applySidebarLayout(): void {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  const w = Number(Settings.get('sidebarWidth')) || 0;
  const clamped = w > 0 ? Math.max(SIDEBAR_MIN_W, Math.min(SIDEBAR_MAX_W, w)) : 0;
  sidebar.style.width = clamped > 0 ? `${clamped}px` : '';
  const collapsed = !!Settings.get('sidebarCollapsed');
  sidebar.classList.toggle('collapsed', collapsed);
  // The toggle button *controls* the sidebar, so it — not the sidebar — carries
  // aria-expanded. Restored state has to reach it too, or the very first launch
  // after a collapse announces the opposite of what is on screen.
  document.getElementById('sidebar-toggle')?.setAttribute('aria-expanded', String(!collapsed));
  document
    .getElementById('sidebar-resizer')
    ?.setAttribute('aria-valuenow', String(clamped || SIDEBAR_MIN_W));
}

// ── Recent searches ────────────────────────────────────────────────────────

/** How many search strings the history dropdown keeps. */
export const RECENT_SEARCH_MAX = 8;

/**
 * Records a search string, most-recent-first, de-duplicated.
 *
 * Case-insensitive de-dup, but the *newest* casing wins, so retyping a query
 * differently does not leave two near-identical rows in the dropdown.
 */
export function pushRecentSearch(q: string): void {
  const query = q.trim();
  if (!query) return;
  const prev = (Settings.get('recentSearches') || []).filter(
    (s) => s.toLowerCase() !== query.toLowerCase(),
  );
  Settings.set('recentSearches', [query, ...prev].slice(0, RECENT_SEARCH_MAX));
}

// ── View persistence ───────────────────────────────────────────────────────

/** Snapshots the current grid view so the next launch can restore it. */
export function saveViewState(): void {
  if (!Settings.get('rememberFilters')) return;
  Settings.set('lastView', {
    filterType: st.filter.type,
    filterValue: st.filter.value,
    envFilter: st.currentEnvFilter,
    tagFilter: st.activeTagFilter,
    prefixFilter: st.activePrefixFilter,
    poolFilter: st.activePoolFilter,
    typeChips: [...st.activeTypeChips],
    expandedBundleIds: [...st.expandedBundles],
    bundleSlotTabs: { ...st.bundleSlotTabs },
    projectIds: [...st.currentSelectedProjectIds],
  });
}

/**
 * Restores the last grid view, dropping anything the loaded vault does not have.
 *
 * The validation is the whole point. A persisted selection is a reference held
 * across a restart, and the vault it pointed at may have been edited, replaced
 * by an import, or swapped for a remote in the meantime (invariant 3). An id
 * that no longer resolves matches nothing in `getFiltered()`, so the user would
 * open the app to an empty grid with their secrets present but invisible — and
 * with no obvious control to un-stick it, because the stale filter is not one
 * they set this session.
 *
 * @returns true when anything was applied, so the caller knows to repaint.
 */
export function restoreViewState(): boolean {
  if (!Settings.get('rememberFilters')) return false;
  const v = Settings.get('lastView');
  if (!v || typeof v !== 'object') return false;

  const entries = st.vault.api_keys || [];
  let applied = false;

  if (Array.isArray(v.expandedBundleIds)) {
    const bundles = new Set(
      entries.filter((entry) => entry.secretType === 'bundle').map((entry) => entryId(entry)),
    );
    const expanded = v.expandedBundleIds.filter((id) => bundles.has(id));
    st.expandedBundles = new Set(expanded);
    applied ||= expanded.length > 0;
  }

  const validSlotTabs: Record<string, string> = {};
  if (
    v.bundleSlotTabs &&
    typeof v.bundleSlotTabs === 'object' &&
    !Array.isArray(v.bundleSlotTabs)
  ) {
    for (const [bundleId, memberId] of Object.entries(v.bundleSlotTabs)) {
      if (
        typeof memberId === 'string' &&
        entries.some((entry) => entry.id === bundleId && entry.secretType === 'bundle') &&
        entries.some((entry) => entry.id === memberId && entry.bundle_id === bundleId)
      )
        validSlotTabs[bundleId] = memberId;
    }
  }
  st.bundleSlotTabs = validSlotTabs;
  applied ||= Object.keys(validSlotTabs).length > 0;

  const categories = new Set(st.vault.user_categories || []);
  const okFilter =
    v.filterType === 'all' ||
    (v.filterType === 'price' && entries.some((e) => e.price_type === v.filterValue)) ||
    (v.filterType === 'category' &&
      (categories.has(v.filterValue) ||
        [...categories].some((c) => c.startsWith(v.filterValue + '/'))));
  if (okFilter && typeof v.filterType === 'string') {
    st.filter = { type: v.filterType, value: String(v.filterValue ?? '') };
    applied = applied || v.filterType !== 'all';
  }

  if (v.envFilter && entries.some((e) => e.environment === v.envFilter)) {
    st.currentEnvFilter = v.envFilter;
    applied = true;
  }
  if (v.tagFilter && entries.some((e) => (e.tags || []).includes(v.tagFilter!))) {
    st.activeTagFilter = v.tagFilter;
    applied = true;
  }
  if (v.prefixFilter && entries.some((e) => (e.provider || '').startsWith(v.prefixFilter!))) {
    st.activePrefixFilter = v.prefixFilter;
    applied = true;
  }
  // A pool is named, not identified, so it stops existing the moment its last
  // member's `pool` field is cleared or renamed. Restoring it unvalidated opens
  // the app to an empty grid under a filter the user never set this session.
  if (v.poolFilter && entries.some((e) => e.pool === v.poolFilter)) {
    st.activePoolFilter = v.poolFilter;
    applied = true;
  }
  // Each chip must still mean something against the loaded vault: '__totp' is
  // always a valid concept, but a SecretType chip for a type this vault no
  // longer has would silently narrow the grid to nothing — and so would a
  // stale '__pool' from a `lastView` written before the Pool chip was
  // removed (invariant 7): nothing matches that token any more, so restoring
  // it unfiltered would open the app to an empty grid with no filter visibly
  // set. Dropped explicitly rather than left to fall through to the "does any
  // entry have this secretType" check, which a literal `'__pool'` would
  // always fail anyway — but failing it *on purpose*, not by accident, is
  // the difference between a decision and a bug that happens to look right.
  if (Array.isArray(v.typeChips) && v.typeChips.length) {
    const validChips = v.typeChips.filter(
      (c) =>
        c !== '__pool' &&
        (c === '__totp' || entries.some((e) => (e.secretType || 'api_key') === c)),
    );
    if (validChips.length) {
      st.activeTypeChips = new Set(validChips);
      applied = true;
    }
  }

  const known = new Set((st.vault.projects || []).map((p) => p.id));
  const projects = (Array.isArray(v.projectIds) ? v.projectIds : []).filter((id) => known.has(id));
  if (projects.length) {
    st.currentSelectedProjectIds = projects;
    applied = applied || !(projects.length === 1 && projects[0] === 'Universal');
  }

  return applied;
}

export function applyActivityBar() {
  const pos = Settings.get('activityBarPosition') || 'left';
  const style = Settings.get('activityBarStyle') || 'icon';
  const layout = document.getElementById('layout')!;
  layout.classList.toggle('activity-bar-right', pos === 'right');
  layout.classList.toggle('activity-bar-icon-label', style === 'icon-label');
}

/**
 * Users/RBAC only means something when this vault is actually being served to
 * other people — either we're connected to a remote server, or we're serving
 * our own vault over LAN.
 *
 * On a purely local vault the panel wrote users into the desktop's own
 * `vault.db`, which `unv-server` never reads (it uses its own file). Accounts
 * created there could never authenticate anywhere: it looked like it worked and
 * silently did nothing.
 */
export function usersPanelAvailable(): boolean {
  return st.store.isRemote || st.lanServerRunning;
}

/** Show or hide the Users entry in the activity bar, and bail out of it if open. */
export function applyUsersPanelVisibility(): void {
  const available = usersPanelAvailable();
  const btn = document.querySelector<HTMLElement>('.activity-btn[data-panel="users"]');
  if (btn) btn.style.display = available ? '' : 'none';
  if (!available && Settings.get('activePanel') === 'users') switchPanel('secrets');
}

export function switchPanel(panel: Panel) {
  const panelEls: Record<string, string[]> = {
    secrets: ['secrets-panel', 'vault-workspace'],
    tools: ['tools-panel', 'tools-workspace'],
    users: ['users-panel', 'users-workspace'],
    remote: ['remote-panel', 'remote-workspace'],
    auth: ['auth-panel', 'auth-workspace'],
  };
  const allSidebars = ['secrets-panel', 'tools-panel', 'users-panel', 'remote-panel', 'auth-panel'];
  const allWorkspaces = [
    'vault-workspace',
    'tools-workspace',
    'users-workspace',
    'remote-workspace',
    'auth-workspace',
  ];
  allSidebars.forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
  allWorkspaces.forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });

  const active = panelEls[panel] ?? panelEls.secrets;
  active.forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.style.display = '';
  });

  // `active` is paint; `aria-selected` is the same fact told to a screen reader,
  // and the roving `tabindex` is what stops a four-button tablist costing four
  // Tab presses to get past. All three must move together or the tablist lies.
  document.querySelectorAll<HTMLButtonElement>('.activity-btn').forEach((btn) => {
    const on = btn.dataset.panel === panel;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-selected', on ? 'true' : 'false');
    btn.tabIndex = on ? 0 : -1;
  });
  Settings.set('activePanel', panel);

  if (panel === 'users') import('./users').then((m) => m.renderUsersPanel()).catch(() => {});
  // The authenticator screen paints its own list, and the ticker it starts is
  // idempotent by assignment, so re-entering the panel costs one render and no
  // second timer.
  if (panel === 'auth') import('./auth-panel').then((m) => m.renderAuthPanel()).catch(() => {});
  if (panel === 'remote')
    import('./remote-panel').then((m) => m.renderRemotePanel()).catch(() => {});
}

export function switchTool(toolId: string) {
  document
    .querySelectorAll<HTMLElement>('.tool-pane')
    .forEach((p) => (p.style.display = p.id === `tool-${toolId}` ? '' : 'none'));
  document.querySelectorAll<HTMLButtonElement>('.tool-nav-btn').forEach((btn) => {
    const on = btn.dataset.tool === toolId;
    btn.classList.toggle('active', on);
    // aria-current rather than aria-selected: these are navigation links into a
    // list of tools, not tabs — there is no tablist wrapping them and claiming
    // otherwise would promise arrow-key semantics that do not exist here.
    if (on) btn.setAttribute('aria-current', 'true');
    else btn.removeAttribute('aria-current');
  });
  Settings.set('activeTool', toolId);
  if (toolId === 'nodes') import('./nodes-pane').then((m) => m.refreshNodes()).catch(() => {});
}

// ── The environment-variable name template ─────────────────────────────────
//
// Phase 23, step 1. **Every generated environment-variable name is built here,
// in one order, and nothing else may construct one.** Before this there were
// three builders that disagreed: `dotenvKey` (provider + key_id) fed the
// `.env` and YAML exports, `envKey` in `import-export.ts` (provider only) fed
// the k8s and tfvars exports, and `data::env_key` in the CLI (provider only)
// fed all four of its. The same entry therefore exported under two different
// names depending on which button you pressed.
//
// The template:
//
//     [PREFIX_] PROVIDER [_KEYID] [_VERSION] [_LABEL] [_ROLE]
//
// **`KEYID` is a deviation from the Phase 23 design, which lists six segments
// and not this one**, on the grounds that `key_id` is identity rather than a
// value. That is true of what it *means* and false of what it already *does*:
// `dotenvKey` has put it in the name since Phase 3, `chunks/env-link.ts` scores
// `PROVIDER_KEYID` as a tier-1 match, and `find_entry` in the CLI parses a bare
// `${NAME}` by splitting on the last underscore into exactly that pair.
// Dropping it would silently rename every variable generated for a keyed entry
// — which is the failure the design's own "the one thing this must not break"
// section is about — in exchange for nothing. Written down because an
// undocumented deviation is indistinguishable from having missed the design.
//
// The twin is `env_name()` in `unv-cli/src/envfile.rs`, pinned by
// `tests/fixtures/parity/env-names.json` and asserted from both sides. It has
// to exist twice because the add/edit form previews the name as it is typed and
// an IPC round trip per keystroke is not a form — the same reason the TOTP seed
// parser exists twice.

/** How the finished name is cased. `upper` is the shell convention and the default. */
export type EnvNameCase = 'upper' | 'preserve' | 'lower';

/** Everything `envName` needs that does not come from the entry. */
export interface EnvNameOpts {
  /** The value's role — `ID`, `SECRET`, an `extra_vars` key. Absent or `value` omits the segment. */
  role?: string | null;
  /** Defaults to the `envCopyCase` setting. */
  case?: EnvNameCase;
  /** Prepend `env_prefixes[0]`. Defaults to the `envIncludePrefix` setting, which is off. */
  includePrefix?: boolean;
}

/** What a legal POSIX-ish environment-variable name looks like. */
export const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * One segment, normalised.
 *
 * Anything outside `[A-Za-z0-9]` collapses to `_`, runs of `_` collapse to one,
 * and leading/trailing `_` are trimmed — which is what stops `SPOTIFY__ID` when
 * a segment ends in punctuation as well as when it is empty.
 */
function envSegment(raw: string | null | undefined, fold: boolean): string {
  let seg = raw ?? '';
  if (fold) seg = seg.toUpperCase();
  return seg
    .replace(/[^A-Za-z0-9]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '');
}

/**
 * The version segment: `2`, `v2`, `V2` → `V2`; `2.0` → `V2_0`;
 * `2026-08-01` → `V2026_08_01`.
 *
 * The leading `v` is stripped **only when a digit follows it**, so the `V` is
 * added once and never doubled, and a word-shaped version (`beta`, `vault`)
 * keeps its first letter instead of being silently decapitated.
 */
export function envVersionSegment(raw: string | null | undefined, fold: boolean): string {
  const trimmed = (raw ?? '').trim();
  const body = /^[vV][0-9]/.test(trimmed) ? trimmed.slice(1) : trimmed;
  const seg = envSegment(body, fold);
  if (!seg) return '';
  return /^[0-9]/.test(seg) ? `V${seg}` : seg;
}

/**
 * Strip a cookie's `__Host-` / `__Secure-` prefix.
 *
 * They are **stripped, not transliterated**: `__HOST_SID` is not a name anyone
 * asked for, and the two prefixes are a browser-side attribute of where a cookie
 * may be set rather than part of its name. That three cookies can collapse into
 * one name is exactly the case E2's collision check has to warn about (step 6),
 * which is why this happens before the segment is normalised rather than inside
 * the normaliser.
 */
export function stripCookiePrefix(name: string): string {
  return name.replace(/^__(?:Host|Secure)-/i, '');
}

/**
 * The environment-variable name this entry generates for `opts.role`.
 *
 * Always returns a legal identifier: a leading digit gains a `_` (no shell will
 * export a name that starts with one), and an entry that normalises away to
 * nothing at all comes back as `UNKNOWN` rather than as the empty string, which
 * would write a nameless `=value` line.
 */
export function envName(entry: VaultEntry, opts: EnvNameOpts = {}): string {
  const mode: EnvNameCase = opts.case ?? (Settings.get('envCopyCase') as EnvNameCase) ?? 'upper';
  const withPrefix = opts.includePrefix ?? !!Settings.get('envIncludePrefix');
  const fold = mode !== 'preserve';

  const role = opts.role && opts.role.toLowerCase() !== 'value' ? stripCookiePrefix(opts.role) : '';

  const parts = [
    withPrefix ? envSegment(entry.env_prefixes?.[0], fold) : '',
    envSegment(entry.provider || 'UNKNOWN', fold),
    envSegment(entry.key_id, fold),
    envVersionSegment(entry.version, fold),
    envSegment(entry.label, fold),
    envSegment(role, fold),
  ].filter(Boolean);

  let name = parts.join('_') || 'UNKNOWN';
  if (/^[0-9]/.test(name)) name = `_${name}`;
  if (mode === 'lower') name = name.toLowerCase();
  return name;
}

// ── Name collisions ────────────────────────────────────────────────────────
//
// Phase 23, E2. Two entries generating the same variable name is a **silent
// overwrite** in whatever loads the file: the dotenv writers emit duplicate
// lines and every parser takes the last, and `Exporter.yaml` writes
// `doc[name] = …`, so the second entry simply wins.
//
// Two entirely routine setups hit it. A **key pool** is by definition several
// entries for one provider, so "Copy All" over a pool emits N identical names.
// And one entry with `primary_role: 'id'` plus an `extra_vars` entry keyed `ID`
// emits `SPOTIFY_ID` twice all by itself.
//
// Compared **case-insensitively**, because Windows environment variables are
// case-insensitive: `envCopyCase: 'preserve'` can produce a pair that collides
// there and not on Linux, which is the worst possible place to find out.

/** One generated name and where it came from. */
export interface GeneratedName {
  name: string;
  entry: VaultEntry;
  /** The role segment — a value role, an `extra_vars` key, or `''` for the primary. */
  role: string;
}

/** Every name one entry generates, in the order a copy emits them. */
export function namesGeneratedBy(entry: VaultEntry, opts: EnvNameOpts = {}): GeneratedName[] {
  const out: GeneratedName[] = [];
  if (entry.api_key) out.push({ name: primaryEnvName(entry, opts), entry, role: '' });
  if (entry.api_secret)
    out.push({ name: secretEnvName(entry, opts), entry, role: entry.secret_role || 'SECRET' });
  if (entry.api_url)
    out.push({ name: envName(entry, { ...opts, role: 'URL' }), entry, role: 'URL' });
  for (const xv of entry.extra_vars ?? []) {
    if (!xv.key) continue;
    out.push({ name: envName(entry, { ...opts, role: xv.key }), entry, role: xv.key });
  }
  return out;
}

/** A name two or more values want. */
export interface NameCollision {
  name: string;
  sources: GeneratedName[];
}

/**
 * Every collision across a selection, including within a single entry.
 *
 * Returns the *groups*, not a boolean: naming both sides is the difference
 * between a warning somebody can act on and one they have to go hunting for.
 */
export function findNameCollisions(entries: VaultEntry[], opts: EnvNameOpts = {}): NameCollision[] {
  const byName = new Map<string, GeneratedName[]>();
  for (const entry of entries) {
    for (const g of namesGeneratedBy(entry, opts)) {
      const key = g.name.toUpperCase();
      const list = byName.get(key);
      if (list) list.push(g);
      else byName.set(key, [g]);
    }
  }
  return [...byName.values()]
    .filter((list) => list.length > 1)
    .map((list) => ({ name: list[0].name, sources: list }));
}

/**
 * Make every name in a list unique, **appending rather than dropping**.
 *
 * A copy that silently emitted one line where the user expected two is the
 * failure this exists to prevent; a name with a suffix is visibly odd and
 * recoverable, a missing variable is neither.
 *
 * Pool members are disambiguated by their position in the pool, everything else
 * by its `key_id` — and by an ordinal when even that is not enough, because the
 * function must terminate with a unique name whatever the data says.
 */
export function disambiguateNames(names: GeneratedName[]): string[] {
  const counts = new Map<string, number>();
  for (const g of names) {
    const k = g.name.toUpperCase();
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  // Everything already emitted, so a suffix can never collide with a name that
  // was fine on its own — appending `_2` to one line and hitting an entry that
  // genuinely generates `X_2` would trade one silent overwrite for another.
  const used = new Set<string>(names.map((g) => g.name.toUpperCase()));

  // The **first** occurrence keeps the name it generated. Renaming both halves
  // of a collision would change a variable that was never ambiguous for the
  // consumer that reads it first, which is the rename this phase's "one thing
  // this must not break" section is about.
  const taken = new Set<string>();

  return names.map((g) => {
    const key = g.name.toUpperCase();
    if ((counts.get(key) ?? 0) < 2) return g.name;
    if (!taken.has(key)) {
      taken.add(key);
      return g.name;
    }
    // An **ordinal**, not the `key_id`.
    //
    // The design says pool members get `_1`/`_2` and everything else gets the
    // `key_id` — written when `key_id` was not expected to be part of the
    // generated name. In this implementation it always is (it is a segment of
    // the template), so appending it again can never disambiguate anything: the
    // two colliding names already contain it. Ordinals it is, and they are
    // stable for a given entry because the emission order is.
    for (let n = 2; n <= names.length + 2; n++) {
      const c = `${g.name}_${n}`;
      if (!used.has(c.toUpperCase())) {
        used.add(c.toUpperCase());
        return c;
      }
    }
    return g.name;
  });
}

// ── Quoting on the way into a `.env` ───────────────────────────────────────
//
// Phase 23, E1. Nothing quoted a value before this: a cookie string
// (`sid=x; csrf=y`), a User-Agent, a password containing `#` and any value with
// a trailing space all produced a file that parsed back as something else. The
// round-trip test exercised the parser only, and the parser stripped exactly one
// layer of surrounding quotes with no escape handling at all.
//
// The property that matters is `parse(write(v)) === v`, not the bytes in
// between — `tests/fixtures/parity/env-names.json` asserts the round trip from
// both sides.

/** Values safe to write bare. Deliberately narrow: anything else gets quoted. */
const ENV_BARE_RE = /^[A-Za-z0-9_./:@-]+$/;

/**
 * A value as it must appear after the `=`.
 *
 * The empty string quotes to `""` rather than to nothing, because a bare `KEY=`
 * is how "unset" is spelled and a deliberately empty value must not read as one.
 * A newline is escaped rather than emitted, so the parser's backslash
 * line-continuation can never see one.
 */
export function quoteEnvValue(value: string): string {
  const v = value ?? '';
  if (v !== '' && ENV_BARE_RE.test(v)) return v;
  return `"${v
    .replace(/[\\"$`]/g, (c) => `\\${c}`)
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')}"`;
}

/**
 * The inverse, applied by the `.env` parsers.
 *
 * Double quotes unescape, single quotes do not — which is what the shells these
 * files are read by do, and what the apps that read them (`dotenv`, `python-dotenv`,
 * `compose`) do too.
 */
export function unquoteEnvValue(raw: string): string {
  const v = raw ?? '';
  if (v.length >= 2 && v.startsWith("'") && v.endsWith("'")) return v.slice(1, -1);
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) {
    return v.slice(1, -1).replace(/\\(.)/g, (_m, c: string) => {
      if (c === 'n') return '\n';
      if (c === 'r') return '\r';
      if (c === 't') return '\t';
      return c;
    });
  }
  return v;
}

/**
 * Everything this entry actually holds, as far as "is it empty?" is concerned.
 *
 * Phase 23, step 4 relaxed the rule that an entry must carry a primary value.
 * Three shapes legitimately have none:
 *
 * - an `env_var` entry whose payload is N named variables in `extra_vars`;
 * - an entry carrying only an authenticator seed (Phase 22 — what an import
 *   from Ente or Aegis produces, when the password lives elsewhere);
 * - a `certificate` or `file_blob`, whose payload is its own field.
 *
 * "The primary value is never empty" was assumed in more places than it was
 * stated, so this is the single predicate every one of those places now asks,
 * rather than each re-deriving it and drifting.
 */
export function entryHasPayload(entry: VaultEntry): boolean {
  if (entry.api_key) return true;
  if (entry.api_secret) return true;
  if (entry.totp_secret) return true;
  if (entry.certificate_data || entry.cert_key_data) return true;
  if (entry.blob_ref) return true;
  // A composite's payload is its template (parts are `extra_vars`, checked
  // below anyway, but a template with zero parts is still a real composite —
  // `unv describe`-shaped structure, not a value). A bundle's payload is
  // membership it does not itself record — see B2 in the design, deferred —
  // so it is never reported empty from this predicate alone.
  if (entry.secretType === 'composite') return !!entry.composite_template;
  if (entry.secretType === 'bundle') return true;
  return (entry.extra_vars ?? []).some((v) => v.key);
}

/**
 * True when this entry is allowed to have no primary value.
 *
 * Distinct from {@link entryHasPayload}: that asks whether anything is stored at
 * all, this asks whether the *form* should insist on the primary slot.
 */
export function primaryIsOptional(entry: VaultEntry): boolean {
  const t = entry.secretType || 'api_key';
  // A composite's value is its rendered template, never `api_key`; a
  // bundle's payload is entirely its members and local variables. Neither
  // type has any use for the primary slot at all.
  if (t === 'certificate' || t === 'file_blob' || t === 'composite' || t === 'bundle') return true;
  if (t === 'env_var') return (entry.extra_vars ?? []).some((v) => v.key);
  // Phase 24.5's sixteen new types all carry `primary: null` in the
  // secret-type registry — none of them has a single primary slot the way
  // `api_key`/`password` do, so the value field is optional the same way it
  // is for `composite`/`bundle`: the real payload is `extra_vars`.
  if (SECRET_TYPES_WITH_NO_PRIMARY.has(t)) return true;
  return !!entry.totp_secret;
}

/** The Phase 24.5 types with `primary: null` — kept as a literal set rather
 * than reading `secret-types.json` here, since `primaryIsOptional` runs on
 * every keystroke in the add/edit form and a `Set` built once is cheaper than
 * a registry lookup on every call. `tests/secret-types.test.ts` pins the two
 * in agreement. */
const SECRET_TYPES_WITH_NO_PRIMARY = new Set([
  'oauth_client',
  'signing_key',
  'registry_token',
  'database',
  'recovery_codes',
  'gpg_key',
  'age_key',
  'local_service',
  'tracker',
  'usenet_server',
  'wifi',
  'license_key',
  'crypto_wallet',
  'passkey',
  'secure_note',
  'identity_document',
]);

// ── Exporter + dotenvKey ───────────────────────────────────────────────────

/**
 * The name of an entry's **primary** value.
 *
 * Role-aware: an entry marked `primary_role: 'id'` generates `SPOTIFY_ID`
 * rather than `SPOTIFY`, which is the reported bug this phase exists to fix —
 * an OAuth client id exported as though it were the key.
 *
 * An entry with no `primary_role` keeps the bare name. That is deliberate and
 * it is the whole reason the field is opt-in: every `.env` already deployed
 * from this app names the primary value `PROVIDER=`.
 */
export function primaryEnvName(entry: VaultEntry, opts: EnvNameOpts = {}): string {
  return envName(entry, { ...opts, role: entry.primary_role ?? null });
}

/**
 * The name of an entry's `api_secret`.
 *
 * `SECRET` unless the entry says otherwise — `secret_role` exists for the
 * issuers whose second half is not called a secret (`AUTH_TOKEN`, `API_SECRET`,
 * `PRIVATE_KEY`).
 */
export function secretEnvName(entry: VaultEntry, opts: EnvNameOpts = {}): string {
  return envName(entry, { ...opts, role: entry.secret_role || 'SECRET' });
}

/**
 * The `.env` name for an entry's primary value.
 *
 * Kept as the name every caller already uses; it is now one line rather than a
 * second implementation of the template.
 */
export function dotenvKey(entry: VaultEntry): string {
  return primaryEnvName(entry);
}

export const Exporter = {
  dotenv(keys: VaultEntry[]): string {
    return keys
      .map((k) => {
        // Quoted on the way out (E1). A cookie string, a User-Agent, a
        // password containing `#` and any value with a trailing space all
        // produced a file that parsed back as something else.
        const lines = [`# ${k.provider}${k.account_name ? ' — ' + k.account_name : ''}`];
        // An empty primary is **omitted**, not written as `NAME=` (Phase 23,
        // step 4). `env_var` entries carry their payload in `extra_vars` and an
        // authenticator-only entry has no primary at all, so emitting the bare
        // name writes a variable that reads as "set to the empty string" into a
        // file about to be loaded — which is a different claim from saying
        // nothing, and the one thing `out.rs` deliberately keeps `empty`
        // distinguishable for.
        if (k.api_key) lines.push(`${primaryEnvName(k)}=${quoteEnvValue(k.api_key)}`);
        if (k.api_secret) lines.push(`${secretEnvName(k)}=${quoteEnvValue(k.api_secret)}`);
        if (k.api_url) lines.push(`${envName(k, { role: 'URL' })}=${quoteEnvValue(k.api_url)}`);
        for (const xv of k.extra_vars ?? []) {
          if (!xv.key) continue;
          lines.push(`${envName(k, { role: xv.key })}=${quoteEnvValue(xv.value ?? '')}`);
        }
        return lines.join('\n');
      })
      .join('\n\n');
  },
  /**
   * YAML export.
   *
   * Delegates quoting to js-yaml. The previous implementation concatenated
   * `KEY: "value"` by hand, which produced invalid YAML for any secret
   * containing a double quote, backslash or newline — i.e. exactly the
   * characters that show up in passwords and PEM blobs.
   */
  yaml(keys: VaultEntry[]): string {
    const doc: Record<string, string> = {};
    keys.forEach((k) => {
      if (k.api_key) doc[primaryEnvName(k)] = k.api_key;
      if (k.api_secret) doc[secretEnvName(k)] = k.api_secret;
      if (k.api_url) doc[envName(k, { role: 'URL' })] = k.api_url;
      for (const xv of k.extra_vars ?? []) {
        if (xv.key) doc[envName(k, { role: xv.key })] = xv.value ?? '';
      }
    });
    const header = `# UnENVerse Export\n# Generated: ${new Date().toISOString()}\n\n`;
    return header + yamlDump(doc, { indent: 2, lineWidth: -1, noRefs: true });
  },
  json(keys: VaultEntry[]): string {
    return JSON.stringify({ api_keys: keys }, null, 2);
  },
};
