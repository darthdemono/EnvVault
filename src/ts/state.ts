import type { VaultData, AppSettings, VaultEntry, RemoteVaultConfig, PersistedView } from './types';
import { dump as yamlDump } from 'js-yaml';
import { hexAlpha, showToast } from './utils';

// ── VaultStore ─────────────────────────────────────────────────────────────

export interface VaultStore {
  load(): Promise<VaultData | null>;
  save(data: VaultData): Promise<void>;
  readonly isRemote: boolean;
  readonly vaultId: string;
}

export class LocalVaultStore implements VaultStore {
  async load(): Promise<VaultData | null> {
    const raw = sessionStorage.getItem('envvault');
    return raw ? JSON.parse(raw) : null;
  }
  async save(data: VaultData): Promise<void> {
    try { sessionStorage.setItem('envvault', JSON.stringify(data)); }
    catch { showToast('Session storage full — export to save changes', 'err'); }
  }
  get isRemote() { return false; }
  get vaultId()  { return 'local'; }
}

/** Thrown when a write was refused because someone else wrote first. */
export class VaultConflictError extends Error {
  constructor() { super('The vault changed since you last loaded it'); this.name = 'VaultConflictError'; }
}

export class TauriVaultStore implements VaultStore {
  private invoke = (window as any).__TAURI__?.core?.invoke?.bind((window as any).__TAURI__.core);
  /**
   * Version of the vault as we last read it.
   *
   * Sent with every save as a compare-and-swap. Without it the desktop wrote the
   * whole blob unconditionally, so while "Open to LAN" is running a peer's edit
   * landing between our load and our next save was silently overwritten.
   */
  private lastVersion: string | null = null;

  async unlock(password: string): Promise<boolean>  { return this.invoke('unlock_vault', { password }); }
  async lock(): Promise<void>                       { return this.invoke('lock_vault'); }
  async isUnlocked(): Promise<boolean>              { return this.invoke('vault_is_unlocked'); }
  async exists(): Promise<boolean>                  { return this.invoke('vault_exists'); }
  async reset(): Promise<void>                      { return this.invoke('reset_vault'); }
  async vaultFilePath(): Promise<string>            { return this.invoke('get_vault_path').catch(() => ''); }

  async load(): Promise<VaultData | null> {
    const res = await this.invoke('load_vault') as { data: VaultData; version: string | null } | null;
    this.lastVersion = res?.version ?? null;
    return res?.data ?? null;
  }

  async save(data: VaultData): Promise<void> {
    try {
      this.lastVersion = await this.invoke('save_vault', {
        data,
        expectVersion: this.lastVersion,
      });
    } catch (e: any) {
      if (String(e?.message ?? e).includes('VAULT_CONFLICT')) throw new VaultConflictError();
      throw e;
    }
  }

  /**
   * Write regardless of what is currently stored, adopting the result as our
   * new base. Only for a user explicitly choosing to overwrite after a conflict.
   */
  async forceSave(data: VaultData): Promise<void> {
    this.lastVersion = await this.invoke('save_vault', { data, expectVersion: null });
  }

  get isRemote() { return false; }
  get vaultId()  { return 'local-native'; }
}

export const inTauri = !!(window as any).__TAURI__;
const _invoke = (window as any).__TAURI__?.core?.invoke?.bind((window as any).__TAURI__?.core);

export class RemoteVaultStore implements VaultStore {
  private token = '';
  /** ETag (vault content version) from the last successful load — sent as If-Match to detect drift. */
  private lastVersion = '';
  /** certFingerprint enables TOFU cert pinning when the server runs TLS with a self-signed cert. */
  constructor(public readonly baseUrl: string, public fingerprint?: string) {}

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
  ): Promise<{ ok: boolean; status: number; json: () => Promise<any>; etag: string | null }> {
    const url = `${this.baseUrl}${path}`;
    const useNative = inTauri && url.startsWith('https://');

    if (useNative && _invoke) {
      // Tauri proxy does not surface response headers — ETag unavailable on this path.
      const result = await _invoke('remote_request', {
        url,
        method: opts.method ?? 'GET',
        headersJson: JSON.stringify(opts.headers ?? {}),
        body: opts.body ?? null,
        fingerprint: this.fingerprint ?? null,
      }) as { status: number; body: string };
      const ok = result.status >= 200 && result.status < 300;
      return { ok, status: result.status, json: async () => JSON.parse(result.body), etag: null };
    }

    const headers: Record<string, string> = {};
    if (opts.headers) Object.assign(headers, opts.headers);
    const r = await fetch(url, { method: opts.method, headers, body: opts.body });
    return { ok: r.ok, status: r.status, json: () => r.json(), etag: r.headers.get('etag') };
  }

  /**
   * Authenticated REST call for the user/class management panel.
   * Returns parsed JSON, or `null` for 204 No Content. Throws on non-2xx with the server error.
   */
  async api(path: string, method = 'GET', body?: any): Promise<any> {
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
      throw new Error(err?.error ?? `Server error ${r.status}`);
    }
    if (r.status === 204) return null;
    return r.json().catch(() => null);
  }

  async unlock(password: string): Promise<boolean> {
    const r = await this._apiFetch('/api/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(body?.error ?? `Server error ${r.status}`);
    }
    const { token } = await r.json();
    this.token = token ?? '';
    return !!this.token;
  }

  async authUser(username: string, password: string): Promise<boolean> {
    const r = await this._apiFetch('/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(body?.error ?? `Auth failed ${r.status}`);
    }
    const { token } = await r.json();
    this.token = token ?? '';
    return !!this.token;
  }

  async lock(): Promise<void> {
    if (!this.token) return;
    try {
      await this._apiFetch('/api/unlock', {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${this.token}` },
      });
    } catch { /* ignore */ }
    this.token = '';
  }

  async isUnlocked(): Promise<boolean> {
    if (!this.token) return false;
    try {
      const r = await this._apiFetch('/api/status');
      return r.ok && (await r.json()).unlocked === true;
    } catch { return false; }
  }

  async load(): Promise<VaultData | null> {
    if (!this.token) return null;
    try {
      const r = await this._apiFetch('/api/vault', {
        headers: { Authorization: `Bearer ${this.token}` },
      });
      if (r.ok && r.etag) this.lastVersion = r.etag;
      return r.ok ? await r.json() : null;
    } catch { return null; }
  }

  async save(data: VaultData): Promise<void> {
    if (!this.token) return;
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json', Authorization: `Bearer ${this.token}` };
      // Optimistic concurrency: prove we wrote against the version we last read.
      if (this.lastVersion) headers['If-Match'] = this.lastVersion;
      const r = await this._apiFetch('/api/vault', { method: 'PUT', headers, body: JSON.stringify(data) });
      if (r.status === 409) {
        showToast('Conflict: vault changed on server since you loaded it. Reconnect/reload before saving.', 'err', 6000);
        return;
      }
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        showToast(`Remote save failed (${r.status})${body?.error ? ': ' + body.error : ''}`, 'err', 4000);
        return;
      }
      // Saved cleanly — drop the token so the next write is unconditional until the next load refreshes it.
      this.lastVersion = '';
    } catch (e: any) {
      showToast(`Remote save failed: ${e?.message ?? 'network error'}`, 'err', 4000);
    }
  }

  async getExpiring(days: number): Promise<any[]> {
    if (!this.token) return [];
    try {
      const r = await this._apiFetch(`/api/vault/expiring?days=${days}`, {
        headers: { Authorization: `Bearer ${this.token}` },
      });
      return r.ok ? await r.json() : [];
    } catch { return []; }
  }

  async getAuditLog(): Promise<any[]> {
    if (!this.token) return [];
    try {
      const r = await this._apiFetch('/api/audit', {
        headers: { Authorization: `Bearer ${this.token}` },
      });
      return r.ok ? await r.json() : [];
    } catch { return []; }
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
    } catch { return false; }
  }

  /** Fetch server status including TLS cert fingerprint (no auth needed). */
  async getStatus(): Promise<{ unlocked: boolean; vault_exists: boolean; cert_fingerprint?: string }> {
    try {
      const r = await this._apiFetch('/api/status');
      return r.ok ? await r.json() : { unlocked: false, vault_exists: false };
    } catch { return { unlocked: false, vault_exists: false }; }
  }

  get isRemote() { return true; }
  get vaultId()  { return this.baseUrl; }
}

// ── Global mutable state bag ───────────────────────────────────────────────
// All modules import `st` and read/write st.xxx directly.
// Using a single object avoids ESM live-binding reassignment restrictions.

export const st = {
  vault: {
    api_keys: [],
    user_categories: [],
    projects: [{ id: 'Universal', name: 'Universal', description: 'All keys belong here by default' }],
  } as VaultData,
  schema: null as any,
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
  undoStack: [] as Array<{ fn: () => void; t: ReturnType<typeof setTimeout> }>,
  /** Reveal state keyed `"<field>-<entryId>"` — index-independent, see `expanded`. */
  revealed: {} as Record<string, boolean>,
  currentSelectedProjectIds: ['Universal'] as string[],
  currentSortBy: 'provider',
  formCustomSelects: new Map<string, any>(),
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

/** Stable id for an entry, assigning one if somehow still absent. */
export function entryId(entry: VaultEntry): string {
  if (!entry.id) entry.id = newEntryId();
  return entry.id;
}

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
    await st.store.save(st.vault);
  } catch (err: any) {
    if (err instanceof VaultConflictError) {
      await resolveSaveConflict();
      return;
    }
    showToast(`Save failed: ${err?.message ?? err}`, 'err', 4000);
  }
}

/**
 * A concurrent writer — almost always a LAN peer — changed the vault between our
 * last read and this save.
 *
 * There is no safe automatic answer: we do not know which change matters more,
 * and silently picking one is how data goes missing. So ask, and make the cost
 * of each option explicit.
 */
async function resolveSaveConflict(): Promise<void> {
  const { showConfirm } = await import('./utils');
  const overwrite = await showConfirm(
    'Someone else changed this vault while you were editing — most likely a peer ' +
    'connected to your LAN server.\n\n' +
    'OK: keep your version and overwrite theirs.\n' +
    'Cancel: discard your unsaved change and reload theirs.',
  );

  if (overwrite) {
    const store = st.store as TauriVaultStore;
    if (typeof store.forceSave === 'function') {
      try {
        await store.forceSave(st.vault);
        showToast('Your version saved, overwriting the other change', 'ok', 3500);
        return;
      } catch (e: any) {
        showToast(`Overwrite failed: ${e?.message ?? e}`, 'err', 4000);
        return;
      }
    }
  }

  // Reload: adopt what is now stored, dropping our unsaved edit.
  const fresh = await st.store.load();
  if (fresh) {
    st.vault.api_keys        = fresh.api_keys;
    st.vault.user_categories = fresh.user_categories || [];
    st.vault.projects        = fresh.projects || [{ id: 'Universal', name: 'Universal', description: '' }];
    triggerRender();
    showToast('Reloaded the other version — your unsaved change was discarded', 'err', 5000);
  }
}

// ── Render callback (breaks potential circular deps) ───────────────────────

let _renderFn: () => void = () => {};
export function setRenderFn(fn: () => void): void { _renderFn = fn; }
export function triggerRender(): void { _renderFn(); }

// ── Settings ───────────────────────────────────────────────────────────────

const DEFAULT_SETTINGS: AppSettings = {
  theme: 'dark', accentColor: '#7364c9', cardSize: 'medium', gridColumns: 'auto',
  defaultAccount: '', defaultExportFormat: 'dotenv', autoLockMinutes: 60, lockOnHide: false,
  maskKeysByDefault: true, showExpiryWarning: true, expiryWarningDays: 30,
  customCss: '', sidebarSections: ['all', 'price', 'env', 'category', 'project', 'tags', 'prefixes'],
  groupByType: false, activityBarPosition: 'left' as const, activityBarStyle: 'icon' as const,
  collapsedSections: [] as ('all' | 'price' | 'env' | 'category' | 'project')[],
  activePanel: 'secrets' as 'secrets' | 'tools' | 'users' | 'remote', activeTool: 'secret-gen',
  remoteSaved: [] as RemoteVaultConfig[],
  panelOrder: ['secrets', 'tools', 'remote', 'users'],
  envCopyField: 'api_key' as const,
  sidebarWidth: 0, sidebarCollapsed: false, lastSortBy: 'provider',
  recentSearches: [] as string[], rememberFilters: true, lastView: null as PersistedView | null,
  experimentalProjectTypes: false,
};

export const Settings = {
  _data: { ...DEFAULT_SETTINGS } as AppSettings,
  get<K extends keyof AppSettings>(k: K): AppSettings[K] { return this._data[k]; },
  set<K extends keyof AppSettings>(k: K, v: AppSettings[K]) { this._data[k] = v; this._persist(); },
  setAll(o: Partial<AppSettings>) { Object.assign(this._data, o); this._persist(); },
  getAll(): AppSettings { return { ...this._data }; },
  _persist() { localStorage.setItem('envvault-settings', JSON.stringify(this._data)); },
  async init() {
    try { const r = await fetch('./settings.json'); if (r.ok) Object.assign(this._data, await r.json()); } catch {}
    try { const s = localStorage.getItem('envvault-settings'); if (s) Object.assign(this._data, JSON.parse(s)); } catch {}
    // One-time migration: env/tags/prefixes became configurable sidebar sections.
    // Earlier installs persisted a list without them — merge them in once so they
    // don't silently vanish, while still honouring later user toggles.
    try {
      if (!localStorage.getItem('envvault-sb-migrated')) {
        const secs = [...(this._data.sidebarSections || [])];
        const insertAfter = (anchor: string, key: any) => {
          if (secs.includes(key)) return;
          const at = secs.indexOf(anchor as any);
          if (at >= 0) secs.splice(at + 1, 0, key); else secs.push(key);
        };
        insertAfter('price', 'env');
        if (!secs.includes('tags' as any))     secs.push('tags' as any);
        if (!secs.includes('prefixes' as any)) secs.push('prefixes' as any);
        this._data.sidebarSections = secs as any;
        localStorage.setItem('envvault-sb-migrated', '1');
        this._persist();
      }
    } catch {}
    this._apply();
  },
  _apply() {
    const d = this._data;
    // OS theme auto-sync (item 21)
    const resolvedTheme = d.theme === 'system'
      ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : d.theme;
    document.documentElement.setAttribute('data-theme', resolvedTheme);
    document.documentElement.style.setProperty('--accent', d.accentColor);
    document.documentElement.style.setProperty('--accent-dim', hexAlpha(d.accentColor, 0.14));
    document.documentElement.style.setProperty('--accent-mid', hexAlpha(d.accentColor, 0.3));
    applyGridSettings(); applySidebarOrder(); applyActivityBar(); applySidebarLayout();
    import('./settings-panel').then(m => m.applyPanelOrder()).catch(() => {});
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
  import('./lock').then(m => m.lockVault('visibility')).catch(() => {});
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
  grid.style.gridTemplateColumns = cols === 'auto'
    ? `repeat(auto-fill, minmax(min(100%, ${minW}px), 1fr))`
    : `repeat(${cols}, minmax(0, 1fr))`;
}

/** All toggleable/reorderable sidebar section keys, in default order. */
export const ALL_SIDEBAR_SECTIONS = ['all', 'price', 'env', 'category', 'project', 'tags', 'prefixes'] as const;
/** Sections whose visibility is also gated on having data (handled by render). */
const DATA_GATED_SECTIONS = ['tags', 'prefixes'];

export function isSidebarSectionEnabled(key: string): boolean {
  const sections = Settings.get('sidebarSections') || [...ALL_SIDEBAR_SECTIONS];
  return (sections as string[]).includes(key);
}

export function applySidebarOrder() {
  const sections = Settings.get('sidebarSections') || [...ALL_SIDEBAR_SECTIONS];
  ALL_SIDEBAR_SECTIONS.forEach(key => {
    const el = document.getElementById(`sidebar-section-${key}`) as HTMLElement | null;
    if (!el) return;
    const idx = (sections as string[]).indexOf(key);
    if (idx >= 0) {
      el.style.order = String(idx);
      el.style.borderTop  = idx === 0 ? '' : '1px solid var(--border)';
      el.style.marginTop  = idx === 0 ? '' : '6px';
      el.style.paddingTop = idx === 0 ? '' : '6px';
      // Data-gated sections (tags/prefixes) are shown by render only when non-empty.
      if (!DATA_GATED_SECTIONS.includes(key)) el.style.display = '';
    } else {
      el.style.display = 'none'; el.style.borderTop = ''; el.style.marginTop = ''; el.style.paddingTop = '';
    }
  });
  const collapsed = Settings.get('collapsedSections') || [];
  (['all', 'price', 'env', 'category', 'project', 'tags', 'prefixes'] as const).forEach(key =>
    document.getElementById(`sidebar-section-${key}`)?.classList.toggle('collapsed', collapsed.includes(key)));
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
  sidebar.style.width = w > 0 ? `${Math.max(SIDEBAR_MIN_W, Math.min(SIDEBAR_MAX_W, w))}px` : '';
  sidebar.classList.toggle('collapsed', !!Settings.get('sidebarCollapsed'));
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
    s => s.toLowerCase() !== query.toLowerCase(),
  );
  Settings.set('recentSearches', [query, ...prev].slice(0, RECENT_SEARCH_MAX));
}

// ── View persistence ───────────────────────────────────────────────────────

/** Snapshots the current grid view so the next launch can restore it. */
export function saveViewState(): void {
  if (!Settings.get('rememberFilters')) return;
  Settings.set('lastView', {
    filterType:   st.filter.type,
    filterValue:  st.filter.value,
    envFilter:    st.currentEnvFilter,
    tagFilter:    st.activeTagFilter,
    prefixFilter: st.activePrefixFilter,
    projectIds:   [...st.currentSelectedProjectIds],
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

  const categories = new Set(st.vault.user_categories || []);
  const okFilter =
    v.filterType === 'all' ||
    (v.filterType === 'price' && entries.some(e => e.price_type === v.filterValue)) ||
    (v.filterType === 'category' && (categories.has(v.filterValue) ||
      [...categories].some(c => c.startsWith(v.filterValue + '/'))));
  if (okFilter && typeof v.filterType === 'string') {
    st.filter = { type: v.filterType, value: String(v.filterValue ?? '') };
    applied = applied || v.filterType !== 'all';
  }

  if (v.envFilter && entries.some(e => e.environment === v.envFilter)) {
    st.currentEnvFilter = v.envFilter; applied = true;
  }
  if (v.tagFilter && entries.some(e => (e.tags || []).includes(v.tagFilter!))) {
    st.activeTagFilter = v.tagFilter; applied = true;
  }
  if (v.prefixFilter && entries.some(e => (e.provider || '').startsWith(v.prefixFilter!))) {
    st.activePrefixFilter = v.prefixFilter; applied = true;
  }

  const known = new Set((st.vault.projects || []).map(p => p.id));
  const projects = (Array.isArray(v.projectIds) ? v.projectIds : []).filter(id => known.has(id));
  if (projects.length) {
    st.currentSelectedProjectIds = projects;
    applied = applied || !(projects.length === 1 && projects[0] === 'Universal');
  }

  return applied;
}

export function applyActivityBar() {
  const pos   = Settings.get('activityBarPosition') || 'left';
  const style = Settings.get('activityBarStyle')    || 'icon';
  const layout = document.getElementById('layout')!;
  layout.classList.toggle('activity-bar-right',      pos   === 'right');
  layout.classList.toggle('activity-bar-icon-label', style === 'icon-label');
}

/**
 * Users/RBAC only means something when this vault is actually being served to
 * other people — either we're connected to a remote server, or we're serving
 * our own vault over LAN.
 *
 * On a purely local vault the panel wrote users into the desktop's own
 * `vault.db`, which `envv-server` never reads (it uses its own file). Accounts
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

export function switchPanel(panel: string) {
  const panelEls: Record<string, string[]> = {
    secrets: ['secrets-panel', 'vault-workspace'],
    tools:   ['tools-panel',   'tools-workspace'],
    users:   ['users-panel',   'users-workspace'],
    remote:  ['remote-panel',  'remote-workspace'],
  };
  const allSidebars   = ['secrets-panel', 'tools-panel', 'users-panel', 'remote-panel'];
  const allWorkspaces = ['vault-workspace', 'tools-workspace', 'users-workspace', 'remote-workspace'];
  allSidebars.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; });
  allWorkspaces.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; });

  const active = panelEls[panel] ?? panelEls.secrets;
  active.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = ''; });

  document.querySelectorAll<HTMLButtonElement>('.activity-btn')
    .forEach(btn => btn.classList.toggle('active', btn.dataset.panel === panel));
  Settings.set('activePanel', panel as any);

  if (panel === 'users')  import('./users').then(m => m.renderUsersPanel()).catch(() => {});
  if (panel === 'remote') import('./remote-panel').then(m => m.renderRemotePanel()).catch(() => {});
}

export function switchTool(toolId: string) {
  document.querySelectorAll<HTMLElement>('.tool-pane')
    .forEach(p => p.style.display = p.id === `tool-${toolId}` ? '' : 'none');
  document.querySelectorAll<HTMLButtonElement>('.tool-nav-btn')
    .forEach(btn => btn.classList.toggle('active', btn.dataset.tool === toolId));
  Settings.set('activeTool', toolId);
}

// ── Exporter + dotenvKey ───────────────────────────────────────────────────

export function dotenvKey(entry: VaultEntry): string {
  const p = (entry.provider || 'UNKNOWN').toUpperCase().replace(/[^A-Z0-9]/g, '_');
  const k = entry.key_id ? '_' + entry.key_id.toUpperCase().replace(/[^A-Z0-9]/g, '_') : '';
  return `${p}${k}`;
}

export const Exporter = {
  dotenv(keys: VaultEntry[]): string {
    return keys.map(k => {
      const b = dotenvKey(k);
      let out = `# ${k.provider}${k.account_name ? ' — ' + k.account_name : ''}\n${b}=${k.api_key}`;
      if (k.api_secret) out += `\n${b}_SECRET=${k.api_secret}`;
      if (k.api_url)    out += `\n${b}_URL=${k.api_url}`;
      return out;
    }).join('\n\n');
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
    keys.forEach(k => {
      const b = dotenvKey(k);
      doc[b] = k.api_key;
      if (k.api_secret) doc[`${b}_SECRET`] = k.api_secret;
      if (k.api_url)    doc[`${b}_URL`]    = k.api_url;
    });
    const header = `# EnvVault Export\n# Generated: ${new Date().toISOString()}\n\n`;
    return header + yamlDump(doc, { indent: 2, lineWidth: -1, noRefs: true });
  },
  json(keys: VaultEntry[]): string { return JSON.stringify({ api_keys: keys }, null, 2); },
};
