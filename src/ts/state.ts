import type { VaultData, AppSettings, VaultEntry, RemoteVaultConfig } from './types';
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
    const raw = sessionStorage.getItem('api-vault');
    return raw ? JSON.parse(raw) : null;
  }
  async save(data: VaultData): Promise<void> {
    try { sessionStorage.setItem('api-vault', JSON.stringify(data)); }
    catch { showToast('Session storage full — export to save changes', 'err'); }
  }
  get isRemote() { return false; }
  get vaultId()  { return 'local'; }
}

export class TauriVaultStore implements VaultStore {
  private invoke = (window as any).__TAURI__?.core?.invoke?.bind((window as any).__TAURI__.core);
  async unlock(password: string): Promise<boolean>  { return this.invoke('unlock_vault', { password }); }
  async lock(): Promise<void>                       { return this.invoke('lock_vault'); }
  async isUnlocked(): Promise<boolean>              { return this.invoke('vault_is_unlocked'); }
  async exists(): Promise<boolean>                  { return this.invoke('vault_exists'); }
  async reset(): Promise<void>                      { return this.invoke('reset_vault'); }
  async load(): Promise<VaultData | null>           { const d = await this.invoke('load_vault'); return d ?? null; }
  async save(data: VaultData): Promise<void>        { await this.invoke('save_vault', { data }); }
  async vaultFilePath(): Promise<string>            { return this.invoke('get_vault_path').catch(() => ''); }
  get isRemote() { return false; }
  get vaultId()  { return 'local-native'; }
}

export const inTauri = !!(window as any).__TAURI__;
const _invoke = (window as any).__TAURI__?.core?.invoke?.bind((window as any).__TAURI__?.core);

export class RemoteVaultStore implements VaultStore {
  private token = '';
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
  ): Promise<{ ok: boolean; status: number; json: () => Promise<any> }> {
    const url = `${this.baseUrl}${path}`;
    const useNative = inTauri && url.startsWith('https://');

    if (useNative && _invoke) {
      const result = await _invoke('remote_request', {
        url,
        method: opts.method ?? 'GET',
        headersJson: JSON.stringify(opts.headers ?? {}),
        body: opts.body ?? null,
        fingerprint: this.fingerprint ?? null,
      }) as { status: number; body: string };
      const ok = result.status >= 200 && result.status < 300;
      return { ok, status: result.status, json: async () => JSON.parse(result.body) };
    }

    const headers: Record<string, string> = {};
    if (opts.headers) Object.assign(headers, opts.headers);
    const r = await fetch(url, { method: opts.method, headers, body: opts.body });
    return { ok: r.ok, status: r.status, json: () => r.json() };
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
      return r.ok ? await r.json() : null;
    } catch { return null; }
  }

  async save(data: VaultData): Promise<void> {
    if (!this.token) return;
    try {
      await this._apiFetch('/api/vault', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.token}` },
        body: JSON.stringify(data),
      });
    } catch { /* ignore */ }
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
  expanded: new Set<number>(),
  allExpanded: false,
  lockTimer: null as ReturnType<typeof setTimeout> | null,
  undoStack: [] as Array<{ fn: () => void; t: ReturnType<typeof setTimeout> }>,
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
};

// ── Render callback (breaks potential circular deps) ───────────────────────

let _renderFn: () => void = () => {};
export function setRenderFn(fn: () => void): void { _renderFn = fn; }
export function triggerRender(): void { _renderFn(); }

// ── Settings ───────────────────────────────────────────────────────────────

const DEFAULT_SETTINGS: AppSettings = {
  theme: 'dark', accentColor: '#7364c9', cardSize: 'medium', gridColumns: 'auto',
  defaultAccount: '', defaultExportFormat: 'dotenv', autoLockMinutes: 60,
  maskKeysByDefault: true, showExpiryWarning: true, expiryWarningDays: 30,
  customCss: '', sidebarSections: ['all', 'price', 'category', 'project'],
  groupByType: false, activityBarPosition: 'left' as const, activityBarStyle: 'icon' as const,
  collapsedSections: [] as ('all' | 'price' | 'env' | 'category' | 'project')[],
  activePanel: 'secrets' as 'secrets' | 'tools' | 'users' | 'remote', activeTool: 'secret-gen',
  remoteSaved: [] as RemoteVaultConfig[],
  panelOrder: ['secrets', 'tools', 'remote', 'users'],
  envCopyField: 'api_key' as const,
};

export const Settings = {
  _data: { ...DEFAULT_SETTINGS } as AppSettings,
  get<K extends keyof AppSettings>(k: K): AppSettings[K] { return this._data[k]; },
  set<K extends keyof AppSettings>(k: K, v: AppSettings[K]) { this._data[k] = v; this._persist(); },
  setAll(o: Partial<AppSettings>) { Object.assign(this._data, o); this._persist(); },
  getAll(): AppSettings { return { ...this._data }; },
  _persist() { localStorage.setItem('apivault-settings', JSON.stringify(this._data)); },
  async init() {
    try { const r = await fetch('./settings.json'); if (r.ok) Object.assign(this._data, await r.json()); } catch {}
    try { const s = localStorage.getItem('apivault-settings'); if (s) Object.assign(this._data, JSON.parse(s)); } catch {}
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
    applyGridSettings(); applySidebarOrder(); applyActivityBar();
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
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && !st.store.isRemote) {
    // Remote vaults: don't auto-lock — it destroys the session token and
    // makes the vault appear wiped until the user re-authenticates.
    import('./lock').then(m => m.lockVault()).catch(() => {});
  }
});

// ── Layout helpers ─────────────────────────────────────────────────────────

export function applyGridSettings() {
  const grid = document.getElementById('card-grid');
  if (!grid) return;
  const size = Settings.get('cardSize');
  const minW = { compact: 280, medium: 360, large: 460 }[size];
  const cols = Settings.get('gridColumns');
  grid.style.gridTemplateColumns = cols === 'auto'
    ? `repeat(auto-fill, minmax(${minW}px, 1fr))`
    : `repeat(${cols}, minmax(${minW}px, 1fr))`;
}

export function applySidebarOrder() {
  const sections = Settings.get('sidebarSections') || ['all', 'price', 'category', 'project'];
  ['all', 'price', 'category', 'project'].forEach(key => {
    const el = document.getElementById(`sidebar-section-${key}`) as HTMLElement | null;
    if (!el) return;
    const idx = sections.indexOf(key as any);
    if (idx >= 0) {
      el.style.order = String(idx); el.style.display = '';
      el.style.borderTop  = idx === 0 ? '' : '1px solid var(--border)';
      el.style.marginTop  = idx === 0 ? '' : '6px';
      el.style.paddingTop = idx === 0 ? '' : '6px';
    } else {
      el.style.display = 'none'; el.style.borderTop = ''; el.style.marginTop = ''; el.style.paddingTop = '';
    }
  });
  const collapsed = Settings.get('collapsedSections') || [];
  (['all', 'price', 'env', 'category', 'project'] as const).forEach(key =>
    document.getElementById(`sidebar-section-${key}`)?.classList.toggle('collapsed', collapsed.includes(key)));
}

export function applyActivityBar() {
  const pos   = Settings.get('activityBarPosition') || 'left';
  const style = Settings.get('activityBarStyle')    || 'icon';
  const layout = document.getElementById('layout')!;
  layout.classList.toggle('activity-bar-right',      pos   === 'right');
  layout.classList.toggle('activity-bar-icon-label', style === 'icon-label');
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
  yaml(keys: VaultEntry[]): string {
    const lines = ['# API Vault Export', `# Generated: ${new Date().toISOString()}`, ''];
    keys.forEach(k => {
      const b = dotenvKey(k);
      lines.push(`# ${k.provider}`, `${b}: "${k.api_key}"`);
      if (k.api_secret) lines.push(`${b}_SECRET: "${k.api_secret}"`);
      if (k.api_url)    lines.push(`${b}_URL: "${k.api_url}"`);
      lines.push('');
    });
    return lines.join('\n');
  },
  json(keys: VaultEntry[]): string { return JSON.stringify({ api_keys: keys }, null, 2); },
};
