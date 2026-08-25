/**
 * @file
 * Remote Vaults panel — manage and connect to multiple remote envv-server instances.
 */

import type { RemoteVaultConfig } from './types';
import {
  st,
  Settings,
  RemoteVaultStore,
  TauriVaultStore,
  LocalVaultStore,
  inTauri,
  applyUsersPanelVisibility,
  resetViewState,
  triggerRender,
} from './state';
import { esc, escAttr, showToast, showConfirm, showPasswordPrompt } from './utils';
import { relativeTime } from './ui-qol';
import { refreshLanPanel } from './lan';

let _finishInitFn: () => Promise<void> = async () => {};
export function setRemoteFinishInitFn(fn: () => Promise<void>) {
  _finishInitFn = fn;
}

// Keep-alive ping — sends GET /api/ping every 90s while connected.
let _pingInterval: ReturnType<typeof setInterval> | null = null;

function startPing() {
  stopPing();
  _pingInterval = setInterval(async () => {
    // Delegate to the store: it owns the session token and routes through the
    // TLS-pinning proxy. This used to hand-build a request reading a `_token`
    // field that does not exist (the field is `token`), so every ping went out
    // as `Bearer ` and was rejected — the keep-alive never kept anything alive.
    if (!(st.store instanceof RemoteVaultStore)) {
      stopPing();
      return;
    }
    await (st.store as RemoteVaultStore).ping();
  }, 90_000);
}

function stopPing() {
  if (_pingInterval !== null) {
    clearInterval(_pingInterval);
    _pingInterval = null;
  }
}

function genId(): string {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

function getSaved(): RemoteVaultConfig[] {
  return Settings.get('remoteSaved') ?? [];
}

function saveSaved(list: RemoteVaultConfig[]) {
  Settings.set('remoteSaved', list);
}

/** Groups a fingerprint into readable pairs so a human can actually compare it. */
function formatFingerprint(fp: string): string {
  return (fp.match(/.{1,2}/g) ?? [fp]).join(':').toUpperCase();
}

/**
 * Trust-on-first-use for an https:// server we have no pin for yet.
 *
 * `remote_request` pins when handed a fingerprint and applies normal CA
 * validation when not, so a self-signed server was unreachable: connecting
 * needed a fingerprint, and obtaining one needed a connection. This breaks the
 * deadlock the same way SSH does — probe the certificate with an
 * unauthenticated request that carries no credentials, show the user what was
 * presented, and pin only what they accept.
 *
 * Returns the accepted fingerprint, or `null` if the user declined or the
 * server is not reachable.
 */
export async function acquireFingerprint(url: string): Promise<string | null> {
  const invoke = (window as any).__TAURI__?.core?.invoke;
  if (!invoke || !url.startsWith('https://')) return null;
  let fp: string;
  try {
    fp = await invoke('probe_cert_fingerprint', { url });
  } catch (e: any) {
    showToast(`Could not reach ${url}: ${e?.message ?? e}`, 'err', 4000);
    return null;
  }
  const ok = await showConfirm(
    `${url} presented a certificate this app has not seen before.\n\n` +
      `SHA-256 fingerprint:\n${formatFingerprint(fp)}\n\n` +
      `Check this against the server before accepting. OK pins this certificate; ` +
      `future connections are refused if it changes.`,
  );
  return ok ? fp : null;
}

/** Saved config for a server, matched on the pair that identifies a login. */
export function findSavedRemote(url: string, username = ''): RemoteVaultConfig | undefined {
  const clean = url.replace(/\/$/, '');
  return getSaved().find((c) => c.url === clean && c.username === username);
}

/**
 * Records a server the user just connected to in the saved-remotes list.
 *
 * The unlock screen has its own server/username fields, so a vault reached that
 * way never went through the "Add Remote" form. It therefore never appeared in
 * the Remote panel or the vault switcher, and the next session had to retype the
 * URL. Connecting is the intent to use a server — that is enough to remember it.
 */
export function upsertSavedRemote(input: {
  url: string;
  username: string;
  certFingerprint?: string;
}): RemoteVaultConfig {
  const url = input.url.replace(/\/$/, '');
  const saved = getSaved();
  const idx = saved.findIndex((c) => c.url === url && c.username === input.username);

  if (idx >= 0) {
    const prev = saved[idx];
    if (
      input.certFingerprint &&
      prev.certFingerprint &&
      prev.certFingerprint !== input.certFingerprint
    ) {
      showToast('⚠ TLS cert fingerprint changed — server certificate may have rotated', 'err');
    }
    saved[idx] = {
      ...prev,
      ...(input.certFingerprint ? { certFingerprint: input.certFingerprint } : {}),
    };
    saveSaved(saved);
    return saved[idx];
  }

  const cfg: RemoteVaultConfig = {
    id: genId(),
    name: url.replace(/^https?:\/\//, '') + (input.username ? ` (${input.username})` : ''),
    url,
    username: input.username,
    ...(input.certFingerprint ? { certFingerprint: input.certFingerprint } : {}),
  };
  saveSaved([...saved, cfg]);
  return cfg;
}

/**
 * Stamps a saved remote as connected *now*.
 *
 * Call this only after authentication has actually succeeded. The unlock
 * screen's server picker sorts on this field, so stamping it on save — or on a
 * failed attempt — would promote a server the user could not get into.
 */
export function markRemoteConnected(id: string): void {
  const saved = getSaved();
  const idx = saved.findIndex((c) => c.id === id);
  if (idx < 0) return;
  saved[idx] = { ...saved[idx], lastConnectedAt: new Date().toISOString() };
  saveSaved(saved);
}

// ── Render ────────────────────────────────────────────────────────────────────

export function renderRemotePanel() {
  const sidebar = document.getElementById('remote-panel-list');
  const workspace = document.getElementById('remote-detail-host');
  if (!sidebar) return;

  const saved = getSaved();
  const activeId = st.activeRemoteId;

  sidebar.innerHTML = saved.length
    ? saved
        .map(
          (cfg) => `
    <button class="remote-list-item${activeId === cfg.id ? ' active' : ''}" data-remote-id="${escAttr(cfg.id)}">
      <span class="remote-item-icon">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
        </svg>
      </span>
      <span class="remote-item-info">
        <span class="remote-item-name">${esc(cfg.name)}</span>
        <span class="remote-item-url">${esc(cfg.url)}</span>
        <span class="remote-item-seen">${esc(relativeTime(cfg.lastConnectedAt))}</span>
      </span>
      ${activeId === cfg.id ? '<span class="remote-connected-dot" title="Connected"></span>' : ''}
    </button>
  `,
        )
        .join('')
    : '<div class="users-empty">No saved remotes.<br>Add one below.</div>';

  if (workspace) {
    if (activeId) {
      const cfg = saved.find((c) => c.id === activeId);
      if (cfg) renderRemoteDetail(cfg, workspace);
    } else {
      workspace.innerHTML =
        '<div class="users-detail-empty">Select a remote vault or add a new one.</div>';
    }
  }
}

function renderRemoteDetail(cfg: RemoteVaultConfig, ws: HTMLElement) {
  const isConnected =
    st.store instanceof RemoteVaultStore && (st.store as RemoteVaultStore).baseUrl === cfg.url;

  ws.innerHTML = `
    <div class="users-detail">
      <div class="users-detail-header">
        <div class="users-detail-avatar" style="background:${isConnected ? 'var(--accent-dim)' : 'var(--surface3)'};color:${isConnected ? 'var(--accent)' : 'var(--text3)'}">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
          </svg>
        </div>
        <div class="users-detail-meta">
          <div class="users-detail-name">
            ${esc(cfg.name)}
            ${isConnected ? '<span class="user-badge" style="background:rgba(79,201,126,.15);color:#4fc97e">Connected</span>' : '<span class="user-badge token-badge">Disconnected</span>'}
          </div>
          <div class="users-detail-sub">${esc(cfg.url)} · ${cfg.username ? esc(cfg.username) : 'owner (master password)'}</div>
        </div>
        <div class="users-detail-actions">
          ${
            isConnected
              ? `<button class="btn btn-xs danger" id="remote-disconnect-btn">Disconnect</button>`
              : `<button class="btn btn-xs btn-accent" id="remote-connect-btn">Connect</button>`
          }
          <button class="btn btn-xs btn-ghost" id="remote-delete-btn">Remove</button>
        </div>
      </div>

      <section class="users-section">
        <div class="users-section-head"><span>Connection Details</span></div>
        <div class="remote-detail-fields">
          <div class="remote-field-row">
            <span class="remote-field-label">Name</span>
            <input class="tool-input remote-edit-field" id="re-name" value="${escAttr(cfg.name)}">
          </div>
          <div class="remote-field-row">
            <span class="remote-field-label">URL</span>
            <input class="tool-input remote-edit-field" id="re-url" value="${escAttr(cfg.url)}" placeholder="http://localhost:8743">
          </div>
          <div class="remote-field-row">
            <span class="remote-field-label">Username</span>
            <input class="tool-input remote-edit-field" id="re-username" value="${escAttr(cfg.username)}" placeholder="leave blank = owner master-password">
          </div>
          <div style="display:flex;gap:6px;margin-top:8px">
            <button class="btn btn-xs accent" id="re-save-btn">Save Changes</button>
            <button class="btn btn-xs btn-ghost" id="re-test-btn">Test Connection</button>
            <span id="re-test-status" style="font-size:11px;color:var(--text3);align-self:center"></span>
          </div>
        </div>
      </section>

      ${
        isConnected
          ? `
      <section class="users-section">
        <div class="users-section-head"><span>Vault Status</span></div>
        <div id="remote-status-area" class="remote-status-area">
          <button class="btn btn-xs btn-ghost" id="remote-refresh-status-btn">Refresh Status</button>
        </div>
      </section>`
          : ''
      }
    </div>
  `;

  // Bindings
  document
    .getElementById('remote-connect-btn')
    ?.addEventListener('click', () => connectRemote(cfg));
  document
    .getElementById('remote-disconnect-btn')
    ?.addEventListener('click', () => disconnectRemote());
  document
    .getElementById('remote-delete-btn')
    ?.addEventListener('click', () => deleteRemote(cfg.id));
  document.getElementById('re-save-btn')?.addEventListener('click', () => saveRemoteEdits(cfg.id));
  document.getElementById('re-test-btn')?.addEventListener('click', () => testRemote(cfg));
  document
    .getElementById('remote-refresh-status-btn')
    ?.addEventListener('click', () => refreshRemoteStatus(cfg));

  if (isConnected) refreshRemoteStatus(cfg);
}

// ── Connect / Disconnect ──────────────────────────────────────────────────────

async function connectRemote(cfg: RemoteVaultConfig) {
  // Styled masked prompt — the native window.prompt() renders as an unstyled
  // system dialog under WebKitGTK and echoes the password in clear text.
  // Establish trust in the certificate *before* asking for a password, so the
  // credential is never typed for a connection the user then declines.
  if (cfg.url.startsWith('https://') && !cfg.certFingerprint) {
    const fp = await acquireFingerprint(cfg.url);
    if (!fp) return;
    const saved = getSaved();
    const idx = saved.findIndex((c) => c.id === cfg.id);
    if (idx >= 0) {
      saved[idx] = { ...saved[idx], certFingerprint: fp };
      saveSaved(saved);
      cfg = saved[idx];
    } else cfg = { ...cfg, certFingerprint: fp };
  }

  const pw = await showPasswordPrompt(
    `${cfg.username ? `Password for "${cfg.username}"` : 'Master password'} on ${cfg.name}:`,
  );
  if (pw === null) return;

  const remote = new RemoteVaultStore(cfg.url, cfg.certFingerprint);
  try {
    let ok: boolean;
    if (cfg.username) {
      ok = await remote.authUser(cfg.username, pw);
    } else {
      ok = await remote.unlock(pw);
    }
    if (!ok) {
      showToast('Authentication failed', 'err');
      return;
    }

    // Record the fingerprint on first contact. A *changed* fingerprint is not
    // silently re-pinned: the old code overwrote the stored value on every
    // connect, so a pin only ever held until the next mismatch — which is the
    // one moment it needs to hold. (The pinned handshake normally rejects a
    // different certificate before this point; this covers the case where the
    // server reports one certificate and serves another.)
    const serverStatus = await remote.getStatus();
    if (serverStatus.cert_fingerprint) {
      const saved = getSaved();
      const idx = saved.findIndex((c) => c.id === cfg.id);
      if (idx >= 0) {
        const stored = saved[idx].certFingerprint;
        if (stored && stored !== serverStatus.cert_fingerprint) {
          showToast(
            '⚠ TLS certificate does not match the pinned one — not trusting it',
            'err',
            6000,
          );
        } else if (!stored) {
          saved[idx] = { ...saved[idx], certFingerprint: serverStatus.cert_fingerprint };
          saveSaved(saved);
          remote.fingerprint = serverStatus.cert_fingerprint;
          cfg = saved[idx];
        }
      }
    }

    markRemoteConnected(cfg.id);
    st.store = remote;
    st.activeRemoteId = cfg.id;
    Settings.set('remote', { enabled: true, serverUrl: cfg.url });
    // Same invariant as switchToLocalVault: every view-scoped selection points
    // at the vault being left. Only switchToLocalVault used to do this, so the
    // local→remote direction carried a project selection, expanded/revealed
    // entry ids and bulk ticks into the remote's data. A selected local project
    // id that the remote does not have matches nothing, so the remote loaded
    // into an empty-looking grid.
    // `st.vault` is deliberately *not* cleared here — finishInit compares the
    // in-memory entries against the remote's to offer the "push local entries"
    // prompt, and clearing them would silently disable it.
    resetViewState();

    // Zeroize the local vault key. Connecting to a remote left it resident in
    // Rust's `VaultState` for the whole session with nothing on screen saying
    // so — a locked-looking app whose key was still in memory. The LAN gate
    // closed the one path that *exploited* it; this closes the hole.
    //
    // It is a real behaviour change: switching back now costs a master
    // password. `keepLocalUnlocked` exists so the old behaviour is available,
    // but it is opt-in and off by default — someone who wants the convenience
    // should choose it knowingly, which is not the same as everybody getting it
    // silently.
    if (!Settings.get('keepLocalUnlocked')) {
      try {
        const tauri = (window as { __TAURI__?: { core?: { invoke?: (c: string) => Promise<unknown> } } })
          .__TAURI__;
        await tauri?.core?.invoke?.('lock_vault');
      } catch {
        // A vault that was never unlocked locally (connected straight from the
        // startup screen) has nothing to lock, and that is not an error worth
        // showing anyone.
      }
    }

    // User ids, class ids and audit rows all belong to the vault we just left.
    const { resetUsersPanelState } = await import('./users');
    resetUsersPanelState();
    const { resetAuditPanel } = await import('./audit');
    resetAuditPanel();

    const nameEl = document.getElementById('vault-name');
    if (nameEl) nameEl.textContent = cfg.name;

    showToast(`Connected to ${cfg.name}`, 'ok');
    applyUsersPanelVisibility();
    // The LAN card lives in this very panel and serves the *local* vault, so it
    // must stop offering to publish the moment a remote takes over.
    refreshLanPanel();
    startPing();
    renderRemotePanel();
    await _finishInitFn();
  } catch (e: any) {
    showToast('Connection failed: ' + (e?.message ?? e), 'err');
  }
}

/**
 * Tears down the remote session and returns to the local vault.
 *
 * Single path for both "Disconnect" and the vault switcher's "Local Vault", so
 * the two cannot drift apart. Two things it must get right:
 *
 * 1. **Clear the whole in-memory vault, projects included.** The switcher used
 *    to null out `api_keys` and `user_categories` but leave `projects`, so the
 *    remote's project tree stayed in the sidebar after its entries vanished.
 * 2. **Do not silently load nothing.** The local vault is usually still locked
 *    here — a user who connected to a remote from the unlock screen never
 *    entered their master password. `load()` then fails, and the old code left
 *    an empty grid with no prompt and no error.
 */
export async function switchToLocalVault(): Promise<void> {
  stopPing();
  if (st.store instanceof RemoteVaultStore) {
    (st.store as RemoteVaultStore).lock().catch(() => {});
  }
  st.store = inTauri ? new TauriVaultStore() : new LocalVaultStore();
  st.activeRemoteId = null;
  Settings.set('remote', { enabled: false, serverUrl: '' });

  st.vault.api_keys = [];
  st.vault.user_categories = [];
  st.vault.projects = [{ id: 'Universal', name: 'Universal', description: '' }];
  resetViewState();
  const { resetUsersPanelState } = await import('./users');
  resetUsersPanelState();
  const { resetAuditPanel } = await import('./audit');
  resetAuditPanel();
  st.vaultOpen = false;

  // Paint the cleared vault *now*, not only via finishInit. Clearing `st.vault`
  // does nothing to the DOM, and the path below where the local vault is still
  // locked returns before finishInit ever runs — which left the remote's
  // sidebar, its project tree and a whole config view of chunk cards (secret
  // values included) alive in the document for a vault we are no longer
  // authenticated to. It also reappeared intact if the unlock was abandoned.
  triggerRender();

  const nameEl = document.getElementById('vault-name');
  if (nameEl) nameEl.textContent = 'Local Vault';

  showToast('Switched to local vault', 'ok');
  applyUsersPanelVisibility();
  refreshLanPanel();
  renderRemotePanel();

  if (st.store instanceof TauriVaultStore) {
    const unlocked = await (st.store as TauriVaultStore).isUnlocked().catch(() => false);
    if (!unlocked) {
      // Dynamic import: lock.ts imports this module statically, and a static
      // import back would be a cycle.
      const { showRelockScreen } = await import('./lock');
      showRelockScreen('switch');
      return;
    }
  }

  await _finishInitFn();
}

function disconnectRemote() {
  void switchToLocalVault();
}

async function deleteRemote(id: string) {
  const saved = getSaved();
  const cfg = saved.find((c) => c.id === id);
  if (!(await showConfirm(`Remove "${cfg?.name ?? id}" from saved remotes?`))) return;
  if (st.activeRemoteId === id) disconnectRemote();
  saveSaved(saved.filter((c) => c.id !== id));
  st.activeRemoteId = null;
  renderRemotePanel();
}

async function saveRemoteEdits(id: string) {
  const name = (document.getElementById('re-name') as HTMLInputElement).value.trim();
  const url = (document.getElementById('re-url') as HTMLInputElement).value
    .trim()
    .replace(/\/$/, '');
  const username = (document.getElementById('re-username') as HTMLInputElement).value.trim();
  if (!name || !url) {
    showToast('Name and URL are required', 'err');
    return;
  }
  const saved = getSaved().map((c) => (c.id === id ? { ...c, name, url, username } : c));
  saveSaved(saved);
  showToast('Saved', 'ok');
  renderRemotePanel();
}

async function testRemote(cfg?: RemoteVaultConfig) {
  const url = (document.getElementById('re-url') as HTMLInputElement)?.value
    .trim()
    .replace(/\/$/, '');
  const statusEl = document.getElementById('re-test-status');
  if (!url) {
    showToast('Enter a URL first', 'err');
    return;
  }
  if (statusEl) statusEl.textContent = 'Testing…';
  try {
    // Must go through RemoteVaultStore, not bare fetch(): for an https:// server
    // with a self-signed cert WebKit rejects the connection outright, so a raw
    // fetch reported "Unreachable" for servers that were perfectly reachable.
    // The store routes via the Tauri proxy and honours the pinned fingerprint.
    let fingerprint = cfg?.certFingerprint;
    // Same bootstrap as connect: an untrusted https server is unreachable until
    // its certificate is pinned, so offer to pin it here too rather than
    // reporting a reachable server as down.
    if (!fingerprint && url.startsWith('https://')) {
      const fp = await acquireFingerprint(url);
      if (!fp) {
        if (statusEl) statusEl.textContent = '✗ Certificate not trusted';
        return;
      }
      fingerprint = fp;
      if (cfg) {
        const saved = getSaved();
        const idx = saved.findIndex((c) => c.id === cfg.id);
        if (idx >= 0) {
          saved[idx] = { ...saved[idx], certFingerprint: fp };
          saveSaved(saved);
        }
      }
    }
    const body = await new RemoteVaultStore(url, fingerprint).getStatus();
    if (statusEl) {
      const base = body.vault_exists
        ? `✓ Server OK · vault ${body.unlocked ? 'unlocked' : 'locked'}`
        : '✓ Server OK · no vault yet';
      statusEl.textContent = base + (body.cert_fingerprint ? ' · TLS ✓' : '');
    }
  } catch {
    if (statusEl) statusEl.textContent = '✗ Unreachable';
  }
}

async function refreshRemoteStatus(cfg: RemoteVaultConfig) {
  const area = document.getElementById('remote-status-area');
  if (!area) return;
  try {
    // Same reasoning as testRemote(): proxy-aware, fingerprint-aware.
    const body = await new RemoteVaultStore(cfg.url, cfg.certFingerprint).getStatus();
    area.innerHTML = `
      <div class="remote-status-grid">
        <div class="remote-status-item">
          <span class="remote-status-label">Server</span>
          <span class="remote-status-val ok">Online</span>
        </div>
        <div class="remote-status-item">
          <span class="remote-status-label">Vault</span>
          <span class="remote-status-val ${body.vault_exists ? 'ok' : 'warn'}">${body.vault_exists ? 'Exists' : 'Not created'}</span>
        </div>
        <div class="remote-status-item">
          <span class="remote-status-label">State</span>
          <span class="remote-status-val ${body.unlocked ? 'ok' : 'warn'}">${body.unlocked ? 'Unlocked' : 'Locked'}</span>
        </div>
      </div>
      <button class="btn btn-xs btn-ghost" id="remote-refresh-status-btn" style="margin-top:8px">Refresh</button>
    `;
    document
      .getElementById('remote-refresh-status-btn')
      ?.addEventListener('click', () => refreshRemoteStatus(cfg));
  } catch {
    area.innerHTML = `<div class="remote-status-err">Could not reach server.</div>
      <button class="btn btn-xs btn-ghost" id="remote-refresh-status-btn" style="margin-top:6px">Retry</button>`;
    document
      .getElementById('remote-refresh-status-btn')
      ?.addEventListener('click', () => refreshRemoteStatus(cfg));
  }
}

// ── Add remote form ───────────────────────────────────────────────────────────

function openAddRemoteForm() {
  const ws = document.getElementById('remote-detail-host');
  if (!ws) return;

  ws.innerHTML = `
    <div class="users-detail">
      <div class="users-detail-header" style="border-bottom:1px solid var(--border);padding-bottom:16px">
        <div class="users-detail-avatar" style="background:var(--surface3)">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
          </svg>
        </div>
        <div class="users-detail-meta">
          <div class="users-detail-name">Add Remote Vault</div>
          <div class="users-detail-sub">Connect to a running envv-server instance.</div>
        </div>
      </div>
      <section class="users-section">
        <div class="users-section-head"><span>Server Details</span></div>
        <div class="create-user-form">
          <label class="user-form-label">Display Name
            <input id="add-remote-name" class="tool-input user-form-field" placeholder="Production Vault" autocomplete="off">
          </label>
          <label class="user-form-label">Server URL
            <input id="add-remote-url" class="tool-input user-form-field" placeholder="http://localhost:8743" type="url" autocomplete="off">
          </label>
          <label class="user-form-label">
            Username
            <span class="form-label-hint">leave blank to authenticate as vault owner (master password)</span>
            <input id="add-remote-username" class="tool-input user-form-field" placeholder="alice" autocomplete="off" spellcheck="false">
          </label>
          <div class="create-user-actions">
            <button class="btn btn-sm btn-accent" id="add-remote-confirm">Save Remote</button>
            <button class="btn btn-sm btn-ghost" id="add-remote-test">Test Connection</button>
            <button class="btn btn-sm btn-ghost" id="add-remote-cancel">Cancel</button>
            <span id="add-test-status" style="font-size:11px;color:var(--text3);align-self:center"></span>
          </div>
        </div>
      </section>
    </div>`;

  (document.getElementById('add-remote-name') as HTMLInputElement)?.focus();

  document.getElementById('add-remote-confirm')!.addEventListener('click', () => {
    const name = (document.getElementById('add-remote-name') as HTMLInputElement).value.trim();
    const url = (document.getElementById('add-remote-url') as HTMLInputElement).value
      .trim()
      .replace(/\/$/, '');
    const username = (
      document.getElementById('add-remote-username') as HTMLInputElement
    ).value.trim();
    if (!name) {
      showToast('Name is required', 'err');
      return;
    }
    if (!url) {
      showToast('URL is required', 'err');
      return;
    }
    const cfg: RemoteVaultConfig = { id: genId(), name, url, username };
    saveSaved([...getSaved(), cfg]);
    st.activeRemoteId = cfg.id;
    showToast(`"${name}" saved`, 'ok');
    renderRemotePanel();
  });

  document.getElementById('add-remote-test')!.addEventListener('click', async () => {
    const url = (document.getElementById('add-remote-url') as HTMLInputElement).value
      .trim()
      .replace(/\/$/, '');
    const statusEl = document.getElementById('add-test-status');
    if (!url) {
      showToast('Enter a URL first', 'err');
      return;
    }
    if (statusEl) statusEl.textContent = 'Testing…';
    try {
      const probe = new RemoteVaultStore(url);
      const body = await probe.getStatus();
      let msg = body.vault_exists ? '✓ Reachable' : '✓ Reachable (no vault yet)';
      if (body.cert_fingerprint) msg += ` · TLS ✓`;
      if (statusEl) statusEl.textContent = msg;
    } catch {
      if (statusEl) statusEl.textContent = '✗ Unreachable';
    }
  });

  document.getElementById('add-remote-cancel')!.addEventListener('click', () => {
    ws.innerHTML = '<div class="users-detail-empty">Select a remote vault or add a new one.</div>';
  });
}

// ── Init ──────────────────────────────────────────────────────────────────────

let _remotePanelListenersAdded = false;

export function initRemotePanel() {
  if (!_remotePanelListenersAdded) {
    _remotePanelListenersAdded = true;

    document.getElementById('remote-panel-list')?.addEventListener('click', (e) => {
      const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('[data-remote-id]');
      if (!btn?.dataset.remoteId) return;
      st.activeRemoteId = btn.dataset.remoteId;
      renderRemotePanel();
    });

    document.getElementById('add-remote-btn')?.addEventListener('click', openAddRemoteForm);
  }

  renderRemotePanel();
}
