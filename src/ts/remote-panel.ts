/**
 * @file Remote Vaults panel — manage and connect to multiple remote apiv-server instances.
 */

import type { RemoteVaultConfig } from './types';
import { st, Settings, RemoteVaultStore, TauriVaultStore, LocalVaultStore, inTauri } from './state';
import { esc, escAttr, showToast, showConfirm } from './utils';

let _finishInitFn: () => Promise<void> = async () => {};
export function setRemoteFinishInitFn(fn: () => Promise<void>) { _finishInitFn = fn; }

// Keep-alive ping — sends GET /api/ping every 90s when connected
let _pingInterval: ReturnType<typeof setInterval> | null = null;

function startPing(url: string) {
  stopPing();
  _pingInterval = setInterval(async () => {
    try {
      if (!(st.store instanceof RemoteVaultStore)) { stopPing(); return; }
      await fetch(`${url}/api/ping`, {
        headers: { Authorization: `Bearer ${(st.store as any)._token ?? ''}` },
      });
    } catch {}
  }, 90_000);
}

function stopPing() {
  if (_pingInterval !== null) { clearInterval(_pingInterval); _pingInterval = null; }
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

// ── Render ────────────────────────────────────────────────────────────────────

export function renderRemotePanel() {
  const sidebar = document.getElementById('remote-panel-list');
  const workspace = document.getElementById('remote-workspace');
  if (!sidebar) return;

  const saved = getSaved();
  const activeId = st.activeRemoteId;

  sidebar.innerHTML = saved.length ? saved.map(cfg => `
    <button class="remote-list-item${activeId === cfg.id ? ' active' : ''}" data-remote-id="${escAttr(cfg.id)}">
      <span class="remote-item-icon">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
        </svg>
      </span>
      <span class="remote-item-info">
        <span class="remote-item-name">${esc(cfg.name)}</span>
        <span class="remote-item-url">${esc(cfg.url)}</span>
      </span>
      ${activeId === cfg.id ? '<span class="remote-connected-dot" title="Connected"></span>' : ''}
    </button>
  `).join('') : '<div class="users-empty">No saved remotes.<br>Add one below.</div>';

  if (workspace) {
    if (activeId) {
      const cfg = saved.find(c => c.id === activeId);
      if (cfg) renderRemoteDetail(cfg, workspace);
    } else {
      workspace.innerHTML = '<div class="users-detail-empty">Select a remote vault or add a new one.</div>';
    }
  }
}

function renderRemoteDetail(cfg: RemoteVaultConfig, ws: HTMLElement) {
  const isConnected = st.store instanceof RemoteVaultStore &&
    (st.store as RemoteVaultStore).baseUrl === cfg.url;

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
          ${isConnected
            ? `<button class="btn btn-xs danger" id="remote-disconnect-btn">Disconnect</button>`
            : `<button class="btn btn-xs btn-accent" id="remote-connect-btn">Connect</button>`}
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

      ${isConnected ? `
      <section class="users-section">
        <div class="users-section-head"><span>Vault Status</span></div>
        <div id="remote-status-area" class="remote-status-area">
          <button class="btn btn-xs btn-ghost" id="remote-refresh-status-btn">Refresh Status</button>
        </div>
      </section>` : ''}
    </div>
  `;

  // Bindings
  document.getElementById('remote-connect-btn')?.addEventListener('click', () => connectRemote(cfg));
  document.getElementById('remote-disconnect-btn')?.addEventListener('click', () => disconnectRemote());
  document.getElementById('remote-delete-btn')?.addEventListener('click', () => deleteRemote(cfg.id));
  document.getElementById('re-save-btn')?.addEventListener('click', () => saveRemoteEdits(cfg.id));
  document.getElementById('re-test-btn')?.addEventListener('click', () => testRemote());
  document.getElementById('remote-refresh-status-btn')?.addEventListener('click', () => refreshRemoteStatus(cfg));

  if (isConnected) refreshRemoteStatus(cfg);
}

// ── Connect / Disconnect ──────────────────────────────────────────────────────

async function connectRemote(cfg: RemoteVaultConfig) {
  const pw = prompt(`${cfg.username ? `Password for "${cfg.username}"` : 'Master password'} on ${cfg.name}:`);
  if (pw === null) return;

  const remote = new RemoteVaultStore(cfg.url, cfg.certFingerprint);
  try {
    let ok: boolean;
    if (cfg.username) {
      ok = await remote.authUser(cfg.username, pw);
    } else {
      ok = await remote.unlock(pw);
    }
    if (!ok) { showToast('Authentication failed', 'err'); return; }

    // Fetch and persist cert fingerprint (TOFU pinning — trust on first use).
    // If the fingerprint changes on a subsequent connect, warn the user.
    const serverStatus = await remote.getStatus();
    if (serverStatus.cert_fingerprint) {
      const saved = getSaved();
      const idx = saved.findIndex(c => c.id === cfg.id);
      if (idx >= 0) {
        if (cfg.certFingerprint && cfg.certFingerprint !== serverStatus.cert_fingerprint) {
          showToast('⚠ TLS cert fingerprint changed — server certificate may have rotated', 'err');
        }
        saved[idx] = { ...saved[idx], certFingerprint: serverStatus.cert_fingerprint };
        saveSaved(saved);
        remote.fingerprint = serverStatus.cert_fingerprint;
        cfg = saved[idx];
      }
    }

    st.store = remote;
    st.activeRemoteId = cfg.id;
    Settings.set('remote', { enabled: true, serverUrl: cfg.url });

    const nameEl = document.getElementById('vault-name');
    if (nameEl) nameEl.textContent = cfg.name;

    showToast(`Connected to ${cfg.name}`, 'ok');
    startPing(cfg.url);
    renderRemotePanel();
    await _finishInitFn();
  } catch (e: any) {
    showToast('Connection failed: ' + (e?.message ?? e), 'err');
  }
}

function disconnectRemote() {
  stopPing();
  if (st.store instanceof RemoteVaultStore) {
    (st.store as RemoteVaultStore).lock().catch(() => {});
  }
  st.store = inTauri ? new TauriVaultStore() : new LocalVaultStore();
  st.activeRemoteId = null;
  Settings.set('remote', { enabled: false, serverUrl: '' });

  const nameEl = document.getElementById('vault-name');
  if (nameEl) nameEl.textContent = 'Local Vault';

  showToast('Disconnected from remote vault', 'ok');
  renderRemotePanel();
}

async function deleteRemote(id: string) {
  const saved = getSaved();
  const cfg = saved.find(c => c.id === id);
  if (!await showConfirm(`Remove "${cfg?.name ?? id}" from saved remotes?`)) return;
  if (st.activeRemoteId === id) disconnectRemote();
  saveSaved(saved.filter(c => c.id !== id));
  st.activeRemoteId = null;
  renderRemotePanel();
}

async function saveRemoteEdits(id: string) {
  const name     = (document.getElementById('re-name')     as HTMLInputElement).value.trim();
  const url      = (document.getElementById('re-url')      as HTMLInputElement).value.trim().replace(/\/$/, '');
  const username = (document.getElementById('re-username')  as HTMLInputElement).value.trim();
  if (!name || !url) { showToast('Name and URL are required', 'err'); return; }
  const saved = getSaved().map(c => c.id === id ? { ...c, name, url, username } : c);
  saveSaved(saved);
  showToast('Saved', 'ok');
  renderRemotePanel();
}

async function testRemote() {
  const url      = (document.getElementById('re-url')  as HTMLInputElement)?.value.trim().replace(/\/$/, '');
  const statusEl = document.getElementById('re-test-status');
  if (!url) { showToast('Enter a URL first', 'err'); return; }
  if (statusEl) statusEl.textContent = 'Testing…';
  try {
    const r = await fetch(`${url}/api/status`);
    const body = await r.json();
    if (statusEl) statusEl.textContent = body.vault_exists
      ? `✓ Server OK · vault ${body.unlocked ? 'unlocked' : 'locked'}`
      : '✓ Server OK · no vault yet';
  } catch {
    if (statusEl) statusEl.textContent = '✗ Unreachable';
  }
}

async function refreshRemoteStatus(cfg: RemoteVaultConfig) {
  const area = document.getElementById('remote-status-area');
  if (!area) return;
  try {
    const r = await fetch(`${cfg.url}/api/status`);
    const body = await r.json();
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
    document.getElementById('remote-refresh-status-btn')?.addEventListener('click', () => refreshRemoteStatus(cfg));
  } catch {
    area.innerHTML = `<div class="remote-status-err">Could not reach server.</div>
      <button class="btn btn-xs btn-ghost" id="remote-refresh-status-btn" style="margin-top:6px">Retry</button>`;
    document.getElementById('remote-refresh-status-btn')?.addEventListener('click', () => refreshRemoteStatus(cfg));
  }
}

// ── Add remote form ───────────────────────────────────────────────────────────

function openAddRemoteForm() {
  const ws = document.getElementById('remote-workspace');
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
          <div class="users-detail-sub">Connect to a running apiv-server instance.</div>
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
    const name     = (document.getElementById('add-remote-name')     as HTMLInputElement).value.trim();
    const url      = (document.getElementById('add-remote-url')      as HTMLInputElement).value.trim().replace(/\/$/, '');
    const username = (document.getElementById('add-remote-username')  as HTMLInputElement).value.trim();
    if (!name) { showToast('Name is required', 'err'); return; }
    if (!url)  { showToast('URL is required', 'err'); return; }
    const cfg: RemoteVaultConfig = { id: genId(), name, url, username };
    saveSaved([...getSaved(), cfg]);
    st.activeRemoteId = cfg.id;
    showToast(`"${name}" saved`, 'ok');
    renderRemotePanel();
  });

  document.getElementById('add-remote-test')!.addEventListener('click', async () => {
    const url      = (document.getElementById('add-remote-url')   as HTMLInputElement).value.trim().replace(/\/$/, '');
    const statusEl = document.getElementById('add-test-status');
    if (!url) { showToast('Enter a URL first', 'err'); return; }
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

export function initRemotePanel() {
  document.getElementById('remote-panel-list')?.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('[data-remote-id]');
    if (!btn?.dataset.remoteId) return;
    st.activeRemoteId = btn.dataset.remoteId;
    renderRemotePanel();
  });

  document.getElementById('add-remote-btn')?.addEventListener('click', openAddRemoteForm);

  renderRemotePanel();
}
