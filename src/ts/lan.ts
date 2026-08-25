/**
 * @file
 * "Open to LAN" — serve this vault to the local network from the desktop.
 *
 * Minecraft-style: the server exists only while the app is open, shares the
 * vault already on screen, and dies when you close it or lock. A Docker
 * `envv-server` remains the option for something always-on.
 *
 * Peers sign in with user accounts. `POST /api/unlock` is refused while hosting,
 * so the master password never crosses the network.
 */

import { st, Settings, applyUsersPanelVisibility, switchPanel, inTauri } from './state';
import { esc, showToast, showConfirm, clipboardWrite } from './utils';

const invoke = (cmd: string, args?: Record<string, unknown>) =>
  (window as any).__TAURI__?.core?.invoke?.(cmd, args) as Promise<any> | undefined;

export interface LanStatus {
  running: boolean;
  port: number;
  url: string;
  fingerprint: string | null;
  peers: number;
  idle_secs: number;
}

const EMPTY: LanStatus = {
  running: false,
  port: 0,
  url: '',
  fingerprint: null,
  peers: 0,
  idle_secs: 0,
};

let _status: LanStatus = { ...EMPTY };
let _poll: ReturnType<typeof setInterval> | null = null;

/** Hours of no peer traffic after which the server closes itself. */
const IDLE_SHUTDOWN_HOURS = 8;

export function lanStatus(): LanStatus {
  return _status;
}

async function refresh(): Promise<void> {
  try {
    _status = (await invoke('lan_status')) ?? { ...EMPTY };
  } catch {
    _status = { ...EMPTY };
  }
  st.lanServerRunning = _status.running;
  applyUsersPanelVisibility();
  render();

  // Auto-lock is suspended while serving, so an abandoned server would keep the
  // vault decrypted indefinitely. Closing it on idle re-arms normal auto-lock.
  if (_status.running && _status.idle_secs > IDLE_SHUTDOWN_HOURS * 3600) {
    await stopLan(/* silent */ true);
    showToast(
      `LAN server closed after ${IDLE_SHUTDOWN_HOURS}h with no peers — auto-lock resumed`,
      'ok',
      5000,
    );
  }
}

function startPolling() {
  if (_poll !== null) return;
  _poll = setInterval(refresh, 5000);
}

function stopPolling() {
  if (_poll !== null) {
    clearInterval(_poll);
    _poll = null;
  }
}

export async function startLan(): Promise<void> {
  // Second gate, not a redundant one. The render gate can be stale — the card
  // is painted once and only repainted on the events we remembered to hook, so
  // a switch to a remote that missed a repaint would leave a live button behind.
  // The consequence of getting this wrong is publishing the wrong vault, which
  // is worth checking at the point of action rather than only at paint time.
  if (!lanAvailable()) {
    showToast(
      st.store.isRemote
        ? 'Open to LAN serves the vault on this machine — switch to the local vault first'
        : 'Open to LAN is only available in the desktop app',
      'err',
      5000,
    );
    render();
    return;
  }

  try {
    _status = await invoke('lan_start', { port: null, tls: true });
    st.lanServerRunning = true;
    applyUsersPanelVisibility();
    startPolling();
    render();
    showToast(`Serving at ${_status.url}`, 'ok', 4000);
    // Auto-lock stays suspended for as long as we serve — resetLock reads
    // st.lanServerRunning and stands down.
    const m = await import('./lock');
    m.resetLock();
  } catch (e: any) {
    const msg = String(e?.message ?? e);
    render();
    if (msg.includes('No user account exists')) {
      showToast('Create a user account first — peers sign in with one', 'err', 5000);
      switchPanel('users');
      return;
    }
    showToast(`Could not open to LAN: ${msg}`, 'err', 5000);
  }
}

export async function stopLan(silent = false): Promise<void> {
  try {
    await invoke('lan_stop');
  } catch {
    /* already down */
  }
  _status = { ...EMPTY };
  st.lanServerRunning = false;
  stopPolling();
  applyUsersPanelVisibility();
  render();
  if (!silent) showToast('LAN server closed', 'ok');
  // Re-arm the inactivity timer that was suspended while serving.
  const m = await import('./lock');
  m.resetLock();
}

/**
 * Stop the server as part of locking, confirming first when peers are connected
 * so a colleague is not cut off mid-edit without warning.
 */
export async function confirmStopForLock(): Promise<boolean> {
  if (!_status.running) return true;
  if (_status.peers > 0) {
    const ok = await showConfirm(
      `${_status.peers} peer${_status.peers === 1 ? ' is' : 's are'} connected to your LAN server. ` +
        `Locking closes it and disconnects ${_status.peers === 1 ? 'them' : 'all of them'}. Continue?`,
    );
    if (!ok) return false;
  }
  await stopLan(/* silent */ true);
  return true;
}

/**
 * Whether "Open to LAN" can serve anything from here.
 *
 * `lan_start` reads the key out of Rust's `VaultState` and opens **this
 * machine's** `vault.db` — it has no idea a remote vault is on screen. Nothing
 * locks the local vault when you connect to a remote (`lockVault` only calls
 * `.lock()` on the *current* store), so after unlock-local → connect-remote the
 * local key is still resident and `lan_start` succeeds. The card sits in
 * `#remote-workspace`, the very panel you are looking at while connected, so
 * pressing it published the local vault while the screen showed the remote's
 * data — the user would reasonably believe they had just shared what they could
 * see.
 *
 * Non-Tauri is excluded too: `invoke` is undefined there, so the button was
 * simply inert.
 */
export function lanAvailable(): boolean {
  return inTauri && !st.store.isRemote;
}

function render(): void {
  const host = document.getElementById('lan-card');
  if (!host) return;

  // A running server stays visible and stoppable regardless — hiding the only
  // "Stop serving" control while the vault is still being published would be
  // strictly worse than showing it in the wrong panel.
  if (!lanAvailable() && !_status.running) {
    host.innerHTML = st.store.isRemote
      ? `<div class="lan-card lan-card-muted">
           <div class="lan-head"><span class="lan-title">Open to LAN</span></div>
           <p class="lan-help">
             Serving shares the vault stored on <strong>this machine</strong>, not the
             remote you are connected to. Switch to the local vault to use it.
           </p>
         </div>`
      : '';
    return;
  }

  if (!_status.running) {
    host.innerHTML = `
      <div class="lan-card">
        <div class="lan-head">
          <span class="lan-title">Open to LAN</span>
          <span class="lan-state off">Not serving</span>
        </div>
        <p class="lan-help">
          Serve <strong>this</strong> vault to your local network straight from the app —
          no Docker, no second database. It closes when you lock or quit.
          <br>Peers sign in with a user account; the master password never leaves this machine.
        </p>
        <div class="lan-actions">
          <button class="btn btn-sm btn-accent" id="lan-start-btn">Open to LAN</button>
        </div>
      </div>`;
    document.getElementById('lan-start-btn')?.addEventListener('click', startLan);
    return;
  }

  const fp = _status.fingerprint ?? '';
  host.innerHTML = `
    <div class="lan-card running">
      <div class="lan-head">
        <span class="lan-title">Open to LAN</span>
        <span class="lan-state on">Serving · ${_status.peers} peer${_status.peers === 1 ? '' : 's'}</span>
      </div>
      <div class="lan-field">
        <span class="lan-label">Address</span>
        <code class="lan-value">${esc(_status.url)}</code>
        <button class="btn btn-xs btn-ghost" id="lan-copy-url">Copy</button>
      </div>
      ${
        fp
          ? `
      <div class="lan-field">
        <span class="lan-label">TLS fingerprint</span>
        <code class="lan-value lan-fp" title="${esc(fp)}">${esc(fp.slice(0, 32))}…</code>
        <button class="btn btn-xs btn-ghost" id="lan-copy-fp">Copy</button>
      </div>
      <p class="lan-help">
        The certificate is self-signed, so peers must pin this fingerprint when adding
        the connection. Compare it on their screen before accepting.
      </p>`
          : `
      <p class="lan-help lan-warn">
        Running without TLS — secrets travel this network in clear text.
      </p>`
      }
      <p class="lan-help">
        Auto-lock is suspended while serving. The server closes itself after
        ${IDLE_SHUTDOWN_HOURS}h with no peer activity.
      </p>
      <div class="lan-actions">
        <button class="btn btn-sm danger" id="lan-stop-btn">Stop serving</button>
      </div>
    </div>`;

  document.getElementById('lan-stop-btn')?.addEventListener('click', async () => {
    if (_status.peers > 0) {
      const ok = await showConfirm(
        `${_status.peers} peer${_status.peers === 1 ? ' is' : 's are'} connected. Disconnect ${_status.peers === 1 ? 'them' : 'all'}?`,
      );
      if (!ok) return;
    }
    await stopLan();
  });
  document
    .getElementById('lan-copy-url')
    ?.addEventListener('click', () =>
      clipboardWrite(_status.url).then(() => showToast('Address copied ✓', 'ok', 1500)),
    );
  document
    .getElementById('lan-copy-fp')
    ?.addEventListener('click', () =>
      clipboardWrite(fp).then(() => showToast('Fingerprint copied ✓', 'ok', 1500)),
    );
}

export function initLanPanel(): void {
  render();
  // Pick up a server left running from before a UI reload.
  refresh().then(() => {
    if (_status.running) startPolling();
  });
}

/**
 * Repaint the LAN card after the active vault changes.
 *
 * `initLanPanel()` runs once from `finishInit()`, and `render()` otherwise only
 * fires on start/stop/poll — none of which a vault switch triggers. So the card
 * kept whatever it was showing when the panel was first built, which is how a
 * live "Open to LAN" button survived a switch to a remote vault.
 */
export function refreshLanPanel(): void {
  render();
}
