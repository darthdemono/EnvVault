/**
 * @file
 * Lock / unlock vault: lockVault, resetLock, showUnlockModal.
 */

import {
  st,
  TauriVaultStore,
  RemoteVaultStore,
  LocalVaultStore,
  inTauri,
  Settings,
  triggerRender,
  resetViewState,
} from './state';
import { showToast, showConfirm, esc } from './utils';
import {
  upsertSavedRemote,
  findSavedRemote,
  renderRemotePanel,
  markRemoteConnected,
} from './remote-panel';
import { showDropdown } from './modals';
import {
  wireRevealButtons,
  resetReveal,
  wireCapsLockHint,
  wirePasswordStrength,
  relativeTime,
} from './ui-qol';

let _finishInitFn: () => Promise<void> = async () => {};
let _warnTimer: ReturnType<typeof setTimeout> | null = null;
let _activityBound = false;

export function setFinishInitFn(fn: () => Promise<void>): void {
  _finishInitFn = fn;
}

export async function lockVault(reason: 'auto' | 'manual' | 'visibility' = 'manual') {
  // Locking tears down the LAN server — it holds a copy of the key, so leaving
  // it up would mean "locked" on screen while peers kept reading and writing.
  // Confirm first if anyone is actually connected.
  if (st.lanServerRunning) {
    const { confirmStopForLock } = await import('./lan');
    if (!(await confirmStopForLock())) return;
  }

  clearTimeout(_warnTimer!);
  clearTimeout(st.lockTimer!);
  _warnTimer = null;
  st.lockTimer = null;

  if (st.store instanceof TauriVaultStore) (st.store as TauriVaultStore).lock().catch(() => {});
  if (st.store instanceof RemoteVaultStore) (st.store as RemoteVaultStore).lock().catch(() => {});

  st.vault.api_keys = [];
  st.vault.user_categories = [];
  st.vault.projects = [{ id: 'Universal', name: 'Universal', description: '' }];
  sessionStorage.removeItem('envvault');

  // Pending undos close over the entries they would restore — including their
  // secret values — and the Undo button stayed live after locking. Locking has
  // to drop them, or a locked vault still holds plaintext secrets in memory and
  // offers a button that puts one back.
  for (const u of st.undoStack) clearTimeout(u.t);
  st.undoStack = [];
  document.getElementById('undo-bar')?.classList.remove('visible');

  // Covers expanded/revealed/filters/search plus bulk mode, which used to stay
  // switched on across a lock.
  resetViewState();
  st.vaultOpen = false;
  triggerRender();

  const lockStatus = document.getElementById('lock-status');
  if (lockStatus) lockStatus.textContent = 'Locked';

  if (st.store instanceof TauriVaultStore) showRelockScreen(reason);
  else {
    document.getElementById('load-banner')!.style.display = 'flex';
    showToast('Vault locked', 'err', 3500);
  }
}

export function showRelockScreen(reason: 'auto' | 'manual' | 'visibility' | 'switch' = 'manual') {
  const overlay = document.getElementById('relock-overlay')!;
  const reasonEl = document.getElementById('relock-reason')!;
  const pwField = document.getElementById('relock-password') as HTMLInputElement;
  const errEl = document.getElementById('relock-error')!;
  const submitBtn = document.getElementById('relock-submit-btn') as HTMLButtonElement;
  const labelEl = document.getElementById('relock-vault-label');

  if (labelEl) {
    const vaultName = document.getElementById('vault-name')?.textContent ?? 'Local Vault';
    labelEl.textContent = vaultName;
  }

  const msgs: Record<typeof reason, string> = {
    auto: 'Auto-locked after inactivity. Enter your master password to continue.',
    visibility: 'Vault locked while the app was in the background.',
    manual: 'Vault locked. Enter your master password to continue.',
    switch: 'Switched to the local vault. Enter your master password to unlock it.',
  };
  reasonEl.textContent = msgs[reason];

  overlay.classList.add('open');
  pwField.value = '';
  errEl.style.display = 'none';
  submitBtn.disabled = false;
  submitBtn.textContent = 'Unlock';
  // Re-mask on every lock: a reveal left switched on would otherwise show the
  // master password in plaintext on the auto-lock screen — the exact moment the
  // user is most likely to be away from the machine.
  resetReveal('relock-password');
  wireRevealButtons(document.getElementById('relock-overlay')!);
  wireCapsLockHint('relock-password', 'relock-capslock');
  setTimeout(() => pwField.focus(), 80);

  function showErr(msg: string) {
    errEl.textContent = msg;
    errEl.style.display = 'block';
    pwField.select();
  }

  async function doUnlock() {
    const pw = pwField.value;
    if (!pw) {
      showErr('Password cannot be empty.');
      return;
    }
    submitBtn.disabled = true;
    submitBtn.textContent = 'Unlocking…';
    try {
      await (st.store as TauriVaultStore).unlock(pw);
      overlay.classList.remove('open');
      await _finishInitFn();
      resetLock();
    } catch (err: any) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Unlock';
      showErr(err?.message ?? 'Wrong password');
    }
  }

  submitBtn.onclick = doUnlock;
  pwField.onkeydown = (e) => {
    if (e.key === 'Enter') doUnlock();
  };
}

export function resetLock() {
  clearTimeout(st.lockTimer!);
  clearTimeout(_warnTimer!);
  _warnTimer = null;

  const mins = Settings.get('autoLockMinutes');
  const lockStatus = document.getElementById('lock-status');

  // Suspended while serving: peers are actively using the vault, and the host
  // not touching the keyboard is not a reason to cut them off. lan.ts closes an
  // idle server instead, which lands back here and re-arms the timer.
  if (st.lanServerRunning) {
    st.lockTimer = null;
    if (lockStatus) lockStatus.textContent = 'Auto-lock: paused (serving LAN)';
    return;
  }

  if (!mins || mins <= 0) {
    st.lockTimer = null;
    if (lockStatus) lockStatus.textContent = 'Auto-lock: Off';
    return;
  }

  const ms = mins * 60_000;
  const warnMs = ms - 60_000; // warn 1 minute before lock

  if (warnMs > 0) {
    _warnTimer = setTimeout(() => {
      showToast(`Vault locks in 1 minute — interact to reset`, 'err', 55_000);
    }, warnMs);
  }

  st.lockTimer = setTimeout(() => lockVault('auto'), ms);
  if (lockStatus) lockStatus.textContent = `Auto-lock: ${mins}min`;

  // Bind activity listeners once — any mouse or keyboard event resets the timer.
  if (!_activityBound) {
    _activityBound = true;
    const onActivity = () => {
      if (st.lockTimer) resetLock();
    };
    document.addEventListener('mousemove', onActivity, { passive: true });
    document.addEventListener('keydown', onActivity, { passive: true });
    document.addEventListener('mousedown', onActivity, { passive: true });
    document.addEventListener('touchstart', onActivity, { passive: true });
  }
}

// ── Unlock modal ──────────────────────────────────────────────────────────────

/**
 * Saved remotes ordered most-recently-connected first.
 *
 * Servers that have never authenticated sort last rather than being dropped:
 * one added through the Remote panel but not yet used is still worth offering,
 * it just should not outrank the one used every morning.
 */
export function recentServers() {
  // Date.parse returns NaN for a missing timestamp, and NaN in a comparator
  // makes *every* comparison return NaN — the sort then leaves the list in
  // whatever order it started, so never-connected servers do not sort last.
  const at = (c: { lastConnectedAt?: string }) => {
    const n = Date.parse(c.lastConnectedAt ?? '');
    return Number.isNaN(n) ? 0 : n;
  };
  return [...(Settings.get('remoteSaved') ?? [])].sort((a, b) => at(b) - at(a));
}

export async function showUnlockModal(isFirstRun: boolean) {
  const overlay = document.getElementById('unlock-overlay')!;
  const titleEl = document.getElementById('unlock-title')!;
  const subtitleEl = document.getElementById('unlock-subtitle')!;
  const confirmGroup = document.getElementById('unlock-confirm-group')!;
  const submitBtn = document.getElementById('unlock-submit-btn') as HTMLButtonElement;
  const pwField = document.getElementById('unlock-password') as HTMLInputElement;
  const confirmField = document.getElementById('unlock-confirm') as HTMLInputElement;
  const userField = document.getElementById('unlock-username') as HTMLInputElement | null;
  const serverField = document.getElementById('unlock-server') as HTMLInputElement | null;
  const errEl = document.getElementById('unlock-error')!;

  function isRemoteMode() {
    const url = serverField?.value.trim() ?? '';
    return !!url || st.store instanceof RemoteVaultStore;
  }

  function configure(firstRun: boolean) {
    submitBtn.disabled = false;
    const remote = isRemoteMode();
    if (remote) {
      titleEl.textContent = 'Connect to Remote Vault';
      subtitleEl.textContent =
        'Enter the server URL, then your credentials. Leave username blank to authenticate as vault owner.';
      confirmGroup.style.display = 'none';
      submitBtn.textContent = 'Connect';
    } else if (firstRun) {
      titleEl.textContent = 'Create Master Password';
      subtitleEl.textContent =
        'This password encrypts your vault with AES-256 + Argon2id. There is no recovery — keep it safe.';
      confirmGroup.style.display = 'block';
      submitBtn.textContent = 'Create Vault';
    } else {
      titleEl.textContent = 'Unlock Vault';
      subtitleEl.textContent = 'Enter your master password to decrypt the vault.';
      confirmGroup.style.display = 'none';
      submitBtn.textContent = 'Unlock';
    }
  }

  configure(isFirstRun);
  overlay.classList.add('open');
  document.getElementById('header')!.style.display = 'none';
  pwField.value = '';
  confirmField.value = '';
  errEl.style.display = 'none';
  if (userField && !userField.value) userField.value = '';

  resetReveal('unlock-password');
  wireRevealButtons(overlay);
  wireCapsLockHint('unlock-password', 'unlock-capslock');
  wirePasswordStrength('unlock-password', 'unlock-strength');

  // Pre-fill server URL from the most recently *connected* remote, falling back
  // to the legacy single-remote setting. Ordering by lastConnectedAt matters:
  // `remote.serverUrl` is whatever was typed last, including a URL that never
  // authenticated, so it would happily re-offer a server the user gave up on.
  if (serverField) {
    const savedUrl = Settings.get('remote')?.serverUrl ?? '';
    const recent = recentServers()[0];
    if (st.store instanceof RemoteVaultStore) {
      serverField.value = (st.store as RemoteVaultStore).baseUrl;
    } else if (recent) {
      serverField.value = recent.url;
      if (userField && !userField.value) userField.value = recent.username;
    } else if (savedUrl) {
      serverField.value = savedUrl;
    }
  }

  // Recent-servers picker. Saves retyping a URL and, more importantly, restores
  // the *username* that goes with it — the two are a pair, and connecting with
  // the right URL under the wrong account just fails authentication.
  const recentBtn = document.getElementById('unlock-server-recent') as HTMLButtonElement | null;
  if (recentBtn && serverField) {
    recentBtn.onclick = () => {
      const servers = recentServers();
      const items: ({ label: string; active: boolean; fn: () => void } | '---')[] = [
        {
          label: '&nbsp;&nbsp;Local Vault',
          active: !serverField.value,
          fn: () => {
            serverField.value = '';
            if (userField) userField.value = '';
            configure(isFirstRun);
            pwField.focus();
          },
        },
      ];
      if (servers.length) items.push('---');
      servers.forEach((cfg) => {
        items.push({
          label:
            `<div>${esc(cfg.name)}</div>` +
            `<div style="font-size:10px;color:var(--text3);margin-top:2px">` +
            `${esc(cfg.url)} · ${esc(relativeTime(cfg.lastConnectedAt))}</div>`,
          active: serverField.value.replace(/\/$/, '') === cfg.url,
          fn: () => {
            serverField.value = cfg.url;
            if (userField) userField.value = cfg.username;
            configure(isFirstRun);
            pwField.focus();
          },
        });
      });
      if (!servers.length) {
        items.push('---');
        items.push({
          label: '<span style="color:var(--text3)">No servers connected yet</span>',
          active: false,
          fn: () => {},
        });
      }
      showDropdown(recentBtn, items);
    };
  }

  // Re-run configure when server URL changes (switches between local/remote layout).
  // Assignment, not addEventListener: showUnlockModal can be called repeatedly
  // (lock -> unlock -> lock), and addEventListener stacked a duplicate handler
  // every time.
  if (serverField) serverField.oninput = () => configure(isFirstRun);

  setTimeout(() => (serverField ?? userField ?? pwField).focus(), 80);

  function showErr(msg: string) {
    errEl.textContent = msg;
    errEl.style.display = 'block';
    pwField.focus();
  }

  async function doUnlock() {
    errEl.style.display = 'none';
    const pw = pwField.value;
    const username = userField?.value.trim() ?? '';
    const serverUrl = serverField?.value.trim().replace(/\/$/, '') ?? '';

    if (serverUrl) {
      // Remote mode (URL provided in modal)
      if (!pw) {
        showErr('Password cannot be empty.');
        return;
      }
      submitBtn.disabled = true;
      submitBtn.textContent = 'Connecting…';
      try {
        // Reuse the pinned fingerprint if this server is already known, so an
        // https:// server with a self-signed cert connects on the first try
        // instead of being rejected by WebKit.
        const known = findSavedRemote(serverUrl, username);
        const remote = new RemoteVaultStore(serverUrl, known?.certFingerprint);
        let ok: boolean;
        if (username) {
          ok = await remote.authUser(username, pw);
        } else {
          ok = await remote.unlock(pw);
        }
        if (!ok) throw new Error('Authentication failed — wrong password or username');

        // TOFU pinning, same as the Remote panel's connect path.
        const fingerprint = await remote
          .getStatus()
          .then((s) => s.cert_fingerprint ?? undefined)
          .catch(() => undefined);
        if (fingerprint) remote.fingerprint = fingerprint;

        // Remember the server. Without this, a vault reached from this screen
        // never reached the saved list, so it was absent from the Remote panel
        // and the vault switcher and had to be retyped every session.
        const cfg = upsertSavedRemote({ url: serverUrl, username, certFingerprint: fingerprint });
        markRemoteConnected(cfg.id);

        st.store = remote;
        st.activeRemoteId = cfg.id;
        Settings.set('remote', { enabled: true, serverUrl });
        const nameEl = document.getElementById('vault-name');
        if (nameEl) nameEl.textContent = cfg.name;
        overlay.classList.remove('open');
        document.getElementById('header')!.style.display = '';
        renderRemotePanel();
        await _finishInitFn();
      } catch (err: any) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Connect';
        showErr(err?.message || String(err) || 'Connection failed');
      }
      return;
    }

    // Local mode
    if (!pw) {
      showErr('Password cannot be empty.');
      return;
    }
    if (isFirstRun && pw.length < 12) {
      showErr('Use at least 12 characters for a secrets manager vault.');
      return;
    }
    if (isFirstRun && pw !== confirmField.value) {
      showErr('Passwords do not match.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = isFirstRun ? 'Creating…' : 'Unlocking…';

    try {
      await (st.store as TauriVaultStore).unlock(pw);
      overlay.classList.remove('open');
      document.getElementById('header')!.style.display = '';
      await _finishInitFn();
    } catch (err: any) {
      submitBtn.disabled = false;
      submitBtn.textContent = isFirstRun ? 'Create Vault' : 'Unlock';
      showErr(err?.message || String(err) || 'Wrong password');
    }
  }

  submitBtn.onclick = doUnlock;
  pwField.onkeydown = (e) => {
    if (e.key === 'Enter') doUnlock();
  };
  confirmField.onkeydown = (e) => {
    if (e.key === 'Enter') doUnlock();
  };

  // reset_vault removed from UI — delete vault data via CLI or by removing
  // the vault.db + vault.salt files from the data directory.
}
