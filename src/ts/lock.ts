/**
 * @file Lock / unlock vault: lockVault, resetLock, showUnlockModal.
 */

import { st, TauriVaultStore, RemoteVaultStore, LocalVaultStore, inTauri, Settings, triggerRender } from './state';
import { showToast, showConfirm } from './utils';

let _finishInitFn: () => Promise<void> = async () => {};
let _warnTimer: ReturnType<typeof setTimeout> | null = null;
let _activityBound = false;

export function setFinishInitFn(fn: () => Promise<void>): void {
  _finishInitFn = fn;
}

export async function lockVault() {
  clearTimeout(_warnTimer!);
  clearTimeout(st.lockTimer!);
  _warnTimer = null;
  st.lockTimer = null;

  if (st.store instanceof TauriVaultStore) (st.store as TauriVaultStore).lock().catch(() => {});
  if (st.store instanceof RemoteVaultStore) (st.store as RemoteVaultStore).lock().catch(() => {});

  st.vault.api_keys = [];
  st.vault.user_categories = [];
  st.vault.projects = [{ id: 'Universal', name: 'Universal', description: '' }];
  sessionStorage.removeItem('api-vault');
  st.expanded.clear();
  st.revealed = {};
  triggerRender();

  const lockStatus = document.getElementById('lock-status');
  if (lockStatus) lockStatus.textContent = 'Locked';

  if (st.store instanceof TauriVaultStore) showUnlockModal(false);
  else { document.getElementById('load-banner')!.style.display = 'flex'; showToast('Vault locked', 'err', 3500); }
}

export function resetLock() {
  clearTimeout(st.lockTimer!);
  clearTimeout(_warnTimer!);
  _warnTimer = null;

  const mins = Settings.get('autoLockMinutes');
  const lockStatus = document.getElementById('lock-status');

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

  st.lockTimer = setTimeout(lockVault, ms);
  if (lockStatus) lockStatus.textContent = `Auto-lock: ${mins}min`;

  // Bind activity listeners once — any mouse or keyboard event resets the timer.
  if (!_activityBound) {
    _activityBound = true;
    const onActivity = () => { if (st.lockTimer) resetLock(); };
    document.addEventListener('mousemove',  onActivity, { passive: true });
    document.addEventListener('keydown',    onActivity, { passive: true });
    document.addEventListener('mousedown',  onActivity, { passive: true });
    document.addEventListener('touchstart', onActivity, { passive: true });
  }
}

// ── Unlock modal ──────────────────────────────────────────────────────────────

export async function showUnlockModal(isFirstRun: boolean) {
  const overlay      = document.getElementById('unlock-overlay')!;
  const titleEl      = document.getElementById('unlock-title')!;
  const subtitleEl   = document.getElementById('unlock-subtitle')!;
  const confirmGroup = document.getElementById('unlock-confirm-group')!;
  const submitBtn    = document.getElementById('unlock-submit-btn') as HTMLButtonElement;
  const resetBtn     = document.getElementById('unlock-reset-btn') as HTMLButtonElement | null;
  const pwField      = document.getElementById('unlock-password') as HTMLInputElement;
  const confirmField = document.getElementById('unlock-confirm') as HTMLInputElement;
  const userField    = document.getElementById('unlock-username') as HTMLInputElement | null;
  const serverField  = document.getElementById('unlock-server') as HTMLInputElement | null;
  const errEl        = document.getElementById('unlock-error')!;

  function isRemoteMode() {
    const url = serverField?.value.trim() ?? '';
    return !!url || st.store instanceof RemoteVaultStore;
  }

  function configure(firstRun: boolean) {
    submitBtn.disabled = false;
    const remote = isRemoteMode();
    if (remote) {
      titleEl.textContent = 'Connect to Remote Vault';
      subtitleEl.textContent = 'Enter the server URL, then your credentials. Leave username blank to authenticate as vault owner.';
      confirmGroup.style.display = 'none';
      submitBtn.textContent = 'Connect';
    } else if (firstRun) {
      titleEl.textContent = 'Create Master Password';
      subtitleEl.textContent = 'This password encrypts your vault with AES-256 + Argon2id. There is no recovery — keep it safe.';
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

  // Pre-fill server URL from saved remote config
  if (serverField) {
    const savedUrl = Settings.get('remote')?.serverUrl ?? '';
    if (st.store instanceof RemoteVaultStore) {
      serverField.value = (st.store as RemoteVaultStore).baseUrl;
    } else if (savedUrl) {
      serverField.value = savedUrl;
    }
  }

  // Re-run configure when server URL changes (switches between local/remote layout)
  serverField?.addEventListener('input', () => configure(isFirstRun));

  setTimeout(() => (serverField ?? userField ?? pwField).focus(), 80);

  function showErr(msg: string) {
    errEl.textContent = msg;
    errEl.style.display = 'block';
    pwField.focus();
  }

  async function doUnlock() {
    errEl.style.display = 'none';
    const pw       = pwField.value;
    const username = userField?.value.trim() ?? '';
    const serverUrl = serverField?.value.trim().replace(/\/$/, '') ?? '';

    if (serverUrl) {
      // Remote mode (URL provided in modal)
      if (!pw) { showErr('Password cannot be empty.'); return; }
      submitBtn.disabled = true;
      submitBtn.textContent = 'Connecting…';
      try {
        const remote = new RemoteVaultStore(serverUrl);
        let ok: boolean;
        if (username) {
          ok = await remote.authUser(username, pw);
        } else {
          ok = await remote.unlock(pw);
        }
        if (!ok) throw new Error('Authentication failed — wrong password or username');
        st.store = remote;
        st.activeRemoteId = null; // connected via modal, not from saved list
        Settings.set('remote', { enabled: true, serverUrl });
        const nameEl = document.getElementById('vault-name');
        if (nameEl) nameEl.textContent = username ? `Remote — ${username}` : serverUrl.replace(/^https?:\/\//, '');
        overlay.classList.remove('open');
        document.getElementById('header')!.style.display = '';
        await _finishInitFn();
      } catch (err: any) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Connect';
        showErr(err?.message || String(err) || 'Connection failed');
      }
      return;
    }

    // Local mode
    if (!pw) { showErr('Password cannot be empty.'); return; }
    if (isFirstRun && pw.length < 12) { showErr('Use at least 12 characters for a secrets manager vault.'); return; }
    if (isFirstRun && pw !== confirmField.value) { showErr('Passwords do not match.'); return; }

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
  pwField.onkeydown     = (e) => { if (e.key === 'Enter') doUnlock(); };
  confirmField.onkeydown = (e) => { if (e.key === 'Enter') doUnlock(); };

  // reset_vault removed from UI — delete vault data via CLI or by removing
  // the vault.db + vault.salt files from the data directory.
}
