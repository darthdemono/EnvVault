/**
 * @file Lock / unlock vault: lockVault, resetLock, showUnlockModal.
 */

import { st, TauriVaultStore, Settings, triggerRender } from './state';
import { showToast, showConfirm } from './utils';

let _finishInitFn: () => Promise<void> = async () => {};

export function setFinishInitFn(fn: () => Promise<void>): void {
  _finishInitFn = fn;
}

export async function lockVault() {
  if (st.store instanceof TauriVaultStore) (st.store as TauriVaultStore).lock().catch(() => {});
  st.vault.api_keys = [];
  st.vault.user_categories = [];
  st.vault.projects = [{ id: 'Universal', name: 'Universal', description: '' }];
  sessionStorage.removeItem('api-vault');
  st.expanded.clear();
  st.revealed = {};
  triggerRender();
  if (st.store instanceof TauriVaultStore) showUnlockModal(false);
  else { document.getElementById('load-banner')!.style.display = 'flex'; showToast('Vault locked', 'err', 3500); }
}

export function resetLock() {
  clearTimeout(st.lockTimer!);
  const mins = Settings.get('autoLockMinutes');
  st.lockTimer = setTimeout(lockVault, mins * 60000);
  document.getElementById('lock-status')!.textContent = `Auto-lock: ${mins}min`;
}

export async function showUnlockModal(isFirstRun: boolean) {
  const overlay = document.getElementById('unlock-overlay')!;
  const titleEl = document.getElementById('unlock-title')!;
  const subtitleEl = document.getElementById('unlock-subtitle')!;
  const confirmGroup = document.getElementById('unlock-confirm-group')!;
  const submitBtn = document.getElementById('unlock-submit-btn') as HTMLButtonElement;
  const resetBtn = document.getElementById('unlock-reset-btn') as HTMLButtonElement;
  const pwField = document.getElementById('unlock-password') as HTMLInputElement;
  const confirmField = document.getElementById('unlock-confirm') as HTMLInputElement;
  const errEl = document.getElementById('unlock-error')!;

  function configure(firstRun: boolean) {
    submitBtn.disabled = false;
    if (firstRun) {
      titleEl.textContent = 'Create Master Password';
      subtitleEl.textContent = 'This password encrypts your vault with AES-256 + Argon2id. There is no recovery — keep it safe.';
      confirmGroup.style.display = 'block';
      submitBtn.textContent = 'Create Vault';
      resetBtn.style.display = 'none';
    } else {
      titleEl.textContent = 'Unlock Vault';
      subtitleEl.textContent = 'Enter your master password to decrypt the vault.';
      confirmGroup.style.display = 'none';
      submitBtn.textContent = 'Unlock';
      resetBtn.style.display = '';
    }
  }

  configure(isFirstRun);
  overlay.classList.add('open');
  document.getElementById('header')!.style.display = 'none';
  pwField.value = '';
  confirmField.value = '';
  errEl.style.display = 'none';
  setTimeout(() => pwField.focus(), 80);

  function showErr(msg: string) {
    errEl.textContent = msg;
    errEl.style.display = 'block';
    pwField.focus();
  }

  async function doUnlock() {
    errEl.style.display = 'none';
    const pw = pwField.value;

    if (!pw) { showErr('Password cannot be empty.'); return; }
    if (isFirstRun && pw.length < 8) { showErr('Use at least 8 characters.'); return; }
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
  pwField.onkeydown = (e) => { if (e.key === 'Enter') doUnlock(); };
  confirmField.onkeydown = (e) => { if (e.key === 'Enter') doUnlock(); };

  resetBtn.onclick = async () => {
    if (!await showConfirm('⚠️ This permanently deletes all vault data and cannot be undone. Continue?')) return;
    try { await (st.store as TauriVaultStore).reset(); } catch { }
    pwField.value = '';
    confirmField.value = '';
    configure(true);
    showToast('Vault reset. Set a new master password.', '', 4000);
  };
}
